#include "../Pch.h"
#include "HyperDbgMemory.h"

extern "C" NTSTATUS NTAPI NtQuerySystemInformation(ULONG, PVOID, ULONG, PULONG);
#pragma comment(lib, "ntdll.lib")

static constexpr ULONG SystemModuleInformation = 11;

struct RtlProcessModuleInformation
{
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
};

struct RtlProcessModules
{
    ULONG NumberOfModules;
    RtlProcessModuleInformation Modules[1];
};

bool HyperDbgMemory::Read(uint32_t pid, uint64_t va, void* out, uint32_t size, ReadPath path)
{
    uint32_t got = 0;
    bool ok = ReadMemoryFn(va, 1, static_cast<int>(path), pid, size, false, nullptr, static_cast<uint8_t*>(out), &got);
    return ok && got == size;
}

uint32_t HyperDbgMemory::ReadRobust(uint32_t pid, uint64_t va, uint8_t* out, uint32_t size, ReadPath path)
{
    uint32_t total = 0;
    uint32_t ok = 0;

    while (total < size)
    {
        uint32_t offinpage = static_cast<uint32_t>((va + total) & (PageSize - 1));
        uint32_t chunk = (std::min)(PageSize - offinpage, size - total);

        if (Read(pid, va + total, out + total, chunk, path))
        {
            ok += chunk;
        }
        else
        {
            std::memset(out + total, 0, chunk);
        }

        total += chunk;
    }

    return ok;
}

bool HyperDbgMemory::WriteBytes(uint32_t pid, uint64_t va, const void* data, uint32_t size)
{
    const uint8_t* bytes = static_cast<const uint8_t*>(data);

    for (uint32_t off = 0; off < size; ++off)
    {
        char cmd[128];
        std::snprintf(cmd, sizeof(cmd), "eb 0x%llx 0x%02x pid %x", static_cast<unsigned long long>(va + off), bytes[off], pid);
        std::string response = Run(cmd);
        if (response.find("err") != std::string::npos)
        {
            return false;
        }
    }
    return true;
}

std::string HyperDbgMemory::EptHook(uint64_t va, uint32_t pid, const std::string& script)
{
    char cmd[512];
    std::snprintf(cmd, sizeof(cmd), "!epthook 0x%llx pid %x script { %s }", static_cast<unsigned long long>(va), pid, script.c_str());
    return Run(cmd);
}

std::string HyperDbgMemory::EptHook(const std::string& symbol, uint32_t pid, const std::string& script)
{
    char cmd[512];
    std::snprintf(cmd, sizeof(cmd), "!epthook %s pid %x script { %s }", symbol.c_str(), pid, script.c_str());
    return Run(cmd);
}

std::string HyperDbgMemory::EptHook2(uint64_t va, uint32_t pid, const std::string& script)
{
    char cmd[512];
    std::snprintf(cmd, sizeof(cmd), "!epthook2 0x%llx pid %x script { %s }", static_cast<unsigned long long>(va), pid, script.c_str());
    return Run(cmd);
}

std::string HyperDbgMemory::EptHook2(const std::string& symbol, uint32_t pid, const std::string& script)
{
    char cmd[512];
    std::snprintf(cmd, sizeof(cmd), "!epthook2 %s pid %x script { %s }", symbol.c_str(), pid, script.c_str());
    return Run(cmd);
}

void HyperDbgMemory::DumpModule(uint32_t pid, uint64_t base, const std::filesystem::path& outpath)
{
    IMAGE_DOS_HEADER dos = {};
    if (!Read(pid, base, &dos, sizeof(dos)))
    {
        throw std::runtime_error("read DOS header failed");
    }
    if (dos.e_magic != IMAGE_DOS_SIGNATURE)
    {
        throw std::runtime_error("MZ magic missing");
    }

    IMAGE_NT_HEADERS64 nt = {};
    if (!Read(pid, base + dos.e_lfanew, &nt, sizeof(nt)))
    {
        throw std::runtime_error("read NT headers failed");
    }
    if (nt.Signature != IMAGE_NT_SIGNATURE)
    {
        throw std::runtime_error("PE magic missing");
    }
    if (nt.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
    {
        throw std::runtime_error("not x64");
    }

    const uint32_t imagesize = nt.OptionalHeader.SizeOfImage;
    if (imagesize < PageSize || imagesize >(1u << 30))
    {
        throw std::runtime_error("SizeOfImage looks bogus");
    }

    std::vector<uint8_t> buf(imagesize, 0);
    uint32_t got = ReadRobust(pid, base, buf.data(), imagesize);

    auto dosout = reinterpret_cast<IMAGE_DOS_HEADER*>(buf.data());
    auto ntout = reinterpret_cast<IMAGE_NT_HEADERS64*>(buf.data() + dosout->e_lfanew);
    auto sec = IMAGE_FIRST_SECTION(ntout);

    ntout->OptionalHeader.FileAlignment = ntout->OptionalHeader.SectionAlignment;
    ntout->OptionalHeader.SizeOfHeaders = (ntout->OptionalHeader.SizeOfHeaders + PageSize - 1) & ~(PageSize - 1);

    for (WORD i = 0; i < ntout->FileHeader.NumberOfSections; ++i)
    {
        sec[i].PointerToRawData = sec[i].VirtualAddress;
        sec[i].SizeOfRawData = sec[i].Misc.VirtualSize;
    }

    std::ofstream file(outpath, std::ios::binary);
    if (!file)
    {
        throw std::runtime_error("open output failed");
    }
    file.write(reinterpret_cast<char*>(buf.data()), buf.size());

    std::printf("[+] dumped %u bytes (%u ok, %u zero-holes) -> %ls\n", imagesize, got, imagesize - got, outpath.wstring().c_str());
}

void HyperDbgMemory::DumpKernelModule(const std::string& name, const std::filesystem::path& outpath)
{
    auto modules = EnumerateKernelModules();
    auto it = std::find_if(modules.begin(), modules.end(), [&](const KernelModule& mod)
        {
            return _stricmp(mod.FileName.c_str(), name.c_str()) == 0;
        });

    if (it == modules.end())
    {
        throw std::runtime_error("driver not loaded: " + name);
    }

    std::printf("[+] %s @ %016llx (%u bytes) -> dumping...\n", it->FileName.c_str(), it->Base, it->Size);

    DumpModule(4, it->Base, outpath);
}

std::vector<KernelModule> HyperDbgMemory::EnumerateKernelModules()
{
    ULONG needed = 0;
    NtQuerySystemInformation(SystemModuleInformation, nullptr, 0, &needed);
    if (needed == 0)
    {
        throw std::runtime_error("NtQSI size query failed");
    }

    std::vector<uint8_t> buf(needed + 0x1000);
    if (NtQuerySystemInformation(SystemModuleInformation, buf.data(), static_cast<ULONG>(buf.size()), &needed) < 0)
    {
        throw std::runtime_error("NtQSI(SystemModuleInformation) failed");
    }

    auto mods = reinterpret_cast<RtlProcessModules*>(buf.data());
    std::vector<KernelModule> out;
    out.reserve(mods->NumberOfModules);

    for (ULONG i = 0; i < mods->NumberOfModules; ++i)
    {
        auto& mod = mods->Modules[i];
        KernelModule k;
        k.Base = reinterpret_cast<uint64_t>(mod.ImageBase);
        k.Size = mod.ImageSize;
        k.FullPath = reinterpret_cast<char*>(mod.FullPathName);
        k.FileName = k.FullPath.c_str() + mod.OffsetToFileName;
        out.push_back(std::move(k));
    }

    return out;
}