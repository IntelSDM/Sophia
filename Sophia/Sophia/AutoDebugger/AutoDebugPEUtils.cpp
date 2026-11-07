#include "../../Pch.h"
#include "AutoDebugPeUtils.h"

#include <Zydis/Zydis.h>


uint32_t AutoDebugPeUtils::ExpRvaToFileOffset(const IMAGE_SECTION_HEADER* sectable, uint32_t nsec, uint32_t rva)
{
    for (uint32_t i = 0; i < nsec; ++i)
    {
        const IMAGE_SECTION_HEADER& s = sectable[i];
        const uint32_t vsize = s.Misc.VirtualSize ? s.Misc.VirtualSize : s.SizeOfRawData;
        if (rva >= s.VirtualAddress && rva < s.VirtualAddress + vsize)
        {
            const uint32_t delta = rva - s.VirtualAddress;
            if (delta >= s.SizeOfRawData)
            {
                return 0;
            }
            return s.PointerToRawData + delta;
        }
    }
    return 0;
}

std::wstring AutoDebugPeUtils::NormalizeNtPath(const std::wstring& path)
{
    if (path.size() >= 4 && path.compare(0, 4, L"\\??\\") == 0)
    {
        return path.substr(4);
    }
    if (path.size() >= 12 && (path.compare(0, 12, L"\\SystemRoot\\") == 0 || path.compare(0, 12, L"\\systemroot\\") == 0))
    {
        wchar_t sysroot[MAX_PATH];
        const UINT n = GetWindowsDirectoryW(sysroot, MAX_PATH);
        if (n > 0 && n < MAX_PATH)
        {
            std::wstring win = sysroot;
            if (!win.empty() && win.back() != L'\\')
            {
                win.push_back(L'\\');
            }
            win.append(path.begin() + 12, path.end());
            return win;
        }
    }
    return path;
}

std::ifstream AutoDebugPeUtils::OpenPeFileForRead(const std::wstring& path)
{
    {
        std::ifstream f(path, std::ios::binary | std::ios::ate);
        if (f)
        {
            return f;
        }
    }
    const std::wstring normalized = NormalizeNtPath(path);
    if (normalized != path)
    {
        std::ifstream f(normalized, std::ios::binary | std::ios::ate);
        if (f)
        {
            return f;
        }
    }
    return std::ifstream{};
}

bool AutoDebugPeUtils::ReadExportsFromDiskFile(const std::wstring& fullpath, std::vector<ForeignExport>& out, std::unordered_map<uint32_t, size_t>& byrva)
{
    std::ifstream f = OpenPeFileForRead(fullpath);
    if (!f)
    {
        return false;
    }
    const std::streamoff filesize = f.tellg();
    if (filesize <= 0 || filesize > static_cast<std::streamoff>(256ULL * 1024 * 1024))
    {
        return false;
    }
    f.seekg(0);
    std::vector<uint8_t> bytes(static_cast<size_t>(filesize));
    if (!f.read(reinterpret_cast<char*>(bytes.data()), filesize))
    {
        return false;
    }

    if (bytes.size() < sizeof(IMAGE_DOS_HEADER))
    {
        return false;
    }
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(bytes.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
    {
        return false;
    }
    if (dos->e_lfanew <= 0 || static_cast<size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS64) > bytes.size())
    {
        return false;
    }
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(bytes.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
    {
        return false;
    }
    if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        return false;
    }

    const uint32_t exprva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    const uint32_t expsize = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    if (exprva == 0 || expsize < sizeof(IMAGE_EXPORT_DIRECTORY))
    {
        return true;
    }

    const auto* sectable = IMAGE_FIRST_SECTION(nt);
    const uint32_t nsec = nt->FileHeader.NumberOfSections;

    const uint32_t expoff = ExpRvaToFileOffset(sectable, nsec, exprva);
    if (expoff == 0 || expoff + sizeof(IMAGE_EXPORT_DIRECTORY) > bytes.size())
    {
        return false;
    }

    const auto* ed = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(bytes.data() + expoff);
    const uint32_t numfuncs = ed->NumberOfFunctions;
    const uint32_t numnames = ed->NumberOfNames;
    if (numfuncs == 0 || numnames == 0)
    {
        return true;
    }
    if (numfuncs > (1u << 20) || numnames > (1u << 20))
    {
        return false;
    }

    const uint32_t aofoff = ExpRvaToFileOffset(sectable, nsec, ed->AddressOfFunctions);
    const uint32_t aonoff = ExpRvaToFileOffset(sectable, nsec, ed->AddressOfNames);
    const uint32_t aooff = ExpRvaToFileOffset(sectable, nsec, ed->AddressOfNameOrdinals);
    if (aofoff == 0 || aonoff == 0 || aooff == 0)
    {
        return false;
    }
    if (aofoff + static_cast<uint64_t>(numfuncs) * 4 > bytes.size())
    {
        return false;
    }
    if (aonoff + static_cast<uint64_t>(numnames) * 4 > bytes.size())
    {
        return false;
    }
    if (aooff + static_cast<uint64_t>(numnames) * 2 > bytes.size())
    {
        return false;
    }

    const auto* funcs = reinterpret_cast<const uint32_t*>(bytes.data() + aofoff);
    const auto* names = reinterpret_cast<const uint32_t*>(bytes.data() + aonoff);
    const auto* ords = reinterpret_cast<const uint16_t*>(bytes.data() + aooff);

    out.reserve(out.size() + numnames);
    for (uint32_t i = 0; i < numnames; ++i)
    {
        const uint32_t namerva = names[i];
        const uint16_t ord = ords[i];
        if (namerva == 0 || ord >= numfuncs)
        {
            continue;
        }

        const uint32_t nameoff = ExpRvaToFileOffset(sectable, nsec, namerva);
        if (nameoff == 0 || nameoff >= bytes.size())
        {
            continue;
        }

        const char* namestr = reinterpret_cast<const char*>(bytes.data() + nameoff);
        const size_t maxlen = std::min<size_t>(512, bytes.size() - nameoff);
        size_t namelen = 0;
        while (namelen < maxlen && namestr[namelen] != 0)
        {
            ++namelen;
        }
        if (namelen == 0 || namelen >= 512)
        {
            continue;
        }

        const uint32_t rva = funcs[ord];
        if (rva == 0)
        {
            continue;
        }
        if (rva >= exprva && rva < exprva + expsize)
        {
            continue;
        }

        ForeignExport fe;
        fe.Rva = rva;
        fe.Name.assign(namestr, namelen);
        byrva[rva] = out.size();
        out.push_back(std::move(fe));
    }

    return true;
}

bool AutoDebugPeUtils::DecodeNtdllSyscallImm(const uint8_t* p, size_t available, uint32_t& outimm)
{
    ZydisDecoder decoder;
    if (ZYAN_FAILED(ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64)))
    {
        return false;
    }

    size_t offset = 0;
    ZydisDecodedInstruction insn;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

    for (int step = 0; step < 6; ++step)
    {
        if (offset >= available)
        {
            return false;
        }
        if (ZYAN_FAILED(ZydisDecoderDecodeFull(&decoder, p + offset, available - offset, &insn, operands)))
        {
            return false;
        }

        if (insn.mnemonic == ZYDIS_MNEMONIC_MOV && insn.operand_count_visible >= 2)
        {
            const ZydisDecodedOperand& dst = operands[0];
            const ZydisDecodedOperand& src = operands[1];
            if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER && dst.reg.value == ZYDIS_REGISTER_EAX && src.type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
            {
                outimm = static_cast<uint32_t>(src.imm.value.u);
                return true;
            }
        }

        offset += insn.length;
    }
    return false;
}