#include "../../Pch.h"
#include "DeobfValClassifier.h"

#include <cstdio>

ValSpace DeobfValClassifier::ClassifyBySection(const std::vector<uint8_t>& buf, uint64_t tracedbase, uint64_t tracedsize, uint64_t val)
{
    if (val < tracedbase) return ValSpace::Unknown;
    const uint64_t rvawithin = val - tracedbase;
    if (tracedsize != 0 && rvawithin >= tracedsize) return ValSpace::Unknown;
    if (rvawithin > 0xFFFFFFFFu) return ValSpace::Unknown;
    const uint32_t rva = static_cast<uint32_t>(rvawithin);

    if (buf.size() < sizeof(IMAGE_DOS_HEADER)) return ValSpace::Unknown;
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(buf.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return ValSpace::Unknown;
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(buf.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return ValSpace::Unknown;
    const auto* sectable = IMAGE_FIRST_SECTION(nt);
    const uint32_t nsec = nt->FileHeader.NumberOfSections;
    for (uint32_t i = 0; i < nsec; ++i)
    {
        const auto& s = sectable[i];
        const uint32_t vsize = s.Misc.VirtualSize ? s.Misc.VirtualSize : s.SizeOfRawData;
        if (rva < s.VirtualAddress || rva >= s.VirtualAddress + vsize) continue;

        const uint32_t ch = s.Characteristics;
        if (ch & IMAGE_SCN_CNT_CODE) return ValSpace::TextRva;
        if ((ch & IMAGE_SCN_MEM_WRITE) == 0 && (ch & IMAGE_SCN_CNT_INITIALIZED_DATA)) return ValSpace::RdataRva;
        if (ch & IMAGE_SCN_MEM_WRITE) return ValSpace::DataRva;
        return ValSpace::SectionOther;
    }
    return ValSpace::Unknown;
}

ForeignHit DeobfValClassifier::ClassifyForeign(const std::vector<ForeignMod>& mods, uint64_t val)
{
    ForeignHit fh;
    for (const ForeignMod& fm : mods)
    {
        if (val >= fm.Base && val < fm.Base + fm.Size)
        {
            fh.Mod = &fm;
            fh.Offset = val - fm.Base;
            return fh;
        }
    }
    return fh;
}

uint32_t DeobfValClassifier::RvaToFileOff(const std::vector<uint8_t>* modbytes, const uint8_t* rawbuf, size_t rawsize, uint32_t rva)
{
    const uint8_t* data = modbytes ? modbytes->data() : rawbuf;
    const size_t   size = modbytes ? modbytes->size() : rawsize;
    if (size < sizeof(IMAGE_DOS_HEADER)) return UINT32_MAX;
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(data);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return UINT32_MAX;
    if (dos->e_lfanew <= 0 || static_cast<size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS64) > size)
    {
        return UINT32_MAX;
    }
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(data + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return UINT32_MAX;
    const auto* sectable = IMAGE_FIRST_SECTION(nt);
    const uint32_t nsec = nt->FileHeader.NumberOfSections;
    for (uint32_t i = 0; i < nsec; ++i)
    {
        const auto& s = sectable[i];
        const uint32_t vsize = s.Misc.VirtualSize ? s.Misc.VirtualSize : s.SizeOfRawData;
        if (rva >= s.VirtualAddress && rva < s.VirtualAddress + vsize)
        {
            const uint32_t delta = rva - s.VirtualAddress;
            if (delta >= s.SizeOfRawData) return UINT32_MAX;
            return s.PointerToRawData + delta;
        }
    }
    return UINT32_MAX;
}

std::string DeobfValClassifier::ReadAnsiFrom(const uint8_t* data, size_t size, uint32_t off)
{
    std::string s;
    if (off >= size) return s;
    s.reserve(kStringDisplayCap);
    const size_t bound = size - off;
    for (size_t i = 0; i < kStringDisplayCap && i < bound; ++i)
    {
        const uint8_t c = data[off + i];
        if (c == 0) break;
        if (c < 0x20 || c > 0x7E) s.push_back('.');
        else                      s.push_back(static_cast<char>(c));
    }
    return s;
}

std::string DeobfValClassifier::ReadWideFrom(const uint8_t* data, size_t size, uint32_t off)
{
    std::string s;
    if (off + 1 >= size) return s;
    s.reserve(kStringDisplayCap);
    const size_t bound = size - off;
    for (size_t i = 0; i + 1 < bound && i / 2 < kStringDisplayCap; i += 2)
    {
        const uint8_t lo = data[off + i];
        const uint8_t hi = data[off + i + 1];
        if (lo == 0 && hi == 0) break;
        if (hi != 0)                     s.push_back('.');
        else if (lo < 0x20 || lo > 0x7E) s.push_back('.');
        else                             s.push_back(static_cast<char>(lo));
    }
    return s;
}

bool DeobfValClassifier::IsAnsiString(const uint64_t head[4])
{
    const uint8_t* b = reinterpret_cast<const uint8_t*>(head);
    bool printable = false;
    for (int i = 0; i < 32; ++i)
    {
        const uint8_t c = b[i];
        if (c == 0) return printable && i >= 2;
        if (c < 0x20 || c > 0x7E) return false;
        printable = true;
    }
    return printable;
}

bool DeobfValClassifier::IsWideString(const uint64_t head[4])
{
    const uint8_t* b = reinterpret_cast<const uint8_t*>(head);
    bool printable = false;
    for (int i = 0; i + 1 < 32; i += 2)
    {
        const uint8_t lo = b[i];
        const uint8_t hi = b[i + 1];
        if (lo == 0 && hi == 0) return printable && i >= 4;
        if (hi != 0) return false;
        if (lo < 0x20 || lo > 0x7E) return false;
        printable = true;
    }
    return printable;
}

std::string DeobfValClassifier::DecodeAnsi(const uint64_t head[4])
{
    const char* b = reinterpret_cast<const char*>(head);
    std::string s;
    for (int i = 0; i < 32; ++i)
    {
        if (b[i] == 0) break;
        s.push_back(b[i]);
    }
    return s;
}

std::string DeobfValClassifier::DecodeWide(const uint64_t head[4])
{
    const uint8_t* b = reinterpret_cast<const uint8_t*>(head);
    std::string s;
    for (int i = 0; i + 1 < 32; i += 2)
    {
        if (b[i] == 0 && b[i + 1] == 0) break;
        s.push_back(static_cast<char>(b[i]));
    }
    return s;
}

std::string DeobfValClassifier::DecodeInlineAscii(uint64_t val)
{
    std::string s;
    uint32_t printablerun = 0;
    for (int i = 0; i < 8; ++i)
    {
        const uint8_t c = static_cast<uint8_t>(val >> (i * 8));
        if (c == 0) break;
        if (c < 0x20 || c > 0x7E) return {};
        s.push_back(static_cast<char>(c));
        ++printablerun;
    }
    if (printablerun < 4) return {};
    return s;
}

std::ifstream DeobfValClassifier::OpenForeign(const std::wstring& path)
{
    {
        std::ifstream f(path, std::ios::binary | std::ios::ate);
        if (f) return f;
    }
    if (path.size() >= 4 && path.compare(0, 4, L"\\??\\") == 0)
    {
        std::ifstream f(path.substr(4), std::ios::binary | std::ios::ate);
        if (f) return f;
    }
    if (path.size() >= 12 &&
        (path.compare(0, 12, L"\\SystemRoot\\") == 0 ||
            path.compare(0, 12, L"\\systemroot\\") == 0))
    {
        wchar_t sysroot[MAX_PATH];
        const UINT n = GetWindowsDirectoryW(sysroot, MAX_PATH);
        if (n > 0 && n < MAX_PATH)
        {
            std::wstring win = sysroot;
            if (!win.empty() && win.back() != L'\\') win.push_back(L'\\');
            win.append(path.begin() + 12, path.end());
            std::ifstream f(win, std::ios::binary | std::ios::ate);
            if (f) return f;
        }
    }
    return std::ifstream{};
}

void DeobfValClassifier::LoadForeignPaths(const std::filesystem::path& modulestsv, std::unordered_map<std::string, std::wstring>& out)
{
    std::ifstream f(modulestsv, std::ios::binary);
    if (!f) return;
    std::string line;
    while (std::getline(f, line))
    {
        if (line.empty() || line[0] == '#') continue;
        std::vector<std::string> cols;
        size_t start = 0;
        while (start <= line.size())
        {
            size_t tab = line.find('\t', start);
            if (tab == std::string::npos)
            {
                cols.push_back(line.substr(start));
                break;
            }
            cols.push_back(line.substr(start, tab - start));
            start = tab + 1;
        }
        if (cols.size() < 4) continue;
        const std::string& name = cols[0];
        if (name.empty() || name == "__traced__") continue;
        std::string pathutf8 = cols.back();
        while (!pathutf8.empty() && (pathutf8.back() == '\r' || pathutf8.back() == '\n')) pathutf8.pop_back();
        if (pathutf8.empty()) continue;
        const int nw = MultiByteToWideChar(CP_UTF8, 0, pathutf8.data(), static_cast<int>(pathutf8.size()), nullptr, 0);
        if (nw <= 0) continue;
        std::wstring pathw(static_cast<size_t>(nw), L'\0');
        MultiByteToWideChar(CP_UTF8, 0, pathutf8.data(), static_cast<int>(pathutf8.size()), pathw.data(), nw);
        out.emplace(name, std::move(pathw));
    }
}