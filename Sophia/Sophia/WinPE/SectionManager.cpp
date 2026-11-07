#include "../../Pch.h"
#include "SectionManager.h"

bool SectionManager::AppendPeSection(std::vector<uint8_t>& buf, const char* name, const std::vector<uint8_t>& content, uint32_t& outrva, uint32_t characteristics)
{
    outrva = 0;
    if (buf.size() < sizeof(IMAGE_DOS_HEADER)) return false;
    auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(buf.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    if (dos->e_lfanew <= 0 || static_cast<size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS64) > buf.size()) return false;
    auto nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(buf.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

    const WORD nsec = nt->FileHeader.NumberOfSections;
    auto sectable = reinterpret_cast<IMAGE_SECTION_HEADER*>(IMAGE_FIRST_SECTION(nt));

    const uint32_t nexthdroff = static_cast<uint32_t>(reinterpret_cast<uint8_t*>(&sectable[nsec]) - buf.data());
    if (nexthdroff + sizeof(IMAGE_SECTION_HEADER) > nt->OptionalHeader.SizeOfHeaders) return false;

    const uint32_t filealign = nt->OptionalHeader.FileAlignment ? nt->OptionalHeader.FileAlignment : 0x200;
    const uint32_t sectalign = nt->OptionalHeader.SectionAlignment ? nt->OptionalHeader.SectionAlignment : 0x1000;

    auto alignup = [](uint64_t v, uint32_t a) -> uint64_t
        {
            return (v + (a - 1)) & ~static_cast<uint64_t>(a - 1);
        };

    uint64_t maxendrva = 0;
    for (WORD i = 0; i < nsec; ++i)
    {
        const uint64_t end = static_cast<uint64_t>(sectable[i].VirtualAddress) + sectable[i].Misc.VirtualSize;
        if (end > maxendrva) maxendrva = end;
    }
    const uint32_t newrva = static_cast<uint32_t>(alignup(maxendrva, sectalign));

    const uint64_t oldfilesize = buf.size();
    const uint32_t newrawoff = static_cast<uint32_t>(alignup(oldfilesize, filealign));

    const uint32_t rawsize = static_cast<uint32_t>(alignup(content.size(), filealign));

    buf.resize(newrawoff, 0);
    buf.resize(static_cast<size_t>(newrawoff) + rawsize, 0);
    if (!content.empty())
    {
        std::memcpy(buf.data() + newrawoff, content.data(), content.size());
    }

    dos = reinterpret_cast<IMAGE_DOS_HEADER*>(buf.data());
    nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(buf.data() + dos->e_lfanew);
    sectable = reinterpret_cast<IMAGE_SECTION_HEADER*>(IMAGE_FIRST_SECTION(nt));

    IMAGE_SECTION_HEADER& h = sectable[nsec];
    std::memset(&h, 0, sizeof(h));
    std::memcpy(h.Name, name, std::min<size_t>(8, std::strlen(name)));
    h.Misc.VirtualSize = static_cast<uint32_t>(content.size());
    h.VirtualAddress = newrva;
    h.SizeOfRawData = rawsize;
    h.PointerToRawData = newrawoff;
    h.Characteristics = characteristics;

    nt->FileHeader.NumberOfSections = static_cast<WORD>(nsec + 1);
    const uint64_t newimageend = static_cast<uint64_t>(newrva) + alignup(content.size() == 0 ? 1 : content.size(), sectalign);
    if (newimageend > nt->OptionalHeader.SizeOfImage)
        nt->OptionalHeader.SizeOfImage = static_cast<uint32_t>(alignup(newimageend, sectalign));

    if (characteristics & IMAGE_SCN_CNT_CODE)
        nt->OptionalHeader.SizeOfCode += rawsize;
    if (characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA)
        nt->OptionalHeader.SizeOfInitializedData += rawsize;

    outrva = newrva;
    return true;
}