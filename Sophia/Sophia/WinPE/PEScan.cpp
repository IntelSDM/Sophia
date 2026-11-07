#include "../../Pch.h"
#include "PeScan.h"
#include "PEScanHelpers.h"

#include <Zydis/Zydis.h>

std::vector<InsnSite> PeScan::ScanFile(const std::string& filepath, uint64_t& preferredbase, const ScanOptions& opts)
{
    std::vector<InsnSite> sites;
    preferredbase = 0;

    std::ifstream f(filepath, std::ios::binary | std::ios::ate);
    if (!f)
    {
        std::fprintf(stderr, "[!] could not open %s\n", filepath.c_str());
        return sites;
    }

    const std::streamoff len = f.tellg();
    if (len < static_cast<std::streamoff>(sizeof(IMAGE_DOS_HEADER)))
    {
        std::fprintf(stderr, "[!] file too small to be a PE (%lld bytes)\n", static_cast<long long>(len));
        return sites;
    }

    f.seekg(0);
    std::vector<uint8_t> buf(static_cast<size_t>(len));
    f.read(reinterpret_cast<char*>(buf.data()), len);
    if (!f)
    {
        std::fprintf(stderr, "[!] short read on %s\n", filepath.c_str());
        return sites;
    }

    auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(buf.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
    {
        std::fprintf(stderr, "[!] no MZ signature\n");
        return sites;
    }
    if (dos->e_lfanew <= 0 || static_cast<size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS64) > buf.size())
    {
        std::fprintf(stderr, "[!] bad e_lfanew (0x%lx)\n", static_cast<unsigned long>(dos->e_lfanew));
        return sites;
    }

    auto nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(buf.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
    {
        std::fprintf(stderr, "[!] no PE signature\n");
        return sites;
    }
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
    {
        std::fprintf(stderr, "[!] not an x64 image (this test scans x64 only)\n");
        return sites;
    }

    preferredbase = nt->OptionalHeader.ImageBase;
    const uint64_t imagesize = nt->OptionalHeader.SizeOfImage;

    const WORD nsec = nt->FileHeader.NumberOfSections;
    auto sec = reinterpret_cast<const IMAGE_SECTION_HEADER*>(IMAGE_FIRST_SECTION(nt));
    const uint8_t* bufbeg = buf.data();
    const uint8_t* bufend = buf.data() + buf.size();

    if (reinterpret_cast<const uint8_t*>(sec) < bufbeg || reinterpret_cast<const uint8_t*>(sec) + static_cast<size_t>(nsec) * sizeof(IMAGE_SECTION_HEADER) > bufend)
    {
        std::fprintf(stderr, "[!] section table out of bounds\n");
        return sites;
    }

    ZydisDecoder decoder;
    if (!ZYAN_SUCCESS(ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64)))
    {
        std::fprintf(stderr, "[!] ZydisDecoderInit failed\n");
        return sites;
    }

    auto sectionallowed = [&opts](const char* namefield) -> bool
        {
            if (opts.Sections.empty()) return true;
            char clean[9] = {};
            std::memcpy(clean, namefield, 8);
            for (int i = 0; i < 8 && clean[i]; ++i)
                clean[i] = static_cast<char>(std::tolower(static_cast<unsigned char>(clean[i])));
            for (const std::string& want : opts.Sections)
            {
                std::string w = want;
                for (char& c : w)
                    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
                if (std::strcmp(clean, w.c_str()) == 0) return true;
            }
            return false;
        };

    auto sectionskippedbyprefix = [&opts](const char* namefield) -> const char*
        {
            if (opts.SkipSectionPrefixes.empty()) return nullptr;
            char clean[9] = {};
            std::memcpy(clean, namefield, 8);
            for (int i = 0; i < 8 && clean[i]; ++i)
                clean[i] = static_cast<char>(std::tolower(static_cast<unsigned char>(clean[i])));
            for (const std::string& pfx : opts.SkipSectionPrefixes)
            {
                std::string p = pfx;
                for (char& c : p)
                    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
                if (p.empty()) continue;
                if (std::strncmp(clean, p.c_str(), p.size()) == 0)
                {
                    static thread_local std::string last;
                    last = pfx;
                    return last.c_str();
                }
            }
            return nullptr;
        };

    if (opts.Ranges.empty())
    {
        for (WORD i = 0; i < nsec; ++i)
        {
            const IMAGE_SECTION_HEADER& s = sec[i];

            const bool executable = (s.Characteristics & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE)) != 0;
            if (!executable) continue;

            char name[9] = {};
            std::memcpy(name, s.Name, 8);

            if (!sectionallowed(name))
            {
                std::printf("[pescan]   section %-8s  SKIPPED (not in filter)\n", name);
                continue;
            }
            if (const char* pfx = sectionskippedbyprefix(name))
            {
                std::printf("[pescan]   section %-8s  SKIPPED (prefix \"%s\" -- e.g. driver INIT section)\n", name, pfx);
                continue;
            }

            uint64_t raw = s.PointerToRawData;
            uint64_t rawsize = s.SizeOfRawData;
            if (raw == 0 || rawsize == 0)   continue;
            if (raw >= buf.size())          continue;
            if (raw + rawsize > buf.size()) rawsize = buf.size() - raw;

            const size_t before = sites.size();
            PeScanHelpers::ScanSection(&decoder, buf.data() + raw, static_cast<size_t>(rawsize), raw, s.VirtualAddress, sites);

            std::printf("[pescan]   section %-8s  raw=0x%llx..0x%llx  rva=0x%x  sites=%zu\n",
                name,
                static_cast<unsigned long long>(raw),
                static_cast<unsigned long long>(raw + rawsize),
                s.VirtualAddress,
                sites.size() - before);
        }
    }
    else
    {
        std::printf("[pescan] range-restricted: %zu range(s)\n", opts.Ranges.size());
        for (const ScanOptions::Range& r : opts.Ranges)
        {
            const IMAGE_SECTION_HEADER* host = nullptr;
            for (WORD i = 0; i < nsec; ++i)
            {
                const IMAGE_SECTION_HEADER& s = sec[i];
                if (r.Rva >= s.VirtualAddress && r.Rva < s.VirtualAddress + s.Misc.VirtualSize)
                {
                    host = &s;
                    break;
                }
            }
            if (!host)
            {
                std::fprintf(stderr, "[pescan] range rva=0x%llx size=0x%llx outside every section -- skipped\n",
                    static_cast<unsigned long long>(r.Rva),
                    static_cast<unsigned long long>(r.Size));
                continue;
            }
            const bool executable = (host->Characteristics & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE)) != 0;
            if (!executable)
            {
                std::fprintf(stderr, "[pescan] range rva=0x%llx lives in a non-executable section -- skipped\n",
                    static_cast<unsigned long long>(r.Rva));
                continue;
            }
            {
                char hostname[9] = {};
                std::memcpy(hostname, host->Name, 8);
                if (const char* pfx = sectionskippedbyprefix(hostname))
                {
                    std::fprintf(stderr, "[pescan] range rva=0x%llx lives in section %-8s matching skip-prefix \"%s\" -- skipped\n",
                        static_cast<unsigned long long>(r.Rva), hostname, pfx);
                    continue;
                }
            }

            uint64_t raw = host->PointerToRawData;
            uint64_t rawsize = host->SizeOfRawData;
            if (raw + rawsize > buf.size()) rawsize = buf.size() - raw;

            const uint64_t offinsection = r.Rva - host->VirtualAddress;
            if (offinsection >= rawsize)
            {
                std::fprintf(stderr, "[pescan] range rva=0x%llx past section raw tail -- skipped\n",
                    static_cast<unsigned long long>(r.Rva));
                continue;
            }
            uint64_t slicesize = r.Size;
            if (offinsection + slicesize > rawsize)
                slicesize = rawsize - offinsection;

            char name[9] = {};
            std::memcpy(name, host->Name, 8);

            const size_t before = sites.size();
            PeScanHelpers::ScanSection(&decoder, buf.data() + raw + offinsection, static_cast<size_t>(slicesize), raw + offinsection, static_cast<uint64_t>(r.Rva), sites);

            std::printf("[pescan]   %-8s  rva=0x%llx..0x%llx  (%llu B)  sites=%zu\n",
                name,
                static_cast<unsigned long long>(r.Rva),
                static_cast<unsigned long long>(r.Rva + slicesize),
                static_cast<unsigned long long>(slicesize),
                sites.size() - before);
        }

        sites.erase(std::remove_if(sites.begin(), sites.end(),
            [&opts](const InsnSite& s)
            {
                for (const ScanOptions::Range& r : opts.Ranges)
                {
                    if (s.Rva >= r.Rva && s.Rva < r.Rva + r.Size) return false;
                }
                return true;
            }), sites.end());
    }

    if (imagesize != 0)
    {
        const size_t before = sites.size();
        sites.erase(std::remove_if(sites.begin(), sites.end(),
            [imagesize](const InsnSite& j) {
                return (j.Kind == SiteKind::Branch || j.Kind == SiteKind::Call) && j.ToRva >= imagesize;
            }),
            sites.end());
        const size_t dropped = before - sites.size();
        if (dropped)
        {
            std::printf("[pescan] dropped %zu jump(s) with out-of-image targets (naive-scan false positives)\n", dropped);
        }
    }

    return sites;
}