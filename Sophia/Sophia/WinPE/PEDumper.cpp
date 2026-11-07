#include "../../Pch.h"
#include "PEDumper.h"

bool PEDumper::ExtractFirstHex(const std::string& s, uint64_t& value)
{
    auto pos = s.find("0x");
    if (pos == std::string::npos)
    {
        return false;
    }
    pos += 2;
    uint64_t v = 0;
    bool any = false;
    while (pos < s.size())
    {
        char c = s[pos];
        int d;
        if (c >= '0' && c <= '9') d = c - '0';
        else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
        else break;
        v = (v << 4) | d;
        any = true;
        ++pos;
    }
    if (!any) return false;
    value = v;
    return true;
}

uint32_t PEDumper::ParseFieldOffset(const std::string& dump, const std::string& fieldname)
{
    size_t linestart = 0;
    while (linestart < dump.size())
    {
        size_t lineend = dump.find('\n', linestart);
        if (lineend == std::string::npos) lineend = dump.size();

        size_t p = linestart;
        while (p < lineend && (dump[p] == ' ' || dump[p] == '\t')) ++p;

        if (p + 3 > lineend || dump.compare(p, 3, "+0x") != 0)
        {
            linestart = lineend + 1;
            continue;
        }
        p += 3;

        uint32_t off = 0;
        bool any = false;
        while (p < lineend)
        {
            char c = dump[p];
            int d;
            if (c >= '0' && c <= '9') d = c - '0';
            else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
            else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
            else break;
            off = (off << 4) | d;
            any = true;
            ++p;
        }
        if (!any)
        {
            linestart = lineend + 1;
            continue;
        }

        size_t nameend = lineend;
        for (size_t i = p; i < lineend; ++i)
        {
            if (dump[i] == '[' || dump[i] == ',')
            {
                nameend = i;
                break;
            }
        }
        while (nameend > p && (dump[nameend - 1] == ' ' || dump[nameend - 1] == '\t' || dump[nameend - 1] == '\r'))
        {
            --nameend;
        }
        size_t namestart = nameend;
        while (namestart > p)
        {
            char c = dump[namestart - 1];
            bool isword = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_';
            if (!isword) break;
            --namestart;
        }

        size_t namelen = nameend - namestart;
        if (namelen == fieldname.size() && dump.compare(namestart, namelen, fieldname) == 0)
        {
            return off;
        }

        linestart = lineend + 1;
    }
    return UINT32_MAX;
}

bool PEDumper::ExtractKernelVaFromDbOutput(const std::string& s, uint64_t& value)
{
    size_t linestart = 0;
    while (linestart < s.size())
    {
        size_t lineend = s.find('\n', linestart);
        if (lineend == std::string::npos) lineend = s.size();

        size_t p = linestart;
        while (p < lineend && (s[p] == ' ' || s[p] == '\t')) ++p;
        if (p + 1 < lineend && s[p] == '0' && (s[p + 1] == 'x' || s[p + 1] == 'X'))
        {
            p += 2;
        }

        uint64_t v = 0;
        int digits = 0;
        while (p < lineend)
        {
            char c = s[p];
            int d;
            if (c >= '0' && c <= '9') d = c - '0';
            else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
            else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
            else if (c == '`') { ++p; continue; }
            else break;
            v = (v << 4) | d;
            ++digits;
            ++p;
        }

        if (digits >= 12 && v >= 0xFFFF800000000000ULL)
        {
            value = v;
            return true;
        }

        linestart = lineend + 1;
    }
    return false;
}

PEDumper::PEDumper(HyperDbgSession& session) : Session(session)
{
}

void PEDumper::EnsureKernelSymbolsLoaded()
{
    Session.Run(".sym reload");
}

uint64_t PEDumper::ResolveKernelSymbol(const std::string& name)
{
    std::string resp = Session.Run("db " + name + " l 10");
    uint64_t v = 0;
    if (!ExtractKernelVaFromDbOutput(resp, v))
    {
        throw std::runtime_error("PEDumper: kernel symbol resolve failed: " + name + "  (response: " + resp.substr(0, 256) + ")");
    }
    return v;
}

uint32_t PEDumper::ResolveStructFieldOffset(const std::string& structname, const std::string& fieldname)
{
    std::string resp = Session.Run("dt " + structname);
    uint32_t off = ParseFieldOffset(resp, fieldname);
    if (off == UINT32_MAX)
    {
        throw std::runtime_error("PEDumper: struct field offset resolve failed: " + structname + "." + fieldname);
    }
    return off;
}

void PEDumper::EnsureCache()
{
    if (Ck.Ready)
    {
        return;
    }

    EnsureKernelSymbolsLoaded();

    Ck.PsActiveProcessHead = ResolveKernelSymbol("nt!PsActiveProcessHead");
    Ck.PsLoadedModuleList = ResolveKernelSymbol("nt!PsLoadedModuleList");
    Ck.EprocessUniqueProcessId = ResolveStructFieldOffset("nt!_EPROCESS", "UniqueProcessId");
    Ck.EprocessActiveProcessLinks = ResolveStructFieldOffset("nt!_EPROCESS", "ActiveProcessLinks");
    Ck.EprocessPeb = ResolveStructFieldOffset("nt!_EPROCESS", "Peb");
    Ck.EprocessImageFileName = ResolveStructFieldOffset("nt!_EPROCESS", "ImageFileName");
    Ck.EprocessSectionBaseAddress = ResolveStructFieldOffset("nt!_EPROCESS", "SectionBaseAddress");
    Ck.EprocessSeAuditProcessCreationInfo = ResolveStructFieldOffset("nt!_EPROCESS", "SeAuditProcessCreationInfo");

    Ck.Ready = true;

    std::printf(
        "[+] PEDumper: cached symbols / offsets\n"
        "      nt!PsActiveProcessHead      = 0x%016llx\n"
        "      nt!PsLoadedModuleList       = 0x%016llx\n"
        "      _EPROCESS.UniqueProcessId   = +0x%x\n"
        "      _EPROCESS.ActiveProcessLinks= +0x%x\n"
        "      _EPROCESS.Peb               = +0x%x\n"
        "      _EPROCESS.ImageFileName     = +0x%x\n"
        "      _EPROCESS.SectionBaseAddress= +0x%x\n"
        "      _EPROCESS.SeAuditProcCreate = +0x%x\n",
        static_cast<unsigned long long>(Ck.PsActiveProcessHead),
        static_cast<unsigned long long>(Ck.PsLoadedModuleList),
        Ck.EprocessUniqueProcessId,
        Ck.EprocessActiveProcessLinks,
        Ck.EprocessPeb,
        Ck.EprocessImageFileName,
        Ck.EprocessSectionBaseAddress,
        Ck.EprocessSeAuditProcessCreationInfo);
}

void PEDumper::PrimeCache()
{
    EnsureCache();
}

bool PEDumper::ReadK(uint64_t va, void* out, uint32_t size)
{
    return Session.Read(4, va, out, size);
}

bool PEDumper::ReadU(uint32_t pid, uint64_t va, void* out, uint32_t size)
{
    return Session.Read(pid, va, out, size, HyperDbgMemory::ReadPath::FromVmxRoot);
}

uint32_t PEDumper::ReadKRobust(uint64_t va, uint8_t* out, uint32_t size)
{
    return Session.ReadRobust(4, va, out, size);
}

uint32_t PEDumper::ReadURobust(uint32_t pid, uint64_t va, uint8_t* out, uint32_t size)
{
    return Session.ReadRobust(pid, va, out, size, HyperDbgMemory::ReadPath::FromVmxRoot);
}

bool PEDumper::ReadUnicodeString(AddressSpace space, uint32_t pid, uint64_t ustringva, std::wstring& out)
{
    struct
    {
        uint16_t Length;
        uint16_t MaximumLength;
        uint32_t Pad;
        uint64_t Buffer;
    } us = {};

    bool ok = (space == AddressSpace::Kernel) ? ReadK(ustringva, &us, sizeof(us)) : ReadU(pid, ustringva, &us, sizeof(us));
    if (!ok) return false;

    if (us.Length == 0 || us.Buffer == 0)
    {
        out.clear();
        return true;
    }

    uint32_t bytes = (std::min)(static_cast<uint32_t>(us.Length), 0x800u);
    uint32_t chars = bytes / 2;
    std::wstring buf(chars, L'\0');

    ok = (space == AddressSpace::Kernel) ? ReadK(us.Buffer, buf.data(), chars * 2) : ReadU(pid, us.Buffer, buf.data(), chars * 2);
    if (!ok) return false;

    out = std::move(buf);
    return true;
}

std::string PEDumper::ToLower(const std::string& s)
{
    std::string result = s;
    for (auto& c : result)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return result;
}

std::string PEDumper::ProcessImageNameLower(uint64_t eproc)
{
    std::string name;

    if (Ck.EprocessSeAuditProcessCreationInfo != 0)
    {
        uint64_t objnameinfo = 0;
        if (ReadK(eproc + Ck.EprocessSeAuditProcessCreationInfo, &objnameinfo, sizeof(objnameinfo)) && objnameinfo != 0)
        {
            std::wstring fullw;
            if (ReadUnicodeString(AddressSpace::Kernel, 0, objnameinfo, fullw) && !fullw.empty())
            {
                size_t slash = fullw.find_last_of(L"\\/");
                std::wstring basew = (slash == std::wstring::npos) ? fullw : fullw.substr(slash + 1);
                name.assign(basew.begin(), basew.end());
            }
        }
    }

    if (name.empty())
    {
        char raw[16] = {};
        if (ReadK(eproc + Ck.EprocessImageFileName, raw, 15))
        {
            raw[15] = '\0';
            name = raw;
        }
    }

    return ToLower(name);
}

uint64_t PEDumper::FindEProcess(uint32_t pid)
{
    EnsureCache();

    uint64_t listhead = Ck.PsActiveProcessHead;
    uint64_t flink = 0;
    if (!ReadK(listhead, &flink, sizeof(flink)))
    {
        throw std::runtime_error("PEDumper: read PsActiveProcessHead.Flink failed");
    }

    uint64_t entry = flink;
    int guard = 0;
    while (entry != listhead && entry != 0 && guard++ < 65536)
    {
        uint64_t eproc = entry - Ck.EprocessActiveProcessLinks;
        uint64_t upid = 0;
        uint64_t nextflink = 0;

        if (!ReadK(eproc + Ck.EprocessUniqueProcessId, &upid, sizeof(upid)))
        {
            break;
        }
        if (!ReadK(entry, &nextflink, sizeof(nextflink)))
        {
            break;
        }

        if (static_cast<uint32_t>(upid) == pid)
        {
            return eproc;
        }

        entry = nextflink;
    }

    return 0;
}

uint32_t PEDumper::FindPidByImageName(const std::string& imagename)
{
    EnsureCache();

    const std::string targetlower = ToLower(imagename);

    uint64_t listhead = Ck.PsActiveProcessHead;
    uint64_t flink = 0;
    if (!ReadK(listhead, &flink, sizeof(flink)))
    {
        return 0;
    }

    uint64_t entry = flink;
    int guard = 0;
    while (entry != listhead && entry != 0 && guard++ < 65536)
    {
        uint64_t eproc = entry - Ck.EprocessActiveProcessLinks;

        uint64_t upid = 0;
        uint64_t nextflink = 0;

        if (!ReadK(eproc + Ck.EprocessUniqueProcessId, &upid, sizeof(upid))) break;
        if (!ReadK(entry, &nextflink, sizeof(nextflink))) break;

        if (ProcessImageNameLower(eproc) == targetlower)
        {
            return static_cast<uint32_t>(upid);
        }

        entry = nextflink;
    }

    return 0;
}

uint32_t PEDumper::FindLivePidByImageName(const std::string& imagename)
{
    EnsureCache();

    const std::string targetlower = ToLower(imagename);

    uint64_t listhead = Ck.PsActiveProcessHead;
    uint64_t flink = 0;
    if (!ReadK(listhead, &flink, sizeof(flink)))
    {
        return 0;
    }

    uint32_t firstmatch = 0;
    uint32_t livematch = 0;
    int      matches = 0;

    uint64_t entry = flink;
    int guard = 0;
    while (entry != listhead && entry != 0 && guard++ < 65536)
    {
        uint64_t eproc = entry - Ck.EprocessActiveProcessLinks;

        uint64_t upid = 0;
        uint64_t nextflink = 0;

        if (!ReadK(eproc + Ck.EprocessUniqueProcessId, &upid, sizeof(upid))) break;
        if (!ReadK(entry, &nextflink, sizeof(nextflink))) break;

        if (ProcessImageNameLower(eproc) == targetlower)
        {
            ++matches;
            uint32_t pid = static_cast<uint32_t>(upid);
            if (firstmatch == 0) firstmatch = pid;

            uint64_t sectionbase = 0;
            ReadK(eproc + Ck.EprocessSectionBaseAddress, &sectionbase, sizeof(sectionbase));

            bool readable = false;
            if (sectionbase != 0)
            {
                IMAGE_DOS_HEADER dos = {};
                readable = ReadU(pid, sectionbase, &dos, sizeof(dos)) && dos.e_magic == IMAGE_DOS_SIGNATURE;
            }

            std::fprintf(stderr,
                "[dump]   candidate '%s' pid=%u sectionBase=0x%llx  user-AS=%s\n",
                imagename.c_str(), pid,
                static_cast<unsigned long long>(sectionbase),
                readable ? "readable" : "UNREADABLE (dead/zombie?)");

            if (readable && livematch == 0) livematch = pid;
        }

        entry = nextflink;
    }

    if (matches > 1)
    {
        std::fprintf(stderr,
            "[dump] %d processes named '%s' -- name is ambiguous (renamed binary "
            "colliding with the real one, or stale instances from prior launches).\n"
            "[dump] choosing pid %u (first with a live address space)%s\n",
            matches, imagename.c_str(),
            livematch ? livematch : firstmatch,
            livematch ? "" : " -- NONE readable, falling back to first match");
    }

    return livematch ? livematch : firstmatch;
}

std::vector<uint32_t> PEDumper::EnumeratePidsByImageName(const std::string& imagename)
{
    EnsureCache();

    const std::string targetlower = ToLower(imagename);

    std::vector<uint32_t> pids;

    uint64_t listhead = Ck.PsActiveProcessHead;
    uint64_t flink = 0;
    if (!ReadK(listhead, &flink, sizeof(flink)))
    {
        return pids;
    }

    uint64_t entry = flink;
    int guard = 0;
    while (entry != listhead && entry != 0 && guard++ < 65536)
    {
        uint64_t eproc = entry - Ck.EprocessActiveProcessLinks;

        uint64_t upid = 0;
        uint64_t nextflink = 0;

        if (!ReadK(eproc + Ck.EprocessUniqueProcessId, &upid, sizeof(upid))) break;
        if (!ReadK(entry, &nextflink, sizeof(nextflink))) break;

        if (ProcessImageNameLower(eproc) == targetlower)
        {
            pids.push_back(static_cast<uint32_t>(upid));
        }

        entry = nextflink;
    }

    return pids;
}

void PEDumper::PrintProcessRoster()
{
    EnsureCache();

    std::fprintf(stderr,
        "[roster] PsActiveProcessHead=0x%llx  offsets: UPID=+0x%x LINKS=+0x%x "
        "PEB=+0x%x NAME=+0x%x SECBASE=+0x%x\n",
        static_cast<unsigned long long>(Ck.PsActiveProcessHead),
        Ck.EprocessUniqueProcessId, Ck.EprocessActiveProcessLinks,
        Ck.EprocessPeb, Ck.EprocessImageFileName, Ck.EprocessSectionBaseAddress);

    uint64_t listhead = Ck.PsActiveProcessHead;
    uint64_t flink = 0;
    if (!ReadK(listhead, &flink, sizeof(flink)))
    {
        std::fprintf(stderr,
            "[roster] FAILED to read PsActiveProcessHead.Flink -- the kernel walk "
            "is broken at the head (bad symbol, or ReadK not working)\n");
        return;
    }

    const char* term = "guard limit hit (list loop?)";
    int count = 0;
    uint64_t entry = flink;
    int guard = 0;
    while (guard++ < 65536)
    {
        if (entry == listhead) { term = "clean (looped back to head)"; break; }
        if (entry == 0) { term = "null Flink"; break; }

        uint64_t eproc = entry - Ck.EprocessActiveProcessLinks;

        unsigned char name[16] = {};
        uint64_t upid = 0, peb = 0, secbase = 0, nextflink = 0;

        if (!ReadK(eproc + Ck.EprocessImageFileName, name, 15))
        {
            term = "read ImageFileName failed"; break;
        }
        if (!ReadK(eproc + Ck.EprocessUniqueProcessId, &upid, sizeof(upid)))
        {
            term = "read UniqueProcessId failed"; break;
        }
        ReadK(eproc + Ck.EprocessPeb, &peb, sizeof(peb));
        ReadK(eproc + Ck.EprocessSectionBaseAddress, &secbase, sizeof(secbase));
        if (!ReadK(entry, &nextflink, sizeof(nextflink)))
        {
            term = "read ActiveProcessLinks.Flink failed"; break;
        }

        char ascii[16] = {};
        for (int i = 0; i < 15; ++i)
            ascii[i] = (name[i] >= 0x20 && name[i] < 0x7f) ? static_cast<char>(name[i]) : '.';

        std::string full = ProcessImageNameLower(eproc);

        const char* uas = "no-secbase";
        if (secbase != 0)
        {
            uint16_t mz = 0;
            if (ReadU(static_cast<uint32_t>(upid), secbase, &mz, sizeof(mz)))
                uas = (mz == IMAGE_DOS_SIGNATURE) ? "READS(MZ)" : "reads(non-MZ)";
            else
                uas = "UNREADABLE";
        }

        std::fprintf(stderr,
            "[roster] eproc=0x%012llx pid=%-6u inline15='%s' full='%s'"
            " peb=0x%llx secbase=0x%llx uAS=%s\n",
            static_cast<unsigned long long>(eproc),
            static_cast<uint32_t>(upid), ascii, full.c_str(),
            static_cast<unsigned long long>(peb),
            static_cast<unsigned long long>(secbase), uas);

        ++count;
        entry = nextflink;
    }

    std::fprintf(stderr, "[roster] %d process(es) walked; termination: %s\n", count, term);
}

std::vector<PEDumper::LoadedModule> PEDumper::EnumerateProcessModules(uint32_t pid)
{
    EnsureCache();

    uint64_t eproc = FindEProcess(pid);
    if (eproc == 0)
    {
        throw std::runtime_error("PEDumper: pid " + std::to_string(pid) + " not found in PsActiveProcessHead");
    }

    uint64_t peb = 0;
    if (!ReadK(eproc + Ck.EprocessPeb, &peb, sizeof(peb)))
    {
        throw std::runtime_error("PEDumper: read EPROCESS.Peb failed");
    }
    if (peb == 0)
    {
        throw std::runtime_error("PEDumper: EPROCESS.Peb is null (pid=System, or process gone)");
    }

    uint64_t ldr = 0;
    bool pebldrok = ReadU(pid, peb + OffPebLdr, &ldr, sizeof(ldr)) && ldr != 0;

    if (!pebldrok)
    {
        uint64_t sectionbase = 0;
        ReadK(eproc + Ck.EprocessSectionBaseAddress, &sectionbase, sizeof(sectionbase));

        std::printf(
            "[!] PEDumper: PEB.Ldr unreadable for pid %u "
            "(peb=0x%llx ldr=0x%llx sectionBase=0x%llx)\n"
            "[!]           probing main image directly to tell anti-dump from a bad pid...\n",
            pid,
            static_cast<unsigned long long>(peb),
            static_cast<unsigned long long>(ldr),
            static_cast<unsigned long long>(sectionbase));

        if (sectionbase == 0)
        {
            throw std::runtime_error("PEDumper: PEB.Ldr unreadable AND SectionBaseAddress is null -- the resolved pid has no primary image (wrong or dead pid).");
        }

        IMAGE_DOS_HEADER dos = {};
        IMAGE_NT_HEADERS64 nt = {};
        bool hdrok = ReadU(pid, sectionbase, &dos, sizeof(dos)) && dos.e_magic == IMAGE_DOS_SIGNATURE && ReadU(pid, sectionbase + dos.e_lfanew, &nt, sizeof(nt)) && nt.Signature == IMAGE_NT_SIGNATURE;

        if (!hdrok)
        {
            throw std::runtime_error("PEDumper: user memory of pid " + std::to_string(pid) + " is unreadable at BOTH PEB and SectionBaseAddress -- this pid is not the live traced process. Drive the dump off the pid that !pt enable path launched, or point FindPidByImageName at the instance that owns the traced VA range.");
        }

        char imagename[16] = {};
        ReadK(eproc + Ck.EprocessImageFileName, imagename, 15);
        std::string nm(imagename);

        LoadedModule m{};
        m.Base = sectionbase;
        m.Size = nt.OptionalHeader.SizeOfImage;
        m.Space = AddressSpace::User;
        m.Pid = pid;
        m.BaseName.assign(nm.begin(), nm.end());

        std::printf(
            "[+] PEDumper: main image readable at 0x%llx (SizeOfImage 0x%x) -- PEB "
            "is scrubbed (anti-dump).\n"
            "[+]           dumping main module '%ls' only (via SectionBaseAddress).\n",
            static_cast<unsigned long long>(sectionbase),
            m.Size, m.BaseName.c_str());

        return { m };
    }

    uint64_t listhead = ldr + OffLdrInLoadOrder;
    uint64_t entry = 0;
    if (!ReadU(pid, listhead, &entry, sizeof(entry)))
    {
        throw std::runtime_error("PEDumper: read InLoadOrderModuleList.Flink failed");
    }

    std::vector<LoadedModule> mods;
    int guard = 0;
    while (entry != 0 && entry != listhead && guard++ < 4096)
    {
        uint64_t nextflink = 0;
        uint64_t dllbase = 0;
        uint32_t sizeofimage = 0;

        bool ok = ReadU(pid, entry, &nextflink, sizeof(nextflink))
            && ReadU(pid, entry + OffLdteDllBase, &dllbase, sizeof(dllbase))
            && ReadU(pid, entry + OffLdteSizeOfImage, &sizeofimage, sizeof(sizeofimage));
        if (!ok) break;

        if (dllbase != 0 && sizeofimage != 0)
        {
            LoadedModule m{};
            m.Base = dllbase;
            m.Size = sizeofimage;
            m.Space = AddressSpace::User;
            m.Pid = pid;
            ReadUnicodeString(AddressSpace::User, pid, entry + OffLdteBaseDllName, m.BaseName);
            ReadUnicodeString(AddressSpace::User, pid, entry + OffLdteFullDllName, m.FullPath);
            mods.push_back(std::move(m));
        }

        entry = nextflink;
    }

    return mods;
}

std::vector<PEDumper::LoadedModule> PEDumper::EnumerateKernelModules()
{
    EnsureCache();

    uint64_t listhead = Ck.PsLoadedModuleList;
    uint64_t entry = 0;
    if (!ReadK(listhead, &entry, sizeof(entry)))
    {
        throw std::runtime_error("PEDumper: read PsLoadedModuleList.Flink failed");
    }

    std::vector<LoadedModule> mods;
    int guard = 0;
    while (entry != 0 && entry != listhead && guard++ < 4096)
    {
        uint64_t nextflink = 0;
        uint64_t dllbase = 0;
        uint32_t sizeofimage = 0;

        bool ok = ReadK(entry, &nextflink, sizeof(nextflink))
            && ReadK(entry + OffLdteDllBase, &dllbase, sizeof(dllbase))
            && ReadK(entry + OffLdteSizeOfImage, &sizeofimage, sizeof(sizeofimage));
        if (!ok) break;

        if (dllbase != 0 && sizeofimage != 0)
        {
            LoadedModule m{};
            m.Base = dllbase;
            m.Size = sizeofimage;
            m.Space = AddressSpace::Kernel;
            m.Pid = 0;
            ReadUnicodeString(AddressSpace::Kernel, 0, entry + OffLdteBaseDllName, m.BaseName);
            ReadUnicodeString(AddressSpace::Kernel, 0, entry + OffLdteFullDllName, m.FullPath);
            mods.push_back(std::move(m));
        }

        entry = nextflink;
    }

    return mods;
}

uint32_t PEDumper::BackfillFromDisk(const LoadedModule& mod, std::vector<uint8_t>& buf, bool includecode)
{
    std::error_code ec;
    std::filesystem::path path = mod.FullPath;
    if (!std::filesystem::exists(path, ec))
    {
        const std::wstring& w = mod.FullPath;
        if (w.rfind(L"\\??\\", 0) == 0)
        {
            path = w.substr(4);
        }
        else if (w.rfind(L"\\SystemRoot\\", 0) == 0)
        {
            wchar_t win[MAX_PATH] = {};
            if (GetWindowsDirectoryW(win, MAX_PATH))
            {
                path = std::filesystem::path(win) / w.substr(12);
            }
        }
        if (!std::filesystem::exists(path, ec))
        {
            std::printf("[!] PEDumper: backfill skipped for %ls (file not found: %ls)\n", mod.BaseName.c_str(), mod.FullPath.c_str());
            return 0;
        }
    }

    std::ifstream in(path, std::ios::binary | std::ios::ate);
    if (!in) return 0;
    std::streamsize flen = in.tellg();
    in.seekg(0);
    std::vector<uint8_t> file(static_cast<size_t>(flen));
    if (!in.read(reinterpret_cast<char*>(file.data()), flen)) return 0;

    if (file.size() < sizeof(IMAGE_DOS_HEADER)) return 0;
    auto fdos = reinterpret_cast<IMAGE_DOS_HEADER*>(file.data());
    if (fdos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    if (static_cast<size_t>(fdos->e_lfanew) + sizeof(IMAGE_NT_HEADERS64) > file.size()) return 0;
    auto fnt = reinterpret_cast<IMAGE_NT_HEADERS64*>(file.data() + fdos->e_lfanew);
    if (fnt->Signature != IMAGE_NT_SIGNATURE) return 0;

    auto fsec = IMAGE_FIRST_SECTION(fnt);
    const DWORD codeflags = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE;
    const uint32_t page = HyperDbgMemory::PageSize;

    uint32_t filled = 0;
    for (WORD i = 0; i < fnt->FileHeader.NumberOfSections; ++i)
    {
        if ((fsec[i].Characteristics & codeflags) && !includecode)
            continue;

        uint32_t rva = fsec[i].VirtualAddress;
        uint32_t vsz = fsec[i].Misc.VirtualSize;
        uint32_t rawptr = fsec[i].PointerToRawData;
        uint32_t rawsz = fsec[i].SizeOfRawData;
        uint32_t covered = (std::min)(vsz, rawsz);

        for (uint32_t off = 0; off < covered; off += page)
        {
            uint32_t chunk = (std::min)(page, covered - off);
            uint64_t bufoff = static_cast<uint64_t>(rva) + off;
            uint64_t fileoff = static_cast<uint64_t>(rawptr) + off;
            if (bufoff + chunk > buf.size()) break;
            if (fileoff + chunk > file.size()) break;

            bool allzero = true;
            for (uint32_t k = 0; k < chunk; ++k)
            {
                if (buf[bufoff + k] != 0) { allzero = false; break; }
            }
            if (!allzero) continue;

            std::memcpy(buf.data() + bufoff, file.data() + fileoff, chunk);
            filled += chunk;
        }
    }
    return filled;
}

PEDumper::DumpResult PEDumper::DumpOne(const LoadedModule& mod, const std::filesystem::path& outpath, bool includecode, bool backfillcode)
{
    DumpResult r{};
    r.Module = mod;
    r.OutPath = outpath;
    r.Ok = false;

    auto readva = [&](uint64_t va, void* out, uint32_t size) -> bool
        {
            return (mod.Space == AddressSpace::Kernel) ? ReadK(va, out, size) : ReadU(mod.Pid, va, out, size);
        };
    auto readrobust = [&](uint64_t va, uint8_t* out, uint32_t size) -> uint32_t
        {
            return (mod.Space == AddressSpace::Kernel) ? ReadKRobust(va, out, size) : ReadURobust(mod.Pid, va, out, size);
        };

    IMAGE_DOS_HEADER dos = {};
    if (!readva(mod.Base, &dos, sizeof(dos)))
    {
        r.Error = "read DOS header failed";
        return r;
    }
    if (dos.e_magic != IMAGE_DOS_SIGNATURE)
    {
        r.Error = "MZ magic missing";
        return r;
    }

    IMAGE_NT_HEADERS64 nt = {};
    if (!readva(mod.Base + dos.e_lfanew, &nt, sizeof(nt)))
    {
        r.Error = "read NT headers failed";
        return r;
    }
    if (nt.Signature != IMAGE_NT_SIGNATURE || nt.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
    {
        r.Error = "not a valid x64 PE";
        return r;
    }

    const uint32_t imagesize = nt.OptionalHeader.SizeOfImage;
    if (imagesize < HyperDbgMemory::PageSize || imagesize >(1u << 30))
    {
        r.Error = "SizeOfImage bogus";
        return r;
    }
    r.Module.Size = imagesize;

    std::vector<uint8_t> buf(imagesize, 0);

    uint32_t headersize = (nt.OptionalHeader.SizeOfHeaders + HyperDbgMemory::PageSize - 1) & ~(HyperDbgMemory::PageSize - 1);
    if (headersize == 0 || headersize > imagesize)
    {
        headersize = (std::min)(imagesize, static_cast<uint32_t>(HyperDbgMemory::PageSize));
    }
    readrobust(mod.Base, buf.data(), headersize);
    r.HeaderBytes = headersize;

    auto dosout = reinterpret_cast<IMAGE_DOS_HEADER*>(buf.data());
    auto ntout = reinterpret_cast<IMAGE_NT_HEADERS64*>(buf.data() + dosout->e_lfanew);
    auto sec = IMAGE_FIRST_SECTION(ntout);

    const DWORD codeflags = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE;

    for (WORD i = 0; i < ntout->FileHeader.NumberOfSections; ++i)
    {
        uint32_t rva = sec[i].VirtualAddress;
        uint32_t vsize = sec[i].Misc.VirtualSize;

        if (rva >= imagesize)
        {
            ++r.SectionsSkipped;
            continue;
        }
        if (rva + vsize > imagesize)
        {
            vsize = imagesize - rva;
        }

        const bool iscode = (sec[i].Characteristics & codeflags) != 0;

        if (iscode && !includecode)
        {
            ++r.SectionsSkipped;
            continue;
        }

        if (vsize > 0)
        {
            readrobust(mod.Base + rva, buf.data() + rva, vsize);
            if (iscode) r.CodeBytes += vsize;
            else        r.DataBytes += vsize;
        }
        ++r.SectionsDumped;
    }

    r.BackfilledBytes = BackfillFromDisk(mod, buf, includecode && backfillcode);

    ntout->OptionalHeader.FileAlignment = ntout->OptionalHeader.SectionAlignment;
    ntout->OptionalHeader.SizeOfHeaders = headersize;
    for (WORD i = 0; i < ntout->FileHeader.NumberOfSections; ++i)
    {
        sec[i].PointerToRawData = sec[i].VirtualAddress;
        sec[i].SizeOfRawData = sec[i].Misc.VirtualSize;
    }

    std::error_code ec;
    std::filesystem::create_directories(outpath.parent_path(), ec);
    std::ofstream f(outpath, std::ios::binary);
    if (!f)
    {
        r.Error = "open output failed";
        return r;
    }
    f.write(reinterpret_cast<const char*>(buf.data()), buf.size());
    if (!f)
    {
        r.Error = "write failed";
        return r;
    }
    r.Ok = true;
    return r;
}

std::vector<PEDumper::DumpResult> PEDumper::DumpModuleList(std::vector<LoadedModule> modules, const std::filesystem::path& outdir, const char* label, bool includecode, bool backfillcode)
{
    std::error_code ec;
    std::filesystem::create_directories(outdir, ec);

    std::vector<DumpResult> results;
    results.reserve(modules.size());

    std::unordered_map<std::wstring, int> seen;

    for (const auto& mod : modules)
    {
        std::wstring basename = mod.BaseName.empty() ? L"unnamed_module" : mod.BaseName;
        int& count = seen[basename];
        std::wstring filename;
        if (count == 0)
        {
            filename = basename;
        }
        else
        {
            wchar_t suffix[32];
            std::swprintf(suffix, 32, L".%016llx", static_cast<unsigned long long>(mod.Base));
            filename = basename + suffix;
        }
        ++count;

        auto outpath = outdir / filename;
        auto r = DumpOne(mod, outpath, includecode, backfillcode);

        if (r.Ok)
        {
            std::printf("[+] %-32ls  %u sec / %u holes  %8u B  (+%u B backfilled)  -> %ls\n",
                basename.c_str(),
                r.SectionsDumped, r.SectionsSkipped,
                r.HeaderBytes + r.DataBytes + r.CodeBytes,
                r.BackfilledBytes,
                filename.c_str());
        }
        else
        {
            std::printf("[!] %-32ls  skipped: %s\n", basename.c_str(), r.Error.c_str());
        }
        results.push_back(std::move(r));
    }

    auto okcount = std::count_if(results.begin(), results.end(), [](const DumpResult& d) { return d.Ok; });
    std::printf("[+] PEDumper: wrote %zu / %zu %s modules to %ls\n", static_cast<size_t>(okcount), results.size(), label, outdir.wstring().c_str());

    return results;
}

std::vector<PEDumper::DumpResult> PEDumper::DumpProcess(uint32_t pid, std::chrono::milliseconds delay, const std::filesystem::path& outdir, bool includecode, bool backfillcode)
{
    {
        std::error_code ec;
        std::filesystem::remove_all(outdir, ec);
        std::filesystem::create_directories(outdir, ec);
        if (ec)
        {
            std::printf("[!] PEDumper: could not fully clear %ls (%s)\n", outdir.wstring().c_str(), ec.message().c_str());
        }
    }

    std::printf("[+] PEDumper: waiting %lld ms for pid %u to initialize...\n", static_cast<long long>(delay.count()), pid);
    std::this_thread::sleep_for(delay);

    std::printf("[+] PEDumper: enumerating user modules for pid %u\n", pid);
    auto modules = EnumerateProcessModules(pid);
    std::printf("[+] PEDumper: %zu module(s) loaded in pid %u\n", modules.size(), pid);

    return DumpModuleList(std::move(modules), outdir, "user", includecode, backfillcode);
}

std::vector<PEDumper::DumpResult> PEDumper::DumpKernel(std::chrono::milliseconds delay, const std::filesystem::path& outdir, bool includecode, bool backfillcode)
{
    {
        std::error_code ec;
        std::filesystem::remove_all(outdir, ec);
        std::filesystem::create_directories(outdir, ec);
        if (ec)
        {
            std::printf("[!] PEDumper: could not fully clear %ls (%s)\n", outdir.wstring().c_str(), ec.message().c_str());
        }
    }

    std::printf("[+] PEDumper: waiting %lld ms before kernel snapshot...\n", static_cast<long long>(delay.count()));
    std::this_thread::sleep_for(delay);

    std::printf("[+] PEDumper: enumerating kernel drivers via PsLoadedModuleList\n");
    auto modules = EnumerateKernelModules();
    std::printf("[+] PEDumper: %zu kernel driver(s) loaded\n", modules.size());

    return DumpModuleList(std::move(modules), outdir, "kernel", includecode, backfillcode);
}