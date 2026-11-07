#include "../../Pch.h"
#include "AutoDebugTool.h"
#include "AutoDebugUtils.h"
#include "AutoDebugPeUtils.h"
#include "AutoDebugHits.h"
#include "Targets/DebugTarget.h"
#include "Targets/DebugTargetRegistry.h"
#include "../Database/AutoDebugStore.h"
#include "../WinPE/PEDumper.h"

#include <tlhelp32.h>
#include <conio.h>



extern "C" LONG __stdcall NtQueryInformationProcess(HANDLE, ULONG, PVOID, ULONG, PULONG);
#pragma comment(lib, "ntdll.lib")

struct ProcessBasicInfoMin
{
    LONG ExitStatus;
    PVOID PebBaseAddress;
    ULONG_PTR AffinityMask;
    LONG BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
};

AutoDebugTool::AutoDebugTool(HyperDbgSession& session)
    : Session(session)
{
}

std::string AutoDebugTool::OpenHitsForwarding(const std::string& stem, std::filesystem::path& hitsfile)
{
    std::error_code ec;

    std::filesystem::path dir = std::filesystem::current_path(ec);
    if (dir.empty() || (dir / (stem + ".autodbg.hits.txt")).string().find(' ') != std::string::npos)
    {
        const std::filesystem::path fallback = LR"(C:\autodbg)";
        std::filesystem::create_directories(fallback, ec);
        std::fprintf(stderr, "[autodebug] output path has a space (or cwd unavailable); HyperDbg's parser can't take that -- hits go to %ls instead\n", fallback.wstring().c_str());
        dir = fallback;
    }
    hitsfile = dir / (stem + ".autodbg.hits.txt");

    {
        std::ofstream clear(hitsfile, std::ios::binary | std::ios::trunc);
    }

    std::string name = "autodbg_" + std::to_string(GetTickCount64());
    if (name.size() > 50)
    {
        name.resize(50);
    }

    char createcmd[512];
    std::snprintf(createcmd, sizeof(createcmd), "output create %s file %s", name.c_str(), hitsfile.string().c_str());

    Session.SetTeeStdout(false);
    const std::string rcreate = Session.Run(createcmd);
    const std::string ropen = Session.Run("output open " + name);
    Session.SetTeeStdout(true);

    if (AutoDebugUtils::ResponseHasError(rcreate) || AutoDebugUtils::ResponseHasError(ropen))
    {
        std::fprintf(stderr, "[autodebug] event-forwarding setup failed (create/open) -- arming without forwarding; hits will print to the console\n");
        Session.SetTeeStdout(false);
        Session.Run("output close " + name);
        Session.SetTeeStdout(true);
        return {};
    }

    std::printf("[autodebug] forwarding hits -> %ls  (source '%s')\n", hitsfile.wstring().c_str(), name.c_str());
    return name;
}

void AutoDebugTool::CloseHitsForwarding(const std::string& outputname)
{
    if (outputname.empty())
    {
        return;
    }
    Session.SetTeeStdout(false);
    Session.Run("output close " + outputname);
    Session.SetTeeStdout(true);
}

uint32_t AutoDebugTool::ReadImageSizeFromDisk(const std::string& filepath)
{
    std::ifstream tf(filepath, std::ios::binary);
    if (!tf)
    {
        return 0;
    }
    IMAGE_DOS_HEADER dos{};
    tf.read(reinterpret_cast<char*>(&dos), sizeof(dos));
    if (!tf || dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew <= 0)
    {
        return 0;
    }
    tf.seekg(dos.e_lfanew);
    IMAGE_NT_HEADERS64 nt{};
    tf.read(reinterpret_cast<char*>(&nt), sizeof(nt));
    if (!tf || nt.Signature != IMAGE_NT_SIGNATURE)
    {
        return 0;
    }
    return nt.OptionalHeader.SizeOfImage;
}

void AutoDebugTool::RunUser(const std::string& dumppath, const std::string& exename, bool monitortargetsyscalls, bool monitorntdllsyscalls)
{
    std::error_code ec;
    if (!std::filesystem::exists(dumppath, ec))
    {
        std::fprintf(stderr, "[!] dump file not found: %s\n", dumppath.c_str());
        return;
    }
    if (exename.empty())
    {
        std::fprintf(stderr, "[!] exe name is empty\n");
        return;
    }
    std::printf("[autodebug] scan target (on disk): %s\n", dumppath.c_str());
    std::printf("[autodebug] attach target (by name): %s\n", exename.c_str());

    ResolvedTarget tgt{};
    tgt.Kind = TargetKind::UserProcess;
    tgt.ScanPath = dumppath;
    tgt.ExeName = exename;
    tgt.RuntimePathW.assign(dumppath.begin(), dumppath.end());
    tgt.DisplayNameW.assign(exename.begin(), exename.end());
    tgt.Base = 0;
    tgt.ImageSize = ReadImageSizeFromDisk(dumppath);
    tgt.Pid = 0;
    tgt.ProcHandle = nullptr;
    tgt.ThreadHandle = nullptr;
    tgt.KernelEnumerator = nullptr;

    RunCore(std::move(tgt), monitortargetsyscalls, monitorntdllsyscalls);
}

uint32_t AutoDebugTool::WaitForProcessByName(const std::string& exename)
{
    std::wstring wantw;
    {
        const int n = MultiByteToWideChar(CP_ACP, 0, exename.data(), static_cast<int>(exename.size()), nullptr, 0);
        wantw.resize(static_cast<size_t>(n));
        MultiByteToWideChar(CP_ACP, 0, exename.data(), static_cast<int>(exename.size()), wantw.data(), n);
        for (wchar_t& c : wantw)
        {
            c = static_cast<wchar_t>(std::towlower(c));
        }
    }

    auto tryonce = [&wantw, &exename]() -> uint32_t
        {
            const HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (snap == INVALID_HANDLE_VALUE)
            {
                return 0;
            }

            PROCESSENTRY32W pe{};
            pe.dwSize = sizeof(pe);

            uint32_t firstpid = 0;
            int matches = 0;

            if (Process32FirstW(snap, &pe))
            {
                do
                {
                    std::wstring cand(pe.szExeFile);
                    for (wchar_t& c : cand)
                    {
                        c = static_cast<wchar_t>(std::towlower(c));
                    }
                    if (cand == wantw)
                    {
                        if (firstpid == 0)
                        {
                            firstpid = pe.th32ProcessID;
                        }
                        ++matches;
                    }
                } while (Process32NextW(snap, &pe));
            }
            CloseHandle(snap);

            if (matches > 1)
            {
                std::fprintf(stderr, "[autodebug] %d processes named '%s' running -- taking pid %u (first in Toolhelp order)\n", matches, exename.c_str(), firstpid);
            }
            return firstpid;
        };

    uint32_t pid = tryonce();
    if (pid != 0)
    {
        return pid;
    }

    std::printf("[autodebug] '%s' not running yet.  Waiting (press any key to cancel)...\n", exename.c_str());

    while (_kbhit())
    {
        (void)_getch();
    }

    const ULONGLONG tickbase = GetTickCount64();
    ULONGLONG lasttick = tickbase;

    for (;;)
    {
        if (_kbhit())
        {
            (void)_getch();
            std::puts("[autodebug] cancelled by user.");
            return 0;
        }
        Sleep(200);

        pid = tryonce();
        if (pid != 0)
        {
            std::printf("[autodebug] found pid %u\n", pid);
            return pid;
        }

        const ULONGLONG now = GetTickCount64();
        if (now - lasttick >= 1000)
        {
            const ULONGLONG elapsedsec = (now - tickbase) / 1000;
            std::printf("[autodebug]   ... still waiting for '%s' (%llu s elapsed)\n", exename.c_str(), static_cast<unsigned long long>(elapsedsec));
            lasttick = now;
        }
    }
}

uint64_t AutoDebugTool::QueryImageBase(uint32_t pid, HANDLE hproc, bool allowrpmfallback)
{
    ProcessBasicInfoMin pbi{};
    ULONG len = 0;
    const LONG st = NtQueryInformationProcess(hproc, 0, &pbi, sizeof(pbi), &len);
    if (st < 0 || pbi.PebBaseAddress == nullptr)
    {
        return 0;
    }

    const uint64_t peb = reinterpret_cast<uint64_t>(pbi.PebBaseAddress);
    uint64_t base = 0;

    if (Session.Read(pid, peb + 0x10, &base, sizeof(base), HyperDbgMemory::ReadPath::FromVmxRoot) && base != 0)
    {
        return base;
    }

    if (allowrpmfallback)
    {
        SIZE_T got = 0;
        if (ReadProcessMemory(hproc, reinterpret_cast<LPCVOID>(peb + 0x10), &base, sizeof(base), &got) && got == sizeof(base))
        {
            return base;
        }
    }
    return 0;
}

void AutoDebugTool::RunDriver(PEDumper& dumper, const std::string& drivername, bool monitortargetsyscalls)
{
    std::printf("[autodebug] target driver: %s\n", drivername.c_str());

    std::vector<PEDumper::LoadedModule> modules;
    try
    {
        modules = dumper.EnumerateKernelModules();
    }
    catch (const std::exception& ex)
    {
        std::fprintf(stderr, "[autodebug] EnumerateKernelModules threw: %s\n", ex.what());
        return;
    }
    if (modules.empty())
    {
        std::fprintf(stderr, "[autodebug] no kernel modules enumerated\n");
        return;
    }

    std::wstring queryw;
    {
        const int n = MultiByteToWideChar(CP_ACP, 0, drivername.data(), static_cast<int>(drivername.size()), nullptr, 0);
        queryw.resize(static_cast<size_t>(n));
        MultiByteToWideChar(CP_ACP, 0, drivername.data(), static_cast<int>(drivername.size()), queryw.data(), n);
        queryw = AutoDebugUtils::ToLowerW(std::move(queryw));
        if (queryw == L"nt")
        {
            queryw = L"ntoskrnl";
        }
    }

    const PEDumper::LoadedModule* hit = nullptr;
    for (const auto& m : modules)
    {
        const std::wstring bn = AutoDebugUtils::ToLowerW(m.BaseName);
        if (bn == queryw || AutoDebugUtils::StemW(bn) == AutoDebugUtils::StemW(queryw))
        {
            hit = &m;
            break;
        }
    }
    if (hit == nullptr)
    {
        std::fprintf(stderr, "[autodebug] driver not loaded: %s (%zu drivers enumerated)\n", drivername.c_str(), modules.size());
        return;
    }

    const std::wstring diskpathw = AutoDebugPeUtils::NormalizeNtPath(hit->FullPath);
    if (diskpathw.empty() || !std::filesystem::exists(diskpathw))
    {
        std::fprintf(stderr, "[autodebug] driver %ls FullDllName '%ls' does not resolve to a readable on disk file (normalized: '%ls'); can't scan\n", hit->BaseName.c_str(), hit->FullPath.c_str(), diskpathw.c_str());
        return;
    }

    std::string diskpatha;
    diskpatha.reserve(diskpathw.size());
    for (wchar_t w : diskpathw)
    {
        if (w > 0x7F)
        {
            std::fprintf(stderr, "[autodebug] driver on disk path contains non ASCII glyphs; scan skipped: %ls\n", diskpathw.c_str());
            return;
        }
        diskpatha.push_back(static_cast<char>(w));
    }

    std::printf("[autodebug] driver %ls\n[autodebug]   live base 0x%llx  size 0x%x\n[autodebug]   on disk   %s\n", hit->BaseName.c_str(), static_cast<unsigned long long>(hit->Base), hit->Size, diskpatha.c_str());

    ResolvedTarget tgt{};
    tgt.Kind = TargetKind::KernelDriver;
    tgt.ScanPath = diskpatha;
    tgt.RuntimePathW = diskpathw;
    tgt.DisplayNameW = hit->BaseName;
    tgt.Base = hit->Base;
    tgt.ImageSize = hit->Size;
    tgt.Pid = 0;
    tgt.ProcHandle = nullptr;
    tgt.ThreadHandle = nullptr;
    tgt.KernelEnumerator = &dumper;

    RunCore(std::move(tgt), monitortargetsyscalls, false);
}

std::vector<InsnSite> AutoDebugTool::ScanJumps(const std::string& filepath, uint64_t& preferredbase, const PeScan::ScanOptions& opts)
{
    return PeScan::ScanFile(filepath, preferredbase, opts);
}

void AutoDebugTool::TouchPage(uint32_t pid, uint64_t va)
{
    char cmd[64];
    std::snprintf(cmd, sizeof(cmd), "db 0x%llx l 1 pid %x", static_cast<unsigned long long>(va), static_cast<unsigned int>(pid));
    Session.Run(cmd);
}

void AutoDebugTool::RunCore(ResolvedTarget tgt, bool monitortargetsyscalls, bool monitorntdllsyscalls)
{
    const bool iskernel = (tgt.Kind == TargetKind::KernelDriver);
    const std::string& filepath = tgt.ScanPath;

    if (iskernel)
    {
        monitorntdllsyscalls = false;
    }

    PeScan::ScanOptions kerneldefaults;
    if (iskernel)
    {
        kerneldefaults.SkipSectionPrefixes.push_back("INIT");
    }

    std::error_code ec;
    std::printf("[autodebug] target: %ls (%s)\n", tgt.DisplayNameW.c_str(), iskernel ? "kernel driver" : "Usermode PE");

    PeScan::ScanOptions scanopts = kerneldefaults;
    const int tgtmode = AutoDebugUtils::PromptChoice("Targeting mode?", { "Whole binary", "Specific section(s)", "Specific range(s)  (comma separated(,) RVA:SIZE)" });

    if (tgtmode == 2)
    {
        const std::string raw = AutoDebugUtils::PromptNonEmpty("Section name(s) (comma separated(,), e.g. .text,.text1): ");
        scanopts.Sections = AutoDebugUtils::SplitCsv(raw);
        std::printf("[autodebug] section filter: %zu entry(s)\n", scanopts.Sections.size());
        for (const std::string& s : scanopts.Sections)
        {
            std::printf("[autodebug]   \"%s\"\n", s.c_str());
        }
    }
    else if (tgtmode == 3)
    {
        std::puts("Enter comma separated(,) ranges as RVA:SIZE in hex.");
        std::puts("  e.g. 0x1000:0x200,0x300000:0x1000");
        const std::string raw = AutoDebugUtils::PromptNonEmpty("> ");
        const std::vector<std::string> tokens = AutoDebugUtils::SplitCsv(raw);

        for (const std::string& t : tokens)
        {
            const size_t colon = t.find(':');
            if (colon == std::string::npos)
            {
                std::fprintf(stderr, "[!] missing ':' in \"%s\" skipped\n", t.c_str());
                continue;
            }
            uint64_t rva = 0;
            uint64_t sz = 0;
            if (!AutoDebugUtils::ParseHex64(t.substr(0, colon), rva) || !AutoDebugUtils::ParseHex64(t.substr(colon + 1), sz) || sz == 0)
            {
                std::fprintf(stderr, "[!] bad start:size \"%s\" skipped (need two hex values, size > 0)\n", t.c_str());
                continue;
            }
            PeScan::ScanOptions::Range r;
            r.Rva = rva;
            r.Size = sz;
            scanopts.Ranges.push_back(r);
            std::printf("[autodebug] range [0x%llx, 0x%llx) (%llu B)\n", static_cast<unsigned long long>(rva), static_cast<unsigned long long>(rva + sz), static_cast<unsigned long long>(sz));
        }

        if (scanopts.Ranges.empty())
        {
            std::fprintf(stderr, "[!] no valid ranges parsed: nothing to scan\n");
            return;
        }
    }

    uint64_t preferredbase = 0;
    std::vector<InsnSite> sites = ScanJumps(filepath, preferredbase, scanopts);

    size_t nbranch = 0;
    size_t ncall = 0;
    size_t ncompare = 0;
    size_t nstring = 0;
    size_t nvec = 0;
    size_t nmov = 0;
    size_t narith = 0;
    size_t nindbranch = 0;
    size_t nindcall = 0;
    size_t nlea = 0;
    size_t nsyscall = 0;
    for (const InsnSite& s : sites)
    {
        switch (s.Kind)
        {
        case SiteKind::Compare:
            ++ncompare;
            break;
        case SiteKind::String:
            ++nstring;
            break;
        case SiteKind::VecMove:
            ++nvec;
            break;
        case SiteKind::Mov:
            ++nmov;
            break;
        case SiteKind::Arith:
            ++narith;
            break;
        case SiteKind::Call:
            ++ncall;
            break;
        case SiteKind::Branch:
            ++nbranch;
            break;
        case SiteKind::IndBranch:
            ++nindbranch;
            break;
        case SiteKind::IndCall:
            ++nindcall;
            break;
        case SiteKind::Lea:
            ++nlea;
            break;
        case SiteKind::Syscall:
            ++nsyscall;
            break;
        default:
            ++nbranch;
            break;
        }
    }
    std::printf("[autodebug] sites found: %zu branch, %zu call, %zu comparison, %zu string, %zu vector load, %zu mov, %zu arith, %zu ind jmp, %zu ind call, %zu lea, %zu syscall\n", nbranch, ncall, ncompare, nstring, nvec, nmov, narith, nindbranch, nindcall, nlea, nsyscall);

    if (sites.empty())
    {
        std::puts("[autodebug] nothing to monitor.");
        return;
    }

    std::puts("\n[autodebug] Kind filter:");
    const bool wantbranch = AutoDebugUtils::PromptYesNo("Monitor branches? [y/n] ", true);
    const bool wantcall = AutoDebugUtils::PromptYesNo("Monitor calls? [y/n] ", true);
    const bool wantcompare = AutoDebugUtils::PromptYesNo("Monitor compares? [y/n] ", true);
    const bool wantarith = AutoDebugUtils::PromptYesNo("Monitor arith? [y/n] ", true);
    const bool wantmov = AutoDebugUtils::PromptYesNo("Monitor movs? [y/n] ", true);
    const bool wantvec = AutoDebugUtils::PromptYesNo("Monitor vecs? [y/n] ", true);
    const bool wantindbranch = AutoDebugUtils::PromptYesNo("Monitor indirect jmps? [y/n] ", true);
    const bool wantindcall = AutoDebugUtils::PromptYesNo("Monitor indirect calls? [y/n] ", true);
    const bool wantlea = AutoDebugUtils::PromptYesNo("Monitor LEAs? [y/n] ", true);
    const bool wantsyscall = monitortargetsyscalls && AutoDebugUtils::PromptYesNo("Monitor direct target syscalls? [y/n] ", true);

    bool capturecallparams = false;
    bool capturestackargs = false;
    bool capturereturns = false;
    if (wantcall || wantindcall)
    {
        std::puts("\n[autodebug] Capture options (Call / IndCall only):");
        capturecallparams = AutoDebugUtils::PromptYesNo("Capture parameters (regs 0..3)? [y/n] ", false);
        if (capturecallparams)
        {
            capturestackargs = AutoDebugUtils::PromptYesNo("Capture stack args 4..7 at [rsp+0x20..0x38]? [y/n] ", false);
        }
        capturereturns = AutoDebugUtils::PromptYesNo("Capture return values (RAX at retaddr)? [y/n] ", false);
    }

    const bool wantntdllsyscalls = !iskernel && (monitorntdllsyscalls || AutoDebugUtils::PromptYesNo("Monitor ntdll syscalls (heavy -- every Nt/Zw fires)? [y/n] ", false));

    const bool forceloadpages = !iskernel && AutoDebugUtils::PromptYesNo("Prefault pages via RPM? (opens PROCESS_VM_READ; No -> HyperDbg `db`) [y/n] ", false);

    const size_t nbeforekindfilter = sites.size();
    sites.erase(std::remove_if(sites.begin(), sites.end(),
        [=](const InsnSite& s)
        {
            switch (s.Kind)
            {
            case SiteKind::Branch:
                return !wantbranch;
            case SiteKind::Call:
                return !wantcall;
            case SiteKind::Compare:
                return !wantcompare;
            case SiteKind::Arith:
                return !wantarith;
            case SiteKind::Mov:
                return !wantmov;
            case SiteKind::VecMove:
                return !wantvec;
            case SiteKind::IndBranch:
                return !wantindbranch;
            case SiteKind::IndCall:
                return !wantindcall;
            case SiteKind::Lea:
                return !wantlea;
            case SiteKind::Syscall:
                return !wantsyscall;
            case SiteKind::String:
                return false;
            default:
                return false;
            }
        }), sites.end());
    std::printf("[autodebug] kind filter kept %zu / %zu site(s)  [branch=%d call=%d compare=%d arith=%d mov=%d vec=%d ind-jmp=%d ind-call=%d lea=%d syscall=%d string=on]\n", sites.size(), nbeforekindfilter, (int)wantbranch, (int)wantcall, (int)wantcompare, (int)wantarith, (int)wantmov, (int)wantvec, (int)wantindbranch, (int)wantindcall, (int)wantlea, (int)wantsyscall);
    if (wantcall || wantindcall)
    {
        std::printf("[autodebug] captures: params=%d stack-args=%d returns=%d\n", (int)capturecallparams, (int)capturestackargs, (int)capturereturns);
    }
    if (wantntdllsyscalls)
    {
        std::puts("[autodebug] ntdll syscalls: on");
    }

    if (sites.empty())
    {
        std::puts("[autodebug] all selected kinds are empty -- nothing to monitor.");
        return;
    }

    std::unordered_set<uint64_t> pages;
    for (const InsnSite& j : sites)
    {
        pages.insert(j.Rva >> 12);
    }
    std::printf("[autodebug] sites span %zu distinct 4KB page(s) -> %zu monitor(s)\n", pages.size(), pages.size());

    AutoDebugStore store;
    AutoDebugStore::OpenResult openres;
    const bool storeok = store.Open(filepath, openres);
    if (storeok)
    {
        if (openres.WasWiped)
        {
            std::printf("[sophiaproj] hash mismatch: prior project wiped, starting fresh -> %ls  (sha256=%s)\n", openres.ProjectDir.wstring().c_str(), openres.Sha256Hex.c_str());
        }
        else if (openres.IsNew)
        {
            std::printf("[sophiaproj] new project -> %ls  (sha256=%s)\n", openres.ProjectDir.wstring().c_str(), openres.Sha256Hex.c_str());
        }
        else
        {
            std::printf("[sophiaproj] reusing project (run #%u) -> %ls\n", openres.PriorRunCount + 1, openres.ProjectDir.wstring().c_str());
            store.LoadObservations();
            const ObsStats& s = store.Stats();
            std::printf("[sophiaproj] loaded %llu prior observations across %llu unique sites\n             (branch=%u call=%u compare=%u mov=%u arith=%u string=%u vec=%u ind-jmp=%u ind-call=%u lea=%u)\n", static_cast<unsigned long long>(s.TotalRecords), static_cast<unsigned long long>(s.UniqueRvas), s.Branches, s.Calls, s.Compares, s.Movs, s.Ariths, s.Strings, s.Vecs, s.IndBranches, s.IndCalls, s.Leas);
        }
    }

    if (storeok && store.IsReused() && !store.ExploredRvas().empty())
    {
        std::puts("");
        std::puts("[sophiaproj] Reuse mode:");
        std::puts("  [1] Continue on the same monitor set (log new distinct values on all sites) -- default");
        std::printf("  [2] Skip already-observed sites (drop the %llu observed RVAs from the per-page conditions)\n", static_cast<unsigned long long>(store.ExploredRvas().size()));
        std::puts("  [3] Cancel");
        std::printf("Choice> ");
        std::fflush(stdout);

        char choice = '1';
        {
            std::string line;
            if (std::getline(std::cin, line))
            {
                for (char c : line)
                {
                    if (c != ' ' && c != '\t' && c != '\r' && c != '\n')
                    {
                        choice = c;
                        break;
                    }
                }
            }
        }

        if (choice == '3')
        {
            std::puts("[sophiaproj] cancelled -- no run.");
            return;
        }

        if (choice == '2')
        {
            const std::unordered_set<uint64_t>& explored = store.ExploredRvas();
            const size_t before = sites.size();
            sites.erase(std::remove_if(sites.begin(), sites.end(),
                [&explored](const InsnSite& s)
                {
                    return explored.count(s.Rva) > 0;
                }), sites.end());

            std::printf("[sophiaproj] dropped %zu already-observed site(s); %zu remain\n", before - sites.size(), sites.size());

            if (sites.empty())
            {
                std::puts("[sophiaproj] every scanned site is already observed -- nothing to arm in mode 2.");
                std::puts("[sophiaproj] try mode 1: it re-arms the full monitor set and catches new tuples on known sites (different call frames, different inputs, etc.).");
                return;
            }

            std::unordered_set<uint64_t> pagesafter;
            for (const InsnSite& j : sites)
            {
                pagesafter.insert(j.Rva >> 12);
            }
            std::printf("[autodebug] filtered site set spans %zu page(s) -> %zu monitor(s)\n", pagesafter.size(), pagesafter.size());
        }
        else if (choice != '1' && choice != 0)
        {
            std::printf("[sophiaproj] unrecognized choice '%c' -- defaulting to 1.\n", choice);
        }
    }

    if (!iskernel && tgt.Pid == 0)
    {
        std::puts("");
        std::puts("[autodebug] === configuration complete ===");
        std::printf("[autodebug] now waiting for process '%s' to appear (press any key to cancel)\n", tgt.ExeName.c_str());
        std::puts("[autodebug] launch the target now, or hit any key to bail out");

        const uint32_t attachedpid = WaitForProcessByName(tgt.ExeName);
        if (attachedpid == 0)
        {
            std::fprintf(stderr, "[!] wait cancelled or no matching process; aborting run (no observations saved for this attempt).\n");
            return;
        }
        std::printf("[autodebug] attached to pid %u\n", attachedpid);

        DWORD openrights = PROCESS_QUERY_LIMITED_INFORMATION;
        if (forceloadpages)
        {
            openrights |= PROCESS_VM_READ;
        }

        const HANDLE attachedproc = OpenProcess(openrights, FALSE, attachedpid);
        if (attachedproc == nullptr)
        {
            std::fprintf(stderr, "[!] OpenProcess(pid=%u) failed (GetLastError=%lu); aborting\n", attachedpid, GetLastError());
            return;
        }

        const uint64_t livebase = QueryImageBase(attachedpid, attachedproc, forceloadpages);
        if (livebase == 0)
        {
            std::fprintf(stderr, "[!] could not read live image base; aborting\n");
            CloseHandle(attachedproc);
            return;
        }

        tgt.Pid = attachedpid;
        tgt.ProcHandle = attachedproc;
        tgt.Base = livebase;
    }

    HANDLE hproc = tgt.ProcHandle;
    const HANDLE hthread = tgt.ThreadHandle;
    const uint32_t pid = tgt.Pid;
    const uint64_t base = tgt.Base;

    std::printf("[autodebug] live base 0x%llx (preferred 0x%llx%s)\n", (unsigned long long)base, (unsigned long long)preferredbase, base == preferredbase ? "" : (iskernel ? " -- KASLR relocated" : " -- ASLR relocated"));

    if (storeok)
    {
        store.SetTracedBase(base);
    }

    if (!iskernel)
    {
        (void)hthread;
        std::puts("[autodebug] target already running; arming immediately.");
    }
    else
    {
        std::puts("[autodebug] kernel driver already loaded; arming immediately.");
    }

    std::printf("[autodebug] WARNING: arming %zu whole-page execute monitors over the target's .text.\n            Every instruction executed on those pages faults + single-steps, so the\n            target will run VERY slowly and hits will flood the console. This is the\n            expected cost of !monitor x over a code region -- scope down (or use\n            !epthook per-site) for anything beyond a smoke test.\n", pages.size());

    std::filesystem::path hitsfile;
    const std::string outputname = OpenHitsForwarding(std::filesystem::path(filepath).stem().string(), hitsfile);

    std::string ntdlloutputname;
    std::filesystem::path ntdllhitsfile;
    uint64_t ntdllbase = 0;
    uint32_t ntdllsize = 0;
    std::wstring ntdllpath;
    std::vector<InsnSite> ntdllsyscallsites;

    if (!iskernel && wantntdllsyscalls)
    {
        const std::vector<ForeignModule> earlymods = SnapshotForeignModules(pid, hproc, base);
        for (const ForeignModule& fm : earlymods)
        {
            if (fm.LowerName == "ntdll.dll")
            {
                ntdllbase = fm.Base;
                ntdllsize = fm.Size;
                ntdllpath = fm.FullPath;
                break;
            }
        }
        if (ntdllbase == 0)
        {
            std::fprintf(stderr, "[autodebug] ntdll not found in PEB.Ldr walk -- indirect syscall monitoring disabled for this run\n");
        }
        else
        {
            std::printf("[autodebug] ntdll live: base=0x%llx size=0x%x path=%ls\n", static_cast<unsigned long long>(ntdllbase), ntdllsize, ntdllpath.c_str());

            std::unordered_map<uint32_t, std::string> syscalltable;
            if (BuildSyscallTable(ntdllpath, syscalltable) && storeok)
            {
                WriteSyscallTable(store.Dir(), syscalltable);
                std::printf("[autodebug] wrote syscall_table.tsv (%zu entries) to %ls\n", syscalltable.size(), store.Dir().wstring().c_str());
            }

            ntdlloutputname = OpenHitsForwarding(std::filesystem::path(filepath).stem().string() + ".syscalls_indirect", ntdllhitsfile);
        }
    }

    pages.clear();
    for (const InsnSite& j : sites)
    {
        pages.insert(j.Rva >> 12);
    }
    if (capturecallparams)
    {
        std::printf("[autodebug] call-param capture ENABLED (regs 0..3%s -- expect ~%dx printfs per Call/IndCall fire, considerable overhead)\n", capturestackargs ? ", stack 4..7" : "", capturestackargs ? 8 : 4);
    }
    if (capturereturns)
    {
        std::puts("[autodebug] return-value capture ENABLED (one phantom clause per Call/IndCall at siteVa+siteLen; cross-page phantoms bucketed into their own monitor pages)");
    }
    if (wantsyscall)
    {
        std::puts("[autodebug] direct-target syscall capture ENABLED (arg + ret payload emitted for every Syscall site; phantom retVa at siteVa+2)");
    }
    const uint32_t armed = BuildMonitors(sites, pid, base, hproc, outputname, capturecallparams, capturestackargs, capturereturns, forceloadpages);
    std::printf("[autodebug] armed %u / %zu monitor(s)\n", armed, pages.size());
    if (!outputname.empty())
    {
        std::printf("[autodebug] monitors live; hits streaming to %ls (rva + all GPRs + rflags). Console stays quiet.\n", hitsfile.wstring().c_str());
    }

    if (!iskernel && hproc != nullptr)
    {
        CloseHandle(hproc);
        hproc = nullptr;
        tgt.ProcHandle = nullptr;
        std::puts("[autodebug] closed process handle; zero handles on target through the observation window");
    }

    if (ntdllbase != 0 && !ntdlloutputname.empty())
    {
        const uint32_t ntdllarmed = BuildNtdllSyscallMonitors(ntdllbase, ntdllsize, ntdllpath, pid, hproc, ntdlloutputname, capturestackargs, ntdllsyscallsites);
        std::printf("[autodebug] ntdll syscall monitors: %u armed; indirect hits streaming to %ls\n", ntdllarmed, ntdllhitsfile.wstring().c_str());
    }
    else
    {
        std::puts("[autodebug] monitors live; hits print as [autodbg-hit] (rva + all GPRs + rflags)...");
    }

    std::puts("\n[+] press ENTER to stop the monitors (target keeps running)\n");
    std::cin.get();

    std::vector<ForeignModule> foreignmods;
    if (!iskernel)
    {
        const HANDLE reopened = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (reopened != nullptr)
        {
            foreignmods = SnapshotForeignModules(pid, reopened, base);
            CloseHandle(reopened);
        }
        else
        {
            std::fprintf(stderr, "[autodebug] iat resolver: could not reopen process (GetLastError=%lu); skipping module snapshot\n", GetLastError());
        }
    }
    else if (tgt.KernelEnumerator != nullptr)
    {
        foreignmods = SnapshotForeignKernelModules(*tgt.KernelEnumerator, base);
    }

    if (storeok)
    {
        WriteModulesSidecar(store.Dir(), foreignmods, base, tgt.ImageSize, tgt.RuntimePathW);
    }

    Session.SetTeeStdout(false);
    Session.Run("events c all");
    Session.SetTeeStdout(true);

    CloseHitsForwarding(outputname);
    CloseHitsForwarding(ntdlloutputname);

    if (storeok && !hitsfile.empty())
    {
        std::error_code hec;
        const bool fileexists = std::filesystem::exists(hitsfile, hec);
        std::printf("[sophiaproj] ingesting hits from %ls %s\n", hitsfile.filename().wstring().c_str(), fileexists ? "..." : "(FILE MISSING)");

        if (fileexists)
        {
            AutoDebugHitParser parser(store, sites, AutoDebugHitParser::HitFlavor::TracedBinary);
            const AutoDebugHitParser::Stats ps = parser.ParseFile(hitsfile);

            ResolveForeignBranchTargets(store, base, foreignmods, ObsKind::IndCall);
            ResolveForeignBranchTargets(store, base, foreignmods, ObsKind::IndBranch);

            std::printf("[sophiaproj] file %llu byte(s), read %llu line(s)\n", static_cast<unsigned long long>(ps.HitsFileBytes), static_cast<unsigned long long>(ps.LinesRead));

            if (ps.LinesRead > 0 && ps.FirstLine[0])
            {
                std::printf("[sophiaproj] first line: %s\n", ps.FirstLine);
            }

            std::printf("[sophiaproj] tags: hit=%llu mem=%llu str=%llu vec=%llu mov=%llu ari=%llu ind=%llu lea=%llu\n", static_cast<unsigned long long>(ps.TagHit), static_cast<unsigned long long>(ps.TagMem), static_cast<unsigned long long>(ps.TagStr), static_cast<unsigned long long>(ps.TagVec), static_cast<unsigned long long>(ps.TagMov), static_cast<unsigned long long>(ps.TagAri), static_cast<unsigned long long>(ps.TagInd), static_cast<unsigned long long>(ps.TagLea));

            std::printf("[sophiaproj] hits=%llu ingested=%llu deduped=%llu error=%llu unknown-rva=%llu parse-error=%llu\n", static_cast<unsigned long long>(ps.HitsSeen), static_cast<unsigned long long>(ps.HitsIngested), static_cast<unsigned long long>(ps.HitsDedup), static_cast<unsigned long long>(ps.HitsError), static_cast<unsigned long long>(ps.UnknownRva), static_cast<unsigned long long>(ps.ParseErrors));

            std::printf("[sophiaproj]   new by kind: branch=%llu call=%llu compare=%llu mov=%llu arith=%llu string=%llu vec=%llu ind-jmp=%llu ind-call=%llu lea=%llu\n", static_cast<unsigned long long>(ps.Branches), static_cast<unsigned long long>(ps.Calls), static_cast<unsigned long long>(ps.Compares), static_cast<unsigned long long>(ps.Movs), static_cast<unsigned long long>(ps.Ariths), static_cast<unsigned long long>(ps.Strings), static_cast<unsigned long long>(ps.Vecs), static_cast<unsigned long long>(ps.IndBranches), static_cast<unsigned long long>(ps.IndCalls), static_cast<unsigned long long>(ps.Leas));

            if (ps.UnknownRva > 0)
            {
                std::printf("[sophiaproj] unknown-RVA sample (%u shown of %llu):", ps.UnknownRvaSampleCount, static_cast<unsigned long long>(ps.UnknownRva));
                for (uint32_t i = 0; i < ps.UnknownRvaSampleCount; ++i)
                {
                    std::printf(" 0x%llx", static_cast<unsigned long long>(ps.UnknownRvaSample[i]));
                }
                std::putchar('\n');
                std::printf("[sophiaproj] ^ compare against ScanJumps output -- these RVAs fired but weren't in the scanned site set\n");
            }
        }

        store.FlushStreams();

        const std::filesystem::path obsdir = store.Dir() / L"observations";
        if (std::filesystem::exists(obsdir, hec))
        {
            std::printf("[sophiaproj] %ls:\n", obsdir.wstring().c_str());
            bool anyfile = false;
            for (auto& e : std::filesystem::directory_iterator(obsdir, hec))
            {
                if (!e.is_regular_file())
                {
                    continue;
                }
                anyfile = true;
                std::error_code sec;
                const auto sz = std::filesystem::file_size(e.path(), sec);
                std::printf("[sophiaproj]   %-16ls  %llu byte(s)\n", e.path().filename().wstring().c_str(), static_cast<unsigned long long>(sec ? 0 : sz));
            }
            if (!anyfile)
            {
                std::puts("[sophiaproj]   (empty -- no records ingested; see stderr for per-hit errors, or the diagnostic block above)");
            }
        }

        {
            std::unordered_set<uint64_t> syscallrvas;
            for (const InsnSite& s : sites)
            {
                if (s.Kind == SiteKind::Syscall)
                {
                    syscallrvas.insert(s.Rva);
                }
            }

            if (!syscallrvas.empty())
            {
                const std::filesystem::path directfile = hitsfile.parent_path() / (std::filesystem::path(filepath).stem().string() + ".autodbg.syscalls_direct.txt");

                std::ifstream in(hitsfile, std::ios::binary);
                std::ofstream sf(directfile, std::ios::binary | std::ios::trunc);
                if (in && sf)
                {
                    auto extractrva = [](const std::string& line) -> uint64_t
                        {
                            size_t p = line.find("rva=");
                            if (p == std::string::npos)
                            {
                                return UINT64_MAX;
                            }
                            p += 4;
                            if (p + 1 < line.size() && line[p] == '0' && (line[p + 1] == 'x' || line[p + 1] == 'X'))
                            {
                                p += 2;
                            }
                            uint64_t r = 0;
                            bool any = false;
                            while (p < line.size())
                            {
                                const char c = line[p];
                                int d;
                                if (c >= '0' && c <= '9')
                                {
                                    d = c - '0';
                                }
                                else if (c >= 'a' && c <= 'f')
                                {
                                    d = c - 'a' + 10;
                                }
                                else if (c >= 'A' && c <= 'F')
                                {
                                    d = c - 'A' + 10;
                                }
                                else
                                {
                                    break;
                                }
                                r = (r << 4) | static_cast<uint64_t>(d);
                                any = true;
                                ++p;
                            }
                            return any ? r : UINT64_MAX;
                        };

                    std::string line;
                    bool passthroughblock = false;
                    uint64_t writtenlines = 0;
                    while (std::getline(in, line))
                    {
                        if (!line.empty() && line.back() == '\r')
                        {
                            line.pop_back();
                        }
                        if (line.empty())
                        {
                            continue;
                        }

                        const bool isret = line.find("[autodbg-ret]") != std::string::npos || line.find("[autodbg-reth]") != std::string::npos;
                        if (isret)
                        {
                            const uint64_t r = extractrva(line);
                            if (r != UINT64_MAX && syscallrvas.count(r))
                            {
                                sf << line << '\n';
                                ++writtenlines;
                            }
                            continue;
                        }

                        if (line.find("[autodbg-hit]") != std::string::npos)
                        {
                            const uint64_t r = extractrva(line);
                            passthroughblock = (r != UINT64_MAX && syscallrvas.count(r) > 0);
                        }

                        if (passthroughblock)
                        {
                            sf << line << '\n';
                            ++writtenlines;
                        }
                    }
                    std::printf("[sophiaproj] wrote direct-syscall log -> %ls (%llu line(s))\n", directfile.wstring().c_str(), static_cast<unsigned long long>(writtenlines));
                }
            }
        }

        const ObsStats& total = store.Stats();
        std::printf("[sophiaproj] in-memory totals: %llu observations across %llu unique sites\n", static_cast<unsigned long long>(total.TotalRecords), static_cast<unsigned long long>(total.UniqueRvas));

        store.FinalizeRun();
    }

    if (storeok && !ntdllhitsfile.empty() && !ntdllsyscallsites.empty())
    {
        std::error_code hec;
        if (std::filesystem::exists(ntdllhitsfile, hec))
        {
            std::printf("[sophiaproj] ingesting ntdll-syscall hits from %ls\n", ntdllhitsfile.filename().wstring().c_str());
            AutoDebugHitParser parser(store, ntdllsyscallsites, AutoDebugHitParser::HitFlavor::NtdllSyscalls);
            const AutoDebugHitParser::Stats ns = parser.ParseFile(ntdllhitsfile);
            std::printf("[sophiaproj] ntdll: file=%llu B, lines=%llu, hits=%llu, ingested=%llu, deduped=%llu, unknown_rva=%llu, parse_errors=%llu\n", static_cast<unsigned long long>(ns.HitsFileBytes), static_cast<unsigned long long>(ns.LinesRead), static_cast<unsigned long long>(ns.HitsSeen), static_cast<unsigned long long>(ns.HitsIngested), static_cast<unsigned long long>(ns.HitsDedup), static_cast<unsigned long long>(ns.UnknownRva), static_cast<unsigned long long>(ns.ParseErrors));
            store.FlushStreams();
        }
    }
}

uint32_t AutoDebugTool::BuildMonitors(std::vector<InsnSite>& sites, uint32_t pid, uint64_t base, HANDLE hproc, const std::string& outputname, bool capturecallparams, bool capturestackargs, bool capturereturns, bool forceloadpages)
{
    if (base == 0 || sites.empty())
    {
        return 0;
    }

    for (InsnSite& j : sites)
    {
        j.Va = base + j.Rva;
    }

    std::map<uint64_t, std::vector<const InsnSite*>> bypage;
    for (const InsnSite& j : sites)
    {
        bypage[j.Va >> 12].push_back(&j);
    }

    struct Phantom
    {
        uint64_t RetVa;
        const InsnSite* Site;
    };
    std::map<uint64_t, std::vector<Phantom>> phantomsbypage;
    uint32_t phantomssamesitepage = 0;
    uint32_t phantomscrosspage = 0;
    uint32_t phantomonlypages = 0;
    uint32_t syscallphantoms = 0;
    {
        const bool anysyscall = std::any_of(sites.begin(), sites.end(), [](const InsnSite& s) { return s.Kind == SiteKind::Syscall; });
        if (capturereturns || anysyscall)
        {
            for (const InsnSite& s : sites)
            {
                const DebugTarget* tgt = DebugTargetRegistry::Get(s.Kind);
                if (tgt == nullptr || !tgt->WantsPhantomRet(capturereturns))
                {
                    continue;
                }

                const uint64_t retva = s.Va + s.Length;
                const uint64_t retpage = retva >> 12;
                const uint64_t sitepage = s.Va >> 12;
                phantomsbypage[retpage].push_back({ retva, &s });
                if (retpage == sitepage)
                {
                    ++phantomssamesitepage;
                }
                else
                {
                    ++phantomscrosspage;
                }
                if (s.Kind == SiteKind::Syscall)
                {
                    ++syscallphantoms;
                }
            }
            for (const auto& [page, _] : phantomsbypage)
            {
                if (bypage.find(page) == bypage.end())
                {
                    bypage[page];
                    ++phantomonlypages;
                }
            }
            std::printf("[autodebug] phantom-ret pages: same-site=%u, cross-page=%u (added %u phantom-only page monitor(s); %u from syscall sites)\n", phantomssamesitepage, phantomscrosspage, phantomonlypages, syscallphantoms);
        }
    }

    {
        char pcmd[64];
        std::snprintf(pcmd, sizeof(pcmd), "prealloc monitor %zx", bypage.size());
        Session.SetTeeStdout(false);
        std::string presp = Session.Run(pcmd);
        Session.SetTeeStdout(true);
        std::printf("[autodebug] %s -> %s\n", pcmd, AutoDebugUtils::ResponseHasError(presp) ? "FAILED (see below)" : "ok");
    }

    const bool iskernel = (pid == 0);

    if (!iskernel)
    {
        uint32_t prefaulted = 0;
        if (hproc != nullptr && forceloadpages)
        {
            for (const auto& kv : bypage)
            {
                const uint64_t page = kv.first << 12;
                uint8_t dummy = 0;
                SIZE_T got = 0;
                if (ReadProcessMemory(hproc, reinterpret_cast<LPCVOID>(page), &dummy, 1, &got) && got == 1)
                {
                    ++prefaulted;
                }
            }
            std::printf("[autodebug] prefaulted %u / %zu page(s) via RPM before arming\n", prefaulted, bypage.size());
        }

        Session.SetTeeStdout(false);
        Session.SetBufferingEnabled(false);
        for (const auto& kv : bypage)
        {
            TouchPage(pid, kv.first << 12);
            ++prefaulted;
        }
        Session.SetBufferingEnabled(true);
        Session.SetTeeStdout(true);

        const char* why = (hproc == nullptr) ? "no OpenProcess handle" : "force-load off, no VM_READ";
        std::printf("[autodebug] db-touched %u / %zu page(s) via HyperDbg before arming (%s)\n", prefaulted, bypage.size(), why);
    }
    else
    {
        std::puts("[autodebug] kernel target: skipping RPM prefault (not applicable). Cold PAGE-section pages will be skipped this run.");
    }

    uint32_t armed = 0;
    uint32_t skipped = 0;
    uint32_t failed = 0;
    uint32_t ntruncated = 0;
    bool shownsample = false;

    static constexpr size_t MaxScriptBytes = 10ull * 1024ull * 1024ull;

    for (const auto& kv : bypage)
    {
        const uint64_t page = kv.first << 12;
        const std::vector<const InsnSite*>& pagesites = kv.second;

        uint8_t probe = 0;
        const bool probeok = iskernel ? Session.Read(4, page, &probe, 1) : Session.Read(pid, page, &probe, 1, HyperDbgMemory::ReadPath::FromVmxRoot);
        if (!probeok)
        {
            ++skipped;
            continue;
        }

        uint64_t lo = UINT64_MAX;
        uint64_t hi = 0;
        for (const InsnSite* j : pagesites)
        {
            if (j->Va < lo)
            {
                lo = j->Va;
            }
            if (j->Va > hi)
            {
                hi = j->Va;
            }
        }

        char range[128];
        if (iskernel)
        {
            std::snprintf(range, sizeof(range), "!monitor x 0x%llx 0x%llx pid all", static_cast<unsigned long long>(lo), static_cast<unsigned long long>(hi));
        }
        else
        {
            std::snprintf(range, sizeof(range), "!monitor x 0x%llx 0x%llx pid %x", static_cast<unsigned long long>(lo), static_cast<unsigned long long>(hi), pid);
        }

        char basebuf[32];
        std::snprintf(basebuf, sizeof(basebuf), "0x%llx", static_cast<unsigned long long>(base));

        std::vector<std::string> sitepayloads(pagesites.size());
        for (size_t i = 0; i < pagesites.size(); ++i)
        {
            const InsnSite* s = pagesites[i];
            const DebugTarget* tgt = DebugTargetRegistry::Get(s->Kind);
            if (tgt != nullptr)
            {
                tgt->EmitPayload(sitepayloads[i], *s, basebuf, capturecallparams, capturestackargs);
            }
        }

        std::vector<std::string> phantompayloads;
        {
            auto pit = phantomsbypage.find(kv.first);
            if (pit != phantomsbypage.end())
            {
                phantompayloads.reserve(pit->second.size());
                for (const Phantom& ph : pit->second)
                {
                    std::string p;
                    const DebugTarget* tgt = DebugTargetRegistry::Get(ph.Site->Kind);
                    if (tgt != nullptr)
                    {
                        tgt->EmitPhantomPayload(p, *ph.Site, ph.RetVa);
                    }
                    phantompayloads.push_back(std::move(p));
                }
            }
        }

        std::string suffix = " }";
        if (!outputname.empty())
        {
            suffix += " output {";
            suffix += outputname;
            suffix += "}";
        }

        const std::string masterhead = std::string(range) + " script { if (";
        std::string mastertail = ") { printf(\"[autodbg-hit] rva=%llx rax=%llx rbx=%llx rcx=%llx rdx=%llx rsi=%llx rdi=%llx rbp=%llx rsp=%llx r8=%llx r9=%llx r10=%llx r11=%llx r12=%llx r13=%llx r14=%llx r15=%llx rflags=%llx\\n\", $context - ";
        mastertail += basebuf;
        mastertail += ", @rax, @rbx, @rcx, @rdx, @rsi, @rdi, @rbp, @rsp, @r8, @r9, @r10, @r11, @r12, @r13, @r14, @r15, @rflags); }";

        size_t projected = masterhead.size() + mastertail.size() + suffix.size();
        size_t nincluded = 0;
        std::string cond;
        for (size_t i = 0; i < pagesites.size(); ++i)
        {
            char term[40];
            int termlen = std::snprintf(term, sizeof(term), "$context == 0x%llx", static_cast<unsigned long long>(pagesites[i]->Va));
            const size_t seplen = (nincluded == 0 ? 0 : 4);
            const size_t added = static_cast<size_t>(termlen) + seplen + sitepayloads[i].size();
            if (projected + added > MaxScriptBytes)
            {
                break;
            }
            projected += added;
            if (nincluded)
            {
                cond += " || ";
            }
            cond += term;
            ++nincluded;
        }

        const bool phantomonly = (nincluded == 0);
        if (phantomonly)
        {
            cond = "$context == 0";
        }

        size_t nphantomsincluded = 0;
        for (size_t i = 0; i < phantompayloads.size(); ++i)
        {
            const size_t added = phantompayloads[i].size();
            if (projected + added > MaxScriptBytes)
            {
                break;
            }
            projected += added;
            ++nphantomsincluded;
        }

        const bool truncated = (nincluded < pagesites.size()) || (nphantomsincluded < phantompayloads.size());
        if (truncated)
        {
            ++ntruncated;
        }

        std::string cmd = masterhead;
        cmd += cond;
        cmd += mastertail;
        for (size_t i = 0; i < nincluded; ++i)
        {
            cmd += sitepayloads[i];
        }
        for (size_t i = 0; i < nphantomsincluded; ++i)
        {
            cmd += phantompayloads[i];
        }
        cmd += suffix;

        if (!shownsample)
        {
            std::printf("[autodebug]   sample cmd: %s\n", cmd.c_str());
            shownsample = true;
        }

        {
            wchar_t tmpdir[MAX_PATH] = {};
            DWORD tlen = GetTempPathW(MAX_PATH, tmpdir);
            if (tlen > 0 && tlen < MAX_PATH)
            {
                std::filesystem::path dumppath = std::filesystem::path(tmpdir) / L"autodbg_last_monitor.txt";
                std::ofstream df(dumppath, std::ios::binary | std::ios::trunc);
                if (df)
                {
                    df << "; page 0x" << std::hex << page << "  sites=" << std::dec << pagesites.size() << "  included=" << nincluded << "  bytes=" << cmd.size() << "\n";
                    df.write(cmd.data(), static_cast<std::streamsize>(cmd.size()));
                }
            }
        }

        Session.SetTeeStdout(false);
        std::string resp = Session.Run(cmd);
        Session.SetTeeStdout(true);

        if (AutoDebugUtils::ResponseHasError(resp))
        {
            std::string e = resp;
            while (!e.empty() && (e.back() == '\n' || e.back() == '\r' || e.back() == ' '))
            {
                e.pop_back();
            }
            for (char& c : e)
            {
                if (c == '\n' || c == '\r')
                {
                    c = ' ';
                }
            }
            if (e.size() > 200)
            {
                e.resize(200);
            }
            std::printf("[autodebug]   page 0x%llx : %zu jump(s) -> FAILED: %s\n", static_cast<unsigned long long>(page), pagesites.size(), e.empty() ? "(no message)" : e.c_str());
            ++failed;
        }
        else
        {
            ++armed;
        }
    }

    std::printf("[autodebug] armed %u / %zu page(s); skipped %u non-resident (never executed -> nothing to catch)%s\n", armed, bypage.size(), skipped, failed ? "" : ", 0 failed");
    if (failed)
    {
        std::printf("[autodebug] %u resident page(s) failed to arm (see above)\n", failed);
    }
    if (ntruncated)
    {
        std::printf("[autodebug] %u monitor(s) exceeded the driver's %llu-MB script cap and had trailing sites dropped this run\n", ntruncated, static_cast<unsigned long long>(MaxScriptBytes / (1024 * 1024)));
        std::printf("[autodebug]   -> rescan with the \"ignore RVAs already observed\" targeting mode to cover the dropped tail(s)\n");
    }
    return armed;
}

std::vector<AutoDebugTool::ForeignModule> AutoDebugTool::SnapshotForeignModules(uint32_t pid, HANDLE hproc, uint64_t tracedbase)
{
    std::vector<ForeignModule> out;

    if (hproc == nullptr)
    {
        std::fprintf(stderr, "[autodebug] iat resolver: no process handle (OpenProcess failed upstream) -- no module snapshot\n");
        return out;
    }
    ProcessBasicInfoMin pbi = {};
    ULONG got = 0;
    if (NtQueryInformationProcess(hproc, 0, &pbi, sizeof(pbi), &got) != 0 || pbi.PebBaseAddress == nullptr)
    {
        std::fprintf(stderr, "[autodebug] iat resolver: NtQueryInformationProcess failed -- no module snapshot\n");
        return out;
    }
    const uint64_t peb = reinterpret_cast<uint64_t>(pbi.PebBaseAddress);

    uint64_t ldr = 0;
    if (!Session.Read(pid, peb + 0x18, &ldr, sizeof(ldr), HyperDbgMemory::ReadPath::FromVmxRoot) || ldr == 0)
    {
        std::fprintf(stderr, "[autodebug] iat resolver: could not read PEB.Ldr\n");
        return out;
    }

    const uint64_t listhead = ldr + 0x10;
    uint64_t flink = 0;
    if (!Session.Read(pid, listhead, &flink, sizeof(flink), HyperDbgMemory::ReadPath::FromVmxRoot) || flink == 0)
    {
        std::fprintf(stderr, "[autodebug] iat resolver: could not read PEB.Ldr list head\n");
        return out;
    }

    constexpr int MaxModules = 512;
    int steps = 0;
    for (uint64_t entry = flink; entry != listhead && steps < MaxModules; ++steps)
    {
        uint64_t dllbase = 0;
        uint32_t sizeofimage = 0;
        if (!Session.Read(pid, entry + 0x30, &dllbase, sizeof(dllbase), HyperDbgMemory::ReadPath::FromVmxRoot) || !Session.Read(pid, entry + 0x40, &sizeofimage, sizeof(sizeofimage), HyperDbgMemory::ReadPath::FromVmxRoot))
        {
            break;
        }

        uint64_t nextflink = 0;
        if (!Session.Read(pid, entry, &nextflink, sizeof(nextflink), HyperDbgMemory::ReadPath::FromVmxRoot) || nextflink == 0)
        {
            break;
        }

        if (dllbase == 0 || dllbase == tracedbase || sizeofimage == 0)
        {
            entry = nextflink;
            continue;
        }

        uint16_t bnlen = 0;
        uint16_t bnmax = 0;
        uint64_t bnbuffer = 0;
        Session.Read(pid, entry + 0x58, &bnlen, sizeof(bnlen), HyperDbgMemory::ReadPath::FromVmxRoot);
        Session.Read(pid, entry + 0x58 + 2, &bnmax, sizeof(bnmax), HyperDbgMemory::ReadPath::FromVmxRoot);
        Session.Read(pid, entry + 0x58 + 8, &bnbuffer, sizeof(bnbuffer), HyperDbgMemory::ReadPath::FromVmxRoot);

        std::wstring basename;
        if (bnbuffer != 0 && bnlen > 0 && bnlen <= 2048)
        {
            basename.resize(bnlen / sizeof(wchar_t));
            if (!Session.Read(pid, bnbuffer, basename.data(), bnlen, HyperDbgMemory::ReadPath::FromVmxRoot))
            {
                basename.clear();
            }
        }

        uint16_t fnlen = 0;
        uint64_t fnbuffer = 0;
        Session.Read(pid, entry + 0x48, &fnlen, sizeof(fnlen), HyperDbgMemory::ReadPath::FromVmxRoot);
        Session.Read(pid, entry + 0x48 + 8, &fnbuffer, sizeof(fnbuffer), HyperDbgMemory::ReadPath::FromVmxRoot);

        std::wstring fullpath;
        if (fnbuffer != 0 && fnlen > 0 && fnlen <= 4096)
        {
            fullpath.resize(fnlen / sizeof(wchar_t));
            if (!Session.Read(pid, fnbuffer, fullpath.data(), fnlen, HyperDbgMemory::ReadPath::FromVmxRoot))
            {
                fullpath.clear();
            }
        }

        ForeignModule fm;
        fm.Base = dllbase;
        fm.Size = sizeofimage;
        fm.FullPath = fullpath;
        fm.LowerName.reserve(basename.size());
        for (wchar_t w : basename)
        {
            char c = (w <= 0x7F) ? static_cast<char>(w) : '?';
            if (c >= 'A' && c <= 'Z')
            {
                c = static_cast<char>(c + 32);
            }
            fm.LowerName.push_back(c);
        }

        if (!fullpath.empty())
        {
            if (!AutoDebugPeUtils::ReadExportsFromDiskFile(fullpath, fm.Exports, fm.ByRva))
            {
                std::fprintf(stderr, "[autodebug] iat resolver: couldn't parse exports from %ls\n", fullpath.c_str());
            }
        }

        out.push_back(std::move(fm));

        entry = nextflink;
    }

    return out;
}

std::vector<AutoDebugTool::ForeignModule> AutoDebugTool::SnapshotForeignKernelModules(PEDumper& dumper, uint64_t tracedbase)
{
    std::vector<ForeignModule> out;

    std::vector<PEDumper::LoadedModule> kmods;
    try
    {
        kmods = dumper.EnumerateKernelModules();
    }
    catch (const std::exception& ex)
    {
        std::fprintf(stderr, "[autodebug] kernel iat resolver: EnumerateKernelModules threw: %s\n", ex.what());
        return out;
    }

    for (const PEDumper::LoadedModule& km : kmods)
    {
        if (km.Base == 0 || km.Size == 0)
        {
            continue;
        }
        if (km.Base == tracedbase)
        {
            continue;
        }

        ForeignModule fm{};
        fm.Base = km.Base;
        fm.Size = km.Size;
        fm.FullPath = AutoDebugPeUtils::NormalizeNtPath(km.FullPath);

        fm.LowerName.reserve(km.BaseName.size());
        for (wchar_t w : km.BaseName)
        {
            char c = (w <= 0x7F) ? static_cast<char>(w) : '?';
            if (c >= 'A' && c <= 'Z')
            {
                c = static_cast<char>(c + 32);
            }
            fm.LowerName.push_back(c);
        }

        if (!fm.FullPath.empty())
        {
            if (!AutoDebugPeUtils::ReadExportsFromDiskFile(fm.FullPath, fm.Exports, fm.ByRva))
            {
                std::fprintf(stderr, "[autodebug] kernel iat resolver: couldn't parse exports from %ls\n", fm.FullPath.c_str());
            }
        }

        out.push_back(std::move(fm));
    }

    return out;
}

void AutoDebugTool::WriteModulesSidecar(const std::filesystem::path& projectdir, const std::vector<ForeignModule>& mods, uint64_t tracedbase, uint32_t tracedsize, const std::wstring& tracedpath)
{
    std::ofstream f(projectdir / L"modules.tsv", std::ios::binary | std::ios::trunc);
    if (!f)
    {
        return;
    }

    auto widepathtoutf8 = [](const std::wstring& w) -> std::string
        {
            if (w.empty())
            {
                return {};
            }
            const int nb = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), static_cast<int>(w.size()), nullptr, 0, nullptr, nullptr);
            if (nb <= 0)
            {
                return {};
            }
            std::string s(static_cast<size_t>(nb), '\0');
            WideCharToMultiByte(CP_UTF8, 0, w.c_str(), static_cast<int>(w.size()), s.data(), nb, nullptr, nullptr);
            return s;
        };

    if (tracedbase != 0)
    {
        char b[64];
        std::snprintf(b, sizeof(b), "%llx\t%x\t", static_cast<unsigned long long>(tracedbase), static_cast<unsigned int>(tracedsize));
        f << "__traced__\t" << b << widepathtoutf8(tracedpath) << '\n';
    }

    for (const ForeignModule& fm : mods)
    {
        if (fm.LowerName.empty() || fm.FullPath.empty())
        {
            continue;
        }
        char b[64];
        std::snprintf(b, sizeof(b), "%llx\t%x\t", static_cast<unsigned long long>(fm.Base), static_cast<unsigned int>(fm.Size));
        f << fm.LowerName << '\t' << b << widepathtoutf8(fm.FullPath) << '\n';
    }
}

bool AutoDebugTool::BuildSyscallTable(const std::wstring& ntdllpath, std::unordered_map<uint32_t, std::string>& out)
{
    out.clear();

    std::vector<ForeignExport> exports;
    std::unordered_map<uint32_t, size_t> byrva;
    if (!AutoDebugPeUtils::ReadExportsFromDiskFile(ntdllpath, exports, byrva))
    {
        std::fprintf(stderr, "[autodebug] syscall table: couldn't parse ntdll exports from %ls\n", ntdllpath.c_str());
        return false;
    }

    std::ifstream f = AutoDebugPeUtils::OpenPeFileForRead(ntdllpath);
    if (!f)
    {
        std::fprintf(stderr, "[autodebug] syscall table: couldn't reopen %ls\n", ntdllpath.c_str());
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
    const auto* sectable = IMAGE_FIRST_SECTION(nt);
    const uint32_t nsec = nt->FileHeader.NumberOfSections;

    uint32_t nmatched = 0;
    uint32_t nskipped = 0;
    for (const ForeignExport& e : exports)
    {
        if (e.Name.size() < 3 || e.Name[0] != 'N' || e.Name[1] != 't')
        {
            continue;
        }

        const uint32_t off = AutoDebugPeUtils::ExpRvaToFileOffset(sectable, nsec, e.Rva);
        if (off == 0 || off + 16 > bytes.size())
        {
            ++nskipped;
            continue;
        }
        const uint8_t* p = bytes.data() + off;
        const size_t available = bytes.size() - off;

        uint32_t idx = 0;
        if (!AutoDebugPeUtils::DecodeNtdllSyscallImm(p, available, idx))
        {
            ++nskipped;
            continue;
        }

        out.emplace(idx, e.Name);
        ++nmatched;
    }

    std::printf("[autodebug] syscall table: matched %u / skipped %u Nt* stubs (%zu unique service numbers)\n", nmatched, nskipped, out.size());
    return !out.empty();
}

void AutoDebugTool::WriteSyscallTable(const std::filesystem::path& projectdir, const std::unordered_map<uint32_t, std::string>& map)
{
    if (map.empty())
    {
        return;
    }

    std::error_code ec;
    std::filesystem::create_directories(projectdir, ec);

    std::filesystem::path p = projectdir / L"syscall_table.tsv";
    std::ofstream f(p, std::ios::binary | std::ios::trunc);
    if (!f)
    {
        return;
    }

    std::vector<std::pair<uint32_t, std::string>> sorted(map.begin(), map.end());
    std::sort(sorted.begin(), sorted.end(), [](const std::pair<uint32_t, std::string>& a, const std::pair<uint32_t, std::string>& b) { return a.first < b.first; });
    for (const auto& kv : sorted)
    {
        char buf[16];
        std::snprintf(buf, sizeof(buf), "0x%x", kv.first);
        f << buf << '\t' << kv.second << '\n';
    }
}

uint32_t AutoDebugTool::BuildNtdllSyscallMonitors(uint64_t ntdllbase, uint32_t ntdllsize, const std::wstring& ntdllpath, uint32_t pid, HANDLE hproc, const std::string& outputname, bool capturestackargs, std::vector<InsnSite>& ntdllsitesout)
{
    ntdllsitesout.clear();
    if (ntdllbase == 0 || ntdllpath.empty())
    {
        return 0;
    }

    std::string ntdllpatha;
    ntdllpatha.reserve(ntdllpath.size());
    for (wchar_t w : ntdllpath)
    {
        if (w > 0x7f)
        {
            std::fprintf(stderr, "[autodebug] ntdll path contains non-ASCII glyphs; syscall scan skipped: %ls\n", ntdllpath.c_str());
            return 0;
        }
        ntdllpatha.push_back(static_cast<char>(w));
    }

    uint64_t preferredbase = 0;
    std::vector<InsnSite> allsites = PeScan::ScanFile(ntdllpatha, preferredbase, PeScan::ScanOptions{});

    for (const InsnSite& s : allsites)
    {
        if (s.Kind == SiteKind::Syscall)
        {
            ntdllsitesout.push_back(s);
        }
    }
    if (ntdllsitesout.empty())
    {
        std::printf("[autodebug] ntdll syscall scan: 0 sites -- unusual, ntdll is expected to have ~500 syscall stubs; check that PeScan::ScanFile against %s produced non-empty output\n", ntdllpatha.c_str());
        return 0;
    }

    for (InsnSite& s : ntdllsitesout)
    {
        s.Va = ntdllbase + s.Rva;
    }

    std::map<uint64_t, std::vector<const InsnSite*>> bypage;
    for (const InsnSite& s : ntdllsitesout)
    {
        bypage[s.Va >> 12].push_back(&s);
    }

    struct Phantom
    {
        uint64_t RetVa;
        const InsnSite* Site;
    };
    std::map<uint64_t, std::vector<Phantom>> phantomsbypage;
    for (const InsnSite& s : ntdllsitesout)
    {
        const uint64_t retva = s.Va + s.Length;
        phantomsbypage[retva >> 12].push_back({ retva, &s });
    }
    for (const auto& [page, _] : phantomsbypage)
    {
        if (bypage.find(page) == bypage.end())
        {
            bypage[page];
        }
    }

    std::printf("[autodebug] ntdll syscall sites: %zu, spanning %zu page(s)\n", ntdllsitesout.size(), bypage.size());

    {
        char pcmd[64];
        std::snprintf(pcmd, sizeof(pcmd), "prealloc monitor %zx", bypage.size());
        Session.SetTeeStdout(false);
        std::string presp = Session.Run(pcmd);
        Session.SetTeeStdout(true);
        std::printf("[autodebug] %s -> %s\n", pcmd, AutoDebugUtils::ResponseHasError(presp) ? "FAILED (see below)" : "ok");
    }

    (void)hproc;

    uint32_t armed = 0;
    uint32_t skipped = 0;
    uint32_t failed = 0;
    char basebuf[32];
    std::snprintf(basebuf, sizeof(basebuf), "0x%llx", static_cast<unsigned long long>(ntdllbase));

    const DebugTarget* syscalltgt = DebugTargetRegistry::Get(SiteKind::Syscall);

    for (const auto& kv : bypage)
    {
        const uint64_t pageidx = kv.first;
        const uint64_t page = pageidx << 12;
        const std::vector<const InsnSite*>& pagesites = kv.second;

        uint8_t probe = 0;
        if (!Session.Read(pid, page, &probe, 1, HyperDbgMemory::ReadPath::FromVmxRoot))
        {
            ++skipped;
            continue;
        }

        uint64_t lo = UINT64_MAX;
        uint64_t hi = 0;
        for (const InsnSite* s : pagesites)
        {
            if (s->Va < lo)
            {
                lo = s->Va;
            }
            if (s->Va > hi)
            {
                hi = s->Va;
            }
        }
        if (lo == UINT64_MAX)
        {
            auto pit = phantomsbypage.find(pageidx);
            if (pit != phantomsbypage.end() && !pit->second.empty())
            {
                for (const Phantom& ph : pit->second)
                {
                    if (ph.RetVa < lo)
                    {
                        lo = ph.RetVa;
                    }
                    if (ph.RetVa > hi)
                    {
                        hi = ph.RetVa;
                    }
                }
            }
            else
            {
                continue;
            }
        }

        char range[128];
        std::snprintf(range, sizeof(range), "!monitor x 0x%llx 0x%llx pid %x", static_cast<unsigned long long>(lo), static_cast<unsigned long long>(hi), pid);

        std::string cmd = range;
        cmd += " script { if (";

        std::string cond;
        for (size_t i = 0; i < pagesites.size(); ++i)
        {
            if (i)
            {
                cond += " || ";
            }
            char t[40];
            std::snprintf(t, sizeof(t), "$context == 0x%llx", static_cast<unsigned long long>(pagesites[i]->Va));
            cond += t;
        }
        if (cond.empty())
        {
            cond = "$context == 0";
        }

        cmd += cond;
        cmd += ") { printf(\"[autodbg-hit] rva=%llx rax=%llx rbx=%llx rcx=%llx rdx=%llx rsi=%llx rdi=%llx rbp=%llx rsp=%llx r8=%llx r9=%llx r10=%llx r11=%llx r12=%llx r13=%llx r14=%llx r15=%llx rflags=%llx\\n\", $context - ";
        cmd += basebuf;
        cmd += ", @rax, @rbx, @rcx, @rdx, @rsi, @rdi, @rbp, @rsp, @r8, @r9, @r10, @r11, @r12, @r13, @r14, @r15, @rflags); }";

        if (syscalltgt != nullptr)
        {
            for (const InsnSite* s : pagesites)
            {
                syscalltgt->EmitPayload(cmd, *s, basebuf, false, capturestackargs);
            }
        }

        auto pit = phantomsbypage.find(pageidx);
        if (pit != phantomsbypage.end() && syscalltgt != nullptr)
        {
            for (const Phantom& ph : pit->second)
            {
                syscalltgt->EmitPhantomPayload(cmd, *ph.Site, ph.RetVa);
            }
        }

        cmd += " }";
        if (!outputname.empty())
        {
            cmd += " output {";
            cmd += outputname;
            cmd += "}";
        }

        Session.SetTeeStdout(false);
        std::string resp = Session.Run(cmd);
        Session.SetTeeStdout(true);

        if (AutoDebugUtils::ResponseHasError(resp))
        {
            std::string e = resp;
            while (!e.empty() && (e.back() == '\n' || e.back() == '\r' || e.back() == ' '))
            {
                e.pop_back();
            }
            for (char& c : e)
            {
                if (c == '\n' || c == '\r')
                {
                    c = ' ';
                }
            }
            if (e.size() > 200)
            {
                e.resize(200);
            }
            std::printf("[autodebug]   ntdll page 0x%llx : %zu site(s) -> FAILED: %s\n", static_cast<unsigned long long>(page), pagesites.size(), e.empty() ? "(no message)" : e.c_str());
            ++failed;
        }
        else
        {
            ++armed;
        }
    }

    std::printf("[autodebug] ntdll syscall monitors armed %u / %zu page(s); skipped %u non-resident, failed %u\n", armed, bypage.size(), skipped, failed);
    return armed;
}

void AutoDebugTool::ResolveForeignBranchTargets(AutoDebugStore& store, uint64_t tracedbase, const std::vector<ForeignModule>& modules, ObsKind kind)
{
    if (kind != ObsKind::IndCall && kind != ObsKind::IndBranch)
    {
        std::fprintf(stderr, "[autodebug] ResolveForeignBranchTargets: unsupported kind %d\n", static_cast<int>(kind));
        return;
    }
    const bool iscallkind = (kind == ObsKind::IndCall);
    const char* kindlabel = iscallkind ? "IndCallHit" : "IndBranchHit";
    const char* passlabel = iscallkind ? "iat resolver (calls)" : "rop resolver (jumps)";

    if (modules.empty())
    {
        std::printf("[autodebug] %s: no foreign modules snapshotted, skipping resolution\n", passlabel);
        return;
    }

    uint64_t hitsseen = 0;
    uint64_t inmodulehits = 0;
    uint64_t nobuckethits = 0;
    uint64_t noexporthits = 0;
    uint64_t resolvedhits = 0;
    uint64_t newrecords = 0;
    uint64_t duprecords = 0;
    uint64_t errrecords = 0;

    uint64_t ropnew = 0;
    uint64_t ropdup = 0;
    uint64_t roperr = 0;

    struct NoExportSample
    {
        std::string Module;
        uint32_t RvaWithin;
        uint64_t TargetVa;
        uint64_t SiteRva;
        std::string NearestName;
        uint32_t NearestRva;
        uint32_t ModuleExportCount;
    };
    constexpr size_t SampleCap = 16;
    std::vector<NoExportSample> noexportsamples;
    noexportsamples.reserve(SampleCap);

    struct NoBucketSample
    {
        uint64_t SiteRva;
        uint64_t TargetVa;
        std::string PrevModule;
        uint64_t PrevModuleEnd;
        std::string PrevBaseModule;
        uint64_t PrevBaseBase;
        uint64_t PrevBaseSize;
        std::string NextModule;
        uint64_t NextModuleBase;
    };
    std::vector<NoBucketSample> nobucketsamples;
    nobucketsamples.reserve(SampleCap);

    const uint64_t tracedend = tracedbase + (1ULL << 31);

    store.ForEachRecord(kind, [&](const void* rec, size_t sz)
        {
            if (sz != sizeof(IndCallHit))
            {
                return;
            }
            ++hitsseen;
            const IndCallHit* h = static_cast<const IndCallHit*>(rec);

            const uint64_t targetva = tracedbase + h->Target;

            if (targetva >= tracedbase && targetva < tracedend)
            {
                ++inmodulehits;
                return;
            }

            const ForeignModule* owner = nullptr;
            for (const ForeignModule& fm : modules)
            {
                if (targetva >= fm.Base && targetva < fm.Base + fm.Size)
                {
                    owner = &fm;
                    break;
                }
            }
            if (!owner)
            {
                ++nobuckethits;
                if (nobucketsamples.size() < SampleCap)
                {
                    NoBucketSample s;
                    s.SiteRva = h->Rva;
                    s.TargetVa = targetva;
                    s.PrevModuleEnd = 0;
                    s.PrevBaseBase = 0;
                    s.PrevBaseSize = 0;
                    s.NextModuleBase = UINT64_MAX;
                    for (const ForeignModule& fm : modules)
                    {
                        const uint64_t end = fm.Base + fm.Size;
                        if (end <= targetva && end > s.PrevModuleEnd)
                        {
                            s.PrevModule = fm.LowerName;
                            s.PrevModuleEnd = end;
                        }
                        if (fm.Base <= targetva && fm.Base > s.PrevBaseBase)
                        {
                            s.PrevBaseModule = fm.LowerName;
                            s.PrevBaseBase = fm.Base;
                            s.PrevBaseSize = fm.Size;
                        }
                        if (fm.Base > targetva && fm.Base < s.NextModuleBase)
                        {
                            s.NextModule = fm.LowerName;
                            s.NextModuleBase = fm.Base;
                        }
                    }
                    nobucketsamples.push_back(std::move(s));
                }
                return;
            }

            const uint32_t rvawithin = static_cast<uint32_t>(targetva - owner->Base);
            auto it = owner->ByRva.find(rvawithin);
            if (it == owner->ByRva.end())
            {
                ++noexporthits;

                {
                    RopHit rh = {};
                    rh.Rva = h->Rva;
                    rh.ModuleRva = rvawithin;
                    std::strncpy(rh.ModuleName, owner->LowerName.c_str(), sizeof(rh.ModuleName) - 1);
                    const IngestResult ir = store.IngestRop(rh);
                    switch (ir)
                    {
                    case IngestResult::New:
                        ++ropnew;
                        break;
                    case IngestResult::Duplicate:
                        ++ropdup;
                        break;
                    case IngestResult::Error:
                        ++roperr;
                        break;
                    }
                }

                if (noexportsamples.size() < SampleCap)
                {
                    NoExportSample s;
                    s.Module = owner->LowerName;
                    s.RvaWithin = rvawithin;
                    s.TargetVa = targetva;
                    s.SiteRva = h->Rva;
                    s.NearestRva = 0;
                    s.ModuleExportCount = static_cast<uint32_t>(owner->Exports.size());
                    uint32_t bestrva = 0;
                    size_t bestidx = SIZE_MAX;
                    for (size_t i = 0; i < owner->Exports.size(); ++i)
                    {
                        const uint32_t exrva = owner->Exports[i].Rva;
                        if (exrva <= rvawithin && exrva >= bestrva)
                        {
                            bestrva = exrva;
                            bestidx = i;
                        }
                    }
                    if (bestidx != SIZE_MAX)
                    {
                        s.NearestName = owner->Exports[bestidx].Name;
                        s.NearestRva = bestrva;
                    }
                    noexportsamples.push_back(std::move(s));
                }
                return;
            }

            const ForeignExport& fe = owner->Exports[it->second];

            if (iscallkind)
            {
                IatHit ih = {};
                ih.Rva = h->Rva;
                ih.ExportRva = fe.Rva;
                std::strncpy(ih.ModuleName, owner->LowerName.c_str(), sizeof(ih.ModuleName) - 1);
                std::strncpy(ih.ExportName, fe.Name.c_str(), sizeof(ih.ExportName) - 1);

                ++resolvedhits;
                const IngestResult ir = store.IngestIat(ih);
                switch (ir)
                {
                case IngestResult::New:
                    ++newrecords;
                    break;
                case IngestResult::Duplicate:
                    ++duprecords;
                    break;
                case IngestResult::Error:
                    ++errrecords;
                    break;
                }
            }
            else
            {
                RopHit rh = {};
                rh.Rva = h->Rva;
                rh.ModuleRva = fe.Rva;
                std::strncpy(rh.ModuleName, owner->LowerName.c_str(), sizeof(rh.ModuleName) - 1);
                const IngestResult ir = store.IngestRop(rh);
                switch (ir)
                {
                case IngestResult::New:
                    ++ropnew;
                    ++resolvedhits;
                    break;
                case IngestResult::Duplicate:
                    ++ropdup;
                    break;
                case IngestResult::Error:
                    ++roperr;
                    break;
                }
            }
        });

    std::printf("[autodebug] %s:\n", passlabel);
    std::printf("[autodebug]   %-12s records read      : %llu\n", kindlabel, static_cast<unsigned long long>(hitsseen));
    std::printf("[autodebug]   in-module (pass 1b handles)  : %llu\n", static_cast<unsigned long long>(inmodulehits));
    std::printf("[autodebug]   out-of-module, no module hit : %llu\n", static_cast<unsigned long long>(nobuckethits));
    std::printf("[autodebug]   in a module but not export   : %llu\n", static_cast<unsigned long long>(noexporthits));
    if (iscallkind)
    {
        std::printf("[autodebug]   resolved to (module, export) : %llu\n", static_cast<unsigned long long>(resolvedhits));
        std::printf("[autodebug]   iats.bin: new=%llu dup=%llu err=%llu\n", static_cast<unsigned long long>(newrecords), static_cast<unsigned long long>(duprecords), static_cast<unsigned long long>(errrecords));
        std::printf("[autodebug]   rop.bin : new=%llu dup=%llu err=%llu (from no-export bucket -- deobf pass 1j will rehost gadgets)\n", static_cast<unsigned long long>(ropnew), static_cast<unsigned long long>(ropdup), static_cast<unsigned long long>(roperr));
    }
    else
    {
        std::printf("[autodebug]   resolved to foreign target   : %llu (all routed to rop.bin -- no IAT-JMP rewrite path)\n", static_cast<unsigned long long>(resolvedhits));
        std::printf("[autodebug]   rop.bin : new=%llu dup=%llu err=%llu (no-export + export-match, both rehosted by pass 1j)\n", static_cast<unsigned long long>(ropnew), static_cast<unsigned long long>(ropdup), static_cast<unsigned long long>(roperr));
    }

    if (!noexportsamples.empty())
    {
        const uint64_t shown = noexportsamples.size();
        std::printf("[autodebug]   no-export sample (%llu of %llu):\n", static_cast<unsigned long long>(shown), static_cast<unsigned long long>(noexporthits));
        for (const NoExportSample& s : noexportsamples)
        {
            if (!s.NearestName.empty())
            {
                const uint32_t offset = s.RvaWithin - s.NearestRva;
                std::printf("[autodebug]     site=0x%08llx  %-20s  rva_within=0x%x  va=0x%llx  nearest=%s+0x%x  (%u exports in module)\n", static_cast<unsigned long long>(s.SiteRva), s.Module.c_str(), s.RvaWithin, static_cast<unsigned long long>(s.TargetVa), s.NearestName.c_str(), offset, s.ModuleExportCount);
            }
            else
            {
                std::printf("[autodebug]     site=0x%08llx  %-20s  rva_within=0x%x  va=0x%llx  nearest=(none)  (%u exports in module)\n", static_cast<unsigned long long>(s.SiteRva), s.Module.c_str(), s.RvaWithin, static_cast<unsigned long long>(s.TargetVa), s.ModuleExportCount);
            }
        }
        if (noexporthits > shown)
        {
            std::printf("[autodebug]     ... and %llu more not shown\n", static_cast<unsigned long long>(noexporthits - shown));
        }
    }

    if (!nobucketsamples.empty())
    {
        const uint64_t shown = nobucketsamples.size();
        std::printf("[autodebug]   no-bucket sample (%llu of %llu):\n", static_cast<unsigned long long>(shown), static_cast<unsigned long long>(nobuckethits));
        for (const NoBucketSample& s : nobucketsamples)
        {
            const char* prevname = s.PrevModule.empty() ? "(nothing below by end)" : s.PrevModule.c_str();
            const char* prevbasename = s.PrevBaseModule.empty() ? "(nothing below by base)" : s.PrevBaseModule.c_str();
            const char* nextname = s.NextModule.empty() ? "(nothing above)" : s.NextModule.c_str();
            const uint64_t gapabove = (s.NextModuleBase != UINT64_MAX) ? (s.NextModuleBase - s.TargetVa) : 0;
            std::printf("[autodebug]     site=0x%08llx  va=0x%llx\n", static_cast<unsigned long long>(s.SiteRva), static_cast<unsigned long long>(s.TargetVa));
            std::printf("[autodebug]       closest end<=va:  %s (end 0x%llx)\n", prevname, static_cast<unsigned long long>(s.PrevModuleEnd));
            std::printf("[autodebug]       closest base<=va: %s (base 0x%llx, size 0x%llx, base+size=0x%llx%s)\n", prevbasename, static_cast<unsigned long long>(s.PrevBaseBase), static_cast<unsigned long long>(s.PrevBaseSize), static_cast<unsigned long long>(s.PrevBaseBase + s.PrevBaseSize), (!s.PrevBaseModule.empty() && s.PrevBaseBase + s.PrevBaseSize < s.TargetVa) ? "  <-- SIZE LOOKS TRUNCATED" : "");
            std::printf("[autodebug]       closest base>va:  %s (base 0x%llx, -0x%llx away)\n", nextname, static_cast<unsigned long long>(s.NextModuleBase), static_cast<unsigned long long>(gapabove));
        }
        if (nobuckethits > shown)
        {
            std::printf("[autodebug]     ... and %llu more not shown\n", static_cast<unsigned long long>(nobuckethits - shown));
        } 

        std::printf("[autodebug]   full loaded-module list (%zu module(s), sorted by base):\n", modules.size());
        std::vector<const ForeignModule*> sorted;
        sorted.reserve(modules.size());
        for (const ForeignModule& fm : modules)
        {
            sorted.push_back(&fm);
        }
        std::sort(sorted.begin(), sorted.end(), [](const ForeignModule* a, const ForeignModule* b) { return a->Base < b->Base; });
        for (const ForeignModule* fm : sorted)
        {
            std::printf("[autodebug]     0x%016llx - 0x%016llx  (size=0x%08x)  %s  (%zu exports)\n", static_cast<unsigned long long>(fm->Base), static_cast<unsigned long long>(fm->Base + fm->Size), fm->Size, fm->LowerName.empty() ? "(no name)" : fm->LowerName.c_str(), fm->Exports.size());
        }
    }
}