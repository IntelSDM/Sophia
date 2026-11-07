#include "../Pch.h"
#include "DumpTool.h"
#include "AutoDebugger/AutoDebugTool.h"
#include "Deobfuscator/Deobfuscator.h"
#include "PTTextRebuilder.h"
#include "CliHelpers.h"
#include "../HyperDBG/PtAnalysis.h"
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <iostream>
#include <mutex>
#include <system_error>
#include <thread>
#include <vector>

#pragma comment(lib, "Keystone.lib")

DumpTool::DumpTool() : DumpTool(Config{})
{
}

DumpTool::DumpTool(const Config& cfg) : Cfg(cfg)
{
}

void DumpTool::EnsureSession()
{
    if (Session)
    {
        return;
    }
    Session = std::make_unique<HyperDbgSession>(Cfg.HyperDbgPath.wstring());
    std::puts("\n[+] hypervisor + hypertrace loaded\n");
    Dumper = std::make_unique<PEDumper>(*Session);
}

bool DumpTool::EnsurePrimed()
{
    if (Primed)
    {
        return PrimeOk;
    }
    Primed = true;
    std::puts("[+] priming PEDumper kernel symbol/offset cache...");
    try
    {
        Dumper->PrimeCache();
        PrimeOk = true;
    }
    catch (const std::exception& ex)
    {
        std::fprintf(stderr, "[!] PEDumper::PrimeCache failed: %s\n", ex.what());
        PrimeOk = false;
    }
    return PrimeOk;
}

DumpTool::Artifacts DumpTool::ArtifactsFor(const std::string& stem) const
{
    Artifacts a;
    a.DumpDir = Cfg.OutputRoot / (stem + ".dumps");
    a.AnalysisJson = Cfg.OutputRoot / (stem + ".pt.json");
    a.DumpCsv = Cfg.OutputRoot / (stem + ".dump.csv");
    a.Manifest = Cfg.OutputRoot / (stem + ".rebuilt.manifest.txt");
    return a;
}

void DumpTool::RunInteractive()
{
    int top = CliHelpers::PromptChoice("=== Sophia: Auto Debugger And Deobfuscator ===", { "Dump", "AutoDebug", "Deobfuscate" });
    switch (top)
    {
    case 1: RunDumpFlow(); break;
    case 2: RunAutoDebugFlow(); break;
    case 3: RunDeobfuscateFlow(); break;
    }
}

void DumpTool::RunDumpFlow()
{
    EnsureSession();
    int kind = CliHelpers::PromptChoice("Target type:", { "Usermode process (launch from .exe path)", "Kernel driver (by loaded driver name)" });
    bool wanttrace = CliHelpers::PromptYesNo("Capture PT trace and rebuild .text?", false);
    const bool dotrace = wanttrace && (kind == 1);
    bool completeimage = true;
    if (!dotrace)
    {
        completeimage = CliHelpers::PromptYesNo("Fill non-resident pages from disk for a complete image?\n  (say No for packed/obfuscated targets -- keeps only what's really in memory)", true);
    }
    if (kind == 1)
    {
        std::string exepath = CliHelpers::PromptNonEmpty("exe path: ");
        if (dotrace)
        {
            TraceAndDumpUser(exepath);
        }
        else
        {
            DumpUser(exepath, completeimage);
        }
    }
    else
    {
        if (wanttrace)
        {
            std::fprintf(stderr, "[!] PT Doesn't support Drivers, Just dumping it instead\n");
        }
        std::string drivername = CliHelpers::PromptNonEmpty("driver name (e.g. hyperkd.sys): ");
        DumpDriver(drivername, completeimage);
    }
    std::puts("\n[+] press ENTER to tear down\n");
    std::cin.get();
}

void DumpTool::RunAutoDebugFlow()
{
    EnsureSession();
    int kind = CliHelpers::PromptChoice("Target type:", { "Usermode process (attach by exe name)", "Kernel driver (by loaded driver name)" });
    AutoDebugTool tool(*Session);
    if (kind == 1)
    {
        std::string dumppath = CliHelpers::PromptNonEmpty("dump path (on disk PE / memory dump for the SCAN): ");
        std::string exename = CliHelpers::PromptNonEmpty("process image name to attach to (e.g. notepad.exe): ");
        tool.RunUser(dumppath, exename);
    }
    else
    {
        if (!EnsurePrimed())
        {
            std::fprintf(stderr, "[!] cache prime failed -- can't enumerate kernel modules for the AutoDebug driver flow. Aborting.\n");
            return;
        }
        std::string drivername = CliHelpers::PromptNonEmpty("driver name (e.g. hyperkd.sys): ");
        tool.RunDriver(*Dumper, drivername);
    }
}

void DumpTool::RunDeobfuscateFlow()
{
    std::string filepath = CliHelpers::PromptNonEmpty("file path: ");
    Deobfuscator deobf;
    Deobfuscator::Report r = deobf.Run(filepath);
    Deobfuscator::PrintReport(r);
}

void DumpTool::DumpUser(const std::string& exepath, bool completeimage)
{
    EnsureSession();
    if (!EnsurePrimed())
    {
        std::fprintf(stderr, "[!] cache prime failed -- cannot dump. Aborting.\n");
        return;
    }
    std::error_code ec;
    if (!std::filesystem::exists(exepath, ec))
    {
        std::fprintf(stderr, "[!] exe not found: %s\n", exepath.c_str());
        return;
    }
    const std::string stem = std::filesystem::path(exepath).stem().string();
    const Artifacts art = ArtifactsFor(stem);
    HANDLE hproc = nullptr;
    uint32_t pid = 0;
    if (!CliHelpers::LaunchProcess(exepath, hproc, pid))
    {
        std::fprintf(stderr, "[!] CreateProcess failed (GetLastError=%lu): %s\n", GetLastError(), exepath.c_str());
        return;
    }
    std::printf("[+] launched %s as pid %u\n", stem.c_str(), pid);
    std::vector<PEDumper::DumpResult> results;
    try
    {
        results = Dumper->DumpProcess(pid, Cfg.DumpDelay, art.DumpDir, true, completeimage);
    }
    catch (const std::exception& ex)
    {
        std::fprintf(stderr, "[!] DumpProcess threw: %s\n", ex.what());
    }
    TerminateProcess(hproc, 0);
    CloseHandle(hproc);
    auto okcount = std::count_if(results.begin(), results.end(), [](const PEDumper::DumpResult& d)
        {
            return d.Ok;
        });
    std::printf("[+] dumped %zu / %zu module(s) to %ls\n", static_cast<size_t>(okcount), results.size(), art.DumpDir.wstring().c_str());
}

void DumpTool::DumpDriver(const std::string& drivername, bool completeimage)
{
    EnsureSession();
    if (!EnsurePrimed())
    {
        std::fprintf(stderr, "[!] cache prime failed -- cannot dump. Aborting.\n");
        return;
    }
    std::vector<PEDumper::LoadedModule> modules;
    try
    {
        modules = Dumper->EnumerateKernelModules();
    }
    catch (const std::exception& ex)
    {
        std::fprintf(stderr, "[!] EnumerateKernelModules threw: %s\n", ex.what());
        return;
    }
    const std::wstring query = CliHelpers::LowerW(CliHelpers::Widen(drivername));
    const PEDumper::LoadedModule* hit = nullptr;
    for (const auto& m : modules)
    {
        if (CliHelpers::DriverNameMatches(m.BaseName, query))
        {
            hit = &m;
            break;
        }
    }
    if (hit == nullptr)
    {
        std::fprintf(stderr, "[!] driver not loaded: %s\n", drivername.c_str());
        std::fprintf(stderr, "    %zu drivers loaded; names containing \"%s\":\n", modules.size(), drivername.c_str());
        int shown = 0;
        for (const auto& m : modules)
        {
            if (CliHelpers::LowerW(m.BaseName).find(query) != std::wstring::npos && shown < 12)
            {
                std::fprintf(stderr, "      %ls\n", m.BaseName.c_str());
                ++shown;
            }
        }
        if (shown == 0)
        {
            std::fprintf(stderr, "      (none -- run with a substring to widen the search)\n");
        }
        return;
    }
    const std::string stem = std::filesystem::path(hit->BaseName).stem().string();
    const Artifacts art = ArtifactsFor(stem);
    {
        std::error_code ec;
        std::filesystem::remove_all(art.DumpDir, ec);
        std::filesystem::create_directories(art.DumpDir, ec);
    }
    std::printf("[+] %ls @ %016llx (%u bytes) -> dumping...\n", hit->BaseName.c_str(), static_cast<unsigned long long>(hit->Base), hit->Size);
    auto out = art.DumpDir / hit->BaseName;
    PEDumper::DumpResult r = Dumper->DumpOne(*hit, out, true, completeimage);
    if (r.Ok)
    {
        std::printf("[+] dumped %ls: %u sec / %u holes  %u B (+%u backfilled) -> %ls\n", hit->BaseName.c_str(), r.SectionsDumped, r.SectionsSkipped, r.HeaderBytes + r.DataBytes + r.CodeBytes, r.BackfilledBytes, out.wstring().c_str());
    }
    else
    {
        std::fprintf(stderr, "[!] dump failed: %s\n", r.Error.c_str());
    }
}

void DumpTool::TraceAndDumpUser(const std::string& exepath)
{
    EnsureSession();
    if (exepath.find(' ') != std::string::npos)
    {
        std::fprintf(stderr, "[!] PT trace needs a space-free path (HyperDbg 0.23 parser can't handle spaces/quotes).\n    Copy the exe somewhere without spaces, or pick the no-trace dump instead.\n");
        return;
    }
    std::error_code ec;
    if (!std::filesystem::exists(exepath, ec))
    {
        std::fprintf(stderr, "[!] exe not found: %s\n", exepath.c_str());
        return;
    }
    const std::string targetimagename = std::filesystem::path(exepath).filename().string();
    const std::string stem = std::filesystem::path(exepath).stem().string();
    const Artifacts art = ArtifactsFor(stem);
    std::filesystem::remove(art.Manifest, ec);
    const bool dumpavailable = EnsurePrimed();
    if (!dumpavailable)
    {
        std::fprintf(stderr, "[!] continuing without PE dump (PT trace still armed)\n");
    }
    PtAnalysis analyzer;
    std::mutex analyzermx;
    std::atomic<bool> tracecomplete{ false };
    std::string donescan;
    donescan.reserve(256);
    Session->SetMessageHandler([&](const char* msg)
        {
            std::lock_guard<std::mutex> lk(analyzermx);
            analyzer.Ingest(msg);
            donescan.append(msg);
            if (donescan.size() > 256)
            {
                donescan.erase(0, donescan.size() - 256);
            }
            if (donescan.find("instruction(s) total") != std::string::npos)
            {
                tracecomplete.store(true);
            }
        });
    Session->SetTeeStdout(false);
    Session->SetBufferingEnabled(false);
    std::fflush(stdout);
    FILE* savedstdout = nullptr;
    freopen_s(&savedstdout, "NUL", "w", stdout);
    std::vector<uint32_t> beforepids;
    if (dumpavailable)
    {
        beforepids = Dumper->EnumeratePidsByImageName(targetimagename);
    }
    const bool enableok = Session->TraceEnableForPath(exepath, Cfg.TraceBufferSize);
    std::vector<PEDumper::DumpResult> dumpresults;
    std::string dumperror;
    std::thread dumpthread;
    if (enableok && dumpavailable)
    {
        dumpthread = std::thread([&]()
            {
                try
                {
                    std::fprintf(stderr, "[dump] waiting for the launched %s instance to appear...\n", targetimagename.c_str());
                    uint32_t pid = 0;
                    for (int i = 0; i < 40 && pid == 0; ++i)
                    {
                        auto now = Dumper->EnumeratePidsByImageName(targetimagename);
                        for (uint32_t cand : now)
                        {
                            if (std::find(beforepids.begin(), beforepids.end(), cand) == beforepids.end())
                            {
                                pid = cand;
                                break;
                            }
                        }
                        if (pid == 0)
                        {
                            std::this_thread::sleep_for(std::chrono::milliseconds(50));
                        }
                    }
                    if (pid == 0)
                    {
                        std::fprintf(stderr, "[dump] no new %s instance appeared after launch; falling back to live-by-name lookup\n", targetimagename.c_str());
                        pid = Dumper->FindLivePidByImageName(targetimagename);
                    }
                    if (pid == 0)
                    {
                        dumperror = "could not identify the launched target pid";
                        std::fprintf(stderr, "[dump] %s -- dumping diagnostics:\n", dumperror.c_str());
                        std::fprintf(stderr, "[dump] matching against name '%s' (case-insensitive, full length)\n", targetimagename.c_str());
                        std::fprintf(stderr, "[dump] pre-launch snapshot held %zu match(es):", beforepids.size());
                        for (uint32_t p : beforepids)
                        {
                            std::fprintf(stderr, " %u", p);
                        }
                        std::fprintf(stderr, "\n");
                        Dumper->PrintProcessRoster();
                        return;
                    }
                    std::fprintf(stderr, "[dump] launched pid = %u; sleeping %llds then snapshotting alongside PT stream...\n", pid, static_cast<long long>(std::chrono::duration_cast<std::chrono::seconds>(Cfg.DumpDelay).count()));
                    dumpresults = Dumper->DumpProcess(pid, Cfg.DumpDelay, art.DumpDir, false);
                    std::fprintf(stderr, "[dump] complete: %zu module(s) attempted\n", dumpresults.size());
                }
                catch (const std::exception& ex)
                {
                    dumperror = ex.what();
                    std::fprintf(stderr, "[dump] exception: %s\n", dumperror.c_str());
                }
            });
    }
    else if (!dumpavailable)
    {
        std::fprintf(stderr, "[dump] skipped (PrimeCache failed above)\n");
    }
    if (enableok)
    {
        std::thread waiter([&]()
            {
                std::cin.get();
                tracecomplete.store(true);
            });
        while (!tracecomplete.load())
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        waiter.detach();
    }
    if (dumpthread.joinable())
    {
        std::fprintf(stderr, "[dump] joining dump thread before !pt disable...\n");
        dumpthread.join();
    }
    Session->SetMessageHandler(nullptr);
    Session->TraceDisable();
    FILE* fdummy = nullptr;
    freopen_s(&fdummy, "CONOUT$", "w", stdout);
    Session->SetTeeStdout(true);
    Session->SetBufferingEnabled(true);
    if (!enableok)
    {
        std::fprintf(stderr, "[!] TraceEnableForPath failed\n");
        return;
    }
    PtTraceStats stats;
    {
        std::lock_guard<std::mutex> lk(analyzermx);
        stats = analyzer.Snapshot();
    }
    std::printf("[+] trace complete: %llu instructions across %zu modules\n", static_cast<unsigned long long>(stats.TotalInstructions), stats.Modules.size());
    PtAnalysis::PrintSummary(stats);
    analyzer.WriteJson(art.AnalysisJson.string(), true);
    analyzer.WriteDump(art.DumpCsv.string());
    std::puts("");
    if (!dumpavailable)
    {
        std::puts("[!] PEDumper: cache prime failed above, no dump attempted");
    }
    else if (!dumperror.empty())
    {
        std::printf("[!] PEDumper thread reported: %s\n", dumperror.c_str());
    }
    else
    {
        auto okcount = std::count_if(dumpresults.begin(), dumpresults.end(), [](const PEDumper::DumpResult& d)
            {
                return d.Ok;
            });
        std::printf("[+] PEDumper: %zu / %zu modules dumped to %ls\n", static_cast<size_t>(okcount), dumpresults.size(), art.DumpDir.wstring().c_str());
        for (const auto& r : dumpresults)
        {
            if (r.Ok)
            {
                std::printf("    [+] %-32ls  %u data / %u code-holes  %8u B\n", r.Module.BaseName.c_str(), r.SectionsDumped, r.SectionsSkipped, r.HeaderBytes + r.DataBytes);
            }
            else
            {
                std::printf("    [!] %-32ls  %s\n", r.Module.BaseName.c_str(), r.Error.c_str());
            }
        }
    }
    if (dumpavailable && !dumpresults.empty())
    {
        try
        {
            PtTextRebuilder rebuilder(*Session, analyzer, dumpresults);
            auto reports = rebuilder.Rebuild(art.Manifest);
            PtTextRebuilder::PrintReport(reports);
            std::printf("[+] rebuilt images written; manifest -> %ls\n", art.Manifest.wstring().c_str());
            std::puts("    load each listed module in IDA at its manifest base (one IDB) for a fully resolved, only-what-executed image.");
        }
        catch (const std::exception& ex)
        {
            std::fprintf(stderr, "[!] PtTextRebuilder failed: %s\n", ex.what());
        }
    }
    else
    {
        std::fprintf(stderr, "[!] rebuild SKIPPED -- no successful dumps this run (dump error: %s).\n[!] No .rebuilt images or manifest were produced. Do NOT load any leftover\n[!] .rebuilt files -- they would be from a previous run.\n", dumperror.empty() ? "none reported" : dumperror.c_str());
    }
}