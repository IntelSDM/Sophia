#pragma once
#include "../HyperDBG/HyperDbgSession.h"
#include "WinPE/PEDumper.h"
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>

class DumpTool
{
public:
    struct Config
    {
        std::filesystem::path OutputRoot = LR"(C:\Users\dev\Desktop)";
        std::filesystem::path HyperDbgPath;
        uint64_t TraceBufferSize = 0x2000000;
        std::chrono::milliseconds DumpDelay = std::chrono::seconds(5);
    };

    DumpTool();
    explicit DumpTool(const Config& cfg);

    void RunInteractive();

    void TraceAndDumpUser(const std::string& exepath);
    void DumpUser(const std::string& exepath, bool completeimage = true);
    void DumpDriver(const std::string& drivername, bool completeimage = true);

private:
    void RunDumpFlow();
    void RunAutoDebugFlow();
    void RunDeobfuscateFlow();

    void EnsureSession();
    bool EnsurePrimed();

    struct Artifacts
    {
        std::filesystem::path DumpDir;
        std::filesystem::path AnalysisJson;
        std::filesystem::path DumpCsv;
        std::filesystem::path Manifest;
    };
    Artifacts ArtifactsFor(const std::string& stem) const;

    Config Cfg;
    std::unique_ptr<HyperDbgSession> Session;
    std::unique_ptr<PEDumper> Dumper;
    bool Primed = false;
    bool PrimeOk = false;
};