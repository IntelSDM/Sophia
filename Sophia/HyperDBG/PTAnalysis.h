#pragma once
#include <cstdint>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

struct PtModuleStats
{
    std::string Name;
    uint64_t UniqueAddresses = 0;
    uint64_t TotalHits = 0;
    uint64_t MinRva = UINT64_MAX;
    uint64_t MaxRva = 0;
    uint64_t UniquePages = 0;
};

struct PtTraceStats
{
    uint64_t ParsedLines = 0;
    uint64_t SkippedLines = 0;
    uint64_t TotalInstructions = 0;
    uint64_t UniqueAddresses = 0;
    uint64_t UniquePages = 0;

    std::unordered_map<std::string, PtModuleStats> Modules;
};

struct PtInsn
{
    uint64_t Va;
    uint64_t Rva;
    std::string Mnemonic;
};

class PtAnalysis
{
public:
    PtAnalysis();

    void Ingest(const char* chunk, size_t len);
    void Ingest(const char* nullterminatedchunk);

    PtTraceStats Snapshot() const;

    void Reset();

    static PtTraceStats AnalyzeString(const std::string& dump);

    static void PrintSummary(const PtTraceStats& stats);

    bool WriteJson(const std::string& path, bool includeaddresses = true) const;

    bool WriteDump(const std::string& path) const;

    std::vector<uint64_t> GetUniqueAddresses(const std::string& modulename) const;
    std::vector<uint64_t> GetUniquePages(const std::string& modulename) const;

    std::vector<PtInsn> GetAllInstructions() const;

private:
    struct ModuleScratch
    {
        std::unordered_set<uint64_t> AddrSet;
        std::unordered_set<uint64_t> PageSet;
        PtModuleStats Stats;

        struct InsnRecord
        {
            uint64_t Rva;
            std::string Mnemonic;
        };
        std::unordered_map<uint64_t, InsnRecord> Insns;
    };

    void IngestLine(const char* line, size_t len);

    std::unordered_map<std::string, ModuleScratch> Scratch;
    std::string PartialLine;

    uint64_t ParsedLines = 0;
    uint64_t SkippedLines = 0;
};