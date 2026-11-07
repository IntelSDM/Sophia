#pragma once
#include "WinPE/PEDumper.h"
#include "../HyperDBG/HyperDbgSession.h"
#include "../HyperDBG/PtAnalysis.h"
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

struct ks_struct;
typedef struct ks_struct ks_engine;

class PtTextRebuilder
{
public:
    PtTextRebuilder(HyperDbgSession& session, const PtAnalysis& analysis, const std::vector<PEDumper::DumpResult>& dumps);
    ~PtTextRebuilder();

    PtTextRebuilder(const PtTextRebuilder&) = delete;
    PtTextRebuilder& operator=(const PtTextRebuilder&) = delete;

    struct ModuleReport
    {
        std::wstring BaseName;
        std::filesystem::path OutPath;
        uint64_t Base = 0;
        uint32_t Instructions = 0;
        uint32_t Encoded = 0;
        uint32_t Failed = 0;
        uint32_t ImportsDirect = 0;
        uint32_t ImportsPatched = 0;
        uint32_t ImportsUnresolved = 0;
        uint32_t RipRewrites = 0;
        uint32_t Overlaps = 0;
        uint32_t NopPads = 0;
        bool Ok = false;
        std::string Error;
    };

    std::vector<ModuleReport> Rebuild(const std::filesystem::path& manifestpath, const std::wstring& outputsuffix = L".rebuilt");

    static void PrintReport(const std::vector<ModuleReport>& reports);

private:
    bool TryAssemble(const std::string& text, uint64_t va, std::vector<uint8_t>& out);
    bool ResolveSlot(uint32_t pid, uint64_t slot, const std::vector<uint8_t>& buf, uint64_t base, uint64_t& target);
    bool EncodeOne(const PtInsn& insn, uint32_t pid, std::vector<uint8_t>& buf, uint64_t base, uint64_t nextrva, ModuleReport& rep, std::vector<uint8_t>& out);
    ModuleReport RebuildModule(const PEDumper::DumpResult& dump, const std::vector<PtInsn>& insns, const std::wstring& outputsuffix);

    HyperDbgSession& Session;
    const PtAnalysis& Analysis;
    const std::vector<PEDumper::DumpResult>& Dumps;
    ks_engine* Ks;
};