#pragma once
#include "AutoDebugTool.h"
#include "../Database/AutoDebugStore.h"

#include <cstdint>
#include <filesystem>
#include <string>
#include <unordered_map>
#include <vector>

class AutoDebugHitParser
{
public:
    enum class HitFlavor
    {
        TracedBinary,
        NtdllSyscalls
    };

    struct Stats
    {
        uint64_t HitsFileBytes = 0;
        uint64_t LinesRead = 0;
        uint64_t HitsSeen = 0;
        uint64_t HitsIngested = 0;
        uint64_t HitsDedup = 0;
        uint64_t HitsError = 0;
        uint64_t UnknownRva = 0;
        uint64_t ParseErrors = 0;

        uint64_t TagHit = 0;
        uint64_t TagMem = 0;
        uint64_t TagStr = 0;
        uint64_t TagVec = 0;
        uint64_t TagMov = 0;
        uint64_t TagAri = 0;
        uint64_t TagInd = 0;
        uint64_t TagLea = 0;
        uint64_t TagArg = 0;
        uint64_t TagArgh = 0;
        uint64_t TagRet = 0;
        uint64_t TagReth = 0;

        uint64_t Branches = 0;
        uint64_t Calls = 0;
        uint64_t Compares = 0;
        uint64_t Movs = 0;
        uint64_t Ariths = 0;
        uint64_t Strings = 0;
        uint64_t Vecs = 0;
        uint64_t IndBranches = 0;
        uint64_t IndCalls = 0;
        uint64_t Leas = 0;
        uint64_t CallArgs = 0;
        uint64_t CallRets = 0;
        uint64_t SyscallsDirect = 0;
        uint64_t SyscallDirectArgs = 0;
        uint64_t SyscallDirectRets = 0;
        uint64_t SyscallsIndirect = 0;
        uint64_t SyscallIndirectArgs = 0;
        uint64_t SyscallIndirectRets = 0;

        uint64_t UnknownRvaSample[5] = {};
        uint32_t UnknownRvaSampleCount = 0;

        char FirstLine[240] = {};
    };

    AutoDebugHitParser(AutoDebugStore& store, const std::vector<InsnSite>& sites, HitFlavor flavor = HitFlavor::TracedBinary);

    Stats ParseFile(const std::filesystem::path& hitsfile);

private:
    struct HitAccum
    {
        bool HaveHit = false;
        uint64_t Rva = 0;
        SophiaGprSet Gpr = {};

        bool HaveMem = false;
        uint64_t MemLo = 0;
        uint64_t MemHi = 0;

        bool HaveMov = false;
        uint64_t MovVal = 0;

        bool HaveAri = false;
        uint64_t AriRval = 0;
        uint64_t AriRval2 = 0;
        uint64_t AriMval = 0;

        struct StringExtra
        {
            bool Have = false;
            uint64_t Addr = 0;
            uint64_t LenRcx = 0;
            uint64_t Window[8] = {};
        };
        StringExtra StrRsi;
        StringExtra StrRdi;

        bool HaveVec = false;
        uint16_t VecQwords = 0;
        uint64_t VecWindow[4] = {};

        bool HaveInd = false;
        uint64_t IndTarget = 0;

        bool HaveLea = false;
        uint64_t LeaEa = 0;

        struct ArgExtra
        {
            bool Have = false;
            uint64_t Val = 0;
            uint64_t Head[4] = {};
        };
        ArgExtra Args[8];
    };

    void Flush(HitAccum& acc, Stats& stats);

    void ParseHitLine(const std::string& line, HitAccum& acc, Stats& stats);
    void ParseMemLine(const std::string& line, HitAccum& acc, Stats& stats);
    void ParseStrLine(const std::string& line, HitAccum& acc, Stats& stats);
    void ParseVecLine(const std::string& line, HitAccum& acc, Stats& stats);
    void ParseMovLine(const std::string& line, HitAccum& acc, Stats& stats);
    void ParseAriLine(const std::string& line, HitAccum& acc, Stats& stats);
    void ParseIndLine(const std::string& line, HitAccum& acc, Stats& stats);
    void ParseLeaLine(const std::string& line, HitAccum& acc, Stats& stats);
    void ParseArgLine(const std::string& line, HitAccum& acc, Stats& stats);
    void ParseArgHeadLine(const std::string& line, HitAccum& acc, Stats& stats);

    void ParseRetLine(const std::string& line, Stats& stats);
    void ParseRetHeadLine(const std::string& line, Stats& stats);

    static size_t FindKV(const std::string& line, const char* key);
    static bool GetHexKV(const std::string& line, const char* key, uint64_t& out);
    static bool GetDecKV(const std::string& line, const char* key, uint64_t& out);
    static bool GetStrKV(const std::string& line, const char* key, std::string& out);

    AutoDebugStore& Store;
    std::unordered_map<uint64_t, SiteKind> KindByRva;
    HitFlavor Flavor;
};