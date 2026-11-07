#pragma once
#include "../AutoDebugger/AutoDebugTool.h"

#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <functional>
#include <string>
#include <unordered_set>
#include <vector>

#pragma pack(push, 1)

struct SophiaGprSet
{
    uint64_t rax, rbx, rcx, rdx;
    uint64_t rsi, rdi, rbp, rsp;
    uint64_t r8, r9, r10, r11;
    uint64_t r12, r13, r14, r15;
    uint64_t rflags;
};
static_assert(sizeof(SophiaGprSet) == 136, "SophiaGprSet must be 17 * u64");

struct BranchHit
{
    uint64_t Rva;
    SophiaGprSet Gpr;
};
static_assert(sizeof(BranchHit) == 144, "BranchHit layout drift");

using CallHit = BranchHit;

struct CompareHit
{
    uint64_t Rva;
    SophiaGprSet Gpr;
    uint64_t MemLo;
    uint64_t MemHi;
};
static_assert(sizeof(CompareHit) == 160, "CompareHit layout drift");

struct MovHit
{
    uint64_t Rva;
    SophiaGprSet Gpr;
    uint64_t MemValue;
};
static_assert(sizeof(MovHit) == 152, "MovHit layout drift");

struct ArithHit
{
    uint64_t Rva;
    SophiaGprSet Gpr;
    uint64_t Rval;
    uint64_t Rval2;
    uint64_t Mval;
};
static_assert(sizeof(ArithHit) == 168, "ArithHit layout drift");

struct StringHit
{
    uint64_t Rva;
    SophiaGprSet Gpr;
    uint8_t Which;
    uint8_t Pad[7];
    uint64_t Addr;
    uint64_t LenRcx;
    uint64_t Window[8];
};
static_assert(sizeof(StringHit) == 232, "StringHit layout drift");

struct VecHit
{
    uint64_t Rva;
    SophiaGprSet Gpr;
    uint16_t NQwords;
    uint8_t Pad[6];
    uint64_t Window[4];
};
static_assert(sizeof(VecHit) == 184, "VecHit layout drift");

struct IndBranchHit
{
    uint64_t Rva;
    SophiaGprSet Gpr;
    uint64_t Target;
};
static_assert(sizeof(IndBranchHit) == 152, "IndBranchHit layout drift");

using IndCallHit = IndBranchHit;

struct LeaHit
{
    uint64_t Rva;
    SophiaGprSet Gpr;
    uint64_t Ea;
};
static_assert(sizeof(LeaHit) == 152, "LeaHit layout drift");

struct IatHit
{
    uint64_t Rva;
    uint32_t ExportRva;
    uint32_t Pad;
    char ModuleName[64];
    char ExportName[128];
};
static_assert(sizeof(IatHit) == 208, "IatHit layout drift");

struct RopHit
{
    uint64_t Rva;
    uint32_t ModuleRva;
    uint32_t Pad;
    char ModuleName[64];
};
static_assert(sizeof(RopHit) == 80, "RopHit layout drift");

struct CallArgHit
{
    uint64_t Rva;
    uint8_t ArgIdx;
    uint8_t Pad0;
    uint16_t Pad1;
    uint32_t Pad2;
    uint64_t Val;
    uint64_t Head[4];
};
static_assert(sizeof(CallArgHit) == 56, "CallArgHit layout drift");

struct CallRetHit
{
    uint64_t Rva;
    uint64_t Rax;
    uint64_t Head[4];
};
static_assert(sizeof(CallRetHit) == 48, "CallRetHit layout drift");

using SyscallDirectHit = BranchHit;
using SyscallIndirectHit = BranchHit;
using SyscallDirectArgHit = CallArgHit;
using SyscallDirectRetHit = CallRetHit;
using SyscallIndirectArgHit = CallArgHit;
using SyscallIndirectRetHit = CallRetHit;

struct SophiaFileHeader
{
    char Magic[4];
    uint16_t Version;
    uint16_t Kind;
    uint32_t RecSize;
    uint32_t Reserved;
};
static_assert(sizeof(SophiaFileHeader) == 16, "SophiaFileHeader layout drift");

#pragma pack(pop)

enum class ObsKind : uint16_t
{
    Branch = 1,
    Call = 2,
    Compare = 3,
    Mov = 4,
    Arith = 5,
    String = 6,
    Vec = 7,
    IndBranch = 8,
    IndCall = 9,
    Lea = 10,
    Iat = 11,
    Rop = 12,
    CallArg = 13,
    CallRet = 14,
    SyscallDirect = 15,
    SyscallDirectArg = 16,
    SyscallDirectRet = 17,
    SyscallIndirect = 18,
    SyscallIndirectArg = 19,
    SyscallIndirectRet = 20,
};

struct ObsStats
{
    uint64_t TotalRecords = 0;
    uint64_t UniqueRvas = 0;
    uint32_t Branches = 0;
    uint32_t Calls = 0;
    uint32_t Compares = 0;
    uint32_t Movs = 0;
    uint32_t Ariths = 0;
    uint32_t Strings = 0;
    uint32_t Vecs = 0;
    uint32_t IndBranches = 0;
    uint32_t IndCalls = 0;
    uint32_t Leas = 0;
    uint32_t Iats = 0;
    uint32_t Rops = 0;
    uint32_t CallArgs = 0;
    uint32_t CallRets = 0;
    uint32_t SyscallsDirect = 0;
    uint32_t SyscallDirectArgs = 0;
    uint32_t SyscallDirectRets = 0;
    uint32_t SyscallsIndirect = 0;
    uint32_t SyscallIndirectArgs = 0;
    uint32_t SyscallIndirectRets = 0;
};

enum class IngestResult : uint8_t
{
    New = 0,
    Duplicate = 1,
    Error = 2,
};

class ManifestJson
{
public:
    static bool FindValue(const std::string& body, const char* key, size_t& start, size_t& end)
    {
        std::string pat = "\"";
        pat += key;
        pat += "\":";
        size_t p = body.find(pat);
        if (p == std::string::npos) return false;
        p += pat.size();
        while (p < body.size() && (body[p] == ' ' || body[p] == '\t')) ++p;
        if (p >= body.size()) return false;

        if (body[p] == '"')
        {
            ++p;
            size_t q = p;
            while (q < body.size() && body[q] != '"')
            {
                if (body[q] == '\\' && q + 1 < body.size()) q += 2;
                else ++q;
            }
            if (q >= body.size()) return false;
            start = p;
            end = q;
        }
        else
        {
            size_t q = p;
            while (q < body.size() && body[q] != ',' && body[q] != '}' && body[q] != '\n')
                ++q;
            start = p;
            end = q;
            while (end > start && (body[end - 1] == ' ' || body[end - 1] == '\r'))
                --end;
        }
        return true;
    }

    static std::string GetStr(const std::string& body, const char* key)
    {
        size_t s, e;
        if (!FindValue(body, key, s, e)) return {};
        std::string raw = body.substr(s, e - s);
        std::string out;
        out.reserve(raw.size());
        for (size_t i = 0; i < raw.size(); ++i)
        {
            if (raw[i] == '\\' && i + 1 < raw.size())
            {
                char n = raw[i + 1];
                switch (n)
                {
                case '"':  out.push_back('"');  ++i; break;
                case '\\': out.push_back('\\'); ++i; break;
                case 'n':  out.push_back('\n'); ++i; break;
                case 'r':  out.push_back('\r'); ++i; break;
                case 't':  out.push_back('\t'); ++i; break;
                default:   out.push_back(raw[i]);
                }
            }
            else out.push_back(raw[i]);
        }
        return out;
    }

    static long long GetInt(const std::string& body, const char* key)
    {
        size_t s, e;
        if (!FindValue(body, key, s, e)) return 0;
        return std::strtoll(body.substr(s, e - s).c_str(), nullptr, 10);
    }

    static void EscapeAppend(std::string& out, const std::string& s)
    {
        out.push_back('"');
        for (char c : s)
        {
            switch (c)
            {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (static_cast<unsigned char>(c) < 0x20)
                {
                    char b[8];
                    std::snprintf(b, sizeof(b), "\\u%04x", static_cast<unsigned>(c));
                    out += b;
                }
                else
                {
                    out.push_back(c);
                }
            }
        }
        out.push_back('"');
    }
};

class AutoDebugStore
{
public:
    struct OpenResult
    {
        bool IsNew = false;
        bool WasWiped = false;
        uint32_t PriorRunCount = 0;
        std::filesystem::path ProjectDir;
        std::string Sha256Hex;
    };

    AutoDebugStore() = default;
    ~AutoDebugStore();
    AutoDebugStore(const AutoDebugStore&) = delete;
    AutoDebugStore& operator=(const AutoDebugStore&) = delete;

    bool Open(const std::string& filepath, OpenResult& result);
    bool OpenReadOnly(const std::string& filepath);
    bool LoadObservations();
    bool ForEachRecord(ObsKind k, const std::function<void(const void*, size_t)>& visit);

    IngestResult Ingest(ObsKind kind, const void* rec, size_t recsize);
    IngestResult IngestBranch(const BranchHit& r);
    IngestResult IngestCall(const CallHit& r);
    IngestResult IngestCompare(const CompareHit& r);
    IngestResult IngestMov(const MovHit& r);
    IngestResult IngestArith(const ArithHit& r);
    IngestResult IngestString(const StringHit& r);
    IngestResult IngestVec(const VecHit& r);
    IngestResult IngestIndBranch(const IndBranchHit& r);
    IngestResult IngestIndCall(const IndCallHit& r);
    IngestResult IngestLea(const LeaHit& r);
    IngestResult IngestIat(const IatHit& r);
    IngestResult IngestRop(const RopHit& r);
    IngestResult IngestCallArg(const CallArgHit& r);
    IngestResult IngestCallRet(const CallRetHit& r);
    IngestResult IngestSyscallDirect(const SyscallDirectHit& r);
    IngestResult IngestSyscallDirectArg(const SyscallDirectArgHit& r);
    IngestResult IngestSyscallDirectRet(const SyscallDirectRetHit& r);
    IngestResult IngestSyscallIndirect(const SyscallIndirectHit& r);
    IngestResult IngestSyscallIndirectArg(const SyscallIndirectArgHit& r);
    IngestResult IngestSyscallIndirectRet(const SyscallIndirectRetHit& r);

    void FlushStreams();
    bool FinalizeRun();

    const std::filesystem::path& Dir() const { return ProjectDir; }
    uint32_t PriorRuns() const { return PriorRunCount; }
    bool IsReused() const { return !IsNew; }
    const std::string& Sha256() const { return SourceSha256Hex; }
    const ObsStats& Stats() const { return Statistics; }
    const std::unordered_set<uint64_t>& ExploredRvas() const { return Explored; }

    static bool HashFileSha256(const std::string& path, std::string& hexout, uint64_t& sizeout);

    void SetTracedBase(uint64_t tracedbase);

private:
    static std::filesystem::path SophiaProjRoot();
    static std::string NowIsoUtc();
    static uint64_t Fnv1a64(const void* data, size_t n);
    static const wchar_t* FilenameFor(ObsKind k);
    static uint32_t RecSizeFor(ObsKind k);

    bool ReadManifest(std::string& shahex, uint64_t& size, uint32_t& runcount, std::string& firstseen);
    bool WriteManifest();
    bool EnsureStreamOpen(ObsKind k);

    struct KindState
    {
        std::ofstream Out;
        std::unordered_set<uint64_t> Keys;
        uint32_t Count = 0;
    };
    KindState Kinds[21];

    ObsStats Statistics;
    std::unordered_set<uint64_t> Explored;

    std::filesystem::path ProjectDir;
    std::string SourcePath;
    std::string SourceSha256Hex;
    uint64_t SourceSize = 0;
    std::string FirstSeen;
    uint32_t PriorRunCount = 0;
    uint64_t TracedBase = 0;
    bool IsNew = true;
    bool Opened = false;
};