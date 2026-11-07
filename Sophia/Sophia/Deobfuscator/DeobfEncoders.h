#pragma once

#include "DeobfContext.h"

#include <Zydis/Zydis.h>

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

enum class ArithEncFamily : uint8_t
{
    Alu81,
    Shift
};

enum class CmpEncFamily : uint8_t
{
    None,
    AluCmp,
    AluTest,
    BitTest
};

struct PdataRange
{
    uint32_t BeginRva;
    uint32_t EndRva;
};

struct HeaderSlackInfo
{
    bool     HaveSlack = false;
    uint32_t PredictedRva = 0;
    uint32_t SectionAlignment = 0;
};

struct EatenBytes
{
    bool                 Ok = false;
    uint32_t             Consumed = 0;
    std::vector<uint8_t> Copy;
};

class TrampolineBuilder
{
public:
    struct SiteRec
    {
        uint64_t SiteFileOff;
        uint64_t SiteRva;
        uint32_t Consumed;
        uint32_t SlotStartRva;
    };

    TrampolineBuilder(std::vector<uint8_t>& buf, ZydisDecoder& decoder, uint32_t predictedsectionrva);

    uint32_t PredictedSectionRva() const { return Predicted; }
    const std::vector<uint8_t>& Blob() const { return BlobData; }
    const std::vector<SiteRec>& Sites() const { return TrampSites; }
    uint64_t BytesSaved() const { return SavedBytes; }

    using PayloadEncoder = std::function<uint32_t(uint8_t*, uint32_t, uint64_t)>;

    bool TryTrampoline(uint64_t sitefileoff, uint32_t sitelen, uint64_t siterva, uint32_t payloadlenhint, PayloadEncoder enc);

    void EmitOutbounds() const;

private:
    std::vector<uint8_t>& Buf;
    ZydisDecoder& Decoder;
    uint32_t                    Predicted;
    std::vector<uint8_t>        BlobData;
    std::vector<SiteRec>        TrampSites;
    uint64_t                    SavedBytes = 0;
};

class DeobfEncoders
{
public:
    static constexpr uint64_t FlagCf = 1ULL << 0;
    static constexpr uint64_t FlagPf = 1ULL << 2;
    static constexpr uint64_t FlagZf = 1ULL << 6;
    static constexpr uint64_t FlagSf = 1ULL << 7;
    static constexpr uint64_t FlagOf = 1ULL << 11;

    static std::optional<bool> WillJccTake(const char* mn, uint64_t rflags);
    static bool IsPlainJcc(const InsnSite& s);

    static void NopFill(std::vector<uint8_t>& buf, uint64_t off, uint32_t len);

    static bool EmitDirectJmp(std::vector<uint8_t>& buf, uint64_t off, uint32_t slot, uint64_t siterva, uint64_t targetrva);
    static bool EmitDirectCall(std::vector<uint8_t>& buf, uint64_t off, uint32_t slot, uint64_t siterva, uint64_t targetrva);
    static bool EmitMovRegImm(std::vector<uint8_t>& buf, uint64_t off, uint32_t slot, uint8_t reg, uint64_t imm);
    static bool EmitLeaRegRipRel(std::vector<uint8_t>& buf, uint64_t off, uint32_t slot, uint8_t reg, uint64_t targetrva, uint64_t siterva);

    static bool ArithEncoderInfo(const char* mn, ArithEncFamily& family, uint8_t& slashdigit, uint8_t& tworegopcode);
    static bool EmitArithRegImm(std::vector<uint8_t>& buf, uint64_t off, uint32_t slot, uint8_t reg, ArithEncFamily family, uint8_t slashdigit, uint8_t tworegopcode, uint64_t imm);

    static bool CmpEncoderInfo(const char* mn, CmpEncFamily& family, uint8_t& slashdigit, uint8_t& tworegopcode);
    static bool EmitCmpRegImm(std::vector<uint8_t>& buf, uint64_t off, uint32_t slot, uint8_t reg, CmpEncFamily family, uint8_t slashdigit, uint8_t tworegopcode, uint64_t imm);

    static uint32_t EncMovRegImm(uint8_t* out, uint32_t cap, uint8_t reg, uint64_t imm);
    static uint32_t EncArithRegImm(uint8_t* out, uint32_t cap, uint8_t reg, ArithEncFamily family, uint8_t slashdigit, uint8_t tworegopcode, uint64_t imm);
    static uint32_t EncLeaRipRel(uint8_t* out, uint32_t cap, uint8_t reg, uint64_t targetrva, uint64_t encodeatrva);
    static uint32_t EncIatCall(uint8_t* out, uint32_t cap, uint64_t iatslotrva, uint64_t encodeatrva);
    static uint32_t EncCmpRegImm(uint8_t* out, uint32_t cap, uint8_t reg, CmpEncFamily family, uint8_t slashdigit, uint8_t tworegopcode, uint64_t imm);

    static uint8_t GprIdByName(const char* name);
    static uint64_t GprById(const SophiaGprSet& gpr, uint8_t id);
    static uint64_t GprByName(const SophiaGprSet& gpr, const char* name);

    static EatenBytes EatForward(const std::vector<uint8_t>& buf, ZydisDecoder& decoder, uint64_t sitefileoff, uint32_t sitelen, uint64_t siterva, uint32_t sloteatenstartrva);
    static void FormatEaExpr(char* out, size_t outsize, uint8_t baseid, uint8_t indexid, uint8_t scale, int64_t disp);

    static bool BuildSectionMap(const std::vector<uint8_t>& buf, DeobfSectionMap& out);
    static bool IsHardStop(const ZydisDecodedInstruction& insn);
    static bool IsPatchableDataSection(const DeobfSection& s);

    static HeaderSlackInfo CheckHeaderSlack(const std::vector<uint8_t>& buf);
    static std::vector<PdataRange> ParsePdataRanges(const std::vector<uint8_t>& buf, const DeobfSectionMap& sm);

    static uint16_t StringElemWidth(const char* mn);
    static uint64_t ReconstructVecAddr(uint64_t siterva, const ZydisDecodedInstruction& insn, const ZydisDecodedOperand* ops, const SophiaGprSet& gpr, bool& outisriprel);
    static bool MergePrefixConsistent(std::vector<uint8_t>& canonical, const uint8_t* obs, size_t obslen);
    static std::string DecodeBufferBytes(const uint8_t* data, size_t n);
    static bool IsRedirectableString(const std::vector<uint8_t>& content);
};