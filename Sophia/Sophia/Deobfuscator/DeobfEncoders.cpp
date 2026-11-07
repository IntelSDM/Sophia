#include "../../Pch.h"
#include "DeobfEncoders.h"

#include <windows.h>
#include <Zydis/Zydis.h>

#include <cstdio>
#include <cstring>

const DeobfSection* DeobfSectionMap::Find(uint64_t rva) const
{
    for (const DeobfSection& s : Sections)
    {
        if (rva >= s.Rva && rva < s.Rva + s.VirtualSize)
        {
            return &s;
        }
    }
    return nullptr;
}

uint64_t DeobfSectionMap::RvaToOffset(uint64_t rva) const
{
    const DeobfSection* s = Find(rva);
    if (!s)
    {
        return UINT64_MAX;
    }
    const uint64_t delta = rva - s->Rva;
    if (delta >= s->RawSize)
    {
        return UINT64_MAX;
    }
    return s->RawOffset + delta;
}

bool DeobfSectionMap::IsExecutable(const DeobfSection& s)
{
    return (s.Characteristics & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE)) != 0;
}

std::optional<bool> DeobfEncoders::WillJccTake(const char* mn, uint64_t rflags)
{
    if (!mn || !mn[0])
    {
        return std::nullopt;
    }

    const bool cf = (rflags & FlagCf) != 0;
    const bool pf = (rflags & FlagPf) != 0;
    const bool zf = (rflags & FlagZf) != 0;
    const bool sf = (rflags & FlagSf) != 0;
    const bool of = (rflags & FlagOf) != 0;

    if (std::strcmp(mn, "jz") == 0) return zf;
    if (std::strcmp(mn, "jnz") == 0) return !zf;
    if (std::strcmp(mn, "js") == 0) return sf;
    if (std::strcmp(mn, "jns") == 0) return !sf;
    if (std::strcmp(mn, "jb") == 0) return cf;
    if (std::strcmp(mn, "jnb") == 0) return !cf;
    if (std::strcmp(mn, "jo") == 0) return of;
    if (std::strcmp(mn, "jno") == 0) return !of;
    if (std::strcmp(mn, "jp") == 0) return pf;
    if (std::strcmp(mn, "jnp") == 0) return !pf;
    if (std::strcmp(mn, "jbe") == 0) return cf || zf;
    if (std::strcmp(mn, "jnbe") == 0) return !cf && !zf;
    if (std::strcmp(mn, "jl") == 0) return sf != of;
    if (std::strcmp(mn, "jnl") == 0) return sf == of;
    if (std::strcmp(mn, "jle") == 0) return zf || (sf != of);
    if (std::strcmp(mn, "jnle") == 0) return !zf && (sf == of);

    return std::nullopt;
}

bool DeobfEncoders::IsPlainJcc(const InsnSite& s)
{
    return s.Kind == SiteKind::Branch && WillJccTake(s.Mnemonic, 0).has_value();
}

void DeobfEncoders::NopFill(std::vector<uint8_t>& buf, uint64_t off, uint32_t len)
{
    for (uint32_t i = 0; i < len; ++i)
    {
        buf[off + i] = 0x90;
    }
}

bool DeobfEncoders::EmitDirectJmp(std::vector<uint8_t>& buf, uint64_t off, uint32_t slot, uint64_t siterva, uint64_t targetrva)
{
    if (slot >= 5)
    {
        const int64_t d32 = static_cast<int64_t>(targetrva) - static_cast<int64_t>(siterva + 5);
        if (d32 >= INT32_MIN && d32 <= INT32_MAX)
        {
            buf[off] = 0xE9;
            int32_t d = static_cast<int32_t>(d32);
            std::memcpy(&buf[off + 1], &d, 4);
            for (uint32_t i = 5; i < slot; ++i)
            {
                buf[off + i] = 0x90;
            }
            return true;
        }
    }
    if (slot >= 2)
    {
        const int64_t d8 = static_cast<int64_t>(targetrva) - static_cast<int64_t>(siterva + 2);
        if (d8 >= INT8_MIN && d8 <= INT8_MAX)
        {
            buf[off] = 0xEB;
            buf[off + 1] = static_cast<uint8_t>(static_cast<int8_t>(d8));
            for (uint32_t i = 2; i < slot; ++i)
            {
                buf[off + i] = 0x90;
            }
            return true;
        }
    }
    return false;
}

bool DeobfEncoders::EmitDirectCall(std::vector<uint8_t>& buf, uint64_t off, uint32_t slot, uint64_t siterva, uint64_t targetrva)
{
    if (slot < 5)
    {
        return false;
    }
    const int64_t d32 = static_cast<int64_t>(targetrva) - static_cast<int64_t>(siterva + 5);
    if (d32 < INT32_MIN || d32 > INT32_MAX)
    {
        return false;
    }
    buf[off] = 0xE8;
    int32_t d = static_cast<int32_t>(d32);
    std::memcpy(&buf[off + 1], &d, 4);
    for (uint32_t i = 5; i < slot; ++i)
    {
        buf[off + i] = 0x90;
    }
    return true;
}

bool DeobfEncoders::EmitMovRegImm(std::vector<uint8_t>& buf, uint64_t off, uint32_t slot, uint8_t reg, uint64_t imm)
{
    const bool fitsu32 = (imm <= 0xFFFFFFFFULL);
    const bool needsrexb = (reg & 8) != 0;
    const uint32_t enclen = fitsu32 ? (needsrexb ? 6u : 5u) : 10u;

    if (off + enclen > buf.size())
    {
        return false;
    }

    uint64_t p = off;
    if (fitsu32)
    {
        if (needsrexb)
        {
            buf[p++] = 0x41;
        }
        buf[p++] = 0xB8 | (reg & 7);
        const uint32_t imm32 = static_cast<uint32_t>(imm);
        std::memcpy(&buf[p], &imm32, 4);
        p += 4;
    }
    else
    {
        uint8_t rex = 0x48;
        if (needsrexb)
        {
            rex |= 0x01;
        }
        buf[p++] = rex;
        buf[p++] = 0xB8 | (reg & 7);
        std::memcpy(&buf[p], &imm, 8);
        p += 8;
    }
    for (uint32_t i = enclen; i < slot; ++i)
    {
        buf[off + i] = 0x90;
    }
    return true;
}

bool DeobfEncoders::EmitLeaRegRipRel(std::vector<uint8_t>& buf, uint64_t off, uint32_t slot, uint8_t reg, uint64_t targetrva, uint64_t siterva)
{
    if (off + 7 > buf.size())
    {
        return false;
    }
    const int64_t d = static_cast<int64_t>(targetrva) - static_cast<int64_t>(siterva) - 7;
    if (d < INT32_MIN || d > INT32_MAX)
    {
        return false;
    }
    uint8_t rex = 0x48;
    if (reg & 8)
    {
        rex |= 0x04;
    }
    buf[off + 0] = rex;
    buf[off + 1] = 0x8D;
    buf[off + 2] = static_cast<uint8_t>(((reg & 7) << 3) | 0x05);
    const int32_t d32 = static_cast<int32_t>(d);
    std::memcpy(&buf[off + 3], &d32, 4);
    for (uint32_t i = 7; i < slot; ++i)
    {
        buf[off + i] = 0x90;
    }
    return true;
}

bool DeobfEncoders::ArithEncoderInfo(const char* mn, ArithEncFamily& family, uint8_t& slashdigit, uint8_t& tworegopcode)
{
    if (!mn || !mn[0]) return false;
    if (std::strcmp(mn, "add") == 0) { family = ArithEncFamily::Alu81; slashdigit = 0; tworegopcode = 0x01; return true; }
    if (std::strcmp(mn, "or") == 0) { family = ArithEncFamily::Alu81; slashdigit = 1; tworegopcode = 0x09; return true; }
    if (std::strcmp(mn, "adc") == 0) { family = ArithEncFamily::Alu81; slashdigit = 2; tworegopcode = 0x11; return true; }
    if (std::strcmp(mn, "sbb") == 0) { family = ArithEncFamily::Alu81; slashdigit = 3; tworegopcode = 0x19; return true; }
    if (std::strcmp(mn, "and") == 0) { family = ArithEncFamily::Alu81; slashdigit = 4; tworegopcode = 0x21; return true; }
    if (std::strcmp(mn, "sub") == 0) { family = ArithEncFamily::Alu81; slashdigit = 5; tworegopcode = 0x29; return true; }
    if (std::strcmp(mn, "xor") == 0) { family = ArithEncFamily::Alu81; slashdigit = 6; tworegopcode = 0x31; return true; }
    if (std::strcmp(mn, "rol") == 0) { family = ArithEncFamily::Shift; slashdigit = 0; tworegopcode = 0; return true; }
    if (std::strcmp(mn, "ror") == 0) { family = ArithEncFamily::Shift; slashdigit = 1; tworegopcode = 0; return true; }
    if (std::strcmp(mn, "rcl") == 0) { family = ArithEncFamily::Shift; slashdigit = 2; tworegopcode = 0; return true; }
    if (std::strcmp(mn, "rcr") == 0) { family = ArithEncFamily::Shift; slashdigit = 3; tworegopcode = 0; return true; }
    if (std::strcmp(mn, "shl") == 0) { family = ArithEncFamily::Shift; slashdigit = 4; tworegopcode = 0; return true; }
    if (std::strcmp(mn, "shr") == 0) { family = ArithEncFamily::Shift; slashdigit = 5; tworegopcode = 0; return true; }
    if (std::strcmp(mn, "sar") == 0) { family = ArithEncFamily::Shift; slashdigit = 7; tworegopcode = 0; return true; }
    return false;
}

bool DeobfEncoders::EmitArithRegImm(std::vector<uint8_t>& buf, uint64_t off, uint32_t slot, uint8_t reg, ArithEncFamily family, uint8_t slashdigit, uint8_t tworegopcode, uint64_t imm)
{
    uint8_t scratch[16];
    const uint32_t enclen = EncArithRegImm(scratch, sizeof(scratch), reg, family, slashdigit, tworegopcode, imm);
    if (enclen == 0 || off + enclen > buf.size())
    {
        return false;
    }
    std::memcpy(&buf[off], scratch, enclen);
    for (uint32_t i = enclen; i < slot; ++i)
    {
        buf[off + i] = 0x90;
    }
    return true;
}

bool DeobfEncoders::CmpEncoderInfo(const char* mn, CmpEncFamily& family, uint8_t& slashdigit, uint8_t& tworegopcode)
{
    if (!mn || !mn[0]) return false;
    if (std::strcmp(mn, "cmp") == 0) { family = CmpEncFamily::AluCmp; slashdigit = 7; tworegopcode = 0x39; return true; }
    if (std::strcmp(mn, "test") == 0) { family = CmpEncFamily::AluTest; slashdigit = 0; tworegopcode = 0x85; return true; }
    if (std::strcmp(mn, "bt") == 0) { family = CmpEncFamily::BitTest; slashdigit = 4; tworegopcode = 0; return true; }
    if (std::strcmp(mn, "bts") == 0) { family = CmpEncFamily::BitTest; slashdigit = 5; tworegopcode = 0; return true; }
    if (std::strcmp(mn, "btr") == 0) { family = CmpEncFamily::BitTest; slashdigit = 6; tworegopcode = 0; return true; }
    if (std::strcmp(mn, "btc") == 0) { family = CmpEncFamily::BitTest; slashdigit = 7; tworegopcode = 0; return true; }
    return false;
}

bool DeobfEncoders::EmitCmpRegImm(std::vector<uint8_t>& buf, uint64_t off, uint32_t slot, uint8_t reg, CmpEncFamily family, uint8_t slashdigit, uint8_t tworegopcode, uint64_t imm)
{
    uint8_t scratch[16];
    const uint32_t enclen = EncCmpRegImm(scratch, sizeof(scratch), reg, family, slashdigit, tworegopcode, imm);
    if (enclen == 0 || off + enclen > buf.size())
    {
        return false;
    }
    std::memcpy(&buf[off], scratch, enclen);
    for (uint32_t i = enclen; i < slot; ++i)
    {
        buf[off + i] = 0x90;
    }
    return true;
}

uint32_t DeobfEncoders::EncMovRegImm(uint8_t* out, uint32_t cap, uint8_t reg, uint64_t imm)
{
    const bool fitsu32 = (imm <= 0xFFFFFFFFULL);
    const bool needsrexb = (reg & 8) != 0;
    const uint32_t enclen = fitsu32 ? (needsrexb ? 6u : 5u) : 10u;
    if (enclen > cap)
    {
        return 0;
    }
    uint32_t p = 0;
    if (fitsu32)
    {
        if (needsrexb)
        {
            out[p++] = 0x41;
        }
        out[p++] = 0xB8 | (reg & 7);
        const uint32_t imm32 = static_cast<uint32_t>(imm);
        std::memcpy(out + p, &imm32, 4);
        p += 4;
    }
    else
    {
        uint8_t rex = 0x48;
        if (needsrexb)
        {
            rex |= 0x01;
        }
        out[p++] = rex;
        out[p++] = 0xB8 | (reg & 7);
        std::memcpy(out + p, &imm, 8);
        p += 8;
    }
    return p;
}

uint32_t DeobfEncoders::EncArithRegImm(uint8_t* out, uint32_t cap, uint8_t reg, ArithEncFamily family, uint8_t slashdigit, uint8_t tworegopcode, uint64_t imm)
{
    if (family == ArithEncFamily::Shift)
    {
        if (cap < 4)
        {
            return 0;
        }
        uint8_t rex = 0x48;
        if (reg & 8)
        {
            rex |= 0x01;
        }
        out[0] = rex;
        out[1] = 0xC1;
        out[2] = static_cast<uint8_t>(0xC0 | ((slashdigit & 7) << 3) | (reg & 7));
        out[3] = static_cast<uint8_t>(imm & 0xFF);
        return 4;
    }
    const int64_t sv = static_cast<int64_t>(imm);
    const bool fitssxt32 = (sv >= INT32_MIN && sv <= INT32_MAX);
    if (fitssxt32)
    {
        if (cap < 7)
        {
            return 0;
        }
        uint8_t rex = 0x48;
        if (reg & 8)
        {
            rex |= 0x01;
        }
        out[0] = rex;
        out[1] = 0x81;
        out[2] = static_cast<uint8_t>(0xC0 | ((slashdigit & 7) << 3) | (reg & 7));
        const int32_t imm32 = static_cast<int32_t>(sv);
        std::memcpy(out + 3, &imm32, 4);
        return 7;
    }
    if (cap < 13)
    {
        return 0;
    }
    const uint8_t scratch = (reg == 0) ? 1u : 0u;
    uint8_t rex1 = 0x48;
    if (scratch & 8)
    {
        rex1 |= 0x01;
    }
    out[0] = rex1;
    out[1] = static_cast<uint8_t>(0xB8 | (scratch & 7));
    std::memcpy(out + 2, &imm, 8);
    uint8_t rex2 = 0x48;
    if (scratch & 8)
    {
        rex2 |= 0x04;
    }
    if (reg & 8)
    {
        rex2 |= 0x01;
    }
    out[10] = rex2;
    out[11] = tworegopcode;
    out[12] = static_cast<uint8_t>(0xC0 | ((scratch & 7) << 3) | (reg & 7));
    return 13;
}

uint32_t DeobfEncoders::EncLeaRipRel(uint8_t* out, uint32_t cap, uint8_t reg, uint64_t targetrva, uint64_t encodeatrva)
{
    if (cap < 7)
    {
        return 0;
    }
    const int64_t d = static_cast<int64_t>(targetrva) - static_cast<int64_t>(encodeatrva) - 7;
    if (d < INT32_MIN || d > INT32_MAX)
    {
        return 0;
    }
    uint8_t rex = 0x48;
    if (reg & 8)
    {
        rex |= 0x04;
    }
    out[0] = rex;
    out[1] = 0x8D;
    out[2] = static_cast<uint8_t>(((reg & 7) << 3) | 0x05);
    const int32_t d32 = static_cast<int32_t>(d);
    std::memcpy(out + 3, &d32, 4);
    return 7;
}

uint32_t DeobfEncoders::EncIatCall(uint8_t* out, uint32_t cap, uint64_t iatslotrva, uint64_t encodeatrva)
{
    if (cap < 6)
    {
        return 0;
    }
    const int64_t d = static_cast<int64_t>(iatslotrva) - static_cast<int64_t>(encodeatrva) - 6;
    if (d < INT32_MIN || d > INT32_MAX)
    {
        return 0;
    }
    out[0] = 0xFF;
    out[1] = 0x15;
    const int32_t d32 = static_cast<int32_t>(d);
    std::memcpy(out + 2, &d32, 4);
    return 6;
}

uint32_t DeobfEncoders::EncCmpRegImm(uint8_t* out, uint32_t cap, uint8_t reg, CmpEncFamily family, uint8_t slashdigit, uint8_t tworegopcode, uint64_t imm)
{
    if (family == CmpEncFamily::BitTest)
    {
        if (cap < 5)
        {
            return 0;
        }
        uint8_t rex = 0x48;
        if (reg & 8)
        {
            rex |= 0x01;
        }
        out[0] = rex;
        out[1] = 0x0F;
        out[2] = 0xBA;
        out[3] = static_cast<uint8_t>(0xC0 | ((slashdigit & 7) << 3) | (reg & 7));
        out[4] = static_cast<uint8_t>(imm & 0xFF);
        return 5;
    }

    const uint8_t opcode = (family == CmpEncFamily::AluTest) ? 0xF7 : 0x81;
    const int64_t sv = static_cast<int64_t>(imm);
    const bool fitssxt32 = (sv >= INT32_MIN && sv <= INT32_MAX);

    if (fitssxt32)
    {
        if (cap < 7)
        {
            return 0;
        }
        uint8_t rex = 0x48;
        if (reg & 8)
        {
            rex |= 0x01;
        }
        out[0] = rex;
        out[1] = opcode;
        out[2] = static_cast<uint8_t>(0xC0 | ((slashdigit & 7) << 3) | (reg & 7));
        const int32_t imm32 = static_cast<int32_t>(sv);
        std::memcpy(out + 3, &imm32, 4);
        return 7;
    }

    if (cap < 13)
    {
        return 0;
    }
    const uint8_t scratch = (reg == 0) ? 1u : 0u;
    uint8_t rex1 = 0x48;
    if (scratch & 8)
    {
        rex1 |= 0x01;
    }
    out[0] = rex1;
    out[1] = static_cast<uint8_t>(0xB8 | (scratch & 7));
    std::memcpy(out + 2, &imm, 8);
    uint8_t rex2 = 0x48;
    if (scratch & 8)
    {
        rex2 |= 0x04;
    }
    if (reg & 8)
    {
        rex2 |= 0x01;
    }
    out[10] = rex2;
    out[11] = tworegopcode;
    out[12] = static_cast<uint8_t>(0xC0 | ((scratch & 7) << 3) | (reg & 7));
    return 13;
}

uint8_t DeobfEncoders::GprIdByName(const char* name)
{
    if (!name || !name[0]) return 0xFF;
    static const char* names[16] =
    {
        "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
        "r8",  "r9",  "r10", "r11", "r12", "r13", "r14", "r15"
    };
    for (uint8_t i = 0; i < 16; ++i)
    {
        if (std::strcmp(name, names[i]) == 0)
        {
            return i;
        }
    }
    return 0xFF;
}

uint64_t DeobfEncoders::GprById(const SophiaGprSet& gpr, uint8_t id)
{
    switch (id)
    {
    case 0:  return gpr.rax;
    case 1:  return gpr.rcx;
    case 2:  return gpr.rdx;
    case 3:  return gpr.rbx;
    case 4:  return gpr.rsp;
    case 5:  return gpr.rbp;
    case 6:  return gpr.rsi;
    case 7:  return gpr.rdi;
    case 8:  return gpr.r8;
    case 9:  return gpr.r9;
    case 10: return gpr.r10;
    case 11: return gpr.r11;
    case 12: return gpr.r12;
    case 13: return gpr.r13;
    case 14: return gpr.r14;
    case 15: return gpr.r15;
    default: return 0;
    }
}

uint64_t DeobfEncoders::GprByName(const SophiaGprSet& gpr, const char* name)
{
    const uint8_t id = GprIdByName(name);
    if (id == 0xFF) return 0;
    return GprById(gpr, id);
}

EatenBytes DeobfEncoders::EatForward(const std::vector<uint8_t>& buf, ZydisDecoder& decoder, uint64_t sitefileoff, uint32_t sitelen, uint64_t siterva, uint32_t sloteatenstartrva)
{
    EatenBytes out;
    if (sitelen >= 5)
    {
        out.Ok = true;
        out.Consumed = sitelen;
        return out;
    }

    uint64_t off = sitefileoff + sitelen;
    uint32_t consumed = sitelen;
    uint32_t eatenrva = sloteatenstartrva;
    while (consumed < 5)
    {
        if (off >= buf.size()) return out;
        size_t avail = buf.size() - off;
        if (avail > 15) avail = 15;
        ZydisDecodedInstruction insn;
        ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, buf.data() + off, avail, &insn, ops)))
        {
            return out;
        }

        const uint64_t insnorigrva = siterva + consumed;

        bool isrelbranch = false;
        bool relimmisshort = false;
        uint32_t relimmoffininsn = 0;
        uint64_t branchtargetrva = 0;

        for (uint8_t oi = 0; oi < insn.operand_count_visible; ++oi)
        {
            if (ops[oi].type == ZYDIS_OPERAND_TYPE_IMMEDIATE && ops[oi].imm.is_relative)
            {
                isrelbranch = true;
                relimmoffininsn = insn.raw.imm[0].offset;
                relimmisshort = (insn.raw.imm[0].size == 8);
                ZyanU64 abstarget = 0;
                ZydisCalcAbsoluteAddress(&insn, &ops[oi], insnorigrva, &abstarget);
                branchtargetrva = abstarget;
                break;
            }
        }

        bool hasriprelmem = false;
        uint32_t ripdispoffininsn = 0;
        uint64_t memabstargetrva = 0;
        for (uint8_t oi = 0; oi < insn.operand_count_visible; ++oi)
        {
            if (ops[oi].type == ZYDIS_OPERAND_TYPE_MEMORY && ops[oi].mem.base == ZYDIS_REGISTER_RIP)
            {
                hasriprelmem = true;
                ripdispoffininsn = insn.raw.disp.offset;
                ZyanU64 abstarget = 0;
                ZydisCalcAbsoluteAddress(&insn, &ops[oi], insnorigrva, &abstarget);
                memabstargetrva = abstarget;
                break;
            }
        }

        if (isrelbranch && relimmisshort)
        {
            const bool isjmpshort = (buf[off] == 0xEB);
            const bool isjccshort = (buf[off] >= 0x70 && buf[off] <= 0x7F);
            if (!isjmpshort && !isjccshort)
            {
                return out;
            }

            const uint32_t newlen = isjmpshort ? 5u : 6u;
            const uint32_t newinsnrva = eatenrva;
            const int64_t nrel = static_cast<int64_t>(branchtargetrva) - static_cast<int64_t>(newinsnrva) - static_cast<int64_t>(newlen);
            if (nrel < INT32_MIN || nrel > INT32_MAX) return out;
            const int32_t nrel32 = static_cast<int32_t>(nrel);

            if (isjmpshort)
            {
                out.Copy.push_back(0xE9);
                uint8_t b[4];
                std::memcpy(b, &nrel32, 4);
                out.Copy.insert(out.Copy.end(), b, b + 4);
            }
            else
            {
                const uint8_t cc = buf[off] & 0x0F;
                out.Copy.push_back(0x0F);
                out.Copy.push_back(0x80 | cc);
                uint8_t b[4];
                std::memcpy(b, &nrel32, 4);
                out.Copy.insert(out.Copy.end(), b, b + 4);
            }
            eatenrva += newlen;
        }
        else
        {
            const uint32_t insnlen = insn.length;
            const uint8_t* src = buf.data() + off;
            const size_t copystart = out.Copy.size();
            out.Copy.insert(out.Copy.end(), src, src + insnlen);
            const uint32_t newinsnrva = eatenrva;

            if (isrelbranch)
            {
                const int64_t nrel = static_cast<int64_t>(branchtargetrva) - static_cast<int64_t>(newinsnrva) - static_cast<int64_t>(insnlen);
                if (nrel < INT32_MIN || nrel > INT32_MAX) return out;
                const int32_t nrel32 = static_cast<int32_t>(nrel);
                std::memcpy(out.Copy.data() + copystart + relimmoffininsn, &nrel32, 4);
            }
            if (hasriprelmem)
            {
                const int64_t nd = static_cast<int64_t>(memabstargetrva) - static_cast<int64_t>(newinsnrva) - static_cast<int64_t>(insnlen);
                if (nd < INT32_MIN || nd > INT32_MAX) return out;
                const int32_t nd32 = static_cast<int32_t>(nd);
                std::memcpy(out.Copy.data() + copystart + ripdispoffininsn, &nd32, 4);
            }
            eatenrva += insnlen;
        }

        consumed += insn.length;
        off += insn.length;
    }

    out.Ok = true;
    out.Consumed = consumed;
    return out;
}

TrampolineBuilder::TrampolineBuilder(std::vector<uint8_t>& buf, ZydisDecoder& decoder, uint32_t predictedsectionrva)
    : Buf(buf), Decoder(decoder), Predicted(predictedsectionrva)
{
}

bool TrampolineBuilder::TryTrampoline(uint64_t sitefileoff, uint32_t sitelen, uint64_t siterva, uint32_t /*payloadlenhint*/, PayloadEncoder enc)
{
    const uint32_t slotstartrva = Predicted + static_cast<uint32_t>(BlobData.size());
    uint8_t scratch[32];
    uint32_t payloadlen = enc(scratch, sizeof(scratch), slotstartrva);
    if (payloadlen == 0 || payloadlen > sizeof(scratch))
    {
        return false;
    }

    const uint32_t sloteatenstartrva = slotstartrva + payloadlen;
    EatenBytes eaten = DeobfEncoders::EatForward(Buf, Decoder, sitefileoff, sitelen, siterva, sloteatenstartrva);
    if (!eaten.Ok)
    {
        return false;
    }

    const uint32_t eatenlen = static_cast<uint32_t>(eaten.Copy.size());
    const uint32_t backe9rva = sloteatenstartrva + eatenlen;
    const uint64_t backtargetrva = siterva + eaten.Consumed;
    const int64_t backdisp = static_cast<int64_t>(backtargetrva) - static_cast<int64_t>(backe9rva) - 5;
    if (backdisp < INT32_MIN || backdisp > INT32_MAX)
    {
        return false;
    }

    BlobData.insert(BlobData.end(), scratch, scratch + payloadlen);
    BlobData.insert(BlobData.end(), eaten.Copy.begin(), eaten.Copy.end());
    BlobData.push_back(0xE9);
    const int32_t bd32 = static_cast<int32_t>(backdisp);
    uint8_t bb[4];
    std::memcpy(bb, &bd32, 4);
    BlobData.insert(BlobData.end(), bb, bb + 4);

    SiteRec s{};
    s.SiteFileOff = sitefileoff;
    s.SiteRva = siterva;
    s.Consumed = eaten.Consumed;
    s.SlotStartRva = slotstartrva;
    TrampSites.push_back(s);

    const uint32_t inplacespill = (payloadlen > sitelen) ? (payloadlen - sitelen) : 0;
    const uint32_t trampspill = (5 > sitelen) ? (5u - sitelen) : 0;
    if (inplacespill > trampspill)
    {
        SavedBytes += (inplacespill - trampspill);
    }
    return true;
}

void TrampolineBuilder::EmitOutbounds() const
{
    for (const SiteRec& s : TrampSites)
    {
        const int64_t d = static_cast<int64_t>(s.SlotStartRva) - static_cast<int64_t>(s.SiteRva) - 5;
        Buf[s.SiteFileOff + 0] = 0xE9;
        const int32_t d32 = static_cast<int32_t>(d);
        std::memcpy(Buf.data() + s.SiteFileOff + 1, &d32, 4);
        for (uint32_t k = 5; k < s.Consumed; ++k)
        {
            Buf[s.SiteFileOff + k] = 0x90;
        }
    }
}

void DeobfEncoders::FormatEaExpr(char* out, size_t outsize, uint8_t baseid, uint8_t indexid, uint8_t scale, int64_t disp)
{
    if (!out || outsize == 0) return;
    static const char* const kregs[16] =
    {
        "rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi",
        "r8","r9","r10","r11","r12","r13","r14","r15"
    };
    std::string s = "[";
    bool any = false;
    if (baseid != 0xFF)
    {
        s += kregs[baseid];
        any = true;
    }
    if (indexid != 0xFF)
    {
        if (any) s += "+";
        s += kregs[indexid];
        if (scale > 1)
        {
            char sc[8];
            std::snprintf(sc, sizeof(sc), "*%u", scale);
            s += sc;
        }
        any = true;
    }
    if (disp != 0 || !any)
    {
        char db[24];
        if (disp < 0)
        {
            std::snprintf(db, sizeof(db), "-0x%llx", static_cast<unsigned long long>(-disp));
            if (any) s += db;
            else s += db + 1;
        }
        else
        {
            std::snprintf(db, sizeof(db), "+0x%llx", static_cast<unsigned long long>(disp));
            if (any) s += db;
            else s += db + 1;
        }
    }
    s += "]";
    std::snprintf(out, outsize, "%s", s.c_str());
}

bool DeobfEncoders::BuildSectionMap(const std::vector<uint8_t>& buf, DeobfSectionMap& out)
{
    out.Sections.clear();
    if (buf.size() < sizeof(IMAGE_DOS_HEADER))
    {
        return false;
    }
    const auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(buf.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
    {
        return false;
    }
    if (dos->e_lfanew <= 0 || static_cast<size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS64) > buf.size())
    {
        return false;
    }
    const auto nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(buf.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
    {
        return false;
    }
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
    {
        return false;
    }

    const WORD nsec = nt->FileHeader.NumberOfSections;
    auto sec = reinterpret_cast<const IMAGE_SECTION_HEADER*>(IMAGE_FIRST_SECTION(nt));
    const uint8_t* bufend = buf.data() + buf.size();
    if (reinterpret_cast<const uint8_t*>(sec) + static_cast<size_t>(nsec) * sizeof(IMAGE_SECTION_HEADER) > bufend)
    {
        return false;
    }

    out.Sections.reserve(nsec);
    for (WORD i = 0; i < nsec; ++i)
    {
        DeobfSection s;
        s.Rva = sec[i].VirtualAddress;
        s.VirtualSize = sec[i].Misc.VirtualSize;
        s.RawOffset = sec[i].PointerToRawData;
        s.RawSize = sec[i].SizeOfRawData;
        s.Characteristics = sec[i].Characteristics;
        std::memcpy(s.Name, sec[i].Name, 8);

        if (s.RawOffset >= buf.size())
        {
            s.RawSize = 0;
        }
        else if (s.RawOffset + s.RawSize > buf.size())
        {
            s.RawSize = static_cast<uint32_t>(buf.size() - s.RawOffset);
        }

        out.Sections.push_back(s);
    }
    return true;
}

bool DeobfEncoders::IsHardStop(const ZydisDecodedInstruction& insn)
{
    if (insn.meta.category == ZYDIS_CATEGORY_RET)
    {
        return true;
    }
    switch (insn.mnemonic)
    {
    case ZYDIS_MNEMONIC_UD2:
    case ZYDIS_MNEMONIC_UD1:
    case ZYDIS_MNEMONIC_HLT:
    case ZYDIS_MNEMONIC_INT:
    case ZYDIS_MNEMONIC_INT1:
    case ZYDIS_MNEMONIC_INT3:
    case ZYDIS_MNEMONIC_INTO:
    case ZYDIS_MNEMONIC_SYSRET:
    case ZYDIS_MNEMONIC_IRET:
    case ZYDIS_MNEMONIC_IRETD:
    case ZYDIS_MNEMONIC_IRETQ:
        return true;
    default:
        return false;
    }
}

bool DeobfEncoders::IsPatchableDataSection(const DeobfSection& s)
{
    if (s.RawSize == 0) return false;
    if ((s.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0) return false;
    if ((s.Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA) == 0) return false;
    return true;
}

HeaderSlackInfo DeobfEncoders::CheckHeaderSlack(const std::vector<uint8_t>& buf)
{
    HeaderSlackInfo out;
    if (buf.size() < sizeof(IMAGE_DOS_HEADER)) return out;
    const auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(buf.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return out;
    if (dos->e_lfanew <= 0 || static_cast<size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS64) > buf.size()) return out;
    const auto nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(buf.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return out;
    const auto sectable = reinterpret_cast<const IMAGE_SECTION_HEADER*>(IMAGE_FIRST_SECTION(nt));
    const uint32_t nsec = nt->FileHeader.NumberOfSections;
    const uint32_t nexthdroff = static_cast<uint32_t>(reinterpret_cast<const uint8_t*>(&sectable[nsec]) - buf.data());
    out.HaveSlack = (nexthdroff + sizeof(IMAGE_SECTION_HEADER) <= nt->OptionalHeader.SizeOfHeaders);
    out.SectionAlignment = nt->OptionalHeader.SectionAlignment ? nt->OptionalHeader.SectionAlignment : 0x1000u;
    uint64_t maxendrva = 0;
    for (WORD i = 0; i < nsec; ++i)
    {
        const uint64_t end = static_cast<uint64_t>(sectable[i].VirtualAddress) + sectable[i].Misc.VirtualSize;
        if (end > maxendrva) maxendrva = end;
    }
    out.PredictedRva = static_cast<uint32_t>((maxendrva + out.SectionAlignment - 1) & ~static_cast<uint64_t>(out.SectionAlignment - 1));
    return out;
}

std::vector<PdataRange> DeobfEncoders::ParsePdataRanges(const std::vector<uint8_t>& buf, const DeobfSectionMap& sm)
{
    std::vector<PdataRange> out;
    if (buf.size() < sizeof(IMAGE_DOS_HEADER)) return out;
    const auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(buf.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return out;
    if (dos->e_lfanew <= 0 || static_cast<size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS64) > buf.size()) return out;
    const auto nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(buf.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return out;

    const IMAGE_DATA_DIRECTORY& dd = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (dd.VirtualAddress == 0 || dd.Size < 12) return out;

    const uint64_t off = sm.RvaToOffset(dd.VirtualAddress);
    if (off == UINT64_MAX || off + dd.Size > buf.size()) return out;

    const uint32_t nentries = dd.Size / 12;
    out.reserve(nentries);
    for (uint32_t i = 0; i < nentries; ++i)
    {
        const uint8_t* p = buf.data() + off + i * 12;
        PdataRange r;
        std::memcpy(&r.BeginRva, p + 0, 4);
        std::memcpy(&r.EndRva, p + 4, 4);
        if (r.EndRva > r.BeginRva) out.push_back(r);
    }
    return out;
}

uint16_t DeobfEncoders::StringElemWidth(const char* mn)
{
    if (!mn || !mn[0]) return 1;
    const size_t n = std::strlen(mn);
    const char last = mn[n - 1];
    switch (last)
    {
    case 'b': return 1;
    case 'w': return 2;
    case 'd': return 4;
    case 'q': return 8;
    default:  return 1;
    }
}

uint64_t DeobfEncoders::ReconstructVecAddr(uint64_t siterva, const ZydisDecodedInstruction& insn, const ZydisDecodedOperand* ops, const SophiaGprSet& gpr, bool& outisriprel)
{
    outisriprel = false;

    int memidx = -1;
    for (int i = 0; i < insn.operand_count_visible; ++i)
    {
        if (ops[i].type == ZYDIS_OPERAND_TYPE_MEMORY)
        {
            memidx = i;
            break;
        }
    }
    if (memidx < 0) return 0;
    const auto& mem = ops[memidx].mem;

    if (mem.segment == ZYDIS_REGISTER_FS || mem.segment == ZYDIS_REGISTER_GS)
    {
        return 0;
    }

    if (mem.base == ZYDIS_REGISTER_RIP)
    {
        outisriprel = true;
        return static_cast<uint64_t>(static_cast<int64_t>(siterva) + static_cast<int64_t>(insn.length) + mem.disp.value);
    }

    uint64_t ea = 0;
    if (mem.base != ZYDIS_REGISTER_NONE)
    {
        ZydisRegister big = ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, mem.base);
        if (big == ZYDIS_REGISTER_NONE) return 0;
        ZyanI8 id = ZydisRegisterGetId(big);
        if (id < 0 || id > 15) return 0;
        ea += GprById(gpr, static_cast<uint8_t>(id));
    }
    if (mem.index != ZYDIS_REGISTER_NONE)
    {
        ZydisRegister big = ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, mem.index);
        if (big == ZYDIS_REGISTER_NONE) return 0;
        ZyanI8 id = ZydisRegisterGetId(big);
        if (id < 0 || id > 15) return 0;
        ea += GprById(gpr, static_cast<uint8_t>(id)) * static_cast<uint64_t>(mem.scale);
    }
    ea = static_cast<uint64_t>(static_cast<int64_t>(ea) + mem.disp.value);
    return ea;
}

bool DeobfEncoders::MergePrefixConsistent(std::vector<uint8_t>& canonical, const uint8_t* obs, size_t obslen)
{
    if (canonical.empty())
    {
        canonical.assign(obs, obs + obslen);
        return true;
    }
    const size_t minlen = canonical.size() < obslen ? canonical.size() : obslen;
    if (minlen > 0 && std::memcmp(canonical.data(), obs, minlen) != 0)
    {
        return false;
    }
    if (obslen > canonical.size())
    {
        canonical.insert(canonical.end(), obs + canonical.size(), obs + obslen);
    }
    return true;
}

std::string DeobfEncoders::DecodeBufferBytes(const uint8_t* data, size_t n)
{
    size_t asciilen = 0;
    while (asciilen < n && data[asciilen] != 0)
    {
        ++asciilen;
    }
    if (asciilen >= 2)
    {
        bool ok = true;
        for (size_t i = 0; i < asciilen; ++i)
        {
            const uint8_t b = data[i];
            if (!((b >= 0x20 && b <= 0x7E) || b == '\t' || b == '\n' || b == '\r'))
            {
                ok = false;
                break;
            }
        }
        if (ok)
        {
            std::string s(reinterpret_cast<const char*>(data), asciilen);
            return "\"" + s + "\"";
        }
    }

    if (n >= 4 && (n & 1) == 0)
    {
        std::string s;
        bool ok = true;
        for (size_t i = 0; i + 1 < n; i += 2)
        {
            const uint8_t lo = data[i], hi = data[i + 1];
            if (lo == 0 && hi == 0) break;
            if (hi != 0 || !((lo >= 0x20 && lo <= 0x7E) || lo == '\t' || lo == '\n' || lo == '\r'))
            {
                ok = false;
                break;
            }
            s.push_back(static_cast<char>(lo));
        }
        if (ok && s.size() >= 2)
        {
            return "L\"" + s + "\"";
        }
    }

    constexpr size_t kmaxhex = 32;
    std::string hex = "[hex] ";
    const size_t nh = n < kmaxhex ? n : kmaxhex;
    for (size_t i = 0; i < nh; ++i)
    {
        char b[4];
        std::snprintf(b, sizeof(b), "%02x", data[i]);
        hex += b;
    }
    if (n > kmaxhex)
    {
        hex += "...";
    }
    return hex;
}

bool DeobfEncoders::IsRedirectableString(const std::vector<uint8_t>& content)
{
    if (content.size() < 4) return false;

    size_t asciilen = 0;
    while (asciilen < content.size() && content[asciilen] != 0)
    {
        const uint8_t b = content[asciilen];
        if (!((b >= 0x20 && b <= 0x7E) || b == '\t' || b == '\n' || b == '\r'))
        {
            break;
        }
        ++asciilen;
    }
    if (asciilen >= 4) return true;

    if (content.size() >= 8 && (content.size() & 1) == 0)
    {
        size_t u16 = 0;
        for (size_t i = 0; i + 1 < content.size(); i += 2)
        {
            const uint8_t lo = content[i], hi = content[i + 1];
            if (lo == 0 && hi == 0) break;
            if (hi != 0 || !((lo >= 0x20 && lo <= 0x7E) || lo == '\t' || lo == '\n' || lo == '\r'))
            {
                break;
            }
            ++u16;
        }
        if (u16 >= 4) return true;
    }
    return false;
}