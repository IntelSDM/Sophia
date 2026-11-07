#pragma once
#include "PEScan.h"
#include <Zydis/Zydis.h>
#include <cstring>
#include <cstdint>

class PeScanHelpers
{
public:
    static bool IsComparison(ZydisMnemonic mn, const char* mstr, int visibleops)
    {
        switch (mn)
        {
        case ZYDIS_MNEMONIC_CMP:
        case ZYDIS_MNEMONIC_TEST:
        case ZYDIS_MNEMONIC_BT:
        case ZYDIS_MNEMONIC_BTS:
        case ZYDIS_MNEMONIC_BTR:
        case ZYDIS_MNEMONIC_BTC:
            return true;
        default: break;
        }
        if (!mstr) return false;
        if (std::strncmp(mstr, "cmpxchg", 7) == 0) return true;
        if (visibleops >= 1 && std::strncmp(mstr, "set", 3) == 0) return true;
        if (std::strncmp(mstr, "cmov", 4) == 0) return true;
        return false;
    }

    static MemOperand ExtractMemOperand(const ZydisDecodedInstruction& insn, const ZydisDecodedOperand* ops)
    {
        MemOperand m;
        for (int i = 0; i < insn.operand_count_visible; ++i)
        {
            const ZydisDecodedOperand& o = ops[i];
            if (o.type != ZYDIS_OPERAND_TYPE_MEMORY) continue;

            m.Present = true;
            m.Width = static_cast<uint16_t>(o.size / 8);
            m.Scale = static_cast<uint8_t>(o.mem.scale);
            if (o.mem.disp.has_displacement)
                m.Disp = static_cast<int64_t>(o.mem.disp.value);

            if (o.mem.base == ZYDIS_REGISTER_RIP)
            {
                m.RipRel = true;
            }
            else if (o.mem.base != ZYDIS_REGISTER_NONE)
            {
                const char* b = ZydisRegisterGetString(o.mem.base);
                if (b) std::strncpy(m.Base, b, sizeof(m.Base) - 1);
            }
            if (o.mem.index != ZYDIS_REGISTER_NONE)
            {
                const char* ix = ZydisRegisterGetString(o.mem.index);
                if (ix) std::strncpy(m.Index, ix, sizeof(m.Index) - 1);
            }
            if (o.mem.segment == ZYDIS_REGISTER_GS)      std::strncpy(m.Seg, "gs", sizeof(m.Seg) - 1);
            else if (o.mem.segment == ZYDIS_REGISTER_FS) std::strncpy(m.Seg, "fs", sizeof(m.Seg) - 1);

            break;
        }
        return m;
    }

    static bool IsStringOp(const ZydisDecodedInstruction& insn, const ZydisDecodedOperand* ops, const char* mstr)
    {
        if (!mstr) return false;
        if ((insn.attributes & (ZYDIS_ATTRIB_HAS_REP | ZYDIS_ATTRIB_HAS_REPE | ZYDIS_ATTRIB_HAS_REPNE)) == 0)
            return false;

        static const char* const unambiguous[] = {
            "movsb", "movsw", "movsq",
            "stosb", "stosw", "stosd", "stosq",
            "lodsb", "lodsw", "lodsd", "lodsq",
            "scasb", "scasw", "scasd", "scasq",
            "cmpsb", "cmpsw", "cmpsq",
        };
        for (const char* s : unambiguous)
            if (std::strcmp(mstr, s) == 0) return true;

        if (std::strcmp(mstr, "movsd") == 0 || std::strcmp(mstr, "cmpsd") == 0)
        {
            for (int i = 0; i < insn.operand_count_visible; ++i)
                if (ops[i].type == ZYDIS_OPERAND_TYPE_MEMORY && (ops[i].mem.base == ZYDIS_REGISTER_RSI || ops[i].mem.base == ZYDIS_REGISTER_RDI))
                    return true;
        }
        return false;
    }

    static bool IsVectorMove(const char* m)
    {
        if (!m) return false;
        return std::strncmp(m, "movdq", 5) == 0 ||
            std::strncmp(m, "movup", 5) == 0 ||
            std::strncmp(m, "movap", 5) == 0 ||
            std::strncmp(m, "lddqu", 5) == 0 ||
            std::strncmp(m, "vmovdq", 6) == 0 ||
            std::strncmp(m, "vmovup", 6) == 0 ||
            std::strncmp(m, "vmovap", 6) == 0 ||
            std::strncmp(m, "vlddqu", 6) == 0;
    }

    static bool IsMovVariant(ZydisMnemonic mn)
    {
        return mn == ZYDIS_MNEMONIC_MOV || mn == ZYDIS_MNEMONIC_MOVZX || mn == ZYDIS_MNEMONIC_MOVSX || mn == ZYDIS_MNEMONIC_MOVSXD;
    }

    static bool IsArith(ZydisMnemonic mn)
    {
        switch (mn)
        {
        case ZYDIS_MNEMONIC_ADD:  case ZYDIS_MNEMONIC_SUB:
        case ZYDIS_MNEMONIC_ADC:  case ZYDIS_MNEMONIC_SBB:
        case ZYDIS_MNEMONIC_INC:  case ZYDIS_MNEMONIC_DEC:
        case ZYDIS_MNEMONIC_XADD:
        case ZYDIS_MNEMONIC_XOR:  case ZYDIS_MNEMONIC_AND:
        case ZYDIS_MNEMONIC_OR:   case ZYDIS_MNEMONIC_NOT:
        case ZYDIS_MNEMONIC_NEG:
        case ZYDIS_MNEMONIC_SHL:  case ZYDIS_MNEMONIC_SHR:
        case ZYDIS_MNEMONIC_SAR:
        case ZYDIS_MNEMONIC_ROL:  case ZYDIS_MNEMONIC_ROR:
        case ZYDIS_MNEMONIC_RCL:  case ZYDIS_MNEMONIC_RCR:
        case ZYDIS_MNEMONIC_SHLD: case ZYDIS_MNEMONIC_SHRD:
        case ZYDIS_MNEMONIC_MUL:  case ZYDIS_MNEMONIC_IMUL:
        case ZYDIS_MNEMONIC_DIV:  case ZYDIS_MNEMONIC_IDIV:
        case ZYDIS_MNEMONIC_LEA:  case ZYDIS_MNEMONIC_BSWAP:
            return true;
        default:
            return false;
        }
    }

    static void ScanSection(const ZydisDecoder* dec, const uint8_t* data, size_t size, uint64_t rawbase, uint64_t rva, std::vector<InsnSite>& out)
    {
        ZyanUSize off = 0;
        while (off < size)
        {
            ZydisDecodedInstruction insn;
            ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
            ZyanStatus st = ZydisDecoderDecodeFull(dec, data + off, size - off, &insn, ops);
            if (!ZYAN_SUCCESS(st))
            {
                ++off;
                continue;
            }

            const uint64_t insnrva = rva + off;
            const ZydisInstructionCategory cat = insn.meta.category;

            if (cat == ZYDIS_CATEGORY_COND_BR || cat == ZYDIS_CATEGORY_UNCOND_BR || cat == ZYDIS_CATEGORY_CALL)
            {
                if (insn.operand_count_visible >= 1 && ops[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE && ops[0].imm.is_relative)
                {
                    ZyanU64 to = 0;
                    if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&insn, &ops[0], insnrva, &to)))
                    {
                        InsnSite js;
                        js.Kind = (cat == ZYDIS_CATEGORY_CALL) ? SiteKind::Call : SiteKind::Branch;
                        js.FileOffset = rawbase + off;
                        js.Rva = insnrva;
                        js.ToRva = to;
                        js.Va = 0;
                        js.Length = insn.length;
                        const char* m = ZydisMnemonicGetString(insn.mnemonic);
                        if (m)
                        {
                            std::strncpy(js.Mnemonic, m, sizeof(js.Mnemonic) - 1);
                        }
                        out.push_back(js);
                    }
                }
                else if ((cat == ZYDIS_CATEGORY_UNCOND_BR || cat == ZYDIS_CATEGORY_CALL) && insn.operand_count_visible >= 1 && (ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER || ops[0].type == ZYDIS_OPERAND_TYPE_MEMORY))
                {
                    InsnSite is;
                    is.Kind = (cat == ZYDIS_CATEGORY_CALL) ? SiteKind::IndCall : SiteKind::IndBranch;
                    is.FileOffset = rawbase + off;
                    is.Rva = insnrva;
                    is.ToRva = 0;
                    is.Va = 0;
                    is.Length = insn.length;
                    const char* m = ZydisMnemonicGetString(insn.mnemonic);
                    if (m)
                    {
                        std::strncpy(is.Mnemonic, m, sizeof(is.Mnemonic) - 1);
                    }
                    if (ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER)
                    {
                        ZydisRegister big = ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, ops[0].reg.value);
                        const char* rn = ZydisRegisterGetString(big != ZYDIS_REGISTER_NONE ? big : ops[0].reg.value);
                        if (rn) std::strncpy(is.Reg, rn, sizeof(is.Reg) - 1);
                    }
                    else
                    {
                        is.Mem = ExtractMemOperand(insn, ops);
                        is.Mem.Read = true;
                    }
                    out.push_back(is);
                }
            }
            else
            {
                const char* mstr = ZydisMnemonicGetString(insn.mnemonic);
                if (insn.mnemonic == ZYDIS_MNEMONIC_SYSCALL)
                {
                    InsnSite sy;
                    sy.Kind = SiteKind::Syscall;
                    sy.FileOffset = rawbase + off;
                    sy.Rva = insnrva;
                    sy.ToRva = 0;
                    sy.Va = 0;
                    sy.Length = insn.length;
                    std::strncpy(sy.Mnemonic, mstr ? mstr : "syscall", sizeof(sy.Mnemonic) - 1);
                    out.push_back(sy);
                }
                else if (IsComparison(insn.mnemonic, mstr, insn.operand_count_visible))
                {
                    InsnSite cs;
                    cs.Kind = SiteKind::Compare;
                    cs.FileOffset = rawbase + off;
                    cs.Rva = insnrva;
                    cs.ToRva = 0;
                    cs.Va = 0;
                    cs.Length = insn.length;
                    if (mstr)
                    {
                        std::strncpy(cs.Mnemonic, mstr, sizeof(cs.Mnemonic) - 1);
                    }
                    cs.Mem = ExtractMemOperand(insn, ops);
                    out.push_back(cs);
                }
                else if (IsStringOp(insn, ops, mstr))
                {
                    InsnSite ss;
                    ss.Kind = SiteKind::String;
                    ss.FileOffset = rawbase + off;
                    ss.Rva = insnrva;
                    ss.ToRva = 0;
                    ss.Va = 0;
                    ss.Length = insn.length;
                    if (mstr)
                    {
                        std::strncpy(ss.Mnemonic, mstr, sizeof(ss.Mnemonic) - 1);
                    }
                    out.push_back(ss);
                }
                else if (IsVectorMove(mstr))
                {
                    int memidx = -1;
                    for (int i = 0; i < insn.operand_count_visible; ++i)
                        if (ops[i].type == ZYDIS_OPERAND_TYPE_MEMORY)
                        {
                            memidx = i;
                            break;
                        }
                    if (memidx > 0)
                    {
                        InsnSite vs;
                        vs.Kind = SiteKind::VecMove;
                        vs.FileOffset = rawbase + off;
                        vs.Rva = insnrva;
                        vs.ToRva = 0;
                        vs.Va = 0;
                        vs.Length = insn.length;
                        if (mstr)
                        {
                            std::strncpy(vs.Mnemonic, mstr, sizeof(vs.Mnemonic) - 1);
                        }
                        vs.Mem = ExtractMemOperand(insn, ops);
                        out.push_back(vs);
                    }
                }
                else if (IsMovVariant(insn.mnemonic))
                {
                    int memidx = -1, regidx = -1;
                    for (int i = 0; i < insn.operand_count_visible; ++i)
                    {
                        if (ops[i].type == ZYDIS_OPERAND_TYPE_MEMORY && memidx < 0)
                            memidx = i;
                        else if (ops[i].type == ZYDIS_OPERAND_TYPE_REGISTER && regidx < 0)
                            regidx = i;
                    }
                    if (memidx >= 0 && regidx >= 0)
                    {
                        InsnSite mv;
                        mv.Kind = SiteKind::Mov;
                        mv.FileOffset = rawbase + off;
                        mv.Rva = insnrva;
                        mv.ToRva = 0;
                        mv.Va = 0;
                        mv.Length = insn.length;
                        if (mstr)
                            std::strncpy(mv.Mnemonic, mstr, sizeof(mv.Mnemonic) - 1);
                        mv.Mem = ExtractMemOperand(insn, ops);
                        mv.Mem.Read = (memidx > 0);
                        const char* rn = ZydisRegisterGetString(ops[regidx].reg.value);
                        if (rn) std::strncpy(mv.Reg, rn, sizeof(mv.Reg) - 1);
                        out.push_back(mv);
                    }
                }
                else if (insn.mnemonic == ZYDIS_MNEMONIC_LEA)
                {
                    InsnSite lea;
                    lea.Kind = SiteKind::Lea;
                    lea.FileOffset = rawbase + off;
                    lea.Rva = insnrva;
                    lea.ToRva = 0;
                    lea.Va = 0;
                    lea.Length = insn.length;
                    if (mstr)
                        std::strncpy(lea.Mnemonic, mstr, sizeof(lea.Mnemonic) - 1);
                    lea.Mem = ExtractMemOperand(insn, ops);
                    for (int i = 0; i < insn.operand_count_visible; ++i)
                    {
                        const ZydisDecodedOperand& o = ops[i];
                        if (o.type == ZYDIS_OPERAND_TYPE_REGISTER)
                        {
                            ZydisRegister big = ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, o.reg.value);
                            const char* rn = ZydisRegisterGetString(big != ZYDIS_REGISTER_NONE ? big : o.reg.value);
                            if (rn) std::strncpy(lea.Reg, rn, sizeof(lea.Reg) - 1);
                            break;
                        }
                    }
                    out.push_back(lea);
                }
                else if (IsArith(insn.mnemonic))
                {
                    InsnSite ar;
                    ar.Kind = SiteKind::Arith;
                    ar.FileOffset = rawbase + off;
                    ar.Rva = insnrva;
                    ar.ToRva = 0;
                    ar.Va = 0;
                    ar.Length = insn.length;
                    if (mstr)
                        std::strncpy(ar.Mnemonic, mstr, sizeof(ar.Mnemonic) - 1);
                    ar.Mem = ExtractMemOperand(insn, ops);
                    if (ar.Mem.Present) ar.Mem.Read = true;
                    int regsseen = 0;
                    for (int i = 0; i < insn.operand_count_visible; ++i)
                    {
                        const ZydisDecodedOperand& o = ops[i];
                        if (o.type == ZYDIS_OPERAND_TYPE_REGISTER)
                        {
                            ZydisRegister big = ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, o.reg.value);
                            const char* rn = ZydisRegisterGetString(big != ZYDIS_REGISTER_NONE ? big : o.reg.value);
                            if (rn)
                            {
                                if (regsseen == 0)
                                    std::strncpy(ar.Reg, rn, sizeof(ar.Reg) - 1);
                                else if (regsseen == 1)
                                    std::strncpy(ar.Reg2, rn, sizeof(ar.Reg2) - 1);
                            }
                            ++regsseen;
                        }
                        else if (o.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && !ar.HasImm)
                        {
                            ar.Imm = o.imm.value.u;
                            ar.HasImm = true;
                        }
                    }
                    out.push_back(ar);
                }
            }

            off += insn.length;
        }
    }

private:
    PeScanHelpers() = delete;
};