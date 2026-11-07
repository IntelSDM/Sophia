#include "../../../../Pch.h"
#include "CfgWalkTarget.h"
#include "../../DeobfEncoders.h"
#include "../../DeobfIo.h"
#include "../../../Database/AutoDebugStore.h"

#include <Zydis/Zydis.h>

#include <cstdio>
#include <cstring>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace
{
    struct Live
    {
        uint32_t             RawOff;
        uint32_t             RawSize;
        std::vector<uint8_t> Alive;
    };

    struct Fillable
    {
        uint32_t             RawOff;
        std::vector<uint8_t> Bits;
    };

    struct SectionTally
    {
        char     Name[9];
        uint32_t Total;
        uint32_t Live;
    };
}

void CfgWalkTarget::Deobfuscate(DeobfContext& ctx, Deobfuscator::Report& r)
{
    std::vector<Live> lives;
    lives.reserve(ctx.Sm.Sections.size());
    std::unordered_map<uint32_t, size_t> liveidxbyrawoff;

    for (const DeobfSection& s : ctx.Sm.Sections)
    {
        if (!DeobfSectionMap::IsExecutable(s)) continue;
        if (s.RawSize == 0) continue;
        Live l;
        l.RawOff = s.RawOffset;
        l.RawSize = s.RawSize;
        l.Alive.assign(s.RawSize, 0);
        liveidxbyrawoff[s.RawOffset] = lives.size();
        lives.push_back(std::move(l));
        r.CodeBytesTotal += s.RawSize;
    }

    auto marklive = [&](uint64_t rva, uint32_t len)
        {
            const DeobfSection* s = ctx.Sm.Find(rva);
            if (!s || !DeobfSectionMap::IsExecutable(*s)) return;
            auto it = liveidxbyrawoff.find(s->RawOffset);
            if (it == liveidxbyrawoff.end()) return;
            Live& l = lives[it->second];
            const uint64_t start = rva - s->Rva;
            for (uint32_t i = 0; i < len; ++i)
            {
                const uint64_t b = start + i;
                if (b < l.Alive.size()) l.Alive[b] = 1;
            }
        };

    const std::unordered_set<uint64_t>& explored = ctx.Store->ExploredRvas();
    r.SeedRvas = explored.size();

    std::unordered_set<uint64_t> visited;
    visited.reserve(explored.size() * 4);
    std::vector<uint64_t> work;
    work.reserve(explored.size() * 2);
    for (uint64_t rva : explored) work.push_back(rva);

    while (!work.empty())
    {
        const uint64_t rva = work.back();
        work.pop_back();
        if (!visited.insert(rva).second) continue;

        const uint64_t off = ctx.Sm.RvaToOffset(rva);
        if (off == UINT64_MAX) continue;

        size_t avail = ctx.Buf.size() - off;
        if (avail > 15) avail = 15;
        ZydisDecodedInstruction insn;
        ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&ctx.Decoder, ctx.Buf.data() + off, avail, &insn, ops))) continue;

        marklive(rva, insn.length);
        ++r.LiveInstructions;

        if (DeobfEncoders::IsHardStop(insn)) continue;

        const ZydisInstructionCategory cat = insn.meta.category;

        if (cat == ZYDIS_CATEGORY_UNCOND_BR)
        {
            if (insn.operand_count_visible >= 1 &&
                ops[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
                ops[0].imm.is_relative)
            {
                ZyanU64 to = 0;
                if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&insn, &ops[0], rva, &to)))
                    work.push_back(to);
            }
            continue;
        }

        work.push_back(rva + insn.length);

        if (cat == ZYDIS_CATEGORY_COND_BR)
        {
            if (insn.operand_count_visible >= 1 &&
                ops[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
                ops[0].imm.is_relative)
            {
                ZyanU64 to = 0;
                if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&insn, &ops[0], rva, &to)))
                    work.push_back(to);
            }
            continue;
        }

        if (cat == ZYDIS_CATEGORY_CALL)
        {
            if (insn.operand_count_visible >= 1 &&
                ops[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
                ops[0].imm.is_relative)
            {
                ZyanU64 to = 0;
                if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&insn, &ops[0], rva, &to)))
                    work.push_back(to);
            }
            continue;
        }
    }

    std::vector<SectionTally> tallies;
    tallies.reserve(lives.size());
    for (const DeobfSection& s : ctx.Sm.Sections)
    {
        if (!DeobfSectionMap::IsExecutable(s)) continue;
        auto it = liveidxbyrawoff.find(s.RawOffset);
        if (it == liveidxbyrawoff.end()) continue;
        const Live& l = lives[it->second];
        uint32_t live = 0;
        for (uint32_t i = 0; i < l.Alive.size(); ++i) if (l.Alive[i]) ++live;
        SectionTally t;
        std::memcpy(t.Name, s.Name, sizeof(t.Name));
        t.Total = l.RawSize;
        t.Live = live;
        tallies.push_back(t);
        r.LiveBytes += live;
    }
    r.DeadBytes = r.CodeBytesTotal > r.LiveBytes ? r.CodeBytesTotal - r.LiveBytes : 0;

    DeobfIo::RuleOpen("dead-code-id (pass 2 identification)");
    std::printf("[deobf]   seed RVAs (observed)     : %llu\n", static_cast<unsigned long long>(r.SeedRvas));
    std::printf("[deobf]   instructions walked      : %llu\n", static_cast<unsigned long long>(r.LiveInstructions));
    std::printf("[deobf]   exec-section bytes total : %llu\n", static_cast<unsigned long long>(r.CodeBytesTotal));
    if (r.CodeBytesTotal > 0)
    {
        const double livep = 100.0 * r.LiveBytes / r.CodeBytesTotal;
        const double deadp = 100.0 * r.DeadBytes / r.CodeBytesTotal;
        std::printf("[deobf]   live bytes               : %llu  (%.2f%%)\n", static_cast<unsigned long long>(r.LiveBytes), livep);
        std::printf("[deobf]   dead bytes (would INT3)  : %llu  (%.2f%%)\n", static_cast<unsigned long long>(r.DeadBytes), deadp);
    }
    if (!tallies.empty())
    {
        std::puts("[deobf] per section:");
        for (const SectionTally& t : tallies)
        {
            const uint32_t dead = t.Total > t.Live ? t.Total - t.Live : 0;
            const double livep = t.Total ? 100.0 * t.Live / t.Total : 0.0;
            std::printf("[deobf]   %-8s  total=%u  live=%u  dead=%u  (%.2f%% live)\n",
                t.Name, t.Total, t.Live, dead, livep);
        }
    }
    DeobfIo::RuleClose();

    std::vector<PdataRange> pdata = DeobfEncoders::ParsePdataRanges(ctx.Buf, ctx.Sm);
    r.PdataFunctions = static_cast<uint32_t>(pdata.size());

    std::vector<Fillable> fills;
    std::unordered_map<uint32_t, size_t> fillidxbyrawoff;
    for (const DeobfSection& s : ctx.Sm.Sections)
    {
        if (!DeobfSectionMap::IsExecutable(s)) continue;
        if (s.RawSize == 0) continue;
        Fillable f;
        f.RawOff = s.RawOffset;
        f.Bits.assign(s.RawSize, 0);
        fillidxbyrawoff[s.RawOffset] = fills.size();
        fills.push_back(std::move(f));
    }
    for (const PdataRange& pr : pdata)
    {
        const DeobfSection* s = ctx.Sm.Find(pr.BeginRva);
        if (!s || !DeobfSectionMap::IsExecutable(*s)) continue;
        auto it = fillidxbyrawoff.find(s->RawOffset);
        if (it == fillidxbyrawoff.end()) continue;
        Fillable& f = fills[it->second];
        const uint64_t secthi = static_cast<uint64_t>(s->Rva) + f.Bits.size();
        const uint64_t lo = pr.BeginRva;
        const uint64_t hi = pr.EndRva < secthi ? pr.EndRva : secthi;
        if (hi <= lo) continue;
        const uint64_t offlo = lo - s->Rva;
        const uint64_t offhi = hi - s->Rva;
        for (uint64_t i = offlo; i < offhi; ++i) f.Bits[i] = 1;
    }

    for (const Fillable& f : fills)
    {
        for (uint32_t i = 0; i < f.Bits.size(); ++i) if (f.Bits[i]) ++r.PdataFillableBytes;
    }

    std::puts("");
    std::printf("[deobf] .pdata: %u function range(s), %llu byte(s) inside any range\n",
        r.PdataFunctions, static_cast<unsigned long long>(r.PdataFillableBytes));

    const bool userwantsfill = DeobfIo::PromptYesNo("[deobf] Remove unhit code (fill dead bytes with 0xCC)?", false);

    if (userwantsfill && pdata.empty())
    {
        std::puts("[deobf] int3-fill: SKIPPED -- no .pdata exception directory. Without RUNTIME_FUNCTION ranges there's no safe way to tell embedded data (jump tables etc.) from code, and blanket filling breaks IDA's analysis. Output remains runnable (rewrites only).");
        r.Int3FillApplied = false;
    }
    else if (userwantsfill)
    {
        for (const DeobfSection& s : ctx.Sm.Sections)
        {
            if (!DeobfSectionMap::IsExecutable(s)) continue;
            auto liveit = liveidxbyrawoff.find(s.RawOffset);
            auto fillit = fillidxbyrawoff.find(s.RawOffset);
            if (liveit == liveidxbyrawoff.end() || fillit == fillidxbyrawoff.end()) continue;
            const Live& l = lives[liveit->second];
            const Fillable& f = fills[fillit->second];
            for (uint32_t i = 0; i < l.Alive.size(); ++i)
            {
                if (!l.Alive[i] && f.Bits[i])
                {
                    ctx.Buf[s.RawOffset + i] = 0xCC;
                    ++r.Int3Bytes;
                }
            }
        }
        r.Int3FillApplied = true;
        const double frac = r.DeadBytes ? 100.0 * r.Int3Bytes / r.DeadBytes : 0.0;
        std::printf("[deobf] int3-fill: INT3-filled %llu byte(s) (%.2f%% of identified dead; the rest is data-in-code preserved by the .pdata mask)\n",
            static_cast<unsigned long long>(r.Int3Bytes), frac);
    }
    else
    {
        std::puts("[deobf] int3-fill: SKIPPED (output remains runnable -- rewrites only)");
    }
}