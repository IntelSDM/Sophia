#include "../../../../Pch.h"
#include "CompareTarget.h"
#include "../../DeobfEncoders.h"
#include "../../DeobfIo.h"
#include "../../../Database/AutoDebugStore.h"
#include "../../../WinPE/SectionManager.h"

#include <windows.h>
#include <Zydis/Zydis.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <map>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace
{
    struct CmpTally
    {
        std::unordered_set<uint64_t> Values;
        uint32_t     HitCount = 0;
        uint32_t     Length = 0;
        uint64_t     FileOff = 0;
        uint8_t      PreservedRegId = 0xFF;
        bool         IsRegReg = false;
        bool         HiddenIsMem = false;
        bool         HasImmForm = false;
        bool         PreservedFirst = true;
        CmpEncFamily Family = CmpEncFamily::None;
        uint8_t      SlashDigit = 0xFF;
        uint8_t      TwoRegOpcode = 0;
        char         Mn[16] = {};
        char         PreservedRegName[8] = {};
        char         HiddenRegName[8] = {};
        std::map<std::pair<uint64_t, uint64_t>, uint32_t> PairCounts;
    };

    struct CmpRewriteRow
    {
        uint64_t    Rva;
        const char* Mn;
        const char* PreservedName;
        char        HiddenLabel[16];
        uint32_t    Slot;
        uint32_t    EncLen;
        uint32_t    NValues;
        uint32_t    NHits;
        uint32_t    TargetRva;
        uint64_t    SingleValue;
        enum PathKind { Skip = 0, Imm = 1, Lea = 2 } Path;
        bool        Ok;
        bool        ViaTramp;
        uint32_t    Consumed;
    };

    struct CmpDeferred
    {
        uint64_t SiteFileOff;
        uint32_t SiteLen;
        uint64_t SiteRva;
        uint32_t TargetRva;
        size_t   RowIdx;
    };

    struct CmpImmDeferred
    {
        uint64_t     SiteFileOff;
        uint32_t     SiteLen;
        uint64_t     SiteRva;
        uint64_t     Value;
        uint8_t      Reg;
        CmpEncFamily Family;
        uint8_t      SlashDigit;
        uint8_t      TwoRegOpcode;
        uint32_t     PayloadLen;
        size_t       RowIdx;
    };
}

void CompareTarget::Deobfuscate(DeobfContext& ctx, Deobfuscator::Report& r)
{
    const HeaderSlackInfo cmplistslack = DeobfEncoders::CheckHeaderSlack(ctx.Buf);
    const bool cmphaveheaderslack = cmplistslack.HaveSlack && ctx.Cfg.WantCmpList;
    const uint32_t cmppredictedsectionrva = cmplistslack.PredictedRva;
    if (!cmphaveheaderslack) r.CmpNoHeaderSlack = true;

    std::unordered_map<uint64_t, CmpTally> cmpperrva;
    std::unordered_set<uint64_t> cmpallrvas;
    std::unordered_set<uint64_t> cmpfilteredrvas;

    ctx.Store->ForEachRecord(ObsKind::Compare,
        [&](const void* rec, size_t sz)
        {
            ++r.CmpRecordsSeen;
            if (sz != sizeof(CompareHit)) return;
            const CompareHit* h = static_cast<const CompareHit*>(rec);
            cmpallrvas.insert(h->Rva);
            if (cmpfilteredrvas.count(h->Rva)) return;

            auto pit = cmpperrva.find(h->Rva);
            CmpTally* tp = nullptr;
            if (pit != cmpperrva.end())
            {
                tp = &pit->second;
            }
            else
            {
                enum class Drop : uint8_t { None, Setcc, Cmpxchg, AlreadyImm, Other };

                CmpTally fresh;
                auto classify = [&]() -> Drop
                    {
                        const uint64_t off = ctx.Sm.RvaToOffset(h->Rva);
                        if (off == UINT64_MAX) return Drop::Other;
                        size_t avail = ctx.PreMovRewriteBuf.size() - off;
                        if (avail > 15) avail = 15;
                        ZydisDecodedInstruction insn;
                        ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
                        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&ctx.Decoder, ctx.PreMovRewriteBuf.data() + off, avail, &insn, ops)))
                        {
                            return Drop::Other;
                        }
                        const char* mstr = ZydisMnemonicGetString(insn.mnemonic);
                        if (!mstr) return Drop::Other;

                        if (std::strncmp(mstr, "set", 3) == 0) return Drop::Setcc;
                        if (std::strncmp(mstr, "cmpxchg", 7) == 0) return Drop::Cmpxchg;

                        if (insn.operand_count_visible < 2) return Drop::Other;
                        for (int i = 0; i < insn.operand_count_visible; ++i)
                        {
                            if (ops[i].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) return Drop::AlreadyImm;
                        }

                        int reg0 = -1, reg1 = -1, mem0 = -1;
                        for (int i = 0; i < insn.operand_count_visible; ++i)
                        {
                            if (ops[i].type == ZYDIS_OPERAND_TYPE_REGISTER)
                            {
                                if (reg0 < 0) reg0 = i;
                                else if (reg1 < 0) reg1 = i;
                            }
                            else if (ops[i].type == ZYDIS_OPERAND_TYPE_MEMORY)
                            {
                                if (mem0 < 0) mem0 = i;
                            }
                        }

                        const bool isregreg = (reg0 == 0 && reg1 == 1 && mem0 < 0);
                        const bool isregmem = (reg0 == 0 && mem0 == 1 && reg1 < 0);
                        const bool ismemreg = (mem0 == 0 && reg0 == 1 && reg1 < 0);
                        if (!isregreg && !isregmem && !ismemreg) return Drop::Other;

                        const int preservedopidx = reg0;

                        ZydisRegister big = ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, ops[preservedopidx].reg.value);
                        if (big == ZYDIS_REGISTER_NONE) return Drop::Other;
                        ZyanI8 id = ZydisRegisterGetId(big);
                        if (id < 0 || id > 15) return Drop::Other;

                        fresh.Length = insn.length;
                        fresh.FileOff = off;
                        fresh.PreservedRegId = static_cast<uint8_t>(id);
                        fresh.IsRegReg = isregreg;
                        fresh.HiddenIsMem = !isregreg;
                        fresh.PreservedFirst = !ismemreg;
                        std::strncpy(fresh.Mn, mstr, sizeof(fresh.Mn) - 1);
                        const char* rn = ZydisRegisterGetString(big);
                        if (rn) std::strncpy(fresh.PreservedRegName, rn, sizeof(fresh.PreservedRegName) - 1);

                        fresh.HasImmForm = DeobfEncoders::CmpEncoderInfo(mstr, fresh.Family, fresh.SlashDigit, fresh.TwoRegOpcode);

                        if (isregreg)
                        {
                            ZydisRegister big2 = ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, ops[reg1].reg.value);
                            const char* rn2 = ZydisRegisterGetString(big2 != ZYDIS_REGISTER_NONE ? big2 : ops[reg1].reg.value);
                            if (rn2) std::strncpy(fresh.HiddenRegName, rn2, sizeof(fresh.HiddenRegName) - 1);
                        }
                        return Drop::None;
                    };

                const Drop drop = classify();
                if (drop != Drop::None)
                {
                    cmpfilteredrvas.insert(h->Rva);
                    switch (drop)
                    {
                    case Drop::Setcc:      ++r.CmpDropSetcc;      break;
                    case Drop::Cmpxchg:    ++r.CmpDropCmpxchg;    break;
                    case Drop::AlreadyImm: ++r.CmpDropAlreadyImm; break;
                    case Drop::Other:      ++r.CmpDropOther;      break;
                    default: break;
                    }
                    return;
                }

                auto ins = cmpperrva.emplace(h->Rva, fresh);
                tp = &ins.first->second;
            }

            uint64_t val = tp->HiddenIsMem ? h->MemLo : DeobfEncoders::GprByName(h->Gpr, tp->HiddenRegName);
            if (tp->Family == CmpEncFamily::BitTest) val &= 0xFF;

            const uint64_t preservedval = DeobfEncoders::GprByName(h->Gpr, tp->PreservedRegName);
            ++tp->PairCounts[{preservedval, val}];

            ++tp->HitCount;
            tp->Values.insert(val);
        });

    r.CmpDistinctRvasSeen = static_cast<uint32_t>(cmpallrvas.size());
    r.CmpObserved = static_cast<uint32_t>(cmpperrva.size());

    std::vector<CmpRewriteRow> cmprewrites;
    cmprewrites.reserve(cmpperrva.size());
    std::vector<CmpDeferred> cmpdeferred;
    std::vector<CmpImmDeferred> cmpimmdeferred;
    std::vector<uint8_t> cmpsectioncontent;
    cmpsectioncontent.reserve(1024);

    std::vector<uint64_t> cmpsitervas;
    cmpsitervas.reserve(cmpperrva.size());
    for (const auto& [rva, t] : cmpperrva) cmpsitervas.push_back(rva);
    std::sort(cmpsitervas.begin(), cmpsitervas.end());

    for (uint64_t rva : cmpsitervas)
    {
        const CmpTally& t = cmpperrva.at(rva);
        const bool monopoly = (t.Values.size() == 1);
        if (monopoly) ++r.CmpMonopoly; else ++r.CmpMixed;

        CmpRewriteRow row{};
        row.Rva = rva;
        row.Mn = t.Mn;
        row.PreservedName = t.PreservedRegName;
        row.Slot = t.Length;
        row.NValues = static_cast<uint32_t>(t.Values.size());
        row.NHits = t.HitCount;
        if (t.IsRegReg)
        {
            std::strncpy(row.HiddenLabel, t.HiddenRegName, sizeof(row.HiddenLabel) - 1);
        }
        else
        {
            std::strncpy(row.HiddenLabel, "[mem]", sizeof(row.HiddenLabel) - 1);
        }

        if (monopoly && t.HasImmForm && t.PreservedRegId != 0xFF && t.FileOff < ctx.Buf.size())
        {
            const uint64_t val = *t.Values.begin();
            uint8_t scratch[32];
            const uint32_t p = DeobfEncoders::EncCmpRegImm(scratch, sizeof(scratch), t.PreservedRegId, t.Family, t.SlashDigit, t.TwoRegOpcode, val);
            if (p == 0)
            {
                // fall through
            }
            else if (p <= t.Length)
            {
                std::memcpy(ctx.Buf.data() + t.FileOff, scratch, p);
                for (uint32_t k = p; k < t.Length; ++k) ctx.Buf[t.FileOff + k] = 0x90;
                ++r.CmpRewriteImmOk;
                ++r.CmpRewriteImmInplace;
                r.CmpBytesPatched += t.Length;
                row.Path = CmpRewriteRow::Imm;
                row.EncLen = p;
                row.Consumed = t.Length;
                row.SingleValue = val;
                row.Ok = true;
                cmprewrites.push_back(row);
                continue;
            }
            else
            {
                row.Path = CmpRewriteRow::Imm;
                row.EncLen = p;
                row.SingleValue = val;
                row.ViaTramp = true;
                CmpImmDeferred di{};
                di.SiteFileOff = t.FileOff;
                di.SiteLen = t.Length;
                di.SiteRva = rva;
                di.Value = val;
                di.Reg = t.PreservedRegId;
                di.Family = t.Family;
                di.SlashDigit = t.SlashDigit;
                di.TwoRegOpcode = t.TwoRegOpcode;
                di.PayloadLen = p;
                di.RowIdx = cmprewrites.size();
                cmpimmdeferred.push_back(di);
                cmprewrites.push_back(row);
                continue;
            }
        }

        if (cmphaveheaderslack && t.PreservedRegId != 0xFF && t.FileOff < ctx.Buf.size())
        {
            const uint64_t sliceoff = cmpsectioncontent.size();
            const uint32_t targetrva = cmppredictedsectionrva + static_cast<uint32_t>(sliceoff);

            constexpr uint8_t  kleascratchreg = 0;
            constexpr uint32_t kleaenclen = 7;

            if (t.Length >= kleaenclen)
            {
                if (!DeobfEncoders::EmitLeaRegRipRel(ctx.Buf, t.FileOff, t.Length, kleascratchreg, targetrva, rva))
                {
                    ++r.CmpRewriteSkip;
                    row.Path = CmpRewriteRow::Lea;
                    row.TargetRva = targetrva;
                    row.Ok = false;
                    cmprewrites.push_back(row);
                    continue;
                }
                row.Consumed = t.Length;
            }
            else
            {
                row.ViaTramp = true;
            }

            std::vector<uint64_t> sortedvals(t.Values.begin(), t.Values.end());
            std::sort(sortedvals.begin(), sortedvals.end());
            for (uint64_t v : sortedvals)
            {
                uint8_t bytes[8];
                std::memcpy(bytes, &v, 8);
                cmpsectioncontent.insert(cmpsectioncontent.end(), bytes, bytes + 8);
            }

            row.Path = CmpRewriteRow::Lea;
            row.EncLen = kleaenclen;
            row.TargetRva = targetrva;
            if (!row.ViaTramp)
            {
                ++r.CmpRewriteLeaOk;
                r.CmpBytesPatched += t.Length;
                r.CmpValuesPacked += static_cast<uint32_t>(t.Values.size());
                row.Ok = true;
            }
            cmprewrites.push_back(row);
            if (row.ViaTramp)
            {
                CmpDeferred d{};
                d.SiteFileOff = t.FileOff;
                d.SiteLen = t.Length;
                d.SiteRva = rva;
                d.TargetRva = targetrva;
                d.RowIdx = cmprewrites.size() - 1;
                cmpdeferred.push_back(d);
            }
            continue;
        }

        ++r.CmpRewriteSkip;
        row.Path = CmpRewriteRow::Skip;
        cmprewrites.push_back(row);
    }

    if (!cmpsectioncontent.empty())
    {
        uint32_t appendedrva = 0;
        if (SectionManager::AppendPeSection(ctx.Buf, ".sophcmp", cmpsectioncontent, appendedrva))
        {
            if (appendedrva != cmppredictedsectionrva)
            {
                std::fprintf(stderr, "[deobf] compare-reveal: WARN predicted section RVA 0x%x doesn't match appended 0x%x -- rewrites may point at wrong bytes\n",
                    cmppredictedsectionrva, appendedrva);
            }
            r.CmpSectionRva = appendedrva;
            r.CmpSectionBytes = static_cast<uint32_t>(cmpsectioncontent.size());
            std::strncpy(r.CmpSectionName, ".sophcmp", sizeof(r.CmpSectionName) - 1);
        }
        else
        {
            std::fprintf(stderr, "[deobf] compare-reveal: AppendPeSection failed after slack check succeeded -- structural mismatch, dropping .sophcmp (rewrites already applied are stale)\n");
        }
    }

    if (!cmpdeferred.empty())
    {
        const HeaderSlackInfo cmplslack = DeobfEncoders::CheckHeaderSlack(ctx.Buf);
        if (!cmplslack.HaveSlack)
        {
            r.CmplTrampNoHeaderSlack = true;
            std::puts("[deobf]   no header slack for .sophcmpl -- deferred sub-7B LEA sites left with original bytes");
            for (const CmpDeferred& d : cmpdeferred)
            {
                CmpRewriteRow& rw = cmprewrites[d.RowIdx];
                rw.ViaTramp = false;
                rw.Ok = false;
                rw.Path = CmpRewriteRow::Skip;
                ++r.CmpRewriteSkip;
            }
        }
        else
        {
            TrampolineBuilder cmpltramp(ctx.Buf, ctx.Decoder, cmplslack.PredictedRva);
            for (const CmpDeferred& d : cmpdeferred)
            {
                CmpRewriteRow& rw = cmprewrites[d.RowIdx];
                const uint32_t tgt = d.TargetRva;
                const bool okt = cmpltramp.TryTrampoline(d.SiteFileOff, d.SiteLen, d.SiteRva, 7,
                    [tgt](uint8_t* out, uint32_t cap, uint64_t at)
                    {
                        return DeobfEncoders::EncLeaRipRel(out, cap, 0, tgt, at);
                    });
                if (okt)
                {
                    rw.Consumed = cmpltramp.Sites().back().Consumed;
                    rw.Ok = true;
                    ++r.CmpRewriteLeaOk;
                    r.CmpBytesPatched += rw.Consumed;
                    r.CmpValuesPacked += rw.NValues;
                }
                else
                {
                    rw.ViaTramp = false;
                    rw.Ok = false;
                    rw.Path = CmpRewriteRow::Skip;
                    ++r.CmpRewriteSkip;
                }
            }
            if (!cmpltramp.Blob().empty())
            {
                uint32_t appendedrva = 0;
                const uint32_t chars = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE;
                if (SectionManager::AppendPeSection(ctx.Buf, ".sophcmpl", cmpltramp.Blob(), appendedrva, chars))
                {
                    if (appendedrva != cmpltramp.PredictedSectionRva())
                    {
                        std::fprintf(stderr, "[deobf] compare-reveal: WARN predicted .sophcmpl RVA 0x%x != appended 0x%x\n",
                            cmpltramp.PredictedSectionRva(), appendedrva);
                    }
                    cmpltramp.EmitOutbounds();
                    r.CmplTrampSectionRva = appendedrva;
                    r.CmplTrampSectionBytes = static_cast<uint32_t>(cmpltramp.Blob().size());
                    r.CmplTrampBytesSaved = cmpltramp.BytesSaved();
                    r.CmplTrampSites = static_cast<uint32_t>(cmpltramp.Sites().size());
                    std::strncpy(r.CmplTrampSectionName, ".sophcmpl", sizeof(r.CmplTrampSectionName) - 1);
                }
                else
                {
                    std::fprintf(stderr, "[deobf] compare-reveal: AppendPeSection .sophcmpl FAILED -- %zu trampolined sites un-rewritten\n", cmpltramp.Sites().size());
                    r.CmpRewriteLeaOk -= static_cast<uint32_t>(cmpltramp.Sites().size());
                    r.CmpRewriteSkip += static_cast<uint32_t>(cmpltramp.Sites().size());
                    for (const CmpDeferred& d : cmpdeferred)
                    {
                        CmpRewriteRow& rw = cmprewrites[d.RowIdx];
                        if (rw.ViaTramp)
                        {
                            rw.ViaTramp = false;
                            rw.Ok = false;
                            rw.Path = CmpRewriteRow::Skip;
                        }
                    }
                }
            }
        }
    }

    if (!cmpimmdeferred.empty())
    {
        const HeaderSlackInfo cmpislack = DeobfEncoders::CheckHeaderSlack(ctx.Buf);
        if (!cmpislack.HaveSlack)
        {
            r.CmpiTrampNoHeaderSlack = true;
            std::puts("[deobf]   no header slack for .sophcmpi -- deferred oversize imm sites left with original bytes");
            for (const CmpImmDeferred& d : cmpimmdeferred)
            {
                CmpRewriteRow& rw = cmprewrites[d.RowIdx];
                rw.ViaTramp = false;
                rw.Ok = false;
                rw.Path = CmpRewriteRow::Skip;
                ++r.CmpRewriteSkip;
            }
        }
        else
        {
            TrampolineBuilder cmpitramp(ctx.Buf, ctx.Decoder, cmpislack.PredictedRva);
            for (const CmpImmDeferred& d : cmpimmdeferred)
            {
                CmpRewriteRow& rw = cmprewrites[d.RowIdx];
                const uint8_t      reg = d.Reg;
                const CmpEncFamily fam = d.Family;
                const uint8_t      sd = d.SlashDigit;
                const uint8_t      tro = d.TwoRegOpcode;
                const uint64_t     val = d.Value;
                const bool okt = cmpitramp.TryTrampoline(d.SiteFileOff, d.SiteLen, d.SiteRva, d.PayloadLen,
                    [reg, fam, sd, tro, val](uint8_t* out, uint32_t cap, uint64_t)
                    {
                        return DeobfEncoders::EncCmpRegImm(out, cap, reg, fam, sd, tro, val);
                    });
                if (okt)
                {
                    rw.Consumed = cmpitramp.Sites().back().Consumed;
                    rw.Ok = true;
                    ++r.CmpRewriteImmOk;
                    ++r.CmpRewriteImmTramp;
                    r.CmpBytesPatched += rw.Consumed;
                }
                else
                {
                    rw.ViaTramp = false;
                    rw.Ok = false;
                    rw.Path = CmpRewriteRow::Skip;
                    ++r.CmpRewriteSkip;
                }
            }
            if (!cmpitramp.Blob().empty())
            {
                uint32_t appendedrva = 0;
                const uint32_t chars = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE;
                if (SectionManager::AppendPeSection(ctx.Buf, ".sophcmpi", cmpitramp.Blob(), appendedrva, chars))
                {
                    if (appendedrva != cmpitramp.PredictedSectionRva())
                    {
                        std::fprintf(stderr, "[deobf] compare-reveal: WARN predicted .sophcmpi RVA 0x%x != appended 0x%x\n",
                            cmpitramp.PredictedSectionRva(), appendedrva);
                    }
                    cmpitramp.EmitOutbounds();
                    r.CmpiTrampSectionRva = appendedrva;
                    r.CmpiTrampSectionBytes = static_cast<uint32_t>(cmpitramp.Blob().size());
                    r.CmpiTrampBytesSaved = cmpitramp.BytesSaved();
                    r.CmpiTrampSites = static_cast<uint32_t>(cmpitramp.Sites().size());
                    std::strncpy(r.CmpiTrampSectionName, ".sophcmpi", sizeof(r.CmpiTrampSectionName) - 1);
                }
                else
                {
                    std::fprintf(stderr, "[deobf] compare-reveal: AppendPeSection .sophcmpi FAILED -- %zu trampolined sites un-rewritten\n", cmpitramp.Sites().size());
                    r.CmpRewriteImmOk -= static_cast<uint32_t>(cmpitramp.Sites().size());
                    r.CmpRewriteImmTramp = 0;
                    r.CmpRewriteSkip += static_cast<uint32_t>(cmpitramp.Sites().size());
                    for (const CmpImmDeferred& d : cmpimmdeferred)
                    {
                        CmpRewriteRow& rw = cmprewrites[d.RowIdx];
                        if (rw.ViaTramp)
                        {
                            rw.ViaTramp = false;
                            rw.Ok = false;
                            rw.Path = CmpRewriteRow::Skip;
                        }
                    }
                }
            }
        }
    }

    if (r.CmpSectionBytes > 0)
    {
        const std::filesystem::path cmpvalspath = ctx.Store->Dir() / L"cmpvals.txt";
        std::ofstream of(cmpvalspath, std::ios::trunc);
        if (of)
        {
            {
                char b[24];
                std::snprintf(b, sizeof(b), "%llx", static_cast<unsigned long long>(ctx.PreferredBase));
                of << b;
            }
            of << "\n\n";

            for (const CmpRewriteRow& rw : cmprewrites)
            {
                if (rw.Path != CmpRewriteRow::Lea || !rw.Ok) continue;
                auto it = cmpperrva.find(rw.Rva);
                if (it == cmpperrva.end()) continue;
                const CmpTally& t = it->second;

                const uint64_t sliceva = ctx.PreferredBase + static_cast<uint64_t>(rw.TargetRva);

                char head[320];
                std::snprintf(head, sizeof(head),
                    "site rva=0x%08llx  mn=%-6s  preserved=%-4s  hidden=%-10s  .sophcmp_va=0x%llx  n=%u  (%u hit(s))\n",
                    static_cast<unsigned long long>(rw.Rva),
                    rw.Mn && rw.Mn[0] ? rw.Mn : "?",
                    rw.PreservedName && rw.PreservedName[0] ? rw.PreservedName : "?",
                    rw.HiddenLabel[0] ? rw.HiddenLabel : "?",
                    static_cast<unsigned long long>(sliceva),
                    rw.NValues, rw.NHits);
                of << head;

                std::vector<uint64_t> sortedvals(t.Values.begin(), t.Values.end());
                std::sort(sortedvals.begin(), sortedvals.end());
                for (size_t i = 0; i < sortedvals.size(); ++i)
                {
                    char line[64];
                    std::snprintf(line, sizeof(line), "  [%3zu] 0x%llx\n", i, static_cast<unsigned long long>(sortedvals[i]));
                    of << line;
                }
                of << "\n";
            }
            r.CmpValsLogPath = cmpvalspath;
        }
    }

    if (!cmpperrva.empty())
    {
        const std::filesystem::path cmpcheckspath = ctx.Store->Dir() / L"cmpchecks.txt";
        std::ofstream of(cmpcheckspath, std::ios::trunc);
        if (of)
        {
            {
                char b[24];
                std::snprintf(b, sizeof(b), "%llx", static_cast<unsigned long long>(ctx.PreferredBase));
                of << b;
            }
            of << "\n\n";

            std::vector<uint64_t> sortedsites;
            sortedsites.reserve(cmpperrva.size());
            for (const auto& kv : cmpperrva) sortedsites.push_back(kv.first);
            std::sort(sortedsites.begin(), sortedsites.end());

            for (uint64_t rva : sortedsites)
            {
                const CmpTally& t = cmpperrva.at(rva);
                const uint64_t siteva = ctx.PreferredBase + rva;

                const char* mn = t.Mn[0] ? t.Mn : "?";
                const char* pres = t.PreservedRegName[0] ? t.PreservedRegName : "?";
                const char* hid = t.IsRegReg ? (t.HiddenRegName[0] ? t.HiddenRegName : "?") : "[mem]";
                const char* op0 = t.PreservedFirst ? pres : hid;
                const char* op1 = t.PreservedFirst ? hid : pres;
                const char* fam =
                    (t.Family == CmpEncFamily::AluCmp) ? "cmp" :
                    (t.Family == CmpEncFamily::AluTest) ? "test" :
                    (t.Family == CmpEncFamily::BitTest) ? "bt" : "?";

                char head[320];
                std::snprintf(head, sizeof(head),
                    "site va=0x%llx  rva=0x%08llx  %s %s, %s  family=%s  hits=%u  distinct_pairs=%zu  distinct_hidden=%zu\n",
                    static_cast<unsigned long long>(siteva),
                    static_cast<unsigned long long>(rva),
                    mn, op0, op1, fam,
                    t.HitCount, t.PairCounts.size(), t.Values.size());
                of << head;

                size_t idx = 0;
                for (const auto& kv : t.PairCounts)
                {
                    const uint64_t a = kv.first.first;
                    const uint64_t b = kv.first.second;
                    const uint32_t n = kv.second;

                    bool flagset = false;
                    switch (t.Family)
                    {
                    case CmpEncFamily::AluCmp:  flagset = (a == b); break;
                    case CmpEncFamily::AluTest: flagset = ((a & b) == 0); break;
                    case CmpEncFamily::BitTest: flagset = ((a >> (b & 63)) & 1ULL) != 0; break;
                    default: break;
                    }
                    const char* verdict = flagset ? "PASS" : "FAIL";
                    const char* meaning =
                        (t.Family == CmpEncFamily::AluCmp) ? (flagset ? "equal" : "not-equal") :
                        (t.Family == CmpEncFamily::AluTest) ? (flagset ? "zero" : "nonzero") :
                        (t.Family == CmpEncFamily::BitTest) ? (flagset ? "bit-set" : "bit-clear") : "?";

                    char line[256];
                    std::snprintf(line, sizeof(line),
                        "  [%3zu] preserved=0x%016llx  hidden=0x%016llx  hits=%-6u  -> %s (%s)\n",
                        idx++,
                        static_cast<unsigned long long>(a),
                        static_cast<unsigned long long>(b),
                        n, verdict, meaning);
                    of << line;
                }
                of << "\n";
            }
            r.CmpChecksLogPath = cmpcheckspath;
        }
    }

    DeobfIo::RuleOpen("compare-reveal");
    std::printf("[deobf]   CompareHit records read          : %llu\n", static_cast<unsigned long long>(r.CmpRecordsSeen));
    std::printf("[deobf]   distinct RVAs in compares.bin    : %u\n", r.CmpDistinctRvasSeen);
    std::printf("[deobf]   compare sites in scope           : %u\n", r.CmpObserved);
    {
        const uint32_t totaldrops = r.CmpDropSetcc + r.CmpDropCmpxchg + r.CmpDropAlreadyImm + r.CmpDropOther;
        std::printf("[deobf]   filtered out                     : %u\n", totaldrops);
        std::printf("[deobf]     already-imm (cmp reg, imm ..)  : %u\n", r.CmpDropAlreadyImm);
        std::printf("[deobf]     setcc                          : %u\n", r.CmpDropSetcc);
        std::printf("[deobf]     cmpxchg / cmpxchg8b / 16b      : %u\n", r.CmpDropCmpxchg);
        std::printf("[deobf]     other (decode / shape / regid) : %u\n", r.CmpDropOther);
    }
    std::printf("[deobf]   monopoly (single hidden value)   : %u\n", r.CmpMonopoly);
    std::printf("[deobf]   mixed (2+ hidden values)         : %u\n", r.CmpMixed);
    std::printf("[deobf]   rewritten via `<mn> reg, imm`    : %u\n", r.CmpRewriteImmOk);
    std::printf("[deobf]   rewritten via LEA -> .sophcmp    : %u\n", r.CmpRewriteLeaOk);
    std::printf("[deobf]   skipped                          : %u\n", r.CmpRewriteSkip);
    std::printf("[deobf]   bytes patched (orig slot sum)    : %llu\n", static_cast<unsigned long long>(r.CmpBytesPatched));
    if (r.CmpNoHeaderSlack)
    {
        std::puts("[deobf]   NOTE: no header slack -- LEA-into-.sophcmp path disabled, only monopoly-imm rewrites ran.");
    }
    if (r.CmpSectionBytes)
    {
        std::printf("[deobf]   .sophcmp section RVA             : 0x%llx\n", static_cast<unsigned long long>(r.CmpSectionRva));
        std::printf("[deobf]   .sophcmp section bytes           : %u\n", r.CmpSectionBytes);
        std::printf("[deobf]   values packed (qwords)           : %u\n", r.CmpValuesPacked);
    }
    std::printf("[deobf]   sub-7B LEA sites trampolined     : %u\n", r.CmplTrampSites);
    if (r.CmplTrampNoHeaderSlack)
    {
        std::puts("[deobf]   NOTE .sophcmpl disabled          : no header slack");
    }
    if (r.CmplTrampSectionBytes)
    {
        std::printf("[deobf]   .sophcmpl section RVA            : 0x%llx\n", static_cast<unsigned long long>(r.CmplTrampSectionRva));
        std::printf("[deobf]   .sophcmpl section bytes          : %u\n", r.CmplTrampSectionBytes);
        std::printf("[deobf]   bytes NOT corrupted downstream   : %llu\n", static_cast<unsigned long long>(r.CmplTrampBytesSaved));
    }
    std::printf("[deobf]   imm-path in-place                : %u\n", r.CmpRewriteImmInplace);
    std::printf("[deobf]   oversize imm sites trampolined   : %u\n", r.CmpiTrampSites);
    if (r.CmpiTrampNoHeaderSlack)
    {
        std::puts("[deobf]   NOTE .sophcmpi disabled          : no header slack");
    }
    if (r.CmpiTrampSectionBytes)
    {
        std::printf("[deobf]   .sophcmpi section RVA            : 0x%llx\n", static_cast<unsigned long long>(r.CmpiTrampSectionRva));
        std::printf("[deobf]   .sophcmpi section bytes          : %u\n", r.CmpiTrampSectionBytes);
        std::printf("[deobf]   bytes NOT corrupted downstream   : %llu\n", static_cast<unsigned long long>(r.CmpiTrampBytesSaved));
    }
    if (!r.CmpValsLogPath.empty())
    {
        std::printf("[deobf]   cmpvals log                      : %ls\n", r.CmpValsLogPath.wstring().c_str());
    }
    if (!r.CmpChecksLogPath.empty())
    {
        std::printf("[deobf]   cmpchecks log                    : %ls\n", r.CmpChecksLogPath.wstring().c_str());
    }
    if (!cmprewrites.empty())
    {
        std::printf("[deobf] cmp rewrite log (all %zu site(s)):\n", cmprewrites.size());
        for (const CmpRewriteRow& rw : cmprewrites)
        {
            const char* dst = rw.PreservedName[0] ? rw.PreservedName : "?";
            const char* hid = rw.HiddenLabel[0] ? rw.HiddenLabel : "?";
            if (rw.Path == CmpRewriteRow::Imm)
            {
                const char* tramp = rw.ViaTramp ? " TRAMP .sophcmpi" : "";
                std::printf("[deobf]   rva=0x%08llx  %-6s  slot=%u consumed=%u enc=%-2u%s  -> %s %s, 0x%llx  (from %s, %u hit(s)/%u val(s))\n",
                    static_cast<unsigned long long>(rw.Rva),
                    rw.Mn, rw.Slot, rw.Consumed, rw.EncLen, tramp,
                    rw.Mn, dst,
                    static_cast<unsigned long long>(rw.SingleValue),
                    hid, rw.NHits, rw.NValues);
            }
            else if (rw.Path == CmpRewriteRow::Lea && rw.Ok)
            {
                const char* tramp = rw.ViaTramp ? " TRAMP .sophcmpl" : "";
                std::printf("[deobf]   rva=0x%08llx  %-6s  slot=%u consumed=%u enc=7%s  -> lea rax, [0x%x]  (from %s, %u hit(s)/%u val(s))\n",
                    static_cast<unsigned long long>(rw.Rva),
                    rw.Mn, rw.Slot, rw.Consumed, tramp, rw.TargetRva,
                    hid, rw.NHits, rw.NValues);
            }
            else
            {
                std::printf("[deobf]   rva=0x%08llx  %-6s  slot=%u  SKIPPED (from %s, %u hit(s)/%u val(s))\n",
                    static_cast<unsigned long long>(rw.Rva),
                    rw.Mn, rw.Slot, hid, rw.NHits, rw.NValues);
            }
        }
    }
    DeobfIo::RuleClose();
}