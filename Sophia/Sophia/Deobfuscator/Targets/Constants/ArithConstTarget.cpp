#include "../../../../Pch.h"
#include "ArithConstTarget.h"
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
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace
{
    struct ArithTally
    {
        std::unordered_set<uint64_t> Values;
        uint32_t                     Length = 0;
        uint64_t                     FileOff = 0;
        uint8_t                      DstRegId = 0xFF;
        ArithEncFamily               Family = ArithEncFamily::Alu81;
        uint8_t                      SlashDigit = 0xFF;
        uint8_t                      TwoRegOpcode = 0;
        bool                         SrcIsReg = false;
        char                         DstName[8] = {};
        char                         SrcName[8] = {};
        char                         Mn[16] = {};
    };

    struct ArithRewriteRow
    {
        uint64_t    Rva;
        const char* Mn;
        const char* DstName;
        const char* SrcName;
        uint32_t    Slot;
        uint32_t    EncLen;
        uint64_t    Value;
        bool        SrcIsReg;
        bool        Ok;
        bool        ViaTramp;
        uint32_t    Consumed;
        bool        IsMixed;
        uint32_t    ListTargetRva;
        uint32_t    NValues;
        const std::unordered_set<uint64_t>* ObservedValues;
    };

    struct AriMonoDefer
    {
        uint64_t FileOff, SiteRva;
        uint32_t SiteLen;
        uint8_t  RegId;
        ArithEncFamily Family;
        uint8_t  SlashDigit, TwoRegOpcode;
        uint64_t Value;
        uint32_t PayloadLen;
        size_t   RowIdx;
    };

    struct AriMixedDefer
    {
        uint64_t FileOff, SiteRva;
        uint32_t SiteLen, TargetRva;
        size_t   RowIdx;
    };

    void PrintSummary(const Deobfuscator::Report& r, const std::vector<ArithRewriteRow>& rewrites)
    {
        DeobfIo::RuleOpen("Constant Arith -- resolution");
        std::printf("[deobf]   ArithHit records read          : %llu\n", static_cast<unsigned long long>(r.ArithRecordsSeen));
        std::printf("[deobf]   rewritable-shape sites observed: %u\n", r.ArithObserved);
        std::printf("[deobf]   monopoly (candidate)           : %u\n", r.ArithMonopoly);
        std::printf("[deobf]   mixed (candidate)              : %u\n", r.ArithMixed);
        std::printf("[deobf]   monopoly rewritten             : %u\n", r.ArithRewriteOk);
        std::printf("[deobf]     in-place                     : %u\n", r.ArithRewriteInplace);
        std::printf("[deobf]     trampoline via .sophari      : %u\n", r.ArithRewriteTramp);
        std::printf("[deobf]   monopoly skipped               : %u\n", r.ArithRewriteSkip);
        std::printf("[deobf]   mixed rewritten (LEA -> list)  : %u\n", r.ArithMixedListOk);
        std::printf("[deobf]     in-place                     : %u\n", r.ArithMixedListInplace);
        std::printf("[deobf]     trampoline via .sophari      : %u\n", r.ArithMixedListTramp);
        std::printf("[deobf]   mixed skipped                  : %u\n", r.ArithMixedListSkip);
        if (r.ArithNoHeaderSlack)
        {
            std::puts("[deobf]   NOTE                           : no header slack for .sophari");
        }
        if (r.ArithNoListHeaderSlack)
        {
            std::puts("[deobf]   NOTE                           : no header slack for .sophariL");
        }
        std::printf("[deobf]   bytes patched (site sum)       : %llu\n", static_cast<unsigned long long>(r.ArithBytesPatched));
        std::printf("[deobf]   bytes NOT corrupted downstream : %llu\n", static_cast<unsigned long long>(r.ArithTrampBytesSaved));
        if (r.ArithListSectionBytes)
        {
            std::printf("[deobf]   .sophariL section RVA          : 0x%llx\n", static_cast<unsigned long long>(r.ArithListSectionRva));
            std::printf("[deobf]   .sophariL section bytes        : %u\n", r.ArithListSectionBytes);
            std::printf("[deobf]   .sophariL values packed        : %u\n", r.ArithListValuesPacked);
        }
        if (r.ArithTrampSectionBytes)
        {
            std::printf("[deobf]   .sophari section RVA           : 0x%llx\n", static_cast<unsigned long long>(r.ArithTrampSectionRva));
            std::printf("[deobf]   .sophari section bytes         : %u\n", r.ArithTrampSectionBytes);
        }
        if (!r.ArithValsLogPath.empty())
        {
            std::printf("[deobf]   arithvals log                  : %ls\n", r.ArithValsLogPath.wstring().c_str());
        }

        if (!rewrites.empty())
        {
            std::printf("[deobf] arith rewrite log (all %zu site(s)):\n", rewrites.size());
            for (const ArithRewriteRow& rw : rewrites)
            {
                const char* src = rw.SrcName[0] ? rw.SrcName : "?";
                const char* dst = rw.DstName[0] ? rw.DstName : "?";
                if (!rw.Ok)
                {
                    std::printf("[deobf]   rva=0x%08llx  %-3s  slot=%u  SKIPPED (from %s, %s)\n",
                        static_cast<unsigned long long>(rw.Rva), rw.Mn, rw.Slot, src, rw.IsMixed ? "mixed" : "monopoly");
                }
                else if (rw.IsMixed)
                {
                    const char* tramp = rw.ViaTramp ? " TRAMP .sophari" : "";
                    std::printf("[deobf]   rva=0x%08llx  %-3s  slot=%u consumed=%u%s  -> lea rax, [0x%x]  (%u vals) (from %s)\n",
                        static_cast<unsigned long long>(rw.Rva), rw.Mn, rw.Slot, rw.Consumed, tramp,
                        rw.ListTargetRva, rw.NValues, src);
                }
                else if (rw.EncLen == 13)
                {
                    const char* scratch = (rw.DstName[0] && std::strcmp(rw.DstName, "rax") == 0) ? "rcx" : "rax";
                    const char* tramp = rw.ViaTramp ? " TRAMP" : "";
                    std::printf("[deobf]   rva=0x%08llx  %-3s  slot=%u consumed=%u enc=13%s  -> movabs %s, 0x%llx; %s %s, %s  (from %s)\n",
                        static_cast<unsigned long long>(rw.Rva), rw.Mn, rw.Slot, rw.Consumed, tramp,
                        scratch, static_cast<unsigned long long>(rw.Value),
                        rw.Mn, dst, scratch, src);
                }
                else
                {
                    const char* tramp = rw.ViaTramp ? " TRAMP" : "";
                    std::printf("[deobf]   rva=0x%08llx  %-3s  slot=%u consumed=%u enc=%-2u%s -> %s %s, 0x%llx  (from %s)\n",
                        static_cast<unsigned long long>(rw.Rva), rw.Mn, rw.Slot, rw.Consumed, rw.EncLen, tramp,
                        rw.Mn, dst, static_cast<unsigned long long>(rw.Value), src);
                }
            }
        }
        DeobfIo::RuleClose();
    }

    void WriteArithValsSidecar(const std::filesystem::path& dir, const std::vector<ArithRewriteRow>& rewrites, uint64_t bufmodedelta, Deobfuscator::Report& r)
    {
        const std::filesystem::path arithvalspath = dir / L"arithvals.txt";
        std::ofstream of(arithvalspath, std::ios::trunc);
        if (!of)
        {
            std::fprintf(stderr, "[deobf] Constant Airth: could not open %ls for write\n", arithvalspath.wstring().c_str());
            return;
        }
        std::vector<const ArithRewriteRow*> mixedrows;
        for (const ArithRewriteRow& rw : rewrites)
        {
            if (rw.IsMixed && rw.Ok) mixedrows.push_back(&rw);
        }
        std::sort(mixedrows.begin(), mixedrows.end(),
            [](const ArithRewriteRow* a, const ArithRewriteRow* b) { return a->Rva < b->Rva; });
        for (const ArithRewriteRow* rw : mixedrows)
        {
            const uint64_t siteva = bufmodedelta + rw->Rva;
            const uint64_t sliceva = bufmodedelta + rw->ListTargetRva;
            std::vector<uint64_t> vals(rw->ObservedValues->begin(), rw->ObservedValues->end());
            std::sort(vals.begin(), vals.end());
            const uint64_t sliceend = sliceva + vals.size() * 8;
            of << "Site VA: 0x" << std::hex << siteva
                << "  RVA 0x" << rw->Rva
                << "  " << rw->Mn
                << "  dst=" << (rw->DstName[0] ? rw->DstName : "?")
                << "  from=" << (rw->SrcName[0] ? rw->SrcName : "?") << "\n";
            of << "Slice VA: 0x" << sliceva << " - 0x" << sliceend
                << "  (" << std::dec << vals.size() << " qword"
                << (vals.size() == 1 ? "" : "s") << ")\n";
            for (size_t i = 0; i < vals.size(); ++i)
            {
                of << "  [" << std::dec << i << "] 0x" << std::hex << vals[i] << "\n";
            }
            of << std::dec << "\n";
        }
        r.ArithValsLogPath = arithvalspath;
    }
}

void ArithConstTarget::Deobfuscate(DeobfContext& ctx, Deobfuscator::Report& r)
{
    std::unordered_map<uint64_t, ArithTally> arithperrva;

    ctx.Store->ForEachRecord(ObsKind::Arith,
        [&](const void* rec, size_t sz)
        {
            ++r.ArithRecordsSeen;
            if (sz != sizeof(ArithHit)) return;
            const ArithHit* h = static_cast<const ArithHit*>(rec);

            auto pit = arithperrva.find(h->Rva);
            ArithTally* tp = nullptr;
            if (pit != arithperrva.end())
            {
                tp = &pit->second;
            }
            else
            {
                const uint64_t off = ctx.Sm.RvaToOffset(h->Rva);
                if (off == UINT64_MAX) return;
                size_t avail = ctx.PreMovRewriteBuf.size() - off;
                if (avail > 15) avail = 15;
                ZydisDecodedInstruction insn;
                ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
                if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&ctx.Decoder, ctx.PreMovRewriteBuf.data() + off, avail, &insn, ops)))
                {
                    return;
                }

                const char* mstr = ZydisMnemonicGetString(insn.mnemonic);
                ArithEncFamily family = ArithEncFamily::Alu81;
                uint8_t slashdigit = 0, tworegopcode = 0;
                if (!mstr || !DeobfEncoders::ArithEncoderInfo(mstr, family, slashdigit, tworegopcode))
                {
                    return;
                }

                if (insn.operand_count_visible < 2) return;
                if (ops[0].type != ZYDIS_OPERAND_TYPE_REGISTER) return;
                bool hasimm = false;
                for (int i = 0; i < insn.operand_count_visible; ++i)
                {
                    if (ops[i].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) hasimm = true;
                }
                if (hasimm) return;

                bool srcisreg;
                if (ops[1].type == ZYDIS_OPERAND_TYPE_REGISTER) srcisreg = true;
                else if (ops[1].type == ZYDIS_OPERAND_TYPE_MEMORY) srcisreg = false;
                else return;

                ArithTally fresh;
                fresh.Length = insn.length;
                fresh.FileOff = off;
                fresh.SrcIsReg = srcisreg;
                fresh.Family = family;
                fresh.SlashDigit = slashdigit;
                fresh.TwoRegOpcode = tworegopcode;

                ZydisRegister big = ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, ops[0].reg.value);
                if (big == ZYDIS_REGISTER_NONE) return;
                ZyanI8 id = ZydisRegisterGetId(big);
                if (id < 0 || id > 15) return;
                fresh.DstRegId = static_cast<uint8_t>(id);
                const char* rn = ZydisRegisterGetString(big);
                if (rn) std::strncpy(fresh.DstName, rn, sizeof(fresh.DstName) - 1);

                if (srcisreg)
                {
                    ZydisRegister big2 = ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, ops[1].reg.value);
                    const char* rn2 = ZydisRegisterGetString(big2 != ZYDIS_REGISTER_NONE ? big2 : ops[1].reg.value);
                    if (rn2) std::strncpy(fresh.SrcName, rn2, sizeof(fresh.SrcName) - 1);
                }
                else
                {
                    std::strncpy(fresh.SrcName, "[mem]", sizeof(fresh.SrcName) - 1);
                }

                std::strncpy(fresh.Mn, mstr, sizeof(fresh.Mn) - 1);
                auto ins = arithperrva.emplace(h->Rva, fresh);
                tp = &ins.first->second;
            }

            uint64_t val = tp->SrcIsReg ? h->Rval2 : h->Mval;
            if (tp->Family == ArithEncFamily::Shift) val &= 0xFF;
            tp->Values.insert(val);
        });

    r.ArithObserved = static_cast<uint32_t>(arithperrva.size());

    const HeaderSlackInfo arilistslack = DeobfEncoders::CheckHeaderSlack(ctx.Buf);
    if (!ctx.Cfg.WantAriList || !arilistslack.HaveSlack)
    {
        r.ArithNoListHeaderSlack = true;
    }
    std::vector<uint8_t> arilistcontent;
    arilistcontent.reserve(512);
    const uint32_t arilistpredictedrva = arilistslack.PredictedRva;

    std::vector<ArithRewriteRow> arithrewrites;
    arithrewrites.reserve(arithperrva.size());
    std::vector<AriMonoDefer> arimonodefer;
    std::vector<AriMixedDefer> arimixeddefer;

    for (const auto& [rva, t] : arithperrva)
    {
        const bool monopoly = (t.Values.size() == 1);
        if (monopoly) ++r.ArithMonopoly; else ++r.ArithMixed;

        if (monopoly)
        {
            const uint64_t val = *t.Values.begin();
            ArithRewriteRow row{ rva, t.Mn, t.DstName, t.SrcName, t.Length, 0, val, t.SrcIsReg, false, false, t.Length, false, 0, 1, nullptr };
            if (t.DstRegId == 0xFF || t.FileOff >= ctx.Buf.size())
            {
                ++r.ArithRewriteSkip;
                arithrewrites.push_back(row);
                continue;
            }
            uint8_t scratch[32];
            const uint32_t p = DeobfEncoders::EncArithRegImm(scratch, sizeof(scratch), t.DstRegId, t.Family, t.SlashDigit, t.TwoRegOpcode, val);
            if (p == 0)
            {
                ++r.ArithRewriteSkip;
                arithrewrites.push_back(row);
                continue;
            }
            row.EncLen = p;
            if (p <= t.Length)
            {
                std::memcpy(ctx.Buf.data() + t.FileOff, scratch, p);
                for (uint32_t k = p; k < t.Length; ++k) ctx.Buf[t.FileOff + k] = 0x90;
                ++r.ArithRewriteOk;
                ++r.ArithRewriteInplace;
                r.ArithBytesPatched += t.Length;
                row.Ok = true;
                arithrewrites.push_back(row);
                continue;
            }
            arithrewrites.push_back(row);
            AriMonoDefer d{};
            d.FileOff = t.FileOff; d.SiteRva = rva; d.SiteLen = t.Length;
            d.RegId = t.DstRegId; d.Family = t.Family;
            d.SlashDigit = t.SlashDigit; d.TwoRegOpcode = t.TwoRegOpcode;
            d.Value = val; d.PayloadLen = p;
            d.RowIdx = arithrewrites.size() - 1;
            arimonodefer.push_back(d);
            continue;
        }

        ArithRewriteRow row{ rva, t.Mn, t.DstName, t.SrcName, t.Length, 7, 0, t.SrcIsReg, false, false, t.Length, true, 0, static_cast<uint32_t>(t.Values.size()), &t.Values };

        if (t.DstRegId == 0xFF || t.FileOff >= ctx.Buf.size() || !arilistslack.HaveSlack)
        {
            ++r.ArithMixedListSkip;
            arithrewrites.push_back(row);
            continue;
        }

        const uint32_t sliceoff = static_cast<uint32_t>(arilistcontent.size());
        const uint32_t targetrva = arilistpredictedrva + sliceoff;
        std::vector<uint64_t> sortedvals(t.Values.begin(), t.Values.end());
        std::sort(sortedvals.begin(), sortedvals.end());
        for (uint64_t v : sortedvals)
        {
            uint8_t bytes[8];
            std::memcpy(bytes, &v, 8);
            arilistcontent.insert(arilistcontent.end(), bytes, bytes + 8);
        }
        row.ListTargetRva = targetrva;
        r.ArithListValuesPacked += static_cast<uint32_t>(sortedvals.size());

        constexpr uint32_t kleaenclen = 7;
        if (t.Length >= kleaenclen)
        {
            if (!DeobfEncoders::EmitLeaRegRipRel(ctx.Buf, t.FileOff, t.Length, 0, targetrva, rva))
            {
                ++r.ArithMixedListSkip;
                arithrewrites.push_back(row);
                continue;
            }
            r.ArithBytesPatched += t.Length;
            ++r.ArithMixedListOk;
            ++r.ArithMixedListInplace;
            row.Ok = true;
            arithrewrites.push_back(row);
            continue;
        }

        arithrewrites.push_back(row);
        AriMixedDefer d{};
        d.FileOff = t.FileOff; d.SiteRva = rva; d.SiteLen = t.Length;
        d.TargetRva = targetrva;
        d.RowIdx = arithrewrites.size() - 1;
        arimixeddefer.push_back(d);
    }

    if (!arilistcontent.empty())
    {
        uint32_t appendedrva = 0;
        if (SectionManager::AppendPeSection(ctx.Buf, ".sophariL", arilistcontent, appendedrva))
        {
            if (appendedrva != arilistpredictedrva)
            {
                std::fprintf(stderr, "[deobf] Constant Arith: WARN predicted .sophariL RVA 0x%x != appended 0x%x\n", arilistpredictedrva, appendedrva);
            }
            r.ArithListSectionRva = appendedrva;
            r.ArithListSectionBytes = static_cast<uint32_t>(arilistcontent.size());
            std::strncpy(r.ArithListSectionName, ".sophariL", sizeof(r.ArithListSectionName) - 1);
        }
        else
        {
            std::fprintf(stderr, "[deobf] Constant Arith: AppendPeSection .sophariL FAILED -- mixed list rewrites rolled back\n");
            const uint32_t okback = r.ArithMixedListOk;
            r.ArithMixedListSkip += okback;
            r.ArithMixedListOk = 0;
            r.ArithMixedListInplace = 0;
            r.ArithListValuesPacked = 0;
            for (ArithRewriteRow& rw : arithrewrites)
            {
                if (rw.IsMixed && rw.Ok) rw.Ok = false;
            }
            arimixeddefer.clear();
        }
    }

    if (!arimonodefer.empty() || !arimixeddefer.empty())
    {
        const HeaderSlackInfo arislack = DeobfEncoders::CheckHeaderSlack(ctx.Buf);
        if (!arislack.HaveSlack)
        {
            r.ArithNoHeaderSlack = true;
            for (const AriMonoDefer& d : arimonodefer)
            {
                arithrewrites[d.RowIdx].Ok = false;
                ++r.ArithRewriteSkip;
            }
            for (const AriMixedDefer& d : arimixeddefer)
            {
                arithrewrites[d.RowIdx].Ok = false;
                ++r.ArithMixedListSkip;
            }
        }
        else
        {
            TrampolineBuilder aritramp(ctx.Buf, ctx.Decoder, arislack.PredictedRva);
            for (const AriMonoDefer& d : arimonodefer)
            {
                const uint8_t regid = d.RegId;
                const ArithEncFamily family = d.Family;
                const uint8_t sd = d.SlashDigit;
                const uint8_t tro = d.TwoRegOpcode;
                const uint64_t value = d.Value;
                const bool okt = aritramp.TryTrampoline(d.FileOff, d.SiteLen, d.SiteRva, d.PayloadLen,
                    [regid, family, sd, tro, value](uint8_t* out, uint32_t cap, uint64_t)
                    {
                        return DeobfEncoders::EncArithRegImm(out, cap, regid, family, sd, tro, value);
                    });
                if (okt)
                {
                    const auto& sr = aritramp.Sites().back();
                    ArithRewriteRow& rw = arithrewrites[d.RowIdx];
                    rw.Consumed = sr.Consumed;
                    rw.ViaTramp = true;
                    rw.Ok = true;
                    ++r.ArithRewriteOk;
                    ++r.ArithRewriteTramp;
                    r.ArithBytesPatched += sr.Consumed;
                }
                else
                {
                    ++r.ArithRewriteSkip;
                }
            }
            for (const AriMixedDefer& d : arimixeddefer)
            {
                const uint32_t tgt = d.TargetRva;
                const bool okt = aritramp.TryTrampoline(d.FileOff, d.SiteLen, d.SiteRva, 7,
                    [tgt](uint8_t* out, uint32_t cap, uint64_t at)
                    {
                        return DeobfEncoders::EncLeaRipRel(out, cap, 0, tgt, at);
                    });
                if (okt)
                {
                    const auto& sr = aritramp.Sites().back();
                    ArithRewriteRow& rw = arithrewrites[d.RowIdx];
                    rw.Consumed = sr.Consumed;
                    rw.ViaTramp = true;
                    rw.Ok = true;
                    ++r.ArithMixedListOk;
                    ++r.ArithMixedListTramp;
                    r.ArithBytesPatched += sr.Consumed;
                }
                else
                {
                    ++r.ArithMixedListSkip;
                }
            }
            if (!aritramp.Blob().empty())
            {
                uint32_t appendedrva = 0;
                const uint32_t chars = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE;
                if (SectionManager::AppendPeSection(ctx.Buf, ".sophari", aritramp.Blob(), appendedrva, chars))
                {
                    if (appendedrva != aritramp.PredictedSectionRva())
                    {
                        std::fprintf(stderr, "[deobf] Constant Arith: WARN predicted .sophari RVA 0x%x != appended 0x%x\n",
                            aritramp.PredictedSectionRva(), appendedrva);
                    }
                    aritramp.EmitOutbounds();
                    r.ArithTrampSectionRva = appendedrva;
                    r.ArithTrampSectionBytes = static_cast<uint32_t>(aritramp.Blob().size());
                    r.ArithTrampBytesSaved = aritramp.BytesSaved();
                    std::strncpy(r.ArithTrampSectionName, ".sophari", sizeof(r.ArithTrampSectionName) - 1);
                }
                else
                {
                    std::fprintf(stderr, "[deobf] Constant Arith: AppendPeSection .sophari FAILED -- %u monopoly + %u mixed sites un-rewritten\n",
                        r.ArithRewriteTramp, r.ArithMixedListTramp);
                    r.ArithRewriteOk -= r.ArithRewriteTramp;
                    r.ArithRewriteSkip += r.ArithRewriteTramp;
                    r.ArithMixedListOk -= r.ArithMixedListTramp;
                    r.ArithMixedListSkip += r.ArithMixedListTramp;
                    for (ArithRewriteRow& rw : arithrewrites)
                    {
                        if (rw.ViaTramp) rw.Ok = false;
                    }
                    r.ArithRewriteTramp = 0;
                    r.ArithMixedListTramp = 0;
                }
            }
        }
    }

    if (r.ArithListSectionBytes > 0)
    {
        WriteArithValsSidecar(ctx.Store->Dir(), arithrewrites, r.BufModeDelta, r);
    }

    std::sort(arithrewrites.begin(), arithrewrites.end(),
        [](const ArithRewriteRow& a, const ArithRewriteRow& b) { return a.Rva < b.Rva; });

    PrintSummary(r, arithrewrites);
}