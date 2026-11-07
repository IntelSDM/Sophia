#include "../../../../Pch.h"
#include "MovConstTarget.h"
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
    struct MovTally
    {
        std::unordered_set<uint64_t> Values;
        uint32_t                     Length = 0;
        uint64_t                     FileOff = 0;
        uint8_t                      RegId = 0xFF;
        bool                         IsLoad = false;
        char                         RegName[8] = {};
        char                         Mn[16] = {};
    };

    struct MovRewriteRow
    {
        uint64_t    Rva;
        const char* Mn;
        const char* RegName;
        uint32_t    Slot;
        uint64_t    Value;
        bool        IsLoad;
        bool        Ok;
        bool        ViaTramp;
        uint32_t    EncLen;
        uint32_t    Consumed;
        bool        IsMixed;
        uint32_t    ListTargetRva;
        uint32_t    NValues;
        const std::unordered_set<uint64_t>* ObservedValues;
    };

    struct MonoTrampDefer
    {
        uint64_t FileOff;
        uint64_t SiteRva;
        uint32_t SiteLen;
        uint8_t  RegId;
        uint64_t Value;
        uint32_t PayloadLen;
        size_t   RowIdx;
    };

    struct MixedListDefer
    {
        uint64_t FileOff;
        uint64_t SiteRva;
        uint32_t SiteLen;
        uint32_t TargetRva;
        size_t   RowIdx;
    };

    void PrintSummary(const Deobfuscator::Report& r, const std::vector<MovRewriteRow>& movrewrites)
    {
        DeobfIo::RuleOpen("mov-const -- resolution");
        std::printf("[deobf]   MovHit records read            : %llu\n", static_cast<unsigned long long>(r.MovRecordsSeen));
        std::printf("[deobf]   mov sites observed             : %u\n", r.MovObserved);
        std::printf("[deobf]   monopoly (candidate)           : %u\n", r.MovMonopoly);
        std::printf("[deobf]   mixed (candidate)              : %u\n", r.MovMixed);
        std::printf("[deobf]   monopoly rewritten             : %u\n", r.MovRewriteOk);
        std::printf("[deobf]     in-place                     : %u\n", r.MovRewriteInplace);
        std::printf("[deobf]     trampoline via .sophmov      : %u\n", r.MovRewriteTramp);
        std::printf("[deobf]   monopoly skipped               : %u\n", r.MovRewriteSkip);
        std::printf("[deobf]   mixed rewritten (LEA -> list)  : %u\n", r.MovMixedListOk);
        std::printf("[deobf]     in-place                     : %u\n", r.MovMixedListInplace);
        std::printf("[deobf]     trampoline via .sophmov      : %u\n", r.MovMixedListTramp);
        std::printf("[deobf]   mixed skipped                  : %u\n", r.MovMixedListSkip);
        if (r.MovNoHeaderSlack)
        {
            std::puts("[deobf]   NOTE                           : no header slack -> oversized monopoly + sub-7B mixed all skipped");
        }
        if (r.MovNoListHeaderSlack)
        {
            std::puts("[deobf]   NOTE                           : no header slack for .sophmovL -> all mixed skipped");
        }
        std::printf("[deobf]   bytes patched (site sum)       : %llu\n", static_cast<unsigned long long>(r.MovBytesPatched));
        std::printf("[deobf]   bytes NOT corrupted downstream : %llu\n", static_cast<unsigned long long>(r.MovTrampBytesSaved));
        if (r.MovListSectionBytes)
        {
            std::printf("[deobf]   .sophmovL section RVA          : 0x%llx\n", static_cast<unsigned long long>(r.MovListSectionRva));
            std::printf("[deobf]   .sophmovL section bytes        : %u\n", r.MovListSectionBytes);
            std::printf("[deobf]   .sophmovL values packed        : %u\n", r.MovListValuesPacked);
        }
        if (r.MovTrampSectionBytes)
        {
            std::printf("[deobf]   .sophmov section RVA           : 0x%llx\n", static_cast<unsigned long long>(r.MovTrampSectionRva));
            std::printf("[deobf]   .sophmov section bytes         : %u\n", r.MovTrampSectionBytes);
        }
        if (!r.MovValsLogPath.empty())
        {
            std::printf("[deobf]   movvals log                    : %ls\n", r.MovValsLogPath.wstring().c_str());
        }

        if (!movrewrites.empty())
        {
            std::printf("[deobf] mov rewrite log (all %zu site(s)):\n", movrewrites.size());
            for (const MovRewriteRow& rw : movrewrites)
            {
                const char* dir = rw.IsLoad ? "ld" : "st";
                if (!rw.Ok)
                {
                    std::printf("[deobf]   rva=0x%08llx  %-6s  %s  slot=%u  SKIPPED (reg=%s enc=%u %s)\n",
                        static_cast<unsigned long long>(rw.Rva),
                        rw.Mn, dir, rw.Slot,
                        rw.RegName[0] ? rw.RegName : "?", rw.EncLen,
                        rw.IsMixed ? "mixed" : "monopoly");
                }
                else if (rw.IsMixed)
                {
                    const char* tramp = rw.ViaTramp ? " TRAMP .sophmov" : "";
                    std::printf("[deobf]   rva=0x%08llx  %-6s  %s  slot=%u consumed=%u%s  -> lea rax, [0x%x]  (%u vals)\n",
                        static_cast<unsigned long long>(rw.Rva),
                        rw.Mn, dir, rw.Slot, rw.Consumed, tramp,
                        rw.ListTargetRva, rw.NValues);
                }
                else if (rw.ViaTramp)
                {
                    std::printf("[deobf]   rva=0x%08llx  %-6s  %s  slot=%u  consumed=%u  enc=%u  -> TRAMP .sophmov  (mov %s, 0x%llx)\n",
                        static_cast<unsigned long long>(rw.Rva),
                        rw.Mn, dir, rw.Slot, rw.Consumed, rw.EncLen,
                        rw.RegName[0] ? rw.RegName : "?",
                        static_cast<unsigned long long>(rw.Value));
                }
                else
                {
                    std::printf("[deobf]   rva=0x%08llx  %-6s  %s  slot=%u  enc=%u  -> mov %s, 0x%llx\n",
                        static_cast<unsigned long long>(rw.Rva),
                        rw.Mn, dir, rw.Slot, rw.EncLen,
                        rw.RegName[0] ? rw.RegName : "?",
                        static_cast<unsigned long long>(rw.Value));
                }
            }
        }
        DeobfIo::RuleClose();
    }

    void WriteMovValsSidecar(const std::filesystem::path& dir, const std::vector<MovRewriteRow>& movrewrites, uint64_t bufmodedelta, Deobfuscator::Report& r)
    {
        const std::filesystem::path movvalspath = dir / L"movvals.txt";
        std::ofstream of(movvalspath, std::ios::trunc);
        if (!of)
        {
            std::fprintf(stderr, "[deobf] mov-const: could not open %ls for write\n", movvalspath.wstring().c_str());
            return;
        }
        of << "# ImageBase used for VA display: 0x" << std::hex << bufmodedelta << std::dec << "\n#\n";
        std::vector<const MovRewriteRow*> mixedrows;
        for (const MovRewriteRow& rw : movrewrites)
        {
            if (rw.IsMixed && rw.Ok) mixedrows.push_back(&rw);
        }
        std::sort(mixedrows.begin(), mixedrows.end(),
            [](const MovRewriteRow* a, const MovRewriteRow* b) { return a->Rva < b->Rva; });
        for (const MovRewriteRow* rw : mixedrows)
        {
            const uint64_t siteva = bufmodedelta + rw->Rva;
            const uint64_t sliceva = bufmodedelta + rw->ListTargetRva;
            std::vector<uint64_t> vals(rw->ObservedValues->begin(), rw->ObservedValues->end());
            std::sort(vals.begin(), vals.end());
            const uint64_t sliceend = sliceva + vals.size() * 8;
            of << "Site VA: 0x" << std::hex << siteva
                << "  RVA 0x" << rw->Rva
                << "  mov reg=" << (rw->RegName[0] ? rw->RegName : "?")
                << " is_load=" << (rw->IsLoad ? 1 : 0) << "\n";
            of << "Slice VA: 0x" << sliceva << " - 0x" << sliceend
                << "  (" << std::dec << vals.size() << " qword"
                << (vals.size() == 1 ? "" : "s") << ")\n";
            for (size_t i = 0; i < vals.size(); ++i)
            {
                of << "  [" << std::dec << i << "] 0x" << std::hex << vals[i] << "\n";
            }
            of << std::dec << "\n";
        }
        r.MovValsLogPath = movvalspath;
    }
}

void MovConstTarget::Deobfuscate(DeobfContext& ctx, Deobfuscator::Report& r)
{
    ctx.PreMovRewriteBuf = ctx.Buf;

    std::unordered_map<uint64_t, MovTally> movperrva;

    ctx.Store->ForEachRecord(ObsKind::Mov,
        [&](const void* rec, size_t sz)
        {
            ++r.MovRecordsSeen;
            if (sz != sizeof(MovHit)) return;
            const MovHit* h = static_cast<const MovHit*>(rec);

            auto pit = movperrva.find(h->Rva);
            MovTally* tp = nullptr;
            if (pit != movperrva.end())
            {
                tp = &pit->second;
            }
            else
            {
                const uint64_t off = ctx.Sm.RvaToOffset(h->Rva);
                if (off == UINT64_MAX) return;
                size_t avail = ctx.Buf.size() - off;
                if (avail > 15) avail = 15;
                ZydisDecodedInstruction insn;
                ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
                if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&ctx.Decoder, ctx.Buf.data() + off, avail, &insn, ops)))
                {
                    return;
                }

                int regop = -1, memop = -1;
                for (int i = 0; i < insn.operand_count_visible; ++i)
                {
                    if (ops[i].type == ZYDIS_OPERAND_TYPE_REGISTER && regop < 0)
                    {
                        regop = i;
                    }
                    else if (ops[i].type == ZYDIS_OPERAND_TYPE_MEMORY && memop < 0)
                    {
                        memop = i;
                    }
                }
                if (regop < 0 || memop < 0) return;

                MovTally fresh;
                fresh.Length = insn.length;
                fresh.FileOff = off;
                fresh.IsLoad = (regop < memop);

                ZydisRegister big = ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, ops[regop].reg.value);
                if (big == ZYDIS_REGISTER_NONE) return;
                ZyanI8 id = ZydisRegisterGetId(big);
                if (id < 0 || id > 15) return;
                fresh.RegId = static_cast<uint8_t>(id);
                const char* rn = ZydisRegisterGetString(big);
                if (rn) std::strncpy(fresh.RegName, rn, sizeof(fresh.RegName) - 1);
                const char* mstr = ZydisMnemonicGetString(insn.mnemonic);
                if (mstr) std::strncpy(fresh.Mn, mstr, sizeof(fresh.Mn) - 1);

                auto ins = movperrva.emplace(h->Rva, fresh);
                tp = &ins.first->second;
            }

            const uint64_t val = tp->IsLoad ? h->MemValue : DeobfEncoders::GprByName(h->Gpr, tp->RegName);
            tp->Values.insert(val);
        });

    r.MovObserved = static_cast<uint32_t>(movperrva.size());

    const HeaderSlackInfo movlistslack = DeobfEncoders::CheckHeaderSlack(ctx.Buf);
    if (!ctx.Cfg.WantMovList || !movlistslack.HaveSlack)
    {
        r.MovNoListHeaderSlack = true;
    }
    std::vector<uint8_t> movlistcontent;
    movlistcontent.reserve(512);
    const uint32_t movlistpredictedrva = movlistslack.PredictedRva;

    std::vector<MovRewriteRow> movrewrites;
    movrewrites.reserve(movperrva.size());
    std::vector<MonoTrampDefer> monotrampdefer;
    std::vector<MixedListDefer> mixedlistdefer;

    for (const auto& [rva, t] : movperrva)
    {
        const bool monopoly = (t.Values.size() == 1);
        if (monopoly) ++r.MovMonopoly; else ++r.MovMixed;

        if (monopoly)
        {
            const uint64_t val = *t.Values.begin();
            MovRewriteRow row{ rva, t.Mn, t.RegName, t.Length, val, t.IsLoad, false, false, 0, t.Length, false, 0, 1, nullptr };

            if (t.RegId == 0xFF || t.FileOff >= ctx.Buf.size())
            {
                ++r.MovRewriteSkip;
                movrewrites.push_back(row);
                continue;
            }
            uint8_t scratch[32];
            const uint32_t p = DeobfEncoders::EncMovRegImm(scratch, sizeof(scratch), t.RegId, val);
            if (p == 0)
            {
                ++r.MovRewriteSkip;
                movrewrites.push_back(row);
                continue;
            }
            row.EncLen = p;
            if (p <= t.Length)
            {
                std::memcpy(ctx.Buf.data() + t.FileOff, scratch, p);
                for (uint32_t k = p; k < t.Length; ++k)
                {
                    ctx.Buf[t.FileOff + k] = 0x90;
                }
                ++r.MovRewriteOk;
                ++r.MovRewriteInplace;
                r.MovBytesPatched += t.Length;
                row.Ok = true;
                movrewrites.push_back(row);
                continue;
            }
            movrewrites.push_back(row);
            MonoTrampDefer d{};
            d.FileOff = t.FileOff;
            d.SiteRva = rva;
            d.SiteLen = t.Length;
            d.RegId = t.RegId;
            d.Value = val;
            d.PayloadLen = p;
            d.RowIdx = movrewrites.size() - 1;
            monotrampdefer.push_back(d);
            continue;
        }

        MovRewriteRow row{ rva, t.Mn, t.RegName, t.Length, 0, t.IsLoad, false, false, 7, t.Length, true, 0, static_cast<uint32_t>(t.Values.size()), &t.Values };

        if (t.RegId == 0xFF || t.FileOff >= ctx.Buf.size() || !movlistslack.HaveSlack)
        {
            ++r.MovMixedListSkip;
            movrewrites.push_back(row);
            continue;
        }

        const uint32_t sliceoff = static_cast<uint32_t>(movlistcontent.size());
        const uint32_t targetrva = movlistpredictedrva + sliceoff;
        std::vector<uint64_t> sortedvals(t.Values.begin(), t.Values.end());
        std::sort(sortedvals.begin(), sortedvals.end());
        for (uint64_t v : sortedvals)
        {
            uint8_t bytes[8];
            std::memcpy(bytes, &v, 8);
            movlistcontent.insert(movlistcontent.end(), bytes, bytes + 8);
        }
        row.ListTargetRva = targetrva;
        r.MovListValuesPacked += static_cast<uint32_t>(sortedvals.size());

        constexpr uint32_t kleaenclen = 7;
        if (t.Length >= kleaenclen)
        {
            if (!DeobfEncoders::EmitLeaRegRipRel(ctx.Buf, t.FileOff, t.Length, 0, targetrva, rva))
            {
                ++r.MovMixedListSkip;
                movrewrites.push_back(row);
                continue;
            }
            r.MovBytesPatched += t.Length;
            ++r.MovMixedListOk;
            ++r.MovMixedListInplace;
            row.Ok = true;
            movrewrites.push_back(row);
            continue;
        }

        movrewrites.push_back(row);
        MixedListDefer d{};
        d.FileOff = t.FileOff;
        d.SiteRva = rva;
        d.SiteLen = t.Length;
        d.TargetRva = targetrva;
        d.RowIdx = movrewrites.size() - 1;
        mixedlistdefer.push_back(d);
    }

    if (!movlistcontent.empty())
    {
        uint32_t appendedrva = 0;
        if (SectionManager::AppendPeSection(ctx.Buf, ".sophmovL", movlistcontent, appendedrva))
        {
            if (appendedrva != movlistpredictedrva)
            {
                std::fprintf(stderr, "[deobf] mov-const: WARN predicted .sophmovL RVA 0x%x != appended 0x%x -- list LEAs may point wrong\n",
                    movlistpredictedrva, appendedrva);
            }
            r.MovListSectionRva = appendedrva;
            r.MovListSectionBytes = static_cast<uint32_t>(movlistcontent.size());
            std::strncpy(r.MovListSectionName, ".sophmovL", sizeof(r.MovListSectionName) - 1);
        }
        else
        {
            std::fprintf(stderr, "[deobf] mov-const: AppendPeSection .sophmovL FAILED -- all mixed-list rewrites rolled back to skips\n");
            const uint32_t okback = r.MovMixedListOk;
            r.MovMixedListSkip += okback;
            r.MovMixedListOk = 0;
            r.MovMixedListInplace = 0;
            r.MovListValuesPacked = 0;
            for (MovRewriteRow& rw : movrewrites)
            {
                if (rw.IsMixed && rw.Ok) rw.Ok = false;
            }
            mixedlistdefer.clear();
        }
    }

    if (!monotrampdefer.empty() || !mixedlistdefer.empty())
    {
        const HeaderSlackInfo movslack = DeobfEncoders::CheckHeaderSlack(ctx.Buf);
        if (!movslack.HaveSlack)
        {
            r.MovNoHeaderSlack = true;
            for (const MonoTrampDefer& d : monotrampdefer)
            {
                movrewrites[d.RowIdx].Ok = false;
                ++r.MovRewriteSkip;
            }
            for (const MixedListDefer& d : mixedlistdefer)
            {
                movrewrites[d.RowIdx].Ok = false;
                ++r.MovMixedListSkip;
            }
        }
        else
        {
            TrampolineBuilder movtramp(ctx.Buf, ctx.Decoder, movslack.PredictedRva);
            for (const MonoTrampDefer& d : monotrampdefer)
            {
                const uint8_t regid = d.RegId;
                const uint64_t value = d.Value;
                const bool okt = movtramp.TryTrampoline(d.FileOff, d.SiteLen, d.SiteRva, d.PayloadLen,
                    [regid, value](uint8_t* out, uint32_t cap, uint64_t)
                    {
                        return DeobfEncoders::EncMovRegImm(out, cap, regid, value);
                    });
                if (okt)
                {
                    const auto& sr = movtramp.Sites().back();
                    MovRewriteRow& rw = movrewrites[d.RowIdx];
                    rw.Consumed = sr.Consumed;
                    rw.ViaTramp = true;
                    rw.Ok = true;
                    ++r.MovRewriteOk;
                    ++r.MovRewriteTramp;
                    r.MovBytesPatched += sr.Consumed;
                }
                else
                {
                    ++r.MovRewriteSkip;
                }
            }
            for (const MixedListDefer& d : mixedlistdefer)
            {
                const uint32_t tgt = d.TargetRva;
                const bool okt = movtramp.TryTrampoline(d.FileOff, d.SiteLen, d.SiteRva, 7,
                    [tgt](uint8_t* out, uint32_t cap, uint64_t at)
                    {
                        return DeobfEncoders::EncLeaRipRel(out, cap, 0, tgt, at);
                    });
                if (okt)
                {
                    const auto& sr = movtramp.Sites().back();
                    MovRewriteRow& rw = movrewrites[d.RowIdx];
                    rw.Consumed = sr.Consumed;
                    rw.ViaTramp = true;
                    rw.Ok = true;
                    ++r.MovMixedListOk;
                    ++r.MovMixedListTramp;
                    r.MovBytesPatched += sr.Consumed;
                }
                else
                {
                    ++r.MovMixedListSkip;
                }
            }

            if (!movtramp.Blob().empty())
            {
                uint32_t appendedrva = 0;
                const uint32_t chars = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE;
                if (SectionManager::AppendPeSection(ctx.Buf, ".sophmov", movtramp.Blob(), appendedrva, chars))
                {
                    if (appendedrva != movtramp.PredictedSectionRva())
                    {
                        std::fprintf(stderr, "[deobf] mov-const: WARN predicted .sophmov RVA 0x%x != appended 0x%x\n",
                            movtramp.PredictedSectionRva(), appendedrva);
                    }
                    movtramp.EmitOutbounds();
                    r.MovTrampSectionRva = appendedrva;
                    r.MovTrampSectionBytes = static_cast<uint32_t>(movtramp.Blob().size());
                    r.MovTrampBytesSaved = movtramp.BytesSaved();
                    std::strncpy(r.MovTrampSectionName, ".sophmov", sizeof(r.MovTrampSectionName) - 1);
                }
                else
                {
                    std::fprintf(stderr, "[deobf] mov-const: AppendPeSection .sophmov FAILED -- %u monopoly + %u mixed sites left un-rewritten\n",
                        r.MovRewriteTramp, r.MovMixedListTramp);
                    r.MovRewriteOk -= r.MovRewriteTramp;
                    r.MovMixedListOk -= r.MovMixedListTramp;
                    r.MovRewriteSkip += r.MovRewriteTramp;
                    r.MovMixedListSkip += r.MovMixedListTramp;
                    r.MovRewriteTramp = 0;
                    r.MovMixedListTramp = 0;
                }
            }
        }
    }

    if (r.MovListSectionBytes > 0)
    {
        WriteMovValsSidecar(ctx.Store->Dir(), movrewrites, r.BufModeDelta, r);
    }

    std::sort(movrewrites.begin(), movrewrites.end(),
        [](const MovRewriteRow& a, const MovRewriteRow& b) { return a.Rva < b.Rva; });

    PrintSummary(r, movrewrites);
}