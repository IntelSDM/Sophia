#include "../../../../Pch.h"
#include "LeaConstTarget.h"
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
    struct LeaTally
    {
        std::unordered_set<uint64_t> Values;
        uint32_t                     Length = 0;
        uint64_t                     FileOff = 0;
        uint8_t                      DstRegId = 0xFF;
        char                         DstName[8] = {};
        char                         EaExpr[32] = {};
    };

    struct LeaRewriteRow
    {
        uint64_t    Rva;
        const char* DstName;
        const char* EaExpr;
        uint32_t    Slot;
        uint64_t    Value;
        bool        Ok;
        bool        ViaTramp;
        uint32_t    Consumed;
        bool        IsMixed;
        uint32_t    ListTargetRva;
        uint32_t    NValues;
        const std::unordered_set<uint64_t>* ObservedValues;
    };

    struct LeaMonoDefer
    {
        uint64_t FileOff, SiteRva;
        uint32_t SiteLen;
        uint8_t  RegId;
        uint64_t Ea;
        size_t   RowIdx;
    };

    struct LeaMixedDefer
    {
        uint64_t FileOff, SiteRva;
        uint32_t SiteLen, TargetRva;
        size_t   RowIdx;
    };

    void PrintSummary(const Deobfuscator::Report& r, const std::vector<LeaRewriteRow>& rewrites)
    {
        DeobfIo::RuleOpen("lea-const -- resolution");
        std::printf("[deobf]   LeaHit records read            : %llu\n", static_cast<unsigned long long>(r.LeaRecordsSeen));
        std::printf("[deobf]   LEA sites observed             : %u\n", r.LeaObserved);
        std::printf("[deobf]   monopoly (candidate)           : %u\n", r.LeaMonopoly);
        std::printf("[deobf]   mixed (candidate)              : %u\n", r.LeaMixed);
        std::printf("[deobf]   monopoly rewritten             : %u\n", r.LeaRewriteOk);
        std::printf("[deobf]     in-place (slot >= 7B)        : %u\n", r.LeaRewriteInplace);
        std::printf("[deobf]     trampoline via .sophlea      : %u\n", r.LeaRewriteTramp);
        std::printf("[deobf]   monopoly skipped               : %u\n", r.LeaRewriteSkip);
        std::printf("[deobf]   mixed rewritten (LEA -> list)  : %u\n", r.LeaMixedListOk);
        std::printf("[deobf]     in-place                     : %u\n", r.LeaMixedListInplace);
        std::printf("[deobf]     trampoline via .sophlea      : %u\n", r.LeaMixedListTramp);
        std::printf("[deobf]   mixed skipped                  : %u\n", r.LeaMixedListSkip);
        if (r.LeaNoHeaderSlack)
        {
            std::puts("[deobf]   NOTE                           : no header slack for .sophlea");
        }
        if (r.LeaNoListHeaderSlack)
        {
            std::puts("[deobf]   NOTE                           : no header slack for .sophleaL");
        }
        std::printf("[deobf]   bytes patched (site sum)       : %llu\n", static_cast<unsigned long long>(r.LeaBytesPatched));
        std::printf("[deobf]   bytes NOT corrupted downstream : %llu\n", static_cast<unsigned long long>(r.LeaTrampBytesSaved));
        if (r.LeaListSectionBytes)
        {
            std::printf("[deobf]   .sophleaL section RVA          : 0x%llx\n", static_cast<unsigned long long>(r.LeaListSectionRva));
            std::printf("[deobf]   .sophleaL section bytes        : %u\n", r.LeaListSectionBytes);
            std::printf("[deobf]   .sophleaL values packed        : %u\n", r.LeaListValuesPacked);
        }
        if (r.LeaTrampSectionBytes)
        {
            std::printf("[deobf]   .sophlea section RVA           : 0x%llx\n", static_cast<unsigned long long>(r.LeaTrampSectionRva));
            std::printf("[deobf]   .sophlea section bytes         : %u\n", r.LeaTrampSectionBytes);
        }
        if (!r.LeaValsLogPath.empty())
        {
            std::printf("[deobf]   leavals log                    : %ls\n", r.LeaValsLogPath.wstring().c_str());
        }

        if (!rewrites.empty())
        {
            std::printf("[deobf] lea rewrite log (all %zu site(s)):\n", rewrites.size());
            for (const LeaRewriteRow& rw : rewrites)
            {
                const char* dst = rw.DstName[0] ? rw.DstName : "?";
                const char* ea = rw.EaExpr[0] ? rw.EaExpr : "[?]";
                if (!rw.Ok)
                {
                    std::printf("[deobf]   rva=0x%08llx  lea  slot=%u  SKIPPED (dst=%s ea=%s %s)\n",
                        static_cast<unsigned long long>(rw.Rva), rw.Slot, dst, ea, rw.IsMixed ? "mixed" : "monopoly");
                }
                else if (rw.IsMixed)
                {
                    const char* tramp = rw.ViaTramp ? " TRAMP .sophlea" : "";
                    std::printf("[deobf]   rva=0x%08llx  lea  slot=%u consumed=%u%s  -> lea rax, [0x%x]  (%u EAs)  (was: lea %s, %s)\n",
                        static_cast<unsigned long long>(rw.Rva), rw.Slot, rw.Consumed, tramp,
                        rw.ListTargetRva, rw.NValues, dst, ea);
                }
                else if (rw.ViaTramp)
                {
                    std::printf("[deobf]   rva=0x%08llx  lea  slot=%u  consumed=%u  -> TRAMP .sophlea  (lea %s, [0x%llx])  (was: lea %s, %s)\n",
                        static_cast<unsigned long long>(rw.Rva), rw.Slot, rw.Consumed, dst,
                        static_cast<unsigned long long>(rw.Value), dst, ea);
                }
                else
                {
                    std::printf("[deobf]   rva=0x%08llx  lea  slot=%u  -> lea %s, [0x%llx]  (was: lea %s, %s)\n",
                        static_cast<unsigned long long>(rw.Rva), rw.Slot, dst,
                        static_cast<unsigned long long>(rw.Value), dst, ea);
                }
            }
        }
        DeobfIo::RuleClose();
    }

    void WriteLeaValsSidecar(const std::filesystem::path& dir, const std::vector<LeaRewriteRow>& rewrites, uint64_t bufmodedelta, Deobfuscator::Report& r)
    {
        const std::filesystem::path leavalspath = dir / L"leavals.txt";
        std::ofstream of(leavalspath, std::ios::trunc);
        if (!of)
        {
            std::fprintf(stderr, "[deobf] lea-const: could not open %ls for write\n", leavalspath.wstring().c_str());
            return;
        }

        of << "# ImageBase used for VA display: 0x" << std::hex << bufmodedelta << std::dec << "\n#\n";
        std::vector<const LeaRewriteRow*> mixedrows;
        for (const LeaRewriteRow& rw : rewrites)
        {
            if (rw.IsMixed && rw.Ok) mixedrows.push_back(&rw);
        }
        std::sort(mixedrows.begin(), mixedrows.end(),
            [](const LeaRewriteRow* a, const LeaRewriteRow* b) { return a->Rva < b->Rva; });
        for (const LeaRewriteRow* rw : mixedrows)
        {
            const uint64_t siteva = bufmodedelta + rw->Rva;
            const uint64_t sliceva = bufmodedelta + rw->ListTargetRva;
            std::vector<uint64_t> vals(rw->ObservedValues->begin(), rw->ObservedValues->end());
            std::sort(vals.begin(), vals.end());
            const uint64_t sliceend = sliceva + vals.size() * 8;
            of << "Site VA: 0x" << std::hex << siteva
                << "  RVA 0x" << rw->Rva
                << "  lea  dst=" << (rw->DstName[0] ? rw->DstName : "?")
                << "  ea=" << (rw->EaExpr[0] ? rw->EaExpr : "[?]") << "\n";
            of << "Slice VA: 0x" << sliceva << " - 0x" << sliceend
                << "  (" << std::dec << vals.size() << " qword"
                << (vals.size() == 1 ? "" : "s") << ")\n";
            for (size_t i = 0; i < vals.size(); ++i)
            {
                of << "  [" << std::dec << i << "] 0x" << std::hex << vals[i] << "\n";
            }
            of << std::dec << "\n";
        }
        r.LeaValsLogPath = leavalspath;
    }
}

void LeaConstTarget::Deobfuscate(DeobfContext& ctx, Deobfuscator::Report& r)
{
    std::unordered_map<uint64_t, LeaTally> leaperrva;
    std::unordered_set<uint64_t> leanothandled;

    ctx.Store->ForEachRecord(ObsKind::Lea,
        [&](const void* rec, size_t sz)
        {
            ++r.LeaRecordsSeen;
            if (sz != sizeof(LeaHit)) return;
            const LeaHit* h = static_cast<const LeaHit*>(rec);
            if (leanothandled.count(h->Rva)) return;

            auto pit = leaperrva.find(h->Rva);
            LeaTally* tp = nullptr;
            if (pit != leaperrva.end())
            {
                tp = &pit->second;
            }
            else
            {
                const uint64_t off = ctx.Sm.RvaToOffset(h->Rva);
                if (off == UINT64_MAX)
                {
                    leanothandled.insert(h->Rva);
                    return;
                }
                size_t avail = ctx.PreMovRewriteBuf.size() - off;
                if (avail > 15) avail = 15;
                ZydisDecodedInstruction insn;
                ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
                if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&ctx.Decoder, ctx.PreMovRewriteBuf.data() + off, avail, &insn, ops)))
                {
                    leanothandled.insert(h->Rva);
                    return;
                }
                if (insn.mnemonic != ZYDIS_MNEMONIC_LEA ||
                    insn.operand_count_visible < 2 ||
                    ops[0].type != ZYDIS_OPERAND_TYPE_REGISTER ||
                    ops[1].type != ZYDIS_OPERAND_TYPE_MEMORY)
                {
                    leanothandled.insert(h->Rva);
                    return;
                }
                const auto& mem = ops[1].mem;
                if (mem.base == ZYDIS_REGISTER_RIP)
                {
                    leanothandled.insert(h->Rva);
                    return;
                }
                if (mem.base == ZYDIS_REGISTER_NONE && mem.index == ZYDIS_REGISTER_NONE)
                {
                    leanothandled.insert(h->Rva);
                    return;
                }

                LeaTally fresh;
                fresh.Length = insn.length;
                fresh.FileOff = off;

                ZydisRegister dstbig = ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, ops[0].reg.value);
                if (dstbig == ZYDIS_REGISTER_NONE)
                {
                    leanothandled.insert(h->Rva);
                    return;
                }
                ZyanI8 dstid = ZydisRegisterGetId(dstbig);
                if (dstid < 0 || dstid > 15)
                {
                    leanothandled.insert(h->Rva);
                    return;
                }
                fresh.DstRegId = static_cast<uint8_t>(dstid);
                const char* dstname = ZydisRegisterGetString(dstbig);
                if (dstname) std::strncpy(fresh.DstName, dstname, sizeof(fresh.DstName) - 1);

                uint8_t baseid = 0xFF, indexid = 0xFF;
                if (mem.base != ZYDIS_REGISTER_NONE)
                {
                    ZydisRegister big = ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, mem.base);
                    if (big != ZYDIS_REGISTER_NONE)
                    {
                        ZyanI8 id = ZydisRegisterGetId(big);
                        if (id >= 0 && id <= 15) baseid = static_cast<uint8_t>(id);
                    }
                }
                if (mem.index != ZYDIS_REGISTER_NONE)
                {
                    ZydisRegister big = ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, mem.index);
                    if (big != ZYDIS_REGISTER_NONE)
                    {
                        ZyanI8 id = ZydisRegisterGetId(big);
                        if (id >= 0 && id <= 15) indexid = static_cast<uint8_t>(id);
                    }
                }
                DeobfEncoders::FormatEaExpr(fresh.EaExpr, sizeof(fresh.EaExpr),
                    baseid, indexid, static_cast<uint8_t>(mem.scale), static_cast<int64_t>(mem.disp.value));

                auto ins = leaperrva.emplace(h->Rva, fresh);
                tp = &ins.first->second;
            }

            tp->Values.insert(h->Ea);
        });

    r.LeaObserved = static_cast<uint32_t>(leaperrva.size());

    const HeaderSlackInfo lealistslack = DeobfEncoders::CheckHeaderSlack(ctx.Buf);
    if (!ctx.Cfg.WantLeaList || !lealistslack.HaveSlack)
    {
        r.LeaNoListHeaderSlack = true;
    }
    std::vector<uint8_t> lealistcontent;
    lealistcontent.reserve(512);
    const uint32_t lealistpredictedrva = lealistslack.PredictedRva;

    std::vector<LeaRewriteRow> learewrites;
    learewrites.reserve(leaperrva.size());
    std::vector<LeaMonoDefer> leamonodefer;
    std::vector<LeaMixedDefer> leamixeddefer;

    for (const auto& [rva, t] : leaperrva)
    {
        const bool monopoly = (t.Values.size() == 1);
        if (monopoly) ++r.LeaMonopoly; else ++r.LeaMixed;

        constexpr uint32_t kleaenclen = 7;

        if (monopoly)
        {
            const uint64_t val = *t.Values.begin();
            LeaRewriteRow row{ rva, t.DstName, t.EaExpr, t.Length, val, false, false, t.Length, false, 0, 1, nullptr };
            if (t.DstRegId == 0xFF || t.FileOff >= ctx.Buf.size())
            {
                ++r.LeaRewriteSkip;
                learewrites.push_back(row);
                continue;
            }
            if (t.Length >= kleaenclen)
            {
                const bool ok = DeobfEncoders::EmitLeaRegRipRel(ctx.Buf, t.FileOff, t.Length, t.DstRegId, val, rva);
                if (ok)
                {
                    ++r.LeaRewriteOk;
                    ++r.LeaRewriteInplace;
                    r.LeaBytesPatched += t.Length;
                    row.Ok = true;
                }
                else
                {
                    ++r.LeaRewriteSkip;
                }
                learewrites.push_back(row);
                continue;
            }
            learewrites.push_back(row);
            LeaMonoDefer d{};
            d.FileOff = t.FileOff; d.SiteRva = rva; d.SiteLen = t.Length;
            d.RegId = t.DstRegId; d.Ea = val;
            d.RowIdx = learewrites.size() - 1;
            leamonodefer.push_back(d);
            continue;
        }

        LeaRewriteRow row{ rva, t.DstName, t.EaExpr, t.Length, 0, false, false, t.Length, true, 0, static_cast<uint32_t>(t.Values.size()), &t.Values };
        if (t.DstRegId == 0xFF || t.FileOff >= ctx.Buf.size() || !lealistslack.HaveSlack)
        {
            ++r.LeaMixedListSkip;
            learewrites.push_back(row);
            continue;
        }
        const uint32_t sliceoff = static_cast<uint32_t>(lealistcontent.size());
        const uint32_t targetrva = lealistpredictedrva + sliceoff;
        std::vector<uint64_t> sortedvals(t.Values.begin(), t.Values.end());
        std::sort(sortedvals.begin(), sortedvals.end());
        for (uint64_t v : sortedvals)
        {
            uint8_t bytes[8];
            std::memcpy(bytes, &v, 8);
            lealistcontent.insert(lealistcontent.end(), bytes, bytes + 8);
        }
        row.ListTargetRva = targetrva;
        r.LeaListValuesPacked += static_cast<uint32_t>(sortedvals.size());

        if (t.Length >= kleaenclen)
        {
            if (!DeobfEncoders::EmitLeaRegRipRel(ctx.Buf, t.FileOff, t.Length, 0, targetrva, rva))
            {
                ++r.LeaMixedListSkip;
                learewrites.push_back(row);
                continue;
            }
            r.LeaBytesPatched += t.Length;
            ++r.LeaMixedListOk;
            ++r.LeaMixedListInplace;
            row.Ok = true;
            learewrites.push_back(row);
            continue;
        }

        learewrites.push_back(row);
        LeaMixedDefer d{};
        d.FileOff = t.FileOff; d.SiteRva = rva; d.SiteLen = t.Length;
        d.TargetRva = targetrva;
        d.RowIdx = learewrites.size() - 1;
        leamixeddefer.push_back(d);
    }

    if (!lealistcontent.empty())
    {
        uint32_t appendedrva = 0;
        if (SectionManager::AppendPeSection(ctx.Buf, ".sophleaL", lealistcontent, appendedrva))
        {
            if (appendedrva != lealistpredictedrva)
            {
                std::fprintf(stderr, "[deobf] lea-const: WARN predicted .sophleaL RVA 0x%x != appended 0x%x\n", lealistpredictedrva, appendedrva);
            }
            r.LeaListSectionRva = appendedrva;
            r.LeaListSectionBytes = static_cast<uint32_t>(lealistcontent.size());
            std::strncpy(r.LeaListSectionName, ".sophleaL", sizeof(r.LeaListSectionName) - 1);
        }
        else
        {
            std::fprintf(stderr, "[deobf] lea-const: AppendPeSection .sophleaL FAILED -- mixed-list rewrites rolled back\n");
            const uint32_t okback = r.LeaMixedListOk;
            r.LeaMixedListSkip += okback;
            r.LeaMixedListOk = 0;
            r.LeaMixedListInplace = 0;
            r.LeaListValuesPacked = 0;
            for (LeaRewriteRow& rw : learewrites)
            {
                if (rw.IsMixed && rw.Ok) rw.Ok = false;
            }
            leamixeddefer.clear();
        }
    }

    if (!leamonodefer.empty() || !leamixeddefer.empty())
    {
        const HeaderSlackInfo leaslack = DeobfEncoders::CheckHeaderSlack(ctx.Buf);
        if (!leaslack.HaveSlack)
        {
            r.LeaNoHeaderSlack = true;
            for (const LeaMonoDefer& d : leamonodefer)
            {
                learewrites[d.RowIdx].Ok = false;
                ++r.LeaRewriteSkip;
            }
            for (const LeaMixedDefer& d : leamixeddefer)
            {
                learewrites[d.RowIdx].Ok = false;
                ++r.LeaMixedListSkip;
            }
        }
        else
        {
            TrampolineBuilder leatramp(ctx.Buf, ctx.Decoder, leaslack.PredictedRva);
            for (const LeaMonoDefer& d : leamonodefer)
            {
                const uint8_t regid = d.RegId;
                const uint64_t ea = d.Ea;
                const bool okt = leatramp.TryTrampoline(d.FileOff, d.SiteLen, d.SiteRva, 7,
                    [regid, ea](uint8_t* out, uint32_t cap, uint64_t at)
                    {
                        return DeobfEncoders::EncLeaRipRel(out, cap, regid, ea, at);
                    });
                if (okt)
                {
                    const auto& sr = leatramp.Sites().back();
                    LeaRewriteRow& rw = learewrites[d.RowIdx];
                    rw.Consumed = sr.Consumed;
                    rw.ViaTramp = true;
                    rw.Ok = true;
                    ++r.LeaRewriteOk;
                    ++r.LeaRewriteTramp;
                    r.LeaBytesPatched += sr.Consumed;
                }
                else
                {
                    ++r.LeaRewriteSkip;
                }
            }
            for (const LeaMixedDefer& d : leamixeddefer)
            {
                const uint32_t tgt = d.TargetRva;
                const bool okt = leatramp.TryTrampoline(d.FileOff, d.SiteLen, d.SiteRva, 7,
                    [tgt](uint8_t* out, uint32_t cap, uint64_t at)
                    {
                        return DeobfEncoders::EncLeaRipRel(out, cap, 0, tgt, at);
                    });
                if (okt)
                {
                    const auto& sr = leatramp.Sites().back();
                    LeaRewriteRow& rw = learewrites[d.RowIdx];
                    rw.Consumed = sr.Consumed;
                    rw.ViaTramp = true;
                    rw.Ok = true;
                    ++r.LeaMixedListOk;
                    ++r.LeaMixedListTramp;
                    r.LeaBytesPatched += sr.Consumed;
                }
                else
                {
                    ++r.LeaMixedListSkip;
                }
            }
            if (!leatramp.Blob().empty())
            {
                uint32_t appendedrva = 0;
                const uint32_t chars = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE;
                if (SectionManager::AppendPeSection(ctx.Buf, ".sophlea", leatramp.Blob(), appendedrva, chars))
                {
                    if (appendedrva != leatramp.PredictedSectionRva())
                    {
                        std::fprintf(stderr, "[deobf] lea-const: WARN predicted .sophlea RVA 0x%x != appended 0x%x\n",
                            leatramp.PredictedSectionRva(), appendedrva);
                    }
                    leatramp.EmitOutbounds();
                    r.LeaTrampSectionRva = appendedrva;
                    r.LeaTrampSectionBytes = static_cast<uint32_t>(leatramp.Blob().size());
                    r.LeaTrampBytesSaved = leatramp.BytesSaved();
                    std::strncpy(r.LeaTrampSectionName, ".sophlea", sizeof(r.LeaTrampSectionName) - 1);
                }
                else
                {
                    std::fprintf(stderr, "[deobf] lea-const: AppendPeSection .sophlea FAILED -- %u monopoly + %u mixed sites un-rewritten\n",
                        r.LeaRewriteTramp, r.LeaMixedListTramp);
                    r.LeaRewriteOk -= r.LeaRewriteTramp;
                    r.LeaRewriteSkip += r.LeaRewriteTramp;
                    r.LeaMixedListOk -= r.LeaMixedListTramp;
                    r.LeaMixedListSkip += r.LeaMixedListTramp;
                    for (LeaRewriteRow& rw : learewrites)
                    {
                        if (rw.ViaTramp) rw.Ok = false;
                    }
                    r.LeaRewriteTramp = 0;
                    r.LeaMixedListTramp = 0;
                }
            }
        }
    }

    if (r.LeaListSectionBytes > 0)
    {
        WriteLeaValsSidecar(ctx.Store->Dir(), learewrites, r.BufModeDelta, r);
    }

    std::sort(learewrites.begin(), learewrites.end(),
        [](const LeaRewriteRow& a, const LeaRewriteRow& b) { return a.Rva < b.Rva; });

    PrintSummary(r, learewrites);
}