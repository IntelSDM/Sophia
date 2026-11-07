#include "../../../../Pch.h"
#include "OpaqueJccTarget.h"
#include "../../DeobfEncoders.h"
#include "../../DeobfIo.h"
#include "../../../Database/AutoDebugStore.h"

#include <Zydis/Zydis.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <unordered_map>
#include <vector>

namespace
{
    struct Tally
    {
        uint32_t Taken = 0;
        uint32_t Ntaken = 0;
        char     Mn[16] = {};
        uint32_t Length = 0;
        uint64_t FileOff = 0;
        uint64_t ToRva = 0;
    };

    struct Row
    {
        uint64_t    Rva;
        const char* Mn;
        uint32_t    Taken;
        uint32_t    Ntaken;
        uint32_t    Length;
        uint64_t    FileOff;
        uint64_t    ToRva;
    };

    struct RewriteRow
    {
        uint64_t    Rva;
        const char* Mn;
        bool        Ok;
        uint32_t    Slot;
        uint64_t    Target;
        bool        Taken;
    };

    void PrintDetection(const Deobfuscator::Report& r, const std::vector<Row>& alwaystaken, const std::vector<Row>& alwaysntaken, const std::vector<Row>& mixed)
    {
        constexpr size_t ksamplecap = 20;
        DeobfIo::RuleOpen("opaques -- detection");
        std::printf("[deobf]   Jccs in catalog          : %u\n", r.JccTotal);
        std::printf("[deobf]   BranchHit records read   : %llu\n", static_cast<unsigned long long>(r.BranchRecordsSeen));
        std::printf("[deobf]   Jccs observed >=1x       : %u  (%.2f%% of catalog)\n",
            r.JccObserved, r.JccTotal ? 100.0 * r.JccObserved / r.JccTotal : 0.0);
        std::printf("[deobf]   observed but non-Jcc*    : %u   (*LOOP / JRCXZ / JMP)\n", r.JccUnclassified);
        std::printf("[deobf]   opaque (candidates)      : %u\n", r.JccOpaque);
        std::printf("[deobf]     always-taken           : %u\n", r.JccAlwaysTaken);
        std::printf("[deobf]     always-not-taken       : %u\n", r.JccAlwaysNtaken);
        std::printf("[deobf]   mixed (real conditionals): %u\n", r.JccMixed);

        auto dump = [&](const char* label, const std::vector<Row>& v)
            {
                if (v.empty()) return;
                const size_t show = v.size() < ksamplecap ? v.size() : ksamplecap;
                std::printf("[deobf] %s (showing %zu of %zu):\n", label, show, v.size());
                for (size_t i = 0; i < show; ++i)
                {
                    const Row& row = v[i];
                    std::printf("[deobf]   rva=0x%08llx  %-4s  taken=%u  ntaken=%u\n",
                        static_cast<unsigned long long>(row.Rva), row.Mn, row.Taken, row.Ntaken);
                }
            };
        dump("always-taken", alwaystaken);
        dump("always-not-taken", alwaysntaken);
        dump("mixed", mixed);
        DeobfIo::RuleClose();
    }

    void PrintRewrite(const Deobfuscator::Report& r, const std::vector<RewriteRow>& rewrites)
    {
        DeobfIo::RuleOpen("opaques -- rewrite");
        std::printf("[deobf]   opaques rewritten          : %u\n", r.JccRewriteOk);
        std::printf("[deobf]   opaques skipped            : %u\n", r.JccRewriteSkip);
        std::printf("[deobf]   total bytes patched        : %llu\n", static_cast<unsigned long long>(r.BytesPatched));
        if (!r.OpaqueJccLogPath.empty())
        {
            std::printf("[deobf]   opaques log                : %ls\n", r.OpaqueJccLogPath.wstring().c_str());
        }

        if (!rewrites.empty())
        {
            std::printf("[deobf] rewrite log (all %zu site(s)):\n", rewrites.size());
            for (const RewriteRow& rw : rewrites)
            {
                if (!rw.Ok)
                {
                    std::printf("[deobf]   rva=0x%08llx  %-4s  slot=%u  SKIPPED (encoder rejected)\n",
                        static_cast<unsigned long long>(rw.Rva), rw.Mn, rw.Slot);
                }
                else if (rw.Taken)
                {
                    std::printf("[deobf]   rva=0x%08llx  %-4s  slot=%u  -> JMP 0x%llx\n",
                        static_cast<unsigned long long>(rw.Rva), rw.Mn, rw.Slot,
                        static_cast<unsigned long long>(rw.Target));
                }
                else
                {
                    std::printf("[deobf]   rva=0x%08llx  %-4s  slot=%u  -> NOP*%u  (fall through)\n",
                        static_cast<unsigned long long>(rw.Rva), rw.Mn, rw.Slot, rw.Slot);
                }
            }
        }
        DeobfIo::RuleClose();
    }
}

void OpaqueJccTarget::Deobfuscate(DeobfContext& ctx, Deobfuscator::Report& r)
{
    std::unordered_map<uint64_t, Tally> perrva;

    ctx.Store->ForEachRecord(ObsKind::Branch,
        [&](const void* rec, size_t sz)
        {
            ++r.BranchRecordsSeen;
            if (sz != sizeof(BranchHit)) return;
            const BranchHit* h = static_cast<const BranchHit*>(rec);

            auto pit = perrva.find(h->Rva);
            Tally* tp = nullptr;
            if (pit != perrva.end())
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
                const char* mstr = ZydisMnemonicGetString(insn.mnemonic);
                if (!mstr) return;
                if (!DeobfEncoders::WillJccTake(mstr, 0).has_value()) return;

                Tally fresh;
                std::strncpy(fresh.Mn, mstr, sizeof(fresh.Mn) - 1);
                fresh.Length = insn.length;
                fresh.FileOff = off;
                if (insn.operand_count_visible >= 1 &&
                    ops[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
                    ops[0].imm.is_relative)
                {
                    ZyanU64 to = 0;
                    if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&insn, &ops[0], h->Rva, &to)))
                    {
                        fresh.ToRva = to;
                    }
                }
                auto ins = perrva.emplace(h->Rva, fresh);
                tp = &ins.first->second;
            }

            auto taken = DeobfEncoders::WillJccTake(tp->Mn, h->Gpr.rflags);
            if (!taken.has_value()) return;
            if (*taken) ++tp->Taken;
            else ++tp->Ntaken;
        });

    uint32_t observedbranchrvas = 0;
    for (uint64_t rva : ctx.Store->ExploredRvas())
    {
        auto it = ctx.BranchIdxByRva.find(rva);
        if (it != ctx.BranchIdxByRva.end()) ++observedbranchrvas;
    }
    r.JccObserved = static_cast<uint32_t>(perrva.size());
    r.JccUnclassified = observedbranchrvas > r.JccObserved ? observedbranchrvas - r.JccObserved : 0;

    std::vector<Row> alwaystakenlist, alwaysntakenlist, mixedlist;
    alwaystakenlist.reserve(perrva.size());
    alwaysntakenlist.reserve(perrva.size());

    for (const auto& [rva, t] : perrva)
    {
        Row row{ rva, t.Mn, t.Taken, t.Ntaken, t.Length, t.FileOff, t.ToRva };
        const bool alwaystaken = (t.Ntaken == 0 && t.Taken > 0);
        const bool alwaysntaken = (t.Taken == 0 && t.Ntaken > 0);
        if (alwaystaken)
        {
            ++r.JccAlwaysTaken;
            alwaystakenlist.push_back(row);
        }
        else if (alwaysntaken)
        {
            ++r.JccAlwaysNtaken;
            alwaysntakenlist.push_back(row);
        }
        else
        {
            ++r.JccMixed;
            mixedlist.push_back(row);
        }
    }
    r.JccOpaque = r.JccAlwaysTaken + r.JccAlwaysNtaken;

    auto byrva = [](const Row& a, const Row& b) { return a.Rva < b.Rva; };
    std::sort(alwaystakenlist.begin(), alwaystakenlist.end(), byrva);
    std::sort(alwaysntakenlist.begin(), alwaysntakenlist.end(), byrva);
    std::sort(mixedlist.begin(), mixedlist.end(), byrva);

    PrintDetection(r, alwaystakenlist, alwaysntakenlist, mixedlist);

    std::vector<RewriteRow> rewrites;
    rewrites.reserve(alwaystakenlist.size() + alwaysntakenlist.size());

    for (const Row& row : alwaystakenlist)
    {
        if (row.FileOff + row.Length > ctx.Buf.size())
        {
            ++r.JccRewriteSkip;
            continue;
        }
        const bool ok = DeobfEncoders::EmitDirectJmp(ctx.Buf, row.FileOff, row.Length, row.Rva, row.ToRva);
        if (ok)
        {
            ++r.JccRewriteOk;
            r.BytesPatched += row.Length;
        }
        else
        {
            ++r.JccRewriteSkip;
        }
        rewrites.push_back({ row.Rva, row.Mn, ok, row.Length, row.ToRva, true });
    }

    for (const Row& row : alwaysntakenlist)
    {
        if (row.FileOff + row.Length > ctx.Buf.size())
        {
            ++r.JccRewriteSkip;
            continue;
        }
        DeobfEncoders::NopFill(ctx.Buf, row.FileOff, row.Length);
        ++r.JccRewriteOk;
        r.BytesPatched += row.Length;
        rewrites.push_back({ row.Rva, row.Mn, true, row.Length, 0, false });
    }

    if (!perrva.empty())
    {
        const std::filesystem::path opaquespath = ctx.Store->Dir() / L"opaques.txt";
        std::ofstream of(opaquespath, std::ios::trunc);
        if (of)
        {
            of << "# site va  rva  mn  target_rva  taken  ntaken  verdict  outcome\n";
            {
                char b[24];
                std::snprintf(b, sizeof(b), "%llx", static_cast<unsigned long long>(ctx.PreferredBase));
                of << b;
            }
            of << "\n\n";

            std::unordered_map<uint64_t, const RewriteRow*> rewritebyrva;
            rewritebyrva.reserve(rewrites.size());
            for (const RewriteRow& rw : rewrites) rewritebyrva.emplace(rw.Rva, &rw);

            std::vector<Row> allrows;
            allrows.reserve(alwaystakenlist.size() + alwaysntakenlist.size() + mixedlist.size());
            allrows.insert(allrows.end(), alwaystakenlist.begin(), alwaystakenlist.end());
            allrows.insert(allrows.end(), alwaysntakenlist.begin(), alwaysntakenlist.end());
            allrows.insert(allrows.end(), mixedlist.begin(), mixedlist.end());
            std::sort(allrows.begin(), allrows.end(),
                [](const Row& a, const Row& b) { return a.Rva < b.Rva; });

            for (const Row& row : allrows)
            {
                const uint64_t siteva = ctx.PreferredBase + row.Rva;
                const bool at_ = (row.Ntaken == 0 && row.Taken > 0);
                const bool an_ = (row.Taken == 0 && row.Ntaken > 0);
                const char* verdict =
                    at_ ? "always-taken" :
                    an_ ? "always-not-taken" : "mixed";

                char head[320];
                std::snprintf(head, sizeof(head),
                    "site va=0x%llx  rva=0x%08llx  %-4s  to=0x%08llx  taken=%-6u  ntaken=%-6u  %-16s",
                    static_cast<unsigned long long>(siteva),
                    static_cast<unsigned long long>(row.Rva),
                    row.Mn,
                    static_cast<unsigned long long>(row.ToRva),
                    row.Taken, row.Ntaken, verdict);
                of << head;

                auto it = rewritebyrva.find(row.Rva);
                if (it != rewritebyrva.end())
                {
                    const RewriteRow* rw = it->second;
                    char tail[192];
                    if (!rw->Ok)
                    {
                        std::snprintf(tail, sizeof(tail),
                            "  -> SKIPPED (encoder rejected, slot=%u)", rw->Slot);
                    }
                    else if (rw->Taken)
                    {
                        std::snprintf(tail, sizeof(tail),
                            "  -> JMP 0x%llx  (slot=%u)",
                            static_cast<unsigned long long>(rw->Target), rw->Slot);
                    }
                    else
                    {
                        std::snprintf(tail, sizeof(tail),
                            "  -> NOP*%u (fall through)", rw->Slot);
                    }
                    of << tail;
                }
                else
                {
                    of << "  -> (kept: real conditional)";
                }
                of << "\n";
            }
            r.OpaqueJccLogPath = opaquespath;
        }
    }

    PrintRewrite(r, rewrites);
}