#include "../../../../Pch.h"
#include "IndBranchTarget.h"
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
#include <unordered_set>
#include <vector>

namespace
{
    struct IndTally
    {
        std::unordered_set<uint64_t> Targets;
        uint32_t                     Length = 0;
        uint64_t                     FileOff = 0;
        bool                         IsCall = false;
        char                         Mn[16] = {};
    };

    struct IndRewriteRow
    {
        uint64_t    Rva;
        const char* Mn;
        uint32_t    Slot;
        uint64_t    Target;
        bool        IsCall;
        bool        Ok;
    };

    struct IndSidecarRow
    {
        uint64_t              Rva;
        const char* Mn;
        uint32_t              Slot;
        bool                  IsCall;
        bool                  IsMixed;
        bool                  Ok;               // meaningful only when !IsMixed
        uint64_t              Target;           // meaningful only when !IsMixed
        std::vector<uint64_t> MixedTargets;     // populated only when IsMixed
    };

    void PrintReport(const Deobfuscator::Report& r, const std::vector<IndRewriteRow>& indrewrites)
    {
        DeobfIo::RuleOpen("indirect-branch -- resolution");
        std::printf("[deobf]   IndHit records read            : %llu\n", static_cast<unsigned long long>(r.IndRecordsSeen));
        std::printf("[deobf]   indirect sites observed        : %u\n", r.IndObserved);
        std::printf("[deobf]   monopoly (candidate)           : %u\n", r.IndMonopoly);
        std::printf("[deobf]   mixed (dispatch table)         : %u\n", r.IndMixed);
        std::printf("[deobf]   rewritten                      : %u\n", r.IndRewriteOk);
        std::printf("[deobf]   skipped                        : %u\n", r.IndRewriteSkip);
        std::printf("[deobf]   bytes patched                  : %llu\n", static_cast<unsigned long long>(r.IndBytesPatched));
        if (!r.IndCallsLogPath.empty())
        {
            std::printf("[deobf]   indcalls log                   : %ls\n", r.IndCallsLogPath.wstring().c_str());
        }
        if (!r.IndBranchesLogPath.empty())
        {
            std::printf("[deobf]   indbranches log                : %ls\n", r.IndBranchesLogPath.wstring().c_str());
        }

        if (!indrewrites.empty())
        {
            std::printf("[deobf] indirect rewrite log (all %zu site(s)):\n", indrewrites.size());
            for (const IndRewriteRow& rw : indrewrites)
            {
                const char* verb = rw.IsCall ? "CALL" : "JMP";
                if (!rw.Ok)
                {
                    std::printf("[deobf]   rva=0x%08llx  %-5s  slot=%u  SKIPPED (slot too small for %s -> 0x%llx)\n",
                        static_cast<unsigned long long>(rw.Rva), rw.Mn, rw.Slot, verb,
                        static_cast<unsigned long long>(rw.Target));
                }
                else
                {
                    std::printf("[deobf]   rva=0x%08llx  %-5s  slot=%u  -> %s 0x%llx\n",
                        static_cast<unsigned long long>(rw.Rva), rw.Mn, rw.Slot, verb,
                        static_cast<unsigned long long>(rw.Target));
                }
            }
        }
        DeobfIo::RuleClose();
    }
}

void IndBranchTarget::Deobfuscate(DeobfContext& ctx, Deobfuscator::Report& r)
{
    if (!ctx.Cfg.WantIndBranch && !ctx.Cfg.WantIndCall)
    {
        DeobfIo::PrintSkip("indirect-branch", "by user (both indirect kinds disabled)");
        return;
    }

    std::unordered_map<uint64_t, IndTally> indperrva;

    auto ingestindkind = [&](ObsKind kind, bool iscall)
        {
            ctx.Store->ForEachRecord(kind,
                [&](const void* rec, size_t sz)
                {
                    ++r.IndRecordsSeen;
                    if (sz != sizeof(IndBranchHit)) return;
                    const IndBranchHit* h = static_cast<const IndBranchHit*>(rec);

                    auto pit = indperrva.find(h->Rva);
                    IndTally* tp = nullptr;
                    if (pit != indperrva.end())
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
                        IndTally fresh;
                        fresh.Length = insn.length;
                        fresh.FileOff = off;
                        fresh.IsCall = iscall;
                        const char* mstr = ZydisMnemonicGetString(insn.mnemonic);
                        if (mstr)
                        {
                            std::strncpy(fresh.Mn, mstr, sizeof(fresh.Mn) - 1);
                        }
                        auto ins = indperrva.emplace(h->Rva, fresh);
                        tp = &ins.first->second;
                    }
                    tp->Targets.insert(h->Target);
                });
        };
    ingestindkind(ObsKind::IndBranch, false);
    ingestindkind(ObsKind::IndCall, true);

    r.IndObserved = static_cast<uint32_t>(indperrva.size());

    std::vector<IndRewriteRow> indrewrites;
    indrewrites.reserve(indperrva.size());
    std::vector<IndSidecarRow> sidecar;
    sidecar.reserve(indperrva.size());

    for (const auto& [rva, t] : indperrva)
    {
        if (t.Targets.size() != 1)
        {
            ++r.IndMixed;
            IndSidecarRow scr;
            scr.Rva = rva;
            scr.Mn = t.Mn;
            scr.Slot = t.Length;
            scr.IsCall = t.IsCall;
            scr.IsMixed = true;
            scr.Ok = false;
            scr.Target = 0;
            scr.MixedTargets.assign(t.Targets.begin(), t.Targets.end());
            std::sort(scr.MixedTargets.begin(), scr.MixedTargets.end());
            sidecar.push_back(std::move(scr));
            continue;
        }
        ++r.IndMonopoly;
        const uint64_t target = *t.Targets.begin();

        IndSidecarRow scr;
        scr.Rva = rva;
        scr.Mn = t.Mn;
        scr.Slot = t.Length;
        scr.IsCall = t.IsCall;
        scr.IsMixed = false;
        scr.Target = target;

        if (t.FileOff + t.Length > ctx.Buf.size())
        {
            ++r.IndRewriteSkip;
            indrewrites.push_back({ rva, t.Mn, t.Length, target, t.IsCall, false });
            scr.Ok = false;
            sidecar.push_back(std::move(scr));
            continue;
        }

        const bool ok = t.IsCall
            ? DeobfEncoders::EmitDirectCall(ctx.Buf, t.FileOff, t.Length, rva, target)
            : DeobfEncoders::EmitDirectJmp(ctx.Buf, t.FileOff, t.Length, rva, target);
        if (ok)
        {
            ++r.IndRewriteOk;
            r.IndBytesPatched += t.Length;
        }
        else
        {
            ++r.IndRewriteSkip;
        }
        indrewrites.push_back({ rva, t.Mn, t.Length, target, t.IsCall, ok });
        scr.Ok = ok;
        sidecar.push_back(std::move(scr));
    }

    std::sort(indrewrites.begin(), indrewrites.end(),
        [](const IndRewriteRow& a, const IndRewriteRow& b) { return a.Rva < b.Rva; });

    auto writesidecar = [&](bool iscall, const wchar_t* filename, std::filesystem::path& outpath)
        {
            std::vector<const IndSidecarRow*> rows;
            rows.reserve(sidecar.size());
            for (const IndSidecarRow& s : sidecar)
            {
                if (s.IsCall == iscall) rows.push_back(&s);
            }
            if (rows.empty()) return;
            std::sort(rows.begin(), rows.end(),
                [](const IndSidecarRow* a, const IndSidecarRow* b) { return a->Rva < b->Rva; });

            const std::filesystem::path p = ctx.Store->Dir() / filename;
            std::ofstream of(p, std::ios::trunc);
            if (!of) return;

            of << (iscall
                ? "# indirect CALL sites  (site va  rva  mn  slot  distinct  outcome)\n"
                : "# indirect JMP  sites  (site va  rva  mn  slot  distinct  outcome)\n");
            {
                char b[24];
                std::snprintf(b, sizeof(b), "%llx", static_cast<unsigned long long>(ctx.PreferredBase));
                of << b;
            }
            of << "\n\n";

            const char* verb = iscall ? "CALL" : "JMP";
            for (const IndSidecarRow* s : rows)
            {
                const uint64_t siteva = ctx.PreferredBase + s->Rva;
                if (s->IsMixed)
                {
                    char head[320];
                    std::snprintf(head, sizeof(head),
                        "site va=0x%llx  rva=0x%08llx  %-5s  slot=%u  distinct=%zu  MIXED (dispatch table, kept)\n",
                        static_cast<unsigned long long>(siteva),
                        static_cast<unsigned long long>(s->Rva),
                        s->Mn, s->Slot, s->MixedTargets.size());
                    of << head;
                    for (uint64_t tg : s->MixedTargets)
                    {
                        const uint64_t tgva = ctx.PreferredBase + tg;
                        char line[128];
                        std::snprintf(line, sizeof(line),
                            "    target va=0x%llx  rva=0x%08llx\n",
                            static_cast<unsigned long long>(tgva),
                            static_cast<unsigned long long>(tg));
                        of << line;
                    }
                }
                else if (s->Ok)
                {
                    char head[320];
                    std::snprintf(head, sizeof(head),
                        "site va=0x%llx  rva=0x%08llx  %-5s  slot=%u  distinct=1  -> %s 0x%llx\n",
                        static_cast<unsigned long long>(siteva),
                        static_cast<unsigned long long>(s->Rva),
                        s->Mn, s->Slot, verb,
                        static_cast<unsigned long long>(s->Target));
                    of << head;
                }
                else
                {
                    char head[320];
                    std::snprintf(head, sizeof(head),
                        "site va=0x%llx  rva=0x%08llx  %-5s  slot=%u  distinct=1  SKIPPED (slot too small for %s -> 0x%llx)\n",
                        static_cast<unsigned long long>(siteva),
                        static_cast<unsigned long long>(s->Rva),
                        s->Mn, s->Slot, verb,
                        static_cast<unsigned long long>(s->Target));
                    of << head;
                }
            }
            outpath = p;
        };

    writesidecar(true, L"indcalls.txt", r.IndCallsLogPath);
    writesidecar(false, L"indbranches.txt", r.IndBranchesLogPath);

    PrintReport(r, indrewrites);
}