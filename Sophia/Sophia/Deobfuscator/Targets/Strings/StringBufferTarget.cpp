#include "../../../../Pch.h"
#include "StringBufferTarget.h"
#include "../../DeobfEncoders.h"
#include "../../DeobfIo.h"
#include "../../../Database/AutoDebugStore.h"

#include <windows.h>
#include <Zydis/Zydis.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <utility>
#include <vector>

namespace
{
    struct BufRow
    {
        uint64_t             Addr;
        uint64_t             Rva;
        bool                 FromStr;
        bool                 FromVec;
        bool                 RipRel;
        const char* Mn;
        std::vector<uint8_t> Content;
        bool                 Mixed;
        bool                 InImage;
        uint64_t             EstRva;
        uint64_t             FileOff;
        uint32_t             PatchLen;
        bool                 AlreadyPlaintext;
        bool                 Patched;
    };
}

void StringBufferTarget::Deobfuscate(DeobfContext& ctx, Deobfuscator::Report& r)
{
    auto& bufbyaddr = ctx.BufByAddr;
    auto& vecsitebyrva = ctx.VecSiteByRva;

    ctx.Store->ForEachRecord(ObsKind::String,
        [&](const void* rec, size_t sz)
        {
            ++r.StrRecordsSeen;
            if (sz != sizeof(StringHit)) return;
            const StringHit* h = static_cast<const StringHit*>(rec);
            if (h->Addr == 0) { ++r.BufAddrFailed; return; }

            auto& g = bufbyaddr[h->Addr];
            if (g.ObsCount == 0)
            {
                g.FirstRva = h->Rva;
                const uint64_t off = ctx.Sm.RvaToOffset(h->Rva);
                if (off != UINT64_MAX)
                {
                    size_t avail = ctx.PreMovRewriteBuf.size() - off;
                    if (avail > 15) avail = 15;
                    ZydisDecodedInstruction insn;
                    ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
                    if (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&ctx.Decoder, ctx.PreMovRewriteBuf.data() + off, avail, &insn, ops)))
                    {
                        const char* mstr = ZydisMnemonicGetString(insn.mnemonic);
                        if (mstr) std::strncpy(g.Mn, mstr, sizeof(g.Mn) - 1);
                    }
                }
            }
            g.FromStr = true;
            ++g.ObsCount;

            const uint16_t ew = DeobfEncoders::StringElemWidth(g.Mn);
            uint64_t effbytes = h->LenRcx * static_cast<uint64_t>(ew);
            if (effbytes == 0) effbytes = 8;
            if (effbytes > 64) effbytes = 64;

            const uint8_t* obs = reinterpret_cast<const uint8_t*>(h->Window);
            if (g.Mixed) return;
            if (!DeobfEncoders::MergePrefixConsistent(g.Canonical, obs, static_cast<size_t>(effbytes)))
            {
                g.Mixed = true;
            }
            if (effbytes > g.LenHint) g.LenHint = effbytes;
        });

    ctx.Store->ForEachRecord(ObsKind::Vec,
        [&](const void* rec, size_t sz)
        {
            ++r.VecRecordsSeen;
            if (sz != sizeof(VecHit)) return;
            const VecHit* h = static_cast<const VecHit*>(rec);

            const uint64_t off = ctx.Sm.RvaToOffset(h->Rva);
            if (off == UINT64_MAX) { ++r.BufAddrFailed; return; }
            size_t avail = ctx.PreMovRewriteBuf.size() - off;
            if (avail > 15) avail = 15;
            ZydisDecodedInstruction insn;
            ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
            if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&ctx.Decoder, ctx.PreMovRewriteBuf.data() + off, avail, &insn, ops)))
            {
                ++r.BufAddrFailed;
                return;
            }
            bool riprel = false;
            const uint64_t addr = DeobfEncoders::ReconstructVecAddr(h->Rva, insn, ops, h->Gpr, riprel);
            if (addr == 0) { ++r.BufAddrFailed; return; }

            auto& g = bufbyaddr[addr];
            if (g.ObsCount == 0)
            {
                g.FirstRva = h->Rva;
                const char* mstr = ZydisMnemonicGetString(insn.mnemonic);
                if (mstr) std::strncpy(g.Mn, mstr, sizeof(g.Mn) - 1);
            }
            g.FromVec = true;
            if (riprel) g.RipRel = true;
            ++g.ObsCount;

            auto siteit = vecsitebyrva.find(h->Rva);
            if (siteit == vecsitebyrva.end())
            {
                VecSiteInfo si;
                si.SiteRva = h->Rva;
                si.InsnLength = insn.length;
                si.SiteFileOff = off;
                si.RipRel = riprel;
                siteit = vecsitebyrva.emplace(h->Rva, si).first;
            }
            siteit->second.AddrsSeen.insert(addr);

            const uint16_t nq = h->NQwords > 4 ? 4 : h->NQwords;
            const size_t effbytes = static_cast<size_t>(nq) * 8;
            const uint8_t* obs = reinterpret_cast<const uint8_t*>(h->Window);
            if (g.Mixed) return;
            if (effbytes > 0 && !DeobfEncoders::MergePrefixConsistent(g.Canonical, obs, effbytes))
            {
                g.Mixed = true;
            }
            if (effbytes > g.LenHint) g.LenHint = effbytes;
        });

    r.BufAddrsObserved = static_cast<uint32_t>(bufbyaddr.size());
    r.BufModeDelta = ctx.PreferredBase;

    std::vector<BufRow> bufrows;
    bufrows.reserve(bufbyaddr.size());

    for (auto& [addr, g] : bufbyaddr)
    {
        BufRow row{};
        row.Addr = addr;
        row.Rva = g.FirstRva;
        row.FromStr = g.FromStr;
        row.FromVec = g.FromVec;
        row.RipRel = g.RipRel;
        row.Mn = g.Mn;
        row.Content = g.Canonical;
        row.Mixed = g.Mixed;

        uint64_t candrva = 0;
        bool     rvaok = false;
        if (row.RipRel)
        {
            candrva = row.Addr;
            rvaok = true;
        }
        else if (row.Addr >= r.BufModeDelta)
        {
            candrva = row.Addr - r.BufModeDelta;
            rvaok = true;
        }

        const DeobfSection* sec = rvaok ? ctx.Sm.Find(candrva) : nullptr;
        if (!sec || !DeobfEncoders::IsPatchableDataSection(*sec))
        {
            ++r.BufOutOfImage;
            bufrows.push_back(std::move(row));
            continue;
        }
        ++r.BufInImage;
        row.InImage = true;
        row.EstRva = candrva;

        const uint64_t fo = ctx.Sm.RvaToOffset(candrva);
        if (fo == UINT64_MAX)
        {
            ++r.BufPatchSkip;
            bufrows.push_back(std::move(row));
            continue;
        }
        row.FileOff = fo;

        if (row.Mixed)
        {
            ++r.BufMixed;
            ++r.BufPatchSkip;
            bufrows.push_back(std::move(row));
            continue;
        }
        ++r.BufMonopoly;

        const uint64_t sectionremaining = static_cast<uint64_t>(sec->RawSize) - (candrva - sec->Rva);
        size_t patchlen = row.Content.size();
        if (patchlen > sectionremaining) patchlen = static_cast<size_t>(sectionremaining);
        if (fo + patchlen > ctx.Buf.size()) patchlen = ctx.Buf.size() - fo;
        if (patchlen == 0)
        {
            ++r.BufPatchSkip;
            bufrows.push_back(std::move(row));
            continue;
        }

        if (std::memcmp(ctx.Buf.data() + fo, row.Content.data(), patchlen) == 0)
        {
            ++r.BufAlreadyPlaintext;
            row.AlreadyPlaintext = true;
            bufrows.push_back(std::move(row));
            continue;
        }

        std::memcpy(ctx.Buf.data() + fo, row.Content.data(), patchlen);
        ++r.BufPatchOk;
        r.BufBytesPatched += static_cast<uint64_t>(patchlen);
        row.Patched = true;
        row.PatchLen = static_cast<uint32_t>(patchlen);
        bufrows.push_back(std::move(row));
    }

    std::sort(bufrows.begin(), bufrows.end(),
        [](const BufRow& a, const BufRow& b) { return a.Addr < b.Addr; });

    const std::filesystem::path stringspath = ctx.Store->Dir() / L"strings.txt";
    {
        std::ofstream of(stringspath, std::ios::trunc);
        if (of)
        {
            of << "# addr | site_rva | src | mnemonic | in_image | est_rva | patch | len | content\n";
            for (const BufRow& row : bufrows)
            {
                const char* src = (row.FromStr && row.FromVec) ? "str+vec" : row.FromStr ? "str" : "vec";
                const char* imgtag = row.InImage ? (row.RipRel ? "yes(rip)" : "yes") : "no";
                char estbuf[24];
                if (row.InImage)
                {
                    std::snprintf(estbuf, sizeof(estbuf), "0x%llx", static_cast<unsigned long long>(row.EstRva));
                }
                else
                {
                    std::strncpy(estbuf, "-", sizeof(estbuf));
                }
                const char* patchtag =
                    row.Mixed ? "mixed" :
                    row.AlreadyPlaintext ? "same" :
                    row.Patched ? "ok" :
                    row.InImage ? "skip" : "-";
                std::string decoded = row.Content.empty() ? std::string("(empty)") : DeobfEncoders::DecodeBufferBytes(row.Content.data(), row.Content.size());

                char head[320];
                std::snprintf(head, sizeof(head),
                    "addr=0x%016llx  rva=0x%08llx  src=%-7s  mn=%-8s  in_image=%-9s  est_rva=%-14s  patch=%-5s  len=%-4zu  ",
                    static_cast<unsigned long long>(row.Addr),
                    static_cast<unsigned long long>(row.Rva),
                    src, row.Mn[0] ? row.Mn : "?",
                    imgtag, estbuf, patchtag, row.Content.size());
                of << head << decoded << "\n";
            }
        }
        else
        {
            std::fprintf(stderr, "[deobf] string-buffer: could not open %ls for write\n", stringspath.wstring().c_str());
        }
    }
    r.StringsLogPath = stringspath;

    DeobfIo::RuleOpen("string-buffer -- recovery");
    std::printf("[deobf]   StringHit records read         : %llu\n", static_cast<unsigned long long>(r.StrRecordsSeen));
    std::printf("[deobf]   VecHit records read            : %llu\n", static_cast<unsigned long long>(r.VecRecordsSeen));
    std::printf("[deobf]   addr reconstruction failed     : %u\n", r.BufAddrFailed);
    std::printf("[deobf]   distinct addrs observed        : %u\n", r.BufAddrsObserved);
    std::printf("[deobf]   in-image (data section)        : %u\n", r.BufInImage);
    std::printf("[deobf]   out-of-image (stack/heap/other): %u\n", r.BufOutOfImage);
    std::printf("[deobf]   monopoly (in-image)            : %u\n", r.BufMonopoly);
    std::printf("[deobf]   mixed (in-image)               : %u\n", r.BufMixed);
    std::printf("[deobf]   already plaintext (in-image)   : %u\n", r.BufAlreadyPlaintext);
    std::printf("[deobf]   patched                        : %u\n", r.BufPatchOk);
    std::printf("[deobf]   skipped                        : %u\n", r.BufPatchSkip);
    std::printf("[deobf]   bytes patched                  : %llu\n", static_cast<unsigned long long>(r.BufBytesPatched));
    std::printf("[deobf]   modeDelta (runtime base used)  : 0x%llx\n", static_cast<unsigned long long>(r.BufModeDelta));
    std::printf("[deobf]   log                            : %ls\n", stringspath.wstring().c_str());

    constexpr size_t kbufsamplecap = 20;
    if (!bufrows.empty())
    {
        const size_t show = bufrows.size() < kbufsamplecap ? bufrows.size() : kbufsamplecap;
        std::printf("[deobf] buffer sample (showing %zu of %zu, full log in strings.txt):\n", show, bufrows.size());
        for (size_t i = 0; i < show; ++i)
        {
            const BufRow& row = bufrows[i];
            std::string decoded = row.Content.empty() ? std::string("(empty)") : DeobfEncoders::DecodeBufferBytes(row.Content.data(), row.Content.size());
            if (decoded.size() > 64) decoded = decoded.substr(0, 61) + "...";
            const char* src = (row.FromStr && row.FromVec) ? "str+vec" : row.FromStr ? "str" : "vec";
            std::printf("[deobf]   addr=0x%016llx  %-7s  %-8s  %s\n",
                static_cast<unsigned long long>(row.Addr), src, row.Mn[0] ? row.Mn : "?", decoded.c_str());
        }
    }
    DeobfIo::RuleClose();
}