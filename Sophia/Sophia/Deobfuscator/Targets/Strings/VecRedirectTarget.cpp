#include "../../../../Pch.h"
#include "VecRedirectTarget.h"
#include "../../DeobfEncoders.h"
#include "../../DeobfIo.h"
#include "../../../Database/AutoDebugStore.h"
#include "../../../WinPE/SectionManager.h"

#include <windows.h>
#include <Zydis/Zydis.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <vector>

namespace
{
    struct AddrContent
    {
        uint64_t Addr;
        const std::vector<uint8_t>* Content;
        bool     InImage;
        uint32_t InImageRva;
    };

    struct RedirectRow
    {
        uint64_t SiteRva;
        uint32_t Slot;
        uint32_t EncLen;
        uint32_t TargetRva;
        uint32_t NAddrs;
        uint32_t ContentBytes;
        const char* Mn;
        const std::vector<uint8_t>* FirstContent;
        uint64_t FirstAddr;
        bool     ViaTramp;
        uint32_t Consumed;
    };

    struct RedirectDeferred
    {
        uint64_t SiteFileOff;
        uint32_t SiteLen;
        uint64_t SiteRva;
        uint32_t TargetRva;
        size_t   RedirRowIdx;
    };

    void EmitOneString(std::vector<uint8_t>& redirectcontent, const std::vector<uint8_t>& c)
    {
        size_t asciilen = 0;
        while (asciilen < c.size() && c[asciilen] != 0)
        {
            const uint8_t b = c[asciilen];
            if (!((b >= 0x20 && b <= 0x7E) || b == '\t' || b == '\n' || b == '\r'))
            {
                break;
            }
            ++asciilen;
        }
        if (asciilen >= 4)
        {
            redirectcontent.insert(redirectcontent.end(), c.begin(), c.begin() + asciilen);
            redirectcontent.push_back(0);
        }
        else
        {
            size_t u16chars = 0;
            for (size_t i = 0; i + 1 < c.size(); i += 2)
            {
                const uint8_t lo = c[i], hi = c[i + 1];
                if (lo == 0 && hi == 0) break;
                if (hi != 0 || !((lo >= 0x20 && lo <= 0x7E) || lo == '\t' || lo == '\n' || lo == '\r'))
                {
                    break;
                }
                ++u16chars;
            }
            const size_t u16bytes = u16chars * 2;
            redirectcontent.insert(redirectcontent.end(), c.begin(), c.begin() + u16bytes);
            redirectcontent.push_back(0);
            redirectcontent.push_back(0);
        }
    }
}

void VecRedirectTarget::Deobfuscate(DeobfContext& ctx, Deobfuscator::Report& r)
{
    auto& bufbyaddr = ctx.BufByAddr;
    auto& vecsitebyrva = ctx.VecSiteByRva;

    const HeaderSlackInfo slack = DeobfEncoders::CheckHeaderSlack(ctx.Buf);
    if (!slack.HaveSlack)
    {
        r.NoHeaderSlack = true;
        DeobfIo::RuleOpen("vec-redirect");
        std::puts("[deobf]   SKIPPED: no header slack -- section table has no room for another IMAGE_SECTION_HEADER without shifting the first section's raw offset.");
        DeobfIo::RuleClose();
        return;
    }

    const uint32_t predictedsectionrva = slack.PredictedRva;

    constexpr size_t kredirlign = 16;
    std::vector<uint8_t> redirectcontent;
    redirectcontent.reserve(2048);

    std::vector<RedirectRow> redirectrows;
    redirectrows.reserve(vecsitebyrva.size());
    std::vector<RedirectDeferred> redirdeferred;

    std::vector<uint64_t> siterva;
    siterva.reserve(vecsitebyrva.size());
    for (const auto& [rva, si] : vecsitebyrva) siterva.push_back(rva);
    std::sort(siterva.begin(), siterva.end());

    for (uint64_t sitervaval : siterva)
    {
        const VecSiteInfo& si = vecsitebyrva.at(sitervaval);

        std::vector<AddrContent> packitems;
        packitems.reserve(si.AddrsSeen.size());
        for (uint64_t addr : si.AddrsSeen)
        {
            auto btit = bufbyaddr.find(addr);
            if (btit == bufbyaddr.end()) continue;
            const BufTally& bt = btit->second;
            if (bt.Mixed) continue;

            bool     inimage = false;
            uint32_t inimagerva = 0;
            {
                uint64_t candrva = 0;
                bool     rvaok = false;
                if (bt.RipRel) { candrva = addr; rvaok = true; }
                else if (addr >= r.BufModeDelta)
                {
                    candrva = addr - r.BufModeDelta;
                    rvaok = true;
                }
                if (rvaok)
                {
                    const DeobfSection* sec = ctx.Sm.Find(candrva);
                    if (sec && DeobfEncoders::IsPatchableDataSection(*sec))
                    {
                        inimage = true;
                        inimagerva = static_cast<uint32_t>(candrva);
                    }
                }
            }

            if (!DeobfEncoders::IsRedirectableString(bt.Canonical)) continue;

            packitems.push_back({ addr, &bt.Canonical, inimage, inimagerva });
        }

        if (packitems.empty())
        {
            ++r.RedirectSkipContent;
            continue;
        }

        ++r.RedirectCandidates;

        std::sort(packitems.begin(), packitems.end(),
            [](const AddrContent& a, const AddrContent& b) { return a.Addr < b.Addr; });

        while (redirectcontent.size() % kredirlign != 0) redirectcontent.push_back(0);
        const uint64_t startoffset = redirectcontent.size();
        const uint64_t contentbefore = startoffset;

        uint32_t targetrva = 0;
        if (packitems.size() == 1 && packitems.front().InImage)
        {
            targetrva = packitems.front().InImageRva;
        }
        else
        {
            targetrva = predictedsectionrva + static_cast<uint32_t>(startoffset);
        }

        constexpr uint8_t  kleascratchreg = 0;
        constexpr uint32_t kleaenclen = 7;
        uint32_t enclen = 0;
        bool     redirdefer = false;
        if (si.InsnLength >= kleaenclen)
        {
            if (!DeobfEncoders::EmitLeaRegRipRel(ctx.Buf, si.SiteFileOff, si.InsnLength, kleascratchreg, targetrva, si.SiteRva))
            {
                ++r.RedirectSkipReach;
                continue;
            }
            enclen = kleaenclen;
        }
        else
        {
            redirdefer = true;
            enclen = kleaenclen;
        }

        if (packitems.size() == 1)
        {
            const AddrContent& item = packitems.front();
            if (!item.InImage)
            {
                EmitOneString(redirectcontent, *item.Content);
            }
        }
        else
        {
            const uint64_t ptrtableoffset = redirectcontent.size();
            const size_t   ptrtablebytes = packitems.size() * 8;
            redirectcontent.insert(redirectcontent.end(), ptrtablebytes, 0);

            std::vector<uint32_t> stringrvas;
            stringrvas.reserve(packitems.size());
            for (const AddrContent& item : packitems)
            {
                if (item.InImage)
                {
                    stringrvas.push_back(item.InImageRva);
                }
                else
                {
                    while (redirectcontent.size() % kredirlign != 0) redirectcontent.push_back(0);
                    stringrvas.push_back(predictedsectionrva + static_cast<uint32_t>(redirectcontent.size()));
                    EmitOneString(redirectcontent, *item.Content);
                }
            }

            for (size_t i = 0; i < packitems.size(); ++i)
            {
                const uint64_t va = r.BufModeDelta + static_cast<uint64_t>(stringrvas[i]);
                std::memcpy(redirectcontent.data() + ptrtableoffset + i * 8, &va, 8);
            }
        }

        const uint32_t packedbytes = static_cast<uint32_t>(redirectcontent.size() - contentbefore);

        if (!redirdefer)
        {
            ++r.RedirectOk;
            if (packitems.size() > 1) ++r.RedirectMultiAddrSites;
        }
        r.RedirectStringsPacked += static_cast<uint32_t>(packitems.size());

        const auto btfirstit = bufbyaddr.find(packitems.front().Addr);
        const char* mnborrow = (btfirstit != bufbyaddr.end()) ? btfirstit->second.Mn : "";
        RedirectRow rw{};
        rw.SiteRva = si.SiteRva;
        rw.Slot = si.InsnLength;
        rw.EncLen = enclen;
        rw.TargetRva = targetrva;
        rw.NAddrs = static_cast<uint32_t>(packitems.size());
        rw.ContentBytes = packedbytes;
        rw.Mn = mnborrow;
        rw.FirstContent = packitems.front().Content;
        rw.FirstAddr = packitems.front().Addr;
        rw.ViaTramp = redirdefer;
        rw.Consumed = si.InsnLength;
        redirectrows.push_back(rw);
        if (redirdefer)
        {
            RedirectDeferred d{};
            d.SiteFileOff = si.SiteFileOff;
            d.SiteLen = si.InsnLength;
            d.SiteRva = si.SiteRva;
            d.TargetRva = targetrva;
            d.RedirRowIdx = redirectrows.size() - 1;
            redirdeferred.push_back(d);
        }
    }

    if (!redirectcontent.empty())
    {
        uint32_t appendedrva = 0;
        if (SectionManager::AppendPeSection(ctx.Buf, ".sophstr", redirectcontent, appendedrva))
        {
            if (appendedrva != predictedsectionrva)
            {
                std::fprintf(stderr, "[deobf] vec-redirect: WARN predicted section RVA 0x%x doesn't match appended 0x%x -- rewrites may point at wrong bytes\n",
                    predictedsectionrva, appendedrva);
            }
            r.RedirectSectionRva = appendedrva;
            r.RedirectSectionBytes = static_cast<uint32_t>(redirectcontent.size());
            std::strncpy(r.RedirectSectionName, ".sophstr", sizeof(r.RedirectSectionName) - 1);
        }
        else
        {
            std::fprintf(stderr, "[deobf] vec-redirect: AppendPeSection failed after slack check succeeded -- structural mismatch, dropping redirect (rewrites already applied are stale)\n");
        }
    }

    if (!redirdeferred.empty())
    {
        const HeaderSlackInfo vecslack = DeobfEncoders::CheckHeaderSlack(ctx.Buf);
        if (!vecslack.HaveSlack)
        {
            r.VecTrampNoHeaderSlack = true;
            std::puts("[deobf]   no header slack for .sophvec -- deferred sub-7B sites left with original bytes");
            for (const RedirectDeferred& d : redirdeferred)
            {
                RedirectRow& rw = redirectrows[d.RedirRowIdx];
                rw.ViaTramp = false;
                ++r.RedirectSkipReach;
            }
        }
        else
        {
            TrampolineBuilder vectramp(ctx.Buf, ctx.Decoder, vecslack.PredictedRva);
            for (const RedirectDeferred& d : redirdeferred)
            {
                RedirectRow& rw = redirectrows[d.RedirRowIdx];
                const uint32_t tgt = d.TargetRva;
                const bool okt = vectramp.TryTrampoline(d.SiteFileOff, d.SiteLen, d.SiteRva, 7,
                    [tgt](uint8_t* out, uint32_t cap, uint64_t at)
                    {
                        return DeobfEncoders::EncLeaRipRel(out, cap, 0, tgt, at);
                    });
                if (okt)
                {
                    rw.Consumed = vectramp.Sites().back().Consumed;
                    ++r.RedirectOk;
                    if (rw.NAddrs > 1) ++r.RedirectMultiAddrSites;
                }
                else
                {
                    rw.ViaTramp = false;
                    ++r.RedirectSkipReach;
                }
            }
            if (!vectramp.Blob().empty())
            {
                uint32_t appendedrva = 0;
                const uint32_t chars = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE;
                if (SectionManager::AppendPeSection(ctx.Buf, ".sophvec", vectramp.Blob(), appendedrva, chars))
                {
                    if (appendedrva != vectramp.PredictedSectionRva())
                    {
                        std::fprintf(stderr, "[deobf] vec-redirect: WARN predicted .sophvec RVA 0x%x != appended 0x%x\n",
                            vectramp.PredictedSectionRva(), appendedrva);
                    }
                    vectramp.EmitOutbounds();
                    r.VecTrampSectionRva = appendedrva;
                    r.VecTrampSectionBytes = static_cast<uint32_t>(vectramp.Blob().size());
                    r.VecTrampBytesSaved = vectramp.BytesSaved();
                    r.VecTrampSites = static_cast<uint32_t>(vectramp.Sites().size());
                    std::strncpy(r.VecTrampSectionName, ".sophvec", sizeof(r.VecTrampSectionName) - 1);
                }
                else
                {
                    std::fprintf(stderr, "[deobf] vec-redirect: AppendPeSection .sophvec FAILED -- %zu trampolined sites left un-rewritten\n", vectramp.Sites().size());
                    r.RedirectOk -= static_cast<uint32_t>(vectramp.Sites().size());
                    for (const RedirectDeferred& d : redirdeferred)
                    {
                        RedirectRow& rw = redirectrows[d.RedirRowIdx];
                        if (rw.ViaTramp)
                        {
                            rw.ViaTramp = false;
                            ++r.RedirectSkipReach;
                        }
                    }
                }
            }
        }
    }

    DeobfIo::RuleOpen("vec-redirect");
    std::printf("[deobf]   redirect candidates              : %u\n", r.RedirectCandidates);
    std::printf("[deobf]   redirected (RIP-rel rewrite)     : %u\n", r.RedirectOk);
    std::printf("[deobf]     of which multi-addr bundles    : %u\n", r.RedirectMultiAddrSites);
    std::printf("[deobf]   total strings packed             : %u\n", r.RedirectStringsPacked);
    std::printf("[deobf]   skipped: no string-like content  : %u\n", r.RedirectSkipContent);
    std::printf("[deobf]   skipped: out of RIP-rel reach    : %u\n", r.RedirectSkipReach);
    if (r.RedirectSectionBytes)
    {
        std::printf("[deobf]   .sophstr section RVA             : 0x%llx\n", static_cast<unsigned long long>(r.RedirectSectionRva));
        std::printf("[deobf]   .sophstr section bytes           : %u\n", r.RedirectSectionBytes);
    }
    std::printf("[deobf]   sub-7B sites trampolined         : %u\n", r.VecTrampSites);
    if (r.VecTrampNoHeaderSlack)
    {
        std::puts("[deobf]   NOTE .sophvec disabled           : no header slack");
    }
    if (r.VecTrampSectionBytes)
    {
        std::printf("[deobf]   .sophvec section RVA             : 0x%llx\n", static_cast<unsigned long long>(r.VecTrampSectionRva));
        std::printf("[deobf]   .sophvec section bytes           : %u\n", r.VecTrampSectionBytes);
        std::printf("[deobf]   bytes NOT corrupted downstream   : %llu\n", static_cast<unsigned long long>(r.VecTrampBytesSaved));
    }
    if (!redirectrows.empty())
    {
        std::printf("[deobf] redirect log (all %zu site(s)):\n", redirectrows.size());
        for (const RedirectRow& rw : redirectrows)
        {
            std::string decoded = (rw.FirstContent && !rw.FirstContent->empty())
                ? DeobfEncoders::DecodeBufferBytes(rw.FirstContent->data(), rw.FirstContent->size())
                : std::string("(empty)");
            if (decoded.size() > 48) decoded = decoded.substr(0, 45) + "...";

            const char* tramp = rw.ViaTramp ? " TRAMP" : "";
            if (rw.NAddrs == 1)
            {
                std::printf("[deobf]   rva=0x%08llx  was %-8s slot=%u consumed=%u%s  -> lea rax, [0x%x]  %s\n",
                    static_cast<unsigned long long>(rw.SiteRva),
                    rw.Mn && rw.Mn[0] ? rw.Mn : "?",
                    rw.Slot, rw.Consumed, tramp, rw.TargetRva, decoded.c_str());
            }
            else
            {
                std::printf("[deobf]   rva=0x%08llx  was %-8s slot=%u consumed=%u%s  -> lea rax, [0x%x]  bundle[%u] %s  (+%u more)\n",
                    static_cast<unsigned long long>(rw.SiteRva),
                    rw.Mn && rw.Mn[0] ? rw.Mn : "?",
                    rw.Slot, rw.Consumed, tramp, rw.TargetRva,
                    rw.NAddrs, decoded.c_str(), rw.NAddrs - 1);
            }
        }
    }
    DeobfIo::RuleClose();
}