#include "../../../../Pch.h"
#include "IatTarget.h"
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
#include <set>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace
{
    struct SiteResolutions
    {
        std::set<std::pair<std::string, std::string>> Resolutions;
    };

    struct MonopolySite
    {
        uint64_t    Rva;
        std::string Module;
        std::string Exp;
    };

    struct SiteBinding
    {
        uint64_t    Rva;
        std::string Module;
        std::string Exp;
        uint32_t    IatSlotRva;
        bool        UsesExisting;
    };

    struct NewModule
    {
        std::string Name;
        std::vector<std::string> Exports;
        std::unordered_map<std::string, size_t> ExportIndex;
        uint32_t DescIdx = 0;
        uint32_t IltOffset = 0;
        uint32_t IatOffset = 0;
        uint32_t NameOffset = 0;
        std::vector<uint32_t> HintNameOffsets;
    };

    struct IatRewriteRow
    {
        uint64_t    Rva;
        uint32_t    Slot;
        uint32_t    IatSlotRva;
        std::string Module;
        std::string Exp;
        bool        UsesExisting;
        bool        Ok;
        bool        ViaTramp;
        uint32_t    Consumed;
    };
}

void IatTarget::Deobfuscate(DeobfContext& ctx, Deobfuscator::Report& r)
{
    std::unordered_map<uint64_t, SiteResolutions> iatpersite;

    ctx.Store->ForEachRecord(ObsKind::Iat,
        [&](const void* rec, size_t sz)
        {
            ++r.IatRecordsSeen;
            if (sz != sizeof(IatHit)) return;
            const IatHit* h = static_cast<const IatHit*>(rec);
            std::string mn(h->ModuleName, strnlen(h->ModuleName, sizeof(h->ModuleName)));
            std::string en(h->ExportName, strnlen(h->ExportName, sizeof(h->ExportName)));
            if (mn.empty() || en.empty()) return;
            iatpersite[h->Rva].Resolutions.emplace(std::move(mn), std::move(en));
        });

    r.IatSitesObserved = static_cast<uint32_t>(iatpersite.size());

    std::vector<MonopolySite> monopolysites;
    monopolysites.reserve(iatpersite.size());
    for (const auto& [rva, sr] : iatpersite)
    {
        if (sr.Resolutions.size() == 1)
        {
            ++r.IatSitesMonopoly;
            const auto& [m, e] = *sr.Resolutions.begin();
            monopolysites.push_back({ rva, m, e });
        }
        else
        {
            ++r.IatSitesMixed;
        }
    }

    DeobfIo::RuleOpen("iat -- reconstruction");
    std::printf("[deobf]   IatHit records read              : %llu\n", static_cast<unsigned long long>(r.IatRecordsSeen));
    std::printf("[deobf]   distinct sites in iats.bin       : %u\n", r.IatSitesObserved);
    std::printf("[deobf]   monopoly (single (module,export)): %u\n", r.IatSitesMonopoly);
    std::printf("[deobf]   mixed (2+ resolutions)           : %u\n", r.IatSitesMixed);

    if (monopolysites.empty())
    {
        std::puts("[deobf]   nothing to rewrite (no monopoly resolutions)");
        DeobfIo::RuleClose();
        return;
    }

    std::vector<std::pair<std::string, uint32_t>> existingbykeylist;
    std::unordered_map<std::string, uint32_t> existingbykey;
    {
        auto dosr = reinterpret_cast<const IMAGE_DOS_HEADER*>(ctx.Buf.data());
        auto ntr = reinterpret_cast<const IMAGE_NT_HEADERS64*>(ctx.Buf.data() + dosr->e_lfanew);
        const auto& impdir = ntr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

        if (impdir.VirtualAddress != 0 && impdir.Size >= sizeof(IMAGE_IMPORT_DESCRIPTOR))
        {
            const uint64_t impoff = ctx.Sm.RvaToOffset(impdir.VirtualAddress);
            if (impoff != UINT64_MAX)
            {
                for (uint32_t descidx = 0; ; ++descidx)
                {
                    const uint64_t descoff = impoff + static_cast<uint64_t>(descidx) * sizeof(IMAGE_IMPORT_DESCRIPTOR);
                    if (descoff + sizeof(IMAGE_IMPORT_DESCRIPTOR) > ctx.Buf.size()) break;
                    const auto* desc = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(ctx.Buf.data() + descoff);
                    if (desc->Name == 0 && desc->FirstThunk == 0 && desc->OriginalFirstThunk == 0) break;
                    if (desc->Name == 0) continue;

                    const uint64_t nameoff = ctx.Sm.RvaToOffset(desc->Name);
                    if (nameoff == UINT64_MAX) continue;
                    std::string modulelower;
                    for (uint64_t p = nameoff; p < ctx.Buf.size() && ctx.Buf[p] != 0; ++p)
                    {
                        char c = static_cast<char>(ctx.Buf[p]);
                        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + 32);
                        modulelower.push_back(c);
                        if (modulelower.size() > 128) break;
                    }
                    if (modulelower.empty()) continue;

                    const uint32_t iltrva = desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk;
                    const uint32_t iatrva = desc->FirstThunk;
                    if (iltrva == 0 || iatrva == 0) continue;

                    const uint64_t iltoff = ctx.Sm.RvaToOffset(iltrva);
                    if (iltoff == UINT64_MAX) continue;

                    for (uint32_t ti = 0; ; ++ti)
                    {
                        const uint64_t thunkoff = iltoff + static_cast<uint64_t>(ti) * 8;
                        if (thunkoff + 8 > ctx.Buf.size()) break;
                        uint64_t thunk = 0;
                        std::memcpy(&thunk, ctx.Buf.data() + thunkoff, 8);
                        if (thunk == 0) break;
                        if (thunk & (1ULL << 63)) continue;

                        const uint32_t hnrva = static_cast<uint32_t>(thunk);
                        const uint64_t hnoff = ctx.Sm.RvaToOffset(hnrva);
                        if (hnoff == UINT64_MAX) continue;
                        if (hnoff + 3 > ctx.Buf.size()) continue;

                        std::string exp;
                        for (uint64_t p = hnoff + 2; p < ctx.Buf.size() && ctx.Buf[p] != 0; ++p)
                        {
                            exp.push_back(static_cast<char>(ctx.Buf[p]));
                            if (exp.size() > 256) break;
                        }
                        if (exp.empty()) continue;

                        const uint32_t slotrva = iatrva + static_cast<uint32_t>(ti * 8);
                        std::string key = modulelower + "!" + exp;
                        if (existingbykey.emplace(key, slotrva).second)
                        {
                            existingbykeylist.emplace_back(std::move(key), slotrva);
                        }
                    }
                }
            }
        }
    }
    r.IatExistingImportsSeen = static_cast<uint32_t>(existingbykeylist.size());
    std::printf("[deobf]   existing imports in DataDir[1]   : %u\n", r.IatExistingImportsSeen);

    std::vector<SiteBinding> bindings;
    bindings.reserve(monopolysites.size());
    std::map<std::string, std::vector<std::string>> newimports;
    std::set<std::pair<std::string, std::string>> newimportsset;

    for (const MonopolySite& ms : monopolysites)
    {
        std::string key = ms.Module + "!" + ms.Exp;
        auto it = existingbykey.find(key);
        SiteBinding sb{};
        sb.Rva = ms.Rva;
        sb.Module = ms.Module;
        sb.Exp = ms.Exp;
        if (it != existingbykey.end())
        {
            sb.IatSlotRva = it->second;
            sb.UsesExisting = true;
            ++r.IatSitesReusedExisting;
        }
        else
        {
            sb.IatSlotRva = 0;
            sb.UsesExisting = false;
            ++r.IatSitesNeedingNew;
            if (newimportsset.emplace(ms.Module, ms.Exp).second)
            {
                newimports[ms.Module].push_back(ms.Exp);
            }
        }
        bindings.push_back(sb);
    }
    std::printf("[deobf]   sites reusing existing IAT slot  : %u\n", r.IatSitesReusedExisting);
    std::printf("[deobf]   sites needing new import         : %u\n", r.IatSitesNeedingNew);

    std::vector<NewModule> newmods;
    newmods.reserve(newimports.size());
    for (auto& [nm, exps] : newimports)
    {
        NewModule nm2;
        nm2.Name = nm;
        nm2.Exports = std::move(exps);
        for (size_t i = 0; i < nm2.Exports.size(); ++i)
        {
            nm2.ExportIndex[nm2.Exports[i]] = i;
        }
        newmods.push_back(std::move(nm2));
    }
    r.IatModulesUsed = static_cast<uint32_t>(newmods.size());

    bool sectionappended = false;
    uint32_t appendedrva = 0;

    if (!newmods.empty())
    {
        const HeaderSlackInfo iatslack = DeobfEncoders::CheckHeaderSlack(ctx.Buf);
        if (!iatslack.HaveSlack)
        {
            r.IatNoHeaderSlack = true;
            std::puts("[deobf]   no header slack for `.sophimp` -- needs-new sites will be skipped, reused-existing sites still get rewritten.");
        }
        else
        {
            const uint32_t iatpredictedsectionrva = iatslack.PredictedRva;

            std::vector<IMAGE_IMPORT_DESCRIPTOR> existingdescs;
            {
                auto dosr = reinterpret_cast<const IMAGE_DOS_HEADER*>(ctx.Buf.data());
                auto ntr = reinterpret_cast<const IMAGE_NT_HEADERS64*>(ctx.Buf.data() + dosr->e_lfanew);
                const auto& impdir = ntr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
                if (impdir.VirtualAddress != 0)
                {
                    const uint64_t impoff = ctx.Sm.RvaToOffset(impdir.VirtualAddress);
                    if (impoff != UINT64_MAX)
                    {
                        for (uint32_t di = 0; ; ++di)
                        {
                            const uint64_t descoff = impoff + static_cast<uint64_t>(di) * sizeof(IMAGE_IMPORT_DESCRIPTOR);
                            if (descoff + sizeof(IMAGE_IMPORT_DESCRIPTOR) > ctx.Buf.size()) break;
                            IMAGE_IMPORT_DESCRIPTOR desc;
                            std::memcpy(&desc, ctx.Buf.data() + descoff, sizeof(desc));
                            if (desc.Name == 0 && desc.FirstThunk == 0 && desc.OriginalFirstThunk == 0) break;
                            existingdescs.push_back(desc);
                        }
                    }
                }
            }

            const uint32_t existingcount = static_cast<uint32_t>(existingdescs.size());
            const uint32_t newcount = static_cast<uint32_t>(newmods.size());
            const uint32_t descarraybytes = (existingcount + newcount + 1) * 20;

            uint32_t off = descarraybytes;
            uint32_t totalexports = 0;
            for (size_t i = 0; i < newmods.size(); ++i)
            {
                NewModule& nm = newmods[i];
                nm.DescIdx = static_cast<uint32_t>(i);
                nm.IltOffset = off;
                off += static_cast<uint32_t>((nm.Exports.size() + 1) * 8);
                nm.IatOffset = off;
                off += static_cast<uint32_t>((nm.Exports.size() + 1) * 8);
                nm.NameOffset = off;
                off += static_cast<uint32_t>(nm.Name.size() + 1);
                nm.HintNameOffsets.resize(nm.Exports.size());
                for (size_t j = 0; j < nm.Exports.size(); ++j)
                {
                    if (off & 1) ++off;
                    nm.HintNameOffsets[j] = off;
                    off += 2;
                    off += static_cast<uint32_t>(nm.Exports[j].size() + 1);
                }
                totalexports += static_cast<uint32_t>(nm.Exports.size());
            }
            r.IatExportsUsed = totalexports;

            const uint32_t sophimpbytes = off;
            const uint32_t sectionrva = iatpredictedsectionrva;
            std::vector<uint8_t> impbytes(sophimpbytes, 0);

            for (uint32_t i = 0; i < existingcount; ++i)
            {
                std::memcpy(impbytes.data() + i * 20, &existingdescs[i], sizeof(IMAGE_IMPORT_DESCRIPTOR));
            }

            for (NewModule& nm : newmods)
            {
                uint8_t* desc = impbytes.data() + (existingcount + nm.DescIdx) * 20;
                const uint32_t oftrva = sectionrva + nm.IltOffset;
                const uint32_t ftrva = sectionrva + nm.IatOffset;
                const uint32_t namerva = sectionrva + nm.NameOffset;
                std::memcpy(desc + 0x00, &oftrva, 4);
                std::memcpy(desc + 0x0C, &namerva, 4);
                std::memcpy(desc + 0x10, &ftrva, 4);
            }

            for (NewModule& nm : newmods)
            {
                std::memcpy(impbytes.data() + nm.NameOffset, nm.Name.data(), nm.Name.size());
                for (size_t j = 0; j < nm.Exports.size(); ++j)
                {
                    const uint32_t hnrva = sectionrva + nm.HintNameOffsets[j];
                    uint64_t thunk = static_cast<uint64_t>(hnrva);
                    std::memcpy(impbytes.data() + nm.IltOffset + j * 8, &thunk, 8);
                    std::memcpy(impbytes.data() + nm.IatOffset + j * 8, &thunk, 8);
                    std::memcpy(impbytes.data() + nm.HintNameOffsets[j] + 2, nm.Exports[j].data(), nm.Exports[j].size());
                }
            }

            if (!SectionManager::AppendPeSection(ctx.Buf, ".sophimp", impbytes, appendedrva))
            {
                std::fprintf(stderr, "[deobf] iat: AppendPeSection failed after slack check succeeded -- dropping new-import path; reused-existing rewrites still apply\n");
            }
            else
            {
                if (appendedrva != sectionrva)
                {
                    std::fprintf(stderr, "[deobf] iat: WARN predicted section RVA 0x%x doesn't match appended 0x%x\n", sectionrva, appendedrva);
                }
                sectionappended = true;
                r.IatSectionRva = appendedrva;
                r.IatSectionBytes = sophimpbytes;
                std::strncpy(r.IatSectionName, ".sophimp", sizeof(r.IatSectionName) - 1);

                auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(ctx.Buf.data());
                auto nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(ctx.Buf.data() + dos->e_lfanew);
                nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = appendedrva;
                nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = descarraybytes;

                for (SiteBinding& sb : bindings)
                {
                    if (sb.UsesExisting) continue;
                    auto mit = std::find_if(newmods.begin(), newmods.end(),
                        [&](const NewModule& nm) { return nm.Name == sb.Module; });
                    if (mit == newmods.end()) continue;
                    auto eit = mit->ExportIndex.find(sb.Exp);
                    if (eit == mit->ExportIndex.end()) continue;
                    sb.IatSlotRva = appendedrva + mit->IatOffset + static_cast<uint32_t>(eit->second * 8);
                }
            }
        }
    }
    else
    {
        std::puts("[deobf]   no new imports needed -- existing IAT table is untouched");
    }

    std::vector<IatRewriteRow> iatrewrites;
    iatrewrites.reserve(bindings.size());

    std::sort(bindings.begin(), bindings.end(),
        [](const SiteBinding& a, const SiteBinding& b) { return a.Rva < b.Rva; });

    const HeaderSlackInfo callslack = DeobfEncoders::CheckHeaderSlack(ctx.Buf);
    if (!callslack.HaveSlack) r.IatTrampNoHeaderSlack = true;
    TrampolineBuilder calltramp(ctx.Buf, ctx.Decoder, callslack.PredictedRva);

    for (const SiteBinding& sb : bindings)
    {
        IatRewriteRow row{};
        row.Rva = sb.Rva;
        row.Module = sb.Module;
        row.Exp = sb.Exp;
        row.UsesExisting = sb.UsesExisting;
        row.IatSlotRva = sb.IatSlotRva;

        if (sb.IatSlotRva == 0)
        {
            ++r.IatRewriteSkip;
            row.Ok = false;
            iatrewrites.push_back(row);
            continue;
        }

        const uint64_t off = ctx.Sm.RvaToOffset(sb.Rva);
        if (off == UINT64_MAX)
        {
            ++r.IatRewriteSkip;
            row.Ok = false;
            iatrewrites.push_back(row);
            continue;
        }

        size_t avail = ctx.Buf.size() - off;
        if (avail > 15) avail = 15;
        ZydisDecodedInstruction insn;
        ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&ctx.Decoder, ctx.Buf.data() + off, avail, &insn, ops)))
        {
            ++r.IatRewriteSkip;
            row.Ok = false;
            iatrewrites.push_back(row);
            continue;
        }
        const uint32_t sitelen = insn.length;
        row.Slot = sitelen;
        row.Consumed = sitelen;

        constexpr uint32_t kiatenclen = 6;
        if (sitelen >= kiatenclen)
        {
            const int64_t d = static_cast<int64_t>(sb.IatSlotRva) - static_cast<int64_t>(sb.Rva) - kiatenclen;
            if (d < INT32_MIN || d > INT32_MAX || off + kiatenclen > ctx.Buf.size())
            {
                ++r.IatRewriteSkip;
                row.Ok = false;
                iatrewrites.push_back(row);
                continue;
            }

            ctx.Buf[off + 0] = 0xFF;
            ctx.Buf[off + 1] = 0x15;
            const int32_t d32 = static_cast<int32_t>(d);
            std::memcpy(ctx.Buf.data() + off + 2, &d32, 4);
            for (uint32_t k = kiatenclen; k < sitelen; ++k) ctx.Buf[off + k] = 0x90;

            ++r.IatRewriteOk;
            ++r.IatRewriteInplace;
            r.IatBytesPatched += sitelen;
            row.Ok = true;
            iatrewrites.push_back(row);
            continue;
        }

        if (!callslack.HaveSlack)
        {
            ++r.IatRewriteSkip;
            row.Ok = false;
            iatrewrites.push_back(row);
            continue;
        }
        const uint64_t iatslot = sb.IatSlotRva;
        const bool okt = calltramp.TryTrampoline(off, sitelen, sb.Rva, kiatenclen,
            [iatslot](uint8_t* out, uint32_t cap, uint64_t at)
            {
                return DeobfEncoders::EncIatCall(out, cap, iatslot, at);
            });
        if (okt)
        {
            const auto& sr = calltramp.Sites().back();
            row.Consumed = sr.Consumed;
            row.ViaTramp = true;
            row.Ok = true;
            ++r.IatRewriteOk;
            ++r.IatRewriteTramp;
            r.IatBytesPatched += sr.Consumed;
        }
        else
        {
            ++r.IatRewriteSkip;
            row.Ok = false;
        }
        iatrewrites.push_back(row);
    }

    if (!calltramp.Blob().empty())
    {
        uint32_t apr = 0;
        const uint32_t chars = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE;
        if (SectionManager::AppendPeSection(ctx.Buf, ".sophcall", calltramp.Blob(), apr, chars))
        {
            if (apr != calltramp.PredictedSectionRva())
            {
                std::fprintf(stderr, "[deobf] iat: WARN predicted .sophcall RVA 0x%x != appended 0x%x\n",
                    calltramp.PredictedSectionRva(), apr);
            }
            calltramp.EmitOutbounds();
            r.IatTrampSectionRva = apr;
            r.IatTrampSectionBytes = static_cast<uint32_t>(calltramp.Blob().size());
            r.IatTrampBytesSaved = calltramp.BytesSaved();
            std::strncpy(r.IatTrampSectionName, ".sophcall", sizeof(r.IatTrampSectionName) - 1);
        }
        else
        {
            std::fprintf(stderr, "[deobf] iat: AppendPeSection .sophcall FAILED -- %u trampolined sites un-rewritten\n", r.IatRewriteTramp);
            r.IatRewriteOk -= r.IatRewriteTramp;
            r.IatRewriteSkip += r.IatRewriteTramp;
            for (IatRewriteRow& rw : iatrewrites)
            {
                if (rw.ViaTramp) { rw.Ok = false; rw.ViaTramp = false; }
            }
            r.IatRewriteTramp = 0;
        }
    }

    const std::filesystem::path iatspath = ctx.Store->Dir() / L"iats.txt";
    std::ofstream ofl(iatspath, std::ios::trunc);
    if (ofl)
    {
        {
            char b[24];
            std::snprintf(b, sizeof(b), "%llx", static_cast<unsigned long long>(ctx.PreferredBase));
            ofl << b;
        }
        ofl << "\n\n";
        for (const IatRewriteRow& row : iatrewrites)
        {
            const uint64_t slotva = ctx.PreferredBase + static_cast<uint64_t>(row.IatSlotRva);
            char line[600];
            std::snprintf(line, sizeof(line),
                "rva=0x%08llx  slot=%u  %-16s  %-40s  .iat_slot_va=0x%llx  source=%s  %s\n",
                static_cast<unsigned long long>(row.Rva), row.Slot,
                row.Module.c_str(), row.Exp.c_str(),
                static_cast<unsigned long long>(slotva),
                row.UsesExisting ? "EXISTING" : "NEW",
                row.Ok ? "OK" : "SKIP");
            ofl << line;
        }
        r.IatLogPath = iatspath;
    }

    if (sectionappended)
    {
        std::printf("[deobf]   new modules imported             : %u\n", r.IatModulesUsed);
        std::printf("[deobf]   new imports added                : %u\n", r.IatExportsUsed);
        std::printf("[deobf]   .sophimp section RVA             : 0x%llx\n", static_cast<unsigned long long>(r.IatSectionRva));
        std::printf("[deobf]   .sophimp section bytes           : %u\n", r.IatSectionBytes);
    }
    std::printf("[deobf]   sites rewritten (FF 15 disp32)   : %u\n", r.IatRewriteOk);
    std::printf("[deobf]   sites skipped                    : %u\n", r.IatRewriteSkip);
    std::printf("[deobf]   bytes patched (orig slot sum)    : %llu\n", static_cast<unsigned long long>(r.IatBytesPatched));
    if (!r.IatLogPath.empty())
    {
        std::printf("[deobf]   iats log                         : %ls\n", r.IatLogPath.wstring().c_str());
    }

    if (!iatrewrites.empty())
    {
        std::printf("[deobf] iat rewrite log (all %zu site(s)):\n", iatrewrites.size());
        for (const IatRewriteRow& row : iatrewrites)
        {
            std::printf("[deobf]   rva=0x%08llx  slot=%u  -> call cs:[__imp_%s]  (%s, %s)  %s\n",
                static_cast<unsigned long long>(row.Rva),
                row.Slot, row.Exp.c_str(), row.Module.c_str(),
                row.UsesExisting ? "EXISTING" : "NEW",
                row.Ok ? "ok" : "SKIPPED");
        }
    }
    DeobfIo::RuleClose();
}