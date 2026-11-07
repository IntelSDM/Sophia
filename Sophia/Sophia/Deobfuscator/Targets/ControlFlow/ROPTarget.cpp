#include "../../../../Pch.h"
#include "RopTarget.h"
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
#include <unordered_set>
#include <utility>
#include <vector>

namespace
{
    struct RopSiteResolutions
    {
        std::set<std::pair<std::string, uint32_t>> Resolutions;
    };

    struct RopMonopolySite
    {
        uint64_t    Rva;
        std::string Module;
        uint32_t    ModuleRva;
    };

    struct Gadget
    {
        std::vector<uint8_t> Bytes;
        uint32_t             Offset = 0;
        bool                 Ok = false;
    };

    enum class WalkOutcome { Ret, NonRetTerminator, DecodeFail, Cap };

    struct RopRewriteRow
    {
        uint64_t    Rva;
        std::string Module;
        uint32_t    ModuleRva;
        uint32_t    Slot;
        uint32_t    GadgetLen;
        uint32_t    LocalRva;
        bool        Ok;
        bool        IsJmp;
    };

    std::ifstream OpenDonor(const std::wstring& path)
    {
        {
            std::ifstream f(path, std::ios::binary | std::ios::ate);
            if (f) return f;
        }
        if (path.size() >= 4 && path.compare(0, 4, L"\\??\\") == 0)
        {
            std::ifstream f(path.substr(4), std::ios::binary | std::ios::ate);
            if (f) return f;
        }
        if (path.size() >= 12 &&
            (path.compare(0, 12, L"\\SystemRoot\\") == 0 ||
                path.compare(0, 12, L"\\systemroot\\") == 0))
        {
            wchar_t sysroot[MAX_PATH];
            const UINT n = GetWindowsDirectoryW(sysroot, MAX_PATH);
            if (n > 0 && n < MAX_PATH)
            {
                std::wstring win = sysroot;
                if (!win.empty() && win.back() != L'\\') win.push_back(L'\\');
                win.append(path.begin() + 12, path.end());
                std::ifstream f(win, std::ios::binary | std::ios::ate);
                if (f) return f;
            }
        }
        return std::ifstream{};
    }

    uint32_t DonorRvaToOffset(const std::vector<uint8_t>& bytes, uint32_t rva)
    {
        if (bytes.size() < sizeof(IMAGE_DOS_HEADER)) return UINT32_MAX;
        const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(bytes.data());
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return UINT32_MAX;
        if (dos->e_lfanew <= 0 || static_cast<size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS64) > bytes.size())
        {
            return UINT32_MAX;
        }
        const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(bytes.data() + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return UINT32_MAX;
        const auto* sectable = IMAGE_FIRST_SECTION(nt);
        const uint32_t nsec = nt->FileHeader.NumberOfSections;
        for (uint32_t i = 0; i < nsec; ++i)
        {
            const auto& s = sectable[i];
            const uint32_t vsize = s.Misc.VirtualSize ? s.Misc.VirtualSize : s.SizeOfRawData;
            if (rva >= s.VirtualAddress && rva < s.VirtualAddress + vsize)
            {
                const uint32_t delta = rva - s.VirtualAddress;
                if (delta >= s.SizeOfRawData) return UINT32_MAX;
                return s.PointerToRawData + delta;
            }
        }
        return UINT32_MAX;
    }
}

void RopTarget::Deobfuscate(DeobfContext& ctx, Deobfuscator::Report& r)
{
    std::unordered_map<std::string, std::wstring> modulepathbyname;
    {
        const std::filesystem::path sidecar = ctx.Store->Dir() / L"modules.tsv";
        std::ifstream f(sidecar, std::ios::binary);
        if (!f)
        {
            r.RopNoModulesSidecar = true;
        }
        else
        {
            std::string line;
            while (std::getline(f, line))
            {
                if (line.empty() || line[0] == '#') continue;
                std::vector<std::string> cols;
                size_t start = 0;
                while (start <= line.size())
                {
                    size_t tab = line.find('\t', start);
                    if (tab == std::string::npos)
                    {
                        cols.push_back(line.substr(start));
                        break;
                    }
                    cols.push_back(line.substr(start, tab - start));
                    start = tab + 1;
                }
                if (cols.size() < 2) continue;
                std::string name = cols.front();
                if (name.empty() || name == "__traced__") continue;
                std::string pathutf8 = cols.back();
                while (!pathutf8.empty() && (pathutf8.back() == '\r' || pathutf8.back() == '\n'))
                {
                    pathutf8.pop_back();
                }
                if (pathutf8.empty()) continue;
                const int nw = MultiByteToWideChar(CP_UTF8, 0, pathutf8.data(), static_cast<int>(pathutf8.size()), nullptr, 0);
                if (nw <= 0) continue;
                std::wstring pathw(static_cast<size_t>(nw), L'\0');
                MultiByteToWideChar(CP_UTF8, 0, pathutf8.data(), static_cast<int>(pathutf8.size()), pathw.data(), nw);
                modulepathbyname.emplace(std::move(name), std::move(pathw));
            }
        }
    }

    std::unordered_set<uint64_t> iatsites;
    ctx.Store->ForEachRecord(ObsKind::Iat,
        [&](const void* rec, size_t sz)
        {
            if (sz != sizeof(IatHit)) return;
            const IatHit* h = static_cast<const IatHit*>(rec);
            iatsites.insert(h->Rva);
        });

    std::unordered_map<uint64_t, RopSiteResolutions> roppersite;
    ctx.Store->ForEachRecord(ObsKind::Rop,
        [&](const void* rec, size_t sz)
        {
            ++r.RopRecordsSeen;
            if (sz != sizeof(RopHit)) return;
            const RopHit* h = static_cast<const RopHit*>(rec);
            std::string mn(h->ModuleName, strnlen(h->ModuleName, sizeof(h->ModuleName)));
            if (mn.empty()) return;
            roppersite[h->Rva].Resolutions.emplace(std::move(mn), h->ModuleRva);
        });

    r.RopSitesObserved = static_cast<uint32_t>(roppersite.size());

    std::vector<RopMonopolySite> monopoly;
    monopoly.reserve(roppersite.size());
    for (const auto& [rva, sr] : roppersite)
    {
        if (iatsites.count(rva))
        {
            ++r.RopSitesOverlapIat;
            continue;
        }
        if (sr.Resolutions.size() == 1)
        {
            ++r.RopSitesMonopoly;
            const auto& [m, mr] = *sr.Resolutions.begin();
            monopoly.push_back({ rva, m, mr });
        }
        else
        {
            ++r.RopSitesMixed;
        }
    }

    DeobfIo::RuleOpen("rop -- gadget rehost");
    std::printf("[deobf]   RopHit records read              : %llu\n", static_cast<unsigned long long>(r.RopRecordsSeen));
    std::printf("[deobf]   distinct sites in rop.bin        : %u\n", r.RopSitesObserved);
    std::printf("[deobf]   sites overlap iats.bin (1i turf) : %u\n", r.RopSitesOverlapIat);
    std::printf("[deobf]   monopoly (single gadget)         : %u\n", r.RopSitesMonopoly);
    std::printf("[deobf]   mixed (2+ gadgets)               : %u\n", r.RopSitesMixed);
    if (r.RopNoModulesSidecar)
    {
        std::puts("[deobf]   modules.tsv missing -- pass cannot resolve donor module paths, skipping the whole gadget-rehost step");
    }

    if (monopoly.empty() || r.RopNoModulesSidecar)
    {
        DeobfIo::RuleClose();
        return;
    }

    std::map<std::pair<std::string, uint32_t>, Gadget> gadgetbykey;
    std::unordered_map<std::string, std::vector<uint8_t>> modulebytes;

    auto loadmodule = [&](const std::string& name) -> const std::vector<uint8_t>*
        {
            auto it = modulebytes.find(name);
            if (it != modulebytes.end())
            {
                return it->second.empty() ? nullptr : &it->second;
            }
            auto pit = modulepathbyname.find(name);
            if (pit == modulepathbyname.end())
            {
                modulebytes[name];
                return nullptr;
            }
            std::ifstream f = OpenDonor(pit->second);
            if (!f) { modulebytes[name]; return nullptr; }
            const std::streamoff sz = f.tellg();
            if (sz <= 0 || sz > static_cast<std::streamoff>(256ULL * 1024 * 1024))
            {
                modulebytes[name];
                return nullptr;
            }
            f.seekg(0);
            std::vector<uint8_t> raw(static_cast<size_t>(sz));
            if (!f.read(reinterpret_cast<char*>(raw.data()), sz))
            {
                modulebytes[name];
                return nullptr;
            }
            auto ins = modulebytes.emplace(name, std::move(raw));
            return &ins.first->second;
        };

    constexpr uint32_t kgadgetinsncap = 64;
    constexpr uint32_t kgadgetbytecap = 512;

    auto walkgadget = [&](const std::vector<uint8_t>& modbytes, uint32_t modulerva, std::vector<uint8_t>& outbytes) -> WalkOutcome
        {
            const uint32_t startoff = DonorRvaToOffset(modbytes, modulerva);
            if (startoff == UINT32_MAX || startoff >= modbytes.size()) return WalkOutcome::DecodeFail;

            uint32_t cursor = startoff;
            uint32_t insncount = 0;
            uint32_t bytecount = 0;

            while (insncount < kgadgetinsncap && bytecount < kgadgetbytecap)
            {
                if (cursor >= modbytes.size()) return WalkOutcome::DecodeFail;
                size_t avail = modbytes.size() - cursor;
                if (avail > 15) avail = 15;
                ZydisDecodedInstruction insn;
                ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
                if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&ctx.Decoder, modbytes.data() + cursor, avail, &insn, ops)))
                {
                    return WalkOutcome::DecodeFail;
                }
                cursor += insn.length;
                bytecount += insn.length;
                ++insncount;

                if (insn.meta.category == ZYDIS_CATEGORY_RET)
                {
                    outbytes.assign(modbytes.data() + startoff, modbytes.data() + cursor);
                    return WalkOutcome::Ret;
                }
                if (insn.meta.category == ZYDIS_CATEGORY_UNCOND_BR ||
                    insn.meta.category == ZYDIS_CATEGORY_COND_BR ||
                    insn.meta.category == ZYDIS_CATEGORY_CALL ||
                    DeobfEncoders::IsHardStop(insn))
                {
                    outbytes.assign(modbytes.data() + startoff, modbytes.data() + cursor);
                    return WalkOutcome::NonRetTerminator;
                }
            }
            return WalkOutcome::Cap;
        };

    std::set<std::string> distinctmodulesused;
    for (const RopMonopolySite& ms : monopoly)
    {
        const auto key = std::make_pair(ms.Module, ms.ModuleRva);
        if (gadgetbykey.count(key)) continue;

        const std::vector<uint8_t>* modbytes = loadmodule(ms.Module);
        if (!modbytes)
        {
            ++r.RopGadgetsNoModule;
            gadgetbykey[key];
            continue;
        }

        Gadget g;
        const WalkOutcome wo = walkgadget(*modbytes, ms.ModuleRva, g.Bytes);
        switch (wo)
        {
        case WalkOutcome::Ret:
            g.Ok = true;
            ++r.RopGadgetsExtracted;
            distinctmodulesused.insert(ms.Module);
            break;
        case WalkOutcome::NonRetTerminator:
            g.Ok = true;
            ++r.RopGadgetsExtracted;
            ++r.RopGadgetsWalkNonret;
            distinctmodulesused.insert(ms.Module);
            break;
        case WalkOutcome::DecodeFail:
            ++r.RopGadgetsWalkBad;
            break;
        case WalkOutcome::Cap:
            ++r.RopGadgetsWalkCap;
            break;
        }
        gadgetbykey.emplace(key, std::move(g));
    }
    r.RopGadgetsUnique = static_cast<uint32_t>(gadgetbykey.size());
    r.RopModulesUsed = static_cast<uint32_t>(distinctmodulesused.size());

    std::printf("[deobf]   unique donor gadgets tried       : %u\n", r.RopGadgetsUnique);
    std::printf("[deobf]   extracted (any terminator)       : %u\n", r.RopGadgetsExtracted);
    std::printf("[deobf]     of which ended non-RET         : %u\n", r.RopGadgetsWalkNonret);
    std::printf("[deobf]   walk hit insn/byte cap           : %u\n", r.RopGadgetsWalkCap);
    std::printf("[deobf]   walk decode failed               : %u\n", r.RopGadgetsWalkBad);
    std::printf("[deobf]   donor module missing on disk     : %u\n", r.RopGadgetsNoModule);
    std::printf("[deobf]   donor modules used               : %u\n", r.RopModulesUsed);

    std::vector<uint8_t> blob;
    for (auto& [key, g] : gadgetbykey)
    {
        if (!g.Ok) continue;
        g.Offset = static_cast<uint32_t>(blob.size());
        blob.insert(blob.end(), g.Bytes.begin(), g.Bytes.end());
    }
    r.RopGadgetBytes = blob.size();

    uint32_t appendedroprva = 0;
    bool ropsectionappended = false;
    if (blob.empty())
    {
        std::puts("[deobf]   no gadgets extracted -- nothing to rehost");
    }
    else
    {
        const HeaderSlackInfo ropslack = DeobfEncoders::CheckHeaderSlack(ctx.Buf);
        if (!ropslack.HaveSlack)
        {
            r.RopNoHeaderSlack = true;
            std::puts("[deobf]   no header slack for `.sophROP` -- all monopoly sites will be counted as skipped");
        }
        else
        {
            const uint32_t roppredictedsectionrva = ropslack.PredictedRva;
            const uint32_t ropchars = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE;
            if (!SectionManager::AppendPeSection(ctx.Buf, ".sophROP", blob, appendedroprva, ropchars))
            {
                std::fprintf(stderr, "[deobf] rop: AppendPeSection failed after slack check succeeded -- all sites skipped\n");
            }
            else
            {
                if (appendedroprva != roppredictedsectionrva)
                {
                    std::fprintf(stderr, "[deobf] rop: WARN predicted section RVA 0x%x doesn't match appended 0x%x\n",
                        roppredictedsectionrva, appendedroprva);
                }
                ropsectionappended = true;
                r.RopSectionRva = appendedroprva;
                r.RopSectionBytes = static_cast<uint32_t>(blob.size());
                std::strncpy(r.RopSectionName, ".sophROP", sizeof(r.RopSectionName) - 1);
            }
        }
    }

    std::vector<RopRewriteRow> roprewrites;
    roprewrites.reserve(monopoly.size());

    std::sort(monopoly.begin(), monopoly.end(),
        [](const RopMonopolySite& a, const RopMonopolySite& b) { return a.Rva < b.Rva; });

    for (const RopMonopolySite& ms : monopoly)
    {
        RopRewriteRow row{};
        row.Rva = ms.Rva;
        row.Module = ms.Module;
        row.ModuleRva = ms.ModuleRva;

        const auto key = std::make_pair(ms.Module, ms.ModuleRva);
        auto gi = gadgetbykey.find(key);
        if (!ropsectionappended || gi == gadgetbykey.end() || !gi->second.Ok)
        {
            ++r.RopRewriteSkip;
            row.Ok = false;
            roprewrites.push_back(std::move(row));
            continue;
        }
        row.GadgetLen = static_cast<uint32_t>(gi->second.Bytes.size());
        row.LocalRva = appendedroprva + gi->second.Offset;

        const uint64_t off = ctx.Sm.RvaToOffset(ms.Rva);
        if (off == UINT64_MAX)
        {
            ++r.RopRewriteSkip;
            row.Ok = false;
            roprewrites.push_back(std::move(row));
            continue;
        }

        size_t avail = ctx.Buf.size() - off;
        if (avail > 15) avail = 15;
        ZydisDecodedInstruction insn;
        ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&ctx.Decoder, ctx.Buf.data() + off, avail, &insn, ops)))
        {
            ++r.RopRewriteSkip;
            row.Ok = false;
            roprewrites.push_back(std::move(row));
            continue;
        }
        const uint32_t sitelen = insn.length;
        row.Slot = sitelen;

        const bool iscall = (insn.meta.category == ZYDIS_CATEGORY_CALL);
        const bool isjmp = (insn.meta.category == ZYDIS_CATEGORY_UNCOND_BR);
        if (!iscall && !isjmp)
        {
            ++r.RopSitesNotBranch;
            ++r.RopRewriteSkip;
            row.Ok = false;
            roprewrites.push_back(std::move(row));
            continue;
        }
        row.IsJmp = isjmp;

        const int64_t d = static_cast<int64_t>(row.LocalRva) - static_cast<int64_t>(ms.Rva) - 5;
        if (d < INT32_MIN || d > INT32_MAX || off + 5 > ctx.Buf.size())
        {
            ++r.RopRewriteSkip;
            row.Ok = false;
            roprewrites.push_back(std::move(row));
            continue;
        }

        ctx.Buf[off + 0] = isjmp ? 0xE9 : 0xE8;
        const int32_t d32 = static_cast<int32_t>(d);
        std::memcpy(ctx.Buf.data() + off + 1, &d32, 4);
        for (uint32_t k = 5; k < sitelen; ++k) ctx.Buf[off + k] = 0x90;

        ++r.RopRewriteOk;
        if (isjmp) ++r.RopRewriteOkJmp;
        else       ++r.RopRewriteOkCall;
        r.RopBytesPatched += sitelen;
        row.Ok = true;
        roprewrites.push_back(std::move(row));
    }

    const std::filesystem::path ropspath = ctx.Store->Dir() / L"rops.txt";
    std::ofstream ofl(ropspath, std::ios::trunc);
    if (ofl)
    {
        ofl << "# site_rva  kind  module  module_rva  gadget_len  local_rva  slot  status\n";
        {
            char b[24];
            std::snprintf(b, sizeof(b), "%llx", static_cast<unsigned long long>(ctx.PreferredBase));
            ofl << b;
        }
        ofl << "\n\n";
        for (const RopRewriteRow& row : roprewrites)
        {
            const uint64_t localva = ctx.PreferredBase + static_cast<uint64_t>(row.LocalRva);
            char line[512];
            std::snprintf(line, sizeof(line),
                "rva=0x%08llx  kind=%-4s  %-20s  module_rva=0x%08x  gadget_len=%u  local_va=0x%llx  slot=%u  %s\n",
                static_cast<unsigned long long>(row.Rva),
                row.IsJmp ? "JMP" : "CALL",
                row.Module.c_str(), row.ModuleRva, row.GadgetLen,
                static_cast<unsigned long long>(localva), row.Slot,
                row.Ok ? "OK" : "SKIP");
            ofl << line;
        }
        r.RopLogPath = ropspath;
    }

    if (ropsectionappended)
    {
        std::printf("[deobf]   .sophROP section RVA             : 0x%llx\n", static_cast<unsigned long long>(r.RopSectionRva));
        std::printf("[deobf]   .sophROP section bytes           : %u\n", r.RopSectionBytes);
    }
    std::printf("[deobf]   sites rewritten (total)          : %u\n", r.RopRewriteOk);
    std::printf("[deobf]     CALL sites (E8 disp32)         : %u\n", r.RopRewriteOkCall);
    std::printf("[deobf]     JMP  sites (E9 disp32)         : %u\n", r.RopRewriteOkJmp);
    std::printf("[deobf]   sites skipped                    : %u\n", r.RopRewriteSkip);
    std::printf("[deobf]     of which not CALL/JMP shape    : %u\n", r.RopSitesNotBranch);
    std::printf("[deobf]   bytes patched (orig slot sum)    : %llu\n", static_cast<unsigned long long>(r.RopBytesPatched));
    if (!r.RopLogPath.empty())
    {
        std::printf("[deobf]   rops log                         : %ls\n", r.RopLogPath.wstring().c_str());
    }

    if (!roprewrites.empty())
    {
        std::printf("[deobf] rop rewrite log (all %zu site(s)):\n", roprewrites.size());
        for (const RopRewriteRow& row : roprewrites)
        {
            if (!row.Ok)
            {
                std::printf("[deobf]   rva=0x%08llx  slot=%u  SKIPPED (gadget %s+0x%x)\n",
                    static_cast<unsigned long long>(row.Rva), row.Slot,
                    row.Module.c_str(), row.ModuleRva);
            }
            else
            {
                std::printf("[deobf]   rva=0x%08llx  slot=%u  -> CALL .sophROP+0x%x  (%s+0x%x, %u B gadget)\n",
                    static_cast<unsigned long long>(row.Rva), row.Slot,
                    row.LocalRva - static_cast<uint32_t>(r.RopSectionRva),
                    row.Module.c_str(), row.ModuleRva, row.GadgetLen);
            }
        }
    }
    DeobfIo::RuleClose();
}