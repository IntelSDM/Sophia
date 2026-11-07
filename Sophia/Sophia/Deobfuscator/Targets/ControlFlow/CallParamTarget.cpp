#include "../../../../Pch.h"
#include "CallParamTarget.h"
#include "../../DeobfIo.h"
#include "../../DeobfValClassifier.h"
#include "../../../Database/AutoDebugStore.h"

#include <windows.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <unordered_map>
#include <vector>

namespace
{
    struct ArgObs
    {
        uint8_t  Idx;
        uint64_t Val;
        uint64_t Head[4];
    };
    struct RetObs
    {
        uint64_t Rax;
        uint64_t Head[4];
        bool     HasHeads;
    };
    struct SiteObs
    {
        std::vector<ArgObs> Args;
        std::vector<RetObs> Rets;
    };
    struct IatEntry
    {
        std::string Module;
        std::string ExportName;
    };

    const char* ArgRegName(uint8_t idx)
    {
        switch (idx)
        {
        case 0: return "RCX";
        case 1: return "RDX";
        case 2: return "R8 ";
        case 3: return "R9 ";
        case 4: case 5: case 6: case 7: return "stk";
        }
        return "?";
    }
}

void CallParamTarget::Deobfuscate(DeobfContext& ctx, Deobfuscator::Report& r)
{
    const std::filesystem::path modulestsv = ctx.Store->Dir() / L"modules.tsv";
    uint64_t tracedruntimebase = 0;
    uint64_t tracedruntimesize = 0;
    std::vector<ForeignMod> foreignmods;
    {
        std::ifstream f(modulestsv, std::ios::binary);
        if (f)
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
                    if (tab == std::string::npos) { cols.push_back(line.substr(start)); break; }
                    cols.push_back(line.substr(start, tab - start));
                    start = tab + 1;
                }
                if (cols.size() < 3) continue;
                const std::string& name = cols[0];
                if (name.empty()) continue;
                uint64_t base = 0, size = 0;
                try { base = std::stoull(cols[1], nullptr, 16); size = std::stoull(cols[2], nullptr, 16); }
                catch (...) { continue; }
                if (name == "__traced__")
                {
                    tracedruntimebase = base;
                    tracedruntimesize = size;
                }
                else
                {
                    foreignmods.push_back({ name, base, size });
                }
            }
        }
    }
    if (tracedruntimebase == 0)
    {
        r.CallargNoTracedBase = true;
        tracedruntimebase = ctx.PreferredBase;
    }

    std::unordered_map<std::string, std::wstring> foreignpathbyname;
    DeobfValClassifier::LoadForeignPaths(modulestsv, foreignpathbyname);

    std::unordered_map<std::string, std::vector<uint8_t>> foreignbytes;
    auto loadforeign = [&](const std::string& name) -> const std::vector<uint8_t>*
        {
            auto it = foreignbytes.find(name);
            if (it != foreignbytes.end()) return it->second.empty() ? nullptr : &it->second;
            auto pit = foreignpathbyname.find(name);
            if (pit == foreignpathbyname.end()) { foreignbytes[name]; return nullptr; }
            std::ifstream f = DeobfValClassifier::OpenForeign(pit->second);
            if (!f) { foreignbytes[name]; return nullptr; }
            const std::streamoff sz = f.tellg();
            if (sz <= 0 || sz > static_cast<std::streamoff>(256ULL * 1024 * 1024)) { foreignbytes[name]; return nullptr; }
            f.seekg(0);
            std::vector<uint8_t> raw(static_cast<size_t>(sz));
            if (!f.read(reinterpret_cast<char*>(raw.data()), sz)) { foreignbytes[name]; return nullptr; }
            auto ins = foreignbytes.emplace(name, std::move(raw));
            return &ins.first->second;
        };

    auto readtracedansi = [&](uint64_t val) -> std::string
        {
            if (val < tracedruntimebase) return {};
            const uint64_t rvawithin = val - tracedruntimebase;
            if (rvawithin > 0xFFFFFFFFu) return {};
            const uint32_t off = DeobfValClassifier::RvaToFileOff(nullptr, ctx.Buf.data(), ctx.Buf.size(), static_cast<uint32_t>(rvawithin));
            if (off == UINT32_MAX) return {};
            return DeobfValClassifier::ReadAnsiFrom(ctx.Buf.data(), ctx.Buf.size(), off);
        };
    auto readtracedwide = [&](uint64_t val) -> std::string
        {
            if (val < tracedruntimebase) return {};
            const uint64_t rvawithin = val - tracedruntimebase;
            if (rvawithin > 0xFFFFFFFFu) return {};
            const uint32_t off = DeobfValClassifier::RvaToFileOff(nullptr, ctx.Buf.data(), ctx.Buf.size(), static_cast<uint32_t>(rvawithin));
            if (off == UINT32_MAX) return {};
            return DeobfValClassifier::ReadWideFrom(ctx.Buf.data(), ctx.Buf.size(), off);
        };
    auto readforeignansi = [&](const std::string& mn, uint64_t offset) -> std::string
        {
            if (offset > 0xFFFFFFFFu) return {};
            const std::vector<uint8_t>* mb = loadforeign(mn);
            if (!mb) return {};
            const uint32_t off = DeobfValClassifier::RvaToFileOff(mb, nullptr, 0, static_cast<uint32_t>(offset));
            if (off == UINT32_MAX) return {};
            return DeobfValClassifier::ReadAnsiFrom(mb->data(), mb->size(), off);
        };
    auto readforeignwide = [&](const std::string& mn, uint64_t offset) -> std::string
        {
            if (offset > 0xFFFFFFFFu) return {};
            const std::vector<uint8_t>* mb = loadforeign(mn);
            if (!mb) return {};
            const uint32_t off = DeobfValClassifier::RvaToFileOff(mb, nullptr, 0, static_cast<uint32_t>(offset));
            if (off == UINT32_MAX) return {};
            return DeobfValClassifier::ReadWideFrom(mb->data(), mb->size(), off);
        };

    std::unordered_map<uint64_t, IatEntry> iatbysite;
    ctx.Store->ForEachRecord(ObsKind::Iat,
        [&](const void* rec, size_t sz)
        {
            if (sz != sizeof(IatHit)) return;
            const IatHit* h = static_cast<const IatHit*>(rec);
            std::string mn(h->ModuleName, strnlen(h->ModuleName, sizeof(h->ModuleName)));
            std::string en(h->ExportName, strnlen(h->ExportName, sizeof(h->ExportName)));
            if (mn.empty() || en.empty()) return;
            iatbysite.emplace(h->Rva, IatEntry{ std::move(mn), std::move(en) });
        });

    std::unordered_map<uint64_t, SiteObs> persite;
    ctx.Store->ForEachRecord(ObsKind::CallArg,
        [&](const void* rec, size_t sz)
        {
            ++r.CallargRecordsSeen;
            if (sz != sizeof(CallArgHit)) return;
            const CallArgHit* h = static_cast<const CallArgHit*>(rec);
            ArgObs a;
            a.Idx = h->ArgIdx;
            a.Val = h->Val;
            a.Head[0] = h->Head[0]; a.Head[1] = h->Head[1]; a.Head[2] = h->Head[2]; a.Head[3] = h->Head[3];
            persite[h->Rva].Args.push_back(a);
        });

    std::unordered_map<uint64_t, std::unordered_map<uint64_t, RetObs>> retsbysite;
    ctx.Store->ForEachRecord(ObsKind::CallRet,
        [&](const void* rec, size_t sz)
        {
            ++r.CallretRecordsSeen;
            if (sz != sizeof(CallRetHit)) return;
            const CallRetHit* h = static_cast<const CallRetHit*>(rec);
            const bool hasheads = (h->Head[0] | h->Head[1] | h->Head[2] | h->Head[3]) != 0;
            auto& perrax = retsbysite[h->Rva];
            auto it = perrax.find(h->Rax);
            if (it == perrax.end())
            {
                RetObs o{ h->Rax, { h->Head[0], h->Head[1], h->Head[2], h->Head[3] }, hasheads };
                perrax.emplace(h->Rax, o);
            }
            else if (hasheads && !it->second.HasHeads)
            {
                it->second.Head[0] = h->Head[0]; it->second.Head[1] = h->Head[1];
                it->second.Head[2] = h->Head[2]; it->second.Head[3] = h->Head[3];
                it->second.HasHeads = true;
            }
        });
    for (auto& [rva, perrax] : retsbysite)
    {
        SiteObs& so = persite[rva];
        for (auto& [rax, obs] : perrax) so.Rets.push_back(obs);
    }

    const std::filesystem::path iatpath = ctx.Store->Dir() / L"callargs.iat.txt";
    const std::filesystem::path othpath = ctx.Store->Dir() / L"callargs.other.txt";
    std::ofstream iatout(iatpath, std::ios::trunc);
    std::ofstream othout(othpath, std::ios::trunc);


    std::vector<uint64_t> orderedsites;
    orderedsites.reserve(persite.size());
    for (const auto& [rva, _] : persite) orderedsites.push_back(rva);
    std::sort(orderedsites.begin(), orderedsites.end());

    auto emitsite = [&](std::ofstream& out, uint64_t siterva, const SiteObs& so, const IatEntry* iat)
        {
            if (!out) return;
            char hdr[256];
            if (iat)
            {
                std::snprintf(hdr, sizeof(hdr), "=== rva=0x%08llx  %s!%s ===\n",
                    static_cast<unsigned long long>(siterva), iat->Module.c_str(), iat->ExportName.c_str());
            }
            else
            {
                std::snprintf(hdr, sizeof(hdr), "=== rva=0x%08llx ===\n", static_cast<unsigned long long>(siterva));
            }
            out << hdr;

            std::vector<ArgObs> args = so.Args;
            std::sort(args.begin(), args.end(),
                [](const ArgObs& a, const ArgObs& b) { if (a.Idx != b.Idx) return a.Idx < b.Idx; return a.Val < b.Val; });

            for (const ArgObs& a : args)
            {
                const ValSpace vs = DeobfValClassifier::ClassifyBySection(ctx.Buf, tracedruntimebase, tracedruntimesize, a.Val);
                const bool looksint = (a.Val < 0x10000ULL) || (a.Val >= 0xFFFFFFFF00000000ULL);
                const bool ansistr = (vs == ValSpace::RdataRva || vs == ValSpace::DataRva) && DeobfValClassifier::IsAnsiString(a.Head);
                const bool widestr = (vs == ValSpace::RdataRva || vs == ValSpace::DataRva) && DeobfValClassifier::IsWideString(a.Head);

                const char* space = "?";
                std::string extra;
                if (looksint)
                {
                    space = "int";
                    ++r.CallargArgsInt;
                }
                else if (ansistr || widestr)
                {
                    space = "rdata";
                    if (widestr)
                    {
                        std::string full = readtracedwide(a.Val);
                        if (full.empty()) full = DeobfValClassifier::DecodeWide(a.Head);
                        extra = "  L\"" + full + "\"";
                        ++r.CallargArgsWideString;
                    }
                    else
                    {
                        std::string full = readtracedansi(a.Val);
                        if (full.empty()) full = DeobfValClassifier::DecodeAnsi(a.Head);
                        extra = "  \"" + full + "\"";
                        ++r.CallargArgsAnsiString;
                    }
                }
                else
                {
                    switch (vs)
                    {
                    case ValSpace::TextRva:  space = "text "; ++r.CallargArgsTracedText; break;
                    case ValSpace::RdataRva: space = "rdata"; ++r.CallargArgsTracedRdata; break;
                    case ValSpace::DataRva:  space = "data "; ++r.CallargArgsTracedData; break;
                    case ValSpace::SectionOther: space = "sect "; break;
                    case ValSpace::Unknown:
                    {
                        const ForeignHit fh = DeobfValClassifier::ClassifyForeign(foreignmods, a.Val);
                        if (fh.Mod)
                        {
                            space = "fmod ";
                            char lbl[128];
                            std::snprintf(lbl, sizeof(lbl), "  %s+0x%llx", fh.Mod->Name.c_str(), static_cast<unsigned long long>(fh.Offset));
                            extra = lbl;
                            std::string wide = readforeignwide(fh.Mod->Name, fh.Offset);
                            if (!wide.empty()) { extra += "  L\""; extra += wide; extra += "\""; }
                            else
                            {
                                std::string ansi = readforeignansi(fh.Mod->Name, fh.Offset);
                                if (!ansi.empty()) { extra += "  \""; extra += ansi; extra += "\""; }
                            }
                            ++r.CallargArgsForeign;
                        }
                        else if (a.Val >= 0x10000ULL && a.Val <= 0x00007FFFFFFFFFFFULL)
                        {
                            space = "stk/hp";
                            ++r.CallargArgsStackHeap;
                        }
                        else
                        {
                            space = "?";
                            std::string inl = DeobfValClassifier::DecodeInlineAscii(a.Val);
                            if (!inl.empty()) extra = "  inline:\"" + inl + "\"";
                            ++r.CallargArgsUnknown;
                        }
                        break;
                    }
                    default: space = "?"; ++r.CallargArgsUnknown; break;
                    }
                }

                char line[320];
                std::snprintf(line, sizeof(line), "  idx=%u (%s)  val=0x%016llx  space=%-6s",
                    a.Idx, ArgRegName(a.Idx), static_cast<unsigned long long>(a.Val), space);
                out << line;
                if (!extra.empty()) out << extra;
                out << "\n";
            }

            if (!so.Rets.empty())
            {
                out << "  ---> returns:\n";
                std::vector<RetObs> rets = so.Rets;
                std::sort(rets.begin(), rets.end(), [](const RetObs& a, const RetObs& b) { return a.Rax < b.Rax; });
                for (const RetObs& ro : rets)
                {
                    const uint64_t v = ro.Rax;
                    const ValSpace vs = DeobfValClassifier::ClassifyBySection(ctx.Buf, tracedruntimebase, tracedruntimesize, v);
                    const bool looksint = (v < 0x10000ULL) || (v >= 0xFFFFFFFF00000000ULL);
                    const bool ansistr = (vs == ValSpace::RdataRva || vs == ValSpace::DataRva) && DeobfValClassifier::IsAnsiString(ro.Head);
                    const bool widestr = (vs == ValSpace::RdataRva || vs == ValSpace::DataRva) && DeobfValClassifier::IsWideString(ro.Head);
                    const char* space = "?";
                    std::string extra;
                    if (looksint) { space = "int"; ++r.CallretValsInt; }
                    else if (ansistr || widestr)
                    {
                        space = "rdata";
                        if (widestr)
                        {
                            std::string full = readtracedwide(v);
                            if (full.empty()) full = DeobfValClassifier::DecodeWide(ro.Head);
                            extra = "  L\"" + full + "\"";
                            ++r.CallretValsWideString;
                        }
                        else
                        {
                            std::string full = readtracedansi(v);
                            if (full.empty()) full = DeobfValClassifier::DecodeAnsi(ro.Head);
                            extra = "  \"" + full + "\"";
                            ++r.CallretValsAnsiString;
                        }
                    }
                    else
                    {
                        switch (vs)
                        {
                        case ValSpace::TextRva:  space = "text "; ++r.CallretValsTracedText; break;
                        case ValSpace::RdataRva: space = "rdata"; ++r.CallretValsTracedRdata; break;
                        case ValSpace::DataRva:  space = "data "; ++r.CallretValsTracedData; break;
                        case ValSpace::SectionOther: space = "sect "; break;
                        case ValSpace::Unknown:
                        {
                            const ForeignHit fh = DeobfValClassifier::ClassifyForeign(foreignmods, v);
                            if (fh.Mod)
                            {
                                space = "fmod ";
                                char lbl[128];
                                std::snprintf(lbl, sizeof(lbl), "  %s+0x%llx", fh.Mod->Name.c_str(), static_cast<unsigned long long>(fh.Offset));
                                extra = lbl;
                                std::string wide = readforeignwide(fh.Mod->Name, fh.Offset);
                                if (!wide.empty()) { extra += "  L\""; extra += wide; extra += "\""; }
                                else
                                {
                                    std::string ansi = readforeignansi(fh.Mod->Name, fh.Offset);
                                    if (!ansi.empty()) { extra += "  \""; extra += ansi; extra += "\""; }
                                }
                                ++r.CallretValsForeign;
                            }
                            else if (v >= 0x10000ULL && v <= 0x00007FFFFFFFFFFFULL)
                            {
                                space = "stk/hp";
                                ++r.CallretValsStackHeap;
                            }
                            else
                            {
                                space = "?";
                                std::string inl = DeobfValClassifier::DecodeInlineAscii(v);
                                if (!inl.empty()) extra = "  inline:\"" + inl + "\"";
                                ++r.CallretValsUnknown;
                            }
                            break;
                        }
                        default: space = "?"; ++r.CallretValsUnknown; break;
                        }
                    }

                    char rline[320];
                    std::snprintf(rline, sizeof(rline), "     rax=0x%016llx  space=%-6s",
                        static_cast<unsigned long long>(v), space);
                    out << rline;
                    if (!extra.empty()) out << extra;
                    out << "\n";
                }
            }
            out << "\n";
        };

    for (uint64_t siterva : orderedsites)
    {
        const SiteObs& so = persite[siterva];
        const bool hasrets = !so.Rets.empty();
        auto iatit = iatbysite.find(siterva);
        if (iatit != iatbysite.end())
        {
            ++r.CallargSitesIat;
            if (hasrets) ++r.CallretSitesIat;
            emitsite(iatout, siterva, so, &iatit->second);
        }
        else
        {
            ++r.CallargSitesOther;
            if (hasrets) ++r.CallretSitesOther;
            emitsite(othout, siterva, so, nullptr);
        }
    }
    if (iatout) r.CallArgIatLogPath = iatpath;
    if (othout) r.CallArgOtherLogPath = othpath;

    DeobfIo::RuleOpen("call-params");
    std::printf("[deobf]   CallArgHit records read       : %llu\n", static_cast<unsigned long long>(r.CallargRecordsSeen));
    if (r.CallargRecordsSeen == 0)
    {
        std::puts("[deobf]   (callargs.bin empty -- AutoDebug run didn't opt into CaptureCallParams)");
    }
    else
    {
        if (r.CallargNoTracedBase) std::puts("[deobf]   NOTE: modules.tsv missing __traced__ row -- runtime-VA translation disabled");
        std::printf("[deobf]   sites -> callargs.iat.txt     : %u\n", r.CallargSitesIat);
        std::printf("[deobf]   sites -> callargs.other.txt   : %u\n", r.CallargSitesOther);
        std::printf("[deobf]   args classified ANSI string   : %u\n", r.CallargArgsAnsiString);
        std::printf("[deobf]   args classified UTF-16 string : %u\n", r.CallargArgsWideString);
        std::printf("[deobf]   args in traced .rdata (other) : %u\n", r.CallargArgsTracedRdata);
        std::printf("[deobf]   args in traced .data / .bss   : %u\n", r.CallargArgsTracedData);
        std::printf("[deobf]   args in traced .text (fn ptr) : %u\n", r.CallargArgsTracedText);
        std::printf("[deobf]   args in foreign module        : %u\n", r.CallargArgsForeign);
        std::printf("[deobf]   args as plain integer         : %u\n", r.CallargArgsInt);
        std::printf("[deobf]   args as stack/heap VA         : %u\n", r.CallargArgsStackHeap);
        std::printf("[deobf]   args unclassified             : %u\n", r.CallargArgsUnknown);
        if (!r.CallArgIatLogPath.empty()) std::printf("[deobf]   iat log                       : %ls\n", r.CallArgIatLogPath.wstring().c_str());
        if (!r.CallArgOtherLogPath.empty()) std::printf("[deobf]   other log                     : %ls\n", r.CallArgOtherLogPath.wstring().c_str());
    }
    std::printf("[deobf]   CallRetHit records read       : %llu\n", static_cast<unsigned long long>(r.CallretRecordsSeen));
    if (r.CallretRecordsSeen == 0)
    {
        std::puts("[deobf]   (callrets.bin empty -- AutoDebug run didn't opt into CaptureReturns)");
    }
    else
    {
        std::printf("[deobf]   sites with returns (IAT)      : %u\n", r.CallretSitesIat);
        std::printf("[deobf]   sites with returns (other)    : %u\n", r.CallretSitesOther);
        std::printf("[deobf]   ret vals ANSI string          : %u\n", r.CallretValsAnsiString);
        std::printf("[deobf]   ret vals UTF-16 string        : %u\n", r.CallretValsWideString);
        std::printf("[deobf]   ret vals traced .rdata        : %u\n", r.CallretValsTracedRdata);
        std::printf("[deobf]   ret vals traced .data / .bss  : %u\n", r.CallretValsTracedData);
        std::printf("[deobf]   ret vals traced .text         : %u\n", r.CallretValsTracedText);
        std::printf("[deobf]   ret vals foreign module       : %u\n", r.CallretValsForeign);
        std::printf("[deobf]   ret vals plain integer        : %u\n", r.CallretValsInt);
        std::printf("[deobf]   ret vals stack/heap VA        : %u\n", r.CallretValsStackHeap);
        std::printf("[deobf]   ret vals unclassified         : %u\n", r.CallretValsUnknown);
    }
    DeobfIo::RuleClose();
}