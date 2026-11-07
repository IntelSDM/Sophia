#include "../../../Pch.h"
#include "SyscallParamTarget.h"
#include "../DeobfIo.h"
#include "../DeobfValClassifier.h"
#include "../../Database/AutoDebugStore.h"

#include <windows.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <unordered_map>
#include <utility>
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
    struct SyscallSiteObs
    {
        std::unordered_map<uint32_t, uint32_t> ServiceCounts;
        std::vector<ArgObs> Args;
        std::vector<RetObs> Rets;
    };

    const char* ArgRegNameSyscall(uint8_t idx)
    {
        switch (idx)
        {
        case 0: return "R10";
        case 1: return "RDX";
        case 2: return "R8 ";
        case 3: return "R9 ";
        case 4: case 5: case 6: case 7: return "stk";
        }
        return "?";
    }
}

void SyscallParamTarget::Deobfuscate(DeobfContext& ctx, Deobfuscator::Report& r)
{
    std::unordered_map<uint32_t, std::string> syscallbyidx;
    {
        std::ifstream f(ctx.Store->Dir() / L"syscall_table.tsv", std::ios::binary);
        if (f)
        {
            std::string line;
            while (std::getline(f, line))
            {
                if (line.empty() || line[0] == '#') continue;
                const size_t tab = line.find('\t');
                if (tab == std::string::npos) continue;
                const std::string idxstr = line.substr(0, tab);
                std::string name = line.substr(tab + 1);
                while (!name.empty() && (name.back() == '\r' || name.back() == '\n')) name.pop_back();
                if (name.empty()) continue;
                uint32_t idx = 0;
                try { idx = static_cast<uint32_t>(std::stoull(idxstr, nullptr, 16)); }
                catch (...) { continue; }
                syscallbyidx.emplace(idx, std::move(name));
            }
        }
    }
    if (syscallbyidx.empty()) r.SyscallNoTable = true;

    const std::filesystem::path modulestsv = ctx.Store->Dir() / L"modules.tsv";
    uint64_t tracedruntimebase = 0;
    uint64_t tracedruntimesize = 0;
    uint64_t ntdllbase = 0;
    uint64_t ntdllsize = 0;
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
                    if (tab == std::string::npos) 
                    { 
                        cols.push_back(line.substr(start));
                        break;
                    }
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
                    if (name == "ntdll.dll") { ntdllbase = base; ntdllsize = size; }
                    foreignmods.push_back({ name, base, size });
                }
            }
        }
    }
    if (tracedruntimebase == 0)
    {
        r.SyscallNoTracedBase = true;
        tracedruntimebase = ctx.PreferredBase;
    }
    if (ntdllbase == 0) r.SyscallNoNtdllBase = true;
    (void)ntdllsize;

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

    std::unordered_map<uint64_t, SyscallSiteObs> persitedirect;
    std::unordered_map<uint64_t, SyscallSiteObs> persiteindirect;

    ctx.Store->ForEachRecord(ObsKind::SyscallDirect,
        [&](const void* rec, size_t sz)
        {
            ++r.SyscallDirectMasterRecords;
            if (sz != sizeof(SyscallDirectHit)) return;
            const auto* h = static_cast<const SyscallDirectHit*>(rec);
            const uint32_t svc = static_cast<uint32_t>(h->Gpr.rax);
            ++persitedirect[h->Rva].ServiceCounts[svc];
        });
    ctx.Store->ForEachRecord(ObsKind::SyscallDirectArg,
        [&](const void* rec, size_t sz)
        {
            ++r.SyscallDirectArgRecords;
            if (sz != sizeof(SyscallDirectArgHit)) return;
            const auto* h = static_cast<const SyscallDirectArgHit*>(rec);
            ArgObs a; a.Idx = h->ArgIdx; a.Val = h->Val;
            a.Head[0] = h->Head[0]; a.Head[1] = h->Head[1]; a.Head[2] = h->Head[2]; a.Head[3] = h->Head[3];
            persitedirect[h->Rva].Args.push_back(a);
        });
    std::unordered_map<uint64_t, std::unordered_map<uint64_t, RetObs>> retsdirectbysite;
    ctx.Store->ForEachRecord(ObsKind::SyscallDirectRet,
        [&](const void* rec, size_t sz)
        {
            ++r.SyscallDirectRetRecords;
            if (sz != sizeof(SyscallDirectRetHit)) return;
            const auto* h = static_cast<const SyscallDirectRetHit*>(rec);
            const bool hasheads = (h->Head[0] | h->Head[1] | h->Head[2] | h->Head[3]) != 0;
            auto& perrax = retsdirectbysite[h->Rva];
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
    for (auto& [rva, perrax] : retsdirectbysite)
    {
        SyscallSiteObs& so = persitedirect[rva];
        for (auto& [rax, obs] : perrax) so.Rets.push_back(obs);
    }

    ctx.Store->ForEachRecord(ObsKind::SyscallIndirect,
        [&](const void* rec, size_t sz)
        {
            ++r.SyscallIndirectMasterRecords;
            if (sz != sizeof(SyscallIndirectHit)) return;
            const auto* h = static_cast<const SyscallIndirectHit*>(rec);
            const uint32_t svc = static_cast<uint32_t>(h->Gpr.rax);
            ++persiteindirect[h->Rva].ServiceCounts[svc];
        });
    ctx.Store->ForEachRecord(ObsKind::SyscallIndirectArg,
        [&](const void* rec, size_t sz)
        {
            ++r.SyscallIndirectArgRecords;
            if (sz != sizeof(SyscallIndirectArgHit)) return;
            const auto* h = static_cast<const SyscallIndirectArgHit*>(rec);
            ArgObs a; a.Idx = h->ArgIdx; a.Val = h->Val;
            a.Head[0] = h->Head[0]; a.Head[1] = h->Head[1]; a.Head[2] = h->Head[2]; a.Head[3] = h->Head[3];
            persiteindirect[h->Rva].Args.push_back(a);
        });
    std::unordered_map<uint64_t, std::unordered_map<uint64_t, RetObs>> retsindirectbysite;
    ctx.Store->ForEachRecord(ObsKind::SyscallIndirectRet,
        [&](const void* rec, size_t sz)
        {
            ++r.SyscallIndirectRetRecords;
            if (sz != sizeof(SyscallIndirectRetHit)) return;
            const auto* h = static_cast<const SyscallIndirectRetHit*>(rec);
            const bool hasheads = (h->Head[0] | h->Head[1] | h->Head[2] | h->Head[3]) != 0;
            auto& perrax = retsindirectbysite[h->Rva];
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
    for (auto& [rva, perrax] : retsindirectbysite)
    {
        SyscallSiteObs& so = persiteindirect[rva];
        for (auto& [rax, obs] : perrax) so.Rets.push_back(obs);
    }

    r.SyscallDirectSites = static_cast<uint32_t>(persitedirect.size());
    r.SyscallIndirectSites = static_cast<uint32_t>(persiteindirect.size());

    auto ntname = [&](uint32_t svc, bool& named) -> std::string
        {
            auto it = syscallbyidx.find(svc);
            if (it != syscallbyidx.end()) { named = true; return it->second; }
            named = false;
            return {};
        };

    auto emitsite = [&](std::ofstream& out, uint64_t siterva, const SyscallSiteObs& so, const char* spacelabel)
        {
            if (!out) return;

            char hdr[256];
            const size_t uniquesvcs = so.ServiceCounts.size();
            if (uniquesvcs == 1)
            {
                const uint32_t svc = so.ServiceCounts.begin()->first;
                bool named = false;
                std::string name = ntname(svc, named);
                if (named)
                {
                    ++r.SyscallServicesNamed;
                    std::snprintf(hdr, sizeof(hdr), "=== rva=0x%08llx (%s)  ntdll!%s (svc=0x%x) ===\n",
                        static_cast<unsigned long long>(siterva), spacelabel, name.c_str(), svc);
                }
                else
                {
                    ++r.SyscallServicesUnnamed;
                    std::snprintf(hdr, sizeof(hdr), "=== rva=0x%08llx (%s)  svc=0x%x (unresolved) ===\n",
                        static_cast<unsigned long long>(siterva), spacelabel, svc);
                }
                out << hdr;
            }
            else
            {
                std::snprintf(hdr, sizeof(hdr), "=== rva=0x%08llx (%s)  services=%zu ===\n",
                    static_cast<unsigned long long>(siterva), spacelabel, uniquesvcs);
                out << hdr;
                std::vector<std::pair<uint32_t, uint32_t>> svcs(so.ServiceCounts.begin(), so.ServiceCounts.end());
                std::sort(svcs.begin(), svcs.end(), [](const auto& a, const auto& b) { return a.first < b.first; });
                out << "  service(s):\n";
                for (const auto& [svc, count] : svcs)
                {
                    bool named = false;
                    std::string name = ntname(svc, named);
                    char line[160];
                    if (named)
                    {
                        ++r.SyscallServicesNamed;
                        std::snprintf(line, sizeof(line), "    0x%08x  %-40s  (%u fires)\n", svc, name.c_str(), count);
                    }
                    else
                    {
                        ++r.SyscallServicesUnnamed;
                        std::snprintf(line, sizeof(line), "    0x%08x  %-40s  (%u fires)\n", svc, "(unresolved)", count);
                    }
                    out << line;
                }
            }

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
                if (looksint) { space = "int"; ++r.SyscallArgsInt; }
                else if (ansistr || widestr)
                {
                    space = "rdata";
                    if (widestr)
                    {
                        std::string full = readtracedwide(a.Val);
                        if (full.empty()) full = DeobfValClassifier::DecodeWide(a.Head);
                        extra = "  L\"" + full + "\"";
                        ++r.SyscallArgsWideString;
                    }
                    else
                    {
                        std::string full = readtracedansi(a.Val);
                        if (full.empty()) full = DeobfValClassifier::DecodeAnsi(a.Head);
                        extra = "  \"" + full + "\"";
                        ++r.SyscallArgsAnsiString;
                    }
                }
                else
                {
                    switch (vs)
                    {
                    case ValSpace::TextRva:  space = "text "; ++r.SyscallArgsTracedText; break;
                    case ValSpace::RdataRva: space = "rdata"; ++r.SyscallArgsTracedRdata; break;
                    case ValSpace::DataRva:  space = "data "; ++r.SyscallArgsTracedData; break;
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
                            ++r.SyscallArgsForeign;
                        }
                        else if (a.Val >= 0x10000ULL && a.Val <= 0x00007FFFFFFFFFFFULL)
                        {
                            space = "stk/hp";
                            ++r.SyscallArgsStackHeap;
                        }
                        else
                        {
                            space = "?";
                            std::string inl = DeobfValClassifier::DecodeInlineAscii(a.Val);
                            if (!inl.empty()) extra = "  inline:\"" + inl + "\"";
                            ++r.SyscallArgsUnknown;
                        }
                        break;
                    }
                    default: space = "?"; ++r.SyscallArgsUnknown; break;
                    }
                }

                char line[320];
                std::snprintf(line, sizeof(line), "  idx=%u (%s)  val=0x%016llx  space=%-6s",
                    a.Idx, ArgRegNameSyscall(a.Idx), static_cast<unsigned long long>(a.Val), space);
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
                    const bool looksint = (v < 0x10000ULL) || (v >= 0xFFFFFFFF00000000ULL);
                    const char* space = "?";
                    std::string extra;
                    if (looksint) { space = "int"; ++r.SyscallRetsInt; }
                    else if (v >= 0x10000ULL && v <= 0x00007FFFFFFFFFFFULL) { space = "stk/hp"; ++r.SyscallRetsStackHeap; }
                    else { space = "?"; ++r.SyscallRetsUnknown; }

                    char rline[160];
                    std::snprintf(rline, sizeof(rline), "     rax=0x%016llx  space=%-6s", static_cast<unsigned long long>(v), space);
                    out << rline;
                    if (!extra.empty()) out << extra;
                    out << "\n";
                }
            }
            out << "\n";
        };

    const std::filesystem::path directpath = ctx.Store->Dir() / L"syscalls_direct.txt";
    const std::filesystem::path indirectpath = ctx.Store->Dir() / L"syscalls_indirect.txt";
    std::ofstream directout(directpath, std::ios::trunc);
    std::ofstream indirectout(indirectpath, std::ios::trunc);

    if (directout)
    {
        directout << "# Args follow the syscall convention: R10 (arg1), RDX, R8, R9, then stack.\n";
    }
    if (indirectout)
    {
        indirectout << "# Args follow the syscall convention: R10 (arg1), RDX, R8, R9, then stack.\n";
    }

    std::vector<uint64_t> ordereddirect;
    ordereddirect.reserve(persitedirect.size());
    for (const auto& [rva, _] : persitedirect) ordereddirect.push_back(rva);
    std::sort(ordereddirect.begin(), ordereddirect.end());

    std::vector<uint64_t> orderedindirect;
    orderedindirect.reserve(persiteindirect.size());
    for (const auto& [rva, _] : persiteindirect) orderedindirect.push_back(rva);
    std::sort(orderedindirect.begin(), orderedindirect.end());

    for (uint64_t rva : ordereddirect)   emitsite(directout, rva, persitedirect[rva], "traced .text");
    for (uint64_t rva : orderedindirect) emitsite(indirectout, rva, persiteindirect[rva], "ntdll");

    if (directout)   r.SyscallsDirectLogPath = directpath;
    if (indirectout) r.SyscallsIndirectLogPath = indirectpath;

    DeobfIo::RuleOpen("syscall-params");
    std::printf("[deobf]   SyscallDirect  masters read   : %llu\n", static_cast<unsigned long long>(r.SyscallDirectMasterRecords));
    std::printf("[deobf]   SyscallDirect  args read      : %llu\n", static_cast<unsigned long long>(r.SyscallDirectArgRecords));
    std::printf("[deobf]   SyscallDirect  rets read      : %llu\n", static_cast<unsigned long long>(r.SyscallDirectRetRecords));
    std::printf("[deobf]   SyscallIndirect masters read  : %llu\n", static_cast<unsigned long long>(r.SyscallIndirectMasterRecords));
    std::printf("[deobf]   SyscallIndirect args read     : %llu\n", static_cast<unsigned long long>(r.SyscallIndirectArgRecords));
    std::printf("[deobf]   SyscallIndirect rets read     : %llu\n", static_cast<unsigned long long>(r.SyscallIndirectRetRecords));
    if (r.SyscallDirectMasterRecords == 0 && r.SyscallIndirectMasterRecords == 0)
    {
        std::puts("[deobf]   (all 6 syscall SODB files empty -- AutoDebug didn't monitor syscalls)");
    }
    else
    {
        if (r.SyscallNoTable) std::puts("[deobf]   NOTE: syscall_table.tsv missing -- every observed service will be labelled (unresolved)");
        if (r.SyscallNoTracedBase) std::puts("[deobf]   NOTE: modules.tsv missing __traced__ row -- direct-target arg VAs won't map to sections");
        if (r.SyscallNoNtdllBase) std::puts("[deobf]   NOTE: modules.tsv missing ntdll.dll row -- ntdll arg attribution disabled");
        std::printf("[deobf]   direct sites                  : %u\n", r.SyscallDirectSites);
        std::printf("[deobf]   indirect sites                : %u\n", r.SyscallIndirectSites);
        std::printf("[deobf]   services named (via table)    : %u\n", r.SyscallServicesNamed);
        std::printf("[deobf]   services unresolved           : %u\n", r.SyscallServicesUnnamed);
        std::printf("[deobf]   args ANSI string              : %u\n", r.SyscallArgsAnsiString);
        std::printf("[deobf]   args UTF-16 string            : %u\n", r.SyscallArgsWideString);
        std::printf("[deobf]   args traced .rdata            : %u\n", r.SyscallArgsTracedRdata);
        std::printf("[deobf]   args traced .data / .bss      : %u\n", r.SyscallArgsTracedData);
        std::printf("[deobf]   args traced .text (fn ptr)    : %u\n", r.SyscallArgsTracedText);
        std::printf("[deobf]   args foreign module           : %u\n", r.SyscallArgsForeign);
        std::printf("[deobf]   args plain integer            : %u\n", r.SyscallArgsInt);
        std::printf("[deobf]   args stack/heap VA            : %u\n", r.SyscallArgsStackHeap);
        std::printf("[deobf]   args unclassified             : %u\n", r.SyscallArgsUnknown);
        std::printf("[deobf]   ret vals plain integer        : %u\n", r.SyscallRetsInt);
        std::printf("[deobf]   ret vals stack/heap VA        : %u\n", r.SyscallRetsStackHeap);
        std::printf("[deobf]   ret vals unclassified         : %u\n", r.SyscallRetsUnknown);
        if (!r.SyscallsDirectLogPath.empty())   std::printf("[deobf]   direct log                    : %ls\n", r.SyscallsDirectLogPath.wstring().c_str());
        if (!r.SyscallsIndirectLogPath.empty()) std::printf("[deobf]   indirect log                  : %ls\n", r.SyscallsIndirectLogPath.wstring().c_str());
    }
    DeobfIo::RuleClose();
}