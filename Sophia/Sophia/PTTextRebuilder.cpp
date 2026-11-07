#include "../Pch.h"
#include "PTTextRebuilder.h"
#include "PTTextHelpers.h"
#include <keystone/keystone.h>
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <unordered_map>

PtTextRebuilder::PtTextRebuilder(HyperDbgSession& session, const PtAnalysis& analysis, const std::vector<PEDumper::DumpResult>& dumps)
    : Session(session)
    , Analysis(analysis)
    , Dumps(dumps)
    , Ks(nullptr)
{
    if (ks_open(KS_ARCH_X86, KS_MODE_64, &Ks) != KS_ERR_OK)
    {
        throw std::runtime_error("PtTextRebuilder: ks_open failed");
    }
    ks_option(Ks, KS_OPT_SYNTAX, KS_OPT_SYNTAX_INTEL);
}

PtTextRebuilder::~PtTextRebuilder()
{
    if (Ks)
    {
        ks_close(Ks);
    }
}

bool PtTextRebuilder::TryAssemble(const std::string& text, uint64_t va, std::vector<uint8_t>& out)
{
    unsigned char* enc = nullptr;
    size_t sz = 0, cnt = 0;
    if (ks_asm(Ks, text.c_str(), va, &enc, &sz, &cnt) != KS_ERR_OK)
    {
        return false;
    }
    out.assign(enc, enc + sz);
    ks_free(enc);
    return true;
}

bool PtTextRebuilder::ResolveSlot(uint32_t pid, uint64_t slot, const std::vector<uint8_t>& buf, uint64_t base, uint64_t& target)
{
    uint64_t v = 0;
    if (Session.Read(pid, slot, &v, sizeof(v), HyperDbgMemory::ReadPath::FromVmxRoot) && PtTextHelpers::PlausiblePointer(v))
    {
        target = v;
        return true;
    }
    if (slot >= base && slot + sizeof(uint64_t) <= base + buf.size())
    {
        uint64_t fv = 0;
        std::memcpy(&fv, buf.data() + (slot - base), sizeof(fv));
        if (PtTextHelpers::PlausiblePointer(fv))
        {
            target = fv;
            return true;
        }
    }
    return false;
}

bool PtTextRebuilder::EncodeOne(const PtInsn& insn, uint32_t pid, std::vector<uint8_t>& buf, uint64_t base, uint64_t nextrva, ModuleReport& rep, std::vector<uint8_t>& out)
{
    const std::string& m = insn.Mnemonic;
    const uint64_t va = insn.Va;
    const std::string tok = PtTextHelpers::FirstToken(m);

    if (tok.rfind("nop", 0) == 0 && (m.find('[') != std::string::npos || m.find(',') != std::string::npos))
    {
        uint32_t n = 1;
        if (nextrva != UINT64_MAX && nextrva > insn.Rva)
        {
            uint64_t gap = nextrva - insn.Rva;
            if (gap >= 1 && gap <= 15)
            {
                n = static_cast<uint32_t>(gap);
            }
        }
        out = PtTextHelpers::CanonicalNop(n);
        return true;
    }

    uint64_t absval = 0;
    size_t lb = 0, rb = 0;
    const bool hasabsmem = PtTextHelpers::FindBareAbsMem(m, absval, lb, rb);

    if (hasabsmem && PtTextHelpers::IsIndirectBranch(tok))
    {
        uint64_t target = 0;
        const bool resolved = ResolveSlot(pid, absval, buf, base, target);

        if (resolved)
        {
            char direct[64];
            std::snprintf(direct, sizeof(direct), "%s 0x%llx", tok.c_str(), static_cast<unsigned long long>(target));
            if (TryAssemble(direct, va, out))
            {
                rep.ImportsDirect++;
                return true;
            }

            std::vector<uint8_t> probe;
            std::string probetxt = PtTextHelpers::ReplaceBracket(m, lb, rb, PtTextHelpers::RipInner(0));
            if (!TryAssemble(probetxt, va, probe))
            {
                rep.Failed++;
                return false;
            }
            int64_t disp = static_cast<int64_t>(absval - (va + probe.size()));
            std::string fixed = PtTextHelpers::ReplaceBracket(m, lb, rb, PtTextHelpers::RipInner(disp));
            if (!TryAssemble(fixed, va, out))
            {
                rep.Failed++;
                return false;
            }

            if (absval >= base && absval + sizeof(uint64_t) <= base + buf.size())
            {
                std::memcpy(buf.data() + (absval - base), &target, sizeof(target));
                rep.ImportsPatched++;
            }
            return true;
        }

        std::vector<uint8_t> probe;
        std::string probetxt = PtTextHelpers::ReplaceBracket(m, lb, rb, PtTextHelpers::RipInner(0));
        if (!TryAssemble(probetxt, va, probe))
        {
            rep.Failed++;
            return false;
        }
        int64_t disp = static_cast<int64_t>(absval - (va + probe.size()));
        std::string fixed = PtTextHelpers::ReplaceBracket(m, lb, rb, PtTextHelpers::RipInner(disp));
        if (!TryAssemble(fixed, va, out))
        {
            rep.Failed++;
            return false;
        }
        rep.ImportsUnresolved++;
        return true;
    }

    if (hasabsmem && !PtTextHelpers::IsBranch(tok) && absval >= 0x10000)
    {
        std::vector<uint8_t> probe;
        std::string probetxt = PtTextHelpers::ReplaceBracket(m, lb, rb, PtTextHelpers::RipInner(0));
        if (!TryAssemble(probetxt, va, probe))
        {
            rep.Failed++;
            return false;
        }
        int64_t disp = static_cast<int64_t>(absval - (va + probe.size()));
        std::string fixed = PtTextHelpers::ReplaceBracket(m, lb, rb, PtTextHelpers::RipInner(disp));
        if (!TryAssemble(fixed, va, out))
        {
            rep.Failed++;
            return false;
        }
        rep.RipRewrites++;
        return true;
    }

    if (!TryAssemble(m, va, out))
    {
        rep.Failed++;
        return false;
    }
    return true;
}

PtTextRebuilder::ModuleReport PtTextRebuilder::RebuildModule(const PEDumper::DumpResult& dump, const std::vector<PtInsn>& insns, const std::wstring& outputsuffix)
{
    ModuleReport rep;
    rep.BaseName = dump.Module.BaseName;
    rep.Base = dump.Module.Base;
    rep.Instructions = static_cast<uint32_t>(insns.size());

    std::ifstream in(dump.OutPath, std::ios::binary | std::ios::ate);
    if (!in)
    {
        rep.Error = "open dump failed";
        return rep;
    }
    std::streamsize len = in.tellg();
    in.seekg(0);
    std::vector<uint8_t> buf(static_cast<size_t>(len));
    if (!in.read(reinterpret_cast<char*>(buf.data()), len))
    {
        rep.Error = "read dump failed";
        return rep;
    }
    in.close();

    if (buf.size() < sizeof(IMAGE_DOS_HEADER))
    {
        rep.Error = "dump too small";
        return rep;
    }
    auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(buf.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || static_cast<size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS64) > buf.size())
    {
        rep.Error = "bad DOS header";
        return rep;
    }
    auto nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(buf.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
    {
        rep.Error = "bad NT header";
        return rep;
    }

    nt->OptionalHeader.ImageBase = dump.Module.Base;

    const uint64_t base = dump.Module.Base;
    const uint32_t imagesize = nt->OptionalHeader.SizeOfImage;

    {
        auto sec = IMAGE_FIRST_SECTION(nt);
        const DWORD codeflags = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE;
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i)
        {
            if (!(sec[i].Characteristics & codeflags))
            {
                continue;
            }
            uint64_t rva = sec[i].VirtualAddress;
            uint64_t vsz = sec[i].Misc.VirtualSize;
            if (rva >= buf.size())
            {
                continue;
            }
            if (rva + vsz > buf.size())
            {
                vsz = buf.size() - rva;
            }
            std::memset(buf.data() + rva, 0xCC, static_cast<size_t>(vsz));
        }
    }

    for (size_t i = 0; i < insns.size(); ++i)
    {
        const PtInsn& insn = insns[i];
        const uint64_t nextrva = (i + 1 < insns.size()) ? insns[i + 1].Rva : UINT64_MAX;

        std::vector<uint8_t> bytes;
        if (!EncodeOne(insn, dump.Module.Pid, buf, base, nextrva, rep, bytes))
        {
            continue;
        }

        const uint64_t off = insn.Rva;
        if (off >= imagesize || off + bytes.size() > buf.size())
        {
            rep.Failed++;
            continue;
        }
        std::memcpy(buf.data() + off, bytes.data(), bytes.size());
        rep.Encoded++;

        if (nextrva != UINT64_MAX)
        {
            uint64_t truelen = nextrva - off;
            uint64_t enclen = bytes.size();

            if (enclen > truelen)
            {
                rep.Overlaps++;
            }
            else if (enclen < truelen && truelen <= 15)
            {
                std::vector<uint8_t> pad = PtTextHelpers::CanonicalNop(static_cast<uint32_t>(truelen - enclen));
                uint64_t padoff = off + enclen;
                if (padoff + pad.size() <= buf.size())
                {
                    std::memcpy(buf.data() + padoff, pad.data(), pad.size());
                    rep.NopPads++;
                }
            }
        }
    }

    std::filesystem::path outpath = dump.OutPath;
    outpath += outputsuffix;
    std::ofstream out(outpath, std::ios::binary | std::ios::trunc);
    if (!out || !out.write(reinterpret_cast<const char*>(buf.data()), buf.size()))
    {
        rep.Error = "write rebuilt image failed";
        return rep;
    }
    rep.OutPath = outpath;
    rep.Ok = true;
    return rep;
}

std::vector<PtTextRebuilder::ModuleReport> PtTextRebuilder::Rebuild(const std::filesystem::path& manifestpath, const std::wstring& outputsuffix)
{
    std::vector<ModuleReport> reports;

    std::vector<PtInsn> all = Analysis.GetAllInstructions();

    struct Range
    {
        uint64_t Lo;
        uint64_t Hi;
        const PEDumper::DumpResult* Dump;
    };
    std::vector<Range> ranges;
    for (const auto& d : Dumps)
    {
        if (!d.Ok)
        {
            continue;
        }
        ranges.push_back({ d.Module.Base, d.Module.Base + d.Module.Size, &d });
    }
    std::sort(ranges.begin(), ranges.end(), [](const Range& a, const Range& b)
        {
            return a.Lo < b.Lo;
        });

    auto findrange = [&](uint64_t va) -> const Range*
        {
            size_t lo = 0, hi = ranges.size();
            while (lo < hi)
            {
                size_t mid = (lo + hi) / 2;
                if (ranges[mid].Lo <= va)
                {
                    lo = mid + 1;
                }
                else
                {
                    hi = mid;
                }
            }
            if (lo == 0)
            {
                return nullptr;
            }
            const Range& r = ranges[lo - 1];
            return (va >= r.Lo && va < r.Hi) ? &r : nullptr;
        };

    std::unordered_map<const PEDumper::DumpResult*, std::vector<PtInsn>> bymodule;
    uint64_t unattributed = 0;
    for (const auto& insn : all)
    {
        const Range* r = findrange(insn.Va);
        if (!r)
        {
            ++unattributed;
            continue;
        }
        PtInsn fixed = insn;
        fixed.Rva = insn.Va - r->Dump->Module.Base;
        bymodule[r->Dump].push_back(std::move(fixed));
    }
    if (unattributed)
    {
        std::fprintf(stderr, "[!] PtTextRebuilder: %llu executed insn(s) fell outside every dumped module range (module not enumerated?)\n", static_cast<unsigned long long>(unattributed));
    }

    std::ofstream mf(manifestpath, std::ios::binary | std::ios::trunc);
    if (mf)
    {
        mf << "# base            size        path                                  name\n";
    }

    for (auto& kv : bymodule)
    {
        std::sort(kv.second.begin(), kv.second.end(), [](const PtInsn& a, const PtInsn& b)
            {
                return a.Va < b.Va;
            });

        ModuleReport rep = RebuildModule(*kv.first, kv.second, outputsuffix);
        if (rep.Ok && mf)
        {
            char line[64];
            std::snprintf(line, sizeof(line), "0x%016llx  0x%08x  ", static_cast<unsigned long long>(kv.first->Module.Base), kv.first->Module.Size);
            mf << line << rep.OutPath.string() << "  " << std::string(kv.first->Module.BaseName.begin(), kv.first->Module.BaseName.end()) << "\n";
        }
        reports.push_back(std::move(rep));
    }

    return reports;
}

void PtTextRebuilder::PrintReport(const std::vector<ModuleReport>& reports)
{
    std::printf("\n===================== PT .text rebuild ======================\n");
    std::printf("  %-24s %8s %8s %7s %8s %8s\n", "module", "insns", "encoded", "failed", "imports", "riprel");
    for (const auto& r : reports)
    {
        std::string name(r.BaseName.begin(), r.BaseName.end());
        if (!r.Ok)
        {
            std::printf("  %-24s  FAILED: %s\n", name.c_str(), r.Error.c_str());
            continue;
        }
        std::printf("  %-24s %8u %8u %7u %8u %8u\n", name.c_str(), r.Instructions, r.Encoded, r.Failed, r.ImportsDirect + r.ImportsPatched, r.RipRewrites);
        if (r.NopPads || r.ImportsUnresolved || r.Overlaps)
        {
            std::printf("      (nop-padded gaps: %u, unresolved imports: %u, length overlaps: %u)\n", r.NopPads, r.ImportsUnresolved, r.Overlaps);
        }
        std::printf("      -> %ls\n", r.OutPath.wstring().c_str());
    }
}