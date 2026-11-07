#include "../Pch.h"
#include "PTAnalysis.h"
#include "PtParseUtil.h"


PtAnalysis::PtAnalysis()
{
    Scratch.reserve(16);
    PartialLine.reserve(256);
}

void PtAnalysis::Reset()
{
    Scratch.clear();
    PartialLine.clear();
    ParsedLines = 0;
    SkippedLines = 0;
}

void PtAnalysis::Ingest(const char* nullterminatedchunk)
{
    Ingest(nullterminatedchunk, std::strlen(nullterminatedchunk));
}

void PtAnalysis::Ingest(const char* chunk, size_t len)
{
    const char* p = chunk;
    const char* end = chunk + len;

    while (p < end)
    {
        const char* nl = static_cast<const char*>(std::memchr(p, '\n', end - p));
        if (nl == nullptr)
        {
            PartialLine.append(p, end - p);
            return;
        }

        if (PartialLine.empty())
        {
            IngestLine(p, nl - p);
        }
        else
        {
            PartialLine.append(p, nl - p);
            IngestLine(PartialLine.data(), PartialLine.size());
            PartialLine.clear();
        }
        p = nl + 1;
    }
}

void PtAnalysis::IngestLine(const char* line, size_t len)
{
    const char* end = line + len;

    const char* cur = PtParseUtil::SkipSpace(line, end);

    if (cur + 2 >= end || cur[0] != '0' || (cur[1] != 'x' && cur[1] != 'X'))
    {
        SkippedLines++;
        return;
    }
    cur += 2;

    auto [va, afterva] = PtParseUtil::ParseHex(cur, end);
    if (afterva == cur)
    {
        SkippedLines++;
        return;
    }
    cur = PtParseUtil::SkipSpace(afterva, end);

    const char* namestart = cur;
    while (cur < end && *cur != '+' && *cur != ' ' && *cur != '\t')
    {
        ++cur;
    }
    if (cur >= end || *cur != '+' || cur == namestart)
    {
        SkippedLines++;
        return;
    }
    std::string name(namestart, static_cast<size_t>(cur - namestart));
    ++cur;
    cur = PtParseUtil::SkipHexPrefix(cur, end);
    auto [rva, afterrva] = PtParseUtil::ParseHex(cur, end);
    if (afterrva == cur)
    {
        SkippedLines++;
        return;
    }

    ParsedLines++;

    auto it = Scratch.find(name);
    if (it == Scratch.end())
    {
        ModuleScratch fresh;
        fresh.Stats.Name = name;
        it = Scratch.emplace(std::move(name), std::move(fresh)).first;
    }
    ModuleScratch& ms = it->second;

    ms.Stats.TotalHits++;
    bool firstseen = ms.AddrSet.insert(va).second;
    if (firstseen) ms.Stats.UniqueAddresses++;
    uint64_t page = va & ~uint64_t(0xFFF);
    if (ms.PageSet.insert(page).second) ms.Stats.UniquePages++;
    if (rva < ms.Stats.MinRva) ms.Stats.MinRva = rva;
    if (rva > ms.Stats.MaxRva) ms.Stats.MaxRva = rva;

    if (firstseen)
    {
        const char* mnstart = PtParseUtil::SkipSpace(afterrva, end);
        const char* mnend = end;
        while (mnend > mnstart && (mnend[-1] == '\r' || mnend[-1] == ' ' || mnend[-1] == '\t'))
        {
            --mnend;
        }

        ModuleScratch::InsnRecord rec;
        rec.Rva = rva;
        rec.Mnemonic.assign(mnstart, static_cast<size_t>(mnend - mnstart));
        ms.Insns.emplace(va, std::move(rec));
    }
}

PtTraceStats PtAnalysis::Snapshot() const
{
    PtTraceStats out;
    out.ParsedLines = ParsedLines;
    out.SkippedLines = SkippedLines;

    for (const auto& kv : Scratch)
    {
        out.TotalInstructions += kv.second.Stats.TotalHits;
        out.UniqueAddresses += kv.second.Stats.UniqueAddresses;
        out.UniquePages += kv.second.Stats.UniquePages;
        out.Modules.emplace(kv.first, kv.second.Stats);
    }
    return out;
}

PtTraceStats PtAnalysis::AnalyzeString(const std::string& dump)
{
    PtAnalysis a;
    a.Ingest(dump.data(), dump.size());
    if (!a.PartialLine.empty())
    {
        a.IngestLine(a.PartialLine.data(), a.PartialLine.size());
        a.PartialLine.clear();
    }
    return a.Snapshot();
}

void PtAnalysis::PrintSummary(const PtTraceStats& stats)
{
    std::printf("\n============================== PT trace summary ==============================\n");
    std::printf("  parsed lines       : %llu\n", static_cast<unsigned long long>(stats.ParsedLines));
    std::printf("  skipped lines      : %llu (headers, meta, blank)\n", static_cast<unsigned long long>(stats.SkippedLines));
    std::printf("  total instructions : %llu\n", static_cast<unsigned long long>(stats.TotalInstructions));
    std::printf("  unique addresses   : %llu\n", static_cast<unsigned long long>(stats.UniqueAddresses));
    std::printf("  unique code pages  : %llu (%llu KB of code touched)\n", static_cast<unsigned long long>(stats.UniquePages), static_cast<unsigned long long>(stats.UniquePages * 4));
    std::printf("  modules seen       : %zu\n", stats.Modules.size());

    std::vector<const PtModuleStats*> sorted;
    sorted.reserve(stats.Modules.size());
    for (const auto& kv : stats.Modules)
    {
        sorted.push_back(&kv.second);
    }
    std::sort(sorted.begin(), sorted.end(), [](const PtModuleStats* a, const PtModuleStats* b)
        {
            return a->TotalHits > b->TotalHits;
        });

    std::printf("\n  %-16s %12s %12s %10s %12s %12s\n", "module", "hits", "unique", "pages", "min rva", "max rva");
    std::printf("  %-16s %12s %12s %10s %12s %12s\n", "------", "----", "------", "-----", "-------", "-------");
    for (const PtModuleStats* m : sorted)
    {
        std::printf("  %-16s %12llu %12llu %10llu %12llx %12llx\n",
            m->Name.c_str(),
            static_cast<unsigned long long>(m->TotalHits),
            static_cast<unsigned long long>(m->UniqueAddresses),
            static_cast<unsigned long long>(m->UniquePages),
            static_cast<unsigned long long>(m->MinRva),
            static_cast<unsigned long long>(m->MaxRva));
    }
    std::printf("==============================================================================\n\n");
}

std::vector<uint64_t> PtAnalysis::GetUniqueAddresses(const std::string& modulename) const
{
    auto it = Scratch.find(modulename);
    if (it == Scratch.end()) return {};
    std::vector<uint64_t> out(it->second.AddrSet.begin(), it->second.AddrSet.end());
    std::sort(out.begin(), out.end());
    return out;
}

std::vector<uint64_t> PtAnalysis::GetUniquePages(const std::string& modulename) const
{
    auto it = Scratch.find(modulename);
    if (it == Scratch.end()) return {};
    std::vector<uint64_t> out(it->second.PageSet.begin(), it->second.PageSet.end());
    std::sort(out.begin(), out.end());
    return out;
}

std::vector<PtInsn> PtAnalysis::GetAllInstructions() const
{
    std::vector<PtInsn> out;
    size_t total = 0;
    for (const auto& kv : Scratch)
    {
        total += kv.second.Insns.size();
    }
    out.reserve(total);

    for (const auto& kv : Scratch)
    {
        for (const auto& in : kv.second.Insns)
        {
            out.push_back(PtInsn{ in.first, in.second.Rva, in.second.Mnemonic });
        }
    }
    std::sort(out.begin(), out.end(), [](const PtInsn& a, const PtInsn& b)
        {
            return a.Va < b.Va;
        });
    return out;
}

bool PtAnalysis::WriteJson(const std::string& path, bool includeaddresses) const
{
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f)
    {
        std::fprintf(stderr, "[!] WriteJson: could not open '%s'\n", path.c_str());
        return false;
    }

    PtTraceStats summary = Snapshot();

    std::vector<const ModuleScratch*> mods;
    mods.reserve(Scratch.size());
    for (const auto& kv : Scratch)
    {
        mods.push_back(&kv.second);
    }
    std::sort(mods.begin(), mods.end(), [](const ModuleScratch* a, const ModuleScratch* b)
        {
            return a->Stats.Name < b->Stats.Name;
        });

    char sbuf[256];

    f << "{\n";

    f << "  \"trace_summary\": {\n";
    std::snprintf(sbuf, sizeof(sbuf),
        "    \"parsed_lines\": %llu,\n"
        "    \"skipped_lines\": %llu,\n"
        "    \"total_instructions\": %llu,\n"
        "    \"unique_addresses\": %llu,\n"
        "    \"unique_pages\": %llu,\n"
        "    \"modules_seen\": %zu\n",
        static_cast<unsigned long long>(summary.ParsedLines),
        static_cast<unsigned long long>(summary.SkippedLines),
        static_cast<unsigned long long>(summary.TotalInstructions),
        static_cast<unsigned long long>(summary.UniqueAddresses),
        static_cast<unsigned long long>(summary.UniquePages),
        summary.Modules.size());
    f << sbuf;
    f << "  },\n";

    f << "  \"modules\": {\n";
    for (size_t i = 0; i < mods.size(); ++i)
    {
        const ModuleScratch& m = *mods[i];
        std::snprintf(sbuf, sizeof(sbuf),
            "    \"%s\": {\n"
            "      \"hits\": %llu,\n"
            "      \"unique_addresses\": %llu,\n"
            "      \"unique_pages\": %llu,\n"
            "      \"min_rva\": \"0x%llx\",\n"
            "      \"max_rva\": \"0x%llx\",\n",
            m.Stats.Name.c_str(),
            static_cast<unsigned long long>(m.Stats.TotalHits),
            static_cast<unsigned long long>(m.Stats.UniqueAddresses),
            static_cast<unsigned long long>(m.Stats.UniquePages),
            static_cast<unsigned long long>(m.Stats.MinRva),
            static_cast<unsigned long long>(m.Stats.MaxRva));
        f << sbuf;

        std::vector<uint64_t> pages(m.PageSet.begin(), m.PageSet.end());
        std::sort(pages.begin(), pages.end());
        f << "      \"pages\": [";
        PtParseUtil::EmitHexArray(f, pages);
        f << "]";

        if (includeaddresses)
        {
            f << ",\n";
            std::vector<uint64_t> addrs(m.AddrSet.begin(), m.AddrSet.end());
            std::sort(addrs.begin(), addrs.end());
            f << "      \"addresses\": [";
            PtParseUtil::EmitHexArray(f, addrs);
            f << "]\n";
        }
        else
        {
            f << "\n";
        }

        f << (i + 1 == mods.size() ? "    }\n" : "    },\n");
    }
    f << "  }\n";
    f << "}\n";

    if (!f.good())
    {
        std::fprintf(stderr, "[!] WriteJson: write to '%s' failed\n", path.c_str());
        return false;
    }

    f.flush();
    auto pos = f.tellp();
    std::printf("[+] wrote analysis JSON (%lld bytes) -> %s\n", static_cast<long long>(pos), path.c_str());
    return true;
}

bool PtAnalysis::WriteDump(const std::string& path) const
{
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f)
    {
        std::fprintf(stderr, "[!] WriteDump: could not open '%s'\n", path.c_str());
        return false;
    }

    f << "va,module,rva,mnemonic\n";

    struct Row
    {
        const std::string* Module;
        uint64_t Va;
        const ModuleScratch::InsnRecord* Rec;
    };
    std::vector<Row> rows;
    size_t total = 0;
    for (const auto& kv : Scratch)
    {
        total += kv.second.Insns.size();
    }
    rows.reserve(total);
    for (const auto& kv : Scratch)
    {
        for (const auto& insn : kv.second.Insns)
        {
            rows.push_back({ &kv.second.Stats.Name, insn.first, &insn.second });
        }
    }
    std::sort(rows.begin(), rows.end(), [](const Row& a, const Row& b)
        {
            if (*a.Module != *b.Module) return *a.Module < *b.Module;
            return a.Va < b.Va;
        });

    char nbuf[64];
    for (const Row& r : rows)
    {
        int n = std::snprintf(nbuf, sizeof(nbuf), "0x%llx,", static_cast<unsigned long long>(r.Va));
        f.write(nbuf, n);
        f.write(r.Module->data(), static_cast<std::streamsize>(r.Module->size()));
        n = std::snprintf(nbuf, sizeof(nbuf), ",0x%llx,", static_cast<unsigned long long>(r.Rec->Rva));
        f.write(nbuf, n);
        PtParseUtil::EmitCsvMnemonic(f, r.Rec->Mnemonic);
        f.put('\n');
    }

    if (!f.good())
    {
        std::fprintf(stderr, "[!] WriteDump: write to '%s' failed\n", path.c_str());
        return false;
    }
    f.flush();
    auto pos = f.tellp();
    std::printf("[+] wrote instruction dump (%zu unique instructions, %lld bytes) -> %s\n", rows.size(), static_cast<long long>(pos), path.c_str());
    return true;
}