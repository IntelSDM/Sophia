#include "../../Pch.h"
#include "AutoDebugHits.h"
#include "AutoDebugUtils.h"



AutoDebugHitParser::AutoDebugHitParser(AutoDebugStore& store, const std::vector<InsnSite>& sites, HitFlavor flavor)
    : Store(store), Flavor(flavor)
{
    KindByRva.reserve(sites.size() * 2);
    for (const InsnSite& s : sites)
    {
        KindByRva.emplace(s.Rva, s.Kind);
    }
}

size_t AutoDebugHitParser::FindKV(const std::string& line, const char* key)
{
    const size_t klen = std::strlen(key);
    size_t p = 0;
    while (p < line.size())
    {
        const size_t f = line.find(key, p);
        if (f == std::string::npos)
        {
            return std::string::npos;
        }
        if (f > 0 && AutoDebugUtils::IsAlnumOrUnderscore(line[f - 1]))
        {
            p = f + 1;
            continue;
        }
        if (f + klen >= line.size() || line[f + klen] != '=')
        {
            p = f + 1;
            continue;
        }
        return f + klen + 1;
    }
    return std::string::npos;
}

bool AutoDebugHitParser::GetHexKV(const std::string& line, const char* key, uint64_t& out)
{
    size_t v = FindKV(line, key);
    if (v == std::string::npos)
    {
        return false;
    }
    if (v + 1 < line.size() && line[v] == '0' && (line[v + 1] == 'x' || line[v + 1] == 'X'))
    {
        v += 2;
    }
    uint64_t val = 0;
    bool any = false;
    while (v < line.size())
    {
        const char c = line[v];
        int d;
        if (c >= '0' && c <= '9')
        {
            d = c - '0';
        }
        else if (c >= 'a' && c <= 'f')
        {
            d = 10 + (c - 'a');
        }
        else if (c >= 'A' && c <= 'F')
        {
            d = 10 + (c - 'A');
        }
        else
        {
            break;
        }
        val = (val << 4) | static_cast<uint64_t>(d);
        any = true;
        ++v;
    }
    if (!any)
    {
        return false;
    }
    out = val;
    return true;
}

bool AutoDebugHitParser::GetDecKV(const std::string& line, const char* key, uint64_t& out)
{
    size_t v = FindKV(line, key);
    if (v == std::string::npos)
    {
        return false;
    }
    uint64_t val = 0;
    bool any = false;
    while (v < line.size())
    {
        const char c = line[v];
        if (c < '0' || c > '9')
        {
            break;
        }
        val = val * 10 + static_cast<uint64_t>(c - '0');
        any = true;
        ++v;
    }
    if (!any)
    {
        return false;
    }
    out = val;
    return true;
}

bool AutoDebugHitParser::GetStrKV(const std::string& line, const char* key, std::string& out)
{
    const size_t v = FindKV(line, key);
    if (v == std::string::npos)
    {
        return false;
    }
    size_t start = v;
    size_t end = v;
    while (end < line.size() && AutoDebugUtils::IsAlnumOrUnderscore(line[end]))
    {
        ++end;
    }
    if (end == start)
    {
        return false;
    }
    out.assign(line, start, end - start);
    for (char& c : out)
    {
        if (c >= 'A' && c <= 'Z')
        {
            c = static_cast<char>(c + ('a' - 'A'));
        }
    }
    return true;
}

void AutoDebugHitParser::ParseHitLine(const std::string& line, HitAccum& acc, Stats& stats)
{
    uint64_t rva = 0;
    if (!GetHexKV(line, "rva", rva))
    {
        ++stats.ParseErrors;
        return;
    }

    acc.HaveHit = true;
    acc.Rva = rva;

    GetHexKV(line, "rax", acc.Gpr.rax);
    GetHexKV(line, "rbx", acc.Gpr.rbx);
    GetHexKV(line, "rcx", acc.Gpr.rcx);
    GetHexKV(line, "rdx", acc.Gpr.rdx);
    GetHexKV(line, "rsi", acc.Gpr.rsi);
    GetHexKV(line, "rdi", acc.Gpr.rdi);
    GetHexKV(line, "rbp", acc.Gpr.rbp);
    GetHexKV(line, "rsp", acc.Gpr.rsp);
    GetHexKV(line, "r8", acc.Gpr.r8);
    GetHexKV(line, "r9", acc.Gpr.r9);
    GetHexKV(line, "r10", acc.Gpr.r10);
    GetHexKV(line, "r11", acc.Gpr.r11);
    GetHexKV(line, "r12", acc.Gpr.r12);
    GetHexKV(line, "r13", acc.Gpr.r13);
    GetHexKV(line, "r14", acc.Gpr.r14);
    GetHexKV(line, "r15", acc.Gpr.r15);
    GetHexKV(line, "rflags", acc.Gpr.rflags);
    ++stats.HitsSeen;
}

void AutoDebugHitParser::ParseMemLine(const std::string& line, HitAccum& acc, Stats& stats)
{
    uint64_t rva = 0;
    if (!GetHexKV(line, "rva", rva) || !acc.HaveHit || rva != acc.Rva)
    {
        ++stats.ParseErrors;
        return;
    }
    uint64_t val = 0;
    if (GetHexKV(line, "val", val))
    {
        acc.HaveMem = true;
        acc.MemLo = val;
        acc.MemHi = 0;
        return;
    }
    uint64_t lo = 0;
    uint64_t hi = 0;
    if (GetHexKV(line, "lo", lo) && GetHexKV(line, "hi", hi))
    {
        acc.HaveMem = true;
        acc.MemLo = lo;
        acc.MemHi = hi;
        return;
    }
    ++stats.ParseErrors;
}

void AutoDebugHitParser::ParseStrLine(const std::string& line, HitAccum& acc, Stats& stats)
{
    uint64_t rva = 0;
    if (!GetHexKV(line, "rva", rva) || !acc.HaveHit || rva != acc.Rva)
    {
        ++stats.ParseErrors;
        return;
    }
    std::string ptr;
    uint64_t addr = 0;
    uint64_t len = 0;
    if (!GetStrKV(line, "ptr", ptr) || !GetHexKV(line, "addr", addr) || !GetHexKV(line, "len", len))
    {
        ++stats.ParseErrors;
        return;
    }
    HitAccum::StringExtra& dst = (ptr == "rdi") ? acc.StrRdi : acc.StrRsi;
    dst.Have = true;
    dst.Addr = addr;
    dst.LenRcx = len;

    char keybuf[4] = { 'b', 0, 0, 0 };
    for (int i = 0; i < 8; ++i)
    {
        keybuf[1] = static_cast<char>('0' + i);
        keybuf[2] = '\0';
        uint64_t q = 0;
        GetHexKV(line, keybuf, q);
        dst.Window[i] = q;
    }
}

void AutoDebugHitParser::ParseVecLine(const std::string& line, HitAccum& acc, Stats& stats)
{
    uint64_t rva = 0;
    if (!GetHexKV(line, "rva", rva) || !acc.HaveHit || rva != acc.Rva)
    {
        ++stats.ParseErrors;
        return;
    }
    acc.HaveVec = true;
    acc.VecQwords = 0;
    char keybuf[4] = { 'v', 0, 0, 0 };
    for (int i = 0; i < 4; ++i)
    {
        keybuf[1] = static_cast<char>('0' + i);
        keybuf[2] = '\0';
        uint64_t q = 0;
        if (GetHexKV(line, keybuf, q))
        {
            acc.VecWindow[i] = q;
            acc.VecQwords = static_cast<uint16_t>(i + 1);
        }
        else
        {
            acc.VecWindow[i] = 0;
        }
    }
}

void AutoDebugHitParser::ParseMovLine(const std::string& line, HitAccum& acc, Stats& stats)
{
    uint64_t rva = 0;
    if (!GetHexKV(line, "rva", rva) || !acc.HaveHit || rva != acc.Rva)
    {
        ++stats.ParseErrors;
        return;
    }
    uint64_t val = 0;
    if (!GetHexKV(line, "val", val))
    {
        ++stats.ParseErrors;
        return;
    }
    acc.HaveMov = true;
    acc.MovVal = val;
}

void AutoDebugHitParser::ParseAriLine(const std::string& line, HitAccum& acc, Stats& stats)
{
    uint64_t rva = 0;
    if (!GetHexKV(line, "rva", rva) || !acc.HaveHit || rva != acc.Rva)
    {
        ++stats.ParseErrors;
        return;
    }
    acc.HaveAri = true;
    GetHexKV(line, "rval", acc.AriRval);
    GetHexKV(line, "rval2", acc.AriRval2);
    GetHexKV(line, "mval", acc.AriMval);
}

void AutoDebugHitParser::ParseIndLine(const std::string& line, HitAccum& acc, Stats& stats)
{
    uint64_t rva = 0;
    if (!GetHexKV(line, "rva", rva) || !acc.HaveHit || rva != acc.Rva)
    {
        ++stats.ParseErrors;
        return;
    }
    uint64_t tgt = 0;
    if (!GetHexKV(line, "tgt", tgt))
    {
        ++stats.ParseErrors;
        return;
    }
    acc.HaveInd = true;
    acc.IndTarget = tgt;
}

void AutoDebugHitParser::ParseLeaLine(const std::string& line, HitAccum& acc, Stats& stats)
{
    uint64_t rva = 0;
    if (!GetHexKV(line, "rva", rva) || !acc.HaveHit || rva != acc.Rva)
    {
        ++stats.ParseErrors;
        return;
    }
    uint64_t ea = 0;
    if (!GetHexKV(line, "ea", ea))
    {
        ++stats.ParseErrors;
        return;
    }
    acc.HaveLea = true;
    acc.LeaEa = ea;
}

void AutoDebugHitParser::ParseArgLine(const std::string& line, HitAccum& acc, Stats& stats)
{
    uint64_t rva = 0;
    if (!GetHexKV(line, "rva", rva) || !acc.HaveHit || rva != acc.Rva)
    {
        ++stats.ParseErrors;
        return;
    }
    uint64_t idx = 0;
    if (!GetDecKV(line, "idx", idx) || idx > 7)
    {
        ++stats.ParseErrors;
        return;
    }
    uint64_t val = 0;
    if (!GetHexKV(line, "val", val))
    {
        ++stats.ParseErrors;
        return;
    }
    HitAccum::ArgExtra& a = acc.Args[idx];
    a.Have = true;
    a.Val = val;
}

void AutoDebugHitParser::ParseArgHeadLine(const std::string& line, HitAccum& acc, Stats& stats)
{
    uint64_t rva = 0;
    if (!GetHexKV(line, "rva", rva) || !acc.HaveHit || rva != acc.Rva)
    {
        ++stats.ParseErrors;
        return;
    }
    uint64_t idx = 0;
    if (!GetDecKV(line, "idx", idx) || idx > 7)
    {
        ++stats.ParseErrors;
        return;
    }
    uint64_t h[4] = {};
    GetHexKV(line, "h0", h[0]);
    GetHexKV(line, "h1", h[1]);
    GetHexKV(line, "h2", h[2]);
    GetHexKV(line, "h3", h[3]);

    HitAccum::ArgExtra& a = acc.Args[idx];
    a.Have = true;
    a.Head[0] = h[0];
    a.Head[1] = h[1];
    a.Head[2] = h[2];
    a.Head[3] = h[3];
}

void AutoDebugHitParser::ParseRetLine(const std::string& line, Stats& stats)
{
    uint64_t rva = 0;
    uint64_t rax = 0;
    if (!GetHexKV(line, "rva", rva))
    {
        ++stats.ParseErrors;
        return;
    }
    if (!GetHexKV(line, "rax", rax))
    {
        ++stats.ParseErrors;
        return;
    }
    CallRetHit c = {};
    c.Rva = rva;
    c.Rax = rax;

    IngestResult res;
    uint64_t* counter = nullptr;
    if (Flavor == HitFlavor::NtdllSyscalls)
    {
        SyscallIndirectRetHit r = c;
        res = Store.IngestSyscallIndirectRet(r);
        counter = &stats.SyscallIndirectRets;
    }
    else
    {
        const auto it = KindByRva.find(rva);
        const bool ownerissyscall = (it != KindByRva.end() && it->second == SiteKind::Syscall);
        if (ownerissyscall)
        {
            SyscallDirectRetHit r = c;
            res = Store.IngestSyscallDirectRet(r);
            counter = &stats.SyscallDirectRets;
        }
        else
        {
            res = Store.IngestCallRet(c);
            counter = &stats.CallRets;
        }
    }
    switch (res)
    {
    case IngestResult::New:
        ++stats.HitsIngested;
        ++*counter;
        break;
    case IngestResult::Duplicate:
        ++stats.HitsDedup;
        break;
    case IngestResult::Error:
        ++stats.HitsError;
        break;
    }
}

void AutoDebugHitParser::ParseRetHeadLine(const std::string& line, Stats& stats)
{
    uint64_t rva = 0;
    uint64_t rax = 0;
    if (!GetHexKV(line, "rva", rva))
    {
        ++stats.ParseErrors;
        return;
    }
    if (!GetHexKV(line, "rax", rax))
    {
        ++stats.ParseErrors;
        return;
    }
    uint64_t h[4] = {};
    GetHexKV(line, "h0", h[0]);
    GetHexKV(line, "h1", h[1]);
    GetHexKV(line, "h2", h[2]);
    GetHexKV(line, "h3", h[3]);

    CallRetHit c = {};
    c.Rva = rva;
    c.Rax = rax;
    c.Head[0] = h[0];
    c.Head[1] = h[1];
    c.Head[2] = h[2];
    c.Head[3] = h[3];

    IngestResult res;
    uint64_t* counter = nullptr;
    if (Flavor == HitFlavor::NtdllSyscalls)
    {
        SyscallIndirectRetHit r = c;
        res = Store.IngestSyscallIndirectRet(r);
        counter = &stats.SyscallIndirectRets;
    }
    else
    {
        const auto it = KindByRva.find(rva);
        const bool ownerissyscall = (it != KindByRva.end() && it->second == SiteKind::Syscall);
        if (ownerissyscall)
        {
            SyscallDirectRetHit r = c;
            res = Store.IngestSyscallDirectRet(r);
            counter = &stats.SyscallDirectRets;
        }
        else
        {
            res = Store.IngestCallRet(c);
            counter = &stats.CallRets;
        }
    }
    switch (res)
    {
    case IngestResult::New:
        ++stats.HitsIngested;
        ++*counter;
        break;
    case IngestResult::Duplicate:
        ++stats.HitsDedup;
        break;
    case IngestResult::Error:
        ++stats.HitsError;
        break;
    }
}

void AutoDebugHitParser::Flush(HitAccum& acc, Stats& stats)
{
    if (!acc.HaveHit)
    {
        return;
    }

    const auto it = KindByRva.find(acc.Rva);
    if (it == KindByRva.end())
    {
        if (stats.UnknownRvaSampleCount < sizeof(stats.UnknownRvaSample) / sizeof(stats.UnknownRvaSample[0]))
        {
            stats.UnknownRvaSample[stats.UnknownRvaSampleCount++] = acc.Rva;
        }
        ++stats.UnknownRva;
        return;
    }
    const SiteKind kind = it->second;

    auto tally = [&](IngestResult res, uint64_t& perkind)
        {
            switch (res)
            {
            case IngestResult::New:
                ++stats.HitsIngested;
                ++perkind;
                break;
            case IngestResult::Duplicate:
                ++stats.HitsDedup;
                break;
            case IngestResult::Error:
                ++stats.HitsError;
                break;
            }
        };

    switch (kind)
    {
    case SiteKind::Branch:
    {
        BranchHit r = {};
        r.Rva = acc.Rva;
        r.Gpr = acc.Gpr;
        tally(Store.IngestBranch(r), stats.Branches);
        break;
    }
    case SiteKind::Call:
    {
        CallHit r = {};
        r.Rva = acc.Rva;
        r.Gpr = acc.Gpr;
        tally(Store.IngestCall(r), stats.Calls);
        break;
    }
    case SiteKind::Compare:
    {
        CompareHit r = {};
        r.Rva = acc.Rva;
        r.Gpr = acc.Gpr;
        r.MemLo = acc.MemLo;
        r.MemHi = acc.MemHi;
        tally(Store.IngestCompare(r), stats.Compares);
        break;
    }
    case SiteKind::Mov:
    {
        MovHit r = {};
        r.Rva = acc.Rva;
        r.Gpr = acc.Gpr;
        r.MemValue = acc.MovVal;
        tally(Store.IngestMov(r), stats.Movs);
        break;
    }
    case SiteKind::Arith:
    {
        ArithHit r = {};
        r.Rva = acc.Rva;
        r.Gpr = acc.Gpr;
        r.Rval = acc.AriRval;
        r.Rval2 = acc.AriRval2;
        r.Mval = acc.AriMval;
        tally(Store.IngestArith(r), stats.Ariths);
        break;
    }
    case SiteKind::String:
    {
        if (acc.StrRsi.Have)
        {
            StringHit r = {};
            r.Rva = acc.Rva;
            r.Gpr = acc.Gpr;
            r.Which = 0;
            r.Addr = acc.StrRsi.Addr;
            r.LenRcx = acc.StrRsi.LenRcx;
            std::memcpy(r.Window, acc.StrRsi.Window, sizeof(r.Window));
            tally(Store.IngestString(r), stats.Strings);
        }
        if (acc.StrRdi.Have)
        {
            StringHit r = {};
            r.Rva = acc.Rva;
            r.Gpr = acc.Gpr;
            r.Which = 1;
            r.Addr = acc.StrRdi.Addr;
            r.LenRcx = acc.StrRdi.LenRcx;
            std::memcpy(r.Window, acc.StrRdi.Window, sizeof(r.Window));
            tally(Store.IngestString(r), stats.Strings);
        }
        break;
    }
    case SiteKind::VecMove:
    {
        VecHit r = {};
        r.Rva = acc.Rva;
        r.Gpr = acc.Gpr;
        r.NQwords = acc.VecQwords;
        std::memcpy(r.Window, acc.VecWindow, sizeof(r.Window));
        tally(Store.IngestVec(r), stats.Vecs);
        break;
    }
    case SiteKind::IndBranch:
    {
        if (!acc.HaveInd)
        {
            break;
        }
        IndBranchHit r = {};
        r.Rva = acc.Rva;
        r.Gpr = acc.Gpr;
        r.Target = acc.IndTarget;
        tally(Store.IngestIndBranch(r), stats.IndBranches);
        break;
    }
    case SiteKind::IndCall:
    {
        if (!acc.HaveInd)
        {
            break;
        }
        IndCallHit r = {};
        r.Rva = acc.Rva;
        r.Gpr = acc.Gpr;
        r.Target = acc.IndTarget;
        tally(Store.IngestIndCall(r), stats.IndCalls);
        break;
    }
    case SiteKind::Lea:
    {
        if (!acc.HaveLea)
        {
            break;
        }
        LeaHit r = {};
        r.Rva = acc.Rva;
        r.Gpr = acc.Gpr;
        r.Ea = acc.LeaEa;
        tally(Store.IngestLea(r), stats.Leas);
        break;
    }
    case SiteKind::Syscall:
    {
        if (Flavor == HitFlavor::NtdllSyscalls)
        {
            SyscallIndirectHit r = {};
            r.Rva = acc.Rva;
            r.Gpr = acc.Gpr;
            tally(Store.IngestSyscallIndirect(r), stats.SyscallsIndirect);
        }
        else
        {
            SyscallDirectHit r = {};
            r.Rva = acc.Rva;
            r.Gpr = acc.Gpr;
            tally(Store.IngestSyscallDirect(r), stats.SyscallsDirect);
        }
        break;
    }
    }

    const bool ownerissyscall = (kind == SiteKind::Syscall);
    for (uint8_t i = 0; i < 8; ++i)
    {
        if (!acc.Args[i].Have)
        {
            continue;
        }
        CallArgHit c = {};
        c.Rva = acc.Rva;
        c.ArgIdx = i;
        c.Val = acc.Args[i].Val;
        c.Head[0] = acc.Args[i].Head[0];
        c.Head[1] = acc.Args[i].Head[1];
        c.Head[2] = acc.Args[i].Head[2];
        c.Head[3] = acc.Args[i].Head[3];

        if (Flavor == HitFlavor::NtdllSyscalls)
        {
            tally(Store.IngestSyscallIndirectArg(c), stats.SyscallIndirectArgs);
        }
        else if (ownerissyscall)
        {
            tally(Store.IngestSyscallDirectArg(c), stats.SyscallDirectArgs);
        }
        else
        {
            tally(Store.IngestCallArg(c), stats.CallArgs);
        }
    }
}

AutoDebugHitParser::Stats AutoDebugHitParser::ParseFile(const std::filesystem::path& hitsfile)
{
    Stats stats = {};

    std::error_code szec;
    const auto fsz = std::filesystem::file_size(hitsfile, szec);
    if (!szec)
    {
        stats.HitsFileBytes = fsz;
    }

    std::ifstream f(hitsfile, std::ios::binary);
    if (!f)
    {
        return stats;
    }

    HitAccum acc;
    std::string line;
    line.reserve(1024);
    bool gotfirstline = false;

    while (std::getline(f, line))
    {
        ++stats.LinesRead;
        if (line.empty())
        {
            continue;
        }
        if (line.back() == '\r')
        {
            line.pop_back();
        }
        if (line.empty())
        {
            continue;
        }

        if (!gotfirstline)
        {
            size_t n = line.size();
            if (n >= sizeof(stats.FirstLine))
            {
                n = sizeof(stats.FirstLine) - 1;
            }
            std::memcpy(stats.FirstLine, line.data(), n);
            stats.FirstLine[n] = '\0';
            gotfirstline = true;
        }

        if (line.find("[autodbg-hit]") != std::string::npos)
        {
            ++stats.TagHit;
            if (acc.HaveHit)
            {
                Flush(acc, stats);
            }
            acc = HitAccum{};
            ParseHitLine(line, acc, stats);
        }
        else if (line.find("[autodbg-mem]") != std::string::npos)
        {
            ++stats.TagMem;
            ParseMemLine(line, acc, stats);
        }
        else if (line.find("[autodbg-str]") != std::string::npos)
        {
            ++stats.TagStr;
            ParseStrLine(line, acc, stats);
        }
        else if (line.find("[autodbg-vec]") != std::string::npos)
        {
            ++stats.TagVec;
            ParseVecLine(line, acc, stats);
        }
        else if (line.find("[autodbg-mov]") != std::string::npos)
        {
            ++stats.TagMov;
            ParseMovLine(line, acc, stats);
        }
        else if (line.find("[autodbg-ari]") != std::string::npos)
        {
            ++stats.TagAri;
            ParseAriLine(line, acc, stats);
        }
        else if (line.find("[autodbg-ind]") != std::string::npos)
        {
            ++stats.TagInd;
            ParseIndLine(line, acc, stats);
        }
        else if (line.find("[autodbg-lea]") != std::string::npos)
        {
            ++stats.TagLea;
            ParseLeaLine(line, acc, stats);
        }
        else if (line.find("[autodbg-argh]") != std::string::npos)
        {
            ++stats.TagArgh;
            ParseArgHeadLine(line, acc, stats);
        }
        else if (line.find("[autodbg-arg]") != std::string::npos)
        {
            ++stats.TagArg;
            ParseArgLine(line, acc, stats);
        }
        else if (line.find("[autodbg-reth]") != std::string::npos)
        {
            ++stats.TagReth;
            ParseRetHeadLine(line, stats);
        }
        else if (line.find("[autodbg-ret]") != std::string::npos)
        {
            ++stats.TagRet;
            ParseRetLine(line, stats);
        }
    }

    if (acc.HaveHit)
    {
        Flush(acc, stats);
    }
    return stats;
}