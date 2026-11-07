#include "../../Pch.h"
#include "AutoDebugStore.h"

#include <windows.h>
#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")


const wchar_t* AutoDebugStore::FilenameFor(ObsKind k)
{
    switch (k)
    {
    case ObsKind::Branch:             return L"branches.bin";
    case ObsKind::Call:               return L"calls.bin";
    case ObsKind::Compare:            return L"compares.bin";
    case ObsKind::Mov:                return L"movs.bin";
    case ObsKind::Arith:              return L"ariths.bin";
    case ObsKind::String:             return L"strings.bin";
    case ObsKind::Vec:                return L"vecs.bin";
    case ObsKind::IndBranch:          return L"ind_branches.bin";
    case ObsKind::IndCall:            return L"ind_calls.bin";
    case ObsKind::Lea:                return L"leas.bin";
    case ObsKind::Iat:                return L"iats.bin";
    case ObsKind::Rop:                return L"rop.bin";
    case ObsKind::CallArg:            return L"callargs.bin";
    case ObsKind::CallRet:            return L"callrets.bin";
    case ObsKind::SyscallDirect:      return L"syscalls_direct.bin";
    case ObsKind::SyscallDirectArg:   return L"syscall_direct_args.bin";
    case ObsKind::SyscallDirectRet:   return L"syscall_direct_rets.bin";
    case ObsKind::SyscallIndirect:    return L"syscalls_indirect.bin";
    case ObsKind::SyscallIndirectArg: return L"syscall_indirect_args.bin";
    case ObsKind::SyscallIndirectRet: return L"syscall_indirect_rets.bin";
    }
    return nullptr;
}

uint32_t AutoDebugStore::RecSizeFor(ObsKind k)
{
    switch (k)
    {
    case ObsKind::Branch:             return static_cast<uint32_t>(sizeof(BranchHit));
    case ObsKind::Call:               return static_cast<uint32_t>(sizeof(CallHit));
    case ObsKind::Compare:            return static_cast<uint32_t>(sizeof(CompareHit));
    case ObsKind::Mov:                return static_cast<uint32_t>(sizeof(MovHit));
    case ObsKind::Arith:              return static_cast<uint32_t>(sizeof(ArithHit));
    case ObsKind::String:             return static_cast<uint32_t>(sizeof(StringHit));
    case ObsKind::Vec:                return static_cast<uint32_t>(sizeof(VecHit));
    case ObsKind::IndBranch:          return static_cast<uint32_t>(sizeof(IndBranchHit));
    case ObsKind::IndCall:            return static_cast<uint32_t>(sizeof(IndCallHit));
    case ObsKind::Lea:                return static_cast<uint32_t>(sizeof(LeaHit));
    case ObsKind::Iat:                return static_cast<uint32_t>(sizeof(IatHit));
    case ObsKind::Rop:                return static_cast<uint32_t>(sizeof(RopHit));
    case ObsKind::CallArg:            return static_cast<uint32_t>(sizeof(CallArgHit));
    case ObsKind::CallRet:            return static_cast<uint32_t>(sizeof(CallRetHit));
    case ObsKind::SyscallDirect:      return static_cast<uint32_t>(sizeof(SyscallDirectHit));
    case ObsKind::SyscallDirectArg:   return static_cast<uint32_t>(sizeof(SyscallDirectArgHit));
    case ObsKind::SyscallDirectRet:   return static_cast<uint32_t>(sizeof(SyscallDirectRetHit));
    case ObsKind::SyscallIndirect:    return static_cast<uint32_t>(sizeof(SyscallIndirectHit));
    case ObsKind::SyscallIndirectArg: return static_cast<uint32_t>(sizeof(SyscallIndirectArgHit));
    case ObsKind::SyscallIndirectRet: return static_cast<uint32_t>(sizeof(SyscallIndirectRetHit));
    }
    return 0;
}

bool AutoDebugStore::HashFileSha256(const std::string& path, std::string& hexout, uint64_t& sizeout)
{
    hexout.clear();
    sizeout = 0;

    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) return false;
    std::streamoff sz = f.tellg();
    if (sz < 0) return false;
    sizeout = static_cast<uint64_t>(sz);
    f.seekg(0);

    BCRYPT_ALG_HANDLE halg = nullptr;
    NTSTATUS st = BCryptOpenAlgorithmProvider(&halg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (st < 0) return false;

    BCRYPT_HASH_HANDLE hhash = nullptr;
    st = BCryptCreateHash(halg, &hhash, nullptr, 0, nullptr, 0, 0);
    if (st < 0)
    {
        BCryptCloseAlgorithmProvider(halg, 0);
        return false;
    }

    std::vector<char> chunk(64 * 1024);
    while (f.good())
    {
        f.read(chunk.data(), static_cast<std::streamsize>(chunk.size()));
        std::streamsize got = f.gcount();
        if (got <= 0) break;
        st = BCryptHashData(hhash, reinterpret_cast<PUCHAR>(chunk.data()), static_cast<ULONG>(got), 0);
        if (st < 0)
        {
            BCryptDestroyHash(hhash);
            BCryptCloseAlgorithmProvider(halg, 0);
            return false;
        }
    }

    uint8_t digest[32] = {};
    st = BCryptFinishHash(hhash, digest, sizeof(digest), 0);
    BCryptDestroyHash(hhash);
    BCryptCloseAlgorithmProvider(halg, 0);
    if (st < 0) return false;

    char hex[65];
    for (int i = 0; i < 32; ++i)
        std::snprintf(hex + i * 2, 3, "%02x", digest[i]);
    hex[64] = '\0';
    hexout = hex;
    return true;
}

uint64_t AutoDebugStore::Fnv1a64(const void* data, size_t n)
{
    constexpr uint64_t OFFSET_BASIS = 0xcbf29ce484222325ULL;
    constexpr uint64_t FNV_PRIME = 0x100000001b3ULL;

    uint64_t h = OFFSET_BASIS;
    const uint8_t* p = static_cast<const uint8_t*>(data);
    for (size_t i = 0; i < n; ++i)
    {
        h ^= p[i];
        h *= FNV_PRIME;
    }
    return h;
}

std::string AutoDebugStore::NowIsoUtc()
{
    SYSTEMTIME st;
    GetSystemTime(&st);
    char b[32];
    std::snprintf(b, sizeof(b), "%04u-%02u-%02uT%02u:%02u:%02uZ", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return b;
}

bool AutoDebugStore::ReadManifest(std::string& shahex, uint64_t& size, uint32_t& runcount, std::string& firstseen)
{
    std::ifstream f(ProjectDir / L"manifest.json", std::ios::binary);
    if (!f) return false;

    std::stringstream ss;
    ss << f.rdbuf();
    std::string body = ss.str();

    shahex = ManifestJson::GetStr(body, "sha256");
    size = static_cast<uint64_t>(ManifestJson::GetInt(body, "size"));
    runcount = static_cast<uint32_t>(ManifestJson::GetInt(body, "run_count"));
    firstseen = ManifestJson::GetStr(body, "first_seen");
    TracedBase = static_cast<uint64_t>(ManifestJson::GetInt(body, "traced_base"));
    return !shahex.empty();
}

bool AutoDebugStore::WriteManifest()
{
    std::ofstream f(ProjectDir / L"manifest.json", std::ios::binary | std::ios::trunc);
    if (!f) return false;

    const std::string lastseen = NowIsoUtc();

    f << "{\n";
    f << "  \"tool_version\": 1,\n";
    f << "  \"source_path\": ";
    {
        std::string j;
        ManifestJson::EscapeAppend(j, SourcePath);
        f << j;
    }
    f << ",\n";
    f << "  \"sha256\": \"" << SourceSha256Hex << "\",\n";
    f << "  \"size\": " << SourceSize << ",\n";
    f << "  \"first_seen\": ";
    {
        std::string j;
        ManifestJson::EscapeAppend(j, FirstSeen);
        f << j;
    }
    f << ",\n";
    f << "  \"last_seen\": ";
    {
        std::string j;
        ManifestJson::EscapeAppend(j, lastseen);
        f << j;
    }
    f << ",\n";
    f << "  \"run_count\": " << PriorRunCount << ",\n";
    f << "  \"traced_base\": " << TracedBase << "\n";
    f << "}\n";
    return static_cast<bool>(f);
}

void AutoDebugStore::SetTracedBase(uint64_t tracedbase)
{
    if (tracedbase == 0) return;

    if (TracedBase == tracedbase) return;
    if (TracedBase == 0 || IsNew)
    {
        TracedBase = tracedbase;
        WriteManifest();
        return;
    }

    std::fprintf(stderr, "[sophiaproj] traced base changed (was 0x%llx, now 0x%llx) -- wiping stale observations from prior run\n", static_cast<unsigned long long>(TracedBase), static_cast<unsigned long long>(tracedbase));

    for (int i = 1; i < 21; ++i)
    {
        if (Kinds[i].Out.is_open()) Kinds[i].Out.close();
        Kinds[i].Keys.clear();
        Kinds[i].Count = 0;
    }
    Explored.clear();
    Statistics = ObsStats{};

    std::error_code ec;
    std::filesystem::remove_all(ProjectDir / L"observations", ec);
    std::filesystem::create_directories(ProjectDir / L"observations", ec);

    TracedBase = tracedbase;
    WriteManifest();
}

std::filesystem::path AutoDebugStore::SophiaProjRoot()
{
    wchar_t buf[MAX_PATH];
    DWORD n = GetModuleFileNameW(nullptr, buf, MAX_PATH);
    if (n == 0 || n == MAX_PATH)
    {
        std::error_code ec;
        return std::filesystem::current_path(ec) / L"sophiaproj";
    }
    return std::filesystem::path(buf).parent_path() / L"sophiaproj";
}

bool AutoDebugStore::Open(const std::string& filepath, OpenResult& result)
{
    result = {};
    Opened = false;

    if (!HashFileSha256(filepath, SourceSha256Hex, SourceSize))
    {
        std::fprintf(stderr, "[sophiaproj] could not hash %s -- store disabled for this run\n", filepath.c_str());
        return false;
    }

    std::error_code ec;
    std::filesystem::path root = SophiaProjRoot();
    std::filesystem::create_directories(root, ec);

    std::string stem = std::filesystem::path(filepath).stem().string();
    if (stem.empty()) stem = "unnamed";
    ProjectDir = root / stem;

    std::filesystem::path abssource = std::filesystem::absolute(filepath, ec);
    SourcePath = ec ? filepath : abssource.string();

    if (std::filesystem::exists(ProjectDir, ec))
    {
        std::string priorsha;
        uint64_t priorsize = 0;
        uint32_t priorrun = 0;
        std::string priorfirstseen;
        const bool manifestok = ReadManifest(priorsha, priorsize, priorrun, priorfirstseen);

        if (manifestok && priorsha == SourceSha256Hex)
        {
            IsNew = false;
            PriorRunCount = priorrun;
            FirstSeen = priorfirstseen.empty() ? NowIsoUtc() : priorfirstseen;
        }
        else
        {
            std::filesystem::remove_all(ProjectDir, ec);
            std::filesystem::create_directories(ProjectDir, ec);
            IsNew = true;
            PriorRunCount = 0;
            FirstSeen = NowIsoUtc();
            result.WasWiped = true;
        }
    }
    else
    {
        std::filesystem::create_directories(ProjectDir, ec);
        IsNew = true;
        PriorRunCount = 0;
        FirstSeen = NowIsoUtc();
    }

    std::filesystem::create_directories(ProjectDir / L"observations", ec);

    if (!WriteManifest())
    {
        std::fprintf(stderr, "[sophiaproj] could not write manifest to %ls\n", ProjectDir.wstring().c_str());
        return false;
    }

    Opened = true;
    result.IsNew = IsNew;
    result.PriorRunCount = PriorRunCount;
    result.ProjectDir = ProjectDir;
    result.Sha256Hex = SourceSha256Hex;
    return true;
}

bool AutoDebugStore::OpenReadOnly(const std::string& filepath)
{
    Opened = false;

    std::error_code ec;
    std::filesystem::path root = SophiaProjRoot();

    std::string stem = std::filesystem::path(filepath).stem().string();
    if (stem.empty()) stem = "unnamed";
    ProjectDir = root / stem;

    if (!std::filesystem::exists(ProjectDir, ec))
    {
        std::fprintf(stderr, "[sophiaproj] OpenReadOnly: project dir does not exist: %ls\n", ProjectDir.wstring().c_str());
        return false;
    }

    std::string priorsha;
    uint64_t priorsize = 0;
    uint32_t priorrun = 0;
    std::string priorfirstseen;
    const bool manifestok = ReadManifest(priorsha, priorsize, priorrun, priorfirstseen);
    if (!manifestok)
    {
        std::fprintf(stderr, "[sophiaproj] OpenReadOnly: manifest.json missing or corrupt under %ls -- proceeding without a stored hash\n", ProjectDir.wstring().c_str());
    }

    IsNew = false;
    SourcePath = filepath;
    SourceSha256Hex = priorsha;
    SourceSize = priorsize;
    PriorRunCount = priorrun;
    FirstSeen = priorfirstseen;
    Opened = true;
    return true;
}

bool AutoDebugStore::EnsureStreamOpen(ObsKind k)
{
    const uint16_t slot = static_cast<uint16_t>(k);
    if (slot == 0 || slot > 20) return false;

    KindState& ks = Kinds[slot];
    if (ks.Out.is_open()) return true;

    const wchar_t* fname = FilenameFor(k);
    if (!fname) return false;
    std::filesystem::path p = ProjectDir / L"observations" / fname;

    std::error_code ec;
    const bool exists = std::filesystem::exists(p, ec);

    ks.Out.open(p, std::ios::binary | std::ios::app);
    if (!ks.Out) return false;

    if (!exists)
    {
        SophiaFileHeader hdr = {};
        std::memcpy(hdr.Magic, "SODB", 4);
        hdr.Version = 1;
        hdr.Kind = slot;
        hdr.RecSize = RecSizeFor(k);
        ks.Out.write(reinterpret_cast<const char*>(&hdr), sizeof(hdr));
        if (!ks.Out) return false;
    }
    return true;
}

IngestResult AutoDebugStore::Ingest(ObsKind kind, const void* rec, size_t recsize)
{
    if (!Opened)
    {
        std::fprintf(stderr, "[sophiaproj] Ingest called before Open() succeeded\n");
        return IngestResult::Error;
    }
    if (rec == nullptr)
    {
        std::fprintf(stderr, "[sophiaproj] Ingest called with null record\n");
        return IngestResult::Error;
    }
    const uint32_t expected = RecSizeFor(kind);
    if (expected == 0)
    {
        std::fprintf(stderr, "[sophiaproj] Ingest called with unknown kind %u\n", static_cast<unsigned>(kind));
        return IngestResult::Error;
    }
    if (recsize != expected)
    {
        std::fprintf(stderr, "[sophiaproj] Ingest size mismatch for kind %u: got %zu, expected %u\n", static_cast<unsigned>(kind), recsize, expected);
        return IngestResult::Error;
    }

    const uint16_t slot = static_cast<uint16_t>(kind);
    KindState& ks = Kinds[slot];

    const uint64_t key = Fnv1a64(rec, recsize);
    if (!ks.Keys.insert(key).second)
        return IngestResult::Duplicate;

    if (!EnsureStreamOpen(kind))
    {
        std::fprintf(stderr, "[sophiaproj] EnsureStreamOpen(kind=%u) FAILED -- observations/%ls will not be written\n", static_cast<unsigned>(kind), FilenameFor(kind));
        ks.Keys.erase(key);
        return IngestResult::Error;
    }

    ks.Out.write(reinterpret_cast<const char*>(rec), static_cast<std::streamsize>(recsize));
    if (!ks.Out)
    {
        std::fprintf(stderr, "[sophiaproj] write to observations/%ls FAILED (fail=%d bad=%d)\n", FilenameFor(kind), static_cast<int>(ks.Out.fail()), static_cast<int>(ks.Out.bad()));
        ks.Keys.erase(key);
        return IngestResult::Error;
    }
    ++ks.Count;

    uint64_t rva = 0;
    std::memcpy(&rva, rec, sizeof(rva));
    Explored.insert(rva);

    ++Statistics.TotalRecords;
    Statistics.UniqueRvas = Explored.size();
    switch (kind)
    {
    case ObsKind::Branch:             Statistics.Branches = ks.Count; break;
    case ObsKind::Call:               Statistics.Calls = ks.Count; break;
    case ObsKind::Compare:            Statistics.Compares = ks.Count; break;
    case ObsKind::Mov:                Statistics.Movs = ks.Count; break;
    case ObsKind::Arith:              Statistics.Ariths = ks.Count; break;
    case ObsKind::String:             Statistics.Strings = ks.Count; break;
    case ObsKind::Vec:                Statistics.Vecs = ks.Count; break;
    case ObsKind::IndBranch:          Statistics.IndBranches = ks.Count; break;
    case ObsKind::IndCall:            Statistics.IndCalls = ks.Count; break;
    case ObsKind::Lea:                Statistics.Leas = ks.Count; break;
    case ObsKind::Iat:                Statistics.Iats = ks.Count; break;
    case ObsKind::Rop:                Statistics.Rops = ks.Count; break;
    case ObsKind::CallArg:            Statistics.CallArgs = ks.Count; break;
    case ObsKind::CallRet:            Statistics.CallRets = ks.Count; break;
    case ObsKind::SyscallDirect:      Statistics.SyscallsDirect = ks.Count; break;
    case ObsKind::SyscallDirectArg:   Statistics.SyscallDirectArgs = ks.Count; break;
    case ObsKind::SyscallDirectRet:   Statistics.SyscallDirectRets = ks.Count; break;
    case ObsKind::SyscallIndirect:    Statistics.SyscallsIndirect = ks.Count; break;
    case ObsKind::SyscallIndirectArg: Statistics.SyscallIndirectArgs = ks.Count; break;
    case ObsKind::SyscallIndirectRet: Statistics.SyscallIndirectRets = ks.Count; break;
    }
    return IngestResult::New;
}

IngestResult AutoDebugStore::IngestBranch(const BranchHit& r) { return Ingest(ObsKind::Branch, &r, sizeof(r)); }
IngestResult AutoDebugStore::IngestCall(const CallHit& r) { return Ingest(ObsKind::Call, &r, sizeof(r)); }
IngestResult AutoDebugStore::IngestCompare(const CompareHit& r) { return Ingest(ObsKind::Compare, &r, sizeof(r)); }
IngestResult AutoDebugStore::IngestMov(const MovHit& r) { return Ingest(ObsKind::Mov, &r, sizeof(r)); }
IngestResult AutoDebugStore::IngestArith(const ArithHit& r) { return Ingest(ObsKind::Arith, &r, sizeof(r)); }
IngestResult AutoDebugStore::IngestString(const StringHit& r) { return Ingest(ObsKind::String, &r, sizeof(r)); }
IngestResult AutoDebugStore::IngestVec(const VecHit& r) { return Ingest(ObsKind::Vec, &r, sizeof(r)); }
IngestResult AutoDebugStore::IngestIndBranch(const IndBranchHit& r) { return Ingest(ObsKind::IndBranch, &r, sizeof(r)); }
IngestResult AutoDebugStore::IngestIndCall(const IndCallHit& r) { return Ingest(ObsKind::IndCall, &r, sizeof(r)); }
IngestResult AutoDebugStore::IngestLea(const LeaHit& r) { return Ingest(ObsKind::Lea, &r, sizeof(r)); }
IngestResult AutoDebugStore::IngestIat(const IatHit& r) { return Ingest(ObsKind::Iat, &r, sizeof(r)); }
IngestResult AutoDebugStore::IngestRop(const RopHit& r) { return Ingest(ObsKind::Rop, &r, sizeof(r)); }
IngestResult AutoDebugStore::IngestCallArg(const CallArgHit& r) { return Ingest(ObsKind::CallArg, &r, sizeof(r)); }
IngestResult AutoDebugStore::IngestCallRet(const CallRetHit& r) { return Ingest(ObsKind::CallRet, &r, sizeof(r)); }
IngestResult AutoDebugStore::IngestSyscallDirect(const SyscallDirectHit& r) { return Ingest(ObsKind::SyscallDirect, &r, sizeof(r)); }
IngestResult AutoDebugStore::IngestSyscallDirectArg(const SyscallDirectArgHit& r) { return Ingest(ObsKind::SyscallDirectArg, &r, sizeof(r)); }
IngestResult AutoDebugStore::IngestSyscallDirectRet(const SyscallDirectRetHit& r) { return Ingest(ObsKind::SyscallDirectRet, &r, sizeof(r)); }
IngestResult AutoDebugStore::IngestSyscallIndirect(const SyscallIndirectHit& r) { return Ingest(ObsKind::SyscallIndirect, &r, sizeof(r)); }
IngestResult AutoDebugStore::IngestSyscallIndirectArg(const SyscallIndirectArgHit& r) { return Ingest(ObsKind::SyscallIndirectArg, &r, sizeof(r)); }
IngestResult AutoDebugStore::IngestSyscallIndirectRet(const SyscallIndirectRetHit& r) { return Ingest(ObsKind::SyscallIndirectRet, &r, sizeof(r)); }

void AutoDebugStore::FlushStreams()
{
    for (int i = 1; i <= 20; ++i)
    {
        if (Kinds[i].Out.is_open()) Kinds[i].Out.flush();
    }
}

bool AutoDebugStore::LoadObservations()
{
    if (!Opened) return false;

    bool allok = true;
    Explored.clear();
    Statistics = ObsStats{};
    for (int i = 0; i < 21; ++i)
    {
        Kinds[i].Keys.clear();
        Kinds[i].Count = 0;
    }

    for (uint16_t slot = 1; slot <= 20; ++slot)
    {
        const ObsKind kind = static_cast<ObsKind>(slot);
        const uint32_t expected = RecSizeFor(kind);
        const wchar_t* fname = FilenameFor(kind);
        if (!fname || expected == 0) continue;

        std::filesystem::path p = ProjectDir / L"observations" / fname;
        std::ifstream f(p, std::ios::binary);
        if (!f) continue;

        SophiaFileHeader hdr = {};
        f.read(reinterpret_cast<char*>(&hdr), sizeof(hdr));
        if (!f)
        {
            std::fprintf(stderr, "[sophiaproj] truncated header on %ls -- skipping\n", fname);
            allok = false;
            continue;
        }
        if (std::memcmp(hdr.Magic, "SODB", 4) != 0 || hdr.Version != 1 || hdr.Kind != slot || hdr.RecSize != expected)
        {
            std::fprintf(stderr, "[sophiaproj] header mismatch on %ls (kind=%u rec_size=%u expected=%u) -- skipping\n", fname, hdr.Kind, hdr.RecSize, expected);
            allok = false;
            continue;
        }

        std::vector<char> buf(expected);
        KindState& ks = Kinds[slot];
        while (f.read(buf.data(), expected))
        {
            const uint64_t key = Fnv1a64(buf.data(), expected);
            if (ks.Keys.insert(key).second)
            {
                ++ks.Count;
                uint64_t rva = 0;
                std::memcpy(&rva, buf.data(), sizeof(rva));
                Explored.insert(rva);
            }
        }
    }

    Statistics.Branches = Kinds[1].Count;
    Statistics.Calls = Kinds[2].Count;
    Statistics.Compares = Kinds[3].Count;
    Statistics.Movs = Kinds[4].Count;
    Statistics.Ariths = Kinds[5].Count;
    Statistics.Strings = Kinds[6].Count;
    Statistics.Vecs = Kinds[7].Count;
    Statistics.IndBranches = Kinds[8].Count;
    Statistics.IndCalls = Kinds[9].Count;
    Statistics.Leas = Kinds[10].Count;
    Statistics.Iats = Kinds[11].Count;
    Statistics.Rops = Kinds[12].Count;
    Statistics.CallArgs = Kinds[13].Count;
    Statistics.CallRets = Kinds[14].Count;
    Statistics.SyscallsDirect = Kinds[15].Count;
    Statistics.SyscallDirectArgs = Kinds[16].Count;
    Statistics.SyscallDirectRets = Kinds[17].Count;
    Statistics.SyscallsIndirect = Kinds[18].Count;
    Statistics.SyscallIndirectArgs = Kinds[19].Count;
    Statistics.SyscallIndirectRets = Kinds[20].Count;
    Statistics.TotalRecords = Kinds[1].Count + Kinds[2].Count + Kinds[3].Count + Kinds[4].Count + Kinds[5].Count + Kinds[6].Count + Kinds[7].Count + Kinds[8].Count + Kinds[9].Count + Kinds[10].Count + Kinds[11].Count + Kinds[12].Count + Kinds[13].Count + Kinds[14].Count + Kinds[15].Count + Kinds[16].Count + Kinds[17].Count + Kinds[18].Count + Kinds[19].Count + Kinds[20].Count;
    Statistics.UniqueRvas = Explored.size();

    return allok;
}

bool AutoDebugStore::ForEachRecord(ObsKind k, const std::function<void(const void*, size_t)>& visit)
{
    if (!Opened) return false;

    const uint32_t expected = RecSizeFor(k);
    const wchar_t* fname = FilenameFor(k);
    if (!fname || expected == 0) return false;

    const uint16_t slot = static_cast<uint16_t>(k);
    if (Kinds[slot].Out.is_open()) Kinds[slot].Out.flush();

    std::filesystem::path p = ProjectDir / L"observations" / fname;
    std::ifstream f(p, std::ios::binary);
    if (!f) return false;

    SophiaFileHeader hdr = {};
    f.read(reinterpret_cast<char*>(&hdr), sizeof(hdr));
    if (!f)
    {
        std::fprintf(stderr, "[sophiaproj] ForEachRecord: truncated header on %ls\n", fname);
        return false;
    }
    if (std::memcmp(hdr.Magic, "SODB", 4) != 0 || hdr.Version != 1 || hdr.Kind != slot || hdr.RecSize != expected)
    {
        std::fprintf(stderr, "[sophiaproj] ForEachRecord: header mismatch on %ls (kind=%u rec_size=%u expected=%u)\n", fname, hdr.Kind, hdr.RecSize, expected);
        return false;
    }

    std::vector<char> rec(expected);
    while (f.read(rec.data(), expected))
    {
        visit(rec.data(), expected);
    }
    return true;
}

bool AutoDebugStore::FinalizeRun()
{
    if (!Opened) return false;

    FlushStreams();

    ++PriorRunCount;
    return WriteManifest();
}

AutoDebugStore::~AutoDebugStore()
{
}