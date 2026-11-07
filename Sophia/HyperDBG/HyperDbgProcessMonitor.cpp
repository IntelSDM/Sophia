#include "../Pch.h"
#include "HyperDbgProcessMonitor.h"

#include <regex>
#include <stdexcept>

static constexpr const char* MARKER_PREFIX = "[HYPRDBG_NP]";

static constexpr uint32_t SPIN_MAX_ITERS = 1000;
static constexpr uint32_t SPIN_SLEEP_US = 100;

HyperDbgProcessMonitor::HyperDbgProcessMonitor(HyperDbgSession& session, const std::string& targetimagename)
    : Session(session),
    TargetImageName(targetimagename),
    OffUniqueProcessId(0),
    OffImageFileName(0),
    OffSeAudit(0),
    OffSectionBaseAddress(0),
    Shared(nullptr),
    SharedSlotsBasePa(0),
    Installed(false),
    WorkerRunning(false)
{
    if (TargetImageName.empty())
    {
        throw std::runtime_error("target image name cannot be empty");
    }
    if (TargetImageName.size() > 14)
    {
        throw std::runtime_error("target image name '" + TargetImageName + "' is longer than 14 chars -- kernel EPROCESS.ImageFileName truncates to 14; shorten or match a prefix");
    }
    for (unsigned char c : TargetImageName)
    {
        if (c < 0x20 || c >= 0x7f || c == '"' || c == '\\')
        {
            throw std::runtime_error("target image name '" + TargetImageName + "' has non-printable or unsafe characters");
        }
    }
}

HyperDbgProcessMonitor::~HyperDbgProcessMonitor()
{
    try
    {
        Stop();
    }
    catch (...)
    {
    }
}

void HyperDbgProcessMonitor::Start()
{
    if (Installed)
    {
        return;
    }

    EnsureKernelSymbolsLoaded();
    QueryEProcessOffsets();
    AllocateSharedPage();

    Session.SetMessageHandler([this](const char* msg)
        {
            OnMessage(msg);
        });

    WorkerRunning.store(true);
    Worker = std::thread(&HyperDbgProcessMonitor::WorkerLoop, this);

    try
    {
        InstallPspInsertProcessHook();
    }
    catch (...)
    {
        WorkerRunning.store(false);
        QueueCv.notify_all();
        if (Worker.joinable()) Worker.join();
        Session.SetMessageHandler(nullptr);
        FreeSharedPage();
        throw;
    }

    Installed = true;
    std::puts("[+] stage-1 hook armed on nt!PspInsertProcess (filtered)");
}

void HyperDbgProcessMonitor::Stop()
{
    if (!Installed)
    {
        return;
    }

    Session.Run("events c all");

    SignalAllSlots();

    Session.SetMessageHandler(nullptr);

    WorkerRunning.store(false);
    QueueCv.notify_all();
    if (Worker.joinable()) Worker.join();

    {
        std::lock_guard<std::mutex> lock(QueueMutex);
        for (auto& evt : Queue)
        {
            SignalSlot(evt.Slot);
        }
        Queue.clear();
    }

    FreeSharedPage();
    Installed = false;
    std::puts("[+] monitor stopped");
}

void HyperDbgProcessMonitor::EnsureKernelSymbolsLoaded()
{
    std::puts("[+] loading kernel symbols (first-run download can take a bit)...");
    Session.SetTeeStdout(false);
    Session.Run(".sym load");
    Session.Run(".sym reload");
    Session.SetTeeStdout(true);
}

void HyperDbgProcessMonitor::QueryEProcessOffsets()
{
    Session.SetTeeStdout(false);
    std::string dump = Session.Run("struct nt!_EPROCESS");
    Session.SetTeeStdout(true);

    OffUniqueProcessId = ParseOffsetForField(dump, "UniqueProcessId");
    OffImageFileName = ParseOffsetForField(dump, "ImageFileName");
    OffSeAudit = ParseOffsetForField(dump, "SeAuditProcessCreationInfo");
    OffSectionBaseAddress = ParseOffsetForField(dump, "SectionBaseAddress");

    std::printf("[+] EPROCESS layout: pid=+0x%x  name=+0x%x  seaudit=+0x%x  section=+0x%x\n", OffUniqueProcessId, OffImageFileName, OffSeAudit, OffSectionBaseAddress);
}

uint32_t HyperDbgProcessMonitor::ParseOffsetForField(const std::string& structdump, const std::string& fieldname)
{
    std::string pattern = R"(/\*\s+0x([0-9a-fA-F]+)\s+\*/[^\n]*?\b)" + fieldname + R"(\b)";

    std::regex re(pattern);
    std::smatch m;
    if (!std::regex_search(structdump, m, re))
    {
        throw std::runtime_error("could not resolve nt!_EPROCESS." + fieldname + " offset");
    }
    return static_cast<uint32_t>(std::stoul(m[1].str(), nullptr, 16));
}

void HyperDbgProcessMonitor::AllocateSharedPage()
{
    Shared = static_cast<SharedRegion*>(VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (Shared == nullptr)
    {
        throw std::runtime_error("VirtualAlloc(shared page) failed");
    }

    std::memset(Shared, 0, 0x1000);

    if (!VirtualLock(Shared, 0x1000))
    {
        DWORD err = GetLastError();
        VirtualFree(Shared, 0, MEM_RELEASE);
        Shared = nullptr;
        throw std::runtime_error("VirtualLock(shared page) failed (err=" + std::to_string(err) + "); run as admin or bump SetProcessWorkingSetSize");
    }

    uint64_t va = reinterpret_cast<uint64_t>(&Shared->Slots[0]);
    SharedSlotsBasePa = QueryPhysicalAddress(va);
    if (SharedSlotsBasePa == 0)
    {
        VirtualUnlock(Shared, 0x1000);
        VirtualFree(Shared, 0, MEM_RELEASE);
        Shared = nullptr;
        throw std::runtime_error("virtual_to_physical returned 0");
    }

    std::printf("[+] shared slots base VA=0x%llx PA=0x%llx (%u slots)\n", va, SharedSlotsBasePa, SlotCount);
}

void HyperDbgProcessMonitor::FreeSharedPage()
{
    if (Shared)
    {
        VirtualUnlock(Shared, 0x1000);
        VirtualFree(Shared, 0, MEM_RELEASE);
        Shared = nullptr;
        SharedSlotsBasePa = 0;
    }
}

uint64_t HyperDbgProcessMonitor::QueryPhysicalAddress(uint64_t va)
{
    char cmd[128];
    std::snprintf(cmd, sizeof(cmd), "!va2pa 0x%llx pid %x", static_cast<unsigned long long>(va), static_cast<unsigned int>(GetCurrentProcessId()));

    Session.SetTeeStdout(false);
    std::string resp = Session.Run(cmd);
    Session.SetTeeStdout(true);

    std::regex re(R"(\b([0-9a-fA-F]+)\b)");
    std::smatch m;
    if (!std::regex_search(resp, m, re))
    {
        return 0;
    }
    uint64_t pa = std::stoull(m[1].str(), nullptr, 16);
    return pa;
}

void HyperDbgProcessMonitor::SignalSlot(uint32_t slot)
{
    if (!Shared || slot >= SlotCount) return;
    Shared->Slots[slot] = 1;
}

void HyperDbgProcessMonitor::SignalAllSlots()
{
    if (!Shared) return;
    for (uint32_t i = 0; i < SlotCount; ++i)
    {
        Shared->Slots[i] = 1;
    }
}

void HyperDbgProcessMonitor::InstallPspInsertProcessHook()
{
    Session.SetTeeStdout(false);
    Session.Run("? .hyprdbg_seq = 0;");
    Session.SetTeeStdout(true);

    char script[2048];
    std::snprintf(script, sizeof(script),
        "eproc = @rcx;"
        "if (strcmp(eproc + 0x%x, \"%s\") == 0) {"
        "  seq = interlocked_increment(&.hyprdbg_seq);"
        "  slot = seq & 0x%x;"
        "  slot_pa = 0x%llx + slot * 8;"
        "  eq_pa(slot_pa, 0);"
        "  pid = poi(eproc + 0x%x);"
        "  audit = poi(eproc + 0x%x);"
        "  if (audit != 0) {"
        "    pathptr = poi(audit + 0x8);"
        "    if (pathptr != 0) {"
        "      printf(\"%s slot=0x%%llx eproc=0x%%llx pid=0x%%llx name=%%s path=%%ws\\n\", "
        "slot, eproc, pid, eproc + 0x%x, pathptr);"
        "    } else {"
        "      printf(\"%s slot=0x%%llx eproc=0x%%llx pid=0x%%llx name=%%s path=-\\n\", "
        "slot, eproc, pid, eproc + 0x%x);"
        "    }"
        "  } else {"
        "    printf(\"%s slot=0x%%llx eproc=0x%%llx pid=0x%%llx name=%%s path=-\\n\", "
        "slot, eproc, pid, eproc + 0x%x);"
        "  }"
        "  i = 0;"
        "  while (i < %u) {"
        "    if (poi_pa(slot_pa) != 0) { i = %u; }"
        "    else { microsleep(%u); i = i + 1; }"
        "  }"
        "}",
        OffImageFileName, TargetImageName.c_str(),
        SlotCount - 1,
        static_cast<unsigned long long>(SharedSlotsBasePa),
        OffUniqueProcessId,
        OffSeAudit,
        MARKER_PREFIX, OffImageFileName,
        MARKER_PREFIX, OffImageFileName,
        MARKER_PREFIX, OffImageFileName,
        SPIN_MAX_ITERS,
        SPIN_MAX_ITERS,
        SPIN_SLEEP_US);

    char cmd[4096];
    std::snprintf(cmd, sizeof(cmd), "!epthook nt!PspInsertProcess script { %s }", script);

    std::string response = Session.Run(cmd);
    if (response.find("err") != std::string::npos ||
        response.find("Err") != std::string::npos ||
        response.find("invalid") != std::string::npos ||
        response.find("failed") != std::string::npos)
    {
        throw std::runtime_error("!epthook install failed:\n" + response);
    }

    std::printf("[+] filter armed: only processes named '%s' will trigger the entrypoint capture flow\n", TargetImageName.c_str());
}

void HyperDbgProcessMonitor::OnMessage(const char* msg)
{
    std::string linesready;
    {
        std::lock_guard<std::mutex> lock(AccMutex);
        AccBuf.append(msg);

        size_t nl;
        while ((nl = AccBuf.find('\n')) != std::string::npos)
        {
            linesready.append(AccBuf, 0, nl + 1);
            AccBuf.erase(0, nl + 1);
        }
    }

    if (linesready.empty()) return;

    size_t start = 0;
    while (start < linesready.size())
    {
        size_t nl = linesready.find('\n', start);
        if (nl == std::string::npos) break;

        std::string line(linesready, start, nl - start);
        start = nl + 1;

        while (!line.empty() && (line.back() == '\r' || line.back() == '\n'))
        {
            line.pop_back();
        }

        if (line.rfind(MARKER_PREFIX, 0) == 0)
        {
            try
            {
                ProcessMarkerLine(line);
            }
            catch (const std::exception& ex)
            {
                std::fprintf(stderr, "[!] marker parse error: %s\n", ex.what());
            }
        }
    }
}

void HyperDbgProcessMonitor::ProcessMarkerLine(const std::string& line)
{
    static const std::regex re(
        R"(\[HYPRDBG_NP\] slot=0x([0-9a-fA-F]+) eproc=0x([0-9a-fA-F]+) )"
        R"(pid=0x([0-9a-fA-F]+) name=(\S+) path=(.*))");

    std::smatch m;
    if (!std::regex_search(line, m, re)) return;

    NewProcEvent evt;
    evt.Slot = static_cast<uint32_t>(std::stoul(m[1].str(), nullptr, 16));
    evt.EprocKernelVa = std::stoull(m[2].str(), nullptr, 16);
    evt.Pid = static_cast<uint32_t>(std::stoull(m[3].str(), nullptr, 16));
    evt.Name = m[4].str();
    evt.Path = m[5].str();

    {
        std::lock_guard<std::mutex> lock(QueueMutex);
        Queue.push_back(std::move(evt));
    }
    QueueCv.notify_one();
}

void HyperDbgProcessMonitor::WorkerLoop()
{
    while (true)
    {
        NewProcEvent evt;
        {
            std::unique_lock<std::mutex> lock(QueueMutex);
            QueueCv.wait(lock, [this]
                {
                    return !Queue.empty() || !WorkerRunning.load();
                });
            if (!WorkerRunning.load() && Queue.empty()) return;
            if (Queue.empty()) continue;

            evt = std::move(Queue.front());
            Queue.pop_front();
        }

        try
        {
            HandleNewProcess(evt);
        }
        catch (const std::exception& ex)
        {
            std::fprintf(stderr, "[!] worker error: %s\n", ex.what());
        }
    }
}

void HyperDbgProcessMonitor::HandleNewProcess(const NewProcEvent& evt)
{
    struct SlotGuard
    {
        HyperDbgProcessMonitor* Self;
        uint32_t Slot;
        bool Released;
        ~SlotGuard()
        {
            if (Self && !Released) Self->SignalSlot(Slot);
        }
        void ReleaseNow()
        {
            if (Self && !Released)
            {
                Self->SignalSlot(Slot);
                Released = true;
            }
        }
    } guard{ this, evt.Slot, false };

    std::printf("[proc] pid=%u name=%s path=%s\n", evt.Pid, evt.Name.c_str(), evt.Path.c_str());

    uint64_t imagebase = 0;
    if (!ReadKernel(evt.EprocKernelVa + OffSectionBaseAddress, &imagebase, sizeof(imagebase)) || imagebase == 0)
    {
        std::fprintf(stderr, "[!] pid=%u: could not read SectionBaseAddress\n", evt.Pid);
        return;
    }

    IMAGE_DOS_HEADER dos{};
    if (!ReadUser(evt.Pid, imagebase, &dos, sizeof(dos)) || dos.e_magic != IMAGE_DOS_SIGNATURE)
    {
        std::fprintf(stderr, "[!] pid=%u: bad DOS header at 0x%llx\n", evt.Pid, imagebase);
        return;
    }

    IMAGE_NT_HEADERS64 nt{};
    if (!ReadUser(evt.Pid, imagebase + dos.e_lfanew, &nt, sizeof(nt)) ||
        nt.Signature != IMAGE_NT_SIGNATURE ||
        nt.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
    {
        std::fprintf(stderr, "[!] pid=%u: bad NT headers (not x64?)\n", evt.Pid);
        return;
    }

    uint64_t entryva = imagebase + nt.OptionalHeader.AddressOfEntryPoint;
    std::printf("[proc] pid=%u  imagebase=0x%llx  entrypoint=0x%llx (rva=0x%x)\n", evt.Pid, imagebase, entryva, nt.OptionalHeader.AddressOfEntryPoint);

    bool entryhooked = false;
    for (int attempt = 0; attempt < 5; ++attempt)
    {
        TouchPage(evt.Pid, entryva);
        if (InstallEntrypointHook(evt.Pid, entryva, evt.Name))
        {
            entryhooked = true;
            break;
        }
        Sleep(20);
    }
    if (!entryhooked)
    {
        std::fprintf(stderr, "[!] pid=%u: entrypoint hook install failed after retries\n", evt.Pid);
        return;
    }
    std::printf("[proc] pid=%u  entrypoint hook armed\n", evt.Pid);

    guard.ReleaseNow();
}

void HyperDbgProcessMonitor::TouchPage(uint32_t pid, uint64_t va)
{
    char cmd[128];
    std::snprintf(cmd, sizeof(cmd), "db 0x%llx l 1 pid %x", static_cast<unsigned long long>(va), static_cast<unsigned int>(pid));

    Session.SetTeeStdout(false);
    Session.Run(cmd);
    Session.SetTeeStdout(true);
}

bool HyperDbgProcessMonitor::InstallEntrypointHook(uint32_t pid, uint64_t entryva, const std::string& name)
{
    char safename[32] = {};
    size_t j = 0;
    for (size_t i = 0; i < name.size() && j + 1 < sizeof(safename); ++i)
    {
        unsigned char c = static_cast<unsigned char>(name[i]);
        if (c >= 0x20 && c < 0x7f && c != '"' && c != '\\')
        {
            safename[j++] = static_cast<char>(c);
        }
    }

    char cmd[512];
    std::snprintf(cmd, sizeof(cmd),
        "!epthook 0x%llx pid %x script { "
        "printf(\"[entry] pid=0x%%llx tid=0x%%llx name=%s rip=0x%%llx\\n\", "
        "$pid, $tid, @rip); "
        "}",
        static_cast<unsigned long long>(entryva),
        pid,
        safename);

    Session.SetTeeStdout(false);
    std::string response = Session.Run(cmd);
    Session.SetTeeStdout(true);

    if (response.find("err") != std::string::npos ||
        response.find("Err") != std::string::npos ||
        response.find("invalid") != std::string::npos ||
        response.find("failed") != std::string::npos)
    {
        return false;
    }
    return true;
}

bool HyperDbgProcessMonitor::ReadKernel(uint64_t va, void* out, uint32_t size)
{
    return Session.Read(4, va, out, size);
}

bool HyperDbgProcessMonitor::ReadUser(uint32_t pid, uint64_t va, void* out, uint32_t size)
{
    return Session.Read(pid, va, out, size, HyperDbgMemory::ReadPath::FromVmxRoot);
}