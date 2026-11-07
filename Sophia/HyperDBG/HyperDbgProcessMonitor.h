#pragma once
#include "HyperDbgSession.h"

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <mutex>
#include <string>
#include <thread>

class HyperDbgProcessMonitor
{
public:
    HyperDbgProcessMonitor(HyperDbgSession& session, const std::string& targetimagename);
    ~HyperDbgProcessMonitor();

    HyperDbgProcessMonitor(const HyperDbgProcessMonitor&) = delete;
    HyperDbgProcessMonitor& operator=(const HyperDbgProcessMonitor&) = delete;

    void Start();
    void Stop();

    bool IsActive() const { return Installed; }

    static constexpr uint32_t SlotCount = 64;

private:
    struct SharedRegion
    {
        volatile uint64_t Slots[SlotCount];
    };

    struct NewProcEvent
    {
        uint32_t Slot;
        uint32_t Pid;
        uint64_t EprocKernelVa;
        std::string Name;
        std::string Path;
    };

    void EnsureKernelSymbolsLoaded();
    void QueryEProcessOffsets();
    static uint32_t ParseOffsetForField(const std::string& structdump, const std::string& fieldname);

    void AllocateSharedPage();
    void FreeSharedPage();
    uint64_t QueryPhysicalAddress(uint64_t va);

    void InstallPspInsertProcessHook();

    void OnMessage(const char* msg);
    void ProcessMarkerLine(const std::string& line);

    void WorkerLoop();
    void HandleNewProcess(const NewProcEvent& evt);
    bool InstallEntrypointHook(uint32_t pid, uint64_t entryva, const std::string& name);

    void TouchPage(uint32_t pid, uint64_t va);

    void SignalSlot(uint32_t slot);
    void SignalAllSlots();

    bool ReadKernel(uint64_t va, void* out, uint32_t size);
    bool ReadUser(uint32_t pid, uint64_t va, void* out, uint32_t size);

    HyperDbgSession& Session;

    std::string TargetImageName;

    uint32_t OffUniqueProcessId;
    uint32_t OffImageFileName;
    uint32_t OffSeAudit;
    uint32_t OffSectionBaseAddress;

    SharedRegion* Shared;
    uint64_t SharedSlotsBasePa;

    bool Installed;

    std::mutex AccMutex;
    std::string AccBuf;

    std::mutex QueueMutex;
    std::condition_variable QueueCv;
    std::deque<NewProcEvent> Queue;
    std::atomic<bool> WorkerRunning;
    std::thread Worker;
};