#pragma once
#include "../../HyperDBG/HyperDbgSession.h"
#include "../WinPE/PEScan.h"
#include "AutoDebugPeUtils.h"

#include <cstdint>
#include <filesystem>
#include <string>
#include <unordered_map>
#include <vector>

class AutoDebugStore;
class PEDumper;
enum class ObsKind : uint16_t;

class AutoDebugTool
{
public:
    explicit AutoDebugTool(HyperDbgSession& session);

    void RunUser(const std::string& dumppath, const std::string& exename, bool monitortargetsyscalls = true, bool monitorntdllsyscalls = false);
    void RunDriver(PEDumper& dumper, const std::string& drivername, bool monitortargetsyscalls = true);

    using ForeignExport = AutoDebugPeUtils::ForeignExport;

private:
    enum class TargetKind
    {
        UserProcess,
        KernelDriver
    };

    struct ResolvedTarget
    {
        TargetKind Kind;
        std::string ScanPath;
        std::string ExeName;
        std::wstring RuntimePathW;
        std::wstring DisplayNameW;
        uint64_t Base;
        uint32_t ImageSize;
        uint32_t Pid;
        HANDLE ProcHandle;
        HANDLE ThreadHandle;
        PEDumper* KernelEnumerator;
    };

    void RunCore(ResolvedTarget tgt, bool monitortargetsyscalls, bool monitorntdllsyscalls);

    std::vector<InsnSite> ScanJumps(const std::string& filepath, uint64_t& preferredbase, const PeScan::ScanOptions& opts = {});

    uint32_t BuildMonitors(std::vector<InsnSite>& sites, uint32_t pid, uint64_t base, HANDLE hproc, const std::string& outputname, bool capturecallparams, bool capturestackargs, bool capturereturns, bool forceloadpages);

    std::string OpenHitsForwarding(const std::string& stem, std::filesystem::path& hitsfile);
    void CloseHitsForwarding(const std::string& outputname);

    uint32_t WaitForProcessByName(const std::string& exename);
    uint64_t QueryImageBase(uint32_t pid, HANDLE hproc, bool allowrpmfallback);

    static uint32_t ReadImageSizeFromDisk(const std::string& filepath);

    void TouchPage(uint32_t pid, uint64_t va);

    struct ForeignModule
    {
        uint64_t Base;
        uint32_t Size;
        std::string LowerName;
        std::wstring FullPath;
        std::vector<ForeignExport> Exports;
        std::unordered_map<uint32_t, size_t> ByRva;
    };

    std::vector<ForeignModule> SnapshotForeignModules(uint32_t pid, HANDLE hproc, uint64_t tracedbase);
    std::vector<ForeignModule> SnapshotForeignKernelModules(PEDumper& dumper, uint64_t tracedbase);

    static void WriteModulesSidecar(const std::filesystem::path& projectdir, const std::vector<ForeignModule>& mods, uint64_t tracedbase, uint32_t tracedsize, const std::wstring& tracedpath);

    void ResolveForeignBranchTargets(AutoDebugStore& store, uint64_t tracedbase, const std::vector<ForeignModule>& modules, ObsKind kind);

    bool BuildSyscallTable(const std::wstring& ntdllpath, std::unordered_map<uint32_t, std::string>& out);
    static void WriteSyscallTable(const std::filesystem::path& projectdir, const std::unordered_map<uint32_t, std::string>& map);

    uint32_t BuildNtdllSyscallMonitors(uint64_t ntdllbase, uint32_t ntdllsize, const std::wstring& ntdllpath, uint32_t pid, HANDLE hproc, const std::string& outputname, bool capturestackargs, std::vector<InsnSite>& ntdllsitesout);

    HyperDbgSession& Session;
};