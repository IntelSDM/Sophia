#pragma once
#include "../../HyperDBG/HyperDbgSession.h"

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

class PEDumper
{
public:
    explicit PEDumper(HyperDbgSession& session);

    enum class AddressSpace : uint32_t
    {
        User,
        Kernel
    };

    struct LoadedModule
    {
        uint64_t     Base;
        uint32_t     Size;
        AddressSpace Space;
        uint32_t     Pid;
        std::wstring BaseName;
        std::wstring FullPath;
    };

    struct DumpResult
    {
        LoadedModule          Module;
        std::filesystem::path OutPath;
        uint32_t              SectionsDumped;
        uint32_t              SectionsSkipped;
        uint32_t              HeaderBytes;
        uint32_t              DataBytes;
        uint32_t              CodeBytes;
        uint32_t              BackfilledBytes;
        bool                  Ok;
        std::string           Error;
    };

    void PrimeCache();

    uint32_t FindPidByImageName(const std::string& imagename);
    uint32_t FindLivePidByImageName(const std::string& imagename);
    std::vector<uint32_t> EnumeratePidsByImageName(const std::string& imagename);
    void PrintProcessRoster();

    std::vector<DumpResult> DumpProcess(uint32_t pid, std::chrono::milliseconds delay, const std::filesystem::path& outdir, bool includecode = false, bool backfillcode = false);
    std::vector<DumpResult> DumpKernel(std::chrono::milliseconds delay, const std::filesystem::path& outdir, bool includecode = false, bool backfillcode = false);

    std::vector<LoadedModule> EnumerateProcessModules(uint32_t pid);
    std::vector<LoadedModule> EnumerateKernelModules();

    DumpResult DumpOne(const LoadedModule& mod, const std::filesystem::path& outpath, bool includecode = false, bool backfillcode = false);

private:
    static constexpr uint32_t OffPebLdr = 0x18;
    static constexpr uint32_t OffLdrInLoadOrder = 0x10;
    static constexpr uint32_t OffLdteDllBase = 0x30;
    static constexpr uint32_t OffLdteSizeOfImage = 0x40;
    static constexpr uint32_t OffLdteFullDllName = 0x48;
    static constexpr uint32_t OffLdteBaseDllName = 0x58;

    void EnsureKernelSymbolsLoaded();
    uint64_t ResolveKernelSymbol(const std::string& name);
    uint32_t ResolveStructFieldOffset(const std::string& structname, const std::string& fieldname);

    struct Cache
    {
        bool     Ready = false;
        uint64_t PsActiveProcessHead = 0;
        uint64_t PsLoadedModuleList = 0;
        uint32_t EprocessUniqueProcessId = 0;
        uint32_t EprocessActiveProcessLinks = 0;
        uint32_t EprocessPeb = 0;
        uint32_t EprocessImageFileName = 0;
        uint32_t EprocessSectionBaseAddress = 0;
        uint32_t EprocessSeAuditProcessCreationInfo = 0;
    } Ck;
    void EnsureCache();

    uint64_t FindEProcess(uint32_t pid);

    std::string ProcessImageNameLower(uint64_t eproc);

    static std::string ToLower(const std::string& s);

    bool ReadK(uint64_t va, void* out, uint32_t size);
    bool ReadU(uint32_t pid, uint64_t va, void* out, uint32_t size);
    uint32_t ReadKRobust(uint64_t va, uint8_t* out, uint32_t size);
    uint32_t ReadURobust(uint32_t pid, uint64_t va, uint8_t* out, uint32_t size);

    bool ReadUnicodeString(AddressSpace space, uint32_t pid, uint64_t ustringva, std::wstring& out);

    std::vector<DumpResult> DumpModuleList(std::vector<LoadedModule> modules, const std::filesystem::path& outdir, const char* label, bool includecode, bool backfillcode);

    static bool ExtractFirstHex(const std::string& s, uint64_t& value);
    static uint32_t ParseFieldOffset(const std::string& dump, const std::string& fieldname);
    static bool ExtractKernelVaFromDbOutput(const std::string& s, uint64_t& value);
    static uint32_t BackfillFromDisk(const LoadedModule& mod, std::vector<uint8_t>& buf, bool includecode);

    HyperDbgSession& Session;
};