#pragma once
#include "HyperDbgSessionBase.h"
#include <cstdint>
#include <string>
#include <vector>
#include <filesystem>

struct KernelModule
{
    uint64_t Base;
    uint32_t Size;
    std::string FullPath;
    std::string FileName;
};

class HyperDbgMemory : public HyperDbgSessionBase
{
public:
    HyperDbgMemory() = default;

    static constexpr uint32_t PageSize = 0x1000;

    enum class ReadPath : int
    {
        FromKernel = 0,
        FromVmxRoot = 1,
    };

    bool Read(uint32_t pid, uint64_t va, void* out, uint32_t size, ReadPath path = ReadPath::FromKernel);
    uint32_t ReadRobust(uint32_t pid, uint64_t va, uint8_t* out, uint32_t size, ReadPath path = ReadPath::FromKernel);
    bool WriteBytes(uint32_t pid, uint64_t va, const void* data, uint32_t size);

    std::string EptHook(uint64_t va, uint32_t pid, const std::string& script);
    std::string EptHook(const std::string& symbol, uint32_t pid, const std::string& script);
    std::string EptHook2(uint64_t va, uint32_t pid, const std::string& script);
    std::string EptHook2(const std::string& symbol, uint32_t pid, const std::string& script);

    void DumpModule(uint32_t pid, uint64_t base, const std::filesystem::path& outpath);
    void DumpKernelModule(const std::string& name, const std::filesystem::path& outpath);

    static std::vector<KernelModule> EnumerateKernelModules();
};