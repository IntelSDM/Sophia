#pragma once

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <fstream>
#include <string>
#include <unordered_map>
#include <vector>

#include <windows.h>

enum class ValSpace : uint8_t
{
    Unknown,
    Int,
    TextRva,
    RdataRva,
    DataRva,
    SectionOther,
    Foreign,
    StackHeap
};

struct ForeignMod
{
    std::string Name;
    uint64_t    Base;
    uint64_t    Size;
};

struct ForeignHit
{
    const ForeignMod* Mod = nullptr;
    uint64_t          Offset = 0;
};

class DeobfValClassifier
{
public:
    static constexpr size_t kStringDisplayCap = 128;

    static ValSpace ClassifyBySection(const std::vector<uint8_t>& buf, uint64_t tracedbase, uint64_t tracedsize, uint64_t val);
    static ForeignHit ClassifyForeign(const std::vector<ForeignMod>& mods, uint64_t val);

    static uint32_t RvaToFileOff(const std::vector<uint8_t>* modbytes, const uint8_t* rawbuf, size_t rawsize, uint32_t rva);

    static std::string ReadAnsiFrom(const uint8_t* data, size_t size, uint32_t off);
    static std::string ReadWideFrom(const uint8_t* data, size_t size, uint32_t off);

    static bool IsAnsiString(const uint64_t head[4]);
    static bool IsWideString(const uint64_t head[4]);
    static std::string DecodeAnsi(const uint64_t head[4]);
    static std::string DecodeWide(const uint64_t head[4]);
    static std::string DecodeInlineAscii(uint64_t val);

    static std::ifstream OpenForeign(const std::wstring& path);

    static void LoadForeignPaths(const std::filesystem::path& modulestsv, std::unordered_map<std::string, std::wstring>& out);
};