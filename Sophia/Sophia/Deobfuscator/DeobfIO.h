#pragma once

#include "Deobfuscator.h"
#include "DeobfContext.h"

#include <cstdint>
#include <string>
#include <vector>

class DeobfIo
{
public:
    static bool PromptYesNo(const char* question, bool dflt);
    static void PromptConfig(DeobfConfig& cfg);

    static void Banner(const char* text);
    static void RuleOpen(const char* text);
    static void RuleClose();
    static void Line(const char* text);
    static void KeyValueU32(const char* key, uint32_t value);
    static void KeyValueU64(const char* key, uint64_t value);
    static void KeyValueRvaU64(const char* key, uint64_t value);
    static void KeyValueStr(const char* key, const char* value);
    static void KeyValuePath(const char* key, const std::filesystem::path& p);

    static void PrintProjectInfo(const std::wstring& dir, const std::string& hash);
    static void PrintStoreStats(const ObsStats& os, uint64_t totalrecords, uint64_t uniquervas);
    static void PrintPescanStats(size_t totalsites, uint32_t plainjccs);
    static void PrintHashMismatchWarn(const std::string& manifesthash, const std::string& inputhash);
    static void PrintSkip(const char* passname, const char* reason);

    static void PrintReport(const Deobfuscator::Report& r);
    static void PrintFatal(const std::string& msg);

    static const char* MnPadded(const char* mn);
};