#pragma once
#include "HyperDbgMemory.h"
#include <cstdint>
#include <string>

class HyperDbgTrace : public HyperDbgMemory
{
public:
    HyperDbgTrace() = default;

    bool IsHyperTraceAvailable() const { return LoadHyperTraceFn != nullptr; }

    void ResolveTraceExports(HMODULE dll);

    bool LoadHyperTraceModule();
    bool IsHyperTraceLoaded() const { return HyperTraceLoaded; }

    bool TraceEnableForPath(const std::string& exepath, uint64_t size = 0, uint32_t core = 0);

    bool TraceDisable();

    const std::string& LastTraceResponse() const { return LastResponse; }

private:
    typedef int (*PFN_LoadHyperTrace)();

    PFN_LoadHyperTrace LoadHyperTraceFn = nullptr;

    bool HyperTraceLoaded = false;
    std::string LastResponse;

    static bool ResponseHasError(const std::string& resp);
};