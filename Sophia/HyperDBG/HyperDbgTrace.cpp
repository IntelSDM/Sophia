#include "../Pch.h"
#include "HyperDbgTrace.h"

void HyperDbgTrace::ResolveTraceExports(HMODULE dll)
{
    if (dll == nullptr) return;

    LoadHyperTraceFn = reinterpret_cast<PFN_LoadHyperTrace>(GetProcAddress(dll, "hyperdbg_u_load_hypertrace_module"));
}

bool HyperDbgTrace::LoadHyperTraceModule()
{
    if (HyperTraceLoaded)
    {
        return true;
    }

    if (LoadHyperTraceFn == nullptr)
    {
        return false;
    }

    int rc = LoadHyperTraceFn();
    if (rc != 0)
    {
        std::fprintf(stderr, "[!] hyperdbg_u_load_hypertrace_module returned %d (no Intel PT / LBR on this CPU, or driver issue)\n", rc);
        return false;
    }

    HyperTraceLoaded = true;
    return true;
}

bool HyperDbgTrace::TraceEnableForPath(const std::string& exepath, uint64_t size, uint32_t core)
{
    if (!HyperTraceLoaded) return false;

    if (exepath.empty())
    {
        std::fprintf(stderr, "[!] TraceEnableForPath: empty path\n");
        return false;
    }
    if (exepath.find(' ') != std::string::npos || exepath.find('"') != std::string::npos)
    {
        std::fprintf(stderr, "[!] TraceEnableForPath: '%s' contains spaces or quotes -- HyperDbg 0.23's parser can't handle those. Copy the exe to a space-free path first.\n", exepath.c_str());
        return false;
    }

    char buf[128];
    std::string cmd = "!pt enable path ";
    cmd += exepath;
    if (size != 0)
    {
        std::snprintf(buf, sizeof(buf), " size 0x%llx", static_cast<unsigned long long>(size));
        cmd += buf;
    }
    if (core != UINT32_MAX)
    {
        std::snprintf(buf, sizeof(buf), " core 0x%x", core);
        cmd += buf;
    }

    LastResponse = Run(cmd);
    return !ResponseHasError(LastResponse);
}

bool HyperDbgTrace::TraceDisable()
{
    if (!HyperTraceLoaded) return false;
    SetTeeStdout(false);
    LastResponse = Run("!pt disable");
    SetTeeStdout(true);
    return !ResponseHasError(LastResponse);
}

bool HyperDbgTrace::ResponseHasError(const std::string& resp)
{
    return resp.find("err") != std::string::npos ||
        resp.find("Err") != std::string::npos ||
        resp.find("invalid") != std::string::npos ||
        resp.find("failed") != std::string::npos ||
        resp.find("not loaded") != std::string::npos;
}