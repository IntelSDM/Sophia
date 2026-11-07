#include "../Pch.h"
#include "HyperDbgSession.h"
#include "ServiceUtil.h"

HyperDbgSession::HyperDbgSession(const std::filesystem::path& hyperdbgdir, const std::wstring& sysname, const std::string& svcname)
    : SvcNameW(svcname.begin(), svcname.end()),
    KdInstalled(false),
    VmmLoaded(false),
    HyperTraceEnabled(false)
{
    Startup(hyperdbgdir, sysname, svcname);
}

HyperDbgSession::~HyperDbgSession()
{
    Shutdown();
}

void HyperDbgSession::Startup(const std::filesystem::path& hyperdbgdir, const std::wstring& sysname, const std::string& svcname)
{
    std::filesystem::current_path(hyperdbgdir);

    LoadLibraryAndResolveExports(hyperdbgdir);

    ResolveTraceExports(Dll);

    if (!DetectVmxFn())
    {
        throw std::runtime_error("CPU/BIOS does not expose VMX");
    }

    ServiceUtil::EvictStale(SvcNameW.c_str());

    auto syspath = (hyperdbgdir / sysname).string();
    std::string svccopy = svcname;
    if (!SetDriverPathFn(syspath.data(), svccopy.data()))
    {
        throw std::runtime_error("hyperdbg_u_set_custom_driver_path failed");
    }

    if (InstallKdFn() != 0)
    {
        throw std::runtime_error("hyperdbg_u_install_kd_driver failed");
    }
    KdInstalled = true;

    if (LoadVmmFn() != 0)
    {
        throw std::runtime_error("hyperdbg_u_load_vmm failed");
    }
    VmmLoaded = true;

    if (IsHyperTraceAvailable() && LoadHyperTraceModule())
    {
        HyperTraceEnabled = true;
        std::puts("[+] hypertrace module loaded (Intel PT ready)");
    }
    else
    {
        std::puts("[!] hypertrace module NOT loaded -- Trace* APIs will no-op. Update HyperDbg (>= v0.19) or check CPU support with `cpu`.");
    }
}

void HyperDbgSession::Shutdown()
{
    if (HyperTraceEnabled)
    {
        try
        {
            Run("unload trace");
        }
        catch (...)
        {
        }
        HyperTraceEnabled = false;
    }

    try
    {
        if (VmmLoaded)
        {
            UnloadVmmFn();
            VmmLoaded = false;
        }
    }
    catch (...)
    {
    }

    try
    {
        if (KdInstalled)
        {
            UnloadKdFn();
            StopKdFn();
            UninstallKdFn();
            KdInstalled = false;
        }
    }
    catch (...)
    {
    }
}