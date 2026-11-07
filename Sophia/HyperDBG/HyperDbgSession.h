#pragma once
#include "HyperDbgTrace.h"
#include <filesystem>
#include <string>

class HyperDbgSession : public HyperDbgTrace
{
public:
    HyperDbgSession(const std::filesystem::path& hyperdbgdir, const std::wstring& sysname = L"hyperkd.sys", const std::string& svcname = "hyperkd");

    virtual ~HyperDbgSession();

private:
    void Startup(const std::filesystem::path& hyperdbgdir, const std::wstring& sysname, const std::string& svcname);
    void Shutdown();

    std::wstring SvcNameW;
    bool KdInstalled;
    bool VmmLoaded;
    bool HyperTraceEnabled;
};