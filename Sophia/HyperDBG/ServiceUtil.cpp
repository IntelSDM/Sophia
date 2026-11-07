#include "../Pch.h"
#include "ServiceUtil.h"

void ServiceUtil::EvictStale(const wchar_t* servicename)
{
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (scm == nullptr)
    {
        return;
    }

    SC_HANDLE svc = OpenServiceW(scm, servicename, SERVICE_ALL_ACCESS);
    if (svc != nullptr)
    {
        SERVICE_STATUS status = {};
        ControlService(svc, SERVICE_CONTROL_STOP, &status);
        DeleteService(svc);
        CloseServiceHandle(svc);
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }

    CloseServiceHandle(scm);
}