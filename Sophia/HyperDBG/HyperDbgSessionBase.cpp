#include "../Pch.h"
#include "HyperDbgSessionBase.h"

HyperDbgSessionBase* HyperDbgSessionBase::ActiveSink = nullptr;

HyperDbgSessionBase::HyperDbgSessionBase()
    : Dll(nullptr),
    DetectVmxFn(nullptr),
    SetDriverPathFn(nullptr),
    InstallKdFn(nullptr),
    UninstallKdFn(nullptr),
    StopKdFn(nullptr),
    LoadVmmFn(nullptr),
    UnloadVmmFn(nullptr),
    UnloadKdFn(nullptr),
    RunCommandFn(nullptr),
    SetMsgCallbackFn(nullptr),
    ReadMemoryFn(nullptr),
    TeeStdout(true)
{
    if (ActiveSink != nullptr)
    {
        throw std::runtime_error("Only one HyperDbg session can exist at a time");
    }
    ActiveSink = this;
}

HyperDbgSessionBase::~HyperDbgSessionBase()
{
    FreeLibraryIfLoaded();
    ActiveSink = nullptr;
}

void HyperDbgSessionBase::LoadLibraryAndResolveExports(const std::filesystem::path& hyperdbgdir)
{
    auto dllpath = (hyperdbgdir / L"libhyperdbg.dll").wstring();
    Dll = LoadLibraryW(dllpath.c_str());
    if (Dll == nullptr)
    {
        throw std::runtime_error("LoadLibrary(libhyperdbg.dll) failed");
    }

    auto resolve = [this](const char* name) -> FARPROC
        {
            FARPROC addr = GetProcAddress(Dll, name);
            if (addr == nullptr)
            {
                throw std::runtime_error(std::string("missing export: ") + name);
            }
            return addr;
        };

    DetectVmxFn = (PFN_DetectVmx)resolve("hyperdbg_u_detect_vmx_support");
    SetDriverPathFn = (PFN_SetDriverPath)resolve("hyperdbg_u_set_custom_driver_path");
    InstallKdFn = (PFN_InstallKd)resolve("hyperdbg_u_install_kd_driver");
    UninstallKdFn = (PFN_UninstallKd)resolve("hyperdbg_u_uninstall_kd_driver");
    StopKdFn = (PFN_StopKd)resolve("hyperdbg_u_stop_kd_driver");
    LoadVmmFn = (PFN_LoadVmm)resolve("hyperdbg_u_load_vmm");
    UnloadVmmFn = (PFN_UnloadVmm)resolve("hyperdbg_u_unload_vmm");
    UnloadKdFn = (PFN_UnloadKd)resolve("hyperdbg_u_unload_kd");
    RunCommandFn = (PFN_RunCommand)resolve("hyperdbg_u_run_command");
    SetMsgCallbackFn = (PFN_SetMsgCallback)resolve("hyperdbg_u_set_text_message_callback");
    ReadMemoryFn = (PFN_ReadMemory)resolve("hyperdbg_u_read_memory");

    SetMsgCallbackFn(reinterpret_cast<void*>(&HyperDbgSessionBase::MessageThunk));
}

void HyperDbgSessionBase::FreeLibraryIfLoaded()
{
    if (Dll != nullptr)
    {
        FreeLibrary(Dll);
        Dll = nullptr;
    }
}

std::string HyperDbgSessionBase::Run(std::string command)
{
    {
        std::lock_guard<std::mutex> lock(BufMutex);
        OutputBuffer.clear();
    }

    command.push_back('\0');
    RunCommandFn(command.data());

    std::lock_guard<std::mutex> lock(BufMutex);
    return OutputBuffer;
}

void HyperDbgSessionBase::SetMessageHandler(MessageHandler h)
{
    std::lock_guard<std::mutex> lock(HandlerMutex);
    ExtraHandler = std::move(h);
}

int __cdecl HyperDbgSessionBase::MessageThunk(const char* msg)
{
    if (ActiveSink == nullptr || msg == nullptr)
    {
        return 0;
    }

    {
        std::lock_guard<std::mutex> lock(ActiveSink->BufMutex);
        if (ActiveSink->BufferingEnabled)
        {
            ActiveSink->OutputBuffer.append(msg);
        }

        if (ActiveSink->TeeStdout)
        {
            std::fputs(msg, stdout);
        }
    }

    MessageHandler handler;
    {
        std::lock_guard<std::mutex> lock(ActiveSink->HandlerMutex);
        handler = ActiveSink->ExtraHandler;
    }
    if (handler)
    {
        handler(msg);
    }

    return 0;
}