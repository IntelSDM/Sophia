#pragma once
#include <windows.h>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <filesystem>

typedef bool (*PFN_DetectVmx)();
typedef bool (*PFN_SetDriverPath)(char*, char*);
typedef int  (*PFN_InstallKd)();
typedef int  (*PFN_UninstallKd)();
typedef int  (*PFN_StopKd)();
typedef int  (*PFN_LoadVmm)();
typedef int  (*PFN_UnloadVmm)();
typedef int  (*PFN_UnloadKd)();
typedef int  (*PFN_RunCommand)(char*);
typedef void (*PFN_SetMsgCallback)(void*);
typedef bool (*PFN_ReadMemory)(uint64_t, int, int, uint32_t, uint32_t, bool, void*, uint8_t*, uint32_t*);

class HyperDbgSessionBase
{
public:
    HyperDbgSessionBase();
    virtual ~HyperDbgSessionBase();

    HyperDbgSessionBase(const HyperDbgSessionBase&) = delete;
    HyperDbgSessionBase& operator=(const HyperDbgSessionBase&) = delete;

    std::string Run(std::string command);
    void SetTeeStdout(bool on) { TeeStdout = on; }
    void SetBufferingEnabled(bool on) { BufferingEnabled = on; }

    using MessageHandler = std::function<void(const char*)>;
    void SetMessageHandler(MessageHandler h);

protected:
    void LoadLibraryAndResolveExports(const std::filesystem::path& hyperdbgdir);
    void FreeLibraryIfLoaded();

    static int __cdecl MessageThunk(const char* msg);

    HMODULE Dll;

    PFN_DetectVmx DetectVmxFn;
    PFN_SetDriverPath SetDriverPathFn;
    PFN_InstallKd InstallKdFn;
    PFN_UninstallKd UninstallKdFn;
    PFN_StopKd StopKdFn;
    PFN_LoadVmm LoadVmmFn;
    PFN_UnloadVmm UnloadVmmFn;
    PFN_UnloadKd UnloadKdFn;
    PFN_RunCommand RunCommandFn;
    PFN_SetMsgCallback SetMsgCallbackFn;
    PFN_ReadMemory ReadMemoryFn;

private:
    static HyperDbgSessionBase* ActiveSink;

    mutable std::mutex BufMutex;
    std::string OutputBuffer;
    bool TeeStdout;
    bool BufferingEnabled = true;

    mutable std::mutex HandlerMutex;
    MessageHandler ExtraHandler;
};