#include "pch.h"
#include "Sophia/Environment/AppConfig.h"
#include "Sophia/DumpTool.h"

#include <cstdio>
#include <iostream>
#pragma comment(lib, "zydis.lib") 



int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int nCmdShow)
{
    AllocConsole();
    FILE* fdummy;
    freopen_s(&fdummy, "CONIN$", "r", stdin);
    freopen_s(&fdummy, "CONOUT$", "w", stderr);
    freopen_s(&fdummy, "CONOUT$", "w", stdout);

    try
    {
        DumpTool::Config cfg;
        cfg.HyperDbgPath = AppConfig::EnsureHyperDbgPath();
        DumpTool tool(std::move(cfg));
        tool.RunInteractive();
    }
    catch (const std::exception& ex)
    {
        std::fprintf(stderr, "fatal: %s\n", ex.what());
        std::cin.get();
        return 1;
    }
    return 0;
}