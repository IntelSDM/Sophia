#include "../../Pch.h"
#include "AppConfig.h"
#include "AppConfigHelpers.h"

std::filesystem::path AppConfig::FilePath()
{
    return AppConfigHelpers::ExeDir() / AppConfigHelpers::ConfigName;
}

std::filesystem::path AppConfig::EnsureHyperDbgPath()
{
    std::filesystem::path stored = AppConfigHelpers::LoadStoredPath();
    if (AppConfigHelpers::ValidHyperDbgFolder(stored))
    {
        std::printf("[+] HyperDbg install: %ls\n", stored.wstring().c_str());
        return stored;
    }
    if (stored.empty())
    {
        std::printf("[i] no HyperDbg install configured -- one-time setup.\n");
    }
    else
    {
        std::printf("[!] stored HyperDbg path no longer valid (missing %s):\n    %ls\n", AppConfigHelpers::CliBinary, stored.wstring().c_str());
    }
    for (;;)
    {
        std::printf("HyperDbg install folder (must contain %s): ", AppConfigHelpers::CliBinary);
        std::fflush(stdout);
        std::string entered = AppConfigHelpers::ReadLineTrimmed();
        if (entered.empty())
        {
            std::printf("[!] path required\n");
            continue;
        }
        std::filesystem::path p(entered);
        if (!AppConfigHelpers::ValidHyperDbgFolder(p))
        {
            std::printf("[!] %s not found under that folder -- try again\n", AppConfigHelpers::CliBinary);
            continue;
        }
        if (AppConfigHelpers::SaveStoredPath(p))
        {
            std::printf("[+] saved HyperDbg path to %ls\n", FilePath().wstring().c_str());
        }
        else
        {
            std::fprintf(stderr, "[!] failed to write %ls -- using the entered path for this run only\n", FilePath().wstring().c_str());
        }
        return p;
    }
}