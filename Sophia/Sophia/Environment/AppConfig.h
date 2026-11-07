#pragma once
#include <filesystem>

class AppConfig
{
public:
    static std::filesystem::path FilePath();
    static std::filesystem::path EnsureHyperDbgPath();
};