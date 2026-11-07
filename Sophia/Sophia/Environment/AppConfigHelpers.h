#pragma once
#include "AppConfig.h"
#include <cctype>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <system_error>
#include <windows.h>

class AppConfigHelpers
{
public:
    static constexpr const char* HyperDbgPathKey = "hyperdbg_path";
    static constexpr const char* CliBinary = "hyperdbg-cli.exe";
    static constexpr const wchar_t* CliBinaryW = L"hyperdbg-cli.exe";
    static constexpr const wchar_t* ConfigName = L"Sophia_Environment.cfg";

    static std::filesystem::path ExeDir()
    {
        wchar_t buf[MAX_PATH]{};
        DWORD n = GetModuleFileNameW(nullptr, buf, MAX_PATH);
        if (n == 0 || n == MAX_PATH)
        {
            return std::filesystem::current_path();
        }
        return std::filesystem::path(buf).parent_path();
    }

    static void Trim(std::string& s)
    {
        auto ws = [](unsigned char c)
            {
                return std::isspace(c) != 0;
            };
        while (!s.empty() && ws(static_cast<unsigned char>(s.front())))
        {
            s.erase(s.begin());
        }
        while (!s.empty() && ws(static_cast<unsigned char>(s.back())))
        {
            s.pop_back();
        }
    }

    static std::string ReadLineTrimmed()
    {
        std::string s;
        if (!std::getline(std::cin, s))
        {
            throw std::runtime_error("stdin closed while asking for HyperDbg path");
        }
        Trim(s);
        if (s.size() >= 2 && s.front() == '"' && s.back() == '"')
        {
            s = s.substr(1, s.size() - 2);
        }
        return s;
    }

    static bool ValidHyperDbgFolder(const std::filesystem::path& p)
    {
        if (p.empty())
        {
            return false;
        }
        std::error_code ec;
        if (!std::filesystem::is_directory(p, ec))
        {
            return false;
        }
        return std::filesystem::is_regular_file(p / CliBinaryW, ec);
    }

    static std::filesystem::path LoadStoredPath()
    {
        std::ifstream in(AppConfig::FilePath());
        if (!in)
        {
            return {};
        }
        std::string line;
        while (std::getline(in, line))
        {
            Trim(line);
            if (line.empty() || line.front() == '#')
            {
                continue;
            }
            auto eq = line.find('=');
            if (eq == std::string::npos)
            {
                continue;
            }
            std::string key = line.substr(0, eq);
            std::string value = line.substr(eq + 1);
            Trim(key);
            Trim(value);
            if (value.size() >= 2 && value.front() == '"' && value.back() == '"')
            {
                value = value.substr(1, value.size() - 2);
            }
            if (key == HyperDbgPathKey && !value.empty())
            {
                return std::filesystem::path(value);
            }
        }
        return {};
    }

    static bool SaveStoredPath(const std::filesystem::path& p)
    {
        std::ofstream out(AppConfig::FilePath(), std::ios::trunc);
        if (!out)
        {
            return false;
        }
        out << HyperDbgPathKey << '=' << p.string() << '\n';
        return static_cast<bool>(out);
    }
};