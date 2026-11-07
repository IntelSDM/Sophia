#pragma once
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cwctype>
#include <filesystem>
#include <initializer_list>
#include <iostream>
#include <string>
#include <windows.h>

class CliHelpers
{
public:
    static std::string ReadLineTrimmed()
    {
        std::string s;
        std::getline(std::cin, s);
        auto isws = [](unsigned char c)
            {
                return std::isspace(c) != 0;
            };
        while (!s.empty() && isws(static_cast<unsigned char>(s.front())))
        {
            s.erase(s.begin());
        }
        while (!s.empty() && isws(static_cast<unsigned char>(s.back())))
        {
            s.pop_back();
        }
        if (s.size() >= 2 && s.front() == '"' && s.back() == '"')
        {
            s = s.substr(1, s.size() - 2);
        }
        return s;
    }

    static int PromptChoice(const char* title, std::initializer_list<const char*> opts)
    {
        for (;;)
        {
            std::printf("\n%s\n", title);
            int i = 1;
            for (const char* o : opts)
            {
                std::printf("  %d) %s\n", i++, o);
            }
            std::printf("> ");
            std::fflush(stdout);
            std::string line = ReadLineTrimmed();
            try
            {
                int choice = std::stoi(line);
                if (choice >= 1 && choice <= static_cast<int>(opts.size()))
                {
                    return choice;
                }
            }
            catch (...)
            {
            }
            std::printf("[!] enter a number 1-%zu\n", opts.size());
        }
    }

    static std::string PromptNonEmpty(const char* prompt)
    {
        for (;;)
        {
            std::printf("%s", prompt);
            std::fflush(stdout);
            std::string s = ReadLineTrimmed();
            if (!s.empty())
            {
                return s;
            }
            std::printf("[!] value required\n");
        }
    }

    static bool PromptYesNo(const char* question, bool dflt)
    {
        std::printf("%s [%s] ", question, dflt ? "y/n" : "y/n");
        std::fflush(stdout);
        std::string s = ReadLineTrimmed();
        if (s.empty())
        {
            return dflt;
        }
        char c = static_cast<char>(std::tolower(static_cast<unsigned char>(s.front())));
        return c == 'y';
    }

    static std::wstring LowerW(std::wstring s)
    {
        for (auto& c : s)
        {
            c = static_cast<wchar_t>(std::towlower(c));
        }
        return s;
    }

    static std::wstring StemW(std::wstring s)
    {
        size_t dot = s.find_last_of(L'.');
        return (dot == std::wstring::npos) ? s : s.substr(0, dot);
    }

    static bool DriverNameMatches(const std::wstring& basename, std::wstring querylower)
    {
        const std::wstring bn = LowerW(basename);
        if (bn == querylower)
        {
            return true;
        }
        if (querylower == L"nt")
        {
            querylower = L"ntoskrnl";
        }
        return StemW(bn) == StemW(querylower);
    }

    static std::wstring Widen(const std::string& s)
    {
        if (s.empty())
        {
            return {};
        }
        int n = MultiByteToWideChar(CP_ACP, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
        std::wstring w(static_cast<size_t>(n), L'\0');
        MultiByteToWideChar(CP_ACP, 0, s.data(), static_cast<int>(s.size()), w.data(), n);
        return w;
    }

    static bool LaunchProcess(const std::string& exepath, HANDLE& hprocess, uint32_t& pid)
    {
        std::wstring wexe = Widen(exepath);
        std::wstring cmd = L"\"" + wexe + L"\"";
        std::wstring cwd = std::filesystem::path(wexe).parent_path().wstring();
        STARTUPINFOW si{};
        si.cb = sizeof(si);
        PROCESS_INFORMATION pi{};
        BOOL ok = CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, FALSE, 0, nullptr, cwd.empty() ? nullptr : cwd.c_str(), &si, &pi);
        if (!ok)
        {
            return false;
        }
        CloseHandle(pi.hThread);
        hprocess = pi.hProcess;
        pid = pi.dwProcessId;
        return true;
    }
};