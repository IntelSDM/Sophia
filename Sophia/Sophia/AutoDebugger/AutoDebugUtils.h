#pragma once

#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cwctype>
#include <initializer_list>
#include <iostream>
#include <string>
#include <vector>

class AutoDebugUtils
{
public:
    static constexpr int StrWindowQwords = 8;
    static constexpr int VecWindowQwordCap = 4;

    struct StrReads
    {
        bool Rsi;
        bool Rdi;
    };

    static bool ResponseHasError(const std::string& r)
    {
        return r.find("err") != std::string::npos
            || r.find("Err") != std::string::npos
            || r.find("invalid") != std::string::npos
            || r.find("failed") != std::string::npos;
    }

    static bool IsAlnumOrUnderscore(char c)
    {
        return (c >= 'a' && c <= 'z')
            || (c >= 'A' && c <= 'Z')
            || (c >= '0' && c <= '9')
            || c == '_';
    }

    static const char* WidthReader(uint16_t wbytes)
    {
        switch (wbytes)
        {
        case 1:
            return "db";
        case 2:
            return "dw";
        case 4:
            return "dd";
        case 8:
            return "dq";
        default:
            return "dq";
        }
    }

    static StrReads StringReads(const char* mstr)
    {
        if (std::strncmp(mstr, "movs", 4) == 0)
        {
            return { true, false };
        }
        if (std::strncmp(mstr, "lods", 4) == 0)
        {
            return { true, false };
        }
        if (std::strncmp(mstr, "scas", 4) == 0)
        {
            return { false, true };
        }
        if (std::strncmp(mstr, "cmps", 4) == 0)
        {
            return { true, true };
        }
        return { false, false };
    }

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
            s.erase(s.begin());
            s.pop_back();
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
            const std::string line = ReadLineTrimmed();
            try
            {
                const int choice = std::stoi(line);
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

    static bool PromptYesNo(const char* prompt, bool defaultyes)
    {
        std::printf("%s", prompt);
        std::fflush(stdout);
        const std::string s = ReadLineTrimmed();
        if (s.empty())
        {
            return defaultyes;
        }
        const char c = static_cast<char>(std::tolower(static_cast<unsigned char>(s.front())));
        if (c == 'y')
        {
            return true;
        }
        if (c == 'n')
        {
            return false;
        }
        return defaultyes;
    }

    static std::vector<std::string> SplitCsv(const std::string& in)
    {
        std::vector<std::string> out;
        std::string cur;
        auto flush = [&]()
            {
                while (!cur.empty() && std::isspace(static_cast<unsigned char>(cur.front())))
                {
                    cur.erase(cur.begin());
                }
                while (!cur.empty() && std::isspace(static_cast<unsigned char>(cur.back())))
                {
                    cur.pop_back();
                }
                if (!cur.empty())
                {
                    out.push_back(cur);
                }
                cur.clear();
            };
        for (char c : in)
        {
            if (c == ',')
            {
                flush();
            }
            else
            {
                cur.push_back(c);
            }
        }
        flush();
        return out;
    }

    static bool ParseHex64(const std::string& s, uint64_t& out)
    {
        if (s.empty())
        {
            return false;
        }
        size_t i = 0;
        if (s.size() >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
        {
            i = 2;
        }
        if (i >= s.size())
        {
            return false;
        }
        uint64_t v = 0;
        for (; i < s.size(); ++i)
        {
            const char c = s[i];
            uint64_t d;
            if (c >= '0' && c <= '9')
            {
                d = static_cast<uint64_t>(c - '0');
            }
            else if (c >= 'a' && c <= 'f')
            {
                d = static_cast<uint64_t>(c - 'a' + 10);
            }
            else if (c >= 'A' && c <= 'F')
            {
                d = static_cast<uint64_t>(c - 'A' + 10);
            }
            else
            {
                return false;
            }
            v = (v << 4) | d;
        }
        out = v;
        return true;
    }

    static std::wstring ToLowerW(std::wstring s)
    {
        for (auto& c : s)
        {
            c = static_cast<wchar_t>(std::towlower(c));
        }
        return s;
    }

    static std::wstring StemW(std::wstring s)
    {
        const size_t dot = s.find_last_of(L'.');
        return (dot == std::wstring::npos) ? s : s.substr(0, dot);
    }
};