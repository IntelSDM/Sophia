#pragma once
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <string>
#include <utility>
#include <vector>

class PtParseUtil
{
public:
    static std::pair<uint64_t, const char*> ParseHex(const char* s, const char* end)
    {
        uint64_t v = 0;
        const char* p = s;
        while (p < end)
        {
            char c = *p;
            uint32_t d;
            if (c >= '0' && c <= '9') d = c - '0';
            else if (c >= 'a' && c <= 'f') d = 10 + (c - 'a');
            else if (c >= 'A' && c <= 'F') d = 10 + (c - 'A');
            else break;
            v = (v << 4) | d;
            ++p;
        }
        return { v, p };
    }

    static const char* SkipSpace(const char* s, const char* end)
    {
        while (s < end && (*s == ' ' || *s == '\t')) ++s;
        return s;
    }

    static const char* SkipHexPrefix(const char* s, const char* end)
    {
        if (s + 1 < end && s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
        {
            return s + 2;
        }
        return s;
    }

    static void EmitHexArray(std::ofstream& out, const std::vector<uint64_t>& sorted)
    {
        char buf[32];
        for (size_t i = 0; i < sorted.size(); ++i)
        {
            int n = std::snprintf(buf, sizeof(buf), (i == 0) ? "\"0x%llx\"" : ", \"0x%llx\"", static_cast<unsigned long long>(sorted[i]));
            out.write(buf, n);
        }
    }

    static void EmitCsvMnemonic(std::ofstream& out, const std::string& s)
    {
        bool needsquote = false;
        for (char c : s)
        {
            if (c == ',' || c == '"' || c == '\n' || c == '\r')
            {
                needsquote = true;
                break;
            }
        }
        if (!needsquote)
        {
            out.write(s.data(), static_cast<std::streamsize>(s.size()));
            return;
        }
        out.put('"');
        for (char c : s)
        {
            if (c == '"') out.put('"');
            out.put(c);
        }
        out.put('"');
    }
};