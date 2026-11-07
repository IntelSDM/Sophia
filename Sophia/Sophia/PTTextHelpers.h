#pragma once
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <set>
#include <string>
#include <vector>

class PtTextHelpers
{
public:
    static std::string FirstToken(const std::string& m)
    {
        size_t i = 0;
        while (i < m.size() && (m[i] == ' ' || m[i] == '\t'))
        {
            ++i;
        }
        size_t s = i;
        while (i < m.size() && m[i] != ' ' && m[i] != '\t')
        {
            ++i;
        }
        std::string t = m.substr(s, i - s);
        for (auto& c : t)
        {
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        }
        return t;
    }

    static bool IsBranch(const std::string& tok)
    {
        static const std::set<std::string> b =
        {
            "jmp", "call",
            "je", "jz", "jne", "jnz", "ja", "jae", "jb", "jbe", "jc", "jnc",
            "jg", "jge", "jl", "jle", "jo", "jno", "js", "jns", "jp", "jnp",
            "jpe", "jpo", "jcxz", "jecxz", "jrcxz",
            "loop", "loope", "loopne", "loopz", "loopnz"
        };
        return b.count(tok) != 0;
    }

    static bool IsIndirectBranch(const std::string& tok)
    {
        return tok == "jmp" || tok == "call";
    }

    static bool FindBareAbsMem(const std::string& m, uint64_t& val, size_t& lb, size_t& rb)
    {
        size_t open = m.find('[');
        while (open != std::string::npos)
        {
            size_t close = m.find(']', open + 1);
            if (close == std::string::npos)
            {
                return false;
            }
            size_t i = open + 1;
            while (i < close && (m[i] == ' ' || m[i] == '\t'))
            {
                ++i;
            }
            if (i + 1 < close && m[i] == '0' && (m[i + 1] == 'x' || m[i + 1] == 'X'))
            {
                size_t j = i + 2;
                uint64_t v = 0;
                bool any = false;
                while (j < close)
                {
                    char c = m[j];
                    int d;
                    if (c >= '0' && c <= '9')
                    {
                        d = c - '0';
                    }
                    else if (c >= 'a' && c <= 'f')
                    {
                        d = c - 'a' + 10;
                    }
                    else if (c >= 'A' && c <= 'F')
                    {
                        d = c - 'A' + 10;
                    }
                    else
                    {
                        break;
                    }
                    v = (v << 4) | d;
                    any = true;
                    ++j;
                }
                size_t k = j;
                while (k < close && (m[k] == ' ' || m[k] == '\t'))
                {
                    ++k;
                }
                if (any && k == close)
                {
                    val = v;
                    lb = open;
                    rb = close;
                    return true;
                }
            }
            open = m.find('[', open + 1);
        }
        return false;
    }

    static std::string ReplaceBracket(const std::string& m, size_t lb, size_t rb, const std::string& inner)
    {
        return m.substr(0, lb) + "[" + inner + "]" + m.substr(rb + 1);
    }

    static std::string RipInner(int64_t disp)
    {
        char rep[48];
        if (disp >= 0)
        {
            std::snprintf(rep, sizeof(rep), "rip + 0x%llx", static_cast<unsigned long long>(disp));
        }
        else
        {
            std::snprintf(rep, sizeof(rep), "rip - 0x%llx", static_cast<unsigned long long>(-disp));
        }
        return rep;
    }

    static std::vector<uint8_t> CanonicalNop(uint32_t n)
    {
        static const std::vector<std::vector<uint8_t>> t =
        {
            {},
            {0x90},
            {0x66,0x90},
            {0x0f,0x1f,0x00},
            {0x0f,0x1f,0x40,0x00},
            {0x0f,0x1f,0x44,0x00,0x00},
            {0x66,0x0f,0x1f,0x44,0x00,0x00},
            {0x0f,0x1f,0x80,0x00,0x00,0x00,0x00},
            {0x0f,0x1f,0x84,0x00,0x00,0x00,0x00,0x00},
            {0x66,0x0f,0x1f,0x84,0x00,0x00,0x00,0x00,0x00},
        };
        std::vector<uint8_t> out;
        if (n == 0)
        {
            return out;
        }
        while (n > 0)
        {
            uint32_t k = (n >= 9) ? 9 : n;
            out.insert(out.end(), t[k].begin(), t[k].end());
            n -= k;
        }
        return out;
    }

    static bool PlausiblePointer(uint64_t p)
    {
        if (p == 0)
        {
            return false;
        }
        if (p < 0x10000)
        {
            return false;
        }
        if (p < 0x0000800000000000ULL)
        {
            return true;
        }
        if (p >= 0xFFFF800000000000ULL)
        {
            return true;
        }
        return false;
    }
};