#pragma once

#include "DebugTarget.h"
#include "../AutoDebugUtils.h"

#include <cstdio>

class StringDebugTarget : public DebugTarget
{
public:
    SiteKind Kind() const override
    {
        return SiteKind::String;
    }

    void EmitPayload(std::string& payload, const InsnSite& site, const std::string& basebuf, bool capturecallparams, bool capturestackargs) const override
    {
        (void)capturecallparams;
        (void)capturestackargs;
        const AutoDebugUtils::StrReads r = AutoDebugUtils::StringReads(site.Mnemonic);
        if (r.Rsi)
        {
            EmitWindow(payload, site, basebuf, "rsi");
        }
        if (r.Rdi)
        {
            EmitWindow(payload, site, basebuf, "rdi");
        }
    }

private:
    static void EmitWindow(std::string& out, const InsnSite& site, const std::string& basebuf, const char* ptr)
    {
        char va[24];
        std::snprintf(va, sizeof(va), "0x%llx", static_cast<unsigned long long>(site.Va));
        out += " if ($context == ";
        out += va;
        out += ") { printf(\"[autodbg-str] rva=%llx ptr=";
        out += ptr;
        out += " addr=%llx len=%llx";
        for (int k = 0; k < AutoDebugUtils::StrWindowQwords; ++k)
        {
            char b[16];
            std::snprintf(b, sizeof(b), " b%d=%%llx", k);
            out += b;
        }
        out += "\\n\", $context - ";
        out += basebuf;
        out += ", @";
        out += ptr;
        out += ", @rcx";
        for (int k = 0; k < AutoDebugUtils::StrWindowQwords; ++k)
        {
            char a[32];
            if (k == 0)
            {
                std::snprintf(a, sizeof(a), ", dq(@%s)", ptr);
            }
            else
            {
                std::snprintf(a, sizeof(a), ", dq(@%s + %d)", ptr, k * 8);
            }
            out += a;
        }
        out += "); }";
    }
};