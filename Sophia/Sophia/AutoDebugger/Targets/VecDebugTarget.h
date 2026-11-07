#pragma once

#include "DebugTarget.h"
#include "../AutoDebugUtils.h"

#include <cstdio>

class VecDebugTarget : public DebugTarget
{
public:
    SiteKind Kind() const override
    {
        return SiteKind::VecMove;
    }

    void EmitPayload(std::string& payload, const InsnSite& site, const std::string& basebuf, bool capturecallparams, bool capturestackargs) const override
    {
        (void)capturecallparams;
        (void)capturestackargs;
        if (!site.Mem.Present)
        {
            return;
        }
        const std::string ea = BuildEaExpr(site.Mem, site.Va, site.Length);
        if (ea.empty())
        {
            return;
        }
        int qw = site.Mem.Width / 8;
        if (qw < 1)
        {
            return;
        }
        if (qw > AutoDebugUtils::VecWindowQwordCap)
        {
            qw = AutoDebugUtils::VecWindowQwordCap;
        }

        char va[24];
        std::snprintf(va, sizeof(va), "0x%llx", static_cast<unsigned long long>(site.Va));
        char wtag[24];
        std::snprintf(wtag, sizeof(wtag), "w=%u", static_cast<unsigned>(site.Mem.Width));
        payload += " if ($context == ";
        payload += va;
        payload += ") { printf(\"[autodbg-vec] rva=%llx ";
        payload += wtag;
        for (int k = 0; k < qw; ++k)
        {
            char v[12];
            std::snprintf(v, sizeof(v), " v%d=%%llx", k);
            payload += v;
        }
        payload += "\\n\", $context - ";
        payload += basebuf;
        for (int k = 0; k < qw; ++k)
        {
            if (k == 0)
            {
                payload += ", dq(" + ea + ")";
            }
            else
            {
                char off[16];
                std::snprintf(off, sizeof(off), " + %d", k * 8);
                payload += ", dq(" + ea + off + ")";
            }
        }
        payload += "); }";
    }
};