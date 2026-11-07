#pragma once

#include "DebugTarget.h"
#include "../AutoDebugUtils.h"

#include <cstdio>

class MovDebugTarget : public DebugTarget
{
public:
    SiteKind Kind() const override
    {
        return SiteKind::Mov;
    }

    void EmitPayload(std::string& payload, const InsnSite& site, const std::string& basebuf, bool capturecallparams, bool capturestackargs) const override
    {
        (void)capturecallparams;
        (void)capturestackargs;
        if (!site.Mem.Present || !site.Mem.Read)
        {
            return;
        }
        const std::string ea = BuildEaExpr(site.Mem, site.Va, site.Length);
        if (ea.empty())
        {
            return;
        }

        char va[24];
        std::snprintf(va, sizeof(va), "0x%llx", static_cast<unsigned long long>(site.Va));
        char wtag[24];
        std::snprintf(wtag, sizeof(wtag), "w=%u", static_cast<unsigned>(site.Mem.Width));
        payload += " if ($context == ";
        payload += va;
        payload += ") { printf(\"[autodbg-mov] rva=%llx ";
        payload += wtag;
        payload += " val=%llx\\n\", $context - ";
        payload += basebuf;
        payload += ", ";
        payload += AutoDebugUtils::WidthReader(site.Mem.Width);
        payload += "(" + ea + ")); }";
    }
};