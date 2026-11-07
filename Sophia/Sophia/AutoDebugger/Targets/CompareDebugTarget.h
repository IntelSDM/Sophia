#pragma once

#include "DebugTarget.h"
#include "../AutoDebugUtils.h"

#include <cstdio>
#include <cstring>

class CompareDebugTarget : public DebugTarget
{
public:
    SiteKind Kind() const override
    {
        return SiteKind::Compare;
    }

    void EmitPayload(std::string& payload, const InsnSite& site, const std::string& basebuf, bool capturecallparams, bool capturestackargs) const override
    {
        (void)capturecallparams;
        (void)capturestackargs;
        if (!site.Mem.Present)
        {
            return;
        }
        if (std::strncmp(site.Mnemonic, "set", 3) == 0)
        {
            return;
        }
        const std::string ea = BuildEaExpr(site.Mem, site.Va, site.Length);
        if (ea.empty())
        {
            return;
        }

        char guard[48];
        std::snprintf(guard, sizeof(guard), " if ($context == 0x%llx) { printf(", static_cast<unsigned long long>(site.Va));
        payload += guard;

        if (site.Mem.Width == 16)
        {
            payload += "\"[autodbg-mem] rva=%llx w=16 lo=%llx hi=%llx\\n\", $context - ";
            payload += basebuf;
            payload += ", dq(" + ea + "), dq(" + ea + " + 8)); }";
        }
        else
        {
            char wtag[24];
            std::snprintf(wtag, sizeof(wtag), "w=%u", site.Mem.Width);
            payload += "\"[autodbg-mem] rva=%llx ";
            payload += wtag;
            payload += " val=%llx\\n\", $context - ";
            payload += basebuf;
            payload += ", ";
            payload += AutoDebugUtils::WidthReader(site.Mem.Width);
            payload += "(" + ea + ")); }";
        }
    }
};