#pragma once

#include "DebugTarget.h"

#include <cstdio>

class LeaDebugTarget : public DebugTarget
{
public:
    SiteKind Kind() const override
    {
        return SiteKind::Lea;
    }

    void EmitPayload(std::string& payload, const InsnSite& site, const std::string& basebuf, bool capturecallparams, bool capturestackargs) const override
    {
        (void)capturecallparams;
        (void)capturestackargs;
        if (!site.Mem.Present)
        {
            return;
        }
        if (site.Mem.RipRel)
        {
            return;
        }
        if (site.Mem.Base[0] == 0 && site.Mem.Index[0] == 0)
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
        payload += " if ($context == ";
        payload += va;
        payload += ") { printf(\"[autodbg-lea] rva=%llx ea=%llx\\n\", $context - ";
        payload += basebuf;
        payload += ", (";
        payload += ea;
        payload += ") - ";
        payload += basebuf;
        payload += "); }";
    }
};