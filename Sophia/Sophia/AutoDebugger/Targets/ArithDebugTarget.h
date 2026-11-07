#pragma once

#include "DebugTarget.h"
#include "../AutoDebugUtils.h"

#include <cstdio>

class ArithDebugTarget : public DebugTarget
{
public:
    SiteKind Kind() const override
    {
        return SiteKind::Arith;
    }

    void EmitPayload(std::string& payload, const InsnSite& site, const std::string& basebuf, bool capturecallparams, bool capturestackargs) const override
    {
        (void)capturecallparams;
        (void)capturestackargs;
        const bool hasreg = site.Reg[0] != 0;
        const bool hasreg2 = site.Reg2[0] != 0;
        bool hasmem = site.Mem.Present && site.Mem.Read;
        std::string ea;
        if (hasmem)
        {
            ea = BuildEaExpr(site.Mem, site.Va, site.Length);
            if (ea.empty())
            {
                hasmem = false;
            }
        }
        if (!hasreg && !hasreg2 && !hasmem)
        {
            return;
        }

        char va[24];
        std::snprintf(va, sizeof(va), "0x%llx", static_cast<unsigned long long>(site.Va));
        payload += " if ($context == ";
        payload += va;
        payload += ") { printf(\"[autodbg-ari] rva=%llx";
        if (hasreg)
        {
            payload += " reg=";
            payload += site.Reg;
            payload += " rval=%llx";
        }
        if (hasreg2)
        {
            payload += " reg2=";
            payload += site.Reg2;
            payload += " rval2=%llx";
        }
        if (hasmem)
        {
            char wtag[24];
            std::snprintf(wtag, sizeof(wtag), " w=%u", static_cast<unsigned>(site.Mem.Width));
            payload += wtag;
            payload += " mval=%llx";
        }
        if (site.HasImm)
        {
            char im[32];
            std::snprintf(im, sizeof(im), " imm=0x%llx", static_cast<unsigned long long>(site.Imm));
            payload += im;
        }
        payload += "\\n\", $context - ";
        payload += basebuf;
        if (hasreg)
        {
            payload += ", @";
            payload += site.Reg;
        }
        if (hasreg2)
        {
            payload += ", @";
            payload += site.Reg2;
        }
        if (hasmem)
        {
            payload += ", ";
            payload += AutoDebugUtils::WidthReader(site.Mem.Width);
            payload += "(" + ea + ")";
        }
        payload += "); }";
    }
};