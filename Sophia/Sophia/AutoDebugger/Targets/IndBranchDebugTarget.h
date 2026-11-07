#pragma once

#include "DebugTarget.h"

#include <cstdio>

class IndBranchDebugTarget : public DebugTarget
{
public:
    SiteKind Kind() const override
    {
        return SiteKind::IndBranch;
    }

    void EmitPayload(std::string& payload, const InsnSite& site, const std::string& basebuf, bool capturecallparams, bool capturestackargs) const override
    {
        (void)capturecallparams;
        (void)capturestackargs;
        std::string tgtexpr;
        bool tgtismem = false;
        std::string tgtea;
        if (site.Reg[0])
        {
            tgtexpr = "@";
            tgtexpr += site.Reg;
        }
        else if (site.Mem.Present)
        {
            const std::string ea = BuildEaExpr(site.Mem, site.Va, site.Length);
            if (ea.empty())
            {
                return;
            }
            tgtexpr = "dq(" + ea + ")";
            tgtea = ea;
            tgtismem = true;
        }
        else
        {
            return;
        }

        char va[24];
        std::snprintf(va, sizeof(va), "0x%llx", static_cast<unsigned long long>(site.Va));
        payload += " if ($context == ";
        payload += va;
        payload += ") { ";
        if (tgtismem)
        {
            payload += "if (check_address(";
            payload += tgtea;
            payload += ") != 0) { ";
        }
        payload += "printf(\"[autodbg-ind] rva=%llx tgt=%llx\\n\", $context - ";
        payload += basebuf;
        payload += ", ";
        payload += tgtexpr;
        payload += " - ";
        payload += basebuf;
        payload += ");";
        if (tgtismem)
        {
            payload += " }";
        }
        payload += " }";
    }
};