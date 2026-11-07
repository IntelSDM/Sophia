#pragma once

#include "DebugTarget.h"

class CallDebugTarget : public DebugTarget
{
public:
    SiteKind Kind() const override
    {
        return SiteKind::Call;
    }

    void EmitPayload(std::string& payload, const InsnSite& site, const std::string& basebuf, bool capturecallparams, bool capturestackargs) const override
    {
        if (!capturecallparams)
        {
            return;
        }
        EmitCallArgClauses(payload, site, basebuf, capturestackargs);
    }

    bool WantsPhantomRet(bool capturereturns) const override
    {
        return capturereturns;
    }

    void EmitPhantomPayload(std::string& payload, const InsnSite& site, uint64_t retva) const override
    {
        EmitPhantomRetClauses(payload, retva, site.Rva);
    }
};