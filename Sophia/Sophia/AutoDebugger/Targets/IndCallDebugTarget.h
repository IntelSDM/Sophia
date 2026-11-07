#pragma once

#include "DebugTarget.h"
#include "IndBranchDebugTarget.h"

class IndCallDebugTarget : public DebugTarget
{
public:
    SiteKind Kind() const override
    {
        return SiteKind::IndCall;
    }

    void EmitPayload(std::string& payload, const InsnSite& site, const std::string& basebuf, bool capturecallparams, bool capturestackargs) const override
    {
        IndBranchDebugTarget branchemit;
        branchemit.EmitPayload(payload, site, basebuf, capturecallparams, capturestackargs);

        if (capturecallparams)
        {
            EmitCallArgClauses(payload, site, basebuf, capturestackargs);
        }
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