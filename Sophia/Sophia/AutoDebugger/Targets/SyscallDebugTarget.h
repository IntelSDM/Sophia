#pragma once

#include "DebugTarget.h"

class SyscallDebugTarget : public DebugTarget
{
public:
    SiteKind Kind() const override
    {
        return SiteKind::Syscall;
    }

    void EmitPayload(std::string& payload, const InsnSite& site, const std::string& basebuf, bool capturecallparams, bool capturestackargs) const override
    {
        (void)capturecallparams;
        EmitSyscallArgClauses(payload, site, basebuf, capturestackargs);
    }

    bool WantsPhantomRet(bool capturereturns) const override
    {
        (void)capturereturns;
        return true;
    }

    void EmitPhantomPayload(std::string& payload, const InsnSite& site, uint64_t retva) const override
    {
        EmitPhantomRetClauses(payload, retva, site.Rva);
    }
};