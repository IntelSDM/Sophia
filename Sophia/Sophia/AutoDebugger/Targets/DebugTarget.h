#pragma once

#include "../../WinPE/PEScan.h"

#include <cstdint>
#include <string>

class DebugTarget
{
public:
    virtual ~DebugTarget() = default;

    virtual SiteKind Kind() const = 0;

    virtual void EmitPayload(std::string& payload, const InsnSite& site, const std::string& basebuf, bool capturecallparams, bool capturestackargs) const = 0;

    virtual bool WantsPhantomRet(bool capturereturns) const
    {
        (void)capturereturns;
        return false;
    }

    virtual void EmitPhantomPayload(std::string& payload, const InsnSite& site, uint64_t retva) const
    {
        (void)payload;
        (void)site;
        (void)retva;
    }

protected:
    static std::string BuildEaExpr(const MemOperand& m, uint64_t siteva, uint32_t len);
    static void EmitCallArgClauses(std::string& payload, const InsnSite& site, const std::string& basebuf, bool capturestackargs);
    static void EmitSyscallArgClauses(std::string& payload, const InsnSite& site, const std::string& basebuf, bool capturestackargs);
    static void EmitPhantomRetClauses(std::string& payload, uint64_t retva, uint64_t callsiterva);
};