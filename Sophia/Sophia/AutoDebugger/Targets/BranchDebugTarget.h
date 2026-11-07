#pragma once

#include "DebugTarget.h"

class BranchDebugTarget : public DebugTarget
{
public:
    SiteKind Kind() const override
    {
        return SiteKind::Branch;
    }

    void EmitPayload(std::string& payload, const InsnSite& site, const std::string& basebuf, bool capturecallparams, bool capturestackargs) const override
    {
        (void)payload;
        (void)site;
        (void)basebuf;
        (void)capturecallparams;
        (void)capturestackargs;
    }
};