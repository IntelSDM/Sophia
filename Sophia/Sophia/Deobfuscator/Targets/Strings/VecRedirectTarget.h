#pragma once

#include "../DeobfuscationTarget.h"

class VecRedirectTarget : public DeobfuscationTarget
{
public:
    const char* Name() const override { return "String Vec"; }
    bool Enabled(const DeobfConfig& cfg) const override { return cfg.WantString; }
    void Deobfuscate(DeobfContext& ctx, Deobfuscator::Report& r) override;
};