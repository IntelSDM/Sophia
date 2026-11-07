#pragma once

#include "../DeobfuscationTarget.h"

class LeaConstTarget : public DeobfuscationTarget
{
public:
    const char* Name() const override { return "Constant LEA"; }
    bool Enabled(const DeobfConfig& cfg) const override { return cfg.WantLea; }
    void Deobfuscate(DeobfContext& ctx, Deobfuscator::Report& r) override;
};