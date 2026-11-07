#pragma once

#include "../DeobfuscationTarget.h"

class ArithConstTarget : public DeobfuscationTarget
{
public:
    const char* Name() const override { return "Constant Arith"; }
    bool Enabled(const DeobfConfig& cfg) const override { return cfg.WantArith; }
    void Deobfuscate(DeobfContext& ctx, Deobfuscator::Report& r) override;
};