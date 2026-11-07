#pragma once

#include "../DeobfuscationTarget.h"

class MovConstTarget : public DeobfuscationTarget
{
public:
    const char* Name() const override { return "Constant MOV"; }
    bool Enabled(const DeobfConfig& cfg) const override { return cfg.WantMov; }
    void Deobfuscate(DeobfContext& ctx, Deobfuscator::Report& r) override;
};