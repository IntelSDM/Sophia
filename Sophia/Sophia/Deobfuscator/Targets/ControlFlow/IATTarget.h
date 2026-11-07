#pragma once

#include "../DeobfuscationTarget.h"

class IatTarget : public DeobfuscationTarget
{
public:
    const char* Name() const override { return "ControlFlow IAT"; }
    bool Enabled(const DeobfConfig& cfg) const override { return cfg.WantIndCall; }
    void Deobfuscate(DeobfContext& ctx, Deobfuscator::Report& r) override;
};