#pragma once

#include "../DeobfuscationTarget.h"

class IndBranchTarget : public DeobfuscationTarget
{
public:
    const char* Name() const override { return "ControlFlow IndirectBranch"; }
    bool Enabled(const DeobfConfig& cfg) const override { return cfg.WantIndBranch || cfg.WantIndCall; }
    void Deobfuscate(DeobfContext& ctx, Deobfuscator::Report& r) override;
};