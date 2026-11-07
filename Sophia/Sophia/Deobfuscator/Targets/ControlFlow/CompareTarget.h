#pragma once

#include "../DeobfuscationTarget.h"

class CompareTarget : public DeobfuscationTarget
{
public:
    const char* Name() const override { return "ControlFlow Compare"; }
    bool Enabled(const DeobfConfig& cfg) const override { return cfg.WantCompare; }
    void Deobfuscate(DeobfContext& ctx, Deobfuscator::Report& r) override;
};