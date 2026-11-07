#pragma once

#include "../DeobfuscationTarget.h"

class CallParamTarget : public DeobfuscationTarget
{
public:
    const char* Name() const override { return "ControlFlow Call Params"; }
    bool Enabled(const DeobfConfig& cfg) const override { return cfg.WantCall || cfg.WantIndCall; }
    void Deobfuscate(DeobfContext& ctx, Deobfuscator::Report& r) override;
};