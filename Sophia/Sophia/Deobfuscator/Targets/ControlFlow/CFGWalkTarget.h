#pragma once

#include "../DeobfuscationTarget.h"

class CfgWalkTarget : public DeobfuscationTarget
{
public:
    const char* Name() const override { return "ControlFlow CFGWalk"; }
    bool Enabled(const DeobfConfig& cfg) const override { (void)cfg; return true; }
    void Deobfuscate(DeobfContext& ctx, Deobfuscator::Report& r) override;
};