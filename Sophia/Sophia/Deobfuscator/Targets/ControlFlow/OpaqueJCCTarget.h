#pragma once

#include "../DeobfuscationTarget.h"

class OpaqueJccTarget : public DeobfuscationTarget
{
public:
    const char* Name() const override { return "ControlFlow Opaque"; }
    bool Enabled(const DeobfConfig& cfg) const override { return cfg.WantBranch; }
    void Deobfuscate(DeobfContext& ctx, Deobfuscator::Report& r) override;
};