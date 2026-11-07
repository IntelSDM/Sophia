#pragma once

#include "../DeobfuscationTarget.h"

class StringBufferTarget : public DeobfuscationTarget
{
public:
    const char* Name() const override { return "String Buffer"; }
    bool Enabled(const DeobfConfig& cfg) const override { return cfg.WantString || cfg.WantVec; }
    void Deobfuscate(DeobfContext& ctx, Deobfuscator::Report& r) override;
};