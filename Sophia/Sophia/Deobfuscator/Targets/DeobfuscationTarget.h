#pragma once

#include "../Deobfuscator.h"
#include "../DeobfContext.h"

class DeobfuscationTarget
{
public:
    virtual ~DeobfuscationTarget() = default;

    virtual const char* Name() const = 0;
    virtual bool Enabled(const DeobfConfig& cfg) const = 0;

    virtual void Deobfuscate(DeobfContext& ctx, Deobfuscator::Report& r) = 0;
};