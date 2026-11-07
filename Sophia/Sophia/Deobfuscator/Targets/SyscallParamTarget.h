#pragma once

#include "DeobfuscationTarget.h"

class SyscallParamTarget : public DeobfuscationTarget
{
public:
    const char* Name() const override { return "Syscall"; }
    bool Enabled(const DeobfConfig& cfg) const override { return cfg.WantSyscall; }
    void Deobfuscate(DeobfContext& ctx, Deobfuscator::Report& r) override;
};