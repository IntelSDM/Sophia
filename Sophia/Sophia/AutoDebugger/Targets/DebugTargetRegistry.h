#pragma once

#include "DebugTarget.h"

class DebugTargetRegistry
{
public:
    static const DebugTarget* Get(SiteKind kind);
};