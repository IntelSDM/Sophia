#include "../../../Pch.h"
#include "DebugTargetRegistry.h"

#include "BranchDebugTarget.h"
#include "CallDebugTarget.h"
#include "CompareDebugTarget.h"
#include "StringDebugTarget.h"
#include "VecDebugTarget.h"
#include "MovDebugTarget.h"
#include "ArithDebugTarget.h"
#include "IndBranchDebugTarget.h"
#include "IndCallDebugTarget.h"
#include "LeaDebugTarget.h"
#include "SyscallDebugTarget.h"

const DebugTarget* DebugTargetRegistry::Get(SiteKind kind)
{
    static const BranchDebugTarget branchtgt;
    static const CallDebugTarget calltgt;
    static const CompareDebugTarget comparetgt;
    static const StringDebugTarget stringtgt;
    static const VecDebugTarget vectgt;
    static const MovDebugTarget movtgt;
    static const ArithDebugTarget arithtgt;
    static const IndBranchDebugTarget indbranchtgt;
    static const IndCallDebugTarget indcalltgt;
    static const LeaDebugTarget leatgt;
    static const SyscallDebugTarget syscalltgt;

    switch (kind)
    {
    case SiteKind::Branch:
        return &branchtgt;
    case SiteKind::Call:
        return &calltgt;
    case SiteKind::Compare:
        return &comparetgt;
    case SiteKind::String:
        return &stringtgt;
    case SiteKind::VecMove:
        return &vectgt;
    case SiteKind::Mov:
        return &movtgt;
    case SiteKind::Arith:
        return &arithtgt;
    case SiteKind::IndBranch:
        return &indbranchtgt;
    case SiteKind::IndCall:
        return &indcalltgt;
    case SiteKind::Lea:
        return &leatgt;
    case SiteKind::Syscall:
        return &syscalltgt;
    default:
        return nullptr;
    }
}