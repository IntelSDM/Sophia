#include "../../../Pch.h"
#include "DebugTarget.h"


std::string DebugTarget::BuildEaExpr(const MemOperand& m, uint64_t siteva, uint32_t len)
{
    if (m.Seg[0])
    {
        return {};
    }

    char num[32];
    if (m.RipRel)
    {
        const uint64_t abs = siteva + len + static_cast<uint64_t>(m.Disp);
        std::snprintf(num, sizeof(num), "0x%llx", static_cast<unsigned long long>(abs));
        return num;
    }

    std::string e;
    bool has = false;
    if (m.Base[0])
    {
        e += "@";
        e += m.Base;
        has = true;
    }
    if (m.Index[0])
    {
        e += has ? " + " : "";
        e += "@";
        e += m.Index;
        if (m.Scale > 1)
        {
            e += "*";
            e += std::to_string(m.Scale);
        }
        has = true;
    }
    if (!has)
    {
        std::snprintf(num, sizeof(num), "0x%llx", static_cast<unsigned long long>(m.Disp));
        return num;
    }
    if (m.Disp != 0)
    {
        if (m.Disp < 0)
        {
            std::snprintf(num, sizeof(num), " - 0x%llx", static_cast<unsigned long long>(-m.Disp));
        }
        else
        {
            std::snprintf(num, sizeof(num), " + 0x%llx", static_cast<unsigned long long>(m.Disp));
        }
        e += num;
    }
    return e;
}

void DebugTarget::EmitCallArgClauses(std::string& payload, const InsnSite& site, const std::string& basebuf, bool capturestackargs)
{
    char va[24];
    std::snprintf(va, sizeof(va), "0x%llx", static_cast<unsigned long long>(site.Va));

    const int nargs = capturestackargs ? 8 : 4;
    for (int idx = 0; idx < nargs; ++idx)
    {
        std::string valexpr;
        switch (idx)
        {
        case 0:
            valexpr = "@rcx";
            break;
        case 1:
            valexpr = "@rdx";
            break;
        case 2:
            valexpr = "@r8";
            break;
        case 3:
            valexpr = "@r9";
            break;
        default:
        {
            char stkoff[16];
            std::snprintf(stkoff, sizeof(stkoff), "0x%x", 0x20 + 8 * (idx - 4));
            valexpr = "dq(@rsp+";
            valexpr += stkoff;
            valexpr += ")";
            break;
        }
        }

        char idxbuf[8];
        std::snprintf(idxbuf, sizeof(idxbuf), "%d", idx);

        payload += " if ($context == ";
        payload += va;
        payload += ") { printf(\"[autodbg-arg] rva=%llx idx=";
        payload += idxbuf;
        payload += " val=%llx\\n\", $context - ";
        payload += basebuf;
        payload += ", ";
        payload += valexpr;
        payload += "); }";

        payload += " if ($context == ";
        payload += va;
        payload += ") { if (check_address(";
        payload += valexpr;
        payload += ") != 0) { printf(\"[autodbg-argh] rva=%llx idx=";
        payload += idxbuf;
        payload += " h0=%llx h1=%llx h2=%llx h3=%llx\\n\", $context - ";
        payload += basebuf;
        payload += ", dq(";
        payload += valexpr;
        payload += "), dq(";
        payload += valexpr;
        payload += "+8), dq(";
        payload += valexpr;
        payload += "+0x10), dq(";
        payload += valexpr;
        payload += "+0x18)); } }";
    }
}

void DebugTarget::EmitSyscallArgClauses(std::string& payload, const InsnSite& site, const std::string& basebuf, bool capturestackargs)
{
    char va[24];
    std::snprintf(va, sizeof(va), "0x%llx", static_cast<unsigned long long>(site.Va));

    const int nargs = capturestackargs ? 8 : 4;
    for (int idx = 0; idx < nargs; ++idx)
    {
        std::string valexpr;
        switch (idx)
        {
        case 0:
            valexpr = "@r10";
            break;
        case 1:
            valexpr = "@rdx";
            break;
        case 2:
            valexpr = "@r8";
            break;
        case 3:
            valexpr = "@r9";
            break;
        default:
        {
            char stkoff[16];
            std::snprintf(stkoff, sizeof(stkoff), "0x%x", 0x28 + 8 * (idx - 4));
            valexpr = "dq(@rsp+";
            valexpr += stkoff;
            valexpr += ")";
            break;
        }
        }

        char idxbuf[8];
        std::snprintf(idxbuf, sizeof(idxbuf), "%d", idx);

        payload += " if ($context == ";
        payload += va;
        payload += ") { printf(\"[autodbg-arg] rva=%llx idx=";
        payload += idxbuf;
        payload += " val=%llx\\n\", $context - ";
        payload += basebuf;
        payload += ", ";
        payload += valexpr;
        payload += "); }";

        payload += " if ($context == ";
        payload += va;
        payload += ") { if (check_address(";
        payload += valexpr;
        payload += ") != 0) { printf(\"[autodbg-argh] rva=%llx idx=";
        payload += idxbuf;
        payload += " h0=%llx h1=%llx h2=%llx h3=%llx\\n\", $context - ";
        payload += basebuf;
        payload += ", dq(";
        payload += valexpr;
        payload += "), dq(";
        payload += valexpr;
        payload += "+8), dq(";
        payload += valexpr;
        payload += "+0x10), dq(";
        payload += valexpr;
        payload += "+0x18)); } }";
    }
}

void DebugTarget::EmitPhantomRetClauses(std::string& payload, uint64_t retva, uint64_t callsiterva)
{
    char retvabuf[24];
    char sitervabuf[24];
    std::snprintf(retvabuf, sizeof(retvabuf), "0x%llx", static_cast<unsigned long long>(retva));
    std::snprintf(sitervabuf, sizeof(sitervabuf), "0x%llx", static_cast<unsigned long long>(callsiterva));

    payload += " if ($context == ";
    payload += retvabuf;
    payload += ") { printf(\"[autodbg-ret] rva=";
    payload += sitervabuf;
    payload += " rax=%llx\\n\", @rax); }";

    payload += " if ($context == ";
    payload += retvabuf;
    payload += ") { if (check_address(@rax) != 0) { printf(\"[autodbg-reth] rva=";
    payload += sitervabuf;
    payload += " rax=%llx h0=%llx h1=%llx h2=%llx h3=%llx\\n\", @rax, dq(@rax), dq(@rax+8), dq(@rax+0x10), dq(@rax+0x18)); } }";
}