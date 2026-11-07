#pragma once
#include <cstdint>
#include <string>
#include <vector>

enum class SiteKind : uint8_t
{
    Branch, Call, Compare, String, VecMove, Mov, Arith, IndBranch, IndCall, Lea, Syscall
};

struct MemOperand
{
    bool     Present = false;
    bool     RipRel = false;
    bool     Read = false;
    uint8_t  Scale = 0;
    uint16_t Width = 0;
    int64_t  Disp = 0;
    char     Base[8] = {};
    char     Index[8] = {};
    char     Seg[4] = {};
};

struct InsnSite
{
    SiteKind   Kind = SiteKind::Branch;
    uint64_t   FileOffset = 0;
    uint64_t   Rva = 0;
    uint64_t   ToRva = 0;
    uint64_t   Va = 0;
    uint32_t   Length = 0;
    char       Mnemonic[16] = {};
    char       Reg[8] = {};
    char       Reg2[8] = {};
    uint64_t   Imm = 0;
    bool       HasImm = false;
    MemOperand Mem;
};

class PeScan
{
public:
    struct ScanOptions
    {
        std::vector<std::string> Sections;
        std::vector<std::string> SkipSectionPrefixes;
        struct Range { uint64_t Rva; uint64_t Size; };
        std::vector<Range> Ranges;
    };

    static std::vector<InsnSite> ScanFile(const std::string& filepath, uint64_t& preferredbase, const ScanOptions& opts = {});

private:
    PeScan() = delete;
};