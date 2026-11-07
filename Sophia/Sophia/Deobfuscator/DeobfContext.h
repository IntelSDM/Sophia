#pragma once

#include "../Database/AutoDebugStore.h"
#include "../WinPE/PEScan.h"

#include <Zydis/Zydis.h>

#include <cstdint>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

struct DeobfConfig
{
    bool WantBranch = true;
    bool WantCall = true;
    bool WantCompare = true;
    bool WantArith = true;
    bool WantMov = true;
    bool WantVec = true;
    bool WantIndBranch = true;
    bool WantIndCall = true;
    bool WantLea = true;
    bool WantSyscall = true;
    bool WantString = true;
    bool WantMovList = false;
    bool WantAriList = false;
    bool WantLeaList = false;
    bool WantCmpList = false;
};

struct DeobfSection
{
    uint32_t Rva = 0;
    uint32_t VirtualSize = 0;
    uint32_t RawOffset = 0;
    uint32_t RawSize = 0;
    uint32_t Characteristics = 0;
    char     Name[9] = {};
};

struct DeobfSectionMap
{
    std::vector<DeobfSection> Sections;

    const DeobfSection* Find(uint64_t rva) const;
    uint64_t RvaToOffset(uint64_t rva) const;
    static bool IsExecutable(const DeobfSection& s);
};

struct BufTally
{
    std::vector<uint8_t> Canonical;
    bool                 Mixed = false;
    uint64_t             FirstRva = 0;
    bool                 FromStr = false;
    bool                 FromVec = false;
    bool                 RipRel = false;
    char                 Mn[16] = {};
    uint64_t             LenHint = 0;
    uint32_t             ObsCount = 0;
};

struct VecSiteInfo
{
    uint64_t                     SiteRva = 0;
    uint32_t                     InsnLength = 0;
    uint64_t                     SiteFileOff = 0;
    bool                         RipRel = false;
    std::unordered_set<uint64_t> AddrsSeen;
};

struct DeobfContext
{
    std::string Filepath;
    std::vector<uint8_t> Buf;
    std::vector<uint8_t> PreMovRewriteBuf;
    DeobfSectionMap Sm;
    ZydisDecoder Decoder{};
    AutoDebugStore* Store = nullptr;
    std::vector<InsnSite> Sites;
    std::unordered_map<uint64_t, size_t> BranchIdxByRva;
    uint64_t PreferredBase = 0;
    DeobfConfig Cfg;

    std::unordered_map<uint64_t, BufTally> BufByAddr;
    std::unordered_map<uint64_t, VecSiteInfo> VecSiteByRva;
};