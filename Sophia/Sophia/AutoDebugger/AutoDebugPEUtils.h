#pragma once

#include <windows.h>

#include <cstdint>
#include <fstream>
#include <string>
#include <unordered_map>
#include <vector>

class AutoDebugTool;

class AutoDebugPeUtils
{
public:
    struct ForeignExport
    {
        uint32_t Rva;
        std::string Name;
    };

    static uint32_t ExpRvaToFileOffset(const IMAGE_SECTION_HEADER* sectable, uint32_t nsec, uint32_t rva);
    static std::wstring NormalizeNtPath(const std::wstring& path);
    static std::ifstream OpenPeFileForRead(const std::wstring& path);

    static bool ReadExportsFromDiskFile(const std::wstring& fullpath, std::vector<ForeignExport>& out, std::unordered_map<uint32_t, size_t>& byrva);

    static bool DecodeNtdllSyscallImm(const uint8_t* p, size_t available, uint32_t& outimm);
};