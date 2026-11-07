#pragma once
#include <cstdint>
#include <vector>

class SectionManager
{
public:
    static bool AppendPeSection(std::vector<uint8_t>& buf, const char* name, const std::vector<uint8_t>& content, uint32_t& outrva, uint32_t characteristics = 0x40000040u);

private:
    SectionManager() = delete;
};