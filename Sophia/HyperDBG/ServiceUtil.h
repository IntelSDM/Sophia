#pragma once
#include <windows.h>

class ServiceUtil
{
public:
    static void EvictStale(const wchar_t* servicename);
};