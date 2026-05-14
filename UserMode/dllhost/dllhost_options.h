#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>

#include <string>

namespace BK::DllHost
{
    enum class DllMode
    {
        LoadOnly,
        ExportVoid,
        Rundll,
        RegisterServer,
        UnregisterServer,
        Install
    };

    struct Options
    {
        std::wstring DllPath;
        DllMode Mode = DllMode::LoadOnly;
        std::wstring ExportName;
        DWORD ExportOrdinal = 0;
        std::wstring RundllArgument;
        std::wstring InstallArgument;
        BOOL InstallEnable = TRUE;
        DWORD LoadFlags = 0;
        DWORD WaitMs = 60000;
        bool FreeOnExit = false;
    };

    void PrintUsage() noexcept;
    bool ParseOptions(int argc, wchar_t **argv, Options &options) noexcept;
} // namespace BK::DllHost
