#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <dbghelp.h>
#include <psapi.h>
#include <stdio.h>
#include <string.h>
#include "sleepwalker_symbol_common.h"

BOOL SLEEPWALKERSymStartsWithInsensitive(_In_opt_z_ const char *Text, _In_opt_z_ const char *Prefix)
{
    size_t prefixLen;

    if (Text == NULL || Prefix == NULL)
    {
        return FALSE;
    }

    prefixLen = strlen(Prefix);
    if (strlen(Text) < prefixLen)
    {
        return FALSE;
    }

    return (_strnicmp(Text, Prefix, prefixLen) == 0);
}

BOOL SLEEPWALKERSymNormalizeKernelImagePath(_In_z_ const char *RawPath, _Out_writes_z_(OutputChars) char *Output,
                                            _In_ size_t OutputChars)
{
    char windowsDir[MAX_PATH];

    if (RawPath == NULL || Output == NULL || OutputChars == 0)
    {
        return FALSE;
    }
    Output[0] = '\0';

    if (SLEEPWALKERSymStartsWithInsensitive(RawPath, "\\SystemRoot\\"))
    {
        UINT len = GetWindowsDirectoryA(windowsDir, RTL_NUMBER_OF(windowsDir));
        if (len == 0 || len >= RTL_NUMBER_OF(windowsDir))
        {
            return FALSE;
        }
        return (sprintf_s(Output, OutputChars, "%s\\%s", windowsDir, RawPath + strlen("\\SystemRoot\\")) > 0);
    }

    if (SLEEPWALKERSymStartsWithInsensitive(RawPath, "\\??\\"))
    {
        return (strcpy_s(Output, OutputChars, RawPath + 4) == 0);
    }

    if (SLEEPWALKERSymStartsWithInsensitive(RawPath, "\\Windows\\"))
    {
        UINT len = GetWindowsDirectoryA(windowsDir, RTL_NUMBER_OF(windowsDir));
        if (len < 2 || len >= RTL_NUMBER_OF(windowsDir))
        {
            return FALSE;
        }
        return (sprintf_s(Output, OutputChars, "%c:%s", windowsDir[0], RawPath) > 0);
    }

    if (RawPath[0] != '\0' && RawPath[1] == ':')
    {
        return (strcpy_s(Output, OutputChars, RawPath) == 0);
    }

    return FALSE;
}

BOOL SLEEPWALKERSymBuildKernelGuessPath(_In_z_ const char *ModuleName, _Out_writes_z_(OutputChars) char *Output,
                                        _In_ size_t OutputChars)
{
    char windowsDir[MAX_PATH];
    const char *suffix;

    if (ModuleName == NULL || Output == NULL || OutputChars == 0)
    {
        return FALSE;
    }
    Output[0] = '\0';

    if (GetWindowsDirectoryA(windowsDir, RTL_NUMBER_OF(windowsDir)) == 0)
    {
        return FALSE;
    }

    if (strstr(ModuleName, ".sys") != NULL || strstr(ModuleName, ".SYS") != NULL)
    {
        suffix = "System32\\drivers";
    }
    else
    {
        suffix = "System32";
    }

    return (sprintf_s(Output, OutputChars, "%s\\%s\\%s", windowsDir, suffix, ModuleName) > 0);
}

DWORD
SLEEPWALKERSymLoadKernelModulesForProcess(_In_ HANDLE SymbolProcess, _Out_opt_ DWORD *LoadedCount,
                                          _Out_opt_ DWORD *TotalCount)
{
    LPVOID drivers[2048];
    DWORD bytesNeeded = 0;
    DWORD count;
    DWORD i;
    DWORD loaded = 0;

    if (LoadedCount != NULL)
    {
        *LoadedCount = 0;
    }
    if (TotalCount != NULL)
    {
        *TotalCount = 0;
    }
    if (SymbolProcess == NULL)
    {
        return ERROR_INVALID_PARAMETER;
    }

    if (!EnumDeviceDrivers(drivers, sizeof(drivers), &bytesNeeded))
    {
        return GetLastError();
    }

    count = bytesNeeded / sizeof(drivers[0]);
    if (count > RTL_NUMBER_OF(drivers))
    {
        count = RTL_NUMBER_OF(drivers);
    }

    for (i = 0; i < count; ++i)
    {
        DWORD64 base = (DWORD64)(ULONG_PTR)drivers[i];
        char rawPath[MAX_PATH];
        char normPath[MAX_PATH];
        char guessPath[MAX_PATH];
        char moduleName[MAX_PATH];
        DWORD64 loadedBase;
        DWORD err;

        ZeroMemory(rawPath, sizeof(rawPath));
        ZeroMemory(normPath, sizeof(normPath));
        ZeroMemory(guessPath, sizeof(guessPath));
        ZeroMemory(moduleName, sizeof(moduleName));

        if (GetDeviceDriverFileNameA(drivers[i], rawPath, RTL_NUMBER_OF(rawPath)) == 0)
        {
            continue;
        }
        if (GetDeviceDriverBaseNameA(drivers[i], moduleName, RTL_NUMBER_OF(moduleName)) == 0)
        {
            (void)strcpy_s(moduleName, RTL_NUMBER_OF(moduleName), "unknown");
        }

        if (!SLEEPWALKERSymNormalizeKernelImagePath(rawPath, normPath, RTL_NUMBER_OF(normPath)))
        {
            (void)strcpy_s(normPath, RTL_NUMBER_OF(normPath), rawPath);
        }

        SetLastError(ERROR_SUCCESS);
        loadedBase = SymLoadModuleEx(SymbolProcess, NULL, normPath, moduleName, base, 0, NULL, 0);
        err = GetLastError();

        if (loadedBase == 0 && err != ERROR_SUCCESS && _stricmp(normPath, rawPath) != 0)
        {
            SetLastError(ERROR_SUCCESS);
            loadedBase = SymLoadModuleEx(SymbolProcess, NULL, rawPath, moduleName, base, 0, NULL, 0);
            err = GetLastError();
        }

        if (loadedBase == 0 && err != ERROR_SUCCESS &&
            SLEEPWALKERSymBuildKernelGuessPath(moduleName, guessPath, RTL_NUMBER_OF(guessPath)))
        {
            SetLastError(ERROR_SUCCESS);
            loadedBase = SymLoadModuleEx(SymbolProcess, NULL, guessPath, moduleName, base, 0, NULL, 0);
            err = GetLastError();
        }

        if (loadedBase == 0 && err != ERROR_SUCCESS)
        {
            SetLastError(ERROR_SUCCESS);
            loadedBase = SymLoadModuleEx(SymbolProcess, NULL, NULL, moduleName, base, 0x1000, NULL, SLMFLAG_VIRTUAL);
            err = GetLastError();
        }

        if (loadedBase != 0 || err == ERROR_SUCCESS)
        {
            loaded += 1;
        }
    }

    if (LoadedCount != NULL)
    {
        *LoadedCount = loaded;
    }
    if (TotalCount != NULL)
    {
        *TotalCount = count;
    }
    return ERROR_SUCCESS;
}
