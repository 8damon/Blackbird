#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <dbghelp.h>
#include <psapi.h>
#include <strsafe.h>
#include <stdio.h>
#include <string.h>
#include "stinger_etw_symbols.h"

#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "psapi.lib")

static HANDLE g_ProcessHandle = NULL;
static BOOL g_Ready = FALSE;
static BOOL g_KernelModulesLoaded = FALSE;

static BOOL
STINGERStartsWithInsensitive(const char* text, const char* prefix)
{
    size_t prefixLen;

    if (text == NULL || prefix == NULL) {
        return FALSE;
    }

    prefixLen = strlen(prefix);
    if (strlen(text) < prefixLen) {
        return FALSE;
    }

    return (_strnicmp(text, prefix, prefixLen) == 0);
}

static BOOL
STINGERNormalizeKernelImagePath(
    _In_z_ const char* RawPath,
    _Out_writes_z_(OutputChars) char* Output,
    _In_ size_t OutputChars
)
{
    char windowsDir[MAX_PATH];

    if (RawPath == NULL || Output == NULL || OutputChars == 0) {
        return FALSE;
    }
    Output[0] = '\0';

    if (STINGERStartsWithInsensitive(RawPath, "\\SystemRoot\\")) {
        UINT len = GetWindowsDirectoryA(windowsDir, RTL_NUMBER_OF(windowsDir));
        if (len == 0 || len >= RTL_NUMBER_OF(windowsDir)) {
            return FALSE;
        }
        return (sprintf_s(Output, OutputChars, "%s\\%s", windowsDir, RawPath + strlen("\\SystemRoot\\")) > 0);
    }

    if (STINGERStartsWithInsensitive(RawPath, "\\??\\")) {
        return (strcpy_s(Output, OutputChars, RawPath + 4) == 0);
    }

    if (STINGERStartsWithInsensitive(RawPath, "\\Windows\\")) {
        UINT len = GetWindowsDirectoryA(windowsDir, RTL_NUMBER_OF(windowsDir));
        if (len < 2 || len >= RTL_NUMBER_OF(windowsDir)) {
            return FALSE;
        }
        return (sprintf_s(Output, OutputChars, "%c:%s", windowsDir[0], RawPath) > 0);
    }

    if (RawPath[0] != '\0' && RawPath[1] == ':') {
        return (strcpy_s(Output, OutputChars, RawPath) == 0);
    }

    return FALSE;
}

static BOOL
STINGERBuildKernelGuessPath(
    _In_z_ const char* ModuleName,
    _Out_writes_z_(OutputChars) char* Output,
    _In_ size_t OutputChars
)
{
    char windowsDir[MAX_PATH];
    const char* suffix;

    if (ModuleName == NULL || Output == NULL || OutputChars == 0) {
        return FALSE;
    }
    Output[0] = '\0';

    if (GetWindowsDirectoryA(windowsDir, RTL_NUMBER_OF(windowsDir)) == 0) {
        return FALSE;
    }

    if (strstr(ModuleName, ".sys") != NULL || strstr(ModuleName, ".SYS") != NULL) {
        suffix = "System32\\drivers";
    } else {
        suffix = "System32";
    }

    return (sprintf_s(Output, OutputChars, "%s\\%s\\%s", windowsDir, suffix, ModuleName) > 0);
}

static BOOL
STINGERIsLikelyKernelAddress(_In_ ULONGLONG Address)
{
#if defined(_WIN64)
    return (Address >= 0xFFFF000000000000ULL);
#else
    UNREFERENCED_PARAMETER(Address);
    return FALSE;
#endif
}

static void
STINGERLoadKernelModules(void)
{
    LPVOID drivers[2048];
    DWORD bytesNeeded = 0;
    DWORD count;
    DWORD i;
    DWORD loaded = 0;

    if (!g_Ready || g_KernelModulesLoaded) {
        return;
    }

    if (!EnumDeviceDrivers(drivers, sizeof(drivers), &bytesNeeded)) {
        wprintf(L"[WARN] symbol resolver: EnumDeviceDrivers failed err=%lu\n", GetLastError());
        return;
    }

    count = bytesNeeded / sizeof(drivers[0]);
    if (count > RTL_NUMBER_OF(drivers)) {
        count = RTL_NUMBER_OF(drivers);
    }

    for (i = 0; i < count; ++i) {
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

        if (GetDeviceDriverFileNameA(drivers[i], rawPath, RTL_NUMBER_OF(rawPath)) == 0) {
            continue;
        }
        if (GetDeviceDriverBaseNameA(drivers[i], moduleName, RTL_NUMBER_OF(moduleName)) == 0) {
            (void)strcpy_s(moduleName, RTL_NUMBER_OF(moduleName), "unknown");
        }

        (void)STINGERNormalizeKernelImagePath(rawPath, normPath, RTL_NUMBER_OF(normPath));

        SetLastError(ERROR_SUCCESS);
        loadedBase = SymLoadModuleEx(
            g_ProcessHandle,
            NULL,
            (normPath[0] != '\0') ? normPath : rawPath,
            moduleName,
            base,
            0,
            NULL,
            0
        );
        err = GetLastError();

        if (loadedBase == 0 && err != ERROR_SUCCESS) {
            if (STINGERBuildKernelGuessPath(moduleName, guessPath, RTL_NUMBER_OF(guessPath))) {
                SetLastError(ERROR_SUCCESS);
                loadedBase = SymLoadModuleEx(
                    g_ProcessHandle,
                    NULL,
                    guessPath,
                    moduleName,
                    base,
                    0,
                    NULL,
                    0
                );
                err = GetLastError();
            }
        }

        if (loadedBase == 0 && err != ERROR_SUCCESS) {
            SetLastError(ERROR_SUCCESS);
            loadedBase = SymLoadModuleEx(
                g_ProcessHandle,
                NULL,
                NULL,
                moduleName,
                base,
                0x1000,
                NULL,
                SLMFLAG_VIRTUAL
            );
            err = GetLastError();
        }

        if (loadedBase != 0 || err == ERROR_SUCCESS) {
            loaded += 1;
        }
    }

    g_KernelModulesLoaded = TRUE;
    wprintf(L"[INFO] symbol resolver: kernel modules loaded=%lu/%lu\n", loaded, count);
}

void
STINGEREtwSymbolsInitialize(void)
{
    DWORD options;
    char symbolPath[2048];

    g_ProcessHandle = GetCurrentProcess();
    options = SymGetOptions();
    options |= SYMOPT_DEFERRED_LOADS | SYMOPT_UNDNAME | SYMOPT_LOAD_LINES;
    SymSetOptions(options);

    if (!SymInitialize(g_ProcessHandle, NULL, TRUE)) {
        wprintf(L"[WARN] symbol resolver: SymInitialize failed err=%lu (address-only fallback)\n", GetLastError());
        return;
    }
    g_Ready = TRUE;

    if (GetEnvironmentVariableA("_NT_SYMBOL_PATH", symbolPath, RTL_NUMBER_OF(symbolPath)) == 0) {
        (void)SymSetSearchPath(g_ProcessHandle, "srv*C:\\symbols*https://msdl.microsoft.com/download/symbols");
    }

    STINGERLoadKernelModules();
}

void
STINGEREtwSymbolsCleanup(void)
{
    if (g_Ready) {
        (void)SymCleanup(g_ProcessHandle);
    }
    g_ProcessHandle = NULL;
    g_Ready = FALSE;
    g_KernelModulesLoaded = FALSE;
}

void
STINGEREtwSymbolsFormatAddress(
    _In_ ULONGLONG Address,
    _Out_writes_z_(OutputChars) PWSTR Output,
    _In_ size_t OutputChars
)
{
    BYTE buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME];
    PSYMBOL_INFO symbol = (PSYMBOL_INFO)buffer;
    DWORD64 displacement = 0;
    IMAGEHLP_MODULE64 moduleInfo;
    IMAGEHLP_LINE64 lineInfo;
    DWORD lineDisplacement = 0;
    BOOL gotSym;
    BOOL gotModule;
    BOOL gotLine;

    if (Output == NULL || OutputChars == 0) {
        return;
    }
    Output[0] = L'\0';

    if (Address == 0) {
        (void)StringCchCopyW(Output, OutputChars, L"<null>");
        return;
    }
    if (!g_Ready) {
        (void)StringCchPrintfW(Output, OutputChars, L"0x%016llX", Address);
        return;
    }

    ZeroMemory(buffer, sizeof(buffer));
    symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
    symbol->MaxNameLen = MAX_SYM_NAME;
    gotSym = SymFromAddr(g_ProcessHandle, (DWORD64)Address, &displacement, symbol);

    ZeroMemory(&moduleInfo, sizeof(moduleInfo));
    moduleInfo.SizeOfStruct = sizeof(moduleInfo);
    gotModule = SymGetModuleInfo64(g_ProcessHandle, (DWORD64)Address, &moduleInfo);

    ZeroMemory(&lineInfo, sizeof(lineInfo));
    lineInfo.SizeOfStruct = sizeof(lineInfo);
    gotLine = SymGetLineFromAddr64(g_ProcessHandle, (DWORD64)Address, &lineDisplacement, &lineInfo);

    if (gotModule && gotSym) {
        (void)StringCchPrintfW(
            Output,
            OutputChars,
            L"%S!%S+0x%llX",
            moduleInfo.ModuleName,
            symbol->Name,
            displacement
        );
    } else if (gotSym) {
        (void)StringCchPrintfW(Output, OutputChars, L"%S+0x%llX", symbol->Name, displacement);
    } else if (gotModule) {
        (void)StringCchPrintfW(
            Output,
            OutputChars,
            L"%S+0x%llX",
            moduleInfo.ModuleName,
            (ULONGLONG)((DWORD64)Address - moduleInfo.BaseOfImage)
        );
    } else if (STINGERIsLikelyKernelAddress(Address)) {
        (void)StringCchPrintfW(Output, OutputChars, L"0x%016llX [kernel-address]", Address);
    } else {
        (void)StringCchPrintfW(Output, OutputChars, L"0x%016llX [unresolved]", Address);
    }

    if (gotLine && lineInfo.FileName != NULL) {
        WCHAR withLine[1024];
        (void)StringCchPrintfW(withLine, RTL_NUMBER_OF(withLine), L"%ls (%S:%lu)", Output, lineInfo.FileName, lineInfo.LineNumber);
        (void)StringCchCopyW(Output, OutputChars, withLine);
    }
}
