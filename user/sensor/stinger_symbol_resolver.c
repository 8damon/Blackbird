#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <dbghelp.h>
#include <psapi.h>
#include <stdio.h>
#include <string.h>
#include "stinger_symbol_resolver.h"

#pragma comment(lib, "Dbghelp.lib")
#pragma comment(lib, "Psapi.lib")

static HANDLE g_SymbolProcess = NULL;
static BOOL g_SymbolsReady = FALSE;
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
    const char* rawPath,
    char* normalizedPath,
    size_t normalizedPathChars
)
{
    char windowsDir[MAX_PATH];

    if (rawPath == NULL || normalizedPath == NULL || normalizedPathChars == 0) {
        return FALSE;
    }

    if (STINGERStartsWithInsensitive(rawPath, "\\SystemRoot\\")) {
        UINT len = GetWindowsDirectoryA(windowsDir, MAX_PATH);
        if (len == 0 || len >= MAX_PATH) {
            return FALSE;
        }

        return (sprintf_s(
            normalizedPath,
            normalizedPathChars,
            "%s\\%s",
            windowsDir,
            rawPath + strlen("\\SystemRoot\\")
        ) > 0);
    }

    if (STINGERStartsWithInsensitive(rawPath, "\\??\\")) {
        return (strcpy_s(normalizedPath, normalizedPathChars, rawPath + 4) == 0);
    }

    if (STINGERStartsWithInsensitive(rawPath, "\\Windows\\")) {
        UINT len = GetWindowsDirectoryA(windowsDir, MAX_PATH);
        if (len < 2 || len >= MAX_PATH) {
            return FALSE;
        }

        return (sprintf_s(
            normalizedPath,
            normalizedPathChars,
            "%c:%s",
            windowsDir[0],
            rawPath
        ) > 0);
    }

    if (rawPath[0] != '\0' && rawPath[1] == ':') {
        return (strcpy_s(normalizedPath, normalizedPathChars, rawPath) == 0);
    }

    return FALSE;
}

static BOOL
STINGERBuildKernelGuessPath(
    const char* moduleName,
    char* guessedPath,
    size_t guessedPathChars
)
{
    char windowsDir[MAX_PATH];
    const char* suffix;

    if (moduleName == NULL || guessedPath == NULL || guessedPathChars == 0) {
        return FALSE;
    }

    if (GetWindowsDirectoryA(windowsDir, RTL_NUMBER_OF(windowsDir)) == 0) {
        return FALSE;
    }

    if (strstr(moduleName, ".sys") != NULL || strstr(moduleName, ".SYS") != NULL) {
        suffix = "System32\\drivers";
    } else {
        suffix = "System32";
    }

    return (sprintf_s(
        guessedPath,
        guessedPathChars,
        "%s\\%s\\%s",
        windowsDir,
        suffix,
        moduleName
    ) > 0);
}

static BOOL
STINGERIsLikelyKernelAddress(UINT64 address)
{
#if defined(_WIN64)
    return (address >= 0xFFFF000000000000ULL);
#else
    UNREFERENCED_PARAMETER(address);
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

    if (!g_SymbolsReady || g_KernelModulesLoaded) {
        return;
    }

    if (!EnumDeviceDrivers(drivers, sizeof(drivers), &bytesNeeded)) {
        printf("[WARN] symbol resolver: EnumDeviceDrivers failed err=%lu\n", GetLastError());
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

        if (!STINGERNormalizeKernelImagePath(rawPath, normPath, RTL_NUMBER_OF(normPath))) {
            (void)strcpy_s(normPath, RTL_NUMBER_OF(normPath), rawPath);
        }

        SetLastError(ERROR_SUCCESS);
        loadedBase = SymLoadModuleEx(
            g_SymbolProcess,
            NULL,
            normPath,
            moduleName,
            base,
            0,
            NULL,
            0
        );
        err = GetLastError();

        if (loadedBase == 0 && err != ERROR_SUCCESS && _stricmp(normPath, rawPath) != 0) {
            SetLastError(ERROR_SUCCESS);
            loadedBase = SymLoadModuleEx(
                g_SymbolProcess,
                NULL,
                rawPath,
                moduleName,
                base,
                0,
                NULL,
                0
            );
            err = GetLastError();
        }

        if (loadedBase == 0 && err != ERROR_SUCCESS && STINGERBuildKernelGuessPath(moduleName, guessPath, RTL_NUMBER_OF(guessPath))) {
            SetLastError(ERROR_SUCCESS);
            loadedBase = SymLoadModuleEx(
                g_SymbolProcess,
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

        if (loadedBase == 0 && err != ERROR_SUCCESS) {
            SetLastError(ERROR_SUCCESS);
            loadedBase = SymLoadModuleEx(
                g_SymbolProcess,
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
    printf("[INFO] symbol resolver: kernel modules loaded=%lu/%lu\n", loaded, count);
}

void
STINGERSymbolResolverInitialize(void)
{
    DWORD options;
    char ntSymbolPath[2048];

    g_SymbolProcess = GetCurrentProcess();
    options = SymGetOptions();
    options |= SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_LOAD_LINES;
    SymSetOptions(options);

    if (!SymInitialize(g_SymbolProcess, NULL, TRUE)) {
        printf("[WARN] symbol resolver: SymInitialize failed err=%lu (raw addresses only)\n", GetLastError());
        return;
    }

    g_SymbolsReady = TRUE;

    if (GetEnvironmentVariableA("_NT_SYMBOL_PATH", ntSymbolPath, RTL_NUMBER_OF(ntSymbolPath)) == 0) {
        (void)SymSetSearchPath(g_SymbolProcess, "srv*C:\\symbols*https://msdl.microsoft.com/download/symbols");
    }

    STINGERLoadKernelModules();
}

void
STINGERSymbolResolverCleanup(void)
{
    if (g_SymbolsReady) {
        (void)SymCleanup(g_SymbolProcess);
    }
    g_SymbolProcess = NULL;
    g_SymbolsReady = FALSE;
    g_KernelModulesLoaded = FALSE;
}

void
STINGERSymbolResolverPrintAddress(UINT64 address)
{
    DWORD64 addr = (DWORD64)address;
    CHAR symBuffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME];
    PSYMBOL_INFO symInfo = (PSYMBOL_INFO)symBuffer;
    DWORD64 symDisplacement = 0;
    IMAGEHLP_MODULE64 modInfo;
    IMAGEHLP_LINE64 lineInfo;
    DWORD lineDisplacement = 0;
    BOOL gotSym = FALSE;
    BOOL gotMod = FALSE;
    BOOL gotLine = FALSE;

    printf("0x%llX", (unsigned long long)address);

    if (!g_SymbolsReady) {
        if (STINGERIsLikelyKernelAddress(address)) {
            printf(" [kernel-address]");
        }
        return;
    }

    ZeroMemory(symBuffer, sizeof(symBuffer));
    symInfo->SizeOfStruct = sizeof(SYMBOL_INFO);
    symInfo->MaxNameLen = MAX_SYM_NAME;
    gotSym = SymFromAddr(g_SymbolProcess, addr, &symDisplacement, symInfo);

    ZeroMemory(&modInfo, sizeof(modInfo));
    modInfo.SizeOfStruct = sizeof(modInfo);
    gotMod = SymGetModuleInfo64(g_SymbolProcess, addr, &modInfo);

    ZeroMemory(&lineInfo, sizeof(lineInfo));
    lineInfo.SizeOfStruct = sizeof(lineInfo);
    gotLine = SymGetLineFromAddr64(g_SymbolProcess, addr, &lineDisplacement, &lineInfo);

    if (gotMod && gotSym) {
        printf(" %s!%s+0x%llX",
            modInfo.ModuleName,
            symInfo->Name,
            (unsigned long long)symDisplacement);
    } else if (gotSym) {
        printf(" %s+0x%llX",
            symInfo->Name,
            (unsigned long long)symDisplacement);
    } else if (gotMod) {
        printf(" %s+0x%llX",
            modInfo.ModuleName,
            (unsigned long long)(addr - modInfo.BaseOfImage));
    } else if (STINGERIsLikelyKernelAddress(address)) {
        printf(" [kernel-address]");
    } else {
        printf(" [unresolved]");
    }

    if (gotLine && lineInfo.FileName != NULL) {
        printf(" (%s:%lu)", lineInfo.FileName, lineInfo.LineNumber);
    }
}
