#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <dbghelp.h>
#include <psapi.h>
#include <stdio.h>
#include <string.h>
#include "blackbird_symbol_resolver.h"
#include "blackbird_symbol_common.h"

#pragma comment(lib, "Dbghelp.lib")
#pragma comment(lib, "Psapi.lib")

static HANDLE g_SymbolProcess = NULL;
static BOOL g_SymbolsReady = FALSE;
static BOOL g_KernelModulesLoaded = FALSE;

static BOOL BLACKBIRDIsLikelyKernelAddress(UINT64 address)
{
#if defined(_WIN64)
    return (address >= 0xFFFF000000000000ULL);
#else
    UNREFERENCED_PARAMETER(address);
    return FALSE;
#endif
}

static void BLACKBIRDLoadKernelModules(void)
{
    DWORD status;
    DWORD loaded = 0;
    DWORD count = 0;

    if (!g_SymbolsReady || g_KernelModulesLoaded)
    {
        return;
    }

    status = BLACKBIRDSymLoadKernelModulesForProcess(g_SymbolProcess, &loaded, &count);
    if (status != ERROR_SUCCESS)
    {
        printf("[WARN] symbol resolver: kernel module load failed err=%lu\n", status);
        return;
    }

    g_KernelModulesLoaded = TRUE;
    printf("[INFO] symbol resolver: kernel modules loaded=%lu/%lu\n", loaded, count);
}

void BLACKBIRDSymbolResolverInitialize(void)
{
    DWORD options;
    char ntSymbolPath[2048];

    g_SymbolProcess = GetCurrentProcess();
    options = SymGetOptions();
    options |= SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_LOAD_LINES;
    SymSetOptions(options);

    if (!SymInitialize(g_SymbolProcess, NULL, TRUE))
    {
        printf("[WARN] symbol resolver: SymInitialize failed err=%lu (raw addresses only)\n", GetLastError());
        return;
    }

    g_SymbolsReady = TRUE;

    if (GetEnvironmentVariableA("_NT_SYMBOL_PATH", ntSymbolPath, RTL_NUMBER_OF(ntSymbolPath)) == 0)
    {
        (void)SymSetSearchPath(g_SymbolProcess, BLACKBIRD_DEFAULT_SYMBOL_PATH);
    }

    BLACKBIRDLoadKernelModules();
}

void BLACKBIRDSymbolResolverCleanup(void)
{
    if (g_SymbolsReady)
    {
        (void)SymCleanup(g_SymbolProcess);
    }
    g_SymbolProcess = NULL;
    g_SymbolsReady = FALSE;
    g_KernelModulesLoaded = FALSE;
}

void BLACKBIRDSymbolResolverPrintAddress(UINT64 address)
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

    if (!g_SymbolsReady)
    {
        if (BLACKBIRDIsLikelyKernelAddress(address))
        {
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

    if (gotMod && gotSym)
    {
        printf(" %s!%s+0x%llX", modInfo.ModuleName, symInfo->Name, (unsigned long long)symDisplacement);
    }
    else if (gotSym)
    {
        printf(" %s+0x%llX", symInfo->Name, (unsigned long long)symDisplacement);
    }
    else if (gotMod)
    {
        printf(" %s+0x%llX", modInfo.ModuleName, (unsigned long long)(addr - modInfo.BaseOfImage));
    }
    else if (BLACKBIRDIsLikelyKernelAddress(address))
    {
        printf(" [kernel-address]");
    }
    else
    {
        printf(" [unresolved]");
    }

    if (gotLine && lineInfo.FileName != NULL)
    {
        printf(" (%s:%lu)", lineInfo.FileName, lineInfo.LineNumber);
    }
}
