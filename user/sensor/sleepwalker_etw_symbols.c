#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <dbghelp.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <strsafe.h>
#include <stdio.h>
#include <string.h>
#include "sleepwalker_etw_symbols.h"
#include "sleepwalker_symbol_common.h"

#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "psapi.lib")

static HANDLE g_ProcessHandle = NULL;
static HANDLE g_SymbolProcessHandle = NULL;
static BOOL g_Ready = FALSE;
static BOOL g_KernelModulesLoaded = FALSE;
static DWORD g_ActiveUserPid = 0;
static DWORD g_LastUserLoadWarnPid = 0;
static CRITICAL_SECTION g_SymbolLock;
static BOOL g_SymbolLockReady = FALSE;
#define SLEEPWALKER_USER_SYMBOL_PID_CACHE 16
static DWORD g_UserModulePids[SLEEPWALKER_USER_SYMBOL_PID_CACHE];
static LONG g_UserModulePidWriteIndex = -1;
#define SLEEPWALKER_MODULE_CACHE_PID_SLOTS 24
#define SLEEPWALKER_MODULE_CACHE_MODULE_SLOTS 192
#define SLEEPWALKER_MODULE_CACHE_NAME_CHARS 96
typedef struct _SLEEPWALKER_MODULE_CACHE_ENTRY
{
    ULONGLONG Base;
    ULONGLONG Size;
    WCHAR Name[SLEEPWALKER_MODULE_CACHE_NAME_CHARS];
} SLEEPWALKER_MODULE_CACHE_ENTRY;
typedef struct _SLEEPWALKER_MODULE_CACHE_PID_ENTRY
{
    DWORD ProcessId;
    DWORD ModuleCount;
    SLEEPWALKER_MODULE_CACHE_ENTRY Modules[SLEEPWALKER_MODULE_CACHE_MODULE_SLOTS];
} SLEEPWALKER_MODULE_CACHE_PID_ENTRY;
static SLEEPWALKER_MODULE_CACHE_PID_ENTRY g_ModuleCache[SLEEPWALKER_MODULE_CACHE_PID_SLOTS];
static LONG g_ModuleCacheWriteIndex = -1;

static PCWSTR SLEEPWALKERGetPathBaseName(_In_z_ PCWSTR Path);

static VOID SLEEPWALKEREnterSymbolLock(VOID)
{
    if (g_SymbolLockReady)
    {
        EnterCriticalSection(&g_SymbolLock);
    }
}

static VOID SLEEPWALKERLeaveSymbolLock(VOID)
{
    if (g_SymbolLockReady)
    {
        LeaveCriticalSection(&g_SymbolLock);
    }
}

static VOID SLEEPWALKERFormatWin32Error(_In_ DWORD ErrorCode, _Out_writes_z_(OutputChars) PWSTR Output,
                                        _In_ size_t OutputChars)
{
    WCHAR message[256];
    DWORD chars;

    if (Output == NULL || OutputChars == 0)
    {
        return;
    }

    if (ErrorCode == ERROR_SUCCESS)
    {
        (void)StringCchCopyW(Output, OutputChars, L"SUCCESS(0)");
        return;
    }

    ZeroMemory(message, sizeof(message));
    chars = FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, ErrorCode,
                           MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), message, RTL_NUMBER_OF(message), NULL);
    if (chars != 0)
    {
        while (chars > 0 && (message[chars - 1] == L'\r' || message[chars - 1] == L'\n' || message[chars - 1] == L' ' ||
                             message[chars - 1] == L'\t'))
        {
            message[chars - 1] = L'\0';
            chars -= 1;
        }
        (void)StringCchPrintfW(Output, OutputChars, L"%lu (%ls)", ErrorCode, message);
        return;
    }

    (void)StringCchPrintfW(Output, OutputChars, L"%lu", ErrorCode);
}

static BOOL SLEEPWALKERIsLikelyKernelAddress(_In_ ULONGLONG Address)
{
#if defined(_WIN64)
    return (Address >= 0xFFFF000000000000ULL);
#else
    UNREFERENCED_PARAMETER(Address);
    return FALSE;
#endif
}

static BOOL SLEEPWALKERIsUserPidCached(_In_ DWORD ProcessId)
{
    UINT32 i;

    if (ProcessId == 0)
    {
        return FALSE;
    }

    for (i = 0; i < RTL_NUMBER_OF(g_UserModulePids); ++i)
    {
        if (g_UserModulePids[i] == ProcessId)
        {
            return TRUE;
        }
    }
    return FALSE;
}

static VOID SLEEPWALKERResetModuleCache(VOID)
{
    ZeroMemory(g_ModuleCache, sizeof(g_ModuleCache));
    InterlockedExchange(&g_ModuleCacheWriteIndex, -1);
}

static VOID SLEEPWALKERCommitModuleSnapshot(_In_ DWORD ProcessId,
                                            _In_reads_(ModuleCount) const SLEEPWALKER_MODULE_CACHE_ENTRY *Modules,
                                            _In_ DWORD ModuleCount)
{
    DWORD i;
    DWORD slot = 0;
    LONG idx;

    if (ProcessId == 0 || Modules == NULL || ModuleCount == 0)
    {
        return;
    }

    for (i = 0; i < RTL_NUMBER_OF(g_ModuleCache); ++i)
    {
        if (g_ModuleCache[i].ProcessId == ProcessId)
        {
            slot = i;
            goto WriteSnapshot;
        }
    }

    idx = InterlockedIncrement(&g_ModuleCacheWriteIndex);
    if (idx < 0)
    {
        idx = 0;
    }
    slot = (DWORD)idx % RTL_NUMBER_OF(g_ModuleCache);

WriteSnapshot:
    g_ModuleCache[slot].ProcessId = ProcessId;
    g_ModuleCache[slot].ModuleCount = ModuleCount;
    if (g_ModuleCache[slot].ModuleCount > RTL_NUMBER_OF(g_ModuleCache[slot].Modules))
    {
        g_ModuleCache[slot].ModuleCount = RTL_NUMBER_OF(g_ModuleCache[slot].Modules);
    }
    for (i = 0; i < g_ModuleCache[slot].ModuleCount; ++i)
    {
        g_ModuleCache[slot].Modules[i] = Modules[i];
    }
}

static SLEEPWALKER_MODULE_CACHE_PID_ENTRY *SLEEPWALKERGetOrCreateModuleCacheSlot(_In_ DWORD ProcessId)
{
    DWORD i;
    DWORD slot;
    LONG idx;

    if (ProcessId == 0)
    {
        return NULL;
    }

    for (i = 0; i < RTL_NUMBER_OF(g_ModuleCache); ++i)
    {
        if (g_ModuleCache[i].ProcessId == ProcessId)
        {
            return &g_ModuleCache[i];
        }
    }

    idx = InterlockedIncrement(&g_ModuleCacheWriteIndex);
    if (idx < 0)
    {
        idx = 0;
    }
    slot = (DWORD)idx % RTL_NUMBER_OF(g_ModuleCache);
    ZeroMemory(&g_ModuleCache[slot], sizeof(g_ModuleCache[slot]));
    g_ModuleCache[slot].ProcessId = ProcessId;
    return &g_ModuleCache[slot];
}

static VOID SLEEPWALKERCacheSingleModuleRange(_In_ DWORD ProcessId, _In_ ULONGLONG ImageBase, _In_ ULONGLONG ImageSize,
                                              _In_opt_z_ PCWSTR ImagePath)
{
    SLEEPWALKER_MODULE_CACHE_PID_ENTRY *slot;
    DWORD i;
    DWORD moduleSlot;
    PCWSTR name;

    if (ProcessId == 0 || ImageBase == 0 || ImageSize == 0)
    {
        return;
    }

    slot = SLEEPWALKERGetOrCreateModuleCacheSlot(ProcessId);
    if (slot == NULL)
    {
        return;
    }

    moduleSlot = (DWORD)-1;
    for (i = 0; i < slot->ModuleCount; ++i)
    {
        if (slot->Modules[i].Base == ImageBase)
        {
            moduleSlot = i;
            break;
        }
    }

    if (moduleSlot == (DWORD)-1)
    {
        if (slot->ModuleCount < RTL_NUMBER_OF(slot->Modules))
        {
            moduleSlot = slot->ModuleCount;
            slot->ModuleCount += 1;
        }
        else
        {
            moduleSlot = (DWORD)(ImageBase % RTL_NUMBER_OF(slot->Modules));
        }
    }

    slot->Modules[moduleSlot].Base = ImageBase;
    slot->Modules[moduleSlot].Size = ImageSize;
    slot->Modules[moduleSlot].Name[0] = L'\0';

    name = SLEEPWALKERGetPathBaseName(ImagePath);
    if (name != NULL && name[0] != L'\0')
    {
        (void)StringCchCopyW(slot->Modules[moduleSlot].Name, RTL_NUMBER_OF(slot->Modules[moduleSlot].Name), name);
    }
}

static BOOL SLEEPWALKERTryResolveViaModuleCache(_In_ DWORD ProcessId, _In_ ULONGLONG Address,
                                                _Out_writes_z_(OutputChars) PWSTR Output, _In_ size_t OutputChars)
{
    DWORD i;
    DWORD j;

    if (ProcessId == 0 || Output == NULL || OutputChars == 0)
    {
        return FALSE;
    }

    for (i = 0; i < RTL_NUMBER_OF(g_ModuleCache); ++i)
    {
        const SLEEPWALKER_MODULE_CACHE_PID_ENTRY *entry = &g_ModuleCache[i];
        if (entry->ProcessId != ProcessId || entry->ModuleCount == 0)
        {
            continue;
        }

        for (j = 0; j < entry->ModuleCount; ++j)
        {
            ULONGLONG base = entry->Modules[j].Base;
            ULONGLONG size = entry->Modules[j].Size;
            ULONGLONG end;

            if (size == 0)
            {
                continue;
            }
            end = base + size;
            if (end < base)
            {
                continue;
            }
            if (Address < base || Address >= end)
            {
                continue;
            }

            (void)StringCchPrintfW(Output, OutputChars, L"%ls+0x%llX",
                                   entry->Modules[j].Name[0] ? entry->Modules[j].Name : L"<module>", Address - base);
            return TRUE;
        }
    }

    return FALSE;
}

static VOID SLEEPWALKERCacheUserPid(_In_ DWORD ProcessId)
{
    LONG idx;

    if (ProcessId == 0)
    {
        return;
    }

    idx = InterlockedIncrement(&g_UserModulePidWriteIndex);
    if (idx < 0)
    {
        idx = 0;
    }
    g_UserModulePids[(UINT32)idx % RTL_NUMBER_OF(g_UserModulePids)] = ProcessId;
}

static VOID SLEEPWALKERLoadUserModulesForProcess(_In_ DWORD ProcessId, _In_ BOOL ForceReload,
                                                 _Out_opt_ DWORD *OpenProcessErrorCode)
{
    HANDLE process;
    HMODULE mods[1024];
    DWORD bytesNeeded = 0;
    DWORD count;
    DWORD i;
    DWORD loaded = 0;
    SLEEPWALKER_MODULE_CACHE_ENTRY moduleSnapshot[SLEEPWALKER_MODULE_CACHE_MODULE_SLOTS];
    DWORD snapshotCount = 0;

    if (OpenProcessErrorCode != NULL)
    {
        *OpenProcessErrorCode = ERROR_SUCCESS;
    }

    if (!g_Ready || ProcessId == 0 || (!ForceReload && SLEEPWALKERIsUserPidCached(ProcessId)))
    {
        return;
    }

    if (ForceReload)
    {
        (void)SymRefreshModuleList(g_ProcessHandle);
    }

    process =
        OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, ProcessId);
    if (process == NULL)
    {
        DWORD openErr = GetLastError();
        if (OpenProcessErrorCode != NULL)
        {
            *OpenProcessErrorCode = openErr;
        }
        if (openErr == ERROR_INVALID_PARAMETER)
        {
            return;
        }
        if (g_LastUserLoadWarnPid != ProcessId)
        {
            g_LastUserLoadWarnPid = ProcessId;
            wprintf(L"[WARN] symbol resolver: OpenProcess failed for pid=%lu err=%lu\n", ProcessId, openErr);
        }
        return;
    }

    if (!EnumProcessModulesEx(process, mods, sizeof(mods), &bytesNeeded, LIST_MODULES_ALL))
    {
        CloseHandle(process);
        return;
    }

    count = bytesNeeded / sizeof(mods[0]);
    if (count > RTL_NUMBER_OF(mods))
    {
        count = RTL_NUMBER_OF(mods);
    }

    for (i = 0; i < count; ++i)
    {
        MODULEINFO mi;
        WCHAR pathW[1024];
        WCHAR pathDos[1024];
        WCHAR nameW[MAX_PATH];
        DWORD64 loadedBase;
        DWORD symErr = ERROR_SUCCESS;
        WCHAR driveName[3];
        WCHAR devicePath[1024];
        WCHAR *pathToTry = NULL;

        ZeroMemory(&mi, sizeof(mi));
        ZeroMemory(pathW, sizeof(pathW));
        ZeroMemory(pathDos, sizeof(pathDos));
        ZeroMemory(nameW, sizeof(nameW));
        ZeroMemory(driveName, sizeof(driveName));
        ZeroMemory(devicePath, sizeof(devicePath));

        if (!GetModuleInformation(process, mods[i], &mi, sizeof(mi)))
        {
            continue;
        }

        (void)GetModuleFileNameExW(process, mods[i], pathW, RTL_NUMBER_OF(pathW));
        (void)GetModuleBaseNameW(process, mods[i], nameW, RTL_NUMBER_OF(nameW));
        if (snapshotCount < RTL_NUMBER_OF(moduleSnapshot))
        {
            moduleSnapshot[snapshotCount].Base = (ULONGLONG)(ULONG_PTR)mi.lpBaseOfDll;
            moduleSnapshot[snapshotCount].Size = (ULONGLONG)mi.SizeOfImage;
            moduleSnapshot[snapshotCount].Name[0] = L'\0';

            if (nameW[0] != L'\0')
            {
                (void)StringCchCopyW(moduleSnapshot[snapshotCount].Name,
                                     RTL_NUMBER_OF(moduleSnapshot[snapshotCount].Name), nameW);
            }
            else if (pathW[0] != L'\0')
            {
                (void)StringCchCopyW(moduleSnapshot[snapshotCount].Name,
                                     RTL_NUMBER_OF(moduleSnapshot[snapshotCount].Name),
                                     SLEEPWALKERGetPathBaseName(pathW));
            }
            snapshotCount += 1;
        }
        pathToTry = (pathW[0] != L'\0') ? pathW : NULL;
        loadedBase = SymLoadModuleExW(g_ProcessHandle, NULL, pathToTry, (nameW[0] != L'\0') ? nameW : NULL,
                                      (DWORD64)(ULONG_PTR)mi.lpBaseOfDll, mi.SizeOfImage, NULL, 0);
        symErr = GetLastError();

        if ((loadedBase == 0) && pathW[0] != L'\0' && wcsncmp(pathW, L"\\??\\", 4) == 0)
        {
            (void)StringCchCopyW(pathDos, RTL_NUMBER_OF(pathDos), pathW + 4);
        }
        else if ((loadedBase == 0) && pathW[0] != L'\0' && pathW[0] == L'\\')
        {
            WCHAR drive;
            for (drive = L'A'; drive <= L'Z' && pathDos[0] == L'\0'; ++drive)
            {
                driveName[0] = drive;
                driveName[1] = L':';
                driveName[2] = L'\0';
                if (!QueryDosDeviceW(driveName, devicePath, RTL_NUMBER_OF(devicePath)))
                {
                    continue;
                }
                if (_wcsnicmp(pathW, devicePath, wcslen(devicePath)) == 0)
                {
                    (void)StringCchPrintfW(pathDos, RTL_NUMBER_OF(pathDos), L"%c:%ls", drive,
                                           pathW + wcslen(devicePath));
                }
            }
        }

        if (loadedBase == 0 && pathDos[0] != L'\0')
        {
            loadedBase = SymLoadModuleExW(g_ProcessHandle, NULL, pathDos, (nameW[0] != L'\0') ? nameW : NULL,
                                          (DWORD64)(ULONG_PTR)mi.lpBaseOfDll, mi.SizeOfImage, NULL, 0);
            symErr = GetLastError();
        }

        if (loadedBase == 0)
        {
            loadedBase = SymLoadModuleExW(g_ProcessHandle, NULL, NULL, (nameW[0] != L'\0') ? nameW : NULL,
                                          (DWORD64)(ULONG_PTR)mi.lpBaseOfDll, mi.SizeOfImage, NULL, SLMFLAG_VIRTUAL);
            symErr = GetLastError();
        }

        if (loadedBase != 0 || symErr == ERROR_SUCCESS)
        {
            loaded += 1;
        }
    }

    CloseHandle(process);
    if (snapshotCount != 0)
    {
        SLEEPWALKERCommitModuleSnapshot(ProcessId, moduleSnapshot, snapshotCount);
    }
    if (loaded != 0)
    {
        SLEEPWALKERCacheUserPid(ProcessId);
    }
    else if (g_LastUserLoadWarnPid != ProcessId)
    {
        g_LastUserLoadWarnPid = ProcessId;
        wprintf(L"[WARN] symbol resolver: user modules loaded=0/%lu for pid=%lu\n", count, ProcessId);
    }
}

static PCWSTR SLEEPWALKERGetPathBaseName(_In_z_ PCWSTR Path)
{
    PCWSTR slash;

    if (Path == NULL || Path[0] == L'\0')
    {
        return L"<unknown>";
    }

    slash = wcsrchr(Path, L'\\');
    return (slash != NULL && slash[1] != L'\0') ? (slash + 1) : Path;
}

static BOOL SLEEPWALKERTryResolveViaModuleEnum(_In_ HANDLE ProcessHandle, _In_ ULONGLONG Address,
                                               _Out_writes_z_(OutputChars) PWSTR Output, _In_ size_t OutputChars,
                                               _Out_opt_ DWORD *ErrorCode)
{
    HMODULE mods[1024];
    DWORD bytesNeeded = 0;
    DWORD count;
    DWORD i;

    if (ErrorCode != NULL)
    {
        *ErrorCode = ERROR_SUCCESS;
    }

    if (!EnumProcessModulesEx(ProcessHandle, mods, sizeof(mods), &bytesNeeded, LIST_MODULES_ALL))
    {
        if (ErrorCode != NULL)
        {
            *ErrorCode = GetLastError();
        }
        return FALSE;
    }

    count = bytesNeeded / sizeof(mods[0]);
    if (count > RTL_NUMBER_OF(mods))
    {
        count = RTL_NUMBER_OF(mods);
    }

    for (i = 0; i < count; ++i)
    {
        MODULEINFO mi;
        ULONGLONG base;
        ULONGLONG end;
        WCHAR moduleName[MAX_PATH];

        ZeroMemory(&mi, sizeof(mi));
        ZeroMemory(moduleName, sizeof(moduleName));
        if (!GetModuleInformation(ProcessHandle, mods[i], &mi, sizeof(mi)))
        {
            continue;
        }

        base = (ULONGLONG)(ULONG_PTR)mi.lpBaseOfDll;
        end = base + (ULONGLONG)mi.SizeOfImage;
        if (end < base)
        {
            continue;
        }
        if (Address < base || Address >= end)
        {
            continue;
        }

        (void)GetModuleBaseNameW(ProcessHandle, mods[i], moduleName, RTL_NUMBER_OF(moduleName));
        if (moduleName[0] == L'\0')
        {
            WCHAR fullPath[1024];
            ZeroMemory(fullPath, sizeof(fullPath));
            (void)GetModuleFileNameExW(ProcessHandle, mods[i], fullPath, RTL_NUMBER_OF(fullPath));
            (void)StringCchCopyW(moduleName, RTL_NUMBER_OF(moduleName), SLEEPWALKERGetPathBaseName(fullPath));
        }
        if (moduleName[0] == L'\0')
        {
            (void)StringCchCopyW(moduleName, RTL_NUMBER_OF(moduleName), L"<module>");
        }

        (void)StringCchPrintfW(Output, OutputChars, L"%ls+0x%llX [module-enum]", moduleName, Address - base);
        return TRUE;
    }

    if (ErrorCode != NULL)
    {
        *ErrorCode = ERROR_NOT_FOUND;
    }
    return FALSE;
}

static BOOL SLEEPWALKERTryResolveViaMappedFile(_In_ HANDLE ProcessHandle, _In_ ULONGLONG Address,
                                               _Out_writes_z_(OutputChars) PWSTR Output, _In_ size_t OutputChars,
                                               _Out_opt_ DWORD *ErrorCode)
{
    MEMORY_BASIC_INFORMATION mbi;
    WCHAR mappedPath[1024];
    ULONGLONG base;

    if (ErrorCode != NULL)
    {
        *ErrorCode = ERROR_SUCCESS;
    }

    ZeroMemory(&mbi, sizeof(mbi));
    ZeroMemory(mappedPath, sizeof(mappedPath));
    if (VirtualQueryEx(ProcessHandle, (LPCVOID)(ULONG_PTR)Address, &mbi, sizeof(mbi)) == 0)
    {
        if (ErrorCode != NULL)
        {
            *ErrorCode = GetLastError();
        }
        return FALSE;
    }
    if (mbi.AllocationBase == NULL)
    {
        if (ErrorCode != NULL)
        {
            *ErrorCode = ERROR_INVALID_ADDRESS;
        }
        return FALSE;
    }
    if (GetMappedFileNameW(ProcessHandle, mbi.AllocationBase, mappedPath, RTL_NUMBER_OF(mappedPath)) == 0)
    {
        if (ErrorCode != NULL)
        {
            *ErrorCode = GetLastError();
        }
        return FALSE;
    }

    base = (ULONGLONG)(ULONG_PTR)mbi.AllocationBase;
    (void)StringCchPrintfW(Output, OutputChars, L"%ls+0x%llX [mapped-file]", SLEEPWALKERGetPathBaseName(mappedPath),
                           (Address >= base) ? (Address - base) : 0);
    if (ErrorCode != NULL)
    {
        *ErrorCode = ERROR_SUCCESS;
    }
    return TRUE;
}

static BOOL SLEEPWALKERTryResolveAddressViaProcess(_In_ DWORD ProcessId, _In_ ULONGLONG Address,
                                                   _Out_writes_z_(OutputChars) PWSTR Output, _In_ size_t OutputChars,
                                                   _Out_opt_ DWORD *OpenProcessErrorCode,
                                                   _Out_opt_ DWORD *ModuleEnumErrorCode,
                                                   _Out_opt_ DWORD *MappedFileErrorCode)
{
    HANDLE process;
    BOOL resolved = FALSE;

    if (OpenProcessErrorCode != NULL)
    {
        *OpenProcessErrorCode = ERROR_SUCCESS;
    }
    if (ModuleEnumErrorCode != NULL)
    {
        *ModuleEnumErrorCode = ERROR_SUCCESS;
    }
    if (MappedFileErrorCode != NULL)
    {
        *MappedFileErrorCode = ERROR_SUCCESS;
    }

    if (ProcessId == 0 || Output == NULL || OutputChars == 0)
    {
        return FALSE;
    }

    process =
        OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, ProcessId);
    if (process == NULL)
    {
        if (OpenProcessErrorCode != NULL)
        {
            *OpenProcessErrorCode = GetLastError();
        }
        return FALSE;
    }

    resolved = SLEEPWALKERTryResolveViaModuleEnum(process, Address, Output, OutputChars, ModuleEnumErrorCode);
    if (!resolved)
    {
        resolved = SLEEPWALKERTryResolveViaMappedFile(process, Address, Output, OutputChars, MappedFileErrorCode);
    }

    CloseHandle(process);
    return resolved;
}

static BOOL SLEEPWALKERTryResolveViaToolhelpSnapshot(_In_ DWORD ProcessId, _In_ ULONGLONG Address,
                                                     _Out_writes_z_(OutputChars) PWSTR Output, _In_ size_t OutputChars,
                                                     _Out_opt_ DWORD *ErrorCode)
{
    HANDLE snap;
    MODULEENTRY32W me;
    BOOL found = FALSE;

    if (ErrorCode != NULL)
    {
        *ErrorCode = ERROR_SUCCESS;
    }

    if (ProcessId == 0 || Output == NULL || OutputChars == 0)
    {
        return FALSE;
    }

    snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, ProcessId);
    if (snap == INVALID_HANDLE_VALUE)
    {
        if (ErrorCode != NULL)
        {
            *ErrorCode = GetLastError();
        }
        return FALSE;
    }

    ZeroMemory(&me, sizeof(me));
    me.dwSize = sizeof(me);
    if (Module32FirstW(snap, &me))
    {
        do
        {
            ULONGLONG base = (ULONGLONG)(ULONG_PTR)me.modBaseAddr;
            ULONGLONG size = (ULONGLONG)me.modBaseSize;
            ULONGLONG end = base + size;

            if (size == 0 || end < base)
            {
                continue;
            }
            if (Address < base || Address >= end)
            {
                continue;
            }

            (void)StringCchPrintfW(Output, OutputChars, L"%ls+0x%llX [toolhelp]",
                                   (me.szModule[0] != L'\0') ? me.szModule : L"<module>", Address - base);
            found = TRUE;
            break;
        } while (Module32NextW(snap, &me));
    }

    CloseHandle(snap);
    if (!found && ErrorCode != NULL)
    {
        *ErrorCode = ERROR_NOT_FOUND;
    }
    return found;
}

static VOID SLEEPWALKERFormatAddressInternal(_In_ ULONGLONG Address, _Out_writes_z_(OutputChars) PWSTR Output,
                                             _In_ size_t OutputChars, _Out_opt_ DWORD *SymFromAddrErrorCode,
                                             _Out_opt_ DWORD *GetModuleInfoErrorCode,
                                             _Out_opt_ DWORD *GetLineInfoErrorCode)
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

    if (SymFromAddrErrorCode != NULL)
    {
        *SymFromAddrErrorCode = ERROR_SUCCESS;
    }
    if (GetModuleInfoErrorCode != NULL)
    {
        *GetModuleInfoErrorCode = ERROR_SUCCESS;
    }
    if (GetLineInfoErrorCode != NULL)
    {
        *GetLineInfoErrorCode = ERROR_SUCCESS;
    }

    if (Output == NULL || OutputChars == 0)
    {
        return;
    }
    Output[0] = L'\0';

    if (Address == 0)
    {
        (void)StringCchCopyW(Output, OutputChars, L"<null>");
        return;
    }
    if (!g_Ready)
    {
        (void)StringCchPrintfW(Output, OutputChars, L"0x%016llX", Address);
        return;
    }

    ZeroMemory(buffer, sizeof(buffer));
    symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
    symbol->MaxNameLen = MAX_SYM_NAME;
    gotSym = SymFromAddr(g_ProcessHandle, (DWORD64)Address, &displacement, symbol);
    if (!gotSym && SymFromAddrErrorCode != NULL)
    {
        *SymFromAddrErrorCode = GetLastError();
    }

    ZeroMemory(&moduleInfo, sizeof(moduleInfo));
    moduleInfo.SizeOfStruct = sizeof(moduleInfo);
    gotModule = SymGetModuleInfo64(g_ProcessHandle, (DWORD64)Address, &moduleInfo);
    if (!gotModule && GetModuleInfoErrorCode != NULL)
    {
        *GetModuleInfoErrorCode = GetLastError();
    }

    ZeroMemory(&lineInfo, sizeof(lineInfo));
    lineInfo.SizeOfStruct = sizeof(lineInfo);
    gotLine = SymGetLineFromAddr64(g_ProcessHandle, (DWORD64)Address, &lineDisplacement, &lineInfo);
    if (!gotLine && GetLineInfoErrorCode != NULL)
    {
        *GetLineInfoErrorCode = GetLastError();
    }

    if (gotModule && gotSym)
    {
        (void)StringCchPrintfW(Output, OutputChars, L"%S!%S+0x%llX", moduleInfo.ModuleName, symbol->Name, displacement);
    }
    else if (gotSym)
    {
        (void)StringCchPrintfW(Output, OutputChars, L"%S+0x%llX", symbol->Name, displacement);
    }
    else if (gotModule)
    {
        (void)StringCchPrintfW(Output, OutputChars, L"%S+0x%llX", moduleInfo.ModuleName,
                               (ULONGLONG)((DWORD64)Address - moduleInfo.BaseOfImage));
    }
    else if (SLEEPWALKERIsLikelyKernelAddress(Address))
    {
        (void)StringCchPrintfW(Output, OutputChars, L"0x%016llX [kernel-address]", Address);
    }
    else
    {
        (void)StringCchPrintfW(Output, OutputChars, L"0x%016llX [unresolved]", Address);
    }

    if (gotLine && lineInfo.FileName != NULL)
    {
        WCHAR withLine[1024];
        (void)StringCchPrintfW(withLine, RTL_NUMBER_OF(withLine), L"%ls (%S:%lu)", Output, lineInfo.FileName,
                               lineInfo.LineNumber);
        (void)StringCchCopyW(Output, OutputChars, withLine);
    }
}

static void SLEEPWALKERLoadKernelModules(void)
{
    DWORD status;
    DWORD loaded = 0;
    DWORD count = 0;

    if (!g_Ready || g_KernelModulesLoaded)
    {
        return;
    }

    status = SLEEPWALKERSymLoadKernelModulesForProcess(g_ProcessHandle, &loaded, &count);
    if (status != ERROR_SUCCESS)
    {
        wprintf(L"[WARN] symbol resolver: kernel module load failed err=%lu\n", status);
        return;
    }

    g_KernelModulesLoaded = TRUE;
    wprintf(L"[INFO] symbol resolver: kernel modules loaded=%lu/%lu\n", loaded, count);
}

static BOOL SLEEPWALKERReinitializeSymbolEngineLocked(_In_ BOOL PrintWarnings)
{
    DWORD options;
    char symbolPath[2048];

    if (g_Ready)
    {
        (void)SymCleanup(g_ProcessHandle);
    }
    if (g_SymbolProcessHandle != NULL)
    {
        CloseHandle(g_SymbolProcessHandle);
        g_SymbolProcessHandle = NULL;
    }

    g_ProcessHandle = GetCurrentProcess();
    g_Ready = FALSE;
    g_KernelModulesLoaded = FALSE;
    g_ActiveUserPid = 0;
    g_LastUserLoadWarnPid = 0;
    ZeroMemory(g_UserModulePids, sizeof(g_UserModulePids));
    InterlockedExchange(&g_UserModulePidWriteIndex, -1);

    options = SymGetOptions();
    options |= SYMOPT_DEFERRED_LOADS | SYMOPT_UNDNAME | SYMOPT_LOAD_LINES;
    SymSetOptions(options);

    if (!SymInitialize(g_ProcessHandle, NULL, TRUE))
    {
        if (PrintWarnings)
        {
            wprintf(L"[WARN] symbol resolver: SymInitialize failed err=%lu (address-only fallback)\n", GetLastError());
        }
        return FALSE;
    }
    g_Ready = TRUE;

    if (GetEnvironmentVariableA("_NT_SYMBOL_PATH", symbolPath, RTL_NUMBER_OF(symbolPath)) == 0)
    {
        (void)SymSetSearchPath(g_ProcessHandle, SLEEPWALKER_DEFAULT_SYMBOL_PATH);
    }

    SLEEPWALKERLoadKernelModules();
    return TRUE;
}

static BOOL SLEEPWALKERSwitchToTargetProcessLocked(_In_ DWORD ProcessId, _Out_opt_ DWORD *OpenProcessErrorCode)
{
    HANDLE targetProcess;
    DWORD options;
    char symbolPath[2048];

    if (OpenProcessErrorCode != NULL)
    {
        *OpenProcessErrorCode = ERROR_SUCCESS;
    }

    if (ProcessId == 0)
    {
        if (OpenProcessErrorCode != NULL)
        {
            *OpenProcessErrorCode = ERROR_INVALID_PARAMETER;
        }
        return FALSE;
    }
    if (g_Ready && g_ActiveUserPid == ProcessId && g_SymbolProcessHandle != NULL)
    {
        return TRUE;
    }

    targetProcess =
        OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, ProcessId);
    if (targetProcess == NULL)
    {
        DWORD openErr = GetLastError();
        if (OpenProcessErrorCode != NULL)
        {
            *OpenProcessErrorCode = openErr;
        }
        if (openErr == ERROR_INVALID_PARAMETER)
        {
            return FALSE;
        }
        if (g_LastUserLoadWarnPid != ProcessId)
        {
            g_LastUserLoadWarnPid = ProcessId;
            wprintf(L"[WARN] symbol resolver: OpenProcess failed for pid=%lu err=%lu\n", ProcessId, openErr);
        }
        return FALSE;
    }

    if (g_Ready)
    {
        (void)SymCleanup(g_ProcessHandle);
    }
    if (g_SymbolProcessHandle != NULL)
    {
        CloseHandle(g_SymbolProcessHandle);
        g_SymbolProcessHandle = NULL;
    }

    g_ProcessHandle = GetCurrentProcess();
    g_SymbolProcessHandle = targetProcess;
    g_Ready = FALSE;
    g_KernelModulesLoaded = FALSE;
    g_ActiveUserPid = 0;
    g_LastUserLoadWarnPid = 0;
    ZeroMemory(g_UserModulePids, sizeof(g_UserModulePids));
    InterlockedExchange(&g_UserModulePidWriteIndex, -1);

    options = SymGetOptions();
    options |= SYMOPT_DEFERRED_LOADS | SYMOPT_UNDNAME | SYMOPT_LOAD_LINES;
    SymSetOptions(options);

    if (!SymInitialize(g_ProcessHandle, NULL, TRUE))
    {
        DWORD err = GetLastError();
        wprintf(L"[WARN] symbol resolver: SymInitialize(token=self invade=true pid=%lu) failed err=%lu\n", ProcessId,
                err);
        CloseHandle(g_SymbolProcessHandle);
        g_SymbolProcessHandle = NULL;
        (void)SLEEPWALKERReinitializeSymbolEngineLocked(FALSE);
        return FALSE;
    }
    g_Ready = TRUE;

    if (GetEnvironmentVariableA("_NT_SYMBOL_PATH", symbolPath, RTL_NUMBER_OF(symbolPath)) == 0)
    {
        (void)SymSetSearchPath(g_ProcessHandle, SLEEPWALKER_DEFAULT_SYMBOL_PATH);
    }

    SLEEPWALKERLoadKernelModules();
    SLEEPWALKERLoadUserModulesForProcess(ProcessId, TRUE, NULL);
    g_ActiveUserPid = ProcessId;
    return TRUE;
}

void SLEEPWALKEREtwSymbolsInitialize(void)
{
    if (!g_SymbolLockReady)
    {
        InitializeCriticalSection(&g_SymbolLock);
        g_SymbolLockReady = TRUE;
    }

    SLEEPWALKEREnterSymbolLock();
    if (SLEEPWALKERReinitializeSymbolEngineLocked(TRUE))
    {
        wprintf(L"[INFO] symbol resolver: mode=dbghelp-first (no remote process module probing)\n");
    }
    SLEEPWALKERLeaveSymbolLock();
}

void SLEEPWALKEREtwSymbolsCleanup(void)
{
    SLEEPWALKEREnterSymbolLock();
    if (g_Ready)
    {
        (void)SymCleanup(g_ProcessHandle);
    }
    if (g_SymbolProcessHandle != NULL)
    {
        CloseHandle(g_SymbolProcessHandle);
        g_SymbolProcessHandle = NULL;
    }
    g_ProcessHandle = NULL;
    g_Ready = FALSE;
    g_KernelModulesLoaded = FALSE;
    g_ActiveUserPid = 0;
    ZeroMemory(g_UserModulePids, sizeof(g_UserModulePids));
    InterlockedExchange(&g_UserModulePidWriteIndex, -1);
    SLEEPWALKERResetModuleCache();
    SLEEPWALKERLeaveSymbolLock();

    if (g_SymbolLockReady)
    {
        DeleteCriticalSection(&g_SymbolLock);
        g_SymbolLockReady = FALSE;
    }
}

void SLEEPWALKEREtwSymbolsCacheModuleForProcess(_In_ DWORD ProcessId, _In_ ULONGLONG ImageBase,
                                                _In_ ULONGLONG ImageSize, _In_opt_z_ PCWSTR ImagePath)
{
    SLEEPWALKEREnterSymbolLock();
    SLEEPWALKERCacheSingleModuleRange(ProcessId, ImageBase, ImageSize, ImagePath);
    SLEEPWALKERLeaveSymbolLock();
}

BOOL SLEEPWALKEREtwSymbolsTryResolveViaModuleCache(_In_ DWORD ProcessId, _In_ ULONGLONG Address,
                                                   _Out_writes_z_(OutputChars) PWSTR Output, _In_ size_t OutputChars)
{
    BOOL resolved;

    SLEEPWALKEREnterSymbolLock();
    resolved = SLEEPWALKERTryResolveViaModuleCache(ProcessId, Address, Output, OutputChars);
    SLEEPWALKERLeaveSymbolLock();
    return resolved;
}

void SLEEPWALKEREtwSymbolsFormatAddress(_In_ ULONGLONG Address, _Out_writes_z_(OutputChars) PWSTR Output,
                                        _In_ size_t OutputChars)
{
    SLEEPWALKEREnterSymbolLock();
    SLEEPWALKERFormatAddressInternal(Address, Output, OutputChars, NULL, NULL, NULL);
    SLEEPWALKERLeaveSymbolLock();
}

void SLEEPWALKEREtwSymbolsFormatAddressForProcess(_In_ DWORD ProcessId, _In_ ULONGLONG Address,
                                                  _Out_writes_z_(OutputChars) PWSTR Output, _In_ size_t OutputChars)
{
    SLEEPWALKEREnterSymbolLock();
    SLEEPWALKERFormatAddressInternal(Address, Output, OutputChars, NULL, NULL, NULL);
    if (ProcessId != 0 && Output != NULL && OutputChars != 0 && wcsstr(Output, L"[unresolved]") != NULL)
    {
        (void)SLEEPWALKERTryResolveViaModuleCache(ProcessId, Address, Output, OutputChars);
    }
    SLEEPWALKERLeaveSymbolLock();
}
