#include "../controller_private.h"

#include <psapi.h>
#include <tlhelp32.h>

#pragma comment(lib, "psapi.lib")

#define BK_CONTROLLER_SYMBOL_WORKER_THREADS 2u
#define BK_CONTROLLER_SYMBOL_MAX_CACHE_ENTRIES 8192u
#define BK_CONTROLLER_SYMBOL_MAX_PROCESS_CONTEXTS 64u
#define BK_CONTROLLER_SYMBOL_MAX_MODULES_PER_PROCESS 192u
#define BK_CONTROLLER_SYMBOL_MAX_KERNEL_MODULES 384u
#define BK_CONTROLLER_SYMBOL_MAX_TEXT_CHARS 128u
#define BK_CONTROLLER_SYMBOL_PROCESS_REFRESH_MS 3000u
#define BK_CONTROLLER_SYMBOL_KERNEL_REFRESH_MS 5000u
#define BK_CONTROLLER_SYMBOL_MAX_QUEUE_DEPTH 4096u

typedef struct _BK_CONTROLLER_SYMBOL_MODULE_ENTRY
{
    UINT64 Base;
    UINT64 End;
    WCHAR Name[MAX_MODULE_NAME32 + 1];
    WCHAR Path[MAX_PATH];
} BK_CONTROLLER_SYMBOL_MODULE_ENTRY, *PBK_CONTROLLER_SYMBOL_MODULE_ENTRY;

typedef struct _BK_CONTROLLER_SYMBOL_PROCESS_CONTEXT
{
    BOOL Valid;
    DWORD ProcessId;
    ULONGLONG LastRefreshTick;
    DWORD ModuleCount;
    BK_CONTROLLER_SYMBOL_MODULE_ENTRY Modules[BK_CONTROLLER_SYMBOL_MAX_MODULES_PER_PROCESS];
} BK_CONTROLLER_SYMBOL_PROCESS_CONTEXT, *PBK_CONTROLLER_SYMBOL_PROCESS_CONTEXT;

typedef struct _BK_CONTROLLER_SYMBOL_CACHE_ENTRY
{
    BOOL Valid;
    DWORD ProcessId;
    UINT64 Address;
    ULONGLONG LastAccessTick;
    WCHAR Text[BK_CONTROLLER_SYMBOL_MAX_TEXT_CHARS];
    WCHAR Path[MAX_PATH];
} BK_CONTROLLER_SYMBOL_CACHE_ENTRY, *PBK_CONTROLLER_SYMBOL_CACHE_ENTRY;

typedef struct _BK_CONTROLLER_SYMBOL_REQUEST
{
    DWORD ProcessId;
    UINT64 Address;
} BK_CONTROLLER_SYMBOL_REQUEST, *PBK_CONTROLLER_SYMBOL_REQUEST;

static SRWLOCK g_SymbolServiceLock = SRWLOCK_INIT;
static OwnedCriticalSection g_SymbolQueueLock;
static UniqueHandle g_SymbolQueueEvent;
static UniqueHandle g_SymbolWorkerThreads[BK_CONTROLLER_SYMBOL_WORKER_THREADS];
static volatile LONG g_SymbolServiceStarted = 0;
static volatile LONG g_SymbolQueueDepth = 0;
static DWORD g_SymbolQueueHead = 0;
static DWORD g_SymbolQueueTail = 0;
static BK_CONTROLLER_SYMBOL_REQUEST g_SymbolQueue[BK_CONTROLLER_SYMBOL_MAX_QUEUE_DEPTH];
static BK_CONTROLLER_SYMBOL_CACHE_ENTRY g_SymbolCache[BK_CONTROLLER_SYMBOL_MAX_CACHE_ENTRIES];
static BK_CONTROLLER_SYMBOL_PROCESS_CONTEXT g_SymbolContexts[BK_CONTROLLER_SYMBOL_MAX_PROCESS_CONTEXTS];
static BK_CONTROLLER_SYMBOL_PROCESS_CONTEXT g_KernelContext;

static VOID ControllerSymbolServicePrimeAddress(_In_ DWORD ProcessId, _In_ UINT64 Address);
static BOOL ControllerSymbolServiceResolveAddress(_In_ DWORD ProcessId, _In_ UINT64 Address,
                                                  _Out_writes_z_(TextChars) PWSTR Text, _In_ size_t TextChars,
                                                  _Out_opt_ PWSTR Path, _In_ size_t PathChars);
static BOOL ControllerSymbolServiceFormatModuleSectionOffset(_In_ const BK_CONTROLLER_SYMBOL_MODULE_ENTRY *Module,
                                                             _In_ UINT64 Address, _Out_writes_z_(TextChars) PWSTR Text,
                                                             _In_ size_t TextChars);

static BOOL ControllerSymbolServiceIsKernelAddress(_In_ UINT64 Address)
{
#if defined(_WIN64)
    return ((Address >> 47) == 0x1FFFFull);
#else
    UNREFERENCED_PARAMETER(Address);
    return FALSE;
#endif
}

static VOID ControllerSymbolServiceAppendReasonToken(_Inout_updates_z_(ReasonChars) PWSTR Reason,
                                                     _In_ size_t ReasonChars, _In_z_ PCWSTR Key, _In_z_ PCWSTR Value)
{
    size_t used;

    if (Reason == NULL || ReasonChars == 0 || Key == NULL || Value == NULL || Value[0] == L'\0')
    {
        return;
    }

    used = wcslen(Reason);
    if (used >= ReasonChars - 1)
    {
        return;
    }

    if (FAILED(StringCchPrintfW(Reason + used, ReasonChars - used, L" %ws=%ws", Key, Value)))
    {
        Reason[ReasonChars - 1] = L'\0';
    }
}

static VOID ControllerSymbolServiceTryAppendStackFrameSymbol(_Inout_ BKIPC_ETW_EVENT *Event, _In_ DWORD ProcessId,
                                                             _In_ DWORD FrameIndex)
{
    WCHAR text[BK_CONTROLLER_SYMBOL_MAX_TEXT_CHARS];
    WCHAR key[32];

    if (Event == NULL || FrameIndex >= Event->StackCount || FrameIndex >= RTL_NUMBER_OF(Event->Stack) ||
        Event->Stack[FrameIndex] == 0)
    {
        return;
    }

    if (ControllerSymbolServiceResolveAddress(ProcessId, Event->Stack[FrameIndex], text, RTL_NUMBER_OF(text), NULL, 0))
    {
        if (SUCCEEDED(StringCchPrintfW(key, RTL_NUMBER_OF(key), L"stack%luSymbol", (unsigned long)FrameIndex)))
        {
            ControllerSymbolServiceAppendReasonToken(Event->Reason, RTL_NUMBER_OF(Event->Reason), key, text);
        }
    }
    else
    {
        ControllerSymbolServicePrimeAddress(ProcessId, Event->Stack[FrameIndex]);
    }
}

static VOID ControllerSymbolServiceStoreCacheEntry(_In_ DWORD ProcessId, _In_ UINT64 Address, _In_z_ PCWSTR Text,
                                                   _In_opt_z_ PCWSTR Path)
{
    DWORD i;
    DWORD candidate = 0;
    ULONGLONG oldestTick = MAXULONGLONG;
    ULONGLONG nowTick = GetTickCount64();

    AcquireSRWLockExclusive(&g_SymbolServiceLock);
    for (i = 0; i < RTL_NUMBER_OF(g_SymbolCache); ++i)
    {
        if (g_SymbolCache[i].Valid && g_SymbolCache[i].ProcessId == ProcessId && g_SymbolCache[i].Address == Address)
        {
            g_SymbolCache[i].LastAccessTick = nowTick;
            (void)StringCchCopyW(g_SymbolCache[i].Text, RTL_NUMBER_OF(g_SymbolCache[i].Text), Text);
            if (Path != NULL)
            {
                (void)StringCchCopyW(g_SymbolCache[i].Path, RTL_NUMBER_OF(g_SymbolCache[i].Path), Path);
            }
            ReleaseSRWLockExclusive(&g_SymbolServiceLock);
            return;
        }

        if (!g_SymbolCache[i].Valid)
        {
            candidate = i;
            oldestTick = 0;
            break;
        }

        if (g_SymbolCache[i].LastAccessTick < oldestTick)
        {
            oldestTick = g_SymbolCache[i].LastAccessTick;
            candidate = i;
        }
    }

    g_SymbolCache[candidate].Valid = TRUE;
    g_SymbolCache[candidate].ProcessId = ProcessId;
    g_SymbolCache[candidate].Address = Address;
    g_SymbolCache[candidate].LastAccessTick = nowTick;
    (void)StringCchCopyW(g_SymbolCache[candidate].Text, RTL_NUMBER_OF(g_SymbolCache[candidate].Text), Text);
    if (Path != NULL)
    {
        (void)StringCchCopyW(g_SymbolCache[candidate].Path, RTL_NUMBER_OF(g_SymbolCache[candidate].Path), Path);
    }
    else
    {
        g_SymbolCache[candidate].Path[0] = L'\0';
    }
    ReleaseSRWLockExclusive(&g_SymbolServiceLock);
}

static BOOL ControllerSymbolServiceTryGetCached(_In_ DWORD ProcessId, _In_ UINT64 Address,
                                                _Out_writes_z_(TextChars) PWSTR Text, _In_ size_t TextChars,
                                                _Out_opt_ PWSTR Path, _In_ size_t PathChars)
{
    DWORD i;
    ULONGLONG nowTick = GetTickCount64();

    if (Text == NULL || TextChars == 0 || Address == 0)
    {
        return FALSE;
    }

    AcquireSRWLockShared(&g_SymbolServiceLock);
    for (i = 0; i < RTL_NUMBER_OF(g_SymbolCache); ++i)
    {
        if (!g_SymbolCache[i].Valid || g_SymbolCache[i].ProcessId != ProcessId || g_SymbolCache[i].Address != Address)
        {
            continue;
        }

        (void)StringCchCopyW(Text, TextChars, g_SymbolCache[i].Text);
        if (Path != NULL && PathChars != 0)
        {
            (void)StringCchCopyW(Path, PathChars, g_SymbolCache[i].Path);
        }
        ReleaseSRWLockShared(&g_SymbolServiceLock);

        AcquireSRWLockExclusive(&g_SymbolServiceLock);
        g_SymbolCache[i].LastAccessTick = nowTick;
        ReleaseSRWLockExclusive(&g_SymbolServiceLock);
        return TRUE;
    }
    ReleaseSRWLockShared(&g_SymbolServiceLock);
    return FALSE;
}

static BOOL ControllerSymbolServiceHasCached(_In_ DWORD ProcessId, _In_ UINT64 Address)
{
    DWORD i;
    BOOL found = FALSE;

    if (Address == 0)
    {
        return FALSE;
    }

    AcquireSRWLockShared(&g_SymbolServiceLock);
    for (i = 0; i < RTL_NUMBER_OF(g_SymbolCache); ++i)
    {
        if (g_SymbolCache[i].Valid && g_SymbolCache[i].ProcessId == ProcessId && g_SymbolCache[i].Address == Address)
        {
            found = TRUE;
            break;
        }
    }
    ReleaseSRWLockShared(&g_SymbolServiceLock);
    return found;
}

static VOID ControllerSymbolServicePrimeAddress(_In_ DWORD ProcessId, _In_ UINT64 Address)
{
    DWORD nextTail;

    if (Address == 0 || InterlockedCompareExchange(&g_SymbolServiceStarted, 0, 0) == 0)
    {
        return;
    }

    if (ControllerSymbolServiceHasCached(ProcessId, Address))
    {
        return;
    }

    EnterCriticalSection(g_SymbolQueueLock.get());
    nextTail = (g_SymbolQueueTail + 1u) % RTL_NUMBER_OF(g_SymbolQueue);
    if (nextTail != g_SymbolQueueHead)
    {
        g_SymbolQueue[g_SymbolQueueTail].ProcessId = ProcessId;
        g_SymbolQueue[g_SymbolQueueTail].Address = Address;
        g_SymbolQueueTail = nextTail;
        InterlockedIncrement(&g_SymbolQueueDepth);
        if (g_SymbolQueueEvent)
        {
            (void)SetEvent(g_SymbolQueueEvent.get());
        }
    }
    LeaveCriticalSection(g_SymbolQueueLock.get());
}

static BOOL ControllerSymbolServiceDequeue(_Out_ PBK_CONTROLLER_SYMBOL_REQUEST Request)
{
    BOOL found = FALSE;

    if (Request == NULL)
    {
        return FALSE;
    }

    EnterCriticalSection(g_SymbolQueueLock.get());
    if (g_SymbolQueueHead != g_SymbolQueueTail)
    {
        *Request = g_SymbolQueue[g_SymbolQueueHead];
        g_SymbolQueueHead = (g_SymbolQueueHead + 1u) % RTL_NUMBER_OF(g_SymbolQueue);
        InterlockedDecrement(&g_SymbolQueueDepth);
        found = TRUE;
    }
    LeaveCriticalSection(g_SymbolQueueLock.get());
    return found;
}

static DWORD ControllerSymbolServiceChooseContextSlot(_In_ DWORD ProcessId)
{
    DWORD i;
    DWORD candidate = 0;
    ULONGLONG oldestTick = MAXULONGLONG;

    for (i = 0; i < RTL_NUMBER_OF(g_SymbolContexts); ++i)
    {
        if (g_SymbolContexts[i].Valid && g_SymbolContexts[i].ProcessId == ProcessId)
        {
            return i;
        }

        if (!g_SymbolContexts[i].Valid)
        {
            return i;
        }

        if (g_SymbolContexts[i].LastRefreshTick < oldestTick)
        {
            oldestTick = g_SymbolContexts[i].LastRefreshTick;
            candidate = i;
        }
    }

    return candidate;
}

static VOID ControllerSymbolServiceRefreshKernelModules(VOID)
{
    LPVOID bases[BK_CONTROLLER_SYMBOL_MAX_KERNEL_MODULES];
    DWORD bytesNeeded = 0;
    DWORD count;
    DWORD i;
    BK_CONTROLLER_SYMBOL_PROCESS_CONTEXT fresh;

    ZeroMemory(&fresh, sizeof(fresh));
    fresh.Valid = TRUE;
    fresh.ProcessId = 0;
    fresh.LastRefreshTick = GetTickCount64();

    if (!EnumDeviceDrivers(bases, sizeof(bases), &bytesNeeded) || bytesNeeded == 0)
    {
        return;
    }

    count = bytesNeeded / sizeof(bases[0]);
    if (count > BK_CONTROLLER_SYMBOL_MAX_KERNEL_MODULES)
    {
        count = BK_CONTROLLER_SYMBOL_MAX_KERNEL_MODULES;
    }

    for (i = 0; i < count && fresh.ModuleCount < RTL_NUMBER_OF(fresh.Modules); ++i)
    {
        WCHAR path[MAX_PATH];
        WCHAR name[MAX_MODULE_NAME32 + 1];
        UINT64 base = (UINT64)(ULONG_PTR)bases[i];
        DWORD slot = fresh.ModuleCount;

        path[0] = L'\0';
        name[0] = L'\0';
        (void)GetDeviceDriverFileNameW(bases[i], path, RTL_NUMBER_OF(path));
        (void)GetDeviceDriverBaseNameW(bases[i], name, RTL_NUMBER_OF(name));

        fresh.Modules[slot].Base = base;
        fresh.Modules[slot].End = 0;
        (void)StringCchCopyW(fresh.Modules[slot].Name, RTL_NUMBER_OF(fresh.Modules[slot].Name),
                             (name[0] != L'\0') ? name : L"<kernel>");
        (void)StringCchCopyW(fresh.Modules[slot].Path, RTL_NUMBER_OF(fresh.Modules[slot].Path), path);
        fresh.ModuleCount += 1;
    }

    for (i = 0; i < fresh.ModuleCount; ++i)
    {
        if (i + 1 < fresh.ModuleCount)
        {
            fresh.Modules[i].End = fresh.Modules[i + 1].Base;
        }
        else
        {
            fresh.Modules[i].End = fresh.Modules[i].Base + 0x2000000ull;
        }
    }

    AcquireSRWLockExclusive(&g_SymbolServiceLock);
    g_KernelContext = fresh;
    ReleaseSRWLockExclusive(&g_SymbolServiceLock);
}

static BOOL ControllerSymbolServiceRefreshProcessContext(_In_ DWORD ProcessId)
{
    HANDLE snapshot;
    MODULEENTRY32W me32;
    BK_CONTROLLER_SYMBOL_PROCESS_CONTEXT fresh;
    DWORD slot;

    if (ProcessId == 0)
    {
        return FALSE;
    }

    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, ProcessId);
    if (snapshot == INVALID_HANDLE_VALUE)
    {
        return FALSE;
    }

    ZeroMemory(&fresh, sizeof(fresh));
    fresh.Valid = TRUE;
    fresh.ProcessId = ProcessId;
    fresh.LastRefreshTick = GetTickCount64();

    ZeroMemory(&me32, sizeof(me32));
    me32.dwSize = sizeof(me32);
    if (Module32FirstW(snapshot, &me32))
    {
        do
        {
            DWORD index;
            if (fresh.ModuleCount >= RTL_NUMBER_OF(fresh.Modules))
            {
                break;
            }

            index = fresh.ModuleCount;
            fresh.Modules[index].Base = (UINT64)(ULONG_PTR)me32.modBaseAddr;
            fresh.Modules[index].End = fresh.Modules[index].Base + (UINT64)me32.modBaseSize;
            (void)StringCchCopyW(fresh.Modules[index].Name, RTL_NUMBER_OF(fresh.Modules[index].Name), me32.szModule);
            (void)StringCchCopyW(fresh.Modules[index].Path, RTL_NUMBER_OF(fresh.Modules[index].Path), me32.szExePath);
            fresh.ModuleCount += 1;
        } while (Module32NextW(snapshot, &me32));
    }

    CloseHandle(snapshot);

    if (fresh.ModuleCount == 0)
    {
        return FALSE;
    }

    AcquireSRWLockExclusive(&g_SymbolServiceLock);
    slot = ControllerSymbolServiceChooseContextSlot(ProcessId);
    g_SymbolContexts[slot] = fresh;
    ReleaseSRWLockExclusive(&g_SymbolServiceLock);
    return TRUE;
}

static BOOL ControllerSymbolServiceFindModule(_In_ DWORD ProcessId, _In_ UINT64 Address,
                                              _Out_ BK_CONTROLLER_SYMBOL_MODULE_ENTRY *Module)
{
    DWORD i;
    BOOL kernel = ControllerSymbolServiceIsKernelAddress(Address);
    BOOL found = FALSE;
    ULONGLONG nowTick = GetTickCount64();

    if (Module == NULL || Address == 0)
    {
        return FALSE;
    }

    if (kernel)
    {
        AcquireSRWLockShared(&g_SymbolServiceLock);
        if (!g_KernelContext.Valid ||
            nowTick - g_KernelContext.LastRefreshTick > BK_CONTROLLER_SYMBOL_KERNEL_REFRESH_MS)
        {
            ReleaseSRWLockShared(&g_SymbolServiceLock);
            ControllerSymbolServiceRefreshKernelModules();
            AcquireSRWLockShared(&g_SymbolServiceLock);
        }

        for (i = 0; i < g_KernelContext.ModuleCount; ++i)
        {
            if (Address >= g_KernelContext.Modules[i].Base && Address < g_KernelContext.Modules[i].End)
            {
                *Module = g_KernelContext.Modules[i];
                found = TRUE;
                break;
            }
        }
        ReleaseSRWLockShared(&g_SymbolServiceLock);
        return found;
    }

    AcquireSRWLockShared(&g_SymbolServiceLock);
    for (i = 0; i < RTL_NUMBER_OF(g_SymbolContexts); ++i)
    {
        if (!g_SymbolContexts[i].Valid || g_SymbolContexts[i].ProcessId != ProcessId)
        {
            continue;
        }

        if (nowTick - g_SymbolContexts[i].LastRefreshTick > BK_CONTROLLER_SYMBOL_PROCESS_REFRESH_MS)
        {
            ReleaseSRWLockShared(&g_SymbolServiceLock);
            if (!ControllerSymbolServiceRefreshProcessContext(ProcessId))
            {
                return FALSE;
            }
            AcquireSRWLockShared(&g_SymbolServiceLock);
            i = (DWORD)-1;
            continue;
        }

        for (DWORD moduleIndex = 0; moduleIndex < g_SymbolContexts[i].ModuleCount; ++moduleIndex)
        {
            if (Address >= g_SymbolContexts[i].Modules[moduleIndex].Base &&
                Address < g_SymbolContexts[i].Modules[moduleIndex].End)
            {
                *Module = g_SymbolContexts[i].Modules[moduleIndex];
                found = TRUE;
                break;
            }
        }
        break;
    }
    ReleaseSRWLockShared(&g_SymbolServiceLock);

    if (!found && ControllerSymbolServiceRefreshProcessContext(ProcessId))
    {
        AcquireSRWLockShared(&g_SymbolServiceLock);
        for (i = 0; i < RTL_NUMBER_OF(g_SymbolContexts); ++i)
        {
            DWORD moduleIndex;

            if (!g_SymbolContexts[i].Valid || g_SymbolContexts[i].ProcessId != ProcessId)
            {
                continue;
            }

            for (moduleIndex = 0; moduleIndex < g_SymbolContexts[i].ModuleCount; ++moduleIndex)
            {
                if (Address >= g_SymbolContexts[i].Modules[moduleIndex].Base &&
                    Address < g_SymbolContexts[i].Modules[moduleIndex].End)
                {
                    *Module = g_SymbolContexts[i].Modules[moduleIndex];
                    found = TRUE;
                    break;
                }
            }
            break;
        }
        ReleaseSRWLockShared(&g_SymbolServiceLock);
    }

    return found;
}

static BOOL ControllerSymbolServiceResolveAddress(_In_ DWORD ProcessId, _In_ UINT64 Address,
                                                  _Out_writes_z_(TextChars) PWSTR Text, _In_ size_t TextChars,
                                                  _Out_opt_ PWSTR Path, _In_ size_t PathChars)
{
    BK_CONTROLLER_SYMBOL_MODULE_ENTRY module;
    UINT64 displacement;

    if (Text == NULL || TextChars == 0 || Address == 0)
    {
        return FALSE;
    }

    Text[0] = L'\0';
    if (Path != NULL && PathChars != 0)
    {
        Path[0] = L'\0';
    }

    if (ControllerSymbolServiceTryGetCached(ProcessId, Address, Text, TextChars, Path, PathChars))
    {
        return TRUE;
    }

    if (!ControllerSymbolServiceFindModule(ProcessId, Address, &module))
    {
        return FALSE;
    }

    displacement = Address - module.Base;
    if (!ControllerSymbolServiceFormatModuleSectionOffset(&module, Address, Text, TextChars) &&
        FAILED(StringCchPrintfW(Text, TextChars, L"%ws+0x%llX", module.Name, (unsigned long long)displacement)))
    {
        return FALSE;
    }

    if (Path != NULL && PathChars != 0)
    {
        (void)StringCchCopyW(Path, PathChars, module.Path);
    }

    ControllerSymbolServiceStoreCacheEntry(ProcessId, Address, Text, module.Path);
    return TRUE;
}

static BOOL ControllerSymbolServiceFormatModuleSectionOffset(_In_ const BK_CONTROLLER_SYMBOL_MODULE_ENTRY *Module,
                                                             _In_ UINT64 Address, _Out_writes_z_(TextChars) PWSTR Text,
                                                             _In_ size_t TextChars)
{
    HANDLE fileHandle = INVALID_HANDLE_VALUE;
    HANDLE mappingHandle = NULL;
    PBYTE view = NULL;
    PIMAGE_DOS_HEADER dos;
    PIMAGE_NT_HEADERS nt;
    PIMAGE_SECTION_HEADER section;
    BOOL resolved = FALSE;
    WORD i;

    if (Module == NULL || Module->Path[0] == L'\0' || Text == NULL || TextChars == 0 || Address < Module->Base)
    {
        return FALSE;
    }

    fileHandle = CreateFileW(Module->Path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                             OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (fileHandle == INVALID_HANDLE_VALUE)
    {
        return FALSE;
    }

    mappingHandle = CreateFileMappingW(fileHandle, NULL, PAGE_READONLY, 0, 0, NULL);
    if (mappingHandle == NULL)
    {
        CloseHandle(fileHandle);
        return FALSE;
    }

    view = (PBYTE)MapViewOfFile(mappingHandle, FILE_MAP_READ, 0, 0, 0);
    if (view == NULL)
    {
        CloseHandle(mappingHandle);
        CloseHandle(fileHandle);
        return FALSE;
    }

    dos = (PIMAGE_DOS_HEADER)view;
    if (dos->e_magic == IMAGE_DOS_SIGNATURE)
    {
        nt = (PIMAGE_NT_HEADERS)(view + dos->e_lfanew);
        if (nt->Signature == IMAGE_NT_SIGNATURE)
        {
            UINT64 rva = Address - Module->Base;
            section = IMAGE_FIRST_SECTION(nt);
            for (i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section)
            {
                UINT32 sectionStart = section->VirtualAddress;
                UINT32 sectionSize = section->Misc.VirtualSize;
                CHAR rawName[9] = {0};
                WCHAR sectionName[16] = {0};
                PCWSTR printableName;
                UINT64 sectionOffset;
                size_t j;

                if (sectionSize == 0)
                {
                    sectionSize = section->SizeOfRawData;
                }
                if (sectionSize == 0 || rva < sectionStart || rva >= ((UINT64)sectionStart + sectionSize))
                {
                    continue;
                }

                CopyMemory(rawName, section->Name, sizeof(section->Name));
                for (j = 0; j < RTL_NUMBER_OF(sectionName) - 1 && rawName[j] != '\0'; ++j)
                {
                    sectionName[j] = (WCHAR)rawName[j];
                }
                sectionName[RTL_NUMBER_OF(sectionName) - 1] = L'\0';

                printableName = sectionName;
                while (*printableName == L'.')
                {
                    ++printableName;
                }
                if (*printableName == L'\0')
                {
                    printableName = L"text";
                }

                sectionOffset = rva - sectionStart;
                resolved = SUCCEEDED(StringCchPrintfW(Text, TextChars, L"%ws.%ws+0x%llX", Module->Name, printableName,
                                                      (unsigned long long)sectionOffset));
                break;
            }
        }
    }

    UnmapViewOfFile(view);
    CloseHandle(mappingHandle);
    CloseHandle(fileHandle);
    return resolved;
}

BOOL ControllerSymbolServiceResolveHookAddress(_In_ DWORD ProcessId, _In_ UINT64 Address,
                                               _Out_writes_z_(TextChars) PWSTR Text, _In_ size_t TextChars,
                                               _Out_opt_ PWSTR Path, _In_ size_t PathChars)
{
    return ControllerSymbolServiceResolveAddress(ProcessId, Address, Text, TextChars, Path, PathChars);
}

VOID ControllerSymbolServicePrimeHookAddress(_In_ DWORD ProcessId, _In_ UINT64 Address)
{
    ControllerSymbolServicePrimeAddress(ProcessId, Address);
}

static DWORD ControllerSymbolServiceResolvePrimaryPid(_In_ const BKIPC_ETW_EVENT *Event)
{
    if (Event == NULL)
    {
        return 0;
    }

    if (Event->ProcessId != 0 && Event->ProcessId <= MAXDWORD)
    {
        return (DWORD)Event->ProcessId;
    }
    if (Event->CallerPid != 0 && Event->CallerPid <= MAXDWORD)
    {
        return (DWORD)Event->CallerPid;
    }
    return Event->EventProcessId;
}

static DWORD ControllerSymbolServiceResolveExecutionPid(_In_ const BKIPC_ETW_EVENT *Event)
{
    DWORD pid;

    if (Event == NULL)
    {
        return 0;
    }

    if (Event->TargetPid != 0 && Event->TargetPid <= MAXDWORD &&
        (Event->Family == BlackbirdIpcEtwFamilyThread || Event->Family == BlackbirdIpcEtwFamilyProcess ||
         (Event->Family == BlackbirdIpcEtwFamilyUserHook && Event->TargetPid != Event->ProcessId)))
    {
        return (DWORD)Event->TargetPid;
    }

    pid = ControllerSymbolServiceResolvePrimaryPid(Event);
    return pid;
}

static VOID ControllerSymbolServiceTryAppendHookArgSymbol(_Inout_ BKIPC_ETW_EVENT *Event, _In_ DWORD ProcessId,
                                                          _In_ UINT32 ArgIndex, _In_z_ PCWSTR TokenName)
{
    WCHAR text[BK_CONTROLLER_SYMBOL_MAX_TEXT_CHARS];

    if (Event == NULL || ProcessId == 0 || TokenName == NULL || TokenName[0] == L'\0' ||
        ArgIndex >= Event->HookArgCount || ArgIndex >= RTL_NUMBER_OF(Event->HookArgs) || Event->HookArgs[ArgIndex] == 0)
    {
        return;
    }

    if (ControllerSymbolServiceResolveAddress(ProcessId, Event->HookArgs[ArgIndex], text, RTL_NUMBER_OF(text), NULL, 0))
    {
        ControllerSymbolServiceAppendReasonToken(Event->Reason, RTL_NUMBER_OF(Event->Reason), TokenName, text);
    }
    else
    {
        ControllerSymbolServicePrimeAddress(ProcessId, Event->HookArgs[ArgIndex]);
    }
}

static DWORD WINAPI ControllerSymbolServiceWorkerProc(_In_ LPVOID Context)
{
    BK_CONTROLLER_SYMBOL_REQUEST request;
    WCHAR text[BK_CONTROLLER_SYMBOL_MAX_TEXT_CHARS];
    WCHAR path[MAX_PATH];

    UNREFERENCED_PARAMETER(Context);

    while (!ControllerShouldStop())
    {
        if (!ControllerSymbolServiceDequeue(&request))
        {
            if (!g_SymbolQueueEvent)
            {
                break;
            }

            (void)WaitForSingleObject(g_SymbolQueueEvent.get(), 125);
            continue;
        }

        (void)ControllerSymbolServiceResolveAddress(request.ProcessId, request.Address, text, RTL_NUMBER_OF(text), path,
                                                    RTL_NUMBER_OF(path));
    }

    return 0;
}

BOOL ControllerSymbolServiceStart(VOID)
{
    if (InterlockedCompareExchange(&g_SymbolServiceStarted, 1, 0) != 0)
    {
        return TRUE;
    }

    ZeroMemory(g_SymbolCache, sizeof(g_SymbolCache));
    ZeroMemory(g_SymbolContexts, sizeof(g_SymbolContexts));
    ZeroMemory(&g_KernelContext, sizeof(g_KernelContext));
    g_SymbolQueueHead = 0;
    g_SymbolQueueTail = 0;
    InterlockedExchange(&g_SymbolQueueDepth, 0);

    g_SymbolQueueEvent.reset(CreateEventW(NULL, FALSE, FALSE, NULL));
    if (!g_SymbolQueueEvent)
    {
        InterlockedExchange(&g_SymbolServiceStarted, 0);
        return FALSE;
    }

    ControllerSymbolServiceRefreshKernelModules();

    DWORD i = 0;
    for (; i < RTL_NUMBER_OF(g_SymbolWorkerThreads); ++i)
    {
        g_SymbolWorkerThreads[i].reset(CreateThread(NULL, 0, ControllerSymbolServiceWorkerProc, NULL, 0, NULL));
        if (!g_SymbolWorkerThreads[i])
        {
            ControllerLog("[WARN] controller symbol service: worker start failed index=%lu err=%lu\n", (unsigned long)i,
                          GetLastError());
            break;
        }
    }

    ControllerLog("[*] controller symbol service started workers=%lu\n", (unsigned long)i);
    return TRUE;
}

VOID ControllerSymbolServiceStop(VOID)
{
    if (InterlockedCompareExchange(&g_SymbolServiceStarted, 0, 1) == 0)
    {
        return;
    }

    if (g_SymbolQueueEvent)
    {
        (void)SetEvent(g_SymbolQueueEvent.get());
    }

    for (DWORD i = 0; i < RTL_NUMBER_OF(g_SymbolWorkerThreads); ++i)
    {
        if (g_SymbolWorkerThreads[i])
        {
            (void)WaitForSingleObject(g_SymbolWorkerThreads[i].get(), 2000);
            g_SymbolWorkerThreads[i].reset();
        }
    }

    g_SymbolQueueEvent.reset();
}

VOID ControllerSymbolServiceEnrichEvent(_Inout_ BKIPC_ETW_EVENT *Event)
{
    WCHAR text[BK_CONTROLLER_SYMBOL_MAX_TEXT_CHARS];
    WCHAR path[MAX_PATH];
    DWORD originPid;
    DWORD execPid;
    DWORD i;
    DWORD framesToPrime;

    if (Event == NULL || InterlockedCompareExchange(&g_SymbolServiceStarted, 0, 0) == 0)
    {
        return;
    }

    originPid = ControllerSymbolServiceResolvePrimaryPid(Event);
    execPid = ControllerSymbolServiceResolveExecutionPid(Event);

    if (Event->OriginAddress != 0 &&
        ControllerSymbolServiceResolveAddress(originPid, Event->OriginAddress, text, RTL_NUMBER_OF(text), path,
                                              RTL_NUMBER_OF(path)))
    {
        if (Event->OriginPath[0] == L'\0' && path[0] != L'\0')
        {
            (void)StringCchCopyW(Event->OriginPath, RTL_NUMBER_OF(Event->OriginPath), path);
        }
        ControllerSymbolServiceAppendReasonToken(Event->Reason, RTL_NUMBER_OF(Event->Reason), L"originSymbol", text);
    }
    else if (Event->OriginAddress != 0)
    {
        ControllerSymbolServicePrimeAddress(originPid, Event->OriginAddress);
    }

    if (Event->StartAddress != 0 &&
        ControllerSymbolServiceResolveAddress(execPid, Event->StartAddress, text, RTL_NUMBER_OF(text), NULL, 0))
    {
        ControllerSymbolServiceAppendReasonToken(Event->Reason, RTL_NUMBER_OF(Event->Reason), L"startSymbol", text);
    }
    else if (Event->StartAddress != 0)
    {
        ControllerSymbolServicePrimeAddress(execPid, Event->StartAddress);
    }

    framesToPrime = (Event->StackCount > RTL_NUMBER_OF(Event->Stack)) ? RTL_NUMBER_OF(Event->Stack) : Event->StackCount;
    for (i = 0; i < framesToPrime; ++i)
    {
        if (Event->Stack[i] != 0)
        {
            ControllerSymbolServicePrimeAddress(originPid, Event->Stack[i]);
        }
    }

    for (i = 0; i < framesToPrime; ++i)
    {
        ControllerSymbolServiceTryAppendStackFrameSymbol(Event, originPid, i);
    }

    if (Event->Family == BlackbirdIpcEtwFamilyUserHook && Event->Operation[0] != '\0')
    {
        if (lstrcmpiA(Event->Operation, "NtCreateThreadEx") == 0)
        {
            ControllerSymbolServiceTryAppendHookArgSymbol(Event, execPid, 3u, L"startRoutineSymbol");
        }
        else if (lstrcmpiA(Event->Operation, "NtQueueApcThread") == 0)
        {
            ControllerSymbolServiceTryAppendHookArgSymbol(Event, execPid, 1u, L"apcRoutineSymbol");
        }
        else if (lstrcmpiA(Event->Operation, "NtQueueApcThreadEx") == 0)
        {
            ControllerSymbolServiceTryAppendHookArgSymbol(Event, execPid, 2u, L"apcRoutineSymbol");
        }
        else if (lstrcmpiA(Event->Operation, "NtQueueApcThreadEx2") == 0)
        {
            ControllerSymbolServiceTryAppendHookArgSymbol(Event, execPid, 3u, L"apcRoutineSymbol");
        }
        else if (lstrcmpiA(Event->Operation, "NtMapViewOfSectionEx") == 0)
        {
            ControllerSymbolServiceTryAppendHookArgSymbol(Event, execPid, 2u, L"mappedBaseSymbol");
        }
    }
}
