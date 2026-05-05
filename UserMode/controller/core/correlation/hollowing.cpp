#include "../controller_private.h"
#include <tlhelp32.h>
#include <psapi.h>

#pragma comment(lib, "psapi.lib")

#define BK_HOLLOW_MARK_CREATE_SUSPENDED 0x00000001ull
#define BK_HOLLOW_MARK_TI_ALLOC_RW_LARGE 0x00000002ull
#define BK_HOLLOW_MARK_TI_WRITE_VM 0x00000004ull
#define BK_HOLLOW_MARK_TI_PROTECT_RX 0x00000008ull
#define BK_HOLLOW_MARK_THREAD_START_NON_IMAGE_EXEC 0x00000010ull
#define BK_HOLLOW_MARK_THREAD_START_OUTSIDE_IMAGE 0x00000020ull
#define BK_HOLLOW_MARK_THREAD_CONTEXT_INTENT 0x00000040ull
#define BK_HOLLOW_MARK_REMOTE_THREAD_INTENT 0x00000080ull
#define BK_HOLLOW_MARK_IMAGE_DRIFT 0x00000100ull
#define BK_HOLLOW_MARK_TXF_SUSPECT 0x00000200ull
#define BK_HOLLOW_MARK_UNMAP_VIEW 0x00000400ull
#define BK_HOLLOW_MARK_PROCESS_HANDLE_INTENT 0x00000800ull

#ifndef BK_INTENT_THREAD_CONTEXT
#define BK_INTENT_THREAD_CONTEXT 0x00000002u
#endif

#define BK_CONTROLLER_MANUAL_MAP_PROBE_QUEUE_CAPACITY 128u
#define BK_HOLLOW_EXEC_KIND_NONE 0u
#define BK_HOLLOW_EXEC_KIND_LOADER 1u
#define BK_HOLLOW_EXEC_KIND_PRIVATE_EXEC 2u
#define BK_MANUAL_MAP_TRAIT_PE_HEADER 0x00000001u
#define BK_MANUAL_MAP_TRAIT_SECTIONS 0x00000002u
#define BK_MANUAL_MAP_TRAIT_IMPORTS 0x00000004u
#define BK_MANUAL_MAP_TRAIT_RELOCS 0x00000008u
#define BK_MANUAL_MAP_TRAIT_TLS 0x00000010u
#define BK_MANUAL_MAP_TRAIT_EXCEPTION 0x00000020u

typedef struct _BK_CONTROLLER_MANUAL_MAP_PROBE_REQUEST
{
    BOOL Active;
    DWORD ActorPid;
    DWORD TargetPid;
    ULONGLONG BaseHint;
    ULONGLONG SizeHint;
    ULONGLONG EnqueueTick;
} BK_CONTROLLER_MANUAL_MAP_PROBE_REQUEST, *PBK_CONTROLLER_MANUAL_MAP_PROBE_REQUEST;

static OwnedCriticalSection g_ManualMapProbeLock;
static UniqueHandle g_ManualMapProbeEvent;
static UniqueHandle g_ManualMapProbeThread;
static BK_CONTROLLER_MANUAL_MAP_PROBE_REQUEST g_ManualMapProbeQueue[BK_CONTROLLER_MANUAL_MAP_PROBE_QUEUE_CAPACITY];
static BOOL ControllerIsExecutableProtect(_In_ ULONG Protect);
static BOOL ControllerProbePeHeaderAtBase(_In_ HANDLE ProcessHandle, _In_ ULONGLONG BaseAddress);
static BOOL ControllerProbePeImageTraitsAtBase(_In_ HANDLE ProcessHandle, _In_ ULONGLONG BaseAddress,
                                               _Out_opt_ DWORD *Traits);
static VOID ControllerReconcileRemoteHandlesForPair(_In_ DWORD ActorPid, _In_ DWORD TargetPid);
static VOID ControllerEvaluateHollowEntryLocked(_Inout_ PBK_CONTROLLER_HOLLOW_ENTRY Entry, _In_ ULONGLONG NowTick);
static VOID ControllerApplyHollowMark(_In_ DWORD ActorPid, _In_ DWORD TargetPid, _In_ UINT64 Mark,
                                      _In_ ULONGLONG AuxBase, _In_ ULONGLONG AuxSize, _In_ ULONG AuxProtect);

static BOOL ControllerTryResolveRemoteModuleBase(_In_ DWORD TargetPid, _In_z_ PCWSTR ModuleName,
                                                 _Out_ ULONGLONG *BaseAddress)
{
    HANDLE snapshot;
    MODULEENTRY32W moduleEntry;

    if (BaseAddress == NULL)
    {
        return FALSE;
    }
    *BaseAddress = 0;

    if (TargetPid == 0 || ModuleName == NULL || ModuleName[0] == L'\0')
    {
        return FALSE;
    }

    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, TargetPid);
    if (snapshot == INVALID_HANDLE_VALUE)
    {
        return FALSE;
    }

    ZeroMemory(&moduleEntry, sizeof(moduleEntry));
    moduleEntry.dwSize = sizeof(moduleEntry);
    if (!Module32FirstW(snapshot, &moduleEntry))
    {
        (void)CloseHandle(snapshot);
        return FALSE;
    }

    do
    {
        if (_wcsicmp(moduleEntry.szModule, ModuleName) == 0 || _wcsicmp(moduleEntry.szExePath, ModuleName) == 0)
        {
            *BaseAddress = (ULONGLONG)(ULONG_PTR)moduleEntry.modBaseAddr;
            (void)CloseHandle(snapshot);
            return TRUE;
        }
    } while (Module32NextW(snapshot, &moduleEntry));

    (void)CloseHandle(snapshot);
    return FALSE;
}

static BOOL ControllerTryResolveRemoteExportAddress(_In_ DWORD TargetPid, _In_z_ PCWSTR ModuleName,
                                                    _In_z_ PCSTR ExportName, _Out_ ULONGLONG *Address)
{
    HMODULE localModule;
    FARPROC localExport;
    ULONGLONG remoteBase = 0;
    ULONGLONG rva;

    if (Address == NULL)
    {
        return FALSE;
    }
    *Address = 0;

    if (TargetPid == 0 || ModuleName == NULL || ExportName == NULL || ExportName[0] == '\0')
    {
        return FALSE;
    }

    localModule = GetModuleHandleW(ModuleName);
    if (localModule == NULL)
    {
        return FALSE;
    }

    localExport = GetProcAddress(localModule, ExportName);
    if (localExport == NULL)
    {
        return FALSE;
    }

    if (!ControllerTryResolveRemoteModuleBase(TargetPid, ModuleName, &remoteBase) || remoteBase == 0)
    {
        return FALSE;
    }

    rva = (ULONGLONG)((ULONG_PTR)localExport - (ULONG_PTR)localModule);
    *Address = remoteBase + rva;
    return TRUE;
}

static BOOL ControllerSampleLooksLikeDllPath(_In_reads_bytes_(SampleSize) const BYTE *Sample, _In_ UINT32 SampleSize)
{
    CHAR ansi[BKIPC_MAX_ETW_DEEP_SAMPLE + 1];
    WCHAR wide[(BKIPC_MAX_ETW_DEEP_SAMPLE / sizeof(WCHAR)) + 1];
    UINT32 copyBytes;
    UINT32 i;

    if (Sample == NULL || SampleSize < 8u)
    {
        return FALSE;
    }

    copyBytes = (SampleSize < BKIPC_MAX_ETW_DEEP_SAMPLE) ? SampleSize : BKIPC_MAX_ETW_DEEP_SAMPLE;
    ZeroMemory(ansi, sizeof(ansi));
    ZeroMemory(wide, sizeof(wide));

    CopyMemory(ansi, Sample, copyBytes);
    ansi[copyBytes] = '\0';
    if (ControllerAsciiContainsInsensitive(ansi, ".dll") || ControllerAsciiContainsInsensitive(ansi, "\\") ||
        ControllerAsciiContainsInsensitive(ansi, "/"))
    {
        return TRUE;
    }

    copyBytes = copyBytes & ~1u;
    if (copyBytes < sizeof(WCHAR) * 4u)
    {
        return FALSE;
    }

    CopyMemory(wide, Sample, copyBytes);
    wide[copyBytes / sizeof(WCHAR)] = L'\0';
    for (i = 0; wide[i] != L'\0'; ++i)
    {
        if (wide[i] < 0x20 && wide[i] != L'\\' && wide[i] != L'/' && wide[i] != L'.')
        {
            break;
        }
    }
    if (wide[0] == L'\0')
    {
        return FALSE;
    }

    return (ControllerWideContainsInsensitive(wide, L".dll") || ControllerWideContainsInsensitive(wide, L"\\") ||
            ControllerWideContainsInsensitive(wide, L"/"));
}

#define BK_SYSTEM_EXTENDED_HANDLE_INFORMATION_CLASS 64u
#define BK_STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)

typedef NTSTATUS(NTAPI *BK_CONTROLLER_NT_QUERY_SYSTEM_INFORMATION_FN)(_In_ ULONG SystemInformationClass,
                                                                      _Out_writes_bytes_opt_(SystemInformationLength)
                                                                          PVOID SystemInformation,
                                                                      _In_ ULONG SystemInformationLength,
                                                                      _Out_opt_ PULONG ReturnLength);

typedef struct _BK_CONTROLLER_SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
{
    PVOID Object;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR HandleValue;
    ULONG GrantedAccess;
    USHORT CreatorBackTraceIndex;
    USHORT ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
} BK_CONTROLLER_SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, *PBK_CONTROLLER_SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

typedef struct _BK_CONTROLLER_SYSTEM_HANDLE_INFORMATION_EX
{
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    BK_CONTROLLER_SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
} BK_CONTROLLER_SYSTEM_HANDLE_INFORMATION_EX, *PBK_CONTROLLER_SYSTEM_HANDLE_INFORMATION_EX;

static BOOL ControllerHandleAccessLooksProcessInjectionCapable(_In_ ULONG GrantedAccess)
{
    return ((GrantedAccess & (PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD | PROCESS_DUP_HANDLE)) !=
            0) ||
           ((GrantedAccess & PROCESS_ALL_ACCESS) == PROCESS_ALL_ACCESS);
}

static BOOL ControllerHandleAccessLooksThreadInjectionCapable(_In_ ULONG GrantedAccess)
{
    return ((GrantedAccess &
             (THREAD_SET_CONTEXT | THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION)) != 0) ||
           ((GrantedAccess & THREAD_ALL_ACCESS) == THREAD_ALL_ACCESS);
}

static VOID ControllerReconcileRemoteHandlesForPair(_In_ DWORD ActorPid, _In_ DWORD TargetPid)
{
    HMODULE ntdll;
    BK_CONTROLLER_NT_QUERY_SYSTEM_INFORMATION_FN ntQuerySystemInformation;
    BYTE *buffer = NULL;
    ULONG bufferSize = 1u << 20;
    ULONG returnLength = 0;
    NTSTATUS status;
    HANDLE actorProcess = NULL;
    PBK_CONTROLLER_SYSTEM_HANDLE_INFORMATION_EX handleInfo;
    ULONG_PTR i;
    ULONG_PTR handleCount;
    ULONG_PTR maxHandleCount;
    SIZE_T handleHeaderBytes;
    UINT64 marks = 0;

    if (ActorPid == 0 || TargetPid == 0 || ActorPid == TargetPid)
    {
        return;
    }

    ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll == NULL)
    {
        return;
    }
    ntQuerySystemInformation =
        (BK_CONTROLLER_NT_QUERY_SYSTEM_INFORMATION_FN)GetProcAddress(ntdll, "NtQuerySystemInformation");
    if (ntQuerySystemInformation == NULL)
    {
        return;
    }

    for (;;)
    {
        buffer = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bufferSize);
        if (buffer == NULL)
        {
            return;
        }

        status =
            ntQuerySystemInformation(BK_SYSTEM_EXTENDED_HANDLE_INFORMATION_CLASS, buffer, bufferSize, &returnLength);
        if (status != BK_STATUS_INFO_LENGTH_MISMATCH)
        {
            break;
        }

        HeapFree(GetProcessHeap(), 0, buffer);
        buffer = NULL;
        if (returnLength > bufferSize)
        {
            bufferSize = returnLength + (64u * 1024u);
        }
        else
        {
            bufferSize *= 2u;
        }
        if (bufferSize > (64u << 20))
        {
            return;
        }
    }

    if (status < 0)
    {
        HeapFree(GetProcessHeap(), 0, buffer);
        return;
    }

    actorProcess = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, ActorPid);
    if (actorProcess == NULL)
    {
        HeapFree(GetProcessHeap(), 0, buffer);
        return;
    }

    handleInfo = (PBK_CONTROLLER_SYSTEM_HANDLE_INFORMATION_EX)buffer;
    handleHeaderBytes = sizeof(*handleInfo) - sizeof(handleInfo->Handles[0]);
    if (bufferSize < handleHeaderBytes)
    {
        CloseHandle(actorProcess);
        HeapFree(GetProcessHeap(), 0, buffer);
        return;
    }
    maxHandleCount = (bufferSize - handleHeaderBytes) / sizeof(handleInfo->Handles[0]);
    handleCount = handleInfo->NumberOfHandles;
    if (handleCount > maxHandleCount)
    {
        handleCount = maxHandleCount;
    }

    for (i = 0; i < handleCount; ++i)
    {
        const BK_CONTROLLER_SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX *entry = &handleInfo->Handles[i];
        HANDLE duplicateHandle = NULL;
        DWORD processId;
        DWORD threadProcessId;

        if ((DWORD)entry->UniqueProcessId != ActorPid)
        {
            continue;
        }
        if ((entry->GrantedAccess &
             (PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD | PROCESS_DUP_HANDLE |
              THREAD_SET_CONTEXT | THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION)) == 0)
        {
            continue;
        }
        if (!DuplicateHandle(actorProcess, (HANDLE)entry->HandleValue, GetCurrentProcess(), &duplicateHandle, 0, FALSE,
                             DUPLICATE_SAME_ACCESS))
        {
            continue;
        }

        processId = GetProcessId(duplicateHandle);
        if (processId == TargetPid && ControllerHandleAccessLooksProcessInjectionCapable(entry->GrantedAccess))
        {
            marks |= BK_HOLLOW_MARK_PROCESS_HANDLE_INTENT;
            if ((entry->GrantedAccess & (PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD)) != 0)
            {
                marks |= BK_HOLLOW_MARK_TI_ALLOC_RW_LARGE;
            }
        }

        threadProcessId = GetProcessIdOfThread(duplicateHandle);
        if (threadProcessId == TargetPid && ControllerHandleAccessLooksThreadInjectionCapable(entry->GrantedAccess))
        {
            marks |= BK_HOLLOW_MARK_THREAD_CONTEXT_INTENT;
        }

        CloseHandle(duplicateHandle);
        if ((marks & (BK_HOLLOW_MARK_PROCESS_HANDLE_INTENT | BK_HOLLOW_MARK_THREAD_CONTEXT_INTENT)) ==
            (BK_HOLLOW_MARK_PROCESS_HANDLE_INTENT | BK_HOLLOW_MARK_THREAD_CONTEXT_INTENT))
        {
            break;
        }
    }

    CloseHandle(actorProcess);
    HeapFree(GetProcessHeap(), 0, buffer);

    if (marks != 0)
    {
        ControllerApplyHollowMark(ActorPid, TargetPid, marks, 0, 0, 0);
    }
}

static UINT32 ControllerClassifyExecutionTarget(_In_ DWORD TargetPid, _In_ ULONGLONG Address,
                                                _Out_opt_ ULONGLONG *RegionBase, _Out_opt_ ULONGLONG *RegionSize,
                                                _Out_opt_ BOOL *HasPeHeader)
{
    static const struct
    {
        PCWSTR ModuleName;
        PCSTR ExportName;
    } loaderExports[] = {{L"kernel32.dll", "LoadLibraryA"},     {L"kernel32.dll", "LoadLibraryW"},
                         {L"kernel32.dll", "LoadLibraryExA"},   {L"kernel32.dll", "LoadLibraryExW"},
                         {L"KernelBase.dll", "LoadLibraryExA"}, {L"KernelBase.dll", "LoadLibraryExW"},
                         {L"ntdll.dll", "LdrLoadDll"}};
    SIZE_T queried;
    HANDLE process;
    MEMORY_BASIC_INFORMATION mbi;
    BOOL hasPe = FALSE;
    DWORD i;

    if (RegionBase != NULL)
    {
        *RegionBase = 0;
    }
    if (RegionSize != NULL)
    {
        *RegionSize = 0;
    }
    if (HasPeHeader != NULL)
    {
        *HasPeHeader = FALSE;
    }

    if (TargetPid == 0 || Address == 0)
    {
        return BK_HOLLOW_EXEC_KIND_NONE;
    }

    for (i = 0; i < RTL_NUMBER_OF(loaderExports); ++i)
    {
        ULONGLONG loaderAddress = 0;
        if (ControllerTryResolveRemoteExportAddress(TargetPid, loaderExports[i].ModuleName, loaderExports[i].ExportName,
                                                    &loaderAddress) &&
            loaderAddress == Address)
        {
            return BK_HOLLOW_EXEC_KIND_LOADER;
        }
    }

    process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, TargetPid);
    if (process == NULL)
    {
        return BK_HOLLOW_EXEC_KIND_NONE;
    }

    ZeroMemory(&mbi, sizeof(mbi));
    queried = VirtualQueryEx(process, (LPCVOID)(ULONG_PTR)Address, &mbi, sizeof(mbi));
    if (queried < sizeof(mbi))
    {
        (void)CloseHandle(process);
        return BK_HOLLOW_EXEC_KIND_NONE;
    }

    if (RegionBase != NULL)
    {
        *RegionBase = (ULONGLONG)(ULONG_PTR)mbi.BaseAddress;
    }
    if (RegionSize != NULL)
    {
        *RegionSize = (ULONGLONG)mbi.RegionSize;
    }

    if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE && ControllerIsExecutableProtect(mbi.Protect))
    {
        hasPe = ControllerProbePeHeaderAtBase(process, (ULONGLONG)(ULONG_PTR)mbi.BaseAddress);
        if (HasPeHeader != NULL)
        {
            *HasPeHeader = hasPe;
        }
        (void)CloseHandle(process);
        return BK_HOLLOW_EXEC_KIND_PRIVATE_EXEC;
    }

    (void)CloseHandle(process);
    return BK_HOLLOW_EXEC_KIND_NONE;
}

static BOOL ControllerEtwTryGetU64Any(_In_ PEVENT_RECORD Record, _In_reads_(NameCount) const PCWSTR *Names,
                                      _In_ size_t NameCount, _Out_ ULONGLONG *Value)
{
    size_t i;

    if (Value == NULL)
    {
        return FALSE;
    }
    *Value = 0;

    for (i = 0; i < NameCount; ++i)
    {
        if (ControllerEtwGetU64Property(Record, Names[i], Value))
        {
            return TRUE;
        }
    }

    return FALSE;
}

static BOOL ControllerEtwTryGetU32Any(_In_ PEVENT_RECORD Record, _In_reads_(NameCount) const PCWSTR *Names,
                                      _In_ size_t NameCount, _Out_ ULONG *Value)
{
    size_t i;

    if (Value == NULL)
    {
        return FALSE;
    }
    *Value = 0;

    for (i = 0; i < NameCount; ++i)
    {
        if (ControllerEtwGetU32Property(Record, Names[i], Value))
        {
            return TRUE;
        }
    }

    return FALSE;
}

static BOOL ControllerIsWritableProtect(_In_ ULONG Protect)
{
    switch (Protect & 0xFF)
    {
    case PAGE_READWRITE:
    case PAGE_WRITECOPY:
    case PAGE_EXECUTE_READWRITE:
    case PAGE_EXECUTE_WRITECOPY:
        return TRUE;
    default:
        return FALSE;
    }
}

static BOOL ControllerIsExecutableProtect(_In_ ULONG Protect)
{
    switch (Protect & 0xFF)
    {
    case PAGE_EXECUTE:
    case PAGE_EXECUTE_READ:
    case PAGE_EXECUTE_READWRITE:
    case PAGE_EXECUTE_WRITECOPY:
        return TRUE;
    default:
        return FALSE;
    }
}

static BOOL ControllerQueryWorkingSetPrivateCopy(_In_ HANDLE ProcessHandle, _In_ ULONGLONG Address)
{
    PSAPI_WORKING_SET_EX_INFORMATION ws;

    if (ProcessHandle == NULL || ProcessHandle == INVALID_HANDLE_VALUE || Address == 0)
    {
        return FALSE;
    }

    ZeroMemory(&ws, sizeof(ws));
    ws.VirtualAddress = (PVOID)(ULONG_PTR)Address;
    if (!QueryWorkingSetEx(ProcessHandle, &ws, sizeof(ws)))
    {
        return FALSE;
    }

    return ws.VirtualAttributes.Valid && !ws.VirtualAttributes.Shared;
}

static BOOL ControllerRangesOverlap(_In_ ULONGLONG BaseA, _In_ ULONGLONG SizeA, _In_ ULONGLONG BaseB,
                                    _In_ ULONGLONG SizeB)
{
    ULONGLONG endA;
    ULONGLONG endB;

    if (SizeA == 0 || SizeB == 0)
    {
        return FALSE;
    }

    endA = BaseA + SizeA;
    endB = BaseB + SizeB;
    if (endA < BaseA || endB < BaseB)
    {
        return FALSE;
    }

    return !(endA <= BaseB || endB <= BaseA);
}

static BOOL ControllerProbePeImageTraitsAtBase(_In_ HANDLE ProcessHandle, _In_ ULONGLONG BaseAddress,
                                               _Out_opt_ DWORD *Traits)
{
    BYTE header[0x1000];
    SIZE_T bytesRead = 0;
    IMAGE_DOS_HEADER dos;
    IMAGE_FILE_HEADER fileHeader;
    MEMORY_BASIC_INFORMATION mbi;
    LONG peOffset;
    DWORD peSignature = 0;
    WORD optionalMagic = 0;
    SIZE_T queried;
    SIZE_T readSize;
    SIZE_T minNtHeaderBytes;
    SIZE_T fileHeaderOffset;
    SIZE_T optionalHeaderOffset;
    SIZE_T sectionHeaderOffset;
    WORD sectionCount;
    WORD optionalHeaderSize;
    DWORD traits = 0;

    if (Traits != NULL)
    {
        *Traits = 0;
    }
    if (ProcessHandle == NULL || ProcessHandle == INVALID_HANDLE_VALUE || BaseAddress == 0)
    {
        return FALSE;
    }

    ZeroMemory(&mbi, sizeof(mbi));
    queried = VirtualQueryEx(ProcessHandle, (LPCVOID)(ULONG_PTR)BaseAddress, &mbi, sizeof(mbi));
    if (queried >= sizeof(mbi) && mbi.State == MEM_COMMIT && mbi.RegionSize != 0)
    {
        ULONGLONG regionBase = (ULONGLONG)(ULONG_PTR)mbi.BaseAddress;
        ULONGLONG regionSize = (ULONGLONG)mbi.RegionSize;
        if (BaseAddress >= regionBase && (BaseAddress - regionBase) < regionSize)
        {
            ULONGLONG available = regionSize - (BaseAddress - regionBase);
            readSize = (available < sizeof(header)) ? (SIZE_T)available : sizeof(header);
        }
        else
        {
            readSize = sizeof(header);
        }
    }
    else
    {
        readSize = sizeof(header);
    }
    if (readSize < sizeof(IMAGE_DOS_HEADER))
    {
        return FALSE;
    }

    ZeroMemory(header, sizeof(header));
    if (!ReadProcessMemory(ProcessHandle, (LPCVOID)(ULONG_PTR)BaseAddress, header, readSize, &bytesRead))
    {
        return FALSE;
    }
    if (bytesRead < sizeof(IMAGE_DOS_HEADER))
    {
        return FALSE;
    }

    CopyMemory(&dos, header, sizeof(dos));
    if (dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew <= 0)
    {
        return FALSE;
    }

    peOffset = dos.e_lfanew;
    minNtHeaderBytes = (SIZE_T)peOffset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + sizeof(WORD);
    if ((SIZE_T)peOffset >= bytesRead || minNtHeaderBytes > bytesRead)
    {
        return FALSE;
    }

    CopyMemory(&peSignature, header + peOffset, sizeof(peSignature));
    if (peSignature != IMAGE_NT_SIGNATURE)
    {
        return FALSE;
    }

    fileHeaderOffset = (SIZE_T)peOffset + sizeof(DWORD);
    optionalHeaderOffset = fileHeaderOffset + sizeof(IMAGE_FILE_HEADER);
    CopyMemory(&fileHeader, header + fileHeaderOffset, sizeof(fileHeader));
    sectionCount = fileHeader.NumberOfSections;
    optionalHeaderSize = fileHeader.SizeOfOptionalHeader;

    CopyMemory(&optionalMagic, header + optionalHeaderOffset, sizeof(optionalMagic));
    if (optionalMagic != IMAGE_NT_OPTIONAL_HDR32_MAGIC && optionalMagic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        return FALSE;
    }

    traits |= BK_MANUAL_MAP_TRAIT_PE_HEADER;
    if (sectionCount != 0 && sectionCount < 96)
    {
        UINT32 i;
        sectionHeaderOffset = optionalHeaderOffset + optionalHeaderSize;
        if (sectionHeaderOffset + ((SIZE_T)sectionCount * sizeof(IMAGE_SECTION_HEADER)) <= bytesRead)
        {
            for (i = 0; i < sectionCount; ++i)
            {
                IMAGE_SECTION_HEADER sectionHeader;
                CopyMemory(&sectionHeader, header + sectionHeaderOffset + ((SIZE_T)i * sizeof(sectionHeader)),
                           sizeof(sectionHeader));
                if (sectionHeader.VirtualAddress != 0 && sectionHeader.Misc.VirtualSize != 0)
                {
                    traits |= BK_MANUAL_MAP_TRAIT_SECTIONS;
                }
            }
        }
    }

    if (optionalHeaderOffset + optionalHeaderSize <= bytesRead)
    {
        if (optionalMagic == IMAGE_NT_OPTIONAL_HDR64_MAGIC && optionalHeaderSize >= sizeof(IMAGE_OPTIONAL_HEADER64))
        {
            IMAGE_OPTIONAL_HEADER64 optionalHeader;
            CopyMemory(&optionalHeader, header + optionalHeaderOffset, sizeof(optionalHeader));
            if (optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress != 0)
                traits |= BK_MANUAL_MAP_TRAIT_IMPORTS;
            if (optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress != 0)
                traits |= BK_MANUAL_MAP_TRAIT_RELOCS;
            if (optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress != 0)
                traits |= BK_MANUAL_MAP_TRAIT_TLS;
            if (optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress != 0)
                traits |= BK_MANUAL_MAP_TRAIT_EXCEPTION;
        }
        else if (optionalMagic == IMAGE_NT_OPTIONAL_HDR32_MAGIC &&
                 optionalHeaderSize >= sizeof(IMAGE_OPTIONAL_HEADER32))
        {
            IMAGE_OPTIONAL_HEADER32 optionalHeader;
            CopyMemory(&optionalHeader, header + optionalHeaderOffset, sizeof(optionalHeader));
            if (optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress != 0)
                traits |= BK_MANUAL_MAP_TRAIT_IMPORTS;
            if (optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress != 0)
                traits |= BK_MANUAL_MAP_TRAIT_RELOCS;
            if (optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress != 0)
                traits |= BK_MANUAL_MAP_TRAIT_TLS;
            if (optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress != 0)
                traits |= BK_MANUAL_MAP_TRAIT_EXCEPTION;
        }
    }

    if (Traits != NULL)
    {
        *Traits = traits;
    }
    return (traits & BK_MANUAL_MAP_TRAIT_PE_HEADER) != 0;
}

static BOOL ControllerProbePeHeaderAtBase(_In_ HANDLE ProcessHandle, _In_ ULONGLONG BaseAddress)
{
    return ControllerProbePeImageTraitsAtBase(ProcessHandle, BaseAddress, NULL);
}

static BOOL ControllerProbeManualMapRegion(_In_ DWORD TargetPid, _In_ ULONGLONG CandidateBase,
                                           _In_ ULONGLONG CandidateSize, _In_ ULONGLONG ThreadStartAddress,
                                           _Out_ BOOL *PrivateExecutableRegion, _Out_ BOOL *HasPeHeader,
                                           _Out_ BOOL *ThreadStartInsideRegion, _Out_opt_ ULONGLONG *ResolvedBase,
                                           _Out_opt_ ULONGLONG *ResolvedSize, _Out_opt_ ULONG *ResolvedProtect,
                                           _Out_opt_ ULONG *ResolvedType, _Out_opt_ DWORD *ManualMapTraits,
                                           _Out_opt_ BOOL *WorkingSetPrivateCopy)
{
    HANDLE process = NULL;
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T queried = 0;
    ULONGLONG regionBase = 0;
    ULONGLONG regionSize = 0;
    BOOL privateExec = FALSE;
    BOOL hasPe = FALSE;
    BOOL startInside = FALSE;

    if (PrivateExecutableRegion == NULL || HasPeHeader == NULL || ThreadStartInsideRegion == NULL || TargetPid == 0 ||
        CandidateBase == 0)
    {
        return FALSE;
    }

    *PrivateExecutableRegion = FALSE;
    *HasPeHeader = FALSE;
    *ThreadStartInsideRegion = FALSE;
    if (ResolvedBase != NULL)
    {
        *ResolvedBase = 0;
    }
    if (ResolvedSize != NULL)
    {
        *ResolvedSize = 0;
    }
    if (ResolvedProtect != NULL)
    {
        *ResolvedProtect = 0;
    }
    if (ResolvedType != NULL)
    {
        *ResolvedType = 0;
    }
    if (ManualMapTraits != NULL)
    {
        *ManualMapTraits = 0;
    }
    if (WorkingSetPrivateCopy != NULL)
    {
        *WorkingSetPrivateCopy = FALSE;
    }

    process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, TargetPid);
    if (process == NULL)
    {
        return FALSE;
    }

    ZeroMemory(&mbi, sizeof(mbi));
    queried = VirtualQueryEx(process, (LPCVOID)(ULONG_PTR)CandidateBase, &mbi, sizeof(mbi));
    if (queried < sizeof(mbi))
    {
        (void)CloseHandle(process);
        return FALSE;
    }

    regionBase = (ULONGLONG)(ULONG_PTR)mbi.BaseAddress;
    regionSize = (ULONGLONG)mbi.RegionSize;
    privateExec = (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE && ControllerIsExecutableProtect(mbi.Protect));
    if (WorkingSetPrivateCopy != NULL && (mbi.Type == MEM_IMAGE || mbi.Type == MEM_MAPPED) &&
        ControllerIsExecutableProtect(mbi.Protect))
    {
        *WorkingSetPrivateCopy = ControllerQueryWorkingSetPrivateCopy(process, (ULONGLONG)(ULONG_PTR)mbi.BaseAddress);
    }

    if (CandidateSize != 0 && !ControllerRangesOverlap(CandidateBase, CandidateSize, regionBase, regionSize))
    {
        privateExec = FALSE;
    }

    if (ThreadStartAddress != 0 && regionSize != 0)
    {
        ULONGLONG end = regionBase + regionSize;
        if (end >= regionBase)
        {
            startInside = (ThreadStartAddress >= regionBase && ThreadStartAddress < end);
        }
    }

    if (privateExec)
    {
        DWORD traits = 0;
        hasPe = ControllerProbePeImageTraitsAtBase(process, regionBase, &traits);
        if (!hasPe && CandidateBase != regionBase)
        {
            DWORD candidateTraits = 0;
            hasPe = ControllerProbePeImageTraitsAtBase(process, CandidateBase, &candidateTraits);
            traits |= candidateTraits;
        }
        if (ManualMapTraits != NULL)
        {
            *ManualMapTraits = traits;
        }
    }

    (void)CloseHandle(process);

    *PrivateExecutableRegion = privateExec;
    *HasPeHeader = hasPe;
    *ThreadStartInsideRegion = startInside;
    if (ResolvedBase != NULL)
    {
        *ResolvedBase = regionBase;
    }
    if (ResolvedSize != NULL)
    {
        *ResolvedSize = regionSize;
    }
    if (ResolvedProtect != NULL)
    {
        *ResolvedProtect = mbi.Protect;
    }
    if (ResolvedType != NULL)
    {
        *ResolvedType = mbi.Type;
    }
    return TRUE;
}

static BOOL ControllerManualMapProbeDequeue(_Out_ PBK_CONTROLLER_MANUAL_MAP_PROBE_REQUEST Request)
{
    DWORD i;

    if (Request == NULL)
    {
        return FALSE;
    }

    EnterCriticalSection(g_ManualMapProbeLock.get());
    for (i = 0; i < RTL_NUMBER_OF(g_ManualMapProbeQueue); ++i)
    {
        if (!g_ManualMapProbeQueue[i].Active)
        {
            continue;
        }

        *Request = g_ManualMapProbeQueue[i];
        ZeroMemory(&g_ManualMapProbeQueue[i], sizeof(g_ManualMapProbeQueue[i]));
        LeaveCriticalSection(g_ManualMapProbeLock.get());
        return TRUE;
    }
    LeaveCriticalSection(g_ManualMapProbeLock.get());
    return FALSE;
}

static VOID ControllerQueueManualMapProbe(_In_ DWORD ActorPid, _In_ DWORD TargetPid, _In_ ULONGLONG BaseHint,
                                          _In_ ULONGLONG SizeHint)
{
    DWORD i;
    DWORD freeIndex = BK_CONTROLLER_MANUAL_MAP_PROBE_QUEUE_CAPACITY;
    DWORD oldestIndex = BK_CONTROLLER_MANUAL_MAP_PROBE_QUEUE_CAPACITY;
    ULONGLONG oldestTick = ~0ull;
    ULONGLONG nowTick = GetTickCount64();

    if (!g_ManualMapProbeEvent || TargetPid == 0)
    {
        return;
    }

    EnterCriticalSection(g_ManualMapProbeLock.get());
    for (i = 0; i < RTL_NUMBER_OF(g_ManualMapProbeQueue); ++i)
    {
        if (!g_ManualMapProbeQueue[i].Active)
        {
            if (freeIndex >= RTL_NUMBER_OF(g_ManualMapProbeQueue))
            {
                freeIndex = i;
            }
            continue;
        }

        if (g_ManualMapProbeQueue[i].ActorPid == ActorPid && g_ManualMapProbeQueue[i].TargetPid == TargetPid)
        {
            g_ManualMapProbeQueue[i].BaseHint = (BaseHint != 0) ? BaseHint : g_ManualMapProbeQueue[i].BaseHint;
            g_ManualMapProbeQueue[i].SizeHint = (SizeHint != 0) ? SizeHint : g_ManualMapProbeQueue[i].SizeHint;
            g_ManualMapProbeQueue[i].EnqueueTick = nowTick;
            LeaveCriticalSection(g_ManualMapProbeLock.get());
            (void)SetEvent(g_ManualMapProbeEvent.get());
            return;
        }

        if (g_ManualMapProbeQueue[i].EnqueueTick < oldestTick)
        {
            oldestTick = g_ManualMapProbeQueue[i].EnqueueTick;
            oldestIndex = i;
        }
    }

    if (freeIndex >= RTL_NUMBER_OF(g_ManualMapProbeQueue))
    {
        freeIndex = oldestIndex;
    }
    if (freeIndex < RTL_NUMBER_OF(g_ManualMapProbeQueue))
    {
        g_ManualMapProbeQueue[freeIndex].Active = TRUE;
        g_ManualMapProbeQueue[freeIndex].ActorPid = ActorPid;
        g_ManualMapProbeQueue[freeIndex].TargetPid = TargetPid;
        g_ManualMapProbeQueue[freeIndex].BaseHint = BaseHint;
        g_ManualMapProbeQueue[freeIndex].SizeHint = SizeHint;
        g_ManualMapProbeQueue[freeIndex].EnqueueTick = nowTick;
    }
    LeaveCriticalSection(g_ManualMapProbeLock.get());

    (void)SetEvent(g_ManualMapProbeEvent.get());
}

static PBK_CONTROLLER_HOLLOW_ENTRY ControllerFindHollowEntryLocked(_In_ DWORD ActorPid, _In_ DWORD TargetPid)
{
    DWORD effectiveActor;
    DWORD i;

    if (TargetPid == 0)
    {
        return NULL;
    }

    effectiveActor = (ActorPid != 0) ? ActorPid : TargetPid;
    for (i = 0; i < BK_CONTROLLER_HOLLOW_MAX_ENTRIES; ++i)
    {
        if (!g_HollowEntries[i].Active)
        {
            continue;
        }
        if (g_HollowEntries[i].TargetPid == TargetPid && g_HollowEntries[i].ActorPid == effectiveActor)
        {
            return &g_HollowEntries[i];
        }
    }

    return NULL;
}

static PBK_CONTROLLER_HOLLOW_ENTRY ControllerGetHollowEntryLocked(_In_ DWORD ActorPid, _In_ DWORD TargetPid,
                                                                  _In_ ULONGLONG NowTick)
{
    DWORD i;
    DWORD candidate = BK_CONTROLLER_HOLLOW_MAX_ENTRIES;
    ULONGLONG oldestTick = ~0ull;

    if (TargetPid == 0)
    {
        return NULL;
    }
    if (ActorPid == 0)
    {
        ActorPid = TargetPid;
    }

    for (i = 0; i < BK_CONTROLLER_HOLLOW_MAX_ENTRIES; ++i)
    {
        if (!g_HollowEntries[i].Active)
        {
            candidate = i;
            break;
        }

        if (g_HollowEntries[i].TargetPid == TargetPid && g_HollowEntries[i].ActorPid == ActorPid)
        {
            return &g_HollowEntries[i];
        }

        if ((NowTick - g_HollowEntries[i].LastSeenTick) > (BK_CONTROLLER_HOLLOW_WINDOW_MS * 2ull))
        {
            candidate = i;
            break;
        }

        if (g_HollowEntries[i].LastSeenTick < oldestTick)
        {
            oldestTick = g_HollowEntries[i].LastSeenTick;
            candidate = i;
        }
    }

    if (candidate >= BK_CONTROLLER_HOLLOW_MAX_ENTRIES)
    {
        return NULL;
    }

    ZeroMemory(&g_HollowEntries[candidate], sizeof(g_HollowEntries[candidate]));
    g_HollowEntries[candidate].Active = TRUE;
    g_HollowEntries[candidate].ActorPid = ActorPid;
    g_HollowEntries[candidate].TargetPid = TargetPid;
    g_HollowEntries[candidate].FirstSeenTick = NowTick;
    g_HollowEntries[candidate].LastSeenTick = NowTick;
    return &g_HollowEntries[candidate];
}

static VOID ControllerEmitSyntheticDetectionEx(_In_ DWORD ActorPid, _In_ DWORD TargetPid, _In_z_ PCSTR DetectionName,
                                               _In_ DWORD Severity, _In_ UINT64 Marks, _In_opt_z_ PCWSTR ReasonText)
{
    BKIPC_ETW_EVENT event;

    if (DetectionName == NULL || DetectionName[0] == '\0' || TargetPid == 0)
    {
        return;
    }

    ZeroMemory(&event, sizeof(event));
    event.Source = BlackbirdIpcEtwSourceBlackbird;
    event.EventId = 0;
    event.Opcode = 0;
    event.Task = 0;
    event.EventProcessId = (ActorPid != 0) ? ActorPid : TargetPid;
    event.EventThreadId = 0;
    event.Severity = Severity;
    event.ProcessId = (ActorPid != 0) ? (UINT64)ActorPid : (UINT64)TargetPid;
    event.TargetPid = (UINT64)TargetPid;
    event.CorrelationFlags = 0;
    event.CorrelationAccessMask = 0;
    event.CorrelationAgeMs = 0;
    (void)StringCchCopyW(event.EventName, RTL_NUMBER_OF(event.EventName), L"DetectionTelemetry");
    (void)StringCchCopyA(event.DetectionName, RTL_NUMBER_OF(event.DetectionName), DetectionName);
    if (ReasonText != NULL && ReasonText[0] != L'\0')
    {
        (void)StringCchCopyW(event.Reason, RTL_NUMBER_OF(event.Reason), ReasonText);
    }
    else
    {
        (void)StringCchPrintfW(event.Reason, RTL_NUMBER_OF(event.Reason), L"synthetic chain marks=0x%llX", Marks);
    }
    event.Reserved2 = ControllerComputeEtwDetectionTraits(event);

    (void)InterlockedIncrement(&g_EtwDetectionEvents);
    ControllerDispatchEtwEvent(&event);
    ControllerLog("[ETW][SYNTH] detection=%s severity=%lu actor=%lu target=%lu marks=0x%llX\n", DetectionName, Severity,
                  ActorPid, TargetPid, Marks);
}

static VOID ControllerEmitSyntheticDetection(_In_ DWORD ActorPid, _In_ DWORD TargetPid, _In_z_ PCSTR DetectionName,
                                             _In_ DWORD Severity, _In_ UINT64 Marks)
{
    ControllerEmitSyntheticDetectionEx(ActorPid, TargetPid, DetectionName, Severity, Marks, NULL);
}

static VOID ControllerRememberImageLoadLocked(_In_ DWORD TargetPid, _In_ ULONGLONG ImageBase, _In_ ULONGLONG ImageSize,
                                              _In_opt_z_ PCWSTR ImagePath, _In_ ULONGLONG NowTick)
{
    DWORD i;

    if (TargetPid == 0)
    {
        return;
    }

    for (i = 0; i < BK_CONTROLLER_HOLLOW_MAX_ENTRIES; ++i)
    {
        ULONGLONG latestExecTick;

        if (!g_HollowEntries[i].Active || g_HollowEntries[i].TargetPid != TargetPid)
        {
            continue;
        }
        latestExecTick = g_HollowEntries[i].LastThreadCreateTick;
        if (g_HollowEntries[i].LastApcTick > latestExecTick)
        {
            latestExecTick = g_HollowEntries[i].LastApcTick;
        }
        if (g_HollowEntries[i].LastSetContextTick > latestExecTick)
        {
            latestExecTick = g_HollowEntries[i].LastSetContextTick;
        }
        if (latestExecTick == 0 || (NowTick - latestExecTick) > BK_CONTROLLER_HOLLOW_WINDOW_MS)
        {
            continue;
        }

        g_HollowEntries[i].LastSeenTick = NowTick;
        g_HollowEntries[i].LastImageLoadTick = NowTick;
        g_HollowEntries[i].LastImageLoadBase = ImageBase;
        g_HollowEntries[i].LastImageLoadSize = ImageSize;
        if (ImagePath != NULL && ImagePath[0] != L'\0')
        {
            (void)StringCchCopyW(g_HollowEntries[i].LastImageLoadPath,
                                 RTL_NUMBER_OF(g_HollowEntries[i].LastImageLoadPath), ImagePath);
        }
        ControllerEvaluateHollowEntryLocked(&g_HollowEntries[i], NowTick);
    }
}

static VOID ControllerEvaluateInjectionEvidenceLocked(_Inout_ PBK_CONTROLLER_HOLLOW_ENTRY Entry, _In_ ULONGLONG NowTick)
{
    BOOL remoteActor;
    BOOL hasAlloc;
    BOOL hasWrite;
    BOOL hasProtect;
    BOOL recentManualMapEvidence;
    WCHAR reasonText[256];

    if (Entry == NULL)
    {
        return;
    }

    remoteActor = (Entry->ActorPid != 0 && Entry->ActorPid != Entry->TargetPid);
    hasAlloc = ((Entry->Marks & BK_HOLLOW_MARK_TI_ALLOC_RW_LARGE) != 0);
    hasWrite = ((Entry->Marks & BK_HOLLOW_MARK_TI_WRITE_VM) != 0);
    hasProtect = ((Entry->Marks & BK_HOLLOW_MARK_TI_PROTECT_RX) != 0);
    recentManualMapEvidence = (Entry->LastManualMapConfirmedEmitTick != 0 &&
                               (NowTick - Entry->LastManualMapConfirmedEmitTick) <= BK_CONTROLLER_HOLLOW_WINDOW_MS) ||
                              (Entry->LastManualMapHeaderlessEmitTick != 0 &&
                               (NowTick - Entry->LastManualMapHeaderlessEmitTick) <= BK_CONTROLLER_HOLLOW_WINDOW_MS);

    if (!remoteActor || !hasWrite)
    {
        return;
    }

    if (Entry->LastThreadCreateKind == BK_HOLLOW_EXEC_KIND_LOADER && Entry->LastThreadCreateTick != 0 &&
        Entry->LastImageLoadTick >= Entry->LastThreadCreateTick &&
        (Entry->LastImageLoadTick - Entry->LastThreadCreateTick) <= 10000ull &&
        (NowTick - Entry->LastRemoteThreadDllEmitTick) > BK_CONTROLLER_MANUAL_MAP_EMIT_COOLDOWN_MS)
    {
        Entry->LastRemoteThreadDllEmitTick = NowTick;
        (void)StringCchPrintfW(reasonText, RTL_NUMBER_OF(reasonText),
                               L"remote thread start=0x%llX imageLoad=%ws alloc=%u write=%u protect=%u dllPathWrite=%u",
                               Entry->LastThreadCreateTarget,
                               (Entry->LastImageLoadPath[0] != L'\0') ? Entry->LastImageLoadPath : L"<unknown>",
                               hasAlloc ? 1u : 0u, hasWrite ? 1u : 0u, hasProtect ? 1u : 0u,
                               Entry->LastDllPathWriteTick != 0 ? 1u : 0u);
        ControllerEmitSyntheticDetectionEx(Entry->ActorPid, Entry->TargetPid, "REMOTE_THREAD_DLL_INJECTION_CONFIRMED",
                                           8, Entry->Marks, reasonText);
    }

    if (Entry->LastApcKind == BK_HOLLOW_EXEC_KIND_LOADER && Entry->LastApcTick != 0 &&
        Entry->LastImageLoadTick >= Entry->LastApcTick && (Entry->LastImageLoadTick - Entry->LastApcTick) <= 10000ull &&
        (NowTick - Entry->LastApcDllEmitTick) > BK_CONTROLLER_MANUAL_MAP_EMIT_COOLDOWN_MS)
    {
        Entry->LastApcDllEmitTick = NowTick;
        (void)StringCchPrintfW(
            reasonText, RTL_NUMBER_OF(reasonText),
            L"remote apc routine=0x%llX imageLoad=%ws alloc=%u write=%u protect=%u dllPathWrite=%u",
            Entry->LastApcRoutine, (Entry->LastImageLoadPath[0] != L'\0') ? Entry->LastImageLoadPath : L"<unknown>",
            hasAlloc ? 1u : 0u, hasWrite ? 1u : 0u, hasProtect ? 1u : 0u, Entry->LastDllPathWriteTick != 0 ? 1u : 0u);
        ControllerEmitSyntheticDetectionEx(Entry->ActorPid, Entry->TargetPid, "APC_DLL_INJECTION_CONFIRMED", 8,
                                           Entry->Marks, reasonText);
    }

    if (Entry->LastSetContextKind == BK_HOLLOW_EXEC_KIND_LOADER && Entry->LastSetContextTick != 0 &&
        Entry->LastResumeTick >= Entry->LastSetContextTick && Entry->LastImageLoadTick >= Entry->LastResumeTick &&
        (Entry->LastImageLoadTick - Entry->LastResumeTick) <= 10000ull &&
        (NowTick - Entry->LastHijackDllEmitTick) > BK_CONTROLLER_MANUAL_MAP_EMIT_COOLDOWN_MS)
    {
        Entry->LastHijackDllEmitTick = NowTick;
        (void)StringCchPrintfW(reasonText, RTL_NUMBER_OF(reasonText),
                               L"thread hijack rip=0x%llX rsp=0x%llX imageLoad=%ws write=%u resume=%u dllPathWrite=%u",
                               Entry->LastSetContextRip, Entry->LastSetContextRsp,
                               (Entry->LastImageLoadPath[0] != L'\0') ? Entry->LastImageLoadPath : L"<unknown>",
                               hasWrite ? 1u : 0u, Entry->LastResumeTick != 0 ? 1u : 0u,
                               Entry->LastDllPathWriteTick != 0 ? 1u : 0u);
        ControllerEmitSyntheticDetectionEx(Entry->ActorPid, Entry->TargetPid, "THREAD_HIJACK_DLL_INJECTION_CONFIRMED",
                                           8, Entry->Marks, reasonText);
    }

    if (recentManualMapEvidence && hasProtect && Entry->LastThreadCreateKind == BK_HOLLOW_EXEC_KIND_PRIVATE_EXEC &&
        (NowTick - Entry->LastRemoteThreadPrivateEmitTick) > BK_CONTROLLER_MANUAL_MAP_EMIT_COOLDOWN_MS)
    {
        Entry->LastRemoteThreadPrivateEmitTick = NowTick;
        (void)StringCchPrintfW(reasonText, RTL_NUMBER_OF(reasonText),
                               L"remote thread privateExec start=0x%llX region=0x%llX+0x%llX pe=%u manualMapEvidence=1",
                               Entry->LastThreadCreateTarget, Entry->LastThreadCreateRegionBase,
                               Entry->LastThreadCreateRegionSize, Entry->LastThreadCreateHasPe ? 1u : 0u);
        ControllerEmitSyntheticDetectionEx(Entry->ActorPid, Entry->TargetPid, "REMOTE_THREAD_MANUAL_MAP_CONFIRMED", 8,
                                           Entry->Marks, reasonText);
    }

    if (recentManualMapEvidence && hasProtect && Entry->LastApcKind == BK_HOLLOW_EXEC_KIND_PRIVATE_EXEC &&
        (NowTick - Entry->LastApcPrivateEmitTick) > BK_CONTROLLER_MANUAL_MAP_EMIT_COOLDOWN_MS)
    {
        Entry->LastApcPrivateEmitTick = NowTick;
        (void)StringCchPrintfW(reasonText, RTL_NUMBER_OF(reasonText),
                               L"apc privateExec routine=0x%llX region=0x%llX+0x%llX pe=%u manualMapEvidence=1",
                               Entry->LastApcRoutine, Entry->LastApcRegionBase, Entry->LastApcRegionSize,
                               Entry->LastApcHasPe ? 1u : 0u);
        ControllerEmitSyntheticDetectionEx(Entry->ActorPid, Entry->TargetPid, "APC_MANUAL_MAP_CONFIRMED", 8,
                                           Entry->Marks, reasonText);
    }

    if (recentManualMapEvidence && hasProtect && Entry->LastSetContextKind == BK_HOLLOW_EXEC_KIND_PRIVATE_EXEC &&
        Entry->LastResumeTick >= Entry->LastSetContextTick &&
        (NowTick - Entry->LastHijackPrivateEmitTick) > BK_CONTROLLER_MANUAL_MAP_EMIT_COOLDOWN_MS)
    {
        Entry->LastHijackPrivateEmitTick = NowTick;
        (void)StringCchPrintfW(reasonText, RTL_NUMBER_OF(reasonText),
                               L"thread hijack privateExec rip=0x%llX region=0x%llX+0x%llX pe=%u manualMapEvidence=1",
                               Entry->LastSetContextRip, Entry->LastSetContextRegionBase,
                               Entry->LastSetContextRegionSize, Entry->LastSetContextHasPe ? 1u : 0u);
        ControllerEmitSyntheticDetectionEx(Entry->ActorPid, Entry->TargetPid, "THREAD_HIJACK_MANUAL_MAP_CONFIRMED", 8,
                                           Entry->Marks, reasonText);
    }
}

static VOID ControllerEvaluateHollowEntryLocked(_Inout_ PBK_CONTROLLER_HOLLOW_ENTRY Entry, _In_ ULONGLONG NowTick)
{
    const UINT64 marks = Entry->Marks;
    const BOOL hasSuspended = ((marks & BK_HOLLOW_MARK_CREATE_SUSPENDED) != 0);
    const BOOL hasAlloc = ((marks & BK_HOLLOW_MARK_TI_ALLOC_RW_LARGE) != 0);
    const BOOL hasWrite = ((marks & BK_HOLLOW_MARK_TI_WRITE_VM) != 0);
    const BOOL hasProtect = ((marks & BK_HOLLOW_MARK_TI_PROTECT_RX) != 0);
    const BOOL hasThreadSuspicious =
        ((marks & (BK_HOLLOW_MARK_THREAD_START_NON_IMAGE_EXEC | BK_HOLLOW_MARK_THREAD_START_OUTSIDE_IMAGE)) != 0);
    const BOOL hasThreadContext = ((marks & BK_HOLLOW_MARK_THREAD_CONTEXT_INTENT) != 0);
    const BOOL hasImageDrift = ((marks & BK_HOLLOW_MARK_IMAGE_DRIFT) != 0);
    const BOOL hasTxf = ((marks & BK_HOLLOW_MARK_TXF_SUSPECT) != 0);
    const BOOL hasUnmap = ((marks & BK_HOLLOW_MARK_UNMAP_VIEW) != 0);
    const BOOL hasProcessHandle = ((marks & BK_HOLLOW_MARK_PROCESS_HANDLE_INTENT) != 0);
    BOOL strong;
    BOOL medium;

    if ((NowTick - Entry->FirstSeenTick) > BK_CONTROLLER_HOLLOW_WINDOW_MS)
    {
        Entry->Marks = 0;
        Entry->FirstSeenTick = NowTick;
        return;
    }

    strong = ((hasSuspended || hasUnmap || hasProcessHandle) && hasAlloc && hasWrite && hasProtect &&
              hasThreadSuspicious && (hasThreadContext || hasImageDrift || hasUnmap));
    medium = (hasAlloc && hasWrite && hasProtect && hasThreadSuspicious) ||
             ((hasSuspended || hasUnmap || hasProcessHandle) && hasThreadSuspicious && hasThreadContext);

    if (strong && ((NowTick - Entry->LastStrongEmitTick) > 3000ull))
    {
        DWORD targetPidSnap = Entry->TargetPid;
        Entry->LastStrongEmitTick = NowTick;
        if (hasTxf)
        {
            ControllerEmitSyntheticDetection(Entry->ActorPid, targetPidSnap, "PROCESS_HOLLOWING_TXF_SUSPECT_CHAIN", 8,
                                             Entry->Marks);
        }
        else if (hasUnmap)
        {
            ControllerEmitSyntheticDetection(Entry->ActorPid, targetPidSnap, "PROCESS_HOLLOWING_UNMAP_REPLACE_CHAIN", 8,
                                             Entry->Marks);
        }
        else
        {
            ControllerEmitSyntheticDetection(Entry->ActorPid, targetPidSnap, "PROCESS_HOLLOWING_MARK_CHAIN_STRONG", 7,
                                             Entry->Marks);
        }
        /* Flag the SR71 client injected into the hollowed target for inline Winsock hook upgrade.
           The IAT hooks will be bypassed by shellcode that calls WS2_32 exports directly. */
        {
            PBK_CONTROLLER_CLIENT client;
            EnterCriticalSection(g_ClientListLock.get());
            for (client = g_ClientList; client != NULL; client = client->Next)
            {
                if (client->ProcessId == targetPidSnap && client->Role == BkctlrClientRoleHook)
                {
                    InterlockedExchange(&client->WinsockInlineUpgradePending, 1);
                    break;
                }
            }
            LeaveCriticalSection(g_ClientListLock.get());
        }
        return;
    }

    if (medium && ((NowTick - Entry->LastMediumEmitTick) > 3000ull))
    {
        Entry->LastMediumEmitTick = NowTick;
        ControllerEmitSyntheticDetection(Entry->ActorPid, Entry->TargetPid, "PROCESS_HOLLOWING_MARK_CHAIN_MEDIUM", 5,
                                         Entry->Marks);
    }

    ControllerEvaluateInjectionEvidenceLocked(Entry, NowTick);
}

static VOID ControllerRememberThreadStart(_In_ DWORD ActorPid, _In_ DWORD TargetPid, _In_ ULONGLONG StartAddress)
{
    PBK_CONTROLLER_HOLLOW_ENTRY entry;
    ULONGLONG nowTick = GetTickCount64();

    if (TargetPid == 0 || StartAddress == 0)
    {
        return;
    }

    AcquireSRWLockExclusive(&g_HollowLock);
    entry = ControllerGetHollowEntryLocked(ActorPid, TargetPid, nowTick);
    if (entry != NULL)
    {
        entry->LastThreadStartAddress = StartAddress;
        entry->LastThreadStartTick = nowTick;
        entry->LastSeenTick = nowTick;
    }
    ReleaseSRWLockExclusive(&g_HollowLock);
}

static VOID ControllerTryEmitManualMapDetection(_In_ DWORD ActorPid, _In_ DWORD TargetPid, _In_ ULONGLONG BaseHint,
                                                _In_ ULONGLONG SizeHint)
{
    PBK_CONTROLLER_HOLLOW_ENTRY entry;
    ULONGLONG nowTick;
    DWORD effectiveActor = 0;
    DWORD effectiveTarget = 0;
    UINT64 marks = 0;
    ULONGLONG candidateBase = 0;
    ULONGLONG candidateSize = 0;
    ULONGLONG threadStartAddress = 0;
    ULONGLONG lastWriteTick = 0;
    ULONGLONG lastProtectTick = 0;
    ULONGLONG lastProbeBase = 0;
    ULONGLONG lastProbeSize = 0;
    ULONGLONG lastProbeTick = 0;
    BOOL hasAlloc;
    BOOL hasWrite;
    BOOL hasProtect;
    BOOL hasThreadSuspicious;
    BOOL remoteActor;
    BOOL privateExecutableRegion = FALSE;
    BOOL hasPeHeader = FALSE;
    BOOL threadStartInsideRegion = FALSE;
    ULONGLONG resolvedBase = 0;
    ULONGLONG resolvedSize = 0;
    ULONG resolvedProtect = 0;
    ULONG resolvedType = 0;
    DWORD manualMapTraits = 0;
    BOOL workingSetPrivateCopy = FALSE;
    const CHAR *detectionName = NULL;
    DWORD severity = 0;
    DWORD kind = 0;
    ULONGLONG *cooldownTick = NULL;
    WCHAR reasonText[256];

    if (TargetPid == 0)
    {
        return;
    }

    nowTick = GetTickCount64();
    AcquireSRWLockShared(&g_HollowLock);
    entry = ControllerFindHollowEntryLocked(ActorPid, TargetPid);
    if (entry != NULL)
    {
        effectiveActor = entry->ActorPid;
        effectiveTarget = entry->TargetPid;
        marks = entry->Marks;
        candidateBase = (BaseHint != 0)
                            ? BaseHint
                            : ((entry->LastProtectRxBase != 0) ? entry->LastProtectRxBase : entry->LastAllocBase);
        candidateSize = (SizeHint != 0)
                            ? SizeHint
                            : ((entry->LastProtectRxSize != 0) ? entry->LastProtectRxSize : entry->LastAllocSize);
        threadStartAddress = entry->LastThreadStartAddress;
        lastWriteTick = entry->LastWriteTick;
        lastProtectTick = entry->LastProtectRxTick;
        lastProbeBase = entry->LastManualMapProbeBase;
        lastProbeSize = entry->LastManualMapProbeSize;
        lastProbeTick = entry->LastManualMapProbeTick;
    }
    ReleaseSRWLockShared(&g_HollowLock);

    if (entry == NULL || effectiveTarget == 0 || candidateBase == 0)
    {
        return;
    }

    hasAlloc = ((marks & BK_HOLLOW_MARK_TI_ALLOC_RW_LARGE) != 0);
    hasWrite = ((marks & BK_HOLLOW_MARK_TI_WRITE_VM) != 0) || (lastWriteTick != 0);
    hasProtect = ((marks & BK_HOLLOW_MARK_TI_PROTECT_RX) != 0) || (lastProtectTick != 0);
    hasThreadSuspicious =
        ((marks & (BK_HOLLOW_MARK_THREAD_START_NON_IMAGE_EXEC | BK_HOLLOW_MARK_THREAD_START_OUTSIDE_IMAGE)) != 0);
    remoteActor = (effectiveActor != 0 && effectiveActor != effectiveTarget);

    if (!remoteActor || !hasAlloc || !hasWrite || !hasProtect || !hasThreadSuspicious)
    {
        return;
    }
    if (lastWriteTick != 0 && (nowTick - lastWriteTick) > BK_CONTROLLER_HOLLOW_WINDOW_MS)
    {
        return;
    }
    if (lastProtectTick != 0 && (nowTick - lastProtectTick) > BK_CONTROLLER_HOLLOW_WINDOW_MS)
    {
        return;
    }

    if (lastProbeTick != 0 && (nowTick - lastProbeTick) < BK_CONTROLLER_MANUAL_MAP_PROBE_MIN_INTERVAL_MS &&
        lastProbeBase == candidateBase && (lastProbeSize == 0 || candidateSize == 0 || lastProbeSize == candidateSize))
    {
        return;
    }

    AcquireSRWLockExclusive(&g_HollowLock);
    entry = ControllerFindHollowEntryLocked(effectiveActor, effectiveTarget);
    if (entry != NULL)
    {
        if (entry->LastManualMapProbeTick != 0 &&
            (nowTick - entry->LastManualMapProbeTick) < BK_CONTROLLER_MANUAL_MAP_PROBE_MIN_INTERVAL_MS &&
            entry->LastManualMapProbeBase == candidateBase &&
            (entry->LastManualMapProbeSize == 0 || candidateSize == 0 ||
             entry->LastManualMapProbeSize == candidateSize))
        {
            entry = NULL;
        }
        else
        {
            entry->LastManualMapProbeBase = candidateBase;
            entry->LastManualMapProbeSize = candidateSize;
            entry->LastManualMapProbeTick = nowTick;
        }
    }
    ReleaseSRWLockExclusive(&g_HollowLock);

    if (entry == NULL)
    {
        return;
    }

    if (!ControllerProbeManualMapRegion(effectiveTarget, candidateBase, candidateSize, threadStartAddress,
                                        &privateExecutableRegion, &hasPeHeader, &threadStartInsideRegion, &resolvedBase,
                                        &resolvedSize, &resolvedProtect, &resolvedType, &manualMapTraits,
                                        &workingSetPrivateCopy))
    {
        return;
    }
    if (!privateExecutableRegion)
    {
        if (workingSetPrivateCopy && hasWrite && hasThreadSuspicious)
        {
            AcquireSRWLockExclusive(&g_HollowLock);
            entry = ControllerFindHollowEntryLocked(effectiveActor, effectiveTarget);
            if (entry != NULL &&
                (nowTick - entry->LastManualMapLikelyEmitTick) >= BK_CONTROLLER_MANUAL_MAP_EMIT_COOLDOWN_MS)
            {
                entry->LastManualMapLikelyEmitTick = nowTick;
            }
            else
            {
                entry = NULL;
            }
            ReleaseSRWLockExclusive(&g_HollowLock);

            if (entry != NULL)
            {
                (void)StringCchPrintfW(
                    reasonText, RTL_NUMBER_OF(reasonText),
                    L"targeted VAD/working-set validation found executable image/mapped private copy base=0x%llX size=0x%llX type=0x%lX protect=0x%lX marks=0x%llX",
                    resolvedBase, resolvedSize, resolvedType, resolvedProtect, marks);
                ControllerEmitSyntheticDetectionEx(effectiveActor, effectiveTarget,
                                                   "PROCESS_HOLLOWING_IMAGE_PRIVATE_COPY_EXEC", 7, marks, reasonText);
            }
        }
        return;
    }

    if (hasPeHeader)
    {
        detectionName = "MANUAL_MAP_CONFIRMED_PRIVATE_EXEC_PE";
        severity = 8;
        kind = 3;
    }
    else if (threadStartInsideRegion || ((marks & BK_HOLLOW_MARK_THREAD_CONTEXT_INTENT) != 0))
    {
        detectionName = "MANUAL_MAP_HEADERLESS_PRIVATE_EXEC";
        severity = 7;
        kind = 2;
    }
    else
    {
        detectionName = "MANUAL_MAP_LIKELY_PRIVATE_EXEC_CHAIN";
        severity = 6;
        kind = 1;
    }

    AcquireSRWLockExclusive(&g_HollowLock);
    entry = ControllerFindHollowEntryLocked(effectiveActor, effectiveTarget);
    if (entry != NULL)
    {
        if (kind == 3)
        {
            cooldownTick = &entry->LastManualMapConfirmedEmitTick;
        }
        else if (kind == 2)
        {
            cooldownTick = &entry->LastManualMapHeaderlessEmitTick;
        }
        else
        {
            cooldownTick = &entry->LastManualMapLikelyEmitTick;
        }

        if (cooldownTick != NULL && (nowTick - *cooldownTick) < BK_CONTROLLER_MANUAL_MAP_EMIT_COOLDOWN_MS)
        {
            entry = NULL;
        }
        else if (cooldownTick != NULL)
        {
            *cooldownTick = nowTick;
        }
    }
    ReleaseSRWLockExclusive(&g_HollowLock);

    if (entry == NULL || detectionName == NULL)
    {
        return;
    }

    (void)StringCchPrintfW(
        reasonText, RTL_NUMBER_OF(reasonText),
        L"manual-map probe base=0x%llX size=0x%llX type=0x%lX protect=0x%lX pe=%u traits=0x%lX privateCopy=%u startInRegion=%u marks=0x%llX",
        resolvedBase, resolvedSize, resolvedType, resolvedProtect, hasPeHeader ? 1u : 0u,
        (unsigned long)manualMapTraits, workingSetPrivateCopy ? 1u : 0u, threadStartInsideRegion ? 1u : 0u, marks);
    ControllerEmitSyntheticDetectionEx(effectiveActor, effectiveTarget, detectionName, severity, marks, reasonText);
}

static VOID ControllerApplyHollowMark(_In_ DWORD ActorPid, _In_ DWORD TargetPid, _In_ UINT64 Mark,
                                      _In_ ULONGLONG AuxBase, _In_ ULONGLONG AuxSize, _In_ ULONG AuxProtect)
{
    PBK_CONTROLLER_HOLLOW_ENTRY entry;
    ULONGLONG nowTick = GetTickCount64();

    if (TargetPid == 0 || Mark == 0)
    {
        return;
    }

    AcquireSRWLockExclusive(&g_HollowLock);
    entry = ControllerGetHollowEntryLocked(ActorPid, TargetPid, nowTick);
    if (entry != NULL)
    {
        entry->Marks |= Mark;
        entry->LastSeenTick = nowTick;
        if (entry->FirstSeenTick == 0)
        {
            entry->FirstSeenTick = nowTick;
        }
        if ((Mark & BK_HOLLOW_MARK_TI_ALLOC_RW_LARGE) != 0 && (AuxBase != 0 || AuxSize != 0))
        {
            entry->LastAllocBase = AuxBase;
            entry->LastAllocSize = AuxSize;
            entry->LastAllocProtect = AuxProtect;
        }
        if ((Mark & BK_HOLLOW_MARK_TI_WRITE_VM) != 0)
        {
            if (AuxBase != 0)
            {
                entry->LastWriteBase = AuxBase;
            }
            if (AuxSize != 0)
            {
                entry->LastWriteSize = AuxSize;
            }
            entry->LastWriteTick = nowTick;
        }
        if ((Mark & BK_HOLLOW_MARK_TI_PROTECT_RX) != 0)
        {
            if (AuxBase != 0)
            {
                entry->LastProtectRxBase = AuxBase;
            }
            if (AuxSize != 0)
            {
                entry->LastProtectRxSize = AuxSize;
            }
            if (AuxProtect != 0)
            {
                entry->LastProtectRxProtect = AuxProtect;
            }
            entry->LastProtectRxTick = nowTick;
        }
        ControllerEvaluateHollowEntryLocked(entry, nowTick);
    }
    ReleaseSRWLockExclusive(&g_HollowLock);
}

static VOID ControllerHandleBlackbirdHollowRecord(_In_ PEVENT_RECORD Record, _In_opt_z_ PCWSTR EventName,
                                                  _In_ const BKIPC_ETW_EVENT *BrokerEvent)
{
    ULONGLONG processId = 0;
    ULONGLONG creatorPid = 0;
    ULONGLONG startAddress = 0;
    ULONGLONG imageBase = 0;
    ULONGLONG imageSize = 0;
    ULONG startRegionType = 0;
    ULONG startRegionProtect = 0;
    ULONG correlationFlags = 0;
    CHAR detectionName[128];

    if (Record == NULL || EventName == NULL || EventName[0] == L'\0')
    {
        return;
    }

    if (wcscmp(EventName, L"ThreadTelemetry") == 0)
    {
        (void)ControllerEtwGetU64Property(Record, L"processId", &processId);
        (void)ControllerEtwGetU64Property(Record, L"creatorPid", &creatorPid);
        (void)ControllerEtwGetU64Property(Record, L"startAddress", &startAddress);
        (void)ControllerEtwGetU64Property(Record, L"imageBase", &imageBase);
        (void)ControllerEtwGetU64Property(Record, L"imageSize", &imageSize);
        (void)ControllerEtwGetU32Property(Record, L"startRegionType", &startRegionType);
        (void)ControllerEtwGetU32Property(Record, L"startRegionProtect", &startRegionProtect);
        (void)ControllerEtwGetU32Property(Record, L"correlationFlags", &correlationFlags);

        if (processId == 0)
        {
            return;
        }

        if (startAddress != 0)
        {
            ControllerRememberThreadStart((DWORD)creatorPid, (DWORD)processId, startAddress);
        }

        if (imageBase != 0 && imageSize != 0 && startAddress != 0)
        {
            ULONGLONG end = imageBase + imageSize;
            if (end < imageBase || startAddress < imageBase || startAddress >= end)
            {
                ControllerApplyHollowMark((DWORD)creatorPid, (DWORD)processId,
                                          BK_HOLLOW_MARK_THREAD_START_OUTSIDE_IMAGE | BK_HOLLOW_MARK_IMAGE_DRIFT, 0, 0,
                                          0);
            }
        }

        if ((startRegionType != MEM_IMAGE) && ControllerIsExecutableProtect(startRegionProtect))
        {
            ControllerApplyHollowMark((DWORD)creatorPid, (DWORD)processId,
                                      BK_HOLLOW_MARK_THREAD_START_NON_IMAGE_EXEC | BK_HOLLOW_MARK_IMAGE_DRIFT, 0, 0, 0);
        }

        if ((correlationFlags & BK_INTENT_THREAD_CONTEXT) != 0)
        {
            ControllerApplyHollowMark((DWORD)creatorPid, (DWORD)processId, BK_HOLLOW_MARK_THREAD_CONTEXT_INTENT, 0, 0,
                                      0);
        }
        if (creatorPid != 0 && processId != 0 && creatorPid != processId && correlationFlags != 0)
        {
            ControllerApplyHollowMark((DWORD)creatorPid, (DWORD)processId, BK_HOLLOW_MARK_REMOTE_THREAD_INTENT, 0, 0,
                                      0);
        }
        ControllerQueueManualMapProbe((DWORD)creatorPid, (DWORD)processId, startAddress, 0);
        return;
    }

    if (wcscmp(EventName, L"ImageTelemetry") == 0)
    {
        WCHAR imagePath[BKIPC_MAX_ETW_IMAGE_PATH];

        ZeroMemory(imagePath, sizeof(imagePath));
        if (BrokerEvent != NULL)
        {
            processId = BrokerEvent->ProcessId;
            imageBase = BrokerEvent->ImageBase;
            imageSize = BrokerEvent->ImageSize;
            if (BrokerEvent->ImagePath[0] != L'\0')
            {
                (void)StringCchCopyW(imagePath, RTL_NUMBER_OF(imagePath), BrokerEvent->ImagePath);
            }
        }
        else
        {
            (void)ControllerEtwGetU64Property(Record, L"processId", &processId);
            (void)ControllerEtwGetU64Property(Record, L"imageBase", &imageBase);
            (void)ControllerEtwGetU64Property(Record, L"imageSize", &imageSize);
            (void)ControllerEtwGetWideProperty(Record, L"imagePath", imagePath, RTL_NUMBER_OF(imagePath));
        }

        if (processId != 0)
        {
            ULONGLONG nowTick = GetTickCount64();
            AcquireSRWLockExclusive(&g_HollowLock);
            ControllerRememberImageLoadLocked((DWORD)processId, imageBase, imageSize, imagePath, nowTick);
            ReleaseSRWLockExclusive(&g_HollowLock);
        }
        return;
    }

    if (wcscmp(EventName, L"NtApiTelemetry") == 0 && BrokerEvent != NULL)
    {
        ControllerObserveUserHookHollowEvent(BrokerEvent);
        return;
    }

    if (wcscmp(EventName, L"ApcTelemetry") == 0 && BrokerEvent != NULL && BrokerEvent->TargetPid != 0)
    {
        ControllerApplyHollowMark((DWORD)BrokerEvent->ProcessId, (DWORD)BrokerEvent->TargetPid,
                                  BK_HOLLOW_MARK_THREAD_CONTEXT_INTENT, 0, 0, BrokerEvent->DesiredAccess);
        return;
    }

    if (wcscmp(EventName, L"DetectionTelemetry") == 0)
    {
        if (BrokerEvent != NULL && BrokerEvent->DetectionName[0] != '\0')
        {
            (void)StringCchCopyA(detectionName, RTL_NUMBER_OF(detectionName), BrokerEvent->DetectionName);
        }
        else
        {
            detectionName[0] = '\0';
            (void)ControllerEtwGetAnsiProperty(Record, L"detectionName", detectionName, RTL_NUMBER_OF(detectionName));
        }

        if (detectionName[0] == '\0')
        {
            return;
        }

        processId = (BrokerEvent != NULL) ? BrokerEvent->ProcessId : 0;
        creatorPid = (BrokerEvent != NULL) ? BrokerEvent->ProcessId : 0;
        if (BrokerEvent != NULL && BrokerEvent->TargetPid != 0)
        {
            processId = BrokerEvent->TargetPid;
        }

        if (strcmp(detectionName, "THREAD_HIJACK_INTENT") == 0 ||
            strcmp(detectionName, "THREAD_ACTIVITY_WITH_THREAD_CONTEXT_INTENT") == 0 ||
            strcmp(detectionName, "REMOTE_APC_CREATION_SUSPECT") == 0)
        {
            ControllerApplyHollowMark((DWORD)creatorPid, (DWORD)processId, BK_HOLLOW_MARK_THREAD_CONTEXT_INTENT, 0, 0,
                                      0);
        }
        if (strcmp(detectionName, "REMOTE_THREAD_WITH_RECENT_HANDLE_INTENT") == 0)
        {
            ControllerApplyHollowMark((DWORD)creatorPid, (DWORD)processId, BK_HOLLOW_MARK_REMOTE_THREAD_INTENT, 0, 0,
                                      0);
        }
        if (strcmp(detectionName, "REMOTE_THREAD_OUTSIDE_MAIN_IMAGE") == 0 ||
            strcmp(detectionName, "REMOTE_THREAD_START_IN_NON_IMAGE_EXECUTABLE_REGION") == 0 ||
            strcmp(detectionName, "POSSIBLE_MANUAL_MAP_OR_HOLLOWING_EXECUTION") == 0)
        {
            ControllerApplyHollowMark((DWORD)creatorPid, (DWORD)processId,
                                      BK_HOLLOW_MARK_THREAD_START_OUTSIDE_IMAGE |
                                          BK_HOLLOW_MARK_THREAD_START_NON_IMAGE_EXEC | BK_HOLLOW_MARK_IMAGE_DRIFT,
                                      0, 0, 0);
        }
    }
}

static VOID ControllerHandleThreatIntelHollowRecord(_In_ PEVENT_RECORD Record, _In_opt_z_ PCWSTR EventName)
{
    static const PCWSTR callerPidNames[] = {L"CallingProcessId", L"CallerProcessId", L"SourceProcessId", L"ProcessId"};
    static const PCWSTR targetPidNames[] = {L"TargetProcessId", L"NewProcessId", L"DestProcessId", L"ProcessId"};
    static const PCWSTR baseAddressNames[] = {L"BaseAddress", L"AllocationBase", L"Address", L"RegionBase"};
    static const PCWSTR sizeNames[] = {L"RegionSize", L"AllocationSize", L"ViewSize", L"Size", L"DataSize"};
    static const PCWSTR protectNames[] = {L"Protection", L"Protect", L"AllocationProtect", L"NewProtect"};
    static const PCWSTR oldProtectNames[] = {L"OldProtect", L"PreviousProtect", L"ProtectOld"};
    static const PCWSTR newProtectNames[] = {L"NewProtect", L"Protect", L"Protection"};
    static const PCWSTR creationFlagsNames[] = {L"CreationFlags", L"CreateFlags", L"ProcessFlags"};

    USHORT task;
    ULONGLONG callerPid = 0;
    ULONGLONG targetPid = 0;
    ULONGLONG baseAddress = 0;
    ULONGLONG regionSize = 0;
    ULONG protect = 0;
    ULONG oldProtect = 0;
    ULONG newProtect = 0;
    ULONG creationFlags = 0;

    if (Record == NULL)
    {
        return;
    }

    task = Record->EventHeader.EventDescriptor.Task;
    (void)ControllerEtwTryGetU64Any(Record, callerPidNames, RTL_NUMBER_OF(callerPidNames), &callerPid);
    (void)ControllerEtwTryGetU64Any(Record, targetPidNames, RTL_NUMBER_OF(targetPidNames), &targetPid);
    if (targetPid == 0)
    {
        targetPid = callerPid;
    }

    if (EventName != NULL && EventName[0] != L'\0' && ControllerWideContainsInsensitive(EventName, L"createprocess"))
    {
        (void)ControllerEtwTryGetU32Any(Record, creationFlagsNames, RTL_NUMBER_OF(creationFlagsNames), &creationFlags);
        if (((creationFlags & CREATE_SUSPENDED) != 0) || ControllerWideContainsInsensitive(EventName, L"suspend"))
        {
            ControllerApplyHollowMark((DWORD)callerPid, (DWORD)targetPid, BK_HOLLOW_MARK_CREATE_SUSPENDED, 0, 0, 0);
        }
    }
    if (EventName != NULL && EventName[0] != L'\0' &&
        (ControllerWideContainsInsensitive(EventName, L"txf") ||
         ControllerWideContainsInsensitive(EventName, L"transact") ||
         ControllerWideContainsInsensitive(EventName, L"ktransaction") ||
         ControllerWideContainsInsensitive(EventName, L"rollback")))
    {
        ControllerApplyHollowMark((DWORD)callerPid, (DWORD)targetPid, BK_HOLLOW_MARK_TXF_SUSPECT, 0, 0, 0);
    }

    if (targetPid == 0)
    {
        return;
    }

    switch (task)
    {
    case 1:
        (void)ControllerEtwTryGetU64Any(Record, baseAddressNames, RTL_NUMBER_OF(baseAddressNames), &baseAddress);
        (void)ControllerEtwTryGetU64Any(Record, sizeNames, RTL_NUMBER_OF(sizeNames), &regionSize);
        (void)ControllerEtwTryGetU32Any(Record, protectNames, RTL_NUMBER_OF(protectNames), &protect);
        if (regionSize >= BK_CONTROLLER_HOLLOW_LARGE_ALLOC_BYTES && ControllerIsWritableProtect(protect))
        {
            ControllerApplyHollowMark((DWORD)callerPid, (DWORD)targetPid, BK_HOLLOW_MARK_TI_ALLOC_RW_LARGE, baseAddress,
                                      regionSize, protect);
        }
        break;
    case 7:
        (void)ControllerEtwTryGetU64Any(Record, baseAddressNames, RTL_NUMBER_OF(baseAddressNames), &baseAddress);
        (void)ControllerEtwTryGetU64Any(Record, sizeNames, RTL_NUMBER_OF(sizeNames), &regionSize);
        ControllerApplyHollowMark((DWORD)callerPid, (DWORD)targetPid, BK_HOLLOW_MARK_TI_WRITE_VM, baseAddress,
                                  regionSize, 0);
        ControllerQueueManualMapProbe((DWORD)callerPid, (DWORD)targetPid, baseAddress, regionSize);
        break;
    case 2:
        (void)ControllerEtwTryGetU64Any(Record, baseAddressNames, RTL_NUMBER_OF(baseAddressNames), &baseAddress);
        (void)ControllerEtwTryGetU64Any(Record, sizeNames, RTL_NUMBER_OF(sizeNames), &regionSize);
        (void)ControllerEtwTryGetU32Any(Record, oldProtectNames, RTL_NUMBER_OF(oldProtectNames), &oldProtect);
        (void)ControllerEtwTryGetU32Any(Record, newProtectNames, RTL_NUMBER_OF(newProtectNames), &newProtect);
        if ((newProtect != 0 && ControllerIsExecutableProtect(newProtect)) &&
            (oldProtect == 0 || ControllerIsWritableProtect(oldProtect)))
        {
            ControllerApplyHollowMark((DWORD)callerPid, (DWORD)targetPid, BK_HOLLOW_MARK_TI_PROTECT_RX, baseAddress,
                                      regionSize, newProtect);
            ControllerQueueManualMapProbe((DWORD)callerPid, (DWORD)targetPid, baseAddress, regionSize);
        }
        break;
    default:
        break;
    }
}
VOID ControllerProcessHollowingEtwRecord(_In_ PEVENT_RECORD Record, _In_opt_z_ PCWSTR EventName,
                                         _In_ const BKIPC_ETW_EVENT *BrokerEvent)
{
    if (Record == NULL)
    {
        return;
    }

    if (IsEqualGUID(Record->EventHeader.ProviderId, BKSC_PROVIDER_GUID_BLACKBIRD))
    {
        ControllerHandleBlackbirdHollowRecord(Record, EventName, BrokerEvent);
    }
    else if (IsEqualGUID(Record->EventHeader.ProviderId, BKSC_PROVIDER_GUID_TI))
    {
        ControllerHandleThreatIntelHollowRecord(Record, EventName);
    }
}

VOID ControllerObserveUserHookHollowEvent(_In_ const BKIPC_ETW_EVENT *Event)
{
    DWORD actorPid;
    DWORD targetPid;
    ULONGLONG nowTick;
    PBK_CONTROLLER_HOLLOW_ENTRY entry;

    if (Event == NULL || Event->Family != BlackbirdIpcEtwFamilyUserHook || Event->ProcessId == 0)
    {
        return;
    }

    actorPid = (DWORD)Event->ProcessId;
    targetPid = (Event->TargetPid != 0 && Event->TargetPid <= 0xFFFFFFFFull) ? (DWORD)Event->TargetPid : actorPid;
    nowTick = GetTickCount64();

    if ((ControllerAsciiEqualsInsensitive(Event->Operation, "LdrLoadDll") ||
         ControllerAsciiEqualsInsensitive(Event->Operation, "LoadLibraryA") ||
         ControllerAsciiEqualsInsensitive(Event->Operation, "LoadLibraryW") ||
         ControllerAsciiEqualsInsensitive(Event->Operation, "LoadLibraryExA") ||
         ControllerAsciiEqualsInsensitive(Event->Operation, "LoadLibraryExW")) &&
        Event->ImagePath[0] != L'\0')
    {
        AcquireSRWLockExclusive(&g_HollowLock);
        ControllerRememberImageLoadLocked(actorPid, Event->ImageBase, Event->ImageSize, Event->ImagePath, nowTick);
        ReleaseSRWLockExclusive(&g_HollowLock);
        return;
    }

    if (ControllerAsciiEqualsInsensitive(Event->Operation, "NtOpenProcess") && targetPid != 0 &&
        targetPid != actorPid && Event->HookArgCount > 1u)
    {
        ULONG desiredAccess = (ULONG)(Event->HookArgs[1] & 0xFFFFFFFFull);
        if (ControllerHandleAccessLooksProcessInjectionCapable(desiredAccess))
        {
            UINT64 marks = BK_HOLLOW_MARK_PROCESS_HANDLE_INTENT;
            if ((desiredAccess & (PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD)) != 0)
            {
                marks |= BK_HOLLOW_MARK_TI_ALLOC_RW_LARGE;
            }
            ControllerApplyHollowMark(actorPid, targetPid, marks, 0, 0, desiredAccess);
            ControllerReconcileRemoteHandlesForPair(actorPid, targetPid);
        }
        return;
    }

    if ((ControllerAsciiEqualsInsensitive(Event->Operation, "NtAllocateVirtualMemory") ||
         ControllerAsciiEqualsInsensitive(Event->Operation, "NtAllocateVirtualMemoryEx")) &&
        targetPid != 0 && targetPid != actorPid)
    {
        BOOL kernelNtApiEvent =
            (Event->Flags & (BKIPC_ETW_FLAG_HOOK_KERNEL_CALLER | BKIPC_ETW_FLAG_HOOK_USER_CALLER)) != 0;
        BOOL allocateEx = ControllerAsciiEqualsInsensitive(Event->Operation, "NtAllocateVirtualMemoryEx");
        ULONGLONG baseAddress = Event->HookArgCount > 1u ? Event->HookArgs[1] : 0;
        UINT32 regionSizeIndex = kernelNtApiEvent ? 2u : (allocateEx ? 2u : 3u);
        UINT32 protectIndex = allocateEx ? 4u : 5u;
        ULONGLONG regionSize = Event->HookArgCount > regionSizeIndex ? Event->HookArgs[regionSizeIndex] : 0;
        ULONG protect = Event->HookArgCount > protectIndex ? (ULONG)(Event->HookArgs[protectIndex] & 0xFFFFFFFFull) : 0;
        ULONG allocType = Event->HookArgCount > (allocateEx ? 3u : 4u)
                              ? (ULONG)(Event->HookArgs[allocateEx ? 3u : 4u] & 0xFFFFFFFFull)
                              : 0;

        if (!allocateEx && protect == 0 && Event->HookArgCount > 3u)
        {
            protect = (ULONG)(Event->HookArgs[3] & 0xFFFFFFFFull);
        }
        if (regionSize >= BK_CONTROLLER_HOLLOW_LARGE_ALLOC_BYTES || ControllerIsWritableProtect(protect) ||
            ControllerIsExecutableProtect(protect))
        {
            ControllerApplyHollowMark(actorPid, targetPid, BK_HOLLOW_MARK_TI_ALLOC_RW_LARGE, baseAddress, regionSize,
                                      (protect != 0) ? protect : allocType);
        }
        return;
    }

    if (ControllerAsciiEqualsInsensitive(Event->Operation, "NtProtectVirtualMemory") && targetPid != 0 &&
        targetPid != actorPid)
    {
        ULONGLONG baseAddress = Event->HookArgCount > 1u ? Event->HookArgs[1] : 0;
        ULONGLONG regionSize = Event->HookArgCount > 2u ? Event->HookArgs[2] : 0;
        ULONG newProtect = Event->HookArgCount > 3u ? (ULONG)(Event->HookArgs[3] & 0xFFFFFFFFull) : 0;

        if (ControllerIsExecutableProtect(newProtect))
        {
            ControllerApplyHollowMark(actorPid, targetPid, BK_HOLLOW_MARK_TI_PROTECT_RX, baseAddress, regionSize,
                                      newProtect);
            ControllerQueueManualMapProbe(actorPid, targetPid, baseAddress, regionSize);
        }
        return;
    }

    if (ControllerAsciiEqualsInsensitive(Event->Operation, "NtWriteVirtualMemory") && targetPid != 0 &&
        targetPid != actorPid)
    {
        ULONGLONG baseAddress = Event->HookArgCount > 1u ? Event->HookArgs[1] : 0;
        ULONGLONG regionSize = Event->HookArgCount > 3u ? Event->HookArgs[3] : 0;

        AcquireSRWLockExclusive(&g_HollowLock);
        entry = ControllerGetHollowEntryLocked(actorPid, targetPid, nowTick);
        if (entry != NULL)
        {
            entry->LastSeenTick = nowTick;
            entry->Marks |= BK_HOLLOW_MARK_TI_WRITE_VM;
            if (baseAddress != 0)
            {
                entry->LastWriteBase = baseAddress;
            }
            if (regionSize != 0)
            {
                entry->LastWriteSize = regionSize;
            }
            entry->LastWriteTick = nowTick;
            if (ControllerSampleLooksLikeDllPath(Event->DeepSample, Event->DeepSampleSize))
            {
                entry->LastDllPathWriteTick = nowTick;
            }
            ControllerEvaluateHollowEntryLocked(entry, nowTick);
        }
        ReleaseSRWLockExclusive(&g_HollowLock);
        ControllerQueueManualMapProbe(actorPid, targetPid, baseAddress, regionSize);
        return;
    }

    if ((ControllerAsciiEqualsInsensitive(Event->Operation, "NtUnmapViewOfSection") ||
         ControllerAsciiEqualsInsensitive(Event->Operation, "NtUnmapViewOfSectionEx")) &&
        targetPid != 0 && targetPid != actorPid)
    {
        ULONGLONG baseAddress = Event->HookArgCount > 1u ? Event->HookArgs[1] : 0;
        ControllerApplyHollowMark(actorPid, targetPid, BK_HOLLOW_MARK_UNMAP_VIEW | BK_HOLLOW_MARK_IMAGE_DRIFT,
                                  baseAddress, 0, 0);
        return;
    }

    if ((ControllerAsciiEqualsInsensitive(Event->Operation, "NtCreateThread") ||
         ControllerAsciiEqualsInsensitive(Event->Operation, "NtCreateThreadEx")) &&
        targetPid != 0 && targetPid != actorPid)
    {
        ULONGLONG regionBase = 0;
        ULONGLONG regionSize = 0;
        BOOL hasPe = FALSE;
        ULONGLONG startRoutine =
            ControllerAsciiEqualsInsensitive(Event->Operation, "NtCreateThreadEx") ? Event->HookArgs[3] : 0;
        UINT32 kind = ControllerClassifyExecutionTarget(targetPid, startRoutine, &regionBase, &regionSize, &hasPe);

        AcquireSRWLockExclusive(&g_HollowLock);
        entry = ControllerGetHollowEntryLocked(actorPid, targetPid, nowTick);
        if (entry != NULL)
        {
            entry->LastSeenTick = nowTick;
            entry->LastThreadCreateTarget = startRoutine;
            entry->LastThreadCreateTick = nowTick;
            entry->LastThreadCreateKind = kind;
            entry->LastThreadCreateHasPe = hasPe ? 1u : 0u;
            entry->LastThreadCreateRegionBase = regionBase;
            entry->LastThreadCreateRegionSize = regionSize;
            entry->Marks |= BK_HOLLOW_MARK_REMOTE_THREAD_INTENT;
            if (kind == BK_HOLLOW_EXEC_KIND_PRIVATE_EXEC)
            {
                entry->Marks |= BK_HOLLOW_MARK_THREAD_START_NON_IMAGE_EXEC | BK_HOLLOW_MARK_THREAD_START_OUTSIDE_IMAGE;
            }
            ControllerEvaluateHollowEntryLocked(entry, nowTick);
        }
        ReleaseSRWLockExclusive(&g_HollowLock);
        if (kind == BK_HOLLOW_EXEC_KIND_PRIVATE_EXEC)
        {
            ControllerQueueManualMapProbe(actorPid, targetPid, startRoutine, 0);
        }
        return;
    }

    if ((ControllerAsciiEqualsInsensitive(Event->Operation, "NtQueueApcThread") ||
         ControllerAsciiEqualsInsensitive(Event->Operation, "NtQueueApcThreadEx") ||
         ControllerAsciiEqualsInsensitive(Event->Operation, "NtQueueApcThreadEx2")) &&
        targetPid != 0 && targetPid != actorPid)
    {
        ULONGLONG routine =
            ControllerAsciiEqualsInsensitive(Event->Operation, "NtQueueApcThread")
                ? Event->HookArgs[1]
                : (ControllerAsciiEqualsInsensitive(Event->Operation, "NtQueueApcThreadEx2") ? Event->HookArgs[3]
                                                                                             : Event->HookArgs[2]);
        ULONGLONG regionBase = 0;
        ULONGLONG regionSize = 0;
        BOOL hasPe = FALSE;
        UINT32 kind = ControllerClassifyExecutionTarget(targetPid, routine, &regionBase, &regionSize, &hasPe);

        AcquireSRWLockExclusive(&g_HollowLock);
        entry = ControllerGetHollowEntryLocked(actorPid, targetPid, nowTick);
        if (entry != NULL)
        {
            entry->LastSeenTick = nowTick;
            entry->LastApcRoutine = routine;
            entry->LastApcTick = nowTick;
            entry->LastApcKind = kind;
            entry->LastApcHasPe = hasPe ? 1u : 0u;
            entry->LastApcRegionBase = regionBase;
            entry->LastApcRegionSize = regionSize;
            entry->Marks |= BK_HOLLOW_MARK_THREAD_CONTEXT_INTENT;
            ControllerEvaluateHollowEntryLocked(entry, nowTick);
        }
        ReleaseSRWLockExclusive(&g_HollowLock);
        if (kind == BK_HOLLOW_EXEC_KIND_PRIVATE_EXEC)
        {
            ControllerQueueManualMapProbe(actorPid, targetPid, routine, 0);
        }
        return;
    }

    if (ControllerAsciiEqualsInsensitive(Event->Operation, "NtSetContextThread") && targetPid != 0 &&
        targetPid != actorPid)
    {
        ULONGLONG regionBase = 0;
        ULONGLONG regionSize = 0;
        BOOL hasPe = FALSE;
        UINT32 kind =
            ControllerClassifyExecutionTarget(targetPid, Event->HookArgs[2], &regionBase, &regionSize, &hasPe);

        AcquireSRWLockExclusive(&g_HollowLock);
        entry = ControllerGetHollowEntryLocked(actorPid, targetPid, nowTick);
        if (entry != NULL)
        {
            entry->LastSeenTick = nowTick;
            entry->LastSetContextRip = Event->HookArgs[2];
            entry->LastSetContextRsp = Event->HookArgs[3];
            entry->LastSetContextTick = nowTick;
            entry->LastSetContextKind = kind;
            entry->LastSetContextHasPe = hasPe ? 1u : 0u;
            entry->LastSetContextRegionBase = regionBase;
            entry->LastSetContextRegionSize = regionSize;
            entry->Marks |= BK_HOLLOW_MARK_THREAD_CONTEXT_INTENT;
            ControllerEvaluateHollowEntryLocked(entry, nowTick);
        }
        ReleaseSRWLockExclusive(&g_HollowLock);
        if (kind == BK_HOLLOW_EXEC_KIND_PRIVATE_EXEC)
        {
            ControllerQueueManualMapProbe(actorPid, targetPid, Event->HookArgs[2], 0);
        }
        return;
    }

    if (ControllerAsciiEqualsInsensitive(Event->Operation, "NtSuspendThread") && targetPid != 0 &&
        targetPid != actorPid)
    {
        AcquireSRWLockExclusive(&g_HollowLock);
        entry = ControllerGetHollowEntryLocked(actorPid, targetPid, nowTick);
        if (entry != NULL)
        {
            entry->LastSeenTick = nowTick;
            entry->LastSuspendTick = nowTick;
            ControllerEvaluateHollowEntryLocked(entry, nowTick);
        }
        ReleaseSRWLockExclusive(&g_HollowLock);
        return;
    }

    if (ControllerAsciiEqualsInsensitive(Event->Operation, "NtResumeThread") && targetPid != 0 && targetPid != actorPid)
    {
        AcquireSRWLockExclusive(&g_HollowLock);
        entry = ControllerGetHollowEntryLocked(actorPid, targetPid, nowTick);
        if (entry != NULL)
        {
            entry->LastSeenTick = nowTick;
            entry->LastResumeTick = nowTick;
            ControllerEvaluateHollowEntryLocked(entry, nowTick);
        }
        ReleaseSRWLockExclusive(&g_HollowLock);
    }
}

static DWORD WINAPI ControllerManualMapProbeThreadProc(_In_ LPVOID Context)
{
    HANDLE waitHandles[2];

    UNREFERENCED_PARAMETER(Context);

    waitHandles[0] = g_StopEvent;
    waitHandles[1] = g_ManualMapProbeEvent.get();

    for (;;)
    {
        DWORD waitResult = WaitForMultipleObjects(RTL_NUMBER_OF(waitHandles), waitHandles, FALSE, INFINITE);
        BK_CONTROLLER_MANUAL_MAP_PROBE_REQUEST request;

        if (waitResult == WAIT_OBJECT_0)
        {
            break;
        }
        if (waitResult != (WAIT_OBJECT_0 + 1))
        {
            continue;
        }

        while (ControllerManualMapProbeDequeue(&request))
        {
            ControllerTryEmitManualMapDetection(request.ActorPid, request.TargetPid, request.BaseHint,
                                                request.SizeHint);
        }
    }

    return 0;
}

BOOL ControllerStartHollowingWorkers(VOID)
{
    if (g_ManualMapProbeThread)
    {
        return TRUE;
    }

    ZeroMemory(g_ManualMapProbeQueue, sizeof(g_ManualMapProbeQueue));
    g_ManualMapProbeEvent.reset(CreateEventW(NULL, FALSE, FALSE, NULL));
    if (!g_ManualMapProbeEvent)
    {
        return FALSE;
    }

    g_ManualMapProbeThread.reset(CreateThread(NULL, 0, ControllerManualMapProbeThreadProc, NULL, 0, NULL));
    if (!g_ManualMapProbeThread)
    {
        g_ManualMapProbeEvent.reset();
        return FALSE;
    }

    return TRUE;
}

VOID ControllerStopHollowingWorkers(VOID)
{
    if (g_ManualMapProbeEvent)
    {
        (void)SetEvent(g_ManualMapProbeEvent.get());
    }

    if (g_ManualMapProbeThread)
    {
        (void)WaitForSingleObject(g_ManualMapProbeThread.get(), 3000);
        g_ManualMapProbeThread.reset();
    }

    g_ManualMapProbeEvent.reset();

    EnterCriticalSection(g_ManualMapProbeLock.get());
    ZeroMemory(g_ManualMapProbeQueue, sizeof(g_ManualMapProbeQueue));
    LeaveCriticalSection(g_ManualMapProbeLock.get());
}

VOID ControllerResetHollowingState(VOID)
{
    AcquireSRWLockExclusive(&g_HollowLock);
    ZeroMemory(g_HollowEntries, sizeof(g_HollowEntries));
    ReleaseSRWLockExclusive(&g_HollowLock);
}
