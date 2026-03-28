#include <ntddk.h>
#include "..\..\core\control.h"
#include "..\..\core\runtime_config.h"
#include "..\..\telemetry\etw.h"
#include "..\hook\ntapi_hook.h"
#include "ntapi_monitor.h"

#if defined(_AMD64_)

#define BLACKBIRD_NTAPI_LOG(_level, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, (_level), __VA_ARGS__)
#define BLACKBIRD_SYSTEM_INFORMATION_CLASS_PROCESS 5u
#define BLACKBIRD_SYSTEM_INFORMATION_CLASS_MODULE 11u
#define BLACKBIRD_SYSTEM_INFORMATION_CLASS_KERNEL_DEBUGGER 35u
#define BLACKBIRD_SYSTEM_INFORMATION_CLASS_FIRMWARE_TABLE 76u
#define BLACKBIRD_FIRMWARE_PROVIDER_RSMB 0x424D5352u

typedef struct _BLACKBIRD_SYSTEM_KERNEL_DEBUGGER_INFORMATION
{
    BOOLEAN KernelDebuggerEnabled;
    BOOLEAN KernelDebuggerNotPresent;
} BLACKBIRD_SYSTEM_KERNEL_DEBUGGER_INFORMATION, *PBLACKBIRD_SYSTEM_KERNEL_DEBUGGER_INFORMATION;

typedef NTSTATUS(NTAPI *PBLACKBIRD_NT_QUERY_SYSTEM_INFORMATION)(_In_ ULONG SystemInformationClass,
                                                                _Out_writes_bytes_opt_(SystemInformationLength)
                                                                    PVOID SystemInformation,
                                                                _In_ ULONG SystemInformationLength,
                                                                _Out_opt_ PULONG ReturnLength);
typedef NTSTATUS(NTAPI *PBLACKBIRD_NT_QUERY_INFORMATION_PROCESS)(_In_ HANDLE ProcessHandle,
                                                                 _In_ ULONG ProcessInformationClass,
                                                                 _Out_writes_bytes_opt_(ProcessInformationLength)
                                                                     PVOID ProcessInformation,
                                                                 _In_ ULONG ProcessInformationLength,
                                                                 _Out_opt_ PULONG ReturnLength);
typedef NTSTATUS(NTAPI *PBLACKBIRD_NT_WRITE_VIRTUAL_MEMORY)(_In_ HANDLE ProcessHandle, _In_ PVOID BaseAddress,
                                                            _In_reads_bytes_(BufferSize) PVOID Buffer,
                                                            _In_ SIZE_T BufferSize,
                                                            _Out_opt_ PSIZE_T NumberOfBytesWritten);
typedef NTSTATUS(NTAPI *PBLACKBIRD_NT_PROTECT_VIRTUAL_MEMORY)(_In_ HANDLE ProcessHandle, _Inout_ PVOID *BaseAddress,
                                                              _Inout_ PSIZE_T RegionSize, _In_ ULONG NewProtect,
                                                              _Out_ PULONG OldProtect);
typedef NTSTATUS(NTAPI *PBLACKBIRD_NT_CREATE_SECTION)(_Out_ PHANDLE SectionHandle, _In_ ACCESS_MASK DesiredAccess,
                                                      _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
                                                      _In_opt_ PLARGE_INTEGER MaximumSize,
                                                      _In_ ULONG SectionPageProtection, _In_ ULONG AllocationAttributes,
                                                      _In_opt_ HANDLE FileHandle);
typedef NTSTATUS(NTAPI *PBLACKBIRD_NT_MAP_VIEW_OF_SECTION)(_In_ HANDLE SectionHandle, _In_ HANDLE ProcessHandle,
                                                           _Inout_ PVOID *BaseAddress, _In_ ULONG_PTR ZeroBits,
                                                           _In_ SIZE_T CommitSize,
                                                           _Inout_opt_ PLARGE_INTEGER SectionOffset,
                                                           _Inout_ PSIZE_T ViewSize, _In_ ULONG InheritDisposition,
                                                           _In_ ULONG AllocationType, _In_ ULONG Win32Protect);
typedef NTSTATUS(NTAPI *PBLACKBIRD_NT_ALLOCATE_VIRTUAL_MEMORY)(_In_ HANDLE ProcessHandle, _Inout_ PVOID *BaseAddress,
                                                               _In_ ULONG_PTR ZeroBits, _Inout_ PSIZE_T RegionSize,
                                                               _In_ ULONG AllocationType, _In_ ULONG Protect);
typedef NTSTATUS(NTAPI *PBLACKBIRD_NT_QUERY_SYSTEM_INFORMATION_EX)(
    _In_ ULONG SystemInformationClass, _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength, _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
    _In_ ULONG SystemInformationLength, _Out_opt_ PULONG ReturnLength);

typedef enum _BLACKBIRD_HOOK_ID
{
    BLACKBIRD_HOOK_QUERY_SYSTEM_INFORMATION = 0,
    BLACKBIRD_HOOK_QUERY_INFORMATION_PROCESS,
    BLACKBIRD_HOOK_WRITE_VIRTUAL_MEMORY,
    BLACKBIRD_HOOK_PROTECT_VIRTUAL_MEMORY,
    BLACKBIRD_HOOK_CREATE_SECTION,
    BLACKBIRD_HOOK_MAP_VIEW_OF_SECTION,
    BLACKBIRD_HOOK_ALLOCATE_VIRTUAL_MEMORY,
    BLACKBIRD_HOOK_QUERY_SYSTEM_INFORMATION_EX,
    BLACKBIRD_HOOK_COUNT
} BLACKBIRD_HOOK_ID;

static volatile LONG g_NtApiMonitorInitialized = 0;
static volatile LONG g_NtApiMonitorUnloading = 0;
EX_RUNDOWN_REF g_NtApiRundown;
volatile LONG g_NtApiAllocatePreLogBudget = 64;
static volatile LONG g_NtApiSkipInitBudget = 8;
static volatile LONG g_NtApiSkipIrqlBudget = 8;
static volatile LONG g_NtApiSkipArmedBudget = 8;
static volatile LONG g_NtApiSkipPidBudget = 8;
static volatile LONG g_NtApiSkipRundownBudget = 8;
static volatile LONG g_NtApiHookInFlight = 0;
static volatile LONG g_NtApiUninitWaitBudget = 16;
static volatile LONG g_NtApiKdSanitizeBudget = 16;
static volatile LONG g_NtApiKdSanitizeApplyBudget = 16;
static volatile UCHAR *g_NtApiSharedKdByte = NULL;
static UCHAR g_NtApiSharedKdOriginalValue = 0;
static BOOLEAN g_NtApiSharedKdSpoofActive = FALSE;
volatile LONG g_NtApiSmbiosSanitizeBudget = 16;
volatile LONG g_NtApiSmbiosSanitizeApplyBudget = 16;

PBLACKBIRD_NT_QUERY_SYSTEM_INFORMATION g_OriginalNtQuerySystemInformation = NULL;
PBLACKBIRD_NT_QUERY_INFORMATION_PROCESS g_OriginalNtQueryInformationProcess = NULL;
PBLACKBIRD_NT_WRITE_VIRTUAL_MEMORY g_OriginalNtWriteVirtualMemory = NULL;
PBLACKBIRD_NT_PROTECT_VIRTUAL_MEMORY g_OriginalNtProtectVirtualMemory = NULL;
PBLACKBIRD_NT_CREATE_SECTION g_OriginalNtCreateSection = NULL;
PBLACKBIRD_NT_MAP_VIEW_OF_SECTION g_OriginalNtMapViewOfSection = NULL;
PBLACKBIRD_NT_ALLOCATE_VIRTUAL_MEMORY g_OriginalNtAllocateVirtualMemory = NULL;
PBLACKBIRD_NT_QUERY_SYSTEM_INFORMATION_EX g_OriginalNtQuerySystemInformationEx = NULL;

NTSTATUS NTAPI BLACKBIRDNtQuerySystemInformationHook(_In_ ULONG SystemInformationClass,
                                                     _Out_writes_bytes_opt_(SystemInformationLength)
                                                         PVOID SystemInformation,
                                                     _In_ ULONG SystemInformationLength, _Out_opt_ PULONG ReturnLength);
NTSTATUS NTAPI BLACKBIRDNtQueryInformationProcessHook(_In_ HANDLE ProcessHandle, _In_ ULONG ProcessInformationClass,
                                                      _Out_writes_bytes_opt_(ProcessInformationLength)
                                                          PVOID ProcessInformation,
                                                      _In_ ULONG ProcessInformationLength,
                                                      _Out_opt_ PULONG ReturnLength);
NTSTATUS NTAPI BLACKBIRDNtWriteVirtualMemoryHook(_In_ HANDLE ProcessHandle, _In_ PVOID BaseAddress,
                                                 _In_reads_bytes_(BufferSize) PVOID Buffer, _In_ SIZE_T BufferSize,
                                                 _Out_opt_ PSIZE_T NumberOfBytesWritten);
NTSTATUS NTAPI BLACKBIRDNtProtectVirtualMemoryHook(_In_ HANDLE ProcessHandle, _Inout_ PVOID *BaseAddress,
                                                   _Inout_ PSIZE_T RegionSize, _In_ ULONG NewProtect,
                                                   _Out_ PULONG OldProtect);
NTSTATUS NTAPI BLACKBIRDNtCreateSectionHook(_Out_ PHANDLE SectionHandle, _In_ ACCESS_MASK DesiredAccess,
                                            _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
                                            _In_opt_ PLARGE_INTEGER MaximumSize, _In_ ULONG SectionPageProtection,
                                            _In_ ULONG AllocationAttributes, _In_opt_ HANDLE FileHandle);
NTSTATUS NTAPI BLACKBIRDNtMapViewOfSectionHook(_In_ HANDLE SectionHandle, _In_ HANDLE ProcessHandle,
                                               _Inout_ PVOID *BaseAddress, _In_ ULONG_PTR ZeroBits,
                                               _In_ SIZE_T CommitSize, _Inout_opt_ PLARGE_INTEGER SectionOffset,
                                               _Inout_ PSIZE_T ViewSize, _In_ ULONG InheritDisposition,
                                               _In_ ULONG AllocationType, _In_ ULONG Win32Protect);
NTSTATUS NTAPI BLACKBIRDNtQuerySystemInformationExHook(
    _In_ ULONG SystemInformationClass, _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength, _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
    _In_ ULONG SystemInformationLength, _Out_opt_ PULONG ReturnLength);
extern NTSTATUS NTAPI BLACKBIRDNtAllocateVirtualMemoryHookStub(_In_ HANDLE ProcessHandle, _Inout_ PVOID *BaseAddress,
                                                               _In_ ULONG_PTR ZeroBits, _Inout_ PSIZE_T RegionSize,
                                                               _In_ ULONG AllocationType, _In_ ULONG Protect);
VOID BLACKBIRDNtApiHookExit(VOID);

VOID BLACKBIRDNtApiHookEnter(VOID);
static VOID BLACKBIRDNtApiWaitForInFlightCalls(VOID);
VOID BLACKBIRDNtApiSanitizeKernelDebuggerInformation(_In_ ULONG SystemInformationClass,
                                                     _Out_writes_bytes_opt_(SystemInformationLength)
                                                         PVOID SystemInformation,
                                                     _In_ ULONG SystemInformationLength, _In_ NTSTATUS Status);
VOID BLACKBIRDNtApiSanitizeFirmwareTableInformation(_In_ ULONG SystemInformationClass,
                                                    _Inout_updates_bytes_opt_(SystemInformationLength)
                                                        PVOID SystemInformation,
                                                    _In_ ULONG SystemInformationLength, _In_ NTSTATUS Status);

static volatile UCHAR *BLACKBIRDNtApiGetSharedKdByteAddress(VOID)
{
    return (volatile UCHAR *)((PUCHAR)SharedUserData + FIELD_OFFSET(KUSER_SHARED_DATA, KdDebuggerEnabled));
}

static VOID BLACKBIRDNtApiApplySharedKdSpoof(VOID)
{
    volatile UCHAR *sharedKdByte;
    const UCHAR desiredValue = 0x00u;

    sharedKdByte = BLACKBIRDNtApiGetSharedKdByteAddress();
    if (sharedKdByte == NULL)
    {
        return;
    }

    g_NtApiSharedKdByte = sharedKdByte;
    g_NtApiSharedKdOriginalValue = *sharedKdByte;
    if (*sharedKdByte != desiredValue)
    {
        *sharedKdByte = desiredValue;
        KeMemoryBarrier();
    }
    g_NtApiSharedKdSpoofActive = TRUE;
}

static VOID BLACKBIRDNtApiRestoreSharedKdSpoof(VOID)
{
    volatile UCHAR *sharedKdByte;

    if (!g_NtApiSharedKdSpoofActive)
    {
        return;
    }

    sharedKdByte = g_NtApiSharedKdByte;
    if (sharedKdByte != NULL)
    {
        *sharedKdByte = g_NtApiSharedKdOriginalValue;
        KeMemoryBarrier();
    }

    g_NtApiSharedKdByte = NULL;
    g_NtApiSharedKdSpoofActive = FALSE;
    g_NtApiSharedKdOriginalValue = 0;
}

static BLACKBIRD_NTAPI_HOOK g_Hooks[BLACKBIRD_HOOK_COUNT];
static const BLACKBIRD_NTAPI_HOOK_DESCRIPTOR g_HookDescriptors[BLACKBIRD_HOOK_COUNT] = {
    {"NtQuerySystemInformation",
     L"NtQuerySystemInformation",
     L"ZwQuerySystemInformation",
     NULL,
     (PVOID)BLACKBIRDNtQuerySystemInformationHook,
     18,
     TRUE,
     0,
     {0},
     0},
    {"NtQueryInformationProcess",
     L"NtQueryProcessInformation",
     L"NtQueryInformationProcess",
     L"ZwQueryInformationProcess",
     (PVOID)BLACKBIRDNtQueryInformationProcessHook,
     19,
     TRUE,
     0,
     {0},
     0},
    {"NtWriteVirtualMemory",
     L"NtWriteVirtualMemory",
     L"ZwWriteVirtualMemory",
     NULL,
     (PVOID)BLACKBIRDNtWriteVirtualMemoryHook,
     17,
     TRUE,
     0,
     {0x48, 0x83, 0xEC, 0x38, 0x48, 0x8B, 0x44, 0x24},
     8},
    {"NtProtectVirtualMemory",
     L"NtProtectVirtualMemory",
     L"ZwProtectVirtualMemory",
     NULL,
     (PVOID)BLACKBIRDNtProtectVirtualMemoryHook,
     20,
     TRUE,
     0,
     {0},
     0},
    {"NtCreateSection",
     L"NtCreateSection",
     L"ZwCreateSection",
     NULL,
     (PVOID)BLACKBIRDNtCreateSectionHook,
     17,
     TRUE,
     0,
     {0},
     0},
    {"NtMapViewOfSection",
     L"NtMapViewOfSection",
     L"ZwMapViewOfSection",
     NULL,
     (PVOID)BLACKBIRDNtMapViewOfSectionHook,
     15,
     TRUE,
     0,
     {0},
     0},
    {"NtAllocateVirtualMemory",
     L"NtAllocateVirtualMemory",
     L"ZwAllocateVirtualMemory",
     NULL,
     (PVOID)BLACKBIRDNtAllocateVirtualMemoryHookStub,
     20,
     TRUE,
     0,
     {0},
     0},
    {"NtQuerySystemInformationEx",
     L"NtQuerySystemInformationEx",
     L"ZwQuerySystemInformationEx",
     NULL,
     (PVOID)BLACKBIRDNtQuerySystemInformationExHook,
     20,
     TRUE,
     0,
     {0},
     0},
};

static PVOID *BLACKBIRDNtApiOriginalSlot(_In_ BLACKBIRD_HOOK_ID HookId)
{
    switch (HookId)
    {
    case BLACKBIRD_HOOK_QUERY_SYSTEM_INFORMATION:
        return (PVOID *)&g_OriginalNtQuerySystemInformation;
    case BLACKBIRD_HOOK_QUERY_INFORMATION_PROCESS:
        return (PVOID *)&g_OriginalNtQueryInformationProcess;
    case BLACKBIRD_HOOK_WRITE_VIRTUAL_MEMORY:
        return (PVOID *)&g_OriginalNtWriteVirtualMemory;
    case BLACKBIRD_HOOK_PROTECT_VIRTUAL_MEMORY:
        return (PVOID *)&g_OriginalNtProtectVirtualMemory;
    case BLACKBIRD_HOOK_CREATE_SECTION:
        return (PVOID *)&g_OriginalNtCreateSection;
    case BLACKBIRD_HOOK_MAP_VIEW_OF_SECTION:
        return (PVOID *)&g_OriginalNtMapViewOfSection;
    case BLACKBIRD_HOOK_ALLOCATE_VIRTUAL_MEMORY:
        return (PVOID *)&g_OriginalNtAllocateVirtualMemory;
    case BLACKBIRD_HOOK_QUERY_SYSTEM_INFORMATION_EX:
        return (PVOID *)&g_OriginalNtQuerySystemInformationEx;
    default:
        return NULL;
    }
}

VOID BLACKBIRDNtApiHookEnter(VOID)
{
    InterlockedIncrement(&g_NtApiHookInFlight);
}

VOID BLACKBIRDNtApiHookExit(VOID)
{
    LONG remaining;

    remaining = InterlockedDecrement(&g_NtApiHookInFlight);
    if (remaining < 0)
    {
        InterlockedExchange(&g_NtApiHookInFlight, 0);
        BLACKBIRD_NTAPI_LOG(DPFLTR_ERROR_LEVEL, "BLACKBIRD: ntapi hook in-flight underflow detected and corrected.\n");
    }
}

static VOID BLACKBIRDNtApiWaitForInFlightCalls(VOID)
{
    LARGE_INTEGER delay;
    LONG inFlight;

    delay.QuadPart = -10 * 1000; // 1ms
    for (;;)
    {
        inFlight = InterlockedCompareExchange(&g_NtApiHookInFlight, 0, 0);
        if (inFlight == 0)
        {
            break;
        }

        if (InterlockedDecrement(&g_NtApiUninitWaitBudget) >= 0)
        {
            BLACKBIRD_NTAPI_LOG(DPFLTR_INFO_LEVEL, "BLACKBIRD: ntapi unload waiting for in-flight hooks count=%ld.\n",
                                inFlight);
        }
        KeDelayExecutionThread(KernelMode, FALSE, &delay);
    }
}

VOID BLACKBIRDNtApiSanitizeKernelDebuggerInformation(_In_ ULONG SystemInformationClass,
                                                     _Out_writes_bytes_opt_(SystemInformationLength)
                                                         PVOID SystemInformation,
                                                     _In_ ULONG SystemInformationLength, _In_ NTSTATUS Status)
{
    PBLACKBIRD_SYSTEM_KERNEL_DEBUGGER_INFORMATION info;

    if (SystemInformationClass != BLACKBIRD_SYSTEM_INFORMATION_CLASS_KERNEL_DEBUGGER || !NT_SUCCESS(Status) ||
        SystemInformation == NULL || SystemInformationLength < sizeof(*info))
    {
        return;
    }

    __try
    {
        info = (PBLACKBIRD_SYSTEM_KERNEL_DEBUGGER_INFORMATION)SystemInformation;
        info->KernelDebuggerEnabled = FALSE;
        info->KernelDebuggerNotPresent = TRUE;
        if (InterlockedDecrement(&g_NtApiKdSanitizeApplyBudget) >= 0)
        {
            BLACKBIRD_NTAPI_LOG(DPFLTR_INFO_LEVEL,
                                "BLACKBIRD: ntapi sanitized kernel-debugger info class=0x%lX enabled=0 notPresent=1.\n",
                                SystemInformationClass);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        if (InterlockedDecrement(&g_NtApiKdSanitizeBudget) >= 0)
        {
            BLACKBIRD_NTAPI_LOG(
                DPFLTR_WARNING_LEVEL,
                "BLACKBIRD: ntapi kernel-debugger sanitize failed class=0x%lX status=0x%08X ex=0x%08X.\n",
                SystemInformationClass, Status, GetExceptionCode());
        }
    }
}

typedef struct _BLACKBIRD_SYSTEM_PROCESS_INFORMATION
{
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize;
    ULONG HardFaultCount;
    ULONG NumberOfThreadsHighWatermark;
    ULONGLONG CycleTime;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    PVOID InheritedFromUniqueProcessId;
} BLACKBIRD_SYSTEM_PROCESS_INFORMATION, *PBLACKBIRD_SYSTEM_PROCESS_INFORMATION;

typedef struct _BLACKBIRD_SYSTEM_MODULE_ENTRY
{
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} BLACKBIRD_SYSTEM_MODULE_ENTRY, *PBLACKBIRD_SYSTEM_MODULE_ENTRY;

typedef struct _BLACKBIRD_SYSTEM_MODULE_INFORMATION
{
    ULONG NumberOfModules;
    BLACKBIRD_SYSTEM_MODULE_ENTRY Modules[1];
} BLACKBIRD_SYSTEM_MODULE_INFORMATION, *PBLACKBIRD_SYSTEM_MODULE_INFORMATION;

static BOOLEAN BLACKBIRDNtApiUnicodeEqualsInsensitive(_In_ PCUNICODE_STRING Value, _In_ PCUNICODE_STRING Expected)
{
    if (Value == NULL || Expected == NULL || Value->Buffer == NULL || Expected->Buffer == NULL)
    {
        return FALSE;
    }

    return RtlEqualUnicodeString(Value, Expected, TRUE);
}

static BOOLEAN BLACKBIRDNtApiAnsiEqualsInsensitive(_In_z_ const UCHAR *Value, _In_z_ const CHAR *Expected)
{
    SIZE_T i = 0;
    CHAR left;
    CHAR right;

    if (Value == NULL || Expected == NULL)
    {
        return FALSE;
    }

    for (;;)
    {
        left = (CHAR)Value[i];
        right = Expected[i];
        if (left >= 'A' && left <= 'Z')
        {
            left = (CHAR)(left - 'A' + 'a');
        }
        if (right >= 'A' && right <= 'Z')
        {
            right = (CHAR)(right - 'A' + 'a');
        }
        if (left != right)
        {
            return FALSE;
        }
        if (left == '\0')
        {
            return TRUE;
        }
        i++;
    }
}

VOID BLACKBIRDNtApiSanitizeProcessInformation(_In_ ULONG SystemInformationClass,
                                             _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
                                             _In_ ULONG SystemInformationLength, _In_ NTSTATUS Status)
{
    static const UNICODE_STRING selfHiddenNames[] = {
        RTL_CONSTANT_STRING(L"BlackbirdController.exe"),
    };
    static const UNICODE_STRING antiVirtualizationNames[] = {
        RTL_CONSTANT_STRING(L"vmtoolsd.exe"),
        RTL_CONSTANT_STRING(L"vm3dservice.exe"),
        RTL_CONSTANT_STRING(L"VGAuthService.exe"),
        RTL_CONSTANT_STRING(L"vboxservice.exe"),
        RTL_CONSTANT_STRING(L"vboxtray.exe"),
        RTL_CONSTANT_STRING(L"qemu-ga.exe"),
        RTL_CONSTANT_STRING(L"qga.exe"),
        RTL_CONSTANT_STRING(L"qemuwmiagent.exe"),
        RTL_CONSTANT_STRING(L"spice-vdagent.exe"),
        RTL_CONSTANT_STRING(L"spice-agent.exe"),
        RTL_CONSTANT_STRING(L"spice-vdagentd.exe"),
        RTL_CONSTANT_STRING(L"virtiofs.exe"),
        RTL_CONSTANT_STRING(L"virtiofsd.exe"),
        RTL_CONSTANT_STRING(L"prl_tools.exe"),
        RTL_CONSTANT_STRING(L"prl_cc.exe"),
        RTL_CONSTANT_STRING(L"prl_tools_service.exe"),
        RTL_CONSTANT_STRING(L"xenservice.exe"),
        RTL_CONSTANT_STRING(L"xensvc.exe"),
    };
    PUCHAR base;
    PBLACKBIRD_SYSTEM_PROCESS_INFORMATION previous;
    PBLACKBIRD_SYSTEM_PROCESS_INFORMATION current;

    if (SystemInformationClass != BLACKBIRD_SYSTEM_INFORMATION_CLASS_PROCESS || !NT_SUCCESS(Status) ||
        SystemInformation == NULL || SystemInformationLength < sizeof(BLACKBIRD_SYSTEM_PROCESS_INFORMATION))
    {
        return;
    }

    __try
    {
        base = (PUCHAR)SystemInformation;
        previous = NULL;
        current = (PBLACKBIRD_SYSTEM_PROCESS_INFORMATION)base;

        for (;;)
        {
            ULONG currentOffset = (ULONG)((PUCHAR)current - base);
            BOOLEAN shouldHide = FALSE;
            ULONG nameIndex;

            if (currentOffset + sizeof(*current) > SystemInformationLength)
            {
                break;
            }

            if (BLACKBIRDRuntimeConfigIsSelfHideEnabled())
            {
                for (nameIndex = 0; nameIndex < RTL_NUMBER_OF(selfHiddenNames); ++nameIndex)
                {
                    if (BLACKBIRDNtApiUnicodeEqualsInsensitive(&current->ImageName, &selfHiddenNames[nameIndex]))
                    {
                        shouldHide = TRUE;
                        break;
                    }
                }
            }


            if (!shouldHide && BLACKBIRDRuntimeConfigIsAntiVirtualizationEnabled())
            {
                for (nameIndex = 0; nameIndex < RTL_NUMBER_OF(antiVirtualizationNames); ++nameIndex)
                {
                    if (BLACKBIRDNtApiUnicodeEqualsInsensitive(&current->ImageName, &antiVirtualizationNames[nameIndex]))
                    {
                        shouldHide = TRUE;
                        break;
                    }
                }
            }

            if (shouldHide)
            {
                if (current->NextEntryOffset == 0)
                {
                    if (previous != NULL)
                    {
                        previous->NextEntryOffset = 0;
                    }
                    else
                    {
                        RtlZeroMemory(current, SystemInformationLength - currentOffset);
                    }
                    break;
                }

                if (currentOffset + current->NextEntryOffset > SystemInformationLength)
                {
                    break;
                }

                if (previous == NULL)
                {
                    SIZE_T bytesToMove = SystemInformationLength - (currentOffset + current->NextEntryOffset);
                    RtlMoveMemory(current, base + currentOffset + current->NextEntryOffset, bytesToMove);
                    RtlZeroMemory(base + SystemInformationLength - current->NextEntryOffset, current->NextEntryOffset);
                    continue;
                }

                previous->NextEntryOffset += current->NextEntryOffset;
                current = (PBLACKBIRD_SYSTEM_PROCESS_INFORMATION)((PUCHAR)previous + previous->NextEntryOffset);
                continue;
            }

            if (current->NextEntryOffset == 0)
            {
                break;
            }
            if (currentOffset + current->NextEntryOffset > SystemInformationLength)
            {
                break;
            }

            previous = current;
            current = (PBLACKBIRD_SYSTEM_PROCESS_INFORMATION)(base + currentOffset + current->NextEntryOffset);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
    }
}

VOID BLACKBIRDNtApiSanitizeModuleInformation(_In_ ULONG SystemInformationClass,
                                            _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
                                            _In_ ULONG SystemInformationLength, _In_ NTSTATUS Status)
{
    PBLACKBIRD_SYSTEM_MODULE_INFORMATION modules;
    ULONG index;

    if (SystemInformationClass != BLACKBIRD_SYSTEM_INFORMATION_CLASS_MODULE || !NT_SUCCESS(Status) ||
        SystemInformation == NULL || SystemInformationLength < sizeof(BLACKBIRD_SYSTEM_MODULE_INFORMATION))
    {
        return;
    }

    if (!BLACKBIRDRuntimeConfigIsSelfHideEnabled())
    {
        return;
    }

    __try
    {
        modules = (PBLACKBIRD_SYSTEM_MODULE_INFORMATION)SystemInformation;
        if (modules->NumberOfModules == 0)
        {
            return;
        }
        if (FIELD_OFFSET(BLACKBIRD_SYSTEM_MODULE_INFORMATION, Modules) +
                (modules->NumberOfModules * sizeof(BLACKBIRD_SYSTEM_MODULE_ENTRY)) >
            SystemInformationLength)
        {
            return;
        }

        index = 0;
        while (index < modules->NumberOfModules)
        {
            PBLACKBIRD_SYSTEM_MODULE_ENTRY entry = &modules->Modules[index];
            const UCHAR *fileName = entry->FullPathName;

            if (entry->OffsetToFileName < RTL_NUMBER_OF(entry->FullPathName))
            {
                fileName = entry->FullPathName + entry->OffsetToFileName;
            }

            if (BLACKBIRDNtApiAnsiEqualsInsensitive(fileName, "blackbird.sys"))
            {
                ULONG remaining = modules->NumberOfModules - index - 1;
                if (remaining != 0)
                {
                    RtlMoveMemory(entry, entry + 1, remaining * sizeof(*entry));
                }
                modules->NumberOfModules--;
                continue;
            }

            index++;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
    }
}

ULONG BLACKBIRDNtApiReadUlongSafe(_In_opt_ PULONG Value)
{
    ULONG observed = 0;

    if (Value == NULL)
    {
        return 0;
    }
    __try
    {
        observed = *Value;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        observed = 0;
    }
    return observed;
}

SIZE_T BLACKBIRDNtApiReadSizeTSafe(_In_opt_ PSIZE_T Value)
{
    SIZE_T observed = 0;

    if (Value == NULL)
    {
        return 0;
    }
    __try
    {
        observed = *Value;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        observed = 0;
    }
    return observed;
}

PVOID BLACKBIRDNtApiReadPointerSafe(_In_opt_ PVOID *Value)
{
    PVOID observed = NULL;

    if (Value == NULL)
    {
        return NULL;
    }
    __try
    {
        observed = *Value;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        observed = NULL;
    }
    return observed;
}

HANDLE BLACKBIRDNtApiReadHandleSafe(_In_opt_ PHANDLE Value)
{
    HANDLE observed = NULL;

    if (Value == NULL)
    {
        return NULL;
    }
    __try
    {
        observed = *Value;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        observed = NULL;
    }
    return observed;
}

ULONGLONG BLACKBIRDNtApiReadLargeIntegerSafe(_In_opt_ PLARGE_INTEGER Value)
{
    ULONGLONG observed = 0;

    if (Value == NULL)
    {
        return 0;
    }
    __try
    {
        observed = (ULONGLONG)Value->QuadPart;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        observed = 0;
    }
    return observed;
}

BOOLEAN BLACKBIRDNtApiShouldLog(_Out_ HANDLE *CallerPid)
{
    HANDLE pid;
    KIRQL irql;

    if (InterlockedCompareExchange(&g_NtApiMonitorInitialized, 0, 0) == 0 ||
        InterlockedCompareExchange(&g_NtApiMonitorUnloading, 0, 0) != 0)
    {
        if (InterlockedDecrement(&g_NtApiSkipInitBudget) >= 0)
        {
            BLACKBIRD_NTAPI_LOG(DPFLTR_INFO_LEVEL,
                                "BLACKBIRD: ntapi should-log skip reason=init-state initialized=%ld unloading=%ld.\n",
                                InterlockedCompareExchange(&g_NtApiMonitorInitialized, 0, 0),
                                InterlockedCompareExchange(&g_NtApiMonitorUnloading, 0, 0));
        }
        return FALSE;
    }
    irql = KeGetCurrentIrql();
    if (irql != PASSIVE_LEVEL)
    {
        if (InterlockedDecrement(&g_NtApiSkipIrqlBudget) >= 0)
        {
            BLACKBIRD_NTAPI_LOG(DPFLTR_INFO_LEVEL, "BLACKBIRD: ntapi should-log skip reason=irql value=%lu.\n", irql);
        }
        return FALSE;
    }
    if (!BLACKBIRDControlIsArmedFast())
    {
        if (InterlockedDecrement(&g_NtApiSkipArmedBudget) >= 0)
        {
            BLACKBIRD_NTAPI_LOG(DPFLTR_INFO_LEVEL, "BLACKBIRD: ntapi should-log skip reason=disarmed.\n");
        }
        return FALSE;
    }

    pid = PsGetCurrentProcessId();
    if (!BLACKBIRDControlHasPidInterest((UINT32)(ULONG_PTR)pid, 0, BLACKBIRD_STREAM_MEMORY))
    {
        if (InterlockedDecrement(&g_NtApiSkipPidBudget) >= 0)
        {
            BLACKBIRD_NTAPI_LOG(DPFLTR_INFO_LEVEL,
                                "BLACKBIRD: ntapi should-log skip reason=pid-not-monitored pid=%u.\n",
                                (UINT32)(ULONG_PTR)pid);
        }
        return FALSE;
    }
    if (!ExAcquireRundownProtection(&g_NtApiRundown))
    {
        if (InterlockedDecrement(&g_NtApiSkipRundownBudget) >= 0)
        {
            BLACKBIRD_NTAPI_LOG(DPFLTR_INFO_LEVEL, "BLACKBIRD: ntapi should-log skip reason=rundown pid=%u.\n",
                                (UINT32)(ULONG_PTR)pid);
        }
        return FALSE;
    }

    *CallerPid = pid;
    return TRUE;
}

VOID BLACKBIRDNtApiLog(_In_z_ PCSTR ApiName, _In_ HANDLE CallerPid, _In_ UINT64 Arg0, _In_ UINT64 Arg1,
                       _In_ UINT64 Arg2, _In_ UINT64 Arg3, _In_ UINT64 Arg4, _In_ UINT64 Arg5, _In_ UINT64 Arg6,
                       _In_ UINT64 Arg7, _In_ NTSTATUS Status)
{
    BLACKBIRDEtwLogNtApiEvent(ApiName, CallerPid, PsGetCurrentThreadId(), Arg0, Arg1, Arg2, Arg3, Arg4, Arg5, Arg6,
                              Arg7, Status);
}

NTSTATUS
BLACKBIRDNtApiMonitorInitialize(VOID)
{
    NTSTATUS status;
    UINT32 i;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (InterlockedCompareExchange(&g_NtApiMonitorInitialized, 1, 0) != 0)
    {
        return STATUS_SUCCESS;
    }

    InterlockedExchange(&g_NtApiMonitorUnloading, 0);
    ExInitializeRundownProtection(&g_NtApiRundown);
    InterlockedExchange(&g_NtApiHookInFlight, 0);
    InterlockedExchange(&g_NtApiUninitWaitBudget, 16);
    InterlockedExchange(&g_NtApiKdSanitizeBudget, 16);
    InterlockedExchange(&g_NtApiKdSanitizeApplyBudget, 16);
    InterlockedExchange(&g_NtApiSmbiosSanitizeBudget, 16);
    InterlockedExchange(&g_NtApiSmbiosSanitizeApplyBudget, 16);
    for (i = 0; i < BLACKBIRD_HOOK_COUNT; ++i)
    {
        BLACKBIRDNtApiHookInitialize(&g_Hooks[i], &g_HookDescriptors[i]);
    }

    BLACKBIRDNtApiApplySharedKdSpoof();

    for (i = 0; i < BLACKBIRD_HOOK_COUNT; ++i)
    {
        PVOID *originalSlot = BLACKBIRDNtApiOriginalSlot((BLACKBIRD_HOOK_ID)i);

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "BLACKBIRD: ntapi hook install begin api=%s.\n",
                   g_HookDescriptors[i].ApiName);

        status = BLACKBIRDNtApiHookInstall(&g_Hooks[i], originalSlot);
        if (!NT_SUCCESS(status))
        {
            if (!g_HookDescriptors[i].Required || status == STATUS_PROCEDURE_NOT_FOUND)
            {
                DbgPrintEx(
                    DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                    "BLACKBIRD: ntapi hook unavailable api=%s required=%u status=0x%08X (continuing without this hook).\n",
                    g_HookDescriptors[i].ApiName, g_HookDescriptors[i].Required ? 1u : 0u, status);
                if (originalSlot != NULL)
                {
                    *originalSlot = NULL;
                }
                continue;
            }
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                       "BLACKBIRD: ntapi hook install failed api=%s status=0x%08X.\n", g_HookDescriptors[i].ApiName,
                       status);
            goto Fail;
        }
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "BLACKBIRD: ntapi monitor initialized.\n");
    return STATUS_SUCCESS;

Fail:
    while (i > 0)
    {
        --i;
        BLACKBIRDNtApiHookRemove(&g_Hooks[i]);
    }

    g_OriginalNtQuerySystemInformation = NULL;
    g_OriginalNtQueryInformationProcess = NULL;
    g_OriginalNtWriteVirtualMemory = NULL;
    g_OriginalNtProtectVirtualMemory = NULL;
    g_OriginalNtCreateSection = NULL;
    g_OriginalNtMapViewOfSection = NULL;
    g_OriginalNtAllocateVirtualMemory = NULL;
    g_OriginalNtQuerySystemInformationEx = NULL;
    BLACKBIRDNtApiRestoreSharedKdSpoof();
    InterlockedExchange(&g_NtApiMonitorInitialized, 0);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
               "BLACKBIRD: ntapi monitor init failed during install status=0x%08X.\n", status);
    return status;
}

VOID BLACKBIRDNtApiMonitorUninitialize(VOID)
{
    UINT32 i;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        return;
    }
    if (InterlockedExchange(&g_NtApiMonitorInitialized, 0) == 0)
    {
        return;
    }

    InterlockedExchange(&g_NtApiMonitorUnloading, 1);
    for (i = 0; i < BLACKBIRD_HOOK_COUNT; ++i)
    {
        BLACKBIRDNtApiHookDeactivate(&g_Hooks[i]);
    }
    ExWaitForRundownProtectionRelease(&g_NtApiRundown);
    BLACKBIRDNtApiWaitForInFlightCalls();
    for (i = 0; i < BLACKBIRD_HOOK_COUNT; ++i)
    {
        BLACKBIRDNtApiHookFreeTrampoline(&g_Hooks[i]);
    }

    BLACKBIRDNtApiRestoreSharedKdSpoof();

    g_OriginalNtQuerySystemInformation = NULL;
    g_OriginalNtQueryInformationProcess = NULL;
    g_OriginalNtWriteVirtualMemory = NULL;
    g_OriginalNtProtectVirtualMemory = NULL;
    g_OriginalNtCreateSection = NULL;
    g_OriginalNtMapViewOfSection = NULL;
    g_OriginalNtAllocateVirtualMemory = NULL;
    g_OriginalNtQuerySystemInformationEx = NULL;
    InterlockedExchange(&g_NtApiMonitorUnloading, 0);
}

BOOLEAN
BLACKBIRDNtApiMonitorSelfCheck(VOID)
{
    UINT32 i;
    PVOID *originalSlot;

    if (InterlockedCompareExchange(&g_NtApiMonitorInitialized, 0, 0) == 0)
    {
        return FALSE;
    }

    for (i = 0; i < BLACKBIRD_HOOK_COUNT; ++i)
    {
        if (!g_HookDescriptors[i].Required)
        {
            continue;
        }
        if (!g_Hooks[i].Installed)
        {
            return FALSE;
        }

        originalSlot = BLACKBIRDNtApiOriginalSlot((BLACKBIRD_HOOK_ID)i);
        if (originalSlot == NULL || *originalSlot == NULL)
        {
            return FALSE;
        }
    }

    return TRUE;
}

#else

NTSTATUS
BLACKBIRDNtApiMonitorInitialize(VOID)
{
    return STATUS_SUCCESS;
}

VOID BLACKBIRDNtApiMonitorUninitialize(VOID)
{
}

BOOLEAN
BLACKBIRDNtApiMonitorSelfCheck(VOID)
{
    return TRUE;
}

#endif







