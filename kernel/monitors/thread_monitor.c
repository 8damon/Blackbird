#include <ntddk.h>
#include "..\core\control.h"
#include "..\telemetry\etw.h"
#include "thread_monitor.h"

#ifndef ThreadQuerySetWin32StartAddress
#define ThreadQuerySetWin32StartAddress ((THREADINFOCLASS)9)
#endif

#ifndef THREAD_QUERY_INFORMATION
#define THREAD_QUERY_INFORMATION (0x0040)
#endif

#ifndef THREAD_QUERY_LIMITED_INFORMATION
#define THREAD_QUERY_LIMITED_INFORMATION (0x0800)
#endif

#ifndef PROCESS_VM_READ
#define PROCESS_VM_READ 0x0010
#endif

#ifndef PROCESS_QUERY_LIMITED_INFORMATION
#define PROCESS_QUERY_LIMITED_INFORMATION 0x1000
#endif

typedef struct _MEMORY_BASIC_INFORMATION {
    PVOID  BaseAddress;
    PVOID  AllocationBase;
    ULONG  AllocationProtect;
    SIZE_T RegionSize;
    ULONG  State;
    ULONG  Protect;
    ULONG  Type;
} MEMORY_BASIC_INFORMATION, * PMEMORY_BASIC_INFORMATION;

typedef enum _STINGER_MEMORY_INFORMATION_CLASS {
    STINGERMemoryBasicInformation = 0
} STINGER_MEMORY_INFORMATION_CLASS;

typedef enum _STINGER_NOTIFY_MODE {
    STINGERNotifyNone = 0,
    STINGERNotifyLegacy,
    STINGERNotifyEx
} STINGER_NOTIFY_MODE;

#define STINGER_THREAD_MAX_OUTSTANDING_WORK 4096

static STINGER_NOTIFY_MODE g_NotifyMode = STINGERNotifyNone;

NTSYSAPI NTSTATUS NTAPI ZwQueryInformationThread(
    _In_ HANDLE ThreadHandle,
    _In_ THREADINFOCLASS ThreadInformationClass,
    _Out_writes_bytes_(ThreadInformationLength) PVOID ThreadInformation,
    _In_ ULONG ThreadInformationLength,
    _Out_opt_ PULONG ReturnLength
);

NTSYSAPI NTSTATUS NTAPI ZwOpenThread(
    _Out_ PHANDLE ThreadHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ PCLIENT_ID ClientId
);

NTSYSAPI NTSTATUS NTAPI ZwQueryVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress,
    _In_ STINGER_MEMORY_INFORMATION_CLASS MemoryInformationClass,
    _Out_writes_bytes_(MemoryInformationLength) PVOID MemoryInformation,
    _In_ SIZE_T MemoryInformationLength,
    _Out_opt_ PSIZE_T ReturnLength
);

NTKERNELAPI PVOID PsGetProcessSectionBaseAddress(_In_ PEPROCESS Process);
NTKERNELAPI NTSTATUS PsLookupProcessByProcessId(_In_ HANDLE ProcessId, _Outptr_ PEPROCESS* Process);

static volatile LONG g_OutstandingWork = 0;
static volatile LONG g_DroppedWork = 0;
static KEVENT g_AllWorkDone;
static BOOLEAN g_ThreadNotifyRegistered = FALSE;
static volatile LONG g_ThreadMonitorStopping = 0;

typedef struct _STINGER_THREAD_WORK {
    WORK_QUEUE_ITEM WorkItem;
    HANDLE ProcessId;
    HANDLE ThreadId;
    HANDLE CreatorProcessId;     // heuristic only
    PEPROCESS Process;           // referenced
} STINGER_THREAD_WORK, * PSTINGER_THREAD_WORK;

static
BOOLEAN
STINGERThreadTryAcquireWorkSlot(
    VOID
)
{
    LONG current;

    for (;;) {
        current = InterlockedCompareExchange(&g_OutstandingWork, 0, 0);
        if (current >= STINGER_THREAD_MAX_OUTSTANDING_WORK) {
            InterlockedIncrement(&g_DroppedWork);
            return FALSE;
        }

        if (InterlockedCompareExchange(&g_OutstandingWork, current + 1, current) == current) {
            if (current == 0) {
                KeClearEvent(&g_AllWorkDone);
            }
            return TRUE;
        }
    }
}

static
VOID
STINGERThreadReleaseWorkSlot(
    VOID
)
{
    if (InterlockedDecrement(&g_OutstandingWork) == 0) {
        KeSetEvent(&g_AllWorkDone, IO_NO_INCREMENT, FALSE);
    }
}

static
VOID
STINGERLogThreadTelemetry(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _In_ HANDLE CreatorPid,
    _In_ PVOID StartAddress,
    _In_ PVOID ImageBase,
    _In_ SIZE_T ImageSize,
    _In_ BOOLEAN GotStart,
    _In_ BOOLEAN GotRange,
    _In_ BOOLEAN IsRemoteCreator,
    _In_ BOOLEAN OutsideMainImage
)
{
    PVOID frames[8] = { 0 };
    ULONG frameCount;

    frameCount = RtlWalkFrameChain(frames, RTL_NUMBER_OF(frames), 0);
    if (frameCount > RTL_NUMBER_OF(frames)) {
        frameCount = RTL_NUMBER_OF(frames);
    }

    STINGEREtwLogThreadEvent(
        ProcessId,
        ThreadId,
        CreatorPid,
        StartAddress,
        ImageBase,
        ImageSize,
        GotStart,
        GotRange,
        IsRemoteCreator,
        OutsideMainImage,
        frameCount,
        frames
    );

    {
        UINT32 flags = 0;
        if (GotStart) {
            flags |= STINGER_THREAD_FLAG_GOT_START;
        }
        if (GotRange) {
            flags |= STINGER_THREAD_FLAG_GOT_RANGE;
        }
        if (IsRemoteCreator) {
            flags |= STINGER_THREAD_FLAG_REMOTE_CREATOR;
        }
        if (OutsideMainImage) {
            flags |= STINGER_THREAD_FLAG_OUTSIDE_MAIN_IMG;
        }

        STINGERControlPublishThreadEvent(
            (UINT64)(ULONG_PTR)ProcessId,
            (UINT64)(ULONG_PTR)ThreadId,
            (UINT64)(ULONG_PTR)CreatorPid,
            (UINT64)(ULONG_PTR)StartAddress,
            (UINT64)(ULONG_PTR)ImageBase,
            (UINT64)ImageSize,
            flags,
            frameCount,
            frames
        );
    }
}

static
BOOLEAN
STINGERQueryThreadStartAddress(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _Out_ PVOID* StartAddress
)
{
    NTSTATUS status;
    OBJECT_ATTRIBUTES oa;
    CLIENT_ID cid;
    HANDLE hThread = NULL;

    *StartAddress = NULL;

    InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    cid.UniqueProcess = ProcessId;
    cid.UniqueThread = ThreadId;

    status = ZwOpenThread(&hThread, THREAD_QUERY_LIMITED_INFORMATION, &oa, &cid);
    if (!NT_SUCCESS(status)) {
        status = ZwOpenThread(&hThread, THREAD_QUERY_INFORMATION, &oa, &cid);
        if (!NT_SUCCESS(status)) {
            return FALSE;
        }
    }

    status = ZwQueryInformationThread(
        hThread,
        ThreadQuerySetWin32StartAddress,
        StartAddress,
        sizeof(*StartAddress),
        NULL
    );

    ZwClose(hThread);
    return NT_SUCCESS(status);
}

static
BOOLEAN
STINGERGetProcessImageRange(
    _In_ HANDLE ProcessId,
    _In_ PEPROCESS Process,
    _Out_ PVOID* ImageBase,
    _Out_ SIZE_T* ImageSize
)
{
    NTSTATUS status;
    OBJECT_ATTRIBUTES oa;
    CLIENT_ID cid;
    HANDLE hProcess = NULL;
    PVOID base = PsGetProcessSectionBaseAddress(Process);
    MEMORY_BASIC_INFORMATION mbi;

    *ImageBase = NULL;
    *ImageSize = 0;

    if (base == NULL) {
        return FALSE;
    }

    InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    cid.UniqueProcess = ProcessId;
    cid.UniqueThread = NULL;

    status = ZwOpenProcess(
        &hProcess,
        PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
        &oa,
        &cid
    );
    if (!NT_SUCCESS(status)) {
        return FALSE;
    }

    RtlZeroMemory(&mbi, sizeof(mbi));
    status = ZwQueryVirtualMemory(
        hProcess,
        base,
        STINGERMemoryBasicInformation,
        &mbi,
        sizeof(mbi),
        NULL
    );

    ZwClose(hProcess);

    if (!NT_SUCCESS(status) || mbi.RegionSize == 0) {
        return FALSE;
    }

    *ImageBase = base;
    *ImageSize = mbi.RegionSize;
    return TRUE;
}

static
VOID
STINGERThreadWorkRoutine(_In_ PVOID Context)
{
    PSTINGER_THREAD_WORK w = (PSTINGER_THREAD_WORK)Context;

    PAGED_CODE(); // worker should run at PASSIVE_LEVEL

    // Safety: if we somehow aren't PASSIVE, bail.
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        goto Exit;
    }

    // Best-effort: process may be terminating; still safe to fail gracefully.
    PVOID threadStart = NULL;
    PVOID imageBase = NULL;
    SIZE_T imageSize = 0;

    BOOLEAN gotStart = STINGERQueryThreadStartAddress(w->ProcessId, w->ThreadId, &threadStart);
    BOOLEAN gotRange = STINGERGetProcessImageRange(w->ProcessId, w->Process, &imageBase, &imageSize);

    BOOLEAN outsideMainImage = FALSE;
    if (gotStart && gotRange && threadStart && imageBase && imageSize) {
        ULONG_PTR start = (ULONG_PTR)threadStart;
        ULONG_PTR base = (ULONG_PTR)imageBase;

        // Overflow-safe bounds check
        ULONG_PTR end = base + (ULONG_PTR)imageSize;
        if (end < base) {
            outsideMainImage = TRUE;
        }
        else {
            outsideMainImage = (start < base) || (start >= end);
        }
    }

    BOOLEAN isRemoteCreator = (w->CreatorProcessId != w->ProcessId);

    STINGERLogThreadTelemetry(
        w->ProcessId,
        w->ThreadId,
        w->CreatorProcessId,
        threadStart,
        imageBase,
        imageSize,
        gotStart,
        gotRange,
        isRemoteCreator,
        outsideMainImage
    );

Exit:
    if (w->Process) {
        ObDereferenceObject(w->Process);
    }

    ExFreePoolWithTag(w, 'traT');

    STINGERThreadReleaseWorkSlot();
}

VOID
STINGERThreadNotifyRoutine(
    HANDLE ProcessId,
    HANDLE ThreadId,
    BOOLEAN Create
)
{
    if (!Create) {
        return;
    }
    if (InterlockedCompareExchange(&g_ThreadMonitorStopping, 0, 0) != 0) {
        return;
    }
    if (!STINGERThreadTryAcquireWorkSlot()) {
        return;
    }

    // Do NOT do Zw* here. Just queue work.
    PEPROCESS process = NULL;
    NTSTATUS status = PsLookupProcessByProcessId(ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        STINGERThreadReleaseWorkSlot();
        return;
    }

    PSTINGER_THREAD_WORK w = (PSTINGER_THREAD_WORK)ExAllocatePool2(
        POOL_FLAG_NON_PAGED | POOL_FLAG_UNINITIALIZED,
        sizeof(*w),
        'traT'
    );
    if (!w) {
        ObDereferenceObject(process);
        STINGERThreadReleaseWorkSlot();
        return;
    }

    RtlZeroMemory(w, sizeof(*w));
    w->ProcessId = ProcessId;
    w->ThreadId = ThreadId;
    w->CreatorProcessId = PsGetCurrentProcessId(); // heuristic only
    w->Process = process; // already referenced by lookup

    ExInitializeWorkItem(&w->WorkItem, STINGERThreadWorkRoutine, w);

    ExQueueWorkItem(&w->WorkItem, DelayedWorkQueue);
}

NTSTATUS
STINGERThreadMonitorInitialize(VOID)
{
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (g_ThreadNotifyRegistered) {
        return STATUS_SUCCESS;
    }

    InterlockedExchange(&g_ThreadMonitorStopping, 0);
    InterlockedExchange(&g_OutstandingWork, 0);
    InterlockedExchange(&g_DroppedWork, 0);
    KeInitializeEvent(&g_AllWorkDone, NotificationEvent, TRUE);

    NTSTATUS status;

    //
    // Try Ex first (preferred)
    //
    status = PsSetCreateThreadNotifyRoutineEx(
        PsCreateThreadNotifyNonSystem,
        (PVOID)STINGERThreadNotifyRoutine
    );

    if (NT_SUCCESS(status)) {
        g_ThreadNotifyRegistered = TRUE;
        g_NotifyMode = STINGERNotifyEx;
        return STATUS_SUCCESS;
    }

    //
    // If Ex failed with ACCESS_DENIED, fall back
    //
    if (status == STATUS_ACCESS_DENIED) {

        status = PsSetCreateThreadNotifyRoutine(
            STINGERThreadNotifyRoutine
        );

        if (NT_SUCCESS(status)) {
            g_ThreadNotifyRegistered = TRUE;
            g_NotifyMode = STINGERNotifyLegacy;
            return STATUS_SUCCESS;
        }
    }

    return status;
}

VOID
STINGERThreadMonitorUninitialize(VOID)
{
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return;
    }
    if (!g_ThreadNotifyRegistered) {
        return;
    }

    InterlockedExchange(&g_ThreadMonitorStopping, 1);
    PsRemoveCreateThreadNotifyRoutine(
        STINGERThreadNotifyRoutine
    );

    g_NotifyMode = STINGERNotifyNone;
    g_ThreadNotifyRegistered = FALSE;

    if (InterlockedCompareExchange(&g_OutstandingWork, 0, 0) != 0) {
        KeWaitForSingleObject(
            &g_AllWorkDone,
            Executive,
            KernelMode,
            FALSE,
            NULL
        );
    }
    InterlockedExchange(&g_ThreadMonitorStopping, 0);
    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_INFO_LEVEL,
        "STINGER: thread monitor uninitialized (dropped=%ld).\n",
        InterlockedCompareExchange(&g_DroppedWork, 0, 0)
    );
}
