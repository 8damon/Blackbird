#include <ntddk.h>
#include "..\core\control.h"
#include "..\telemetry\etw.h"
#include "correlation.h"
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

#ifndef PROCESS_VM_OPERATION
#define PROCESS_VM_OPERATION 0x0008
#endif

#ifndef MEM_IMAGE
#define MEM_IMAGE 0x01000000
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

typedef NTSTATUS(NTAPI* PSTINGER_PS_SET_CREATE_THREAD_NOTIFY_ROUTINE_EX)(
    _In_ PSCREATETHREADNOTIFYTYPE NotifyType,
    _In_ PVOID NotifyRoutine
);

#define STINGER_THREAD_MAX_OUTSTANDING_WORK 4096
#define STINGER_THREAD_CORRELATION_WINDOW_MS 10000

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
static volatile LONG g_ThreadDropLogCounter = 0;
static volatile LONG g_ThreadLookupFailureCounter = 0;
static volatile LONG g_ThreadAllocFailureCounter = 0;
static volatile LONG g_ThreadInitFailureCounter = 0;

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
    LONG dropCounter;

    for (;;) {
        current = InterlockedCompareExchange(&g_OutstandingWork, 0, 0);
        if (current >= STINGER_THREAD_MAX_OUTSTANDING_WORK) {
            InterlockedIncrement(&g_DroppedWork);
            dropCounter = InterlockedIncrement(&g_ThreadDropLogCounter);
            if (dropCounter == 1 || ((dropCounter & 0xFF) == 0)) {
                DbgPrintEx(
                    DPFLTR_IHVDRIVER_ID,
                    DPFLTR_WARNING_LEVEL,
                    "STINGER: thread callback drop (work queue full max=%lu) totalDrops=%lu outstanding=%ld.\n",
                    STINGER_THREAD_MAX_OUTSTANDING_WORK,
                    (ULONG)dropCounter,
                    current
                );
            }
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
PSTINGER_PS_SET_CREATE_THREAD_NOTIFY_ROUTINE_EX
STINGERResolvePsSetCreateThreadNotifyRoutineEx(
    VOID
)
{
    UNICODE_STRING routineName;

    RtlInitUnicodeString(&routineName, L"PsSetCreateThreadNotifyRoutineEx");
    return (PSTINGER_PS_SET_CREATE_THREAD_NOTIFY_ROUTINE_EX)MmGetSystemRoutineAddress(&routineName);
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
    _In_ BOOLEAN OutsideMainImage,
    _In_ UINT32 CorrelationFlags,
    _In_ UINT32 CorrelationAccessMask,
    _In_ UINT32 CorrelationAgeMs,
    _In_ ULONG StartRegionProtect,
    _In_ ULONG StartRegionState,
    _In_ ULONG StartRegionType,
    _In_ NTSTATUS StartRegionStatus
)
{
    PVOID frames[8] = { 0 };
    ULONG frameCount = 0;
    BOOLEAN startRegionExecutable;
    BOOLEAN captureFrames;

    captureFrames = IsRemoteCreator || OutsideMainImage || (CorrelationFlags != 0);
    if (captureFrames) {
        frameCount = RtlWalkFrameChain(frames, RTL_NUMBER_OF(frames), 0);
        if (frameCount > RTL_NUMBER_OF(frames)) {
            frameCount = RTL_NUMBER_OF(frames);
        }
    }

    startRegionExecutable =
        ((StartRegionProtect & PAGE_EXECUTE) != 0) ||
        ((StartRegionProtect & PAGE_EXECUTE_READ) != 0) ||
        ((StartRegionProtect & PAGE_EXECUTE_READWRITE) != 0) ||
        ((StartRegionProtect & PAGE_EXECUTE_WRITECOPY) != 0);

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
        CorrelationFlags,
        CorrelationAccessMask,
        CorrelationAgeMs,
        StartRegionProtect,
        StartRegionState,
        StartRegionType,
        StartRegionStatus,
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
        if (CorrelationFlags != 0) {
            flags |= STINGER_THREAD_FLAG_CORRELATED_INTENT;
        }
        if ((CorrelationFlags & STINGER_INTENT_PROCESS_MEMORY) != 0) {
            flags |= STINGER_THREAD_FLAG_CORR_MEMORY;
        }
        if ((CorrelationFlags & STINGER_INTENT_THREAD_CONTEXT) != 0) {
            flags |= STINGER_THREAD_FLAG_CORR_THREAD_CTX;
        }
        if ((CorrelationFlags & STINGER_INTENT_DUP_HANDLE) != 0) {
            flags |= STINGER_THREAD_FLAG_CORR_DUP_HANDLE;
        }
        if (startRegionExecutable) {
            flags |= STINGER_THREAD_FLAG_START_REGION_EXEC;
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
NTSTATUS
STINGERQueryAddressRegion(
    _In_ HANDLE ProcessId,
    _In_ PVOID Address,
    _Out_ ULONG* Protect,
    _Out_ ULONG* State,
    _Out_ ULONG* Type
)
{
    NTSTATUS status;
    OBJECT_ATTRIBUTES oa;
    CLIENT_ID cid;
    HANDLE hProcess = NULL;
    MEMORY_BASIC_INFORMATION mbi;

    if (Protect != NULL) {
        *Protect = 0;
    }
    if (State != NULL) {
        *State = 0;
    }
    if (Type != NULL) {
        *Type = 0;
    }

    if (Address == NULL) {
        return STATUS_INVALID_PARAMETER;
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
        return status;
    }

    RtlZeroMemory(&mbi, sizeof(mbi));
    status = ZwQueryVirtualMemory(
        hProcess,
        Address,
        STINGERMemoryBasicInformation,
        &mbi,
        sizeof(mbi),
        NULL
    );
    ZwClose(hProcess);

    if (!NT_SUCCESS(status)) {
        return status;
    }

    if (Protect != NULL) {
        *Protect = mbi.Protect;
    }
    if (State != NULL) {
        *State = mbi.State;
    }
    if (Type != NULL) {
        *Type = mbi.Type;
    }
    return STATUS_SUCCESS;
}

static
VOID
STINGERThreadWorkRoutine(_In_ PVOID Context)
{
    PSTINGER_THREAD_WORK w = (PSTINGER_THREAD_WORK)Context;
    PVOID threadStart = NULL;
    PVOID imageBase = NULL;
    SIZE_T imageSize = 0;
    BOOLEAN gotStart;
    BOOLEAN gotRange;
    BOOLEAN outsideMainImage = FALSE;
    BOOLEAN isRemoteCreator;
    UINT32 correlationFlags = 0;
    UINT32 correlationAccessMask = 0;
    UINT32 correlationAgeMs = 0;
    ULONG startRegionProtect = 0;
    ULONG startRegionState = 0;
    ULONG startRegionType = 0;
    NTSTATUS startRegionStatus = STATUS_NOT_FOUND;
    BOOLEAN startRegionExecutable = FALSE;
    BOOLEAN startRegionNonImage = FALSE;
    BOOLEAN correlatedIntentFound;
    HANDLE creatorPidForTelemetry;
    HANDLE correlatedCallerPid = NULL;

    PAGED_CODE(); // worker should run at PASSIVE_LEVEL

    // Safety: if we somehow aren't PASSIVE, bail.
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        goto Exit;
    }

    // Best-effort: process may be terminating; still safe to fail gracefully.
    gotStart = STINGERQueryThreadStartAddress(w->ProcessId, w->ThreadId, &threadStart);
    gotRange = STINGERGetProcessImageRange(w->ProcessId, w->Process, &imageBase, &imageSize);
    if (gotStart && gotRange && threadStart && imageBase && imageSize) {
        ULONG_PTR start = (ULONG_PTR)threadStart;
        ULONG_PTR base = (ULONG_PTR)imageBase;

        // Overflow-safe bounds check
        ULONG_PTR end = base + (ULONG_PTR)imageSize;
        if (end < base) {
            outsideMainImage = TRUE;
        } else {
            outsideMainImage = (start < base) || (start >= end);
        }
    }

    if (gotStart && threadStart != NULL) {
        startRegionStatus = STINGERQueryAddressRegion(
            w->ProcessId,
            threadStart,
            &startRegionProtect,
            &startRegionState,
            &startRegionType
        );
    }
    if (NT_SUCCESS(startRegionStatus)) {
        startRegionExecutable =
            ((startRegionProtect & PAGE_EXECUTE) != 0) ||
            ((startRegionProtect & PAGE_EXECUTE_READ) != 0) ||
            ((startRegionProtect & PAGE_EXECUTE_READWRITE) != 0) ||
            ((startRegionProtect & PAGE_EXECUTE_WRITECOPY) != 0);
        startRegionNonImage = (startRegionType != MEM_IMAGE);
    }

    creatorPidForTelemetry = w->CreatorProcessId;
    isRemoteCreator = (creatorPidForTelemetry != w->ProcessId);
    correlatedIntentFound = STINGERCorrelationQueryRecentIntent(
        creatorPidForTelemetry,
        w->ProcessId,
        STINGER_THREAD_CORRELATION_WINDOW_MS,
        &correlationFlags,
        &correlationAccessMask,
        &correlationAgeMs
    );
    if (!correlatedIntentFound) {
        correlatedIntentFound = STINGERCorrelationQueryRecentIntentForTarget(
            w->ProcessId,
            STINGER_THREAD_CORRELATION_WINDOW_MS,
            TRUE,
            &correlatedCallerPid,
            &correlationFlags,
            &correlationAccessMask,
            &correlationAgeMs
        );
        if (correlatedIntentFound && correlatedCallerPid != NULL) {
            creatorPidForTelemetry = correlatedCallerPid;
            isRemoteCreator = (creatorPidForTelemetry != w->ProcessId);
        }
    }
    if (!correlatedIntentFound) {
        correlationFlags = 0;
        correlationAccessMask = 0;
        correlationAgeMs = 0;
    }

    if (isRemoteCreator && outsideMainImage && correlatedIntentFound) {
        STINGEREtwLogDetectionEvent(
            "REMOTE_THREAD_WITH_RECENT_HANDLE_INTENT",
            4,
            creatorPidForTelemetry,
            w->ProcessId,
            correlationFlags,
            correlationAccessMask,
            correlationAgeMs,
            L"remote thread start outside image with recent handle intent"
        );
    } else if (isRemoteCreator && startRegionExecutable && startRegionNonImage && correlatedIntentFound) {
        STINGEREtwLogDetectionEvent(
            "REMOTE_THREAD_START_IN_NON_IMAGE_EXECUTABLE_REGION",
            4,
            creatorPidForTelemetry,
            w->ProcessId,
            correlationFlags,
            correlationAccessMask,
            correlationAgeMs,
            L"remote thread start address is executable but not backed by MEM_IMAGE with recent handle intent"
        );
    } else if (isRemoteCreator && outsideMainImage) {
        STINGEREtwLogDetectionEvent(
            "REMOTE_THREAD_OUTSIDE_MAIN_IMAGE",
            3,
            creatorPidForTelemetry,
            w->ProcessId,
            0,
            0,
            0,
            L"remote thread start outside target main image"
        );
    } else if (correlatedIntentFound && ((correlationFlags & STINGER_INTENT_THREAD_CONTEXT) != 0)) {
        STINGEREtwLogDetectionEvent(
            "THREAD_ACTIVITY_WITH_THREAD_CONTEXT_INTENT",
            2,
            creatorPidForTelemetry,
            w->ProcessId,
            correlationFlags,
            correlationAccessMask,
            correlationAgeMs,
            L"thread context-related handle intent observed before thread event"
        );
    }

    if (correlatedIntentFound &&
        ((correlationFlags & (STINGER_INTENT_PROCESS_MEMORY | STINGER_INTENT_THREAD_CONTEXT)) ==
            (STINGER_INTENT_PROCESS_MEMORY | STINGER_INTENT_THREAD_CONTEXT)) &&
        startRegionExecutable &&
        startRegionNonImage) {
        STINGEREtwLogDetectionEvent(
            "POSSIBLE_MANUAL_MAP_OR_HOLLOWING_EXECUTION",
            4,
            creatorPidForTelemetry,
            w->ProcessId,
            correlationFlags,
            correlationAccessMask,
            correlationAgeMs,
            L"thread execution observed from non-image executable region with process-memory and thread-context intent"
        );
    }

    STINGERLogThreadTelemetry(
        w->ProcessId,
        w->ThreadId,
        creatorPidForTelemetry,
        threadStart,
        imageBase,
        imageSize,
        gotStart,
        gotRange,
        isRemoteCreator,
        outsideMainImage,
        correlationFlags,
        correlationAccessMask,
        correlationAgeMs,
        startRegionProtect,
        startRegionState,
        startRegionType,
        startRegionStatus
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
    LONG failureCounter;

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
        failureCounter = InterlockedIncrement(&g_ThreadLookupFailureCounter);
        if (failureCounter == 1 || ((failureCounter & 0xFF) == 0)) {
            DbgPrintEx(
                DPFLTR_IHVDRIVER_ID,
                DPFLTR_WARNING_LEVEL,
                "STINGER: thread callback lookup failure pid=%p tid=%p status=0x%08X total=%lu.\n",
                ProcessId,
                ThreadId,
                status,
                (ULONG)failureCounter
            );
        }
        STINGERThreadReleaseWorkSlot();
        return;
    }

    PSTINGER_THREAD_WORK w = (PSTINGER_THREAD_WORK)ExAllocatePool2(
        POOL_FLAG_NON_PAGED | POOL_FLAG_UNINITIALIZED,
        sizeof(*w),
        'traT'
    );
    if (!w) {
        failureCounter = InterlockedIncrement(&g_ThreadAllocFailureCounter);
        if (failureCounter == 1 || ((failureCounter & 0xFF) == 0)) {
            DbgPrintEx(
                DPFLTR_IHVDRIVER_ID,
                DPFLTR_ERROR_LEVEL,
                "STINGER: thread callback alloc failure pid=%p tid=%p total=%lu.\n",
                ProcessId,
                ThreadId,
                (ULONG)failureCounter
            );
        }
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

    NTSTATUS status = STATUS_PROCEDURE_NOT_FOUND;
    PSTINGER_PS_SET_CREATE_THREAD_NOTIFY_ROUTINE_EX setNotifyRoutineEx;

    //
    // Try Ex first (preferred)
    //
    setNotifyRoutineEx = STINGERResolvePsSetCreateThreadNotifyRoutineEx();
    if (setNotifyRoutineEx != NULL) {
        status = setNotifyRoutineEx(
            PsCreateThreadNotifyNonSystem,
            (PVOID)STINGERThreadNotifyRoutine
        );
    }

    if (NT_SUCCESS(status)) {
        g_ThreadNotifyRegistered = TRUE;
        g_NotifyMode = STINGERNotifyEx;
        return STATUS_SUCCESS;
    }

    //
    // Ex can be unavailable or rejected; fall back.
    //
    if (setNotifyRoutineEx == NULL || status == STATUS_ACCESS_DENIED) {

        status = PsSetCreateThreadNotifyRoutine(
            STINGERThreadNotifyRoutine
        );

        if (NT_SUCCESS(status)) {
            g_ThreadNotifyRegistered = TRUE;
            g_NotifyMode = STINGERNotifyLegacy;
            return STATUS_SUCCESS;
        }
    }

    {
        LONG failureCounter = InterlockedIncrement(&g_ThreadInitFailureCounter);
        if (failureCounter == 1 || ((failureCounter & 0xFF) == 0)) {
            DbgPrintEx(
                DPFLTR_IHVDRIVER_ID,
                DPFLTR_ERROR_LEVEL,
                "STINGER: thread monitor callback registration failure status=0x%08X mode=%lu total=%lu.\n",
                status,
                g_NotifyMode,
                (ULONG)failureCounter
            );
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

BOOLEAN
STINGERThreadMonitorSelfCheck(
    VOID
)
{
    LONG outstanding;

    if (!g_ThreadNotifyRegistered) {
        return FALSE;
    }
    if (g_NotifyMode == STINGERNotifyNone) {
        return FALSE;
    }

    outstanding = InterlockedCompareExchange(&g_OutstandingWork, 0, 0);
    if (outstanding < 0 || outstanding > STINGER_THREAD_MAX_OUTSTANDING_WORK) {
        return FALSE;
    }

    return TRUE;
}
