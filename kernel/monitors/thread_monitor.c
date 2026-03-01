#include <ntddk.h>
#include "..\core\control.h"
#include "..\core\protection_utils.h"
#include "..\telemetry\etw.h"
#include "..\correlation\intent_store.h"
#include "..\correlation\hollowing_engine.h"
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

typedef struct _MEMORY_BASIC_INFORMATION
{
    PVOID BaseAddress;
    PVOID AllocationBase;
    ULONG AllocationProtect;
    SIZE_T RegionSize;
    ULONG State;
    ULONG Protect;
    ULONG Type;
} MEMORY_BASIC_INFORMATION, *PMEMORY_BASIC_INFORMATION;

typedef enum _SLEEPWALKER_MEMORY_INFORMATION_CLASS
{
    SLEEPWALKERMemoryBasicInformation = 0
} SLEEPWALKER_MEMORY_INFORMATION_CLASS;

typedef enum _SLEEPWALKER_NOTIFY_MODE
{
    SLEEPWALKERNotifyNone = 0,
    SLEEPWALKERNotifyEx
} SLEEPWALKER_NOTIFY_MODE;

typedef NTSTATUS(NTAPI *PSLEEPWALKER_PS_SET_CREATE_THREAD_NOTIFY_ROUTINE_EX)(_In_ PSCREATETHREADNOTIFYTYPE NotifyType,
                                                                             _In_ PVOID NotifyRoutine);

#define SLEEPWALKER_THREAD_MAX_OUTSTANDING_WORK 4096
#define SLEEPWALKER_THREAD_CORRELATION_WINDOW_MS 5000

static SLEEPWALKER_NOTIFY_MODE g_NotifyMode = SLEEPWALKERNotifyNone;

NTSYSAPI NTSTATUS NTAPI ZwQueryInformationThread(_In_ HANDLE ThreadHandle, _In_ THREADINFOCLASS ThreadInformationClass,
                                                 _Out_writes_bytes_(ThreadInformationLength) PVOID ThreadInformation,
                                                 _In_ ULONG ThreadInformationLength, _Out_opt_ PULONG ReturnLength);

NTSYSAPI NTSTATUS NTAPI ZwOpenThread(_Out_ PHANDLE ThreadHandle, _In_ ACCESS_MASK DesiredAccess,
                                     _In_ POBJECT_ATTRIBUTES ObjectAttributes, _In_ PCLIENT_ID ClientId);

NTSYSAPI NTSTATUS NTAPI ZwQueryVirtualMemory(_In_ HANDLE ProcessHandle, _In_opt_ PVOID BaseAddress,
                                             _In_ SLEEPWALKER_MEMORY_INFORMATION_CLASS MemoryInformationClass,
                                             _Out_writes_bytes_(MemoryInformationLength) PVOID MemoryInformation,
                                             _In_ SIZE_T MemoryInformationLength, _Out_opt_ PSIZE_T ReturnLength);

NTKERNELAPI PVOID PsGetProcessSectionBaseAddress(_In_ PEPROCESS Process);
NTKERNELAPI NTSTATUS PsLookupProcessByProcessId(_In_ HANDLE ProcessId, _Outptr_ PEPROCESS *Process);

static volatile LONG g_OutstandingWork = 0;
static volatile LONG g_DroppedWork = 0;
static KEVENT g_AllWorkDone;
static BOOLEAN g_ThreadNotifyRegistered = FALSE;
static volatile LONG g_ThreadMonitorStopping = 0;
static volatile LONG g_ThreadDropLogCounter = 0;
static volatile LONG g_ThreadLookupFailureCounter = 0;
static volatile LONG g_ThreadAllocFailureCounter = 0;
static volatile LONG g_ThreadInitFailureCounter = 0;
static PSLEEPWALKER_PS_SET_CREATE_THREAD_NOTIFY_ROUTINE_EX g_SetNotifyRoutineEx = NULL;

typedef struct _SLEEPWALKER_THREAD_WORK
{
    WORK_QUEUE_ITEM WorkItem;
    HANDLE ProcessId;
    HANDLE ThreadId;
    HANDLE CreatorProcessId; // heuristic only
    PEPROCESS Process;       // referenced
} SLEEPWALKER_THREAD_WORK, *PSLEEPWALKER_THREAD_WORK;

static BOOLEAN SLEEPWALKERThreadTryAcquireWorkSlot(VOID)
{
    LONG current;
    LONG dropCounter;

    for (;;)
    {
        current = InterlockedCompareExchange(&g_OutstandingWork, 0, 0);
        if (current >= SLEEPWALKER_THREAD_MAX_OUTSTANDING_WORK)
        {
            InterlockedIncrement(&g_DroppedWork);
            dropCounter = InterlockedIncrement(&g_ThreadDropLogCounter);
            if (dropCounter == 1 || ((dropCounter & 0xFF) == 0))
            {
                DbgPrintEx(
                    DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                    "SLEEPWALKER: thread callback drop (work queue full max=%lu) totalDrops=%lu outstanding=%ld.\n",
                    SLEEPWALKER_THREAD_MAX_OUTSTANDING_WORK, (ULONG)dropCounter, current);
            }
            return FALSE;
        }

        if (InterlockedCompareExchange(&g_OutstandingWork, current + 1, current) == current)
        {
            if (current == 0)
            {
                KeClearEvent(&g_AllWorkDone);
            }
            return TRUE;
        }
    }
}

static PSLEEPWALKER_PS_SET_CREATE_THREAD_NOTIFY_ROUTINE_EX SLEEPWALKERResolvePsSetCreateThreadNotifyRoutineEx(VOID)
{
    UNICODE_STRING routineName;

    RtlInitUnicodeString(&routineName, L"PsSetCreateThreadNotifyRoutineEx");
    return (PSLEEPWALKER_PS_SET_CREATE_THREAD_NOTIFY_ROUTINE_EX)MmGetSystemRoutineAddress(&routineName);
}

static VOID SLEEPWALKERThreadReleaseWorkSlot(VOID)
{
    if (InterlockedDecrement(&g_OutstandingWork) == 0)
    {
        KeSetEvent(&g_AllWorkDone, IO_NO_INCREMENT, FALSE);
    }
}

static VOID SLEEPWALKERLogThreadTelemetry(_In_ HANDLE ProcessId, _In_ HANDLE ThreadId, _In_ HANDLE CreatorPid,
                                          _In_ PVOID StartAddress, _In_ PVOID ImageBase, _In_ SIZE_T ImageSize,
                                          _In_ BOOLEAN GotStart, _In_ BOOLEAN GotRange, _In_ BOOLEAN IsRemoteCreator,
                                          _In_ BOOLEAN OutsideMainImage, _In_ UINT32 CorrelationFlags,
                                          _In_ UINT32 CorrelationAccessMask, _In_ UINT32 CorrelationAgeMs,
                                          _In_ ULONG StartRegionProtect, _In_ ULONG StartRegionState,
                                          _In_ ULONG StartRegionType, _In_ NTSTATUS StartRegionStatus)
{
    PVOID frames[8] = {0};
    ULONG frameCount = 0;
    BOOLEAN startRegionExecutable;
    BOOLEAN captureFrames;

    captureFrames = IsRemoteCreator || OutsideMainImage || (CorrelationFlags != 0);
    if (captureFrames)
    {
        frameCount = RtlWalkFrameChain(frames, RTL_NUMBER_OF(frames), 0);
        if (frameCount > RTL_NUMBER_OF(frames))
        {
            frameCount = RTL_NUMBER_OF(frames);
        }
    }

    startRegionExecutable = SLEEPWALKERIsExecutableProtection(StartRegionProtect);

    SLEEPWALKEREtwLogThreadEvent(ProcessId, ThreadId, CreatorPid, StartAddress, ImageBase, ImageSize, GotStart,
                                 GotRange, IsRemoteCreator, OutsideMainImage, CorrelationFlags, CorrelationAccessMask,
                                 CorrelationAgeMs, StartRegionProtect, StartRegionState, StartRegionType,
                                 StartRegionStatus, frameCount, frames);

    {
        UINT32 flags = 0;
        if (GotStart)
        {
            flags |= SLEEPWALKER_THREAD_FLAG_GOT_START;
        }
        if (GotRange)
        {
            flags |= SLEEPWALKER_THREAD_FLAG_GOT_RANGE;
        }
        if (IsRemoteCreator)
        {
            flags |= SLEEPWALKER_THREAD_FLAG_REMOTE_CREATOR;
        }
        if (OutsideMainImage)
        {
            flags |= SLEEPWALKER_THREAD_FLAG_OUTSIDE_MAIN_IMG;
        }
        if (CorrelationFlags != 0)
        {
            flags |= SLEEPWALKER_THREAD_FLAG_CORRELATED_INTENT;
        }
        if ((CorrelationFlags & SLEEPWALKER_INTENT_PROCESS_MEMORY) != 0)
        {
            flags |= SLEEPWALKER_THREAD_FLAG_CORR_MEMORY;
        }
        if ((CorrelationFlags & SLEEPWALKER_INTENT_THREAD_CONTEXT) != 0)
        {
            flags |= SLEEPWALKER_THREAD_FLAG_CORR_THREAD_CTX;
        }
        if ((CorrelationFlags & SLEEPWALKER_INTENT_DUP_HANDLE) != 0)
        {
            flags |= SLEEPWALKER_THREAD_FLAG_CORR_DUP_HANDLE;
        }
        if (startRegionExecutable)
        {
            flags |= SLEEPWALKER_THREAD_FLAG_START_REGION_EXEC;
        }

        SLEEPWALKERControlPublishThreadEvent((UINT64)(ULONG_PTR)ProcessId, (UINT64)(ULONG_PTR)ThreadId,
                                             (UINT64)(ULONG_PTR)CreatorPid, (UINT64)(ULONG_PTR)StartAddress,
                                             (UINT64)(ULONG_PTR)ImageBase, (UINT64)ImageSize, flags, frameCount,
                                             frames);
    }
}

static BOOLEAN SLEEPWALKERQueryThreadStartAddress(_In_ HANDLE ProcessId, _In_ HANDLE ThreadId,
                                                  _Out_ PVOID *StartAddress)
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
    if (!NT_SUCCESS(status))
    {
        status = ZwOpenThread(&hThread, THREAD_QUERY_INFORMATION, &oa, &cid);
        if (!NT_SUCCESS(status))
        {
            return FALSE;
        }
    }

    status =
        ZwQueryInformationThread(hThread, ThreadQuerySetWin32StartAddress, StartAddress, sizeof(*StartAddress), NULL);

    ZwClose(hThread);
    return NT_SUCCESS(status);
}

static BOOLEAN SLEEPWALKERGetProcessImageRange(_In_ HANDLE ProcessId, _In_ PEPROCESS Process, _Out_ PVOID *ImageBase,
                                               _Out_ SIZE_T *ImageSize)
{
    NTSTATUS status;
    OBJECT_ATTRIBUTES oa;
    CLIENT_ID cid;
    HANDLE hProcess = NULL;
    PVOID base = PsGetProcessSectionBaseAddress(Process);
    MEMORY_BASIC_INFORMATION mbi;

    *ImageBase = NULL;
    *ImageSize = 0;

    if (base == NULL)
    {
        return FALSE;
    }

    InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    cid.UniqueProcess = ProcessId;
    cid.UniqueThread = NULL;

    status = ZwOpenProcess(&hProcess, PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, &oa, &cid);
    if (!NT_SUCCESS(status))
    {
        return FALSE;
    }

    RtlZeroMemory(&mbi, sizeof(mbi));
    status = ZwQueryVirtualMemory(hProcess, base, SLEEPWALKERMemoryBasicInformation, &mbi, sizeof(mbi), NULL);

    ZwClose(hProcess);

    if (!NT_SUCCESS(status) || mbi.RegionSize == 0)
    {
        return FALSE;
    }

    *ImageBase = base;
    *ImageSize = mbi.RegionSize;
    return TRUE;
}

static NTSTATUS SLEEPWALKERQueryAddressRegion(_In_ HANDLE ProcessId, _In_ PVOID Address, _Out_ ULONG *Protect,
                                              _Out_ ULONG *State, _Out_ ULONG *Type)
{
    NTSTATUS status;
    OBJECT_ATTRIBUTES oa;
    CLIENT_ID cid;
    HANDLE hProcess = NULL;
    MEMORY_BASIC_INFORMATION mbi;

    if (Protect != NULL)
    {
        *Protect = 0;
    }
    if (State != NULL)
    {
        *State = 0;
    }
    if (Type != NULL)
    {
        *Type = 0;
    }

    if (Address == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    cid.UniqueProcess = ProcessId;
    cid.UniqueThread = NULL;

    status = ZwOpenProcess(&hProcess, PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, &oa, &cid);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    RtlZeroMemory(&mbi, sizeof(mbi));
    status = ZwQueryVirtualMemory(hProcess, Address, SLEEPWALKERMemoryBasicInformation, &mbi, sizeof(mbi), NULL);
    ZwClose(hProcess);

    if (!NT_SUCCESS(status))
    {
        return status;
    }

    if (Protect != NULL)
    {
        *Protect = mbi.Protect;
    }
    if (State != NULL)
    {
        *State = mbi.State;
    }
    if (Type != NULL)
    {
        *Type = mbi.Type;
    }
    return STATUS_SUCCESS;
}

static VOID SLEEPWALKERThreadWorkRoutine(_In_ PVOID Context)
{
    PSLEEPWALKER_THREAD_WORK w = (PSLEEPWALKER_THREAD_WORK)Context;
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
    HANDLE creatorPidForTelemetry;
    BOOLEAN hasCorrelation = FALSE;

    PAGED_CODE(); // worker should run at PASSIVE_LEVEL

    // Safety: if we somehow aren't PASSIVE, bail.
    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        goto Exit;
    }
    if (InterlockedCompareExchange(&g_ThreadMonitorStopping, 0, 0) != 0)
    {
        goto Exit;
    }

    // Best-effort: process may be terminating; still safe to fail gracefully.
    gotStart = SLEEPWALKERQueryThreadStartAddress(w->ProcessId, w->ThreadId, &threadStart);
    gotRange = SLEEPWALKERGetProcessImageRange(w->ProcessId, w->Process, &imageBase, &imageSize);
    if (gotStart && gotRange && threadStart && imageBase && imageSize)
    {
        ULONG_PTR start = (ULONG_PTR)threadStart;
        ULONG_PTR base = (ULONG_PTR)imageBase;

        // Overflow-safe bounds check
        ULONG_PTR end = base + (ULONG_PTR)imageSize;
        if (end < base)
        {
            outsideMainImage = TRUE;
        }
        else
        {
            outsideMainImage = (start < base) || (start >= end);
        }
    }

    if (gotStart && threadStart != NULL)
    {
        startRegionStatus = SLEEPWALKERQueryAddressRegion(w->ProcessId, threadStart, &startRegionProtect,
                                                          &startRegionState, &startRegionType);
    }
    if (InterlockedCompareExchange(&g_ThreadMonitorStopping, 0, 0) != 0)
    {
        goto Exit;
    }
    if (NT_SUCCESS(startRegionStatus))
    {
        startRegionExecutable = SLEEPWALKERIsExecutableProtection(startRegionProtect);
        startRegionNonImage = (startRegionType != MEM_IMAGE);
    }

    creatorPidForTelemetry = w->CreatorProcessId;
    if (creatorPidForTelemetry == NULL)
    {
        creatorPidForTelemetry = w->ProcessId;
    }

    hasCorrelation = SLEEPWALKERHollowingResolveThreadCorrelation(
        w->ProcessId, creatorPidForTelemetry, SLEEPWALKER_THREAD_CORRELATION_WINDOW_MS, &creatorPidForTelemetry,
        &correlationFlags, &correlationAccessMask, &correlationAgeMs);
    if (!hasCorrelation)
    {
        correlationFlags = 0;
        correlationAccessMask = 0;
        correlationAgeMs = 0;
    }

    isRemoteCreator = (creatorPidForTelemetry != w->ProcessId);

    SLEEPWALKERLogThreadTelemetry(w->ProcessId, w->ThreadId, creatorPidForTelemetry, threadStart, imageBase, imageSize,
                                  gotStart, gotRange, isRemoteCreator, outsideMainImage, correlationFlags,
                                  correlationAccessMask, correlationAgeMs, startRegionProtect, startRegionState,
                                  startRegionType, startRegionStatus);
    SLEEPWALKERHollowingObserveThread(w->ProcessId, creatorPidForTelemetry, outsideMainImage, gotStart,
                                      startRegionExecutable, startRegionNonImage, correlationFlags,
                                      correlationAccessMask, correlationAgeMs);

Exit:
    if (w->Process)
    {
        ObDereferenceObject(w->Process);
    }

    ExFreePoolWithTag(w, 'traT');

    SLEEPWALKERThreadReleaseWorkSlot();
}

VOID SLEEPWALKERThreadNotifyRoutine(HANDLE ProcessId, HANDLE ThreadId, BOOLEAN Create)
{
    LONG failureCounter;

    if (!Create)
    {
        return;
    }
    if (InterlockedCompareExchange(&g_ThreadMonitorStopping, 0, 0) != 0)
    {
        return;
    }
    if (!SLEEPWALKERThreadTryAcquireWorkSlot())
    {
        return;
    }

    // Do NOT do Zw* here. Just queue work.
    PEPROCESS process = NULL;
    NTSTATUS status = PsLookupProcessByProcessId(ProcessId, &process);
    if (!NT_SUCCESS(status))
    {
        failureCounter = InterlockedIncrement(&g_ThreadLookupFailureCounter);
        if (failureCounter == 1 || ((failureCounter & 0xFF) == 0))
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "SLEEPWALKER: thread callback lookup failure pid=%p tid=%p status=0x%08X total=%lu.\n",
                       ProcessId, ThreadId, status, (ULONG)failureCounter);
        }
        SLEEPWALKERThreadReleaseWorkSlot();
        return;
    }

    PSLEEPWALKER_THREAD_WORK w =
        (PSLEEPWALKER_THREAD_WORK)ExAllocatePool2(POOL_FLAG_NON_PAGED | POOL_FLAG_UNINITIALIZED, sizeof(*w), 'traT');
    if (!w)
    {
        failureCounter = InterlockedIncrement(&g_ThreadAllocFailureCounter);
        if (failureCounter == 1 || ((failureCounter & 0xFF) == 0))
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                       "SLEEPWALKER: thread callback alloc failure pid=%p tid=%p total=%lu.\n", ProcessId, ThreadId,
                       (ULONG)failureCounter);
        }
        ObDereferenceObject(process);
        SLEEPWALKERThreadReleaseWorkSlot();
        return;
    }

    RtlZeroMemory(w, sizeof(*w));
    w->ProcessId = ProcessId;
    w->ThreadId = ThreadId;
    w->CreatorProcessId = PsGetCurrentProcessId(); // heuristic only
    w->Process = process;                          // already referenced by lookup

    ExInitializeWorkItem(&w->WorkItem, SLEEPWALKERThreadWorkRoutine, w);

    ExQueueWorkItem(&w->WorkItem, DelayedWorkQueue);
}

NTSTATUS
SLEEPWALKERThreadMonitorInitialize(VOID)
{
    NTSTATUS status;
    LONG failureCounter;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (g_ThreadNotifyRegistered)
    {
        return STATUS_SUCCESS;
    }

    InterlockedExchange(&g_ThreadMonitorStopping, 0);
    InterlockedExchange(&g_OutstandingWork, 0);
    InterlockedExchange(&g_DroppedWork, 0);
    KeInitializeEvent(&g_AllWorkDone, NotificationEvent, TRUE);

    g_SetNotifyRoutineEx = SLEEPWALKERResolvePsSetCreateThreadNotifyRoutineEx();
    if (g_SetNotifyRoutineEx == NULL)
    {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    status = g_SetNotifyRoutineEx(PsCreateThreadNotifyNonSystem, (PVOID)SLEEPWALKERThreadNotifyRoutine);

    if (!NT_SUCCESS(status))
    {
        failureCounter = InterlockedIncrement(&g_ThreadInitFailureCounter);
        if (failureCounter == 1 || ((failureCounter & 0xFF) == 0))
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                       "SLEEPWALKER: thread monitor callback registration failure status=0x%08X total=%lu.\n", status,
                       (ULONG)failureCounter);
        }
        g_SetNotifyRoutineEx = NULL;
        return status;
    }

    g_ThreadNotifyRegistered = TRUE;
    g_NotifyMode = SLEEPWALKERNotifyEx;
    return STATUS_SUCCESS;
}

VOID SLEEPWALKERThreadMonitorUninitialize(VOID)
{
    NTSTATUS status;
    LARGE_INTEGER waitInterval;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        return;
    }
    if (!g_ThreadNotifyRegistered)
    {
        return;
    }

    InterlockedExchange(&g_ThreadMonitorStopping, 1);
    status = PsRemoveCreateThreadNotifyRoutine(SLEEPWALKERThreadNotifyRoutine);
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "SLEEPWALKER: thread monitor callback removal failed; monitor remains registered (status=0x%08X).\n",
                   status);
        return;
    }

    g_NotifyMode = SLEEPWALKERNotifyNone;
    g_ThreadNotifyRegistered = FALSE;
    g_SetNotifyRoutineEx = NULL;

    waitInterval.QuadPart = -(LONGLONG)1000 * 10000;
    while (InterlockedCompareExchange(&g_OutstandingWork, 0, 0) != 0)
    {
        NTSTATUS waitStatus;

        waitStatus = KeWaitForSingleObject(&g_AllWorkDone, Executive, KernelMode, FALSE, &waitInterval);
        if (waitStatus == STATUS_TIMEOUT)
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                       "SLEEPWALKER: thread monitor draining (outstanding=%ld).\n",
                       InterlockedCompareExchange(&g_OutstandingWork, 0, 0));
        }
    }
    InterlockedExchange(&g_ThreadMonitorStopping, 0);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "SLEEPWALKER: thread monitor uninitialized (dropped=%ld).\n",
               InterlockedCompareExchange(&g_DroppedWork, 0, 0));
}

BOOLEAN
SLEEPWALKERThreadMonitorSelfCheck(VOID)
{
    LONG outstanding;

    if (!g_ThreadNotifyRegistered)
    {
        return FALSE;
    }
    if (g_NotifyMode != SLEEPWALKERNotifyEx || g_SetNotifyRoutineEx == NULL)
    {
        return FALSE;
    }

    outstanding = InterlockedCompareExchange(&g_OutstandingWork, 0, 0);
    if (outstanding < 0 || outstanding > SLEEPWALKER_THREAD_MAX_OUTSTANDING_WORK)
    {
        return FALSE;
    }

    return TRUE;
}
