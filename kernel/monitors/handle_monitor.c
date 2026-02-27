#include <ntddk.h>
#include "..\core\control.h"
#include "..\core\protection_utils.h"
#include "..\core\unicode_utils.h"
#include "..\telemetry\etw.h"
#include "handle_monitor.h"

#ifndef PROCESS_VM_READ
#define PROCESS_VM_READ 0x0010
#endif

#ifndef PROCESS_VM_WRITE
#define PROCESS_VM_WRITE 0x0020
#endif

#ifndef PROCESS_VM_OPERATION
#define PROCESS_VM_OPERATION 0x0008
#endif

#ifndef PROCESS_QUERY_LIMITED_INFORMATION
#define PROCESS_QUERY_LIMITED_INFORMATION 0x1000
#endif

#ifndef THREAD_SET_CONTEXT
#define THREAD_SET_CONTEXT 0x0010
#endif

#ifndef THREAD_SUSPEND_RESUME
#define THREAD_SUSPEND_RESUME 0x0002
#endif

#ifndef THREAD_GET_CONTEXT
#define THREAD_GET_CONTEXT 0x0008
#endif

#ifndef THREAD_ALL_ACCESS
#define THREAD_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xFFFF)
#endif

#ifndef _MEMORY_BASIC_INFORMATION
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
#endif

typedef enum _SLEEPWALKER_MEMORY_INFORMATION_CLASS
{
    SLEEPWALKERMemoryBasicInformation = 0,
    SLEEPWALKERMemorySectionName = 2
} SLEEPWALKER_MEMORY_INFORMATION_CLASS;

NTSYSAPI NTSTATUS NTAPI ZwQueryVirtualMemory(_In_ HANDLE ProcessHandle, _In_opt_ PVOID BaseAddress,
                                             _In_ SLEEPWALKER_MEMORY_INFORMATION_CLASS MemoryInformationClass,
                                             _Out_writes_bytes_(MemoryInformationLength) PVOID MemoryInformation,
                                             _In_ SIZE_T MemoryInformationLength, _Out_opt_ PSIZE_T ReturnLength);

#ifndef RTL_WALK_USER_MODE_STACK
#define RTL_WALK_USER_MODE_STACK 0x00000001
#endif

NTKERNELAPI HANDLE PsGetThreadProcessId(_In_ PETHREAD Thread);
NTKERNELAPI NTSTATUS PsLookupProcessByProcessId(_In_ HANDLE ProcessId, _Outptr_ PEPROCESS *Process);
NTKERNELAPI NTSTATUS MmCopyVirtualMemory(_In_ PEPROCESS FromProcess, _In_ const VOID *FromAddress,
                                         _In_ PEPROCESS ToProcess, _Out_writes_bytes_(BufferSize) PVOID ToAddress,
                                         _In_ SIZE_T BufferSize, _In_ KPROCESSOR_MODE PreviousMode,
                                         _Out_ PSIZE_T NumberOfBytesCopied);

#define SLEEPWALKER_HANDLE_MAX_OUTSTANDING_WORK 2048
#define SLEEPWALKER_DEEP_CAPTURE_MAX_BYTES 64
#define SLEEPWALKER_DEEP_CACHE_RING_SIZE 64
#define SLEEPWALKER_DEEP_CACHE_TTL_MS 3000

static PVOID g_ProcessObRegistrationHandle = NULL;
static OB_OPERATION_REGISTRATION g_OperationRegistration[2];
static OB_CALLBACK_REGISTRATION g_CallbackRegistration;
static UNICODE_STRING g_CallbackAltitude;
static const WCHAR g_CallbackAltitudeBuffer[] = L"385000.424242";
static volatile LONG g_HandleOutstandingWork = 0;
static volatile LONG g_HandleDroppedWork = 0;
static volatile LONG g_HandleStackCaptureFaults = 0;
static KEVENT g_HandleAllWorkDone;
static volatile LONG g_HandleMonitorStopping = 0;
static BOOLEAN g_HandleMonitorRegistered = FALSE;
static volatile LONG g_HandleCallbackDropLogCounter = 0;
static volatile LONG g_HandleAllocFailureCounter = 0;
static volatile LONG g_HandleStackFaultLogCounter = 0;
static KSPIN_LOCK g_DeepCacheLock;
static volatile LONG g_DeepCacheWriteIndex = -1;
static ULONGLONG g_DeepCacheQpcFrequency = 1;

typedef struct _SLEEPWALKER_DEEP_CACHE_ENTRY
{
    UINT64 CallerPid;
    UINT64 AllocationBase;
    UINT64 RegionSize;
    ULONG RegionProtect;
    ULONG RegionState;
    ULONG RegionType;
    UCHAR Sample[SLEEPWALKER_DEEP_CAPTURE_MAX_BYTES];
    UINT32 SampleSize;
    INT64 TimestampQpc;
} SLEEPWALKER_DEEP_CACHE_ENTRY, *PSLEEPWALKER_DEEP_CACHE_ENTRY;

static SLEEPWALKER_DEEP_CACHE_ENTRY g_DeepCache[SLEEPWALKER_DEEP_CACHE_RING_SIZE];

/*
 * Hot-path debug tracing is disabled by default to prevent KD console flooding.
 * Define SLEEPWALKER_VERBOSE_HOTPATH_DEBUG=1 for local deep diagnostics.
 */
#if !defined(SLEEPWALKER_VERBOSE_HOTPATH_DEBUG)
#define SLEEPWALKER_VERBOSE_HOTPATH_DEBUG 0
#endif

#if defined(DBG) && DBG && SLEEPWALKER_VERBOSE_HOTPATH_DEBUG
#define SLEEPWALKER_DBG_PRINT(_level, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, (_level), __VA_ARGS__)
#else
#define SLEEPWALKER_DBG_PRINT(_level, ...) ((void)0)
#endif

typedef struct _SLEEPWALKER_HANDLE_WORK
{
    WORK_QUEUE_ITEM WorkItem;
    HANDLE CallerPid;
    HANDLE TargetPid;
    ACCESS_MASK DesiredAccess;
    BOOLEAN IsThreadObject;
    BOOLEAN IsDuplicateOperation;
    ULONG FrameCount;
    PVOID Frames[8];
} SLEEPWALKER_HANDLE_WORK, *PSLEEPWALKER_HANDLE_WORK;

typedef enum _SLEEPWALKER_HANDLE_CLASSIFICATION
{
    SLEEPWALKERHandleUnknown = 0,
    SLEEPWALKERHandleLegitimateSyscall,
    SLEEPWALKERHandleDirectSyscallSuspect
} SLEEPWALKER_HANDLE_CLASSIFICATION;

typedef struct _SLEEPWALKER_HANDLE_TELEMETRY
{
    PVOID OriginAddress;
    PVOID AllocationBase;
    SIZE_T RegionSize;
    ULONG OriginProtect;
    ULONG RegionState;
    ULONG RegionType;
    WCHAR OriginPath[512];
    ULONG FrameCount;
    PVOID Frames[8];
    NTSTATUS OpenProcessStatus;
    NTSTATUS BasicInfoStatus;
    NTSTATUS SectionNameStatus;
    ULONG DeepSampleSize;
    UCHAR DeepSample[SLEEPWALKER_DEEP_CAPTURE_MAX_BYTES];
    BOOLEAN DeepPathCandidate;
    BOOLEAN DeepPathCaptured;
    BOOLEAN DeepPathCacheHit;
} SLEEPWALKER_HANDLE_TELEMETRY, *PSLEEPWALKER_HANDLE_TELEMETRY;

static BOOLEAN SLEEPWALKERHandleTryAcquireWorkSlot(VOID)
{
    LONG current;

    for (;;)
    {
        current = InterlockedCompareExchange(&g_HandleOutstandingWork, 0, 0);
        if (current >= SLEEPWALKER_HANDLE_MAX_OUTSTANDING_WORK)
        {
            InterlockedIncrement(&g_HandleDroppedWork);
            SLEEPWALKER_DBG_PRINT(DPFLTR_WARNING_LEVEL, "SLEEPWALKER[DBG]: handle monitor work queue full (max=%lu).\n",
                                  SLEEPWALKER_HANDLE_MAX_OUTSTANDING_WORK);
            return FALSE;
        }

        if (InterlockedCompareExchange(&g_HandleOutstandingWork, current + 1, current) == current)
        {
            if (current == 0)
            {
                KeClearEvent(&g_HandleAllWorkDone);
            }
            return TRUE;
        }
    }
}

static VOID SLEEPWALKERHandleReleaseWorkSlot(VOID)
{
    if (InterlockedDecrement(&g_HandleOutstandingWork) == 0)
    {
        KeSetEvent(&g_HandleAllWorkDone, IO_NO_INCREMENT, FALSE);
    }
}

static ULONGLONG SLEEPWALKERDeepCacheMsToQpc(_In_ UINT32 Ms)
{
    ULONGLONG ticks;

    if (Ms == 0)
    {
        return 0;
    }

    ticks = ((ULONGLONG)Ms * g_DeepCacheQpcFrequency) / 1000ULL;
    return (ticks == 0) ? 1 : ticks;
}

static BOOLEAN SLEEPWALKERDeepCacheLookup(_In_ HANDLE CallerPid, _In_ PVOID AllocationBase, _In_ SIZE_T RegionSize,
                                          _In_ ULONG RegionProtect, _In_ ULONG RegionState, _In_ ULONG RegionType,
                                          _Out_writes_bytes_(SLEEPWALKER_DEEP_CAPTURE_MAX_BYTES) UCHAR *Sample,
                                          _Out_ UINT32 *SampleSize)
{
    KIRQL oldIrql;
    UINT32 i;
    INT64 nowQpc;
    ULONGLONG maxAgeQpc;

    if (Sample == NULL || SampleSize == NULL || AllocationBase == NULL || RegionSize == 0)
    {
        return FALSE;
    }

    nowQpc = KeQueryPerformanceCounter(NULL).QuadPart;
    maxAgeQpc = SLEEPWALKERDeepCacheMsToQpc(SLEEPWALKER_DEEP_CACHE_TTL_MS);
    KeAcquireSpinLock(&g_DeepCacheLock, &oldIrql);
    for (i = 0; i < RTL_NUMBER_OF(g_DeepCache); ++i)
    {
        const SLEEPWALKER_DEEP_CACHE_ENTRY *e = &g_DeepCache[i];
        INT64 ageQpc;
        UINT32 safeSize;

        if (e->TimestampQpc == 0)
        {
            continue;
        }
        if (e->CallerPid != (UINT64)(ULONG_PTR)CallerPid || e->AllocationBase != (UINT64)(ULONG_PTR)AllocationBase ||
            e->RegionSize != (UINT64)RegionSize || e->RegionProtect != RegionProtect || e->RegionState != RegionState ||
            e->RegionType != RegionType)
        {
            continue;
        }

        ageQpc = nowQpc - e->TimestampQpc;
        if (ageQpc < 0 || (ULONGLONG)ageQpc > maxAgeQpc)
        {
            continue;
        }

        safeSize =
            (e->SampleSize > SLEEPWALKER_DEEP_CAPTURE_MAX_BYTES) ? SLEEPWALKER_DEEP_CAPTURE_MAX_BYTES : e->SampleSize;
        *SampleSize = safeSize;
        if (safeSize != 0)
        {
            RtlCopyMemory(Sample, e->Sample, safeSize);
        }
        KeReleaseSpinLock(&g_DeepCacheLock, oldIrql);
        return TRUE;
    }
    KeReleaseSpinLock(&g_DeepCacheLock, oldIrql);
    return FALSE;
}

static VOID SLEEPWALKERDeepCacheStore(_In_ HANDLE CallerPid, _In_ PVOID AllocationBase, _In_ SIZE_T RegionSize,
                                      _In_ ULONG RegionProtect, _In_ ULONG RegionState, _In_ ULONG RegionType,
                                      _In_reads_bytes_(SampleSize) const UCHAR *Sample, _In_ UINT32 SampleSize)
{
    LONG idx;
    UINT32 slot;
    KIRQL oldIrql;
    UINT32 safeSize;

    if (AllocationBase == NULL || RegionSize == 0 || Sample == NULL || SampleSize == 0)
    {
        return;
    }

    safeSize = (SampleSize > SLEEPWALKER_DEEP_CAPTURE_MAX_BYTES) ? SLEEPWALKER_DEEP_CAPTURE_MAX_BYTES : SampleSize;

    idx = InterlockedIncrement(&g_DeepCacheWriteIndex);
    if (idx < 0)
    {
        idx = 0;
    }
    slot = (UINT32)idx % RTL_NUMBER_OF(g_DeepCache);

    KeAcquireSpinLock(&g_DeepCacheLock, &oldIrql);
    g_DeepCache[slot].CallerPid = (UINT64)(ULONG_PTR)CallerPid;
    g_DeepCache[slot].AllocationBase = (UINT64)(ULONG_PTR)AllocationBase;
    g_DeepCache[slot].RegionSize = (UINT64)RegionSize;
    g_DeepCache[slot].RegionProtect = RegionProtect;
    g_DeepCache[slot].RegionState = RegionState;
    g_DeepCache[slot].RegionType = RegionType;
    g_DeepCache[slot].SampleSize = safeSize;
    RtlCopyMemory(g_DeepCache[slot].Sample, Sample, safeSize);
    g_DeepCache[slot].TimestampQpc = KeQueryPerformanceCounter(NULL).QuadPart;
    KeReleaseSpinLock(&g_DeepCacheLock, oldIrql);
}

static PCSTR SLEEPWALKERHandleClassToString(_In_ SLEEPWALKER_HANDLE_CLASSIFICATION Class)
{
    if (Class == SLEEPWALKERHandleLegitimateSyscall)
    {
        return "LEGITIMATE-SYSCALL";
    }
    if (Class == SLEEPWALKERHandleDirectSyscallSuspect)
    {
        return "DIRECT-SYSCALL-SUSPECT";
    }
    return "UNKNOWN-ORIGIN";
}

static VOID SLEEPWALKERLogHandleTelemetry(_In_ SLEEPWALKER_HANDLE_CLASSIFICATION Class, _In_ HANDLE CallerPid,
                                          _In_ HANDLE TargetPid, _In_ ACCESS_MASK DesiredAccess,
                                          _In_ BOOLEAN IsThreadObject, _In_ BOOLEAN IsDuplicateOperation,
                                          _In_ BOOLEAN ExecProtect, _In_ BOOLEAN FromNtdll, _In_ BOOLEAN FromExe,
                                          _In_ PSLEEPWALKER_HANDLE_TELEMETRY Telemetry)
{
    UINT32 flags = 0;
    BOOLEAN memoryRelated;
    UINT32 classId;

    SLEEPWALKEREtwLogHandleEvent(
        SLEEPWALKERHandleClassToString(Class), CallerPid, TargetPid, DesiredAccess, Telemetry->OriginAddress,
        Telemetry->OriginProtect, ExecProtect, FromNtdll, FromExe,
        (Telemetry->OriginPath[0] != L'\0') ? Telemetry->OriginPath : NULL, Telemetry->FrameCount, Telemetry->Frames,
        Telemetry->OpenProcessStatus, Telemetry->BasicInfoStatus, Telemetry->SectionNameStatus,
        (UINT64)(ULONG_PTR)Telemetry->AllocationBase, (UINT64)Telemetry->RegionSize, Telemetry->OriginProtect,
        Telemetry->RegionState, Telemetry->RegionType, Telemetry->DeepSampleSize, Telemetry->DeepSample);

    if (ExecProtect)
    {
        flags |= SLEEPWALKER_HANDLE_FLAG_EXEC_PROTECT;
    }
    if (FromNtdll)
    {
        flags |= SLEEPWALKER_HANDLE_FLAG_FROM_NTDLL;
    }
    if (FromExe)
    {
        flags |= SLEEPWALKER_HANDLE_FLAG_FROM_EXE;
    }

    memoryRelated = ((DesiredAccess & PROCESS_VM_OPERATION) != 0) || ((DesiredAccess & PROCESS_VM_READ) != 0) ||
                    ((DesiredAccess & PROCESS_VM_WRITE) != 0) || ((DesiredAccess & PROCESS_ALL_ACCESS) != 0);
    if (memoryRelated)
    {
        flags |= SLEEPWALKER_HANDLE_FLAG_MEMORY_RELATED;
    }
    if (IsThreadObject)
    {
        flags |= SLEEPWALKER_HANDLE_FLAG_THREAD_OBJECT;
    }
    if (IsDuplicateOperation)
    {
        flags |= SLEEPWALKER_HANDLE_FLAG_DUPLICATE_OPERATION;
    }
    if (Telemetry->DeepPathCandidate)
    {
        flags |= SLEEPWALKER_HANDLE_FLAG_DEEP_PATH_CANDIDATE;
    }
    if (Telemetry->DeepPathCaptured)
    {
        flags |= SLEEPWALKER_HANDLE_FLAG_DEEP_PATH_CAPTURED;
    }
    if (Telemetry->DeepPathCacheHit)
    {
        flags |= SLEEPWALKER_HANDLE_FLAG_DEEP_PATH_CACHE_HIT;
    }

    classId = SleepwalkerHandleClassUnknown;
    if (Class == SLEEPWALKERHandleLegitimateSyscall)
    {
        classId = SleepwalkerHandleClassLegitimateSyscall;
    }
    else if (Class == SLEEPWALKERHandleDirectSyscallSuspect)
    {
        classId = SleepwalkerHandleClassDirectSyscallSuspect;
    }

    SLEEPWALKERControlPublishHandleEvent(
        (UINT64)(ULONG_PTR)CallerPid, (UINT64)(ULONG_PTR)TargetPid, (UINT32)DesiredAccess, classId,
        (UINT64)(ULONG_PTR)Telemetry->OriginAddress, Telemetry->OriginProtect, flags,
        (Telemetry->OriginPath[0] != L'\0') ? Telemetry->OriginPath : NULL, Telemetry->FrameCount, Telemetry->Frames,
        (INT32)Telemetry->OpenProcessStatus, (INT32)Telemetry->BasicInfoStatus, (INT32)Telemetry->SectionNameStatus,
        (UINT64)(ULONG_PTR)Telemetry->AllocationBase, (UINT64)Telemetry->RegionSize, Telemetry->OriginProtect,
        Telemetry->RegionState, Telemetry->RegionType, Telemetry->DeepSampleSize, Telemetry->DeepSample);
}

static VOID SLEEPWALKERCaptureDeepPathData(_In_ HANDLE CallerProcessId, _In_ BOOLEAN ShouldCapture,
                                           _In_ const MEMORY_BASIC_INFORMATION *Mbi,
                                           _Inout_ PSLEEPWALKER_HANDLE_TELEMETRY Telemetry)
{
    NTSTATUS status;
    PEPROCESS sourceProcess = NULL;
    PEPROCESS localProcess;
    SIZE_T bytesRead = 0;
    UINT32 sampleSize;

    if (!ShouldCapture || Mbi == NULL || Telemetry == NULL)
    {
        return;
    }

    Telemetry->DeepPathCandidate = TRUE;
    Telemetry->AllocationBase = Mbi->AllocationBase;
    Telemetry->RegionSize = Mbi->RegionSize;
    Telemetry->RegionState = Mbi->State;
    Telemetry->RegionType = Mbi->Type;

    if (Mbi->BaseAddress == NULL || Mbi->RegionSize == 0)
    {
        return;
    }

    if (SLEEPWALKERDeepCacheLookup(CallerProcessId, Mbi->BaseAddress, Mbi->RegionSize, Mbi->Protect, Mbi->State,
                                   Mbi->Type, Telemetry->DeepSample, &sampleSize))
    {
        Telemetry->DeepPathCaptured = TRUE;
        Telemetry->DeepPathCacheHit = TRUE;
        Telemetry->DeepSampleSize = sampleSize;
        return;
    }

    status = PsLookupProcessByProcessId(CallerProcessId, &sourceProcess);
    if (!NT_SUCCESS(status))
    {
        return;
    }

    localProcess = PsGetCurrentProcess();
    status = MmCopyVirtualMemory(sourceProcess, Mbi->BaseAddress, localProcess, Telemetry->DeepSample,
                                 sizeof(Telemetry->DeepSample), KernelMode, &bytesRead);
    ObDereferenceObject(sourceProcess);
    if (!NT_SUCCESS(status) || bytesRead == 0)
    {
        return;
    }

    if (bytesRead > RTL_NUMBER_OF(Telemetry->DeepSample))
    {
        bytesRead = RTL_NUMBER_OF(Telemetry->DeepSample);
    }
    Telemetry->DeepSampleSize = (ULONG)bytesRead;
    Telemetry->DeepPathCaptured = TRUE;
    Telemetry->DeepPathCacheHit = FALSE;
    SLEEPWALKERDeepCacheStore(CallerProcessId, Mbi->BaseAddress, Mbi->RegionSize, Mbi->Protect, Mbi->State, Mbi->Type,
                              Telemetry->DeepSample, Telemetry->DeepSampleSize);
}

static VOID SLEEPWALKERClassifyUserOrigin(_In_ HANDLE CallerProcessId, _In_ ULONG FrameCount,
                                          _In_reads_(FrameCount) PVOID *Frames,
                                          _Out_ PSLEEPWALKER_HANDLE_TELEMETRY Telemetry)
{
    NTSTATUS status;
    OBJECT_ATTRIBUTES objectAttributes;
    CLIENT_ID clientId;
    HANDLE processHandle = NULL;
    MEMORY_BASIC_INFORMATION mbi;
    UCHAR sectionNameRaw[1024];
    PUNICODE_STRING sectionName;
    UNICODE_STRING originPathUs;
    BOOLEAN execProtect;
    BOOLEAN fromNtdll;
    BOOLEAN deepPathGate;

    RtlZeroMemory(Telemetry, sizeof(*Telemetry));
    Telemetry->OpenProcessStatus = STATUS_UNSUCCESSFUL;
    Telemetry->BasicInfoStatus = STATUS_UNSUCCESSFUL;
    Telemetry->SectionNameStatus = STATUS_UNSUCCESSFUL;

    if (FrameCount == 0 || Frames == NULL || Frames[0] == NULL)
    {
        return;
    }
    Telemetry->OriginAddress = Frames[0];
    Telemetry->FrameCount =
        (FrameCount > RTL_NUMBER_OF(Telemetry->Frames)) ? RTL_NUMBER_OF(Telemetry->Frames) : FrameCount;
    RtlCopyMemory(Telemetry->Frames, Frames, Telemetry->FrameCount * sizeof(PVOID));

    InitializeObjectAttributes(&objectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    clientId.UniqueProcess = CallerProcessId;
    clientId.UniqueThread = NULL;

    status = ZwOpenProcess(&processHandle, PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, &objectAttributes,
                           &clientId);
    Telemetry->OpenProcessStatus = status;
    if (!NT_SUCCESS(status))
    {
        SLEEPWALKER_DBG_PRINT(DPFLTR_TRACE_LEVEL,
                              "SLEEPWALKER[DBG]: ZwOpenProcess failed callerPid=%p status=0x%08X.\n", CallerProcessId,
                              (ULONG)status);
        return;
    }
    if (InterlockedCompareExchange(&g_HandleMonitorStopping, 0, 0) != 0)
    {
        ZwClose(processHandle);
        return;
    }

    RtlZeroMemory(&mbi, sizeof(mbi));
    status = ZwQueryVirtualMemory(processHandle, Telemetry->OriginAddress, SLEEPWALKERMemoryBasicInformation, &mbi,
                                  sizeof(mbi), NULL);
    Telemetry->BasicInfoStatus = status;
    if (NT_SUCCESS(status))
    {
        Telemetry->OriginProtect = mbi.Protect;
        Telemetry->AllocationBase = mbi.AllocationBase;
        Telemetry->RegionSize = mbi.RegionSize;
        Telemetry->RegionState = mbi.State;
        Telemetry->RegionType = mbi.Type;
    }
    else
    {
        SLEEPWALKER_DBG_PRINT(DPFLTR_TRACE_LEVEL,
                              "SLEEPWALKER[DBG]: ZwQueryVirtualMemory(basic) failed callerPid=%p status=0x%08X.\n",
                              CallerProcessId, (ULONG)status);
    }
    if (InterlockedCompareExchange(&g_HandleMonitorStopping, 0, 0) != 0)
    {
        ZwClose(processHandle);
        return;
    }

    RtlZeroMemory(sectionNameRaw, sizeof(sectionNameRaw));
    status = ZwQueryVirtualMemory(processHandle, Telemetry->OriginAddress, SLEEPWALKERMemorySectionName, sectionNameRaw,
                                  sizeof(sectionNameRaw), NULL);
    Telemetry->SectionNameStatus = status;
    if (NT_SUCCESS(status))
    {
        sectionName = (PUNICODE_STRING)sectionNameRaw;
        SLEEPWALKERSafeCopyUnicode(sectionName, Telemetry->OriginPath, RTL_NUMBER_OF(Telemetry->OriginPath));
    }
    else
    {
        SLEEPWALKER_DBG_PRINT(DPFLTR_TRACE_LEVEL,
                              "SLEEPWALKER[DBG]: ZwQueryVirtualMemory(section) failed callerPid=%p status=0x%08X.\n",
                              CallerProcessId, (ULONG)status);
    }

    RtlInitUnicodeString(&originPathUs, Telemetry->OriginPath);
    execProtect = SLEEPWALKERIsExecutableProtection(Telemetry->OriginProtect);
    fromNtdll = SLEEPWALKERUnicodeContainsInsensitive(&originPathUs, L"ntdll.dll", 9);
    deepPathGate = (execProtect && !fromNtdll);
    SLEEPWALKERCaptureDeepPathData(CallerProcessId, deepPathGate, &mbi, Telemetry);

    ZwClose(processHandle);
}

static VOID SLEEPWALKERHandleWorkRoutine(_In_ PVOID Context)
{
    PSLEEPWALKER_HANDLE_WORK work = (PSLEEPWALKER_HANDLE_WORK)Context;
    SLEEPWALKER_HANDLE_TELEMETRY telemetry;
    UNICODE_STRING originPathUs;
    BOOLEAN execProtect;
    BOOLEAN fromNtdll;
    BOOLEAN fromExe;
    SLEEPWALKER_HANDLE_CLASSIFICATION classification = SLEEPWALKERHandleUnknown;

    PAGED_CODE();
    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        goto Exit;
    }
    if (InterlockedCompareExchange(&g_HandleMonitorStopping, 0, 0) != 0)
    {
        goto Exit;
    }

    SLEEPWALKERClassifyUserOrigin(work->CallerPid, work->FrameCount, work->Frames, &telemetry);

    RtlInitUnicodeString(&originPathUs, telemetry.OriginPath);
    execProtect = SLEEPWALKERIsExecutableProtection(telemetry.OriginProtect);

    fromNtdll = SLEEPWALKERUnicodeContainsInsensitive(&originPathUs, L"ntdll.dll", 9);
    fromExe = SLEEPWALKERUnicodeContainsInsensitive(&originPathUs, L".exe", 4);

    SLEEPWALKERLogHandleTelemetry(classification, work->CallerPid, work->TargetPid, work->DesiredAccess,
                                  work->IsThreadObject, work->IsDuplicateOperation, execProtect, fromNtdll, fromExe,
                                  &telemetry);

    SLEEPWALKER_DBG_PRINT(DPFLTR_INFO_LEVEL,
                          "SLEEPWALKER[DBG]: handle event caller=%p target=%p access=0x%08X class=%s open=0x%08X "
                          "basic=0x%08X section=0x%08X frames=%lu.\n",
                          work->CallerPid, work->TargetPid, work->DesiredAccess,
                          SLEEPWALKERHandleClassToString(classification), (ULONG)telemetry.OpenProcessStatus,
                          (ULONG)telemetry.BasicInfoStatus, (ULONG)telemetry.SectionNameStatus, work->FrameCount);

Exit:
    SLEEPWALKERHandleReleaseWorkSlot();
    ExFreePoolWithTag(work, 'hdtT');
}

static OB_PREOP_CALLBACK_STATUS SLEEPWALKERProcessPreOperation(
    _In_ PVOID RegistrationContext, _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation)
{
    ACCESS_MASK desiredAccess;
    HANDLE callerPid;
    HANDLE targetPid;
    PEPROCESS targetProcess;
    PETHREAD targetThread;
    PSLEEPWALKER_HANDLE_WORK work;
    PVOID userFrames[16] = {0};
    ULONG frameCount;
    ULONG copyCount;
    BOOLEAN hasVmWriteOrFull;
    BOOLEAN hasThreadContextAccess;
    BOOLEAN shouldCaptureStack;
    BOOLEAN isThreadObject = FALSE;
    BOOLEAN isDuplicateOperation = FALSE;
    LONG failureCounter;

    UNREFERENCED_PARAMETER(RegistrationContext);

    if (InterlockedCompareExchange(&g_HandleMonitorStopping, 0, 0) != 0)
    {
        return OB_PREOP_SUCCESS;
    }

    if (OperationInformation == NULL || OperationInformation->KernelHandle)
    {
        return OB_PREOP_SUCCESS;
    }

    if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
    {
        desiredAccess = OperationInformation->Parameters->CreateHandleInformation.DesiredAccess;
    }
    else if (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE)
    {
        desiredAccess = OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess;
        isDuplicateOperation = TRUE;
    }
    else
    {
        return OB_PREOP_SUCCESS;
    }

    hasVmWriteOrFull = FALSE;
    hasThreadContextAccess = FALSE;
    if (OperationInformation->ObjectType == *PsProcessType)
    {
        targetProcess = (PEPROCESS)OperationInformation->Object;
        targetPid = PsGetProcessId(targetProcess);

        hasVmWriteOrFull = ((desiredAccess & PROCESS_VM_OPERATION) != 0) || ((desiredAccess & PROCESS_VM_WRITE) != 0) ||
                           ((desiredAccess & PROCESS_ALL_ACCESS) != 0);
    }
    else if (OperationInformation->ObjectType == *PsThreadType)
    {
        isThreadObject = TRUE;
        targetThread = (PETHREAD)OperationInformation->Object;
        targetPid = PsGetThreadProcessId(targetThread);

        hasThreadContextAccess = ((desiredAccess & THREAD_SET_CONTEXT) != 0) ||
                                 ((desiredAccess & THREAD_GET_CONTEXT) != 0) ||
                                 ((desiredAccess & THREAD_SUSPEND_RESUME) != 0);
    }
    else
    {
        return OB_PREOP_SUCCESS;
    }

    if (!hasVmWriteOrFull && !hasThreadContextAccess)
    {
        return OB_PREOP_SUCCESS;
    }

    callerPid = PsGetCurrentProcessId();

    if (!SLEEPWALKERHandleTryAcquireWorkSlot())
    {
        failureCounter = InterlockedIncrement(&g_HandleCallbackDropLogCounter);
        if (failureCounter == 1 || ((failureCounter & 0xFF) == 0))
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "SLEEPWALKER: handle callback drop caller=%p target=%p access=0x%08X total=%lu.\n", callerPid,
                       targetPid, desiredAccess, (ULONG)failureCounter);
        }
        SLEEPWALKER_DBG_PRINT(
            DPFLTR_WARNING_LEVEL,
            "SLEEPWALKER[DBG]: dropping handle preop caller=%p target=%p access=0x%08X (work slot unavailable).\n",
            callerPid, targetPid, desiredAccess);
        return OB_PREOP_SUCCESS;
    }

    work =
        (PSLEEPWALKER_HANDLE_WORK)ExAllocatePool2(POOL_FLAG_NON_PAGED | POOL_FLAG_UNINITIALIZED, sizeof(*work), 'hdtT');
    if (work == NULL)
    {
        failureCounter = InterlockedIncrement(&g_HandleAllocFailureCounter);
        if (failureCounter == 1 || ((failureCounter & 0xFF) == 0))
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                       "SLEEPWALKER: handle callback alloc failure caller=%p target=%p access=0x%08X total=%lu.\n",
                       callerPid, targetPid, desiredAccess, (ULONG)failureCounter);
        }
        SLEEPWALKER_DBG_PRINT(DPFLTR_ERROR_LEVEL, "SLEEPWALKER[DBG]: ExAllocatePool2 failed for handle work item.\n");
        SLEEPWALKERHandleReleaseWorkSlot();
        return OB_PREOP_SUCCESS;
    }

    RtlZeroMemory(work, sizeof(*work));
    work->CallerPid = callerPid;
    work->TargetPid = targetPid;
    work->DesiredAccess = desiredAccess;
    work->IsThreadObject = isThreadObject;
    work->IsDuplicateOperation = isDuplicateOperation;

    frameCount = 0;
    copyCount = 0;
    shouldCaptureStack =
        isDuplicateOperation ||
        ((desiredAccess & (PROCESS_VM_WRITE | PROCESS_ALL_ACCESS | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME)) != 0);
    if (shouldCaptureStack)
    {
        __try
        {
            frameCount = RtlWalkFrameChain(userFrames, RTL_NUMBER_OF(userFrames), RTL_WALK_USER_MODE_STACK);
            copyCount = (frameCount > RTL_NUMBER_OF(work->Frames)) ? RTL_NUMBER_OF(work->Frames) : frameCount;
            if (copyCount != 0)
            {
                RtlCopyMemory(work->Frames, userFrames, copyCount * sizeof(PVOID));
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            copyCount = 0;
            RtlZeroMemory(work->Frames, sizeof(work->Frames));
            InterlockedIncrement(&g_HandleStackCaptureFaults);
            failureCounter = InterlockedIncrement(&g_HandleStackFaultLogCounter);
            if (failureCounter == 1 || ((failureCounter & 0xFF) == 0))
            {
                DbgPrintEx(
                    DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                    "SLEEPWALKER: handle callback stack capture fault caller=%p target=%p access=0x%08X total=%lu.\n",
                    callerPid, targetPid, desiredAccess, (ULONG)failureCounter);
            }
            SLEEPWALKER_DBG_PRINT(DPFLTR_WARNING_LEVEL,
                                  "SLEEPWALKER[DBG]: RtlWalkFrameChain fault caller=%p target=%p access=0x%08X.\n",
                                  callerPid, targetPid, desiredAccess);
        }
    }

    work->FrameCount = copyCount;

    ExInitializeWorkItem(&work->WorkItem, SLEEPWALKERHandleWorkRoutine, work);
    ExQueueWorkItem(&work->WorkItem, DelayedWorkQueue);
    SLEEPWALKER_DBG_PRINT(DPFLTR_TRACE_LEVEL,
                          "SLEEPWALKER[DBG]: queued handle work caller=%p target=%p access=0x%08X frames=%lu.\n",
                          callerPid, targetPid, desiredAccess, copyCount);

    return OB_PREOP_SUCCESS;
}

NTSTATUS
SLEEPWALKERHandleMonitorInitialize(VOID)
{
    NTSTATUS status;
    LARGE_INTEGER freq;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (g_HandleMonitorRegistered)
    {
        return STATUS_SUCCESS;
    }
    KeInitializeEvent(&g_HandleAllWorkDone, NotificationEvent, TRUE);
    KeInitializeSpinLock(&g_DeepCacheLock);
    RtlZeroMemory(g_DeepCache, sizeof(g_DeepCache));
    InterlockedExchange(&g_DeepCacheWriteIndex, -1);
    freq = KeQueryPerformanceCounter(NULL);
    g_DeepCacheQpcFrequency = (freq.QuadPart > 0) ? (ULONGLONG)freq.QuadPart : 1;
    InterlockedExchange(&g_HandleMonitorStopping, 0);
    InterlockedExchange(&g_HandleOutstandingWork, 0);
    InterlockedExchange(&g_HandleDroppedWork, 0);
    InterlockedExchange(&g_HandleStackCaptureFaults, 0);

    RtlZeroMemory(&g_OperationRegistration, sizeof(g_OperationRegistration));
    g_OperationRegistration[0].ObjectType = PsProcessType;
    g_OperationRegistration[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    g_OperationRegistration[0].PreOperation = SLEEPWALKERProcessPreOperation;
    g_OperationRegistration[0].PostOperation = NULL;

    g_OperationRegistration[1].ObjectType = PsThreadType;
    g_OperationRegistration[1].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    g_OperationRegistration[1].PreOperation = SLEEPWALKERProcessPreOperation;
    g_OperationRegistration[1].PostOperation = NULL;

    RtlZeroMemory(&g_CallbackRegistration, sizeof(g_CallbackRegistration));
    g_CallbackRegistration.Version = OB_FLT_REGISTRATION_VERSION;
    g_CallbackRegistration.OperationRegistrationCount = RTL_NUMBER_OF(g_OperationRegistration);
    g_CallbackRegistration.RegistrationContext = NULL;
    g_CallbackRegistration.OperationRegistration = g_OperationRegistration;
    RtlInitUnicodeString(&g_CallbackAltitude, g_CallbackAltitudeBuffer);
    g_CallbackRegistration.Altitude = g_CallbackAltitude;

    status = ObRegisterCallbacks(&g_CallbackRegistration, &g_ProcessObRegistrationHandle);
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "SLEEPWALKER: ObRegisterCallbacks failed (0x%08X).\n",
                   status);
        return status;
    }

    g_HandleMonitorRegistered = TRUE;
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "SLEEPWALKER: process handle monitor initialized.\n");
    return STATUS_SUCCESS;
}

VOID SLEEPWALKERHandleMonitorUninitialize(VOID)
{
    LARGE_INTEGER waitInterval;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        return;
    }
    if (!g_HandleMonitorRegistered)
    {
        return;
    }

    InterlockedExchange(&g_HandleMonitorStopping, 1);
    if (g_ProcessObRegistrationHandle != NULL)
    {
        ObUnRegisterCallbacks(g_ProcessObRegistrationHandle);
        g_ProcessObRegistrationHandle = NULL;
    }
    g_HandleMonitorRegistered = FALSE;

    waitInterval.QuadPart = -(LONGLONG)1000 * 10000;
    while (InterlockedCompareExchange(&g_HandleOutstandingWork, 0, 0) != 0)
    {
        NTSTATUS waitStatus;

        waitStatus = KeWaitForSingleObject(&g_HandleAllWorkDone, Executive, KernelMode, FALSE, &waitInterval);
        if (waitStatus == STATUS_TIMEOUT)
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                       "SLEEPWALKER: handle monitor draining (outstanding=%ld).\n",
                       InterlockedCompareExchange(&g_HandleOutstandingWork, 0, 0));
        }
    }

    InterlockedExchange(&g_HandleMonitorStopping, 0);
    RtlZeroMemory(g_DeepCache, sizeof(g_DeepCache));
    InterlockedExchange(&g_DeepCacheWriteIndex, -1);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "SLEEPWALKER: process handle monitor uninitialized (dropped=%ld, stackCaptureFaults=%ld).\n",
               InterlockedCompareExchange(&g_HandleDroppedWork, 0, 0),
               InterlockedCompareExchange(&g_HandleStackCaptureFaults, 0, 0));
}

BOOLEAN
SLEEPWALKERHandleMonitorSelfCheck(VOID)
{
    if (!g_HandleMonitorRegistered)
    {
        return FALSE;
    }
    if (g_ProcessObRegistrationHandle == NULL)
    {
        return FALSE;
    }
    if (g_CallbackRegistration.OperationRegistrationCount != RTL_NUMBER_OF(g_OperationRegistration))
    {
        return FALSE;
    }
    if (g_CallbackRegistration.OperationRegistration != g_OperationRegistration)
    {
        return FALSE;
    }
    if (g_OperationRegistration[0].PreOperation != SLEEPWALKERProcessPreOperation ||
        g_OperationRegistration[1].PreOperation != SLEEPWALKERProcessPreOperation)
    {
        return FALSE;
    }
    if (InterlockedCompareExchange(&g_HandleOutstandingWork, 0, 0) < 0)
    {
        return FALSE;
    }

    return TRUE;
}
