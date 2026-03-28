#include <ntddk.h>
#include <ntimage.h>
#include <intrin.h>
#include <ntstrsafe.h>
#include "..\core\control.h"
#include "..\core\protection_utils.h"
#include "..\core\pool_compat.h"
#include "..\core\unicode_utils.h"
#include "..\telemetry\etw.h"
#include "apc_monitor.h"
#include "process_monitor.h"
#include "..\correlation\intent_store.h"
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

#ifndef PROCESS_CREATE_THREAD
#define PROCESS_CREATE_THREAD 0x0002
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

#ifndef THREAD_QUERY_INFORMATION
#define THREAD_QUERY_INFORMATION 0x0040
#endif

#ifndef THREAD_QUERY_LIMITED_INFORMATION
#define THREAD_QUERY_LIMITED_INFORMATION 0x0800
#endif

#ifndef THREAD_ALL_ACCESS
#define THREAD_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xFFFF)
#endif

#define BLACKBIRD_PROTECTED_PROCESS_ALLOWED_ACCESS (PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE)
#define BLACKBIRD_PROTECTED_THREAD_ALLOWED_ACCESS (THREAD_QUERY_LIMITED_INFORMATION | SYNCHRONIZE)

#ifndef MEM_COMMIT
#define MEM_COMMIT 0x00001000
#endif

#ifndef MEM_IMAGE
#define MEM_IMAGE 0x01000000
#endif

#ifndef IMAGE_DIRECTORY_ENTRY_EXPORT
#define IMAGE_DIRECTORY_ENTRY_EXPORT 0
#endif

#ifndef IMAGE_DIRECTORY_ENTRY_EXCEPTION
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION 3
#endif

#ifndef ThreadBasicInformation
#define ThreadBasicInformation ((THREADINFOCLASS)0)
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

typedef struct _BLACKBIRD_THREAD_BASIC_INFORMATION
{
    NTSTATUS ExitStatus;
    PVOID TebBaseAddress;
    CLIENT_ID ClientId;
    KAFFINITY AffinityMask;
    KPRIORITY Priority;
    KPRIORITY BasePriority;
} BLACKBIRD_THREAD_BASIC_INFORMATION, *PBLACKBIRD_THREAD_BASIC_INFORMATION;

typedef struct _BLACKBIRD_NT_TIB
{
    PVOID ExceptionList;
    PVOID StackBase;
    PVOID StackLimit;
    PVOID SubSystemTib;
    PVOID FiberData;
    PVOID ArbitraryUserPointer;
    PVOID Self;
} BLACKBIRD_NT_TIB, *PBLACKBIRD_NT_TIB;

typedef enum _BLACKBIRD_MEMORY_INFORMATION_CLASS
{
    BLACKBIRDMemoryBasicInformation = 0,
    BLACKBIRDMemorySectionName = 2
} BLACKBIRD_MEMORY_INFORMATION_CLASS;

NTSYSAPI NTSTATUS NTAPI ZwQueryVirtualMemory(_In_ HANDLE ProcessHandle, _In_opt_ PVOID BaseAddress,
                                             _In_ BLACKBIRD_MEMORY_INFORMATION_CLASS MemoryInformationClass,
                                             _Out_writes_bytes_(MemoryInformationLength) PVOID MemoryInformation,
                                             _In_ SIZE_T MemoryInformationLength, _Out_opt_ PSIZE_T ReturnLength);
NTSYSAPI NTSTATUS NTAPI ZwOpenThread(_Out_ PHANDLE ThreadHandle, _In_ ACCESS_MASK DesiredAccess,
                                     _In_ POBJECT_ATTRIBUTES ObjectAttributes, _In_ PCLIENT_ID ClientId);
NTSYSAPI NTSTATUS NTAPI ZwQueryInformationThread(_In_ HANDLE ThreadHandle, _In_ THREADINFOCLASS ThreadInformationClass,
                                                 _Out_writes_bytes_(ThreadInformationLength) PVOID ThreadInformation,
                                                 _In_ ULONG ThreadInformationLength, _Out_opt_ PULONG ReturnLength);
NTSYSAPI VOID NTAPI RtlCaptureContext(_Out_ PCONTEXT ContextRecord);

#ifndef RTL_WALK_USER_MODE_STACK
#define RTL_WALK_USER_MODE_STACK 0x00000001
#endif

NTKERNELAPI HANDLE PsGetThreadProcessId(_In_ PETHREAD Thread);
NTKERNELAPI NTSTATUS PsLookupProcessByProcessId(_In_ HANDLE ProcessId, _Outptr_ PEPROCESS *Process);
NTKERNELAPI PCHAR PsGetProcessImageFileName(_In_ PEPROCESS Process);
NTKERNELAPI NTSTATUS MmCopyVirtualMemory(_In_ PEPROCESS FromProcess, _In_ const VOID *FromAddress,
                                         _In_ PEPROCESS ToProcess, _Out_writes_bytes_(BufferSize) PVOID ToAddress,
                                         _In_ SIZE_T BufferSize, _In_ KPROCESSOR_MODE PreviousMode,
                                         _Out_ PSIZE_T NumberOfBytesCopied);

#define BLACKBIRD_HANDLE_MAX_OUTSTANDING_WORK 2048
#define BLACKBIRD_DEEP_CAPTURE_MAX_BYTES 64
#define BLACKBIRD_DEEP_CACHE_RING_SIZE 64
#define BLACKBIRD_DEEP_CACHE_TTL_MS 3000

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

typedef struct _BLACKBIRD_DEEP_CACHE_ENTRY
{
    UINT64 CallerPid;
    UINT64 AllocationBase;
    UINT64 SampleAddress;
    UINT64 RegionSize;
    ULONG RegionProtect;
    ULONG RegionState;
    ULONG RegionType;
    UCHAR Sample[BLACKBIRD_DEEP_CAPTURE_MAX_BYTES];
    UINT32 SampleSize;
    INT64 TimestampQpc;
} BLACKBIRD_DEEP_CACHE_ENTRY, *PBLACKBIRD_DEEP_CACHE_ENTRY;

static BLACKBIRD_DEEP_CACHE_ENTRY g_DeepCache[BLACKBIRD_DEEP_CACHE_RING_SIZE];

/*
 * Hot-path debug tracing is disabled by default to prevent KD console flooding.
 * Define BLACKBIRD_VERBOSE_HOTPATH_DEBUG=1 for local deep diagnostics.
 */
#if !defined(BLACKBIRD_VERBOSE_HOTPATH_DEBUG)
#define BLACKBIRD_VERBOSE_HOTPATH_DEBUG 0
#endif

#if defined(DBG) && DBG && BLACKBIRD_VERBOSE_HOTPATH_DEBUG
#define BLACKBIRD_DBG_PRINT(_level, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, (_level), __VA_ARGS__)
#else
#define BLACKBIRD_DBG_PRINT(_level, ...) ((void)0)
#endif

typedef struct _BLACKBIRD_HANDLE_WORK
{
    WORK_QUEUE_ITEM WorkItem;
    HANDLE CallerPid;
    HANDLE CallerTid;
    HANDLE TargetPid;
    ACCESS_MASK DesiredAccess;
    BOOLEAN IsThreadObject;
    BOOLEAN IsDuplicateOperation;
    UINT32 CaptureFlags;
    ULONG FrameCount;
    PVOID Frames[8];
    ULONG FullFrameCount;
    PVOID FullFrames[BLACKBIRD_MAX_FULL_EVENT_FRAMES];
    UINT64 RegRax;
    UINT64 RegRbx;
    UINT64 RegRcx;
    UINT64 RegRdx;
    UINT64 RegRsi;
    UINT64 RegRdi;
    UINT64 RegRbp;
    UINT64 RegRsp;
    UINT64 RegR8;
    UINT64 RegR9;
    UINT64 RegR10;
    UINT64 RegR11;
    UINT64 RegR12;
    UINT64 RegR13;
    UINT64 RegR14;
    UINT64 RegR15;
    UINT64 RegRip;
    UINT64 RegEFlags;
    UINT64 RegDr0;
    UINT64 RegDr1;
    UINT64 RegDr2;
    UINT64 RegDr3;
    UINT64 RegDr6;
    UINT64 RegDr7;
    UINT64 EarlyOriginAddress;
    ULONG EarlyOriginSampleSize;
    UCHAR EarlyOriginSample[BLACKBIRD_DEEP_CAPTURE_MAX_BYTES];
} BLACKBIRD_HANDLE_WORK, *PBLACKBIRD_HANDLE_WORK;

typedef enum _BLACKBIRD_HANDLE_CLASSIFICATION
{
    BLACKBIRDHandleUnknown = 0,
    BLACKBIRDHandleLegitimateSyscall,
    BLACKBIRDHandleDirectSyscallSuspect
} BLACKBIRD_HANDLE_CLASSIFICATION;

typedef struct _BLACKBIRD_HANDLE_TELEMETRY
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
    UCHAR DeepSample[BLACKBIRD_DEEP_CAPTURE_MAX_BYTES];
    BOOLEAN DeepPathCandidate;
    BOOLEAN DeepPathCaptured;
    BOOLEAN DeepPathCacheHit;
    BOOLEAN ReturnAddressValid;
    BOOLEAN StackValidated;
    BOOLEAN StackSpoofSuspect;
    BOOLEAN SyscallExportChecked;
    BOOLEAN SyscallExportMatch;
    BOOLEAN ModuleChainChecked;
    BOOLEAN ModuleChainSane;
    BOOLEAN UnwindMetadataChecked;
    BOOLEAN UnwindMetadataValid;
    BOOLEAN TebStackBoundsChecked;
    BOOLEAN TebStackBoundsValid;
    BOOLEAN FramesOutsideTebStack;
    UINT32 CaptureFlags;
    ULONG FullFrameCount;
    PVOID FullFrames[BLACKBIRD_MAX_FULL_EVENT_FRAMES];
    UINT64 RegRax;
    UINT64 RegRbx;
    UINT64 RegRcx;
    UINT64 RegRdx;
    UINT64 RegRsi;
    UINT64 RegRdi;
    UINT64 RegRbp;
    UINT64 RegRsp;
    UINT64 RegR8;
    UINT64 RegR9;
    UINT64 RegR10;
    UINT64 RegR11;
    UINT64 RegR12;
    UINT64 RegR13;
    UINT64 RegR14;
    UINT64 RegR15;
    UINT64 RegRip;
    UINT64 RegEFlags;
    UINT64 RegDr0;
    UINT64 RegDr1;
    UINT64 RegDr2;
    UINT64 RegDr3;
    UINT64 RegDr6;
    UINT64 RegDr7;
    UINT64 StackSnapshotAddress;
    ULONG StackSnapshotSize;
    UCHAR StackSnapshot[BLACKBIRD_MAX_STACK_SNAPSHOT_BYTES];
} BLACKBIRD_HANDLE_TELEMETRY, *PBLACKBIRD_HANDLE_TELEMETRY;

static VOID BLACKBIRDCaptureRegisterSnapshot(_Out_ PBLACKBIRD_HANDLE_WORK Work)
{
#if defined(_M_AMD64)
    CONTEXT context;

    if (Work == NULL)
    {
        return;
    }

    RtlZeroMemory(&context, sizeof(context));
    // Snapshot the callback-time CPU state as forensic context without suspending the caller thread.
    RtlCaptureContext(&context);

    Work->RegRax = context.Rax;
    Work->RegRbx = context.Rbx;
    Work->RegRcx = context.Rcx;
    Work->RegRdx = context.Rdx;
    Work->RegRsi = context.Rsi;
    Work->RegRdi = context.Rdi;
    Work->RegRbp = context.Rbp;
    Work->RegRsp = context.Rsp;
    Work->RegR8 = context.R8;
    Work->RegR9 = context.R9;
    Work->RegR10 = context.R10;
    Work->RegR11 = context.R11;
    Work->RegR12 = context.R12;
    Work->RegR13 = context.R13;
    Work->RegR14 = context.R14;
    Work->RegR15 = context.R15;
    Work->RegRip = context.Rip;
    Work->RegEFlags = context.EFlags;
    Work->CaptureFlags |= BLACKBIRD_HANDLE_CAPTURE_CONTEXT_VALID;

    __try
    {
        Work->RegDr0 = __readdr(0);
        Work->RegDr1 = __readdr(1);
        Work->RegDr2 = __readdr(2);
        Work->RegDr3 = __readdr(3);
        Work->RegDr6 = __readdr(6);
        Work->RegDr7 = __readdr(7);
        Work->CaptureFlags |= BLACKBIRD_HANDLE_CAPTURE_DEBUG_REGS_VALID;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
    }
#else
    UNREFERENCED_PARAMETER(Work);
#endif
}

static VOID BLACKBIRDApplyWorkCaptureToTelemetry(_In_opt_ const BLACKBIRD_HANDLE_WORK *Work,
                                                 _Inout_ PBLACKBIRD_HANDLE_TELEMETRY Telemetry)
{
    ULONG safeFullCount;

    if (Work == NULL || Telemetry == NULL)
    {
        return;
    }

    Telemetry->CaptureFlags = Work->CaptureFlags;

    safeFullCount = (Work->FullFrameCount > RTL_NUMBER_OF(Telemetry->FullFrames)) ? RTL_NUMBER_OF(Telemetry->FullFrames)
                                                                                  : Work->FullFrameCount;
    Telemetry->FullFrameCount = safeFullCount;
    if (safeFullCount != 0)
    {
        RtlCopyMemory(Telemetry->FullFrames, Work->FullFrames, safeFullCount * sizeof(PVOID));
        Telemetry->CaptureFlags |= BLACKBIRD_HANDLE_CAPTURE_FULL_FRAMES_VALID;
    }

    Telemetry->RegRax = Work->RegRax;
    Telemetry->RegRbx = Work->RegRbx;
    Telemetry->RegRcx = Work->RegRcx;
    Telemetry->RegRdx = Work->RegRdx;
    Telemetry->RegRsi = Work->RegRsi;
    Telemetry->RegRdi = Work->RegRdi;
    Telemetry->RegRbp = Work->RegRbp;
    Telemetry->RegRsp = Work->RegRsp;
    Telemetry->RegR8 = Work->RegR8;
    Telemetry->RegR9 = Work->RegR9;
    Telemetry->RegR10 = Work->RegR10;
    Telemetry->RegR11 = Work->RegR11;
    Telemetry->RegR12 = Work->RegR12;
    Telemetry->RegR13 = Work->RegR13;
    Telemetry->RegR14 = Work->RegR14;
    Telemetry->RegR15 = Work->RegR15;
    Telemetry->RegRip = Work->RegRip;
    Telemetry->RegEFlags = Work->RegEFlags;
    Telemetry->RegDr0 = Work->RegDr0;
    Telemetry->RegDr1 = Work->RegDr1;
    Telemetry->RegDr2 = Work->RegDr2;
    Telemetry->RegDr3 = Work->RegDr3;
    Telemetry->RegDr6 = Work->RegDr6;
    Telemetry->RegDr7 = Work->RegDr7;
}

static VOID BLACKBIRDCaptureStackSnapshot(_In_ PEPROCESS SourceProcess, _In_ UINT64 StackPointer,
                                          _Inout_ PBLACKBIRD_HANDLE_TELEMETRY Telemetry)
{
    NTSTATUS status;
    SIZE_T bytesRead = 0;
    PEPROCESS localProcess;

    if (SourceProcess == NULL || Telemetry == NULL || StackPointer == 0)
    {
        return;
    }

    localProcess = PsGetCurrentProcess();
    status = MmCopyVirtualMemory(SourceProcess, (PVOID)(ULONG_PTR)StackPointer, localProcess, Telemetry->StackSnapshot,
                                 sizeof(Telemetry->StackSnapshot), KernelMode, &bytesRead);
    if (!NT_SUCCESS(status) || bytesRead == 0)
    {
        return;
    }

    if (bytesRead > RTL_NUMBER_OF(Telemetry->StackSnapshot))
    {
        bytesRead = RTL_NUMBER_OF(Telemetry->StackSnapshot);
    }

    Telemetry->StackSnapshotAddress = StackPointer;
    Telemetry->StackSnapshotSize = (ULONG)bytesRead;
    Telemetry->CaptureFlags |= BLACKBIRD_HANDLE_CAPTURE_STACK_SNAPSHOT_VALID;
}

static BOOLEAN BLACKBIRDHandleTryAcquireWorkSlot(VOID)
{
    LONG current;

    for (;;)
    {
        current = InterlockedCompareExchange(&g_HandleOutstandingWork, 0, 0);
        if (current >= BLACKBIRD_HANDLE_MAX_OUTSTANDING_WORK)
        {
            InterlockedIncrement(&g_HandleDroppedWork);
            BLACKBIRD_DBG_PRINT(DPFLTR_WARNING_LEVEL, "BLACKBIRD[DBG]: handle monitor work queue full (max=%lu).\n",
                                BLACKBIRD_HANDLE_MAX_OUTSTANDING_WORK);
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

static VOID BLACKBIRDHandleReleaseWorkSlot(VOID)
{
    if (InterlockedDecrement(&g_HandleOutstandingWork) == 0)
    {
        KeSetEvent(&g_HandleAllWorkDone, IO_NO_INCREMENT, FALSE);
    }
}

static ULONGLONG BLACKBIRDDeepCacheMsToQpc(_In_ UINT32 Ms)
{
    ULONGLONG ticks;

    if (Ms == 0)
    {
        return 0;
    }

    ticks = ((ULONGLONG)Ms * g_DeepCacheQpcFrequency) / 1000ULL;
    return (ticks == 0) ? 1 : ticks;
}

static BOOLEAN BLACKBIRDDeepCacheLookup(_In_ HANDLE CallerPid, _In_ PVOID AllocationBase, _In_ PVOID SampleAddress,
                                        _In_ SIZE_T RegionSize, _In_ ULONG RegionProtect, _In_ ULONG RegionState,
                                        _In_ ULONG RegionType,
                                        _Out_writes_bytes_(BLACKBIRD_DEEP_CAPTURE_MAX_BYTES) UCHAR *Sample,
                                        _Out_ UINT32 *SampleSize)
{
    KIRQL oldIrql;
    UINT32 i;
    INT64 nowQpc;
    ULONGLONG maxAgeQpc;

    if (Sample == NULL || SampleSize == NULL || AllocationBase == NULL || SampleAddress == NULL || RegionSize == 0)
    {
        return FALSE;
    }

    nowQpc = KeQueryPerformanceCounter(NULL).QuadPart;
    maxAgeQpc = BLACKBIRDDeepCacheMsToQpc(BLACKBIRD_DEEP_CACHE_TTL_MS);
    KeAcquireSpinLock(&g_DeepCacheLock, &oldIrql);
    for (i = 0; i < RTL_NUMBER_OF(g_DeepCache); ++i)
    {
        const BLACKBIRD_DEEP_CACHE_ENTRY *e = &g_DeepCache[i];
        INT64 ageQpc;
        UINT32 safeSize;

        if (e->TimestampQpc == 0)
        {
            continue;
        }
        if (e->CallerPid != (UINT64)(ULONG_PTR)CallerPid || e->AllocationBase != (UINT64)(ULONG_PTR)AllocationBase ||
            e->SampleAddress != (UINT64)(ULONG_PTR)SampleAddress || e->RegionSize != (UINT64)RegionSize ||
            e->RegionProtect != RegionProtect || e->RegionState != RegionState || e->RegionType != RegionType)
        {
            continue;
        }

        ageQpc = nowQpc - e->TimestampQpc;
        if (ageQpc < 0 || (ULONGLONG)ageQpc > maxAgeQpc)
        {
            continue;
        }

        safeSize =
            (e->SampleSize > BLACKBIRD_DEEP_CAPTURE_MAX_BYTES) ? BLACKBIRD_DEEP_CAPTURE_MAX_BYTES : e->SampleSize;
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

static VOID BLACKBIRDDeepCacheStore(_In_ HANDLE CallerPid, _In_ PVOID AllocationBase, _In_ PVOID SampleAddress,
                                    _In_ SIZE_T RegionSize, _In_ ULONG RegionProtect, _In_ ULONG RegionState,
                                    _In_ ULONG RegionType, _In_reads_bytes_(SampleSize) const UCHAR *Sample,
                                    _In_ UINT32 SampleSize)
{
    LONG idx;
    UINT32 slot;
    KIRQL oldIrql;
    UINT32 safeSize;

    if (AllocationBase == NULL || SampleAddress == NULL || RegionSize == 0 || Sample == NULL || SampleSize == 0)
    {
        return;
    }

    safeSize = (SampleSize > BLACKBIRD_DEEP_CAPTURE_MAX_BYTES) ? BLACKBIRD_DEEP_CAPTURE_MAX_BYTES : SampleSize;

    idx = InterlockedIncrement(&g_DeepCacheWriteIndex);
    if (idx < 0)
    {
        idx = 0;
    }
    slot = (UINT32)idx % RTL_NUMBER_OF(g_DeepCache);

    KeAcquireSpinLock(&g_DeepCacheLock, &oldIrql);
    g_DeepCache[slot].CallerPid = (UINT64)(ULONG_PTR)CallerPid;
    g_DeepCache[slot].AllocationBase = (UINT64)(ULONG_PTR)AllocationBase;
    g_DeepCache[slot].SampleAddress = (UINT64)(ULONG_PTR)SampleAddress;
    g_DeepCache[slot].RegionSize = (UINT64)RegionSize;
    g_DeepCache[slot].RegionProtect = RegionProtect;
    g_DeepCache[slot].RegionState = RegionState;
    g_DeepCache[slot].RegionType = RegionType;
    g_DeepCache[slot].SampleSize = safeSize;
    RtlCopyMemory(g_DeepCache[slot].Sample, Sample, safeSize);
    g_DeepCache[slot].TimestampQpc = KeQueryPerformanceCounter(NULL).QuadPart;
    KeReleaseSpinLock(&g_DeepCacheLock, oldIrql);
}

static BOOLEAN BLACKBIRDReadProcessBytes(_In_ PEPROCESS SourceProcess, _In_ const VOID *Address,
                                         _Out_writes_bytes_(Size) VOID *Buffer, _In_ SIZE_T Size)
{
    NTSTATUS status;
    SIZE_T bytesRead = 0;
    PEPROCESS localProcess;

    if (SourceProcess == NULL || Address == NULL || Buffer == NULL || Size == 0)
    {
        return FALSE;
    }

    localProcess = PsGetCurrentProcess();
    status = MmCopyVirtualMemory(SourceProcess, Address, localProcess, Buffer, Size, KernelMode, &bytesRead);
    return NT_SUCCESS(status) && bytesRead == Size;
}

static VOID BLACKBIRDCaptureImmediateOriginSample(_In_ HANDLE CallerProcessId, _In_ PVOID OriginAddress,
                                                  _Inout_ PBLACKBIRD_HANDLE_WORK Work)
{
    NTSTATUS status;
    PEPROCESS sourceProcess = NULL;
    PEPROCESS localProcess;
    SIZE_T bytesRead = 0;

    if (CallerProcessId == NULL || OriginAddress == NULL || Work == NULL)
    {
        return;
    }

    status = PsLookupProcessByProcessId(CallerProcessId, &sourceProcess);
    if (!NT_SUCCESS(status))
    {
        return;
    }

    localProcess = PsGetCurrentProcess();
    status = MmCopyVirtualMemory(sourceProcess, OriginAddress, localProcess, Work->EarlyOriginSample,
                                 sizeof(Work->EarlyOriginSample), KernelMode, &bytesRead);
    ObDereferenceObject(sourceProcess);
    if (!NT_SUCCESS(status) || bytesRead == 0)
    {
        return;
    }

    if (bytesRead > sizeof(Work->EarlyOriginSample))
    {
        bytesRead = sizeof(Work->EarlyOriginSample);
    }

    Work->EarlyOriginAddress = (UINT64)(ULONG_PTR)OriginAddress;
    Work->EarlyOriginSampleSize = (ULONG)bytesRead;
}

static CHAR BLACKBIRDAsciiUpper(_In_ CHAR Value)
{
    if (Value >= 'a' && Value <= 'z')
    {
        return (CHAR)(Value - ('a' - 'A'));
    }
    return Value;
}

static BOOLEAN BLACKBIRDAsciiEqualsInsensitive(_In_z_ const CHAR *Left, _In_z_ const CHAR *Right)
{
    SIZE_T i;

    if (Left == NULL || Right == NULL)
    {
        return FALSE;
    }

    for (i = 0;; ++i)
    {
        CHAR a = BLACKBIRDAsciiUpper(Left[i]);
        CHAR b = BLACKBIRDAsciiUpper(Right[i]);
        if (a != b)
        {
            return FALSE;
        }
        if (a == '\0')
        {
            return TRUE;
        }
    }
}

static BOOLEAN BLACKBIRDExtractSyscallNumberNearAddress(_In_ PEPROCESS SourceProcess, _In_ const VOID *Address,
                                                        _Out_ ULONG *SyscallNumber)
{
    UCHAR bytes[64];
    ULONG_PTR base;
    SIZE_T readLen;
    SIZE_T offsetIntoRead;
    SIZE_T i;
    BOOLEAN found = FALSE;
    ULONG foundValue = 0;
    SIZE_T bestDistance = (SIZE_T)-1;

    if (SourceProcess == NULL || Address == NULL || SyscallNumber == NULL)
    {
        return FALSE;
    }

    base = (ULONG_PTR)Address;
    if (base < 32)
    {
        return FALSE;
    }

    base -= 32;
    readLen = sizeof(bytes);
    if (!BLACKBIRDReadProcessBytes(SourceProcess, (const VOID *)base, bytes, readLen))
    {
        return FALSE;
    }

    offsetIntoRead = (SIZE_T)((ULONG_PTR)Address - base);
    for (i = 0; i + 7 < readLen; ++i)
    {
        ULONG extracted;
        SIZE_T j;

        if (bytes[i] != 0xB8)
        {
            continue;
        }

        RtlCopyMemory(&extracted, &bytes[i + 1], sizeof(extracted));
        for (j = i + 5; j + 1 < readLen && j <= i + 12; ++j)
        {
            SIZE_T distance;

            if (bytes[j] != 0x0F || bytes[j + 1] != 0x05)
            {
                continue;
            }
            if (j > offsetIntoRead + 1)
            {
                continue;
            }

            distance = offsetIntoRead - j;
            if (distance < bestDistance)
            {
                bestDistance = distance;
                found = TRUE;
                foundValue = extracted;
            }
        }
    }

    if (!found)
    {
        return FALSE;
    }

    *SyscallNumber = foundValue;
    return TRUE;
}

static BOOLEAN BLACKBIRDValidateReturnAddress(_In_ PEPROCESS SourceProcess, _In_ PVOID ReturnAddress)
{
    UCHAR tail[8];
    ULONG_PTR addrValue;

    if (SourceProcess == NULL || ReturnAddress == NULL)
    {
        return FALSE;
    }

    addrValue = (ULONG_PTR)ReturnAddress;
    if (addrValue < sizeof(tail))
    {
        return FALSE;
    }

    if (!BLACKBIRDReadProcessBytes(SourceProcess, (const VOID *)(addrValue - sizeof(tail)), tail, sizeof(tail)))
    {
        return FALSE;
    }

    if (tail[3] == 0xE8)
    {
        return TRUE;
    }
    if (tail[6] == 0xFF && ((tail[7] & 0x38) == 0x10))
    {
        return TRUE;
    }

    return FALSE;
}

static BOOLEAN BLACKBIRDValidateStackFrames(_In_ HANDLE ProcessHandle, _In_ ULONG FrameCount,
                                            _In_reads_(FrameCount) PVOID *Frames, _Out_ BOOLEAN *SpoofSuspect)
{
    ULONG i;
    PVOID priorFrame = NULL;

    if (SpoofSuspect != NULL)
    {
        *SpoofSuspect = FALSE;
    }

    if (ProcessHandle == NULL || Frames == NULL || FrameCount == 0)
    {
        return FALSE;
    }

    for (i = 0; i < FrameCount; ++i)
    {
        MEMORY_BASIC_INFORMATION mbi;
        NTSTATUS status;
        PVOID frame = Frames[i];
        BOOLEAN execProtect;

        if (frame == NULL || (ULONG_PTR)frame < 0x10000)
        {
            return FALSE;
        }
        if (frame == priorFrame)
        {
            return FALSE;
        }

        RtlZeroMemory(&mbi, sizeof(mbi));
        status = ZwQueryVirtualMemory(ProcessHandle, frame, BLACKBIRDMemoryBasicInformation, &mbi, sizeof(mbi), NULL);
        if (!NT_SUCCESS(status))
        {
            return FALSE;
        }

        execProtect = BLACKBIRDIsExecutableProtection(mbi.Protect);
        if (mbi.State != MEM_COMMIT || !execProtect)
        {
            return FALSE;
        }

        if (mbi.Type != MEM_IMAGE && SpoofSuspect != NULL)
        {
            *SpoofSuspect = TRUE;
        }

        priorFrame = frame;
    }

    return TRUE;
}

static PCSTR BLACKBIRDGetExpectedSyscallExport(_In_ BOOLEAN IsThreadObject, _In_ BOOLEAN IsDuplicateOperation)
{
    if (IsDuplicateOperation)
    {
        return "NtDuplicateObject";
    }
    if (IsThreadObject)
    {
        return "NtOpenThread";
    }
    return "NtOpenProcess";
}

static BOOLEAN BLACKBIRDIsNtdllPath(_In_ const UNICODE_STRING *Path)
{
    if (Path == NULL || Path->Buffer == NULL || Path->Length == 0)
    {
        return FALSE;
    }

    return BLACKBIRDUnicodeContainsInsensitive(Path, L"ntdll.dll", 9);
}

static BOOLEAN BLACKBIRDIsSyscallStubModulePath(_In_ const UNICODE_STRING *Path)
{
    if (Path == NULL || Path->Buffer == NULL || Path->Length == 0)
    {
        return FALSE;
    }

    if (BLACKBIRDIsNtdllPath(Path))
    {
        return TRUE;
    }

    return BLACKBIRDUnicodeContainsInsensitive(Path, L"win32u.dll", 10);
}

static BOOLEAN BLACKBIRDGetNtdllBaseFromFrames(_In_ HANDLE ProcessHandle, _In_ ULONG FrameCount,
                                               _In_reads_(FrameCount) PVOID *Frames, _Out_ PVOID *NtdllBase)
{
    ULONG i;
    WCHAR sectionPath[512];

    if (NtdllBase == NULL)
    {
        return FALSE;
    }
    *NtdllBase = NULL;

    if (ProcessHandle == NULL || Frames == NULL || FrameCount == 0)
    {
        return FALSE;
    }

    for (i = 0; i < FrameCount; ++i)
    {
        MEMORY_BASIC_INFORMATION mbi;
        UCHAR sectionNameRaw[1024];
        PUNICODE_STRING sectionName;
        UNICODE_STRING sectionUs;
        NTSTATUS status;

        if (Frames[i] == NULL)
        {
            continue;
        }

        RtlZeroMemory(&mbi, sizeof(mbi));
        status =
            ZwQueryVirtualMemory(ProcessHandle, Frames[i], BLACKBIRDMemoryBasicInformation, &mbi, sizeof(mbi), NULL);
        if (!NT_SUCCESS(status) || mbi.AllocationBase == NULL)
        {
            continue;
        }

        RtlZeroMemory(sectionNameRaw, sizeof(sectionNameRaw));
        status = ZwQueryVirtualMemory(ProcessHandle, Frames[i], BLACKBIRDMemorySectionName, sectionNameRaw,
                                      sizeof(sectionNameRaw), NULL);
        if (!NT_SUCCESS(status))
        {
            continue;
        }

        sectionName = (PUNICODE_STRING)sectionNameRaw;
        RtlZeroMemory(sectionPath, sizeof(sectionPath));
        BLACKBIRDSafeCopyUnicode(sectionName, sectionPath, RTL_NUMBER_OF(sectionPath));
        RtlInitUnicodeString(&sectionUs, sectionPath);
        if (!BLACKBIRDIsNtdllPath(&sectionUs))
        {
            continue;
        }

        *NtdllBase = mbi.AllocationBase;
        return TRUE;
    }

    return FALSE;
}

static BOOLEAN BLACKBIRDResolveExportSyscallNumber(_In_ PEPROCESS SourceProcess, _In_ PVOID ModuleBase,
                                                   _In_z_ PCSTR ExportName, _Out_ ULONG *SyscallNumber)
{
    IMAGE_DOS_HEADER dos;
    IMAGE_NT_HEADERS64 nt;
    IMAGE_EXPORT_DIRECTORY exports;
    ULONG namesSize;
    ULONG ordinalsSize;
    ULONG funcsSize;
    ULONG *nameRvas = NULL;
    USHORT *ordinals = NULL;
    ULONG *funcRvas = NULL;
    ULONG i;
    BOOLEAN success = FALSE;

    if (SourceProcess == NULL || ModuleBase == NULL || ExportName == NULL || SyscallNumber == NULL)
    {
        return FALSE;
    }

    if (!BLACKBIRDReadProcessBytes(SourceProcess, ModuleBase, &dos, sizeof(dos)))
    {
        goto Exit;
    }
    if (dos.e_magic != IMAGE_DOS_SIGNATURE)
    {
        goto Exit;
    }
    if (dos.e_lfanew <= 0 || dos.e_lfanew > 0x2000)
    {
        goto Exit;
    }

    if (!BLACKBIRDReadProcessBytes(SourceProcess, (const VOID *)((ULONG_PTR)ModuleBase + (ULONG_PTR)dos.e_lfanew), &nt,
                                   sizeof(nt)))
    {
        goto Exit;
    }
    if (nt.Signature != IMAGE_NT_SIGNATURE || nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        goto Exit;
    }
    if (nt.OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXPORT)
    {
        goto Exit;
    }
    if (nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0 ||
        nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size < sizeof(exports))
    {
        goto Exit;
    }

    if (!BLACKBIRDReadProcessBytes(
            SourceProcess,
            (const VOID *)((ULONG_PTR)ModuleBase +
                           nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress),
            &exports, sizeof(exports)))
    {
        goto Exit;
    }

    if (exports.NumberOfNames == 0 || exports.NumberOfFunctions == 0 || exports.AddressOfNames == 0 ||
        exports.AddressOfNameOrdinals == 0 || exports.AddressOfFunctions == 0 || exports.NumberOfNames > 8192 ||
        exports.NumberOfFunctions > 8192)
    {
        goto Exit;
    }

    namesSize = exports.NumberOfNames * sizeof(ULONG);
    ordinalsSize = exports.NumberOfNames * sizeof(USHORT);
    funcsSize = exports.NumberOfFunctions * sizeof(ULONG);

    nameRvas = (ULONG *)BLACKBIRDAllocatePoolCompat(POOL_FLAG_PAGED, namesSize, 'ndtT');
    ordinals = (USHORT *)BLACKBIRDAllocatePoolCompat(POOL_FLAG_PAGED, ordinalsSize, 'odtT');
    funcRvas = (ULONG *)BLACKBIRDAllocatePoolCompat(POOL_FLAG_PAGED, funcsSize, 'fdtT');
    if (nameRvas == NULL || ordinals == NULL || funcRvas == NULL)
    {
        goto Exit;
    }

    if (!BLACKBIRDReadProcessBytes(SourceProcess, (const VOID *)((ULONG_PTR)ModuleBase + exports.AddressOfNames),
                                   nameRvas, namesSize) ||
        !BLACKBIRDReadProcessBytes(SourceProcess, (const VOID *)((ULONG_PTR)ModuleBase + exports.AddressOfNameOrdinals),
                                   ordinals, ordinalsSize) ||
        !BLACKBIRDReadProcessBytes(SourceProcess, (const VOID *)((ULONG_PTR)ModuleBase + exports.AddressOfFunctions),
                                   funcRvas, funcsSize))
    {
        goto Exit;
    }

    for (i = 0; i < exports.NumberOfNames; ++i)
    {
        CHAR nameBuffer[64];
        SIZE_T j;
        USHORT ordinal;
        ULONG funcRva;
        PVOID funcAddress;

        if (nameRvas[i] == 0)
        {
            continue;
        }

        RtlZeroMemory(nameBuffer, sizeof(nameBuffer));
        if (!BLACKBIRDReadProcessBytes(SourceProcess, (const VOID *)((ULONG_PTR)ModuleBase + nameRvas[i]), nameBuffer,
                                       sizeof(nameBuffer) - 1))
        {
            continue;
        }

        for (j = 0; j < sizeof(nameBuffer); ++j)
        {
            if (nameBuffer[j] == '\0')
            {
                break;
            }
        }
        if (j == sizeof(nameBuffer))
        {
            continue;
        }
        if (!BLACKBIRDAsciiEqualsInsensitive(nameBuffer, ExportName))
        {
            continue;
        }

        ordinal = ordinals[i];
        if (ordinal >= exports.NumberOfFunctions)
        {
            break;
        }

        funcRva = funcRvas[ordinal];
        if (funcRva == 0)
        {
            break;
        }
        funcAddress = (PVOID)((ULONG_PTR)ModuleBase + funcRva);
        success = BLACKBIRDExtractSyscallNumberNearAddress(SourceProcess, funcAddress, SyscallNumber);
        break;
    }

Exit:
    if (funcRvas != NULL)
    {
        ExFreePoolWithTag(funcRvas, 'fdtT');
    }
    if (ordinals != NULL)
    {
        ExFreePoolWithTag(ordinals, 'odtT');
    }
    if (nameRvas != NULL)
    {
        ExFreePoolWithTag(nameRvas, 'ndtT');
    }

    return success;
}

static BOOLEAN BLACKBIRDQueryFrameModuleInfo(_In_ HANDLE ProcessHandle, _In_ PVOID Frame, _Out_ PVOID *AllocationBase,
                                             _Out_ BOOLEAN *Executable, _Out_ BOOLEAN *ImageBacked,
                                             _Out_ BOOLEAN *IsSyscallStubModule)
{
    MEMORY_BASIC_INFORMATION mbi;
    UCHAR sectionNameRaw[1024];
    PUNICODE_STRING sectionName;
    WCHAR sectionPath[512];
    UNICODE_STRING sectionUs;
    NTSTATUS status;

    if (ProcessHandle == NULL || Frame == NULL || AllocationBase == NULL || Executable == NULL || ImageBacked == NULL ||
        IsSyscallStubModule == NULL)
    {
        return FALSE;
    }

    *AllocationBase = NULL;
    *Executable = FALSE;
    *ImageBacked = FALSE;
    *IsSyscallStubModule = FALSE;

    RtlZeroMemory(&mbi, sizeof(mbi));
    status = ZwQueryVirtualMemory(ProcessHandle, Frame, BLACKBIRDMemoryBasicInformation, &mbi, sizeof(mbi), NULL);
    if (!NT_SUCCESS(status))
    {
        return FALSE;
    }

    *AllocationBase = mbi.AllocationBase;
    *Executable = (mbi.State == MEM_COMMIT) && BLACKBIRDIsExecutableProtection(mbi.Protect);
    *ImageBacked = (mbi.Type == MEM_IMAGE);
    if (mbi.AllocationBase == NULL)
    {
        return TRUE;
    }

    RtlZeroMemory(sectionNameRaw, sizeof(sectionNameRaw));
    status = ZwQueryVirtualMemory(ProcessHandle, Frame, BLACKBIRDMemorySectionName, sectionNameRaw,
                                  sizeof(sectionNameRaw), NULL);
    if (!NT_SUCCESS(status))
    {
        return TRUE;
    }

    sectionName = (PUNICODE_STRING)sectionNameRaw;
    RtlZeroMemory(sectionPath, sizeof(sectionPath));
    BLACKBIRDSafeCopyUnicode(sectionName, sectionPath, RTL_NUMBER_OF(sectionPath));
    RtlInitUnicodeString(&sectionUs, sectionPath);
    *IsSyscallStubModule = BLACKBIRDIsSyscallStubModulePath(&sectionUs);
    return TRUE;
}

static BOOLEAN BLACKBIRDValidateModuleChainSanity(_In_ HANDLE ProcessHandle, _In_ ULONG FrameCount,
                                                  _In_reads_(FrameCount) PVOID *Frames)
{
    ULONG i;
    ULONG inspectCount;
    BOOLEAN sawSyscallStubModule = FALSE;
    BOOLEAN sawHeadSyscallStubModule = FALSE;
    BOOLEAN sawNonSyscallStubModule = FALSE;
    PVOID syscallStubModuleBase = NULL;

    if (ProcessHandle == NULL || Frames == NULL || FrameCount == 0)
    {
        return FALSE;
    }

    inspectCount = (FrameCount > 6U) ? 6U : FrameCount;
    for (i = 0; i < inspectCount; ++i)
    {
        PVOID frameBase;
        BOOLEAN exec;
        BOOLEAN image;
        BOOLEAN isSyscallStubModule;

        if (!BLACKBIRDQueryFrameModuleInfo(ProcessHandle, Frames[i], &frameBase, &exec, &image, &isSyscallStubModule))
        {
            return FALSE;
        }
        if (!exec || !image || frameBase == NULL)
        {
            return FALSE;
        }

        if (isSyscallStubModule)
        {
            sawSyscallStubModule = TRUE;
            if (i <= 2U)
            {
                sawHeadSyscallStubModule = TRUE;
            }
            if (syscallStubModuleBase == NULL)
            {
                syscallStubModuleBase = frameBase;
            }
            else if (syscallStubModuleBase != frameBase)
            {
                return FALSE;
            }
        }
        else
        {
            sawNonSyscallStubModule = TRUE;
        }
    }

    return (sawSyscallStubModule && sawHeadSyscallStubModule && sawNonSyscallStubModule);
}

static BOOLEAN BLACKBIRDModuleContainsUnwindForRva(_In_ PEPROCESS SourceProcess, _In_ PVOID ModuleBase, _In_ ULONG Rva)
{
    IMAGE_DOS_HEADER dos;
    IMAGE_NT_HEADERS64 nt;
    ULONG exceptionRva;
    ULONG exceptionSize;
    ULONG count;
    SIZE_T tableBytes;
    IMAGE_RUNTIME_FUNCTION_ENTRY *table = NULL;
    LONG low;
    LONG high;
    BOOLEAN found = FALSE;

    if (SourceProcess == NULL || ModuleBase == NULL)
    {
        return FALSE;
    }

    if (!BLACKBIRDReadProcessBytes(SourceProcess, ModuleBase, &dos, sizeof(dos)) ||
        dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew <= 0 || dos.e_lfanew > 0x2000)
    {
        return FALSE;
    }

    if (!BLACKBIRDReadProcessBytes(SourceProcess, (const VOID *)((ULONG_PTR)ModuleBase + (ULONG_PTR)dos.e_lfanew), &nt,
                                   sizeof(nt)) ||
        nt.Signature != IMAGE_NT_SIGNATURE || nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
        nt.OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXCEPTION)
    {
        return FALSE;
    }

    exceptionRva = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;
    exceptionSize = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size;
    if (exceptionRva == 0 || exceptionSize < sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY))
    {
        return FALSE;
    }

    count = exceptionSize / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY);
    if (count == 0 || count > 65536)
    {
        return FALSE;
    }

    tableBytes = (SIZE_T)count * sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY);
    table = (IMAGE_RUNTIME_FUNCTION_ENTRY *)BLACKBIRDAllocatePoolCompat(POOL_FLAG_PAGED, tableBytes, 'udtT');
    if (table == NULL)
    {
        return FALSE;
    }

    if (!BLACKBIRDReadProcessBytes(SourceProcess, (const VOID *)((ULONG_PTR)ModuleBase + exceptionRva), table,
                                   tableBytes))
    {
        ExFreePoolWithTag(table, 'udtT');
        return FALSE;
    }

    low = 0;
    high = (LONG)count - 1;
    while (low <= high)
    {
        LONG mid = low + ((high - low) / 2);
        ULONG begin = table[mid].BeginAddress;
        ULONG end = table[mid].EndAddress;

        if (Rva < begin)
        {
            high = mid - 1;
            continue;
        }
        if (Rva >= end)
        {
            low = mid + 1;
            continue;
        }
        found = TRUE;
        break;
    }

    ExFreePoolWithTag(table, 'udtT');
    return found;
}

static BOOLEAN BLACKBIRDValidateUnwindMetadata(_In_ HANDLE ProcessHandle, _In_ PEPROCESS SourceProcess,
                                               _In_ ULONG FrameCount, _In_reads_(FrameCount) PVOID *Frames)
{
    ULONG i;
    ULONG inspectCount;

    if (ProcessHandle == NULL || SourceProcess == NULL || Frames == NULL || FrameCount == 0)
    {
        return FALSE;
    }

    inspectCount = (FrameCount > 6U) ? 6U : FrameCount;
    for (i = 0; i < inspectCount; ++i)
    {
        MEMORY_BASIC_INFORMATION mbi;
        NTSTATUS status;
        ULONG_PTR addr;
        ULONG_PTR base;
        ULONG rva;

        if (Frames[i] == NULL)
        {
            return FALSE;
        }

        RtlZeroMemory(&mbi, sizeof(mbi));
        status =
            ZwQueryVirtualMemory(ProcessHandle, Frames[i], BLACKBIRDMemoryBasicInformation, &mbi, sizeof(mbi), NULL);
        if (!NT_SUCCESS(status) || mbi.AllocationBase == NULL || mbi.Type != MEM_IMAGE)
        {
            return FALSE;
        }

        addr = (ULONG_PTR)Frames[i];
        base = (ULONG_PTR)mbi.AllocationBase;
        if (addr < base || (addr - base) > MAXULONG)
        {
            return FALSE;
        }
        rva = (ULONG)(addr - base);
        if (!BLACKBIRDModuleContainsUnwindForRva(SourceProcess, mbi.AllocationBase, rva))
        {
            return FALSE;
        }
    }

    return TRUE;
}

static BOOLEAN BLACKBIRDQueryTebStackBounds(_In_ HANDLE CallerProcessId, _In_ HANDLE CallerThreadId,
                                            _In_ PEPROCESS SourceProcess, _Out_ ULONG_PTR *StackLimit,
                                            _Out_ ULONG_PTR *StackBase)
{
    OBJECT_ATTRIBUTES oa;
    CLIENT_ID cid;
    HANDLE threadHandle = NULL;
    BLACKBIRD_THREAD_BASIC_INFORMATION tbi;
    BLACKBIRD_NT_TIB tib;
    NTSTATUS status;
    ULONG_PTR limit;
    ULONG_PTR base;

    if (SourceProcess == NULL || StackLimit == NULL || StackBase == NULL || CallerThreadId == NULL)
    {
        return FALSE;
    }

    *StackLimit = 0;
    *StackBase = 0;

    InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    cid.UniqueProcess = CallerProcessId;
    cid.UniqueThread = CallerThreadId;
    status = ZwOpenThread(&threadHandle, THREAD_QUERY_LIMITED_INFORMATION, &oa, &cid);
    if (!NT_SUCCESS(status))
    {
        status = ZwOpenThread(&threadHandle, THREAD_QUERY_INFORMATION, &oa, &cid);
        if (!NT_SUCCESS(status))
        {
            return FALSE;
        }
    }

    RtlZeroMemory(&tbi, sizeof(tbi));
    status = ZwQueryInformationThread(threadHandle, ThreadBasicInformation, &tbi, sizeof(tbi), NULL);
    ZwClose(threadHandle);
    if (!NT_SUCCESS(status) || tbi.TebBaseAddress == NULL)
    {
        return FALSE;
    }
    if ((ULONG_PTR)tbi.TebBaseAddress >= (ULONG_PTR)MmSystemRangeStart)
    {
        return FALSE;
    }

    RtlZeroMemory(&tib, sizeof(tib));
    if (!BLACKBIRDReadProcessBytes(SourceProcess, tbi.TebBaseAddress, &tib, sizeof(tib)))
    {
        return FALSE;
    }

    limit = (ULONG_PTR)tib.StackLimit;
    base = (ULONG_PTR)tib.StackBase;
    if (limit == 0 || base == 0 || limit >= base)
    {
        return FALSE;
    }
    if (base - limit < 0x4000 || base - limit > (64ULL * 1024ULL * 1024ULL))
    {
        return FALSE;
    }

    *StackLimit = limit;
    *StackBase = base;
    return TRUE;
}

static BOOLEAN BLACKBIRDFramesOutsideStackBounds(_In_ ULONG FrameCount, _In_reads_(FrameCount) PVOID *Frames,
                                                 _In_ ULONG_PTR StackLimit, _In_ ULONG_PTR StackBase)
{
    ULONG i;

    if (Frames == NULL || FrameCount == 0 || StackLimit == 0 || StackBase == 0 || StackLimit >= StackBase)
    {
        return FALSE;
    }

    for (i = 0; i < FrameCount; ++i)
    {
        ULONG_PTR a = (ULONG_PTR)Frames[i];
        if (a >= StackLimit && a < StackBase)
        {
            return FALSE;
        }
    }

    return TRUE;
}

static PCSTR BLACKBIRDHandleClassToString(_In_ BLACKBIRD_HANDLE_CLASSIFICATION Class)
{
    if (Class == BLACKBIRDHandleLegitimateSyscall)
    {
        return "LEGITIMATE-SYSCALL";
    }
    if (Class == BLACKBIRDHandleDirectSyscallSuspect)
    {
        return "DIRECT-SYSCALL-SUSPECT";
    }
    return "UNKNOWN-ORIGIN";
}

static BOOLEAN BLACKBIRDHandleAccessIsHighRisk(_In_ ACCESS_MASK DesiredAccess, _In_ BOOLEAN IsThreadObject)
{
    if (IsThreadObject)
    {
        return ((DesiredAccess & THREAD_SET_CONTEXT) != 0) || ((DesiredAccess & THREAD_SUSPEND_RESUME) != 0) ||
               ((DesiredAccess & THREAD_ALL_ACCESS) == THREAD_ALL_ACCESS);
    }

    return ((DesiredAccess & PROCESS_VM_OPERATION) != 0) || ((DesiredAccess & PROCESS_VM_WRITE) != 0) ||
           ((DesiredAccess & PROCESS_CREATE_THREAD) != 0) ||
           ((DesiredAccess & PROCESS_ALL_ACCESS) == PROCESS_ALL_ACCESS);
}

static UINT32 BLACKBIRDCountHandleAnomalySignals(_In_ BOOLEAN ExecProtect, _In_ BOOLEAN FromSyscallModule,
                                                 _In_ const BLACKBIRD_HANDLE_TELEMETRY *Telemetry)
{
    UINT32 signals = 0;

    if (Telemetry == NULL)
    {
        return 0;
    }

    if (!Telemetry->StackValidated)
    {
        signals += 1;
    }
    if (Telemetry->StackSpoofSuspect)
    {
        signals += 1;
    }
    if (!Telemetry->ReturnAddressValid)
    {
        signals += 1;
    }
    if (Telemetry->SyscallExportChecked && !Telemetry->SyscallExportMatch)
    {
        signals += 1;
    }
    if (Telemetry->ModuleChainChecked && !Telemetry->ModuleChainSane)
    {
        signals += 1;
    }
    if (Telemetry->UnwindMetadataChecked && !Telemetry->UnwindMetadataValid)
    {
        signals += 1;
    }
    if (Telemetry->TebStackBoundsChecked && (!Telemetry->TebStackBoundsValid || !Telemetry->FramesOutsideTebStack))
    {
        signals += 1;
    }
    if (ExecProtect && !FromSyscallModule)
    {
        signals += 1;
    }

    return signals;
}

static VOID BLACKBIRDLogHandleTelemetry(_In_ BLACKBIRD_HANDLE_CLASSIFICATION Class, _In_ HANDLE CallerPid,
                                        _In_ HANDLE TargetPid, _In_ ACCESS_MASK DesiredAccess,
                                        _In_ BOOLEAN IsThreadObject, _In_ BOOLEAN IsDuplicateOperation,
                                        _In_ BOOLEAN ExecProtect, _In_ BOOLEAN FromNtdll, _In_ BOOLEAN FromExe,
                                        _In_ PBLACKBIRD_HANDLE_TELEMETRY Telemetry)
{
    UINT32 flags = 0;
    BOOLEAN memoryRelated;
    BOOLEAN stackIntegrityAnomaly;
    BOOLEAN highRiskAccess;
    BOOLEAN fromSyscallModule;
    UINT32 anomalySignals;
    UINT32 classId;
    UNICODE_STRING originPathUs;
    BLACKBIRD_HANDLE_EVENT handleEvent;
    UINT32 i;
    UINT32 safeFrameCount;
    UINT32 safeFullFrameCount;
    UINT32 safeStackBytes;

    BLACKBIRDEtwLogHandleEvent(
        BLACKBIRDHandleClassToString(Class), CallerPid, TargetPid, DesiredAccess, Telemetry->OriginAddress,
        Telemetry->OriginProtect, ExecProtect, FromNtdll, FromExe,
        (Telemetry->OriginPath[0] != L'\0') ? Telemetry->OriginPath : NULL, Telemetry->FrameCount, Telemetry->Frames,
        Telemetry->OpenProcessStatus, Telemetry->BasicInfoStatus, Telemetry->SectionNameStatus,
        (UINT64)(ULONG_PTR)Telemetry->AllocationBase, (UINT64)Telemetry->RegionSize, Telemetry->OriginProtect,
        Telemetry->RegionState, Telemetry->RegionType, Telemetry->DeepSampleSize, Telemetry->DeepSample);

    if (ExecProtect)
    {
        flags |= BLACKBIRD_HANDLE_FLAG_EXEC_PROTECT;
    }
    if (FromNtdll)
    {
        flags |= BLACKBIRD_HANDLE_FLAG_FROM_NTDLL;
    }
    if (FromExe)
    {
        flags |= BLACKBIRD_HANDLE_FLAG_FROM_EXE;
    }

    memoryRelated = ((DesiredAccess & PROCESS_VM_OPERATION) != 0) || ((DesiredAccess & PROCESS_VM_READ) != 0) ||
                    ((DesiredAccess & PROCESS_VM_WRITE) != 0) || ((DesiredAccess & PROCESS_CREATE_THREAD) != 0) ||
                    ((DesiredAccess & PROCESS_ALL_ACCESS) == PROCESS_ALL_ACCESS);
    highRiskAccess = BLACKBIRDHandleAccessIsHighRisk(DesiredAccess, IsThreadObject);
    RtlInitUnicodeString(&originPathUs, Telemetry->OriginPath);
    fromSyscallModule = BLACKBIRDIsSyscallStubModulePath(&originPathUs);
    anomalySignals = BLACKBIRDCountHandleAnomalySignals(ExecProtect, fromSyscallModule, Telemetry);
    if (memoryRelated)
    {
        flags |= BLACKBIRD_HANDLE_FLAG_MEMORY_RELATED;
    }
    if (IsThreadObject)
    {
        flags |= BLACKBIRD_HANDLE_FLAG_THREAD_OBJECT;
    }
    if (IsDuplicateOperation)
    {
        flags |= BLACKBIRD_HANDLE_FLAG_DUPLICATE_OPERATION;
    }
    if (Telemetry->DeepPathCandidate)
    {
        flags |= BLACKBIRD_HANDLE_FLAG_DEEP_PATH_CANDIDATE;
    }
    if (Telemetry->DeepPathCaptured)
    {
        flags |= BLACKBIRD_HANDLE_FLAG_DEEP_PATH_CAPTURED;
    }
    if (Telemetry->DeepPathCacheHit)
    {
        flags |= BLACKBIRD_HANDLE_FLAG_DEEP_PATH_CACHE_HIT;
    }
    if (Telemetry->ReturnAddressValid)
    {
        flags |= BLACKBIRD_HANDLE_FLAG_RETURN_ADDRESS_VALID;
    }
    if (Telemetry->StackValidated)
    {
        flags |= BLACKBIRD_HANDLE_FLAG_STACK_VALIDATED;
    }
    if (Telemetry->StackSpoofSuspect)
    {
        flags |= BLACKBIRD_HANDLE_FLAG_STACK_SPOOF_SUSPECT;
    }
    if (Telemetry->SyscallExportChecked && Telemetry->SyscallExportMatch)
    {
        flags |= BLACKBIRD_HANDLE_FLAG_SYSCALL_EXPORT_MATCH;
    }
    if (Telemetry->SyscallExportChecked && !Telemetry->SyscallExportMatch)
    {
        flags |= BLACKBIRD_HANDLE_FLAG_SYSCALL_EXPORT_MISMATCH;
    }
    if (Telemetry->ModuleChainChecked && Telemetry->ModuleChainSane)
    {
        flags |= BLACKBIRD_HANDLE_FLAG_MODULE_CHAIN_SANE;
    }
    if (Telemetry->UnwindMetadataChecked && Telemetry->UnwindMetadataValid)
    {
        flags |= BLACKBIRD_HANDLE_FLAG_UNWIND_METADATA_VALID;
    }
    if (Telemetry->TebStackBoundsChecked && Telemetry->TebStackBoundsValid)
    {
        flags |= BLACKBIRD_HANDLE_FLAG_TEB_STACK_BOUNDS_VALID;
    }
    if (Telemetry->TebStackBoundsChecked && Telemetry->FramesOutsideTebStack)
    {
        flags |= BLACKBIRD_HANDLE_FLAG_FRAMES_OUTSIDE_TEB_STACK;
    }

    classId = BlackbirdHandleClassUnknown;
    if (Class == BLACKBIRDHandleLegitimateSyscall)
    {
        classId = BlackbirdHandleClassLegitimateSyscall;
    }
    else if (Class == BLACKBIRDHandleDirectSyscallSuspect)
    {
        classId = BlackbirdHandleClassDirectSyscallSuspect;
    }

    if (Class == BLACKBIRDHandleDirectSyscallSuspect && highRiskAccess && anomalySignals >= 3 && CallerPid != TargetPid)
    {
        BLACKBIRDEtwLogDetectionEvent("DIRECT_SYSCALL_SUSPECT_HANDLE_OPERATION", 5, CallerPid, TargetPid, 0,
                                      (UINT32)DesiredAccess, 0,
                                      L"direct-syscall suspect requires multiple stack/module/teb/export anomalies");
    }

    stackIntegrityAnomaly =
        (Telemetry->StackSpoofSuspect || !Telemetry->StackValidated || !Telemetry->ReturnAddressValid ||
         (Telemetry->ModuleChainChecked && !Telemetry->ModuleChainSane) ||
         (Telemetry->UnwindMetadataChecked && !Telemetry->UnwindMetadataValid) ||
         (Telemetry->TebStackBoundsChecked && (!Telemetry->TebStackBoundsValid || !Telemetry->FramesOutsideTebStack)));
    if (stackIntegrityAnomaly && (Class == BLACKBIRDHandleDirectSyscallSuspect) && highRiskAccess &&
        anomalySignals >= 4 && CallerPid != TargetPid)
    {
        BLACKBIRDEtwLogDetectionEvent("STACK_INTEGRITY_ANOMALY_ON_HANDLE_OP", 6, CallerPid, TargetPid, 0,
                                      (UINT32)DesiredAccess, 0,
                                      L"high-confidence stack integrity anomaly on high-risk handle operation");
    }

    /* Credential-access: process-memory handle to lsass.exe */
    if (!IsThreadObject &&
        (DesiredAccess & (PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD)) != 0 &&
        CallerPid != TargetPid)
    {
        PEPROCESS targetProc = NULL;
        NTSTATUS  lookupSt   = PsLookupProcessByProcessId(TargetPid, &targetProc);
        if (NT_SUCCESS(lookupSt))
        {
            PCHAR imageName = PsGetProcessImageFileName(targetProc);
            if (imageName != NULL)
            {
                /* Case-insensitive byte compare against "lsass.exe" */
                static const CHAR kLsass[] = "lsass.exe";
                BOOLEAN isLsass = TRUE;
                ULONG   ci;
                for (ci = 0; ci < sizeof(kLsass) - 1u; ++ci)
                {
                    CHAR c = imageName[ci];
                    if (c >= 'A' && c <= 'Z') c = (CHAR)(c + 32);
                    if (c != kLsass[ci]) { isLsass = FALSE; break; }
                }
                if (isLsass && imageName[sizeof(kLsass) - 1u] == '\0')
                {
                    ULONG sev = (Class == BLACKBIRDHandleDirectSyscallSuspect) ? 8u : 7u;
                    BLACKBIRDEtwLogDetectionEvent("CREDENTIAL_ACCESS_LSASS_HANDLE", sev,
                                                  CallerPid, TargetPid, 0, (UINT32)DesiredAccess, 0,
                                                  L"cross-process memory handle to lsass.exe — credential access attempt");
                }

                /* Winlogon memory access is also high-value — holds logon tokens */
                {
                    static const CHAR kWinlogon[] = "winlogon.exe";
                    BOOLEAN isWinlogon = TRUE;
                    for (ci = 0; ci < sizeof(kWinlogon) - 1u; ++ci)
                    {
                        CHAR c = imageName[ci];
                        if (c >= 'A' && c <= 'Z') c = (CHAR)(c + 32);
                        if (c != kWinlogon[ci]) { isWinlogon = FALSE; break; }
                    }
                    if (isWinlogon && imageName[sizeof(kWinlogon) - 1u] == '\0' &&
                        (DesiredAccess & (PROCESS_VM_READ | PROCESS_VM_WRITE)) != 0)
                    {
                        BLACKBIRDEtwLogDetectionEvent("CREDENTIAL_ACCESS_WINLOGON_HANDLE", 6,
                                                      CallerPid, TargetPid, 0, (UINT32)DesiredAccess, 0,
                                                      L"cross-process memory handle to winlogon.exe");
                    }
                }
            }
            ObDereferenceObject(targetProc);
        }
    }

    if (BLACKBIRDControlHasClientsFast())
    {
        RtlZeroMemory(&handleEvent, sizeof(handleEvent));
        handleEvent.CallerPid = (UINT64)(ULONG_PTR)CallerPid;
        handleEvent.TargetPid = (UINT64)(ULONG_PTR)TargetPid;
        handleEvent.DesiredAccess = (UINT32)DesiredAccess;
        handleEvent.ClassId = classId;
        handleEvent.OriginAddress = (UINT64)(ULONG_PTR)Telemetry->OriginAddress;
        handleEvent.OriginProtect = Telemetry->OriginProtect;
        handleEvent.Flags = flags;
        handleEvent.StatusOpenProcess = (INT32)Telemetry->OpenProcessStatus;
        handleEvent.StatusBasicInfo = (INT32)Telemetry->BasicInfoStatus;
        handleEvent.StatusSectionName = (INT32)Telemetry->SectionNameStatus;
        handleEvent.DeepAllocationBase = (UINT64)(ULONG_PTR)Telemetry->AllocationBase;
        handleEvent.DeepRegionSize = (UINT64)Telemetry->RegionSize;
        handleEvent.DeepRegionProtect = Telemetry->OriginProtect;
        handleEvent.DeepRegionState = Telemetry->RegionState;
        handleEvent.DeepRegionType = Telemetry->RegionType;

        handleEvent.DeepSampleSize = Telemetry->DeepSampleSize;
        if (handleEvent.DeepSampleSize > RTL_NUMBER_OF(handleEvent.DeepSample))
        {
            handleEvent.DeepSampleSize = RTL_NUMBER_OF(handleEvent.DeepSample);
        }
        if (handleEvent.DeepSampleSize != 0)
        {
            RtlCopyMemory(handleEvent.DeepSample, Telemetry->DeepSample, handleEvent.DeepSampleSize);
        }

        if (Telemetry->OriginPath[0] != L'\0')
        {
            (void)RtlStringCchCopyW(handleEvent.OriginPath, RTL_NUMBER_OF(handleEvent.OriginPath),
                                    Telemetry->OriginPath);
        }

        safeFrameCount = (Telemetry->FrameCount > RTL_NUMBER_OF(handleEvent.Frames)) ? RTL_NUMBER_OF(handleEvent.Frames)
                                                                                     : Telemetry->FrameCount;
        handleEvent.FrameCount = safeFrameCount;
        for (i = 0; i < safeFrameCount; ++i)
        {
            handleEvent.Frames[i] = (UINT64)(ULONG_PTR)Telemetry->Frames[i];
        }

        safeFullFrameCount = (Telemetry->FullFrameCount > RTL_NUMBER_OF(handleEvent.FullFrames))
                                 ? RTL_NUMBER_OF(handleEvent.FullFrames)
                                 : Telemetry->FullFrameCount;
        handleEvent.FullFrameCount = safeFullFrameCount;
        for (i = 0; i < safeFullFrameCount; ++i)
        {
            handleEvent.FullFrames[i] = (UINT64)(ULONG_PTR)Telemetry->FullFrames[i];
        }

        handleEvent.CaptureFlags = Telemetry->CaptureFlags;
        handleEvent.RegRax = Telemetry->RegRax;
        handleEvent.RegRbx = Telemetry->RegRbx;
        handleEvent.RegRcx = Telemetry->RegRcx;
        handleEvent.RegRdx = Telemetry->RegRdx;
        handleEvent.RegRsi = Telemetry->RegRsi;
        handleEvent.RegRdi = Telemetry->RegRdi;
        handleEvent.RegRbp = Telemetry->RegRbp;
        handleEvent.RegRsp = Telemetry->RegRsp;
        handleEvent.RegR8 = Telemetry->RegR8;
        handleEvent.RegR9 = Telemetry->RegR9;
        handleEvent.RegR10 = Telemetry->RegR10;
        handleEvent.RegR11 = Telemetry->RegR11;
        handleEvent.RegR12 = Telemetry->RegR12;
        handleEvent.RegR13 = Telemetry->RegR13;
        handleEvent.RegR14 = Telemetry->RegR14;
        handleEvent.RegR15 = Telemetry->RegR15;
        handleEvent.RegRip = Telemetry->RegRip;
        handleEvent.RegEFlags = Telemetry->RegEFlags;
        handleEvent.RegDr0 = Telemetry->RegDr0;
        handleEvent.RegDr1 = Telemetry->RegDr1;
        handleEvent.RegDr2 = Telemetry->RegDr2;
        handleEvent.RegDr3 = Telemetry->RegDr3;
        handleEvent.RegDr6 = Telemetry->RegDr6;
        handleEvent.RegDr7 = Telemetry->RegDr7;
        handleEvent.StackSnapshotAddress = Telemetry->StackSnapshotAddress;
        safeStackBytes = Telemetry->StackSnapshotSize;
        if (safeStackBytes > RTL_NUMBER_OF(handleEvent.StackSnapshot))
        {
            safeStackBytes = RTL_NUMBER_OF(handleEvent.StackSnapshot);
        }
        handleEvent.StackSnapshotSize = safeStackBytes;
        if (safeStackBytes != 0)
        {
            RtlCopyMemory(handleEvent.StackSnapshot, Telemetry->StackSnapshot, safeStackBytes);
        }

        BLACKBIRDControlPublishHandleEvent(&handleEvent);
    }
}

static VOID BLACKBIRDCaptureDeepPathData(_In_ HANDLE CallerProcessId, _In_ BOOLEAN ShouldCapture,
                                         _In_ const MEMORY_BASIC_INFORMATION *Mbi,
                                         _In_opt_ const BLACKBIRD_HANDLE_WORK *Work,
                                         _Inout_ PBLACKBIRD_HANDLE_TELEMETRY Telemetry)
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

    if (Work != NULL && Work->EarlyOriginSampleSize != 0 &&
        Work->EarlyOriginAddress == (UINT64)(ULONG_PTR)Telemetry->OriginAddress)
    {
        Telemetry->DeepSampleSize = (Work->EarlyOriginSampleSize > RTL_NUMBER_OF(Telemetry->DeepSample))
                                        ? RTL_NUMBER_OF(Telemetry->DeepSample)
                                        : Work->EarlyOriginSampleSize;
        RtlCopyMemory(Telemetry->DeepSample, Work->EarlyOriginSample, Telemetry->DeepSampleSize);
        Telemetry->DeepPathCaptured = TRUE;
        Telemetry->DeepPathCacheHit = FALSE;
        BLACKBIRDDeepCacheStore(CallerProcessId, Mbi->BaseAddress, Telemetry->OriginAddress, Mbi->RegionSize,
                                Mbi->Protect, Mbi->State, Mbi->Type, Telemetry->DeepSample, Telemetry->DeepSampleSize);
        return;
    }

    if (Mbi->BaseAddress == NULL || Mbi->RegionSize == 0)
    {
        return;
    }

    if (BLACKBIRDDeepCacheLookup(CallerProcessId, Mbi->BaseAddress,
                                 (Telemetry->OriginAddress != NULL) ? Telemetry->OriginAddress : Mbi->BaseAddress,
                                 Mbi->RegionSize, Mbi->Protect, Mbi->State, Mbi->Type, Telemetry->DeepSample,
                                 &sampleSize))
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
    status = MmCopyVirtualMemory(
        sourceProcess, (Telemetry->OriginAddress != NULL) ? Telemetry->OriginAddress : Mbi->BaseAddress, localProcess,
        Telemetry->DeepSample, sizeof(Telemetry->DeepSample), KernelMode, &bytesRead);
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
    BLACKBIRDDeepCacheStore(CallerProcessId, Mbi->BaseAddress,
                            (Telemetry->OriginAddress != NULL) ? Telemetry->OriginAddress : Mbi->BaseAddress,
                            Mbi->RegionSize, Mbi->Protect, Mbi->State, Mbi->Type, Telemetry->DeepSample,
                            Telemetry->DeepSampleSize);
}

static VOID BLACKBIRDClassifyUserOrigin(_In_ HANDLE CallerProcessId, _In_ HANDLE CallerThreadId,
                                        _In_ BOOLEAN IsThreadObject, _In_ BOOLEAN IsDuplicateOperation,
                                        _In_ ULONG FrameCount, _In_reads_(FrameCount) PVOID *Frames,
                                        _In_opt_ const BLACKBIRD_HANDLE_WORK *Work,
                                        _Out_ PBLACKBIRD_HANDLE_TELEMETRY Telemetry)
{
    NTSTATUS status;
    OBJECT_ATTRIBUTES objectAttributes;
    CLIENT_ID clientId;
    HANDLE processHandle = NULL;
    PEPROCESS sourceProcess = NULL;
    MEMORY_BASIC_INFORMATION mbi;
    UCHAR sectionNameRaw[1024];
    PUNICODE_STRING sectionName;
    UNICODE_STRING originPathUs;
    BOOLEAN execProtect;
    BOOLEAN fromNtdll;
    BOOLEAN fromSyscallModule;
    BOOLEAN deepPathGate;
    PVOID ntdllBase = NULL;
    PCSTR expectedExportName;
    ULONG expectedSyscallNumber;
    ULONG observedSyscallNumber;
    BOOLEAN hasExpectedSyscall;
    BOOLEAN hasObservedSyscall;
    ULONG_PTR stackLimit;
    ULONG_PTR stackBase;

    RtlZeroMemory(Telemetry, sizeof(*Telemetry));
    Telemetry->OpenProcessStatus = STATUS_UNSUCCESSFUL;
    Telemetry->BasicInfoStatus = STATUS_UNSUCCESSFUL;
    Telemetry->SectionNameStatus = STATUS_UNSUCCESSFUL;
    BLACKBIRDApplyWorkCaptureToTelemetry(Work, Telemetry);

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
        BLACKBIRD_DBG_PRINT(DPFLTR_TRACE_LEVEL, "BLACKBIRD[DBG]: ZwOpenProcess failed callerPid=%p status=0x%08X.\n",
                            CallerProcessId, (ULONG)status);
        return;
    }
    if (InterlockedCompareExchange(&g_HandleMonitorStopping, 0, 0) != 0)
    {
        if (sourceProcess != NULL)
        {
            ObDereferenceObject(sourceProcess);
        }
        ZwClose(processHandle);
        return;
    }
    (void)PsLookupProcessByProcessId(CallerProcessId, &sourceProcess);

    RtlZeroMemory(&mbi, sizeof(mbi));
    status = ZwQueryVirtualMemory(processHandle, Telemetry->OriginAddress, BLACKBIRDMemoryBasicInformation, &mbi,
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
        BLACKBIRD_DBG_PRINT(DPFLTR_TRACE_LEVEL,
                            "BLACKBIRD[DBG]: ZwQueryVirtualMemory(basic) failed callerPid=%p status=0x%08X.\n",
                            CallerProcessId, (ULONG)status);
    }
    if (InterlockedCompareExchange(&g_HandleMonitorStopping, 0, 0) != 0)
    {
        if (sourceProcess != NULL)
        {
            ObDereferenceObject(sourceProcess);
        }
        ZwClose(processHandle);
        return;
    }

    RtlZeroMemory(sectionNameRaw, sizeof(sectionNameRaw));
    status = ZwQueryVirtualMemory(processHandle, Telemetry->OriginAddress, BLACKBIRDMemorySectionName, sectionNameRaw,
                                  sizeof(sectionNameRaw), NULL);
    Telemetry->SectionNameStatus = status;
    if (NT_SUCCESS(status))
    {
        sectionName = (PUNICODE_STRING)sectionNameRaw;
        BLACKBIRDSafeCopyUnicode(sectionName, Telemetry->OriginPath, RTL_NUMBER_OF(Telemetry->OriginPath));
    }
    else
    {
        BLACKBIRD_DBG_PRINT(DPFLTR_TRACE_LEVEL,
                            "BLACKBIRD[DBG]: ZwQueryVirtualMemory(section) failed callerPid=%p status=0x%08X.\n",
                            CallerProcessId, (ULONG)status);
    }

    RtlInitUnicodeString(&originPathUs, Telemetry->OriginPath);
    execProtect = BLACKBIRDIsExecutableProtection(Telemetry->OriginProtect);
    fromNtdll = BLACKBIRDIsNtdllPath(&originPathUs);
    fromSyscallModule = BLACKBIRDIsSyscallStubModulePath(&originPathUs);
    // Capture sample bytes for executable origins, including ntdll/win32u stubs, so UI can disassemble real origin
    // bytes.
    deepPathGate = execProtect;
    BLACKBIRDCaptureDeepPathData(CallerProcessId, deepPathGate, &mbi, Work, Telemetry);

    Telemetry->StackValidated = BLACKBIRDValidateStackFrames(processHandle, Telemetry->FrameCount, Telemetry->Frames,
                                                             &Telemetry->StackSpoofSuspect);
    if (sourceProcess != NULL && Telemetry->FrameCount > 1 && Telemetry->Frames[1] != NULL)
    {
        Telemetry->ReturnAddressValid = BLACKBIRDValidateReturnAddress(sourceProcess, Telemetry->Frames[1]);
    }
    else
    {
        Telemetry->ReturnAddressValid = FALSE;
    }

    if (fromNtdll && Telemetry->AllocationBase != NULL)
    {
        ntdllBase = Telemetry->AllocationBase;
    }
    else
    {
        (void)BLACKBIRDGetNtdllBaseFromFrames(processHandle, Telemetry->FrameCount, Telemetry->Frames, &ntdllBase);
    }

    expectedExportName = BLACKBIRDGetExpectedSyscallExport(IsThreadObject, IsDuplicateOperation);
    hasExpectedSyscall =
        BLACKBIRDResolveExportSyscallNumber(sourceProcess, ntdllBase, expectedExportName, &expectedSyscallNumber);
    hasObservedSyscall =
        BLACKBIRDExtractSyscallNumberNearAddress(sourceProcess, Telemetry->OriginAddress, &observedSyscallNumber);
    Telemetry->SyscallExportChecked = hasExpectedSyscall;
    Telemetry->SyscallExportMatch =
        hasExpectedSyscall && hasObservedSyscall && (expectedSyscallNumber == observedSyscallNumber);

    Telemetry->ModuleChainChecked = TRUE;
    Telemetry->ModuleChainSane =
        BLACKBIRDValidateModuleChainSanity(processHandle, Telemetry->FrameCount, Telemetry->Frames);

    Telemetry->UnwindMetadataChecked = (sourceProcess != NULL);
    Telemetry->UnwindMetadataValid =
        Telemetry->UnwindMetadataChecked &&
        BLACKBIRDValidateUnwindMetadata(processHandle, sourceProcess, Telemetry->FrameCount, Telemetry->Frames);

    stackLimit = 0;
    stackBase = 0;
    Telemetry->TebStackBoundsChecked = (sourceProcess != NULL && CallerThreadId != NULL);
    Telemetry->TebStackBoundsValid =
        Telemetry->TebStackBoundsChecked &&
        BLACKBIRDQueryTebStackBounds(CallerProcessId, CallerThreadId, sourceProcess, &stackLimit, &stackBase);
    Telemetry->FramesOutsideTebStack =
        Telemetry->TebStackBoundsValid &&
        BLACKBIRDFramesOutsideStackBounds(Telemetry->FrameCount, Telemetry->Frames, stackLimit, stackBase);

    if (sourceProcess != NULL && (Telemetry->CaptureFlags & BLACKBIRD_HANDLE_CAPTURE_CONTEXT_VALID) != 0 &&
        Telemetry->RegRsp != 0)
    {
        BLACKBIRDCaptureStackSnapshot(sourceProcess, Telemetry->RegRsp, Telemetry);
    }

    if (sourceProcess != NULL)
    {
        ObDereferenceObject(sourceProcess);
    }
    ZwClose(processHandle);
}

static VOID BLACKBIRDHandleWorkRoutine(_In_ PVOID Context)
{
    PBLACKBIRD_HANDLE_WORK work = (PBLACKBIRD_HANDLE_WORK)Context;
    BLACKBIRD_HANDLE_TELEMETRY telemetry;
    UNICODE_STRING originPathUs;
    BOOLEAN execProtect;
    BOOLEAN fromNtdll;
    BOOLEAN fromSyscallModule;
    BOOLEAN fromExe;
    BOOLEAN highRiskAccess;
    UINT32 anomalySignals;
    BLACKBIRD_HANDLE_CLASSIFICATION classification = BLACKBIRDHandleUnknown;

    PAGED_CODE();
    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        goto Exit;
    }
    if (InterlockedCompareExchange(&g_HandleMonitorStopping, 0, 0) != 0)
    {
        goto Exit;
    }
    if (!BLACKBIRDControlHasClientsFast())
    {
        goto Exit;
    }

    BLACKBIRDClassifyUserOrigin(work->CallerPid, work->CallerTid, work->IsThreadObject, work->IsDuplicateOperation,
                                work->FrameCount, work->Frames, work, &telemetry);

    RtlInitUnicodeString(&originPathUs, telemetry.OriginPath);
    execProtect = BLACKBIRDIsExecutableProtection(telemetry.OriginProtect);

    fromNtdll = BLACKBIRDIsNtdllPath(&originPathUs);
    fromSyscallModule = BLACKBIRDIsSyscallStubModulePath(&originPathUs);
    fromExe = BLACKBIRDUnicodeContainsInsensitive(&originPathUs, L".exe", 4);
    highRiskAccess = BLACKBIRDHandleAccessIsHighRisk(work->DesiredAccess, work->IsThreadObject);
    anomalySignals = BLACKBIRDCountHandleAnomalySignals(execProtect, fromSyscallModule, &telemetry);
    if (fromSyscallModule && telemetry.StackValidated && !telemetry.StackSpoofSuspect && telemetry.ReturnAddressValid &&
        telemetry.ModuleChainChecked && telemetry.ModuleChainSane && telemetry.UnwindMetadataChecked &&
        telemetry.UnwindMetadataValid && telemetry.TebStackBoundsChecked && telemetry.TebStackBoundsValid &&
        telemetry.FramesOutsideTebStack)
    {
        classification = BLACKBIRDHandleLegitimateSyscall;
    }
    else if (highRiskAccess && execProtect && anomalySignals >= 2)
    {
        classification = BLACKBIRDHandleDirectSyscallSuspect;
    }
    else
    {
        classification = BLACKBIRDHandleUnknown;
    }

    BLACKBIRDLogHandleTelemetry(classification, work->CallerPid, work->TargetPid, work->DesiredAccess,
                                work->IsThreadObject, work->IsDuplicateOperation, execProtect, fromNtdll, fromExe,
                                &telemetry);

    BLACKBIRD_DBG_PRINT(DPFLTR_INFO_LEVEL,
                        "BLACKBIRD[DBG]: handle event caller=%p target=%p access=0x%08X class=%s open=0x%08X "
                        "basic=0x%08X section=0x%08X frames=%lu.\n",
                        work->CallerPid, work->TargetPid, work->DesiredAccess,
                        BLACKBIRDHandleClassToString(classification), (ULONG)telemetry.OpenProcessStatus,
                        (ULONG)telemetry.BasicInfoStatus, (ULONG)telemetry.SectionNameStatus, work->FrameCount);

Exit:
    BLACKBIRDHandleReleaseWorkSlot();
    ExFreePoolWithTag(work, 'hdtT');
}

static OB_PREOP_CALLBACK_STATUS BLACKBIRDProcessPreOperation(_In_ PVOID RegistrationContext,
                                                             _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation)
{
    ACCESS_MASK desiredAccess;
    ACCESS_MASK originalDesiredAccess;
    ACCESS_MASK sanitizedAccess;
    HANDLE callerPid;
    HANDLE callerTid;
    HANDLE targetPid;
    PEPROCESS targetProcess;
    PETHREAD targetThread;
    PBLACKBIRD_HANDLE_WORK work;
    PVOID userFrames[BLACKBIRD_MAX_FULL_EVENT_FRAMES] = {0};
    ULONG frameCount;
    ULONG copyCount;
    ULONG fullCopyCount;
    BOOLEAN hasVmWriteOrFull;
    BOOLEAN hasThreadContextAccess;
    UINT32 intentFlags;
    UINT32 streamMask;
    UINT32 callerPid32;
    UINT32 targetPid32;
    UINT32 secondaryPid32;
    BOOLEAN shouldCaptureStack;
    BOOLEAN isThreadObject = FALSE;
    BOOLEAN isDuplicateOperation = FALSE;
    BOOLEAN isProtectedTarget;
    BOOLEAN trustedProtectedCaller;
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

    originalDesiredAccess = desiredAccess;
    sanitizedAccess = desiredAccess;
    hasVmWriteOrFull = FALSE;
    hasThreadContextAccess = FALSE;
    if (OperationInformation->ObjectType == *PsProcessType)
    {
        targetProcess = (PEPROCESS)OperationInformation->Object;
        targetPid = PsGetProcessId(targetProcess);

        hasVmWriteOrFull = ((originalDesiredAccess & PROCESS_VM_OPERATION) != 0) ||
                           ((originalDesiredAccess & PROCESS_VM_WRITE) != 0) ||
                           ((originalDesiredAccess & PROCESS_CREATE_THREAD) != 0) ||
                           ((originalDesiredAccess & PROCESS_ALL_ACCESS) == PROCESS_ALL_ACCESS);
    }
    else if (OperationInformation->ObjectType == *PsThreadType)
    {
        isThreadObject = TRUE;
        targetThread = (PETHREAD)OperationInformation->Object;
        targetPid = PsGetThreadProcessId(targetThread);

        hasThreadContextAccess = ((originalDesiredAccess & THREAD_SET_CONTEXT) != 0) ||
                                 ((originalDesiredAccess & THREAD_GET_CONTEXT) != 0) ||
                                 ((originalDesiredAccess & THREAD_SUSPEND_RESUME) != 0) ||
                                 ((originalDesiredAccess & THREAD_ALL_ACCESS) == THREAD_ALL_ACCESS);
    }
    else
    {
        return OB_PREOP_SUCCESS;
    }

    callerPid = PsGetCurrentProcessId();
    callerTid = PsGetCurrentThreadId();
    callerPid32 = (UINT32)(ULONG_PTR)callerPid;
    targetPid32 = (UINT32)(ULONG_PTR)targetPid;
    isProtectedTarget = BLACKBIRDProcessMonitorIsProtectedPid(targetPid32);
    trustedProtectedCaller = BLACKBIRDProcessMonitorIsTrustedProtectedCaller(callerPid32, targetPid32);
    if (isProtectedTarget && !trustedProtectedCaller)
    {
        sanitizedAccess &= isThreadObject ? BLACKBIRD_PROTECTED_THREAD_ALLOWED_ACCESS
                                          : BLACKBIRD_PROTECTED_PROCESS_ALLOWED_ACCESS;
        if (sanitizedAccess != desiredAccess)
        {
            if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
            {
                OperationInformation->Parameters->CreateHandleInformation.DesiredAccess = sanitizedAccess;
            }
            else
            {
                OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess = sanitizedAccess;
            }
            desiredAccess = sanitizedAccess;
        }
    }

    if (!hasVmWriteOrFull && !hasThreadContextAccess)
    {
        return OB_PREOP_SUCCESS;
    }
    if (!BLACKBIRDControlHasClientsFast())
    {
        return OB_PREOP_SUCCESS;
    }

    secondaryPid32 = (targetPid32 != callerPid32) ? targetPid32 : 0;
    streamMask = BLACKBIRD_STREAM_HANDLE;
    if (hasVmWriteOrFull)
    {
        streamMask |= BLACKBIRD_STREAM_MEMORY;
    }

    if (!BLACKBIRDControlHasPidInterest(callerPid32, secondaryPid32, streamMask))
    {
        return OB_PREOP_SUCCESS;
    }

    intentFlags = 0;
    if (hasVmWriteOrFull)
    {
        intentFlags |= BLACKBIRD_INTENT_PROCESS_MEMORY;
    }
    if (hasThreadContextAccess)
    {
        intentFlags |= BLACKBIRD_INTENT_THREAD_CONTEXT;
    }
    if (isDuplicateOperation && (intentFlags != 0))
    {
        intentFlags |= BLACKBIRD_INTENT_DUP_HANDLE;
    }

    if (intentFlags != 0)
    {
        BLACKBIRDCorrelationRecordHandleIntent(callerPid, targetPid, originalDesiredAccess, intentFlags);
    }
    if (isThreadObject)
    {
        BLACKBIRDApcMonitorRecordThreadHandleIntent(callerPid, targetPid, originalDesiredAccess, isDuplicateOperation);
    }

    if (!BLACKBIRDHandleTryAcquireWorkSlot())
    {
        failureCounter = InterlockedIncrement(&g_HandleCallbackDropLogCounter);
        if (failureCounter == 1 || ((failureCounter & 0xFF) == 0))
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "BLACKBIRD: handle callback drop caller=%p target=%p access=0x%08X total=%lu.\n", callerPid,
                       targetPid, originalDesiredAccess, (ULONG)failureCounter);
        }
        BLACKBIRD_DBG_PRINT(
            DPFLTR_WARNING_LEVEL,
            "BLACKBIRD[DBG]: dropping handle preop caller=%p target=%p access=0x%08X (work slot unavailable).\n",
            callerPid, targetPid, originalDesiredAccess);
        return OB_PREOP_SUCCESS;
    }

    work = (PBLACKBIRD_HANDLE_WORK)BLACKBIRDAllocatePoolCompat(POOL_FLAG_NON_PAGED, sizeof(*work), 'hdtT');
    if (work == NULL)
    {
        failureCounter = InterlockedIncrement(&g_HandleAllocFailureCounter);
        if (failureCounter == 1 || ((failureCounter & 0xFF) == 0))
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                       "BLACKBIRD: handle callback alloc failure caller=%p target=%p access=0x%08X total=%lu.\n",
                       callerPid, targetPid, originalDesiredAccess, (ULONG)failureCounter);
        }
        BLACKBIRD_DBG_PRINT(DPFLTR_ERROR_LEVEL, "BLACKBIRD[DBG]: ExAllocatePool2 failed for handle work item.\n");
        BLACKBIRDHandleReleaseWorkSlot();
        return OB_PREOP_SUCCESS;
    }

    RtlZeroMemory(work, sizeof(*work));
    work->CallerPid = callerPid;
    work->CallerTid = callerTid;
    work->TargetPid = targetPid;
    work->DesiredAccess = originalDesiredAccess;
    work->IsThreadObject = isThreadObject;
    work->IsDuplicateOperation = isDuplicateOperation;

    frameCount = 0;
    copyCount = 0;
    fullCopyCount = 0;
    BLACKBIRDCaptureRegisterSnapshot(work);
    shouldCaptureStack = isDuplicateOperation ||
                         ((originalDesiredAccess & (PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD |
                                                    THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME)) != 0) ||
                         ((originalDesiredAccess & PROCESS_ALL_ACCESS) == PROCESS_ALL_ACCESS) ||
                         ((originalDesiredAccess & THREAD_ALL_ACCESS) == THREAD_ALL_ACCESS);
    if (shouldCaptureStack)
    {
        __try
        {
            frameCount = RtlWalkFrameChain(userFrames, RTL_NUMBER_OF(userFrames), RTL_WALK_USER_MODE_STACK);
            copyCount = (frameCount > RTL_NUMBER_OF(work->Frames)) ? RTL_NUMBER_OF(work->Frames) : frameCount;
            fullCopyCount =
                (frameCount > RTL_NUMBER_OF(work->FullFrames)) ? RTL_NUMBER_OF(work->FullFrames) : frameCount;
            if (copyCount != 0)
            {
                RtlCopyMemory(work->Frames, userFrames, copyCount * sizeof(PVOID));
            }
            if (fullCopyCount != 0)
            {
                RtlCopyMemory(work->FullFrames, userFrames, fullCopyCount * sizeof(PVOID));
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            copyCount = 0;
            fullCopyCount = 0;
            RtlZeroMemory(work->Frames, sizeof(work->Frames));
            RtlZeroMemory(work->FullFrames, sizeof(work->FullFrames));
            InterlockedIncrement(&g_HandleStackCaptureFaults);
            failureCounter = InterlockedIncrement(&g_HandleStackFaultLogCounter);
            if (failureCounter == 1 || ((failureCounter & 0xFF) == 0))
            {
                DbgPrintEx(
                    DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                    "BLACKBIRD: handle callback stack capture fault caller=%p target=%p access=0x%08X total=%lu.\n",
                    callerPid, targetPid, desiredAccess, (ULONG)failureCounter);
            }
            BLACKBIRD_DBG_PRINT(DPFLTR_WARNING_LEVEL,
                                "BLACKBIRD[DBG]: RtlWalkFrameChain fault caller=%p target=%p access=0x%08X.\n",
                                callerPid, targetPid, desiredAccess);
        }
    }

    work->FrameCount = copyCount;
    work->FullFrameCount = fullCopyCount;
    if (copyCount != 0 && work->Frames[0] != NULL)
    {
        BLACKBIRDCaptureImmediateOriginSample(callerPid, work->Frames[0], work);
    }

    ExInitializeWorkItem(&work->WorkItem, BLACKBIRDHandleWorkRoutine, work);
    ExQueueWorkItem(&work->WorkItem, DelayedWorkQueue);
    BLACKBIRD_DBG_PRINT(DPFLTR_TRACE_LEVEL,
                        "BLACKBIRD[DBG]: queued handle work caller=%p target=%p access=0x%08X frames=%lu.\n", callerPid,
                        targetPid, desiredAccess, copyCount);

    return OB_PREOP_SUCCESS;
}

NTSTATUS
BLACKBIRDHandleMonitorInitialize(VOID)
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
    KeQueryPerformanceCounter(&freq);
    g_DeepCacheQpcFrequency = (freq.QuadPart > 0) ? (ULONGLONG)freq.QuadPart : 1;
    InterlockedExchange(&g_HandleMonitorStopping, 0);
    InterlockedExchange(&g_HandleOutstandingWork, 0);
    InterlockedExchange(&g_HandleDroppedWork, 0);
    InterlockedExchange(&g_HandleStackCaptureFaults, 0);

    RtlZeroMemory(&g_OperationRegistration, sizeof(g_OperationRegistration));
    g_OperationRegistration[0].ObjectType = PsProcessType;
    g_OperationRegistration[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    g_OperationRegistration[0].PreOperation = BLACKBIRDProcessPreOperation;
    g_OperationRegistration[0].PostOperation = NULL;

    g_OperationRegistration[1].ObjectType = PsThreadType;
    g_OperationRegistration[1].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    g_OperationRegistration[1].PreOperation = BLACKBIRDProcessPreOperation;
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
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "BLACKBIRD: ObRegisterCallbacks failed (0x%08X).\n",
                   status);
        return status;
    }

    g_HandleMonitorRegistered = TRUE;
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "BLACKBIRD: process handle monitor initialized.\n");
    return STATUS_SUCCESS;
}

VOID BLACKBIRDHandleMonitorUninitialize(VOID)
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
                       "BLACKBIRD: handle monitor draining (outstanding=%ld).\n",
                       InterlockedCompareExchange(&g_HandleOutstandingWork, 0, 0));
        }
    }

    InterlockedExchange(&g_HandleMonitorStopping, 0);
    RtlZeroMemory(g_DeepCache, sizeof(g_DeepCache));
    InterlockedExchange(&g_DeepCacheWriteIndex, -1);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "BLACKBIRD: process handle monitor uninitialized (dropped=%ld, stackCaptureFaults=%ld).\n",
               InterlockedCompareExchange(&g_HandleDroppedWork, 0, 0),
               InterlockedCompareExchange(&g_HandleStackCaptureFaults, 0, 0));
}

BOOLEAN
BLACKBIRDHandleMonitorSelfCheck(VOID)
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
    if (g_OperationRegistration[0].PreOperation != BLACKBIRDProcessPreOperation ||
        g_OperationRegistration[1].PreOperation != BLACKBIRDProcessPreOperation)
    {
        return FALSE;
    }
    if (InterlockedCompareExchange(&g_HandleOutstandingWork, 0, 0) < 0)
    {
        return FALSE;
    }

    return TRUE;
}



