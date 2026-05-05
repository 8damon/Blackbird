#include <ntddk.h>
#include <ntimage.h>
#include <intrin.h>
#include <ntstrsafe.h>
#include "..\core\control.h"
#include "..\core\tempus_debug.h"
#include "..\core\protection_utils.h"
#include "..\core\pool_compat.h"
#include "..\core\unicode_utils.h"
#include "..\telemetry\etw.h"
#include "..\monitors\apc_monitor.h"
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

#ifndef PROCESS_QUERY_INFORMATION
#define PROCESS_QUERY_INFORMATION 0x0400
#endif

#ifndef PROCESS_SET_INFORMATION
#define PROCESS_SET_INFORMATION 0x0200
#endif

#ifndef PROCESS_CREATE_PROCESS
#define PROCESS_CREATE_PROCESS 0x0080
#endif

#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE 0x0001
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

#define BK_PROTECTED_PROCESS_ALLOWED_ACCESS (PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE)
#define BK_PROTECTED_THREAD_ALLOWED_ACCESS (THREAD_QUERY_LIMITED_INFORMATION | SYNCHRONIZE)

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

typedef struct _BK_THREAD_BASIC_INFORMATION
{
    NTSTATUS ExitStatus;
    PVOID TebBaseAddress;
    CLIENT_ID ClientId;
    KAFFINITY AffinityMask;
    KPRIORITY Priority;
    KPRIORITY BasePriority;
} BK_THREAD_BASIC_INFORMATION, *PBK_THREAD_BASIC_INFORMATION;

typedef struct _BK_NT_TIB
{
    PVOID ExceptionList;
    PVOID StackBase;
    PVOID StackLimit;
    PVOID SubSystemTib;
    PVOID FiberData;
    PVOID ArbitraryUserPointer;
    PVOID Self;
} BK_NT_TIB, *PBK_NT_TIB;

typedef enum _BK_MEMORY_INFORMATION_CLASS
{
    BkchdlMemoryBasicInformation = 0,
    BkchdlMemorySectionName = 2
} BK_MEMORY_INFORMATION_CLASS;

NTSYSAPI NTSTATUS NTAPI ZwQueryVirtualMemory(_In_ HANDLE ProcessHandle, _In_opt_ PVOID BaseAddress,
                                             _In_ BK_MEMORY_INFORMATION_CLASS MemoryInformationClass,
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
NTKERNELAPI HANDLE PsGetThreadId(_In_ PETHREAD Thread);
NTKERNELAPI NTSTATUS PsLookupProcessByProcessId(_In_ HANDLE ProcessId, _Outptr_ PEPROCESS *Process);
NTKERNELAPI PCHAR PsGetProcessImageFileName(_In_ PEPROCESS Process);
NTKERNELAPI NTSTATUS MmCopyVirtualMemory(_In_ PEPROCESS FromProcess, _In_ const VOID *FromAddress,
                                         _In_ PEPROCESS ToProcess, _Out_writes_bytes_(BufferSize) PVOID ToAddress,
                                         _In_ SIZE_T BufferSize, _In_ KPROCESSOR_MODE PreviousMode,
                                         _Out_ PSIZE_T NumberOfBytesCopied);

#define BK_HANDLE_MAX_OUTSTANDING_WORK 2048
#define BK_DEEP_CAPTURE_MAX_BYTES 64
#define BK_DEEP_CACHE_RING_SIZE 64
#define BK_DEEP_CACHE_TTL_MS 3000
#define BK_SYSCALL_EXPORT_MATCH_WINDOW_BYTES 0x40u

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

typedef struct _BK_DEEP_CACHE_ENTRY
{
    UINT64 CallerPid;
    UINT64 AllocationBase;
    UINT64 SampleAddress;
    UINT64 RegionSize;
    ULONG RegionProtect;
    ULONG RegionState;
    ULONG RegionType;
    UCHAR Sample[BK_DEEP_CAPTURE_MAX_BYTES];
    UINT32 SampleSize;
    INT64 TimestampQpc;
} BK_DEEP_CACHE_ENTRY, *PBK_DEEP_CACHE_ENTRY;

static BK_DEEP_CACHE_ENTRY g_DeepCache[BK_DEEP_CACHE_RING_SIZE];

/*
 * Hot-path debug tracing is disabled by default to prevent KD console flooding.
 * Define BK_VERBOSE_HOTPATH_DEBUG=1 for local deep diagnostics.
 */
#if !defined(BK_VERBOSE_HOTPATH_DEBUG)
#define BK_VERBOSE_HOTPATH_DEBUG 0
#endif

#if defined(DBG) && DBG && BK_VERBOSE_HOTPATH_DEBUG
#define BK_DBG_PRINT(_level, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, (_level), __VA_ARGS__)
#else
#define BK_DBG_PRINT(_level, ...) ((void)0)
#endif

typedef struct _BK_HANDLE_WORK
{
    WORK_QUEUE_ITEM WorkItem;
    HANDLE CallerPid;
    HANDLE CallerTid;
    HANDLE TargetPid;
    HANDLE TargetTid;
    UINT64 ObjectAddress;
    ACCESS_MASK DesiredAccess;
    BOOLEAN IsThreadObject;
    BOOLEAN IsDuplicateOperation;
    UINT32 CaptureFlags;
    ULONG FrameCount;
    PVOID Frames[8];
    ULONG FullFrameCount;
    PVOID FullFrames[BK_MAX_FULL_EVENT_FRAMES];
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
    UCHAR EarlyOriginSample[BK_DEEP_CAPTURE_MAX_BYTES];
} BK_HANDLE_WORK, *PBK_HANDLE_WORK;

typedef enum _BK_HANDLE_CLASSIFICATION
{
    BkchdlHandleUnknown = 0,
    BkchdlHandleLegitimateSyscall,
    BkchdlHandleDirectSyscallSuspect
} BK_HANDLE_CLASSIFICATION;

typedef struct _BK_HANDLE_TELEMETRY
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
    UCHAR DeepSample[BK_DEEP_CAPTURE_MAX_BYTES];
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
    PVOID FullFrames[BK_MAX_FULL_EVENT_FRAMES];
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
    UCHAR StackSnapshot[BK_MAX_STACK_SNAPSHOT_BYTES];
} BK_HANDLE_TELEMETRY, *PBK_HANDLE_TELEMETRY;

static VOID BkchdlCaptureRegisterSnapshot(_Out_ PBK_HANDLE_WORK Work)
{
#if defined(_M_AMD64)
    CONTEXT context;

    if (Work == NULL)
    {
        return;
    }

    RtlZeroMemory(&context, sizeof(context));
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
    Work->CaptureFlags |= BK_HANDLE_CAPTURE_CONTEXT_VALID;

    __try
    {
        Work->RegDr0 = __readdr(0);
        Work->RegDr1 = __readdr(1);
        Work->RegDr2 = __readdr(2);
        Work->RegDr3 = __readdr(3);
        Work->RegDr6 = __readdr(6);
        Work->RegDr7 = __readdr(7);
        Work->CaptureFlags |= BK_HANDLE_CAPTURE_DEBUG_REGS_VALID;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
    }
#else
    UNREFERENCED_PARAMETER(Work);
#endif
}

static VOID BkchdlApplyWorkCaptureToTelemetry(_In_opt_ const BK_HANDLE_WORK *Work,
                                              _Inout_ PBK_HANDLE_TELEMETRY Telemetry)
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
        Telemetry->CaptureFlags |= BK_HANDLE_CAPTURE_FULL_FRAMES_VALID;
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

static VOID BkchdlCaptureStackSnapshot(_In_ PEPROCESS SourceProcess, _In_ UINT64 StackPointer,
                                       _Inout_ PBK_HANDLE_TELEMETRY Telemetry)
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
    Telemetry->CaptureFlags |= BK_HANDLE_CAPTURE_STACK_SNAPSHOT_VALID;
}

static BOOLEAN BkchdlHandleTryAcquireWorkSlot(VOID)
{
    LONG current;

    for (;;)
    {
        current = InterlockedCompareExchange(&g_HandleOutstandingWork, 0, 0);
        if (current >= BK_HANDLE_MAX_OUTSTANDING_WORK)
        {
            InterlockedIncrement(&g_HandleDroppedWork);
            BK_DBG_PRINT(DPFLTR_WARNING_LEVEL, "BK[DBG]: handle monitor work queue full (max=%lu).\n",
                         BK_HANDLE_MAX_OUTSTANDING_WORK);
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

static VOID BkchdlHandleReleaseWorkSlot(VOID)
{
    if (InterlockedDecrement(&g_HandleOutstandingWork) == 0)
    {
        KeSetEvent(&g_HandleAllWorkDone, IO_NO_INCREMENT, FALSE);
    }
}

static ULONGLONG BkchdlDeepCacheMsToQpc(_In_ UINT32 Ms)
{
    ULONGLONG ticks;

    if (Ms == 0)
    {
        return 0;
    }

    ticks = ((ULONGLONG)Ms * g_DeepCacheQpcFrequency) / 1000ULL;
    return (ticks == 0) ? 1 : ticks;
}

static BOOLEAN BkchdlDeepCacheLookup(_In_ HANDLE CallerPid, _In_ PVOID AllocationBase, _In_ PVOID SampleAddress,
                                     _In_ SIZE_T RegionSize, _In_ ULONG RegionProtect, _In_ ULONG RegionState,
                                     _In_ ULONG RegionType, _Out_writes_bytes_(BK_DEEP_CAPTURE_MAX_BYTES) UCHAR *Sample,
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
    maxAgeQpc = BkchdlDeepCacheMsToQpc(BK_DEEP_CACHE_TTL_MS);
    KeAcquireSpinLock(&g_DeepCacheLock, &oldIrql);
    for (i = 0; i < RTL_NUMBER_OF(g_DeepCache); ++i)
    {
        const BK_DEEP_CACHE_ENTRY *e = &g_DeepCache[i];
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

        safeSize = (e->SampleSize > BK_DEEP_CAPTURE_MAX_BYTES) ? BK_DEEP_CAPTURE_MAX_BYTES : e->SampleSize;
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

static VOID BkchdlDeepCacheStore(_In_ HANDLE CallerPid, _In_ PVOID AllocationBase, _In_ PVOID SampleAddress,
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

    safeSize = (SampleSize > BK_DEEP_CAPTURE_MAX_BYTES) ? BK_DEEP_CAPTURE_MAX_BYTES : SampleSize;

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

static BOOLEAN BkchdlReadProcessBytes(_In_ PEPROCESS SourceProcess, _In_ const VOID *Address,
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

static VOID BkchdlCaptureImmediateOriginSample(_In_ HANDLE CallerProcessId, _In_ PVOID OriginAddress,
                                               _Inout_ PBK_HANDLE_WORK Work)
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

static CHAR BkchdlAsciiUpper(_In_ CHAR Value)
{
    if (Value >= 'a' && Value <= 'z')
    {
        return (CHAR)(Value - ('a' - 'A'));
    }
    return Value;
}

static BOOLEAN BkchdlAsciiEqualsInsensitive(_In_z_ const CHAR *Left, _In_z_ const CHAR *Right)
{
    SIZE_T i;

    if (Left == NULL || Right == NULL)
    {
        return FALSE;
    }

    for (i = 0;; ++i)
    {
        CHAR a = BkchdlAsciiUpper(Left[i]);
        CHAR b = BkchdlAsciiUpper(Right[i]);
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

static BOOLEAN BkchdlExtractSyscallNumberNearAddress(_In_ PEPROCESS SourceProcess, _In_ const VOID *Address,
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
    if (!BkchdlReadProcessBytes(SourceProcess, (const VOID *)base, bytes, readLen))
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

static BOOLEAN BkchdlValidateReturnAddress(_In_ PEPROCESS SourceProcess, _In_ PVOID ReturnAddress)
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

    if (!BkchdlReadProcessBytes(SourceProcess, (const VOID *)(addrValue - sizeof(tail)), tail, sizeof(tail)))
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

static BOOLEAN BkchdlValidateStackFrames(_In_ HANDLE ProcessHandle, _In_ ULONG FrameCount,
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
        status = ZwQueryVirtualMemory(ProcessHandle, frame, BkchdlMemoryBasicInformation, &mbi, sizeof(mbi), NULL);
        if (!NT_SUCCESS(status))
        {
            return FALSE;
        }

        execProtect = BkprotIsExecutableProtection(mbi.Protect);
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

static PCSTR BkchdlGetExpectedSyscallExport(_In_ BOOLEAN IsThreadObject, _In_ BOOLEAN IsDuplicateOperation)
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

static BOOLEAN BkchdlIsNtdllPath(_In_ const UNICODE_STRING *Path)
{
    if (Path == NULL || Path->Buffer == NULL || Path->Length == 0)
    {
        return FALSE;
    }

    return BkstrUnicodeContainsInsensitive(Path, L"ntdll.dll", 9);
}

static BOOLEAN BkchdlIsSyscallStubModulePath(_In_ const UNICODE_STRING *Path)
{
    if (Path == NULL || Path->Buffer == NULL || Path->Length == 0)
    {
        return FALSE;
    }

    if (BkchdlIsNtdllPath(Path))
    {
        return TRUE;
    }

    return BkstrUnicodeContainsInsensitive(Path, L"win32u.dll", 10);
}

static BOOLEAN BkchdlGetNtdllBaseFromFrames(_In_ HANDLE ProcessHandle, _In_ ULONG FrameCount,
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
        status = ZwQueryVirtualMemory(ProcessHandle, Frames[i], BkchdlMemoryBasicInformation, &mbi, sizeof(mbi), NULL);
        if (!NT_SUCCESS(status) || mbi.AllocationBase == NULL)
        {
            continue;
        }

        RtlZeroMemory(sectionNameRaw, sizeof(sectionNameRaw));
        status = ZwQueryVirtualMemory(ProcessHandle, Frames[i], BkchdlMemorySectionName, sectionNameRaw,
                                      sizeof(sectionNameRaw), NULL);
        if (!NT_SUCCESS(status))
        {
            continue;
        }

        sectionName = (PUNICODE_STRING)sectionNameRaw;
        RtlZeroMemory(sectionPath, sizeof(sectionPath));
        BkstrSafeCopyUnicode(sectionName, sectionPath, RTL_NUMBER_OF(sectionPath));
        RtlInitUnicodeString(&sectionUs, sectionPath);
        if (!BkchdlIsNtdllPath(&sectionUs))
        {
            continue;
        }

        *NtdllBase = mbi.AllocationBase;
        return TRUE;
    }

    return FALSE;
}

static BOOLEAN BkchdlAddressWithinExportWindow(_In_opt_ PVOID Address, _In_opt_ PVOID ExportAddress)
{
    ULONG_PTR address;
    ULONG_PTR exportAddress;

    if (Address == NULL || ExportAddress == NULL)
    {
        return FALSE;
    }

    address = (ULONG_PTR)Address;
    exportAddress = (ULONG_PTR)ExportAddress;
    return address >= exportAddress && (address - exportAddress) < BK_SYSCALL_EXPORT_MATCH_WINDOW_BYTES;
}

static BOOLEAN BkchdlBuildZwAlias(_In_z_ PCSTR ExportName, _Out_writes_(AliasChars) PCHAR Alias, _In_ SIZE_T AliasChars)
{
    SIZE_T i;

    if (ExportName == NULL || Alias == NULL || AliasChars < 3)
    {
        return FALSE;
    }
    if (ExportName[0] != 'N' || ExportName[1] != 't')
    {
        return FALSE;
    }

    Alias[0] = 'Z';
    Alias[1] = 'w';
    for (i = 2; i < AliasChars - 1; ++i)
    {
        Alias[i] = ExportName[i];
        if (ExportName[i] == '\0')
        {
            return TRUE;
        }
    }

    Alias[AliasChars - 1] = '\0';
    return FALSE;
}

static BOOLEAN BkchdlResolveExportSyscallNumber(_In_ PEPROCESS SourceProcess, _In_ PVOID ModuleBase,
                                                _In_z_ PCSTR ExportName, _Out_ ULONG *SyscallNumber,
                                                _Out_opt_ PVOID *ExportAddress)
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
    PVOID resolvedAddress = NULL;

    if (SourceProcess == NULL || ModuleBase == NULL || ExportName == NULL || SyscallNumber == NULL)
    {
        return FALSE;
    }
    if (ExportAddress != NULL)
    {
        *ExportAddress = NULL;
    }

    if (!BkchdlReadProcessBytes(SourceProcess, ModuleBase, &dos, sizeof(dos)))
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

    if (!BkchdlReadProcessBytes(SourceProcess, (const VOID *)((ULONG_PTR)ModuleBase + (ULONG_PTR)dos.e_lfanew), &nt,
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

    if (!BkchdlReadProcessBytes(
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

    nameRvas = (ULONG *)BkpoolAllocateCompat(POOL_FLAG_PAGED, namesSize, 'ndtT');
    ordinals = (USHORT *)BkpoolAllocateCompat(POOL_FLAG_PAGED, ordinalsSize, 'odtT');
    funcRvas = (ULONG *)BkpoolAllocateCompat(POOL_FLAG_PAGED, funcsSize, 'fdtT');
    if (nameRvas == NULL || ordinals == NULL || funcRvas == NULL)
    {
        goto Exit;
    }

    if (!BkchdlReadProcessBytes(SourceProcess, (const VOID *)((ULONG_PTR)ModuleBase + exports.AddressOfNames), nameRvas,
                                namesSize) ||
        !BkchdlReadProcessBytes(SourceProcess, (const VOID *)((ULONG_PTR)ModuleBase + exports.AddressOfNameOrdinals),
                                ordinals, ordinalsSize) ||
        !BkchdlReadProcessBytes(SourceProcess, (const VOID *)((ULONG_PTR)ModuleBase + exports.AddressOfFunctions),
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
        if (!BkchdlReadProcessBytes(SourceProcess, (const VOID *)((ULONG_PTR)ModuleBase + nameRvas[i]), nameBuffer,
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
        if (!BkchdlAsciiEqualsInsensitive(nameBuffer, ExportName))
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
        success = BkchdlExtractSyscallNumberNearAddress(SourceProcess, funcAddress, SyscallNumber);
        if (success)
        {
            resolvedAddress = funcAddress;
        }
        break;
    }

Exit:
    if (success && ExportAddress != NULL)
    {
        *ExportAddress = resolvedAddress;
    }
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

static BOOLEAN BkchdlResolveExpectedSyscallExport(_In_ PEPROCESS SourceProcess, _In_ PVOID NtdllBase,
                                                  _In_z_ PCSTR ExportName, _In_opt_ PVOID OriginAddress,
                                                  _Out_ ULONG *SyscallNumber, _Out_ BOOLEAN *OriginInsideExpectedExport)
{
    ULONG primaryNumber = 0;
    ULONG aliasNumber = 0;
    PVOID primaryAddress = NULL;
    PVOID aliasAddress = NULL;
    CHAR aliasName[64];
    BOOLEAN primaryResolved;
    BOOLEAN aliasResolved = FALSE;
    BOOLEAN primaryInside;
    BOOLEAN aliasInside;

    if (SyscallNumber == NULL || OriginInsideExpectedExport == NULL)
    {
        return FALSE;
    }

    *SyscallNumber = 0;
    *OriginInsideExpectedExport = FALSE;

    primaryResolved =
        BkchdlResolveExportSyscallNumber(SourceProcess, NtdllBase, ExportName, &primaryNumber, &primaryAddress);
    if (BkchdlBuildZwAlias(ExportName, aliasName, RTL_NUMBER_OF(aliasName)))
    {
        aliasResolved =
            BkchdlResolveExportSyscallNumber(SourceProcess, NtdllBase, aliasName, &aliasNumber, &aliasAddress);
    }

    primaryInside = primaryResolved && BkchdlAddressWithinExportWindow(OriginAddress, primaryAddress);
    aliasInside = aliasResolved && BkchdlAddressWithinExportWindow(OriginAddress, aliasAddress);

    if (primaryInside)
    {
        *SyscallNumber = primaryNumber;
        *OriginInsideExpectedExport = TRUE;
        return TRUE;
    }
    if (aliasInside)
    {
        *SyscallNumber = aliasNumber;
        *OriginInsideExpectedExport = TRUE;
        return TRUE;
    }
    if (primaryResolved)
    {
        *SyscallNumber = primaryNumber;
        return TRUE;
    }
    if (aliasResolved)
    {
        *SyscallNumber = aliasNumber;
        return TRUE;
    }

    return FALSE;
}

static BOOLEAN BkchdlQueryFrameModuleInfo(_In_ HANDLE ProcessHandle, _In_ PVOID Frame, _Out_ PVOID *AllocationBase,
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
    status = ZwQueryVirtualMemory(ProcessHandle, Frame, BkchdlMemoryBasicInformation, &mbi, sizeof(mbi), NULL);
    if (!NT_SUCCESS(status))
    {
        return FALSE;
    }

    *AllocationBase = mbi.AllocationBase;
    *Executable = (mbi.State == MEM_COMMIT) && BkprotIsExecutableProtection(mbi.Protect);
    *ImageBacked = (mbi.Type == MEM_IMAGE);
    if (mbi.AllocationBase == NULL)
    {
        return TRUE;
    }

    RtlZeroMemory(sectionNameRaw, sizeof(sectionNameRaw));
    status = ZwQueryVirtualMemory(ProcessHandle, Frame, BkchdlMemorySectionName, sectionNameRaw, sizeof(sectionNameRaw),
                                  NULL);
    if (!NT_SUCCESS(status))
    {
        return TRUE;
    }

    sectionName = (PUNICODE_STRING)sectionNameRaw;
    RtlZeroMemory(sectionPath, sizeof(sectionPath));
    BkstrSafeCopyUnicode(sectionName, sectionPath, RTL_NUMBER_OF(sectionPath));
    RtlInitUnicodeString(&sectionUs, sectionPath);
    *IsSyscallStubModule = BkchdlIsSyscallStubModulePath(&sectionUs);
    return TRUE;
}

static BOOLEAN BkchdlValidateModuleChainSanity(_In_ HANDLE ProcessHandle, _In_ ULONG FrameCount,
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

        if (!BkchdlQueryFrameModuleInfo(ProcessHandle, Frames[i], &frameBase, &exec, &image, &isSyscallStubModule))
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

static BOOLEAN BkchdlModuleContainsUnwindForRva(_In_ PEPROCESS SourceProcess, _In_ PVOID ModuleBase, _In_ ULONG Rva)
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

    if (!BkchdlReadProcessBytes(SourceProcess, ModuleBase, &dos, sizeof(dos)) || dos.e_magic != IMAGE_DOS_SIGNATURE ||
        dos.e_lfanew <= 0 || dos.e_lfanew > 0x2000)
    {
        return FALSE;
    }

    if (!BkchdlReadProcessBytes(SourceProcess, (const VOID *)((ULONG_PTR)ModuleBase + (ULONG_PTR)dos.e_lfanew), &nt,
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
    table = (IMAGE_RUNTIME_FUNCTION_ENTRY *)BkpoolAllocateCompat(POOL_FLAG_PAGED, tableBytes, 'udtT');
    if (table == NULL)
    {
        return FALSE;
    }

    if (!BkchdlReadProcessBytes(SourceProcess, (const VOID *)((ULONG_PTR)ModuleBase + exceptionRva), table, tableBytes))
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

static BOOLEAN BkchdlValidateUnwindMetadata(_In_ HANDLE ProcessHandle, _In_ PEPROCESS SourceProcess,
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
        status = ZwQueryVirtualMemory(ProcessHandle, Frames[i], BkchdlMemoryBasicInformation, &mbi, sizeof(mbi), NULL);
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
        if (!BkchdlModuleContainsUnwindForRva(SourceProcess, mbi.AllocationBase, rva))
        {
            return FALSE;
        }
    }

    return TRUE;
}

static BOOLEAN BkchdlQueryTebStackBounds(_In_ HANDLE CallerProcessId, _In_ HANDLE CallerThreadId,
                                         _In_ PEPROCESS SourceProcess, _Out_ ULONG_PTR *StackLimit,
                                         _Out_ ULONG_PTR *StackBase)
{
    OBJECT_ATTRIBUTES oa;
    CLIENT_ID cid;
    HANDLE threadHandle = NULL;
    BK_THREAD_BASIC_INFORMATION tbi;
    BK_NT_TIB tib;
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
    if (!BkchdlReadProcessBytes(SourceProcess, tbi.TebBaseAddress, &tib, sizeof(tib)))
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

static BOOLEAN BkchdlFramesOutsideStackBounds(_In_ ULONG FrameCount, _In_reads_(FrameCount) PVOID *Frames,
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

static PCSTR BkchdlClassToString(_In_ BK_HANDLE_CLASSIFICATION Class)
{
    if (Class == BkchdlHandleLegitimateSyscall)
    {
        return "LEGITIMATE-SYSCALL";
    }
    if (Class == BkchdlHandleDirectSyscallSuspect)
    {
        return "DIRECT-SYSCALL-SUSPECT";
    }
    return "UNKNOWN-ORIGIN";
}

static BOOLEAN BkchdlHandleAccessIsHighRisk(_In_ ACCESS_MASK DesiredAccess, _In_ BOOLEAN IsThreadObject)
{
    if (IsThreadObject)
    {
        return ((DesiredAccess & THREAD_SET_CONTEXT) != 0) || ((DesiredAccess & THREAD_SUSPEND_RESUME) != 0) ||
               ((DesiredAccess & THREAD_GET_CONTEXT) != 0) || ((DesiredAccess & THREAD_QUERY_INFORMATION) != 0) ||
               ((DesiredAccess & THREAD_ALL_ACCESS) == THREAD_ALL_ACCESS);
    }

    return ((DesiredAccess & PROCESS_VM_OPERATION) != 0) || ((DesiredAccess & PROCESS_VM_WRITE) != 0) ||
           ((DesiredAccess & PROCESS_CREATE_THREAD) != 0) || ((DesiredAccess & PROCESS_DUP_HANDLE) != 0) ||
           ((DesiredAccess & PROCESS_ALL_ACCESS) == PROCESS_ALL_ACCESS);
}

static UINT32 BkchdlClassifyEnterpriseTargetName(_In_opt_z_ PCSTR ImageName)
{
    UINT32 flags = 0;

    if (ImageName == NULL)
    {
        return 0;
    }

    if (BkchdlAsciiEqualsInsensitive(ImageName, "lsass.exe"))
    {
        return BK_ENTERPRISE_FLAG_CREDENTIAL_PROCESS | BK_ENTERPRISE_FLAG_PRIVILEGED_TARGET |
               BK_ENTERPRISE_FLAG_LSASS_TARGET | BK_ENTERPRISE_FLAG_KERBEROS_NTLM;
    }
    if (BkchdlAsciiEqualsInsensitive(ImageName, "lsaiso.exe"))
    {
        return BK_ENTERPRISE_FLAG_CREDENTIAL_PROCESS | BK_ENTERPRISE_FLAG_PRIVILEGED_TARGET |
               BK_ENTERPRISE_FLAG_KERBEROS_NTLM;
    }
    if (BkchdlAsciiEqualsInsensitive(ImageName, "winlogon.exe"))
    {
        return BK_ENTERPRISE_FLAG_CREDENTIAL_PROCESS | BK_ENTERPRISE_FLAG_PRIVILEGED_TARGET |
               BK_ENTERPRISE_FLAG_WINLOGON_TARGET;
    }

    if (BkchdlAsciiEqualsInsensitive(ImageName, "services.exe") ||
        BkchdlAsciiEqualsInsensitive(ImageName, "wininit.exe") ||
        BkchdlAsciiEqualsInsensitive(ImageName, "csrss.exe") || BkchdlAsciiEqualsInsensitive(ImageName, "smss.exe"))
    {
        flags |= BK_ENTERPRISE_FLAG_PRIVILEGED_TARGET;
    }

    return flags;
}

static BOOLEAN BkchdlProcessAccessIsCredentialRelevant(_In_ ACCESS_MASK DesiredAccess)
{
    return ((DesiredAccess & (PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD |
                              PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION)) !=
            0) ||
           ((DesiredAccess & PROCESS_ALL_ACCESS) == PROCESS_ALL_ACCESS);
}

static BOOLEAN BkchdlProcessAccessIsPrivilegeRelevant(_In_ ACCESS_MASK DesiredAccess)
{
    return ((DesiredAccess & (PROCESS_TERMINATE | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE |
                              PROCESS_DUP_HANDLE | PROCESS_CREATE_PROCESS | PROCESS_SET_INFORMATION)) != 0) ||
           ((DesiredAccess & PROCESS_ALL_ACCESS) == PROCESS_ALL_ACCESS);
}

static UINT32 BkchdlEnterpriseAccessFlags(_In_ ACCESS_MASK DesiredAccess, _In_ BOOLEAN IsThreadObject,
                                          _In_ BOOLEAN IsDuplicateOperation)
{
    UINT32 flags = IsThreadObject ? BK_ENTERPRISE_FLAG_THREAD_OBJECT : BK_ENTERPRISE_FLAG_PROCESS_OBJECT;

    if (IsDuplicateOperation)
    {
        flags |= BK_ENTERPRISE_FLAG_DUPLICATE_HANDLE;
    }
    if ((DesiredAccess & PROCESS_VM_READ) != 0)
    {
        flags |= BK_ENTERPRISE_FLAG_VM_READ;
    }
    if ((DesiredAccess & PROCESS_VM_WRITE) != 0)
    {
        flags |= BK_ENTERPRISE_FLAG_VM_WRITE;
    }
    if ((DesiredAccess & PROCESS_VM_OPERATION) != 0)
    {
        flags |= BK_ENTERPRISE_FLAG_VM_OPERATION;
    }
    if ((DesiredAccess & PROCESS_CREATE_THREAD) != 0)
    {
        flags |= BK_ENTERPRISE_FLAG_CREATE_THREAD;
    }
    if ((DesiredAccess & (PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION | THREAD_QUERY_INFORMATION |
                          THREAD_QUERY_LIMITED_INFORMATION)) != 0)
    {
        flags |= BK_ENTERPRISE_FLAG_QUERY_ACCESS;
    }
    if ((DesiredAccess & (THREAD_SET_CONTEXT | THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME)) != 0)
    {
        flags |= BK_ENTERPRISE_FLAG_THREAD_CONTEXT;
    }
    if ((DesiredAccess & (PROCESS_TERMINATE | PROCESS_SET_INFORMATION)) != 0)
    {
        flags |= BK_ENTERPRISE_FLAG_SET_OR_TERMINATE;
    }

    return flags;
}

static BOOLEAN BkchdlProcessEnterpriseCandidate(_In_ PEPROCESS TargetProcess, _In_ HANDLE CallerPid,
                                                _In_ HANDLE TargetPid, _In_ ACCESS_MASK DesiredAccess)
{
    UINT32 targetFlags;
    PCHAR imageName;

    if (TargetProcess == NULL || CallerPid == TargetPid)
    {
        return FALSE;
    }

    imageName = PsGetProcessImageFileName(TargetProcess);
    targetFlags = BkchdlClassifyEnterpriseTargetName(imageName);
    if ((targetFlags & BK_ENTERPRISE_FLAG_CREDENTIAL_PROCESS) != 0)
    {
        return BkchdlProcessAccessIsCredentialRelevant(DesiredAccess);
    }
    if ((targetFlags & BK_ENTERPRISE_FLAG_PRIVILEGED_TARGET) != 0)
    {
        return BkchdlProcessAccessIsPrivilegeRelevant(DesiredAccess);
    }

    return FALSE;
}

static VOID BkchdlPublishEnterpriseHandleEvent(_In_ BK_HANDLE_CLASSIFICATION Class, _In_ HANDLE CallerPid,
                                               _In_ HANDLE CallerTid, _In_ HANDLE TargetPid, _In_ HANDLE TargetTid,
                                               _In_ UINT64 ObjectAddress, _In_ ACCESS_MASK DesiredAccess,
                                               _In_ BOOLEAN IsThreadObject, _In_ BOOLEAN IsDuplicateOperation,
                                               _In_ const BK_HANDLE_TELEMETRY *Telemetry)
{
    PEPROCESS targetProcess = NULL;
    PCHAR imageName;
    UINT32 targetFlags;
    UINT32 flags;
    BK_ENTERPRISE_EVENT event;
    UINT32 callerPid32 = (UINT32)(ULONG_PTR)CallerPid;
    UINT32 targetPid32 = (UINT32)(ULONG_PTR)TargetPid;

    if (CallerPid == TargetPid || callerPid32 == 0 || targetPid32 == 0)
    {
        return;
    }
    if (!BkctlHasPidInterest(callerPid32, targetPid32, BK_STREAM_ENTERPRISE))
    {
        return;
    }

    if (!NT_SUCCESS(PsLookupProcessByProcessId(TargetPid, &targetProcess)))
    {
        return;
    }

    imageName = PsGetProcessImageFileName(targetProcess);
    targetFlags = BkchdlClassifyEnterpriseTargetName(imageName);
    if ((targetFlags & BK_ENTERPRISE_FLAG_CREDENTIAL_PROCESS) != 0)
    {
        if (!BkchdlProcessAccessIsCredentialRelevant(DesiredAccess))
        {
            ObDereferenceObject(targetProcess);
            return;
        }
    }
    else if ((targetFlags & BK_ENTERPRISE_FLAG_PRIVILEGED_TARGET) != 0)
    {
        if (!IsThreadObject && !BkchdlProcessAccessIsPrivilegeRelevant(DesiredAccess))
        {
            ObDereferenceObject(targetProcess);
            return;
        }
    }
    else
    {
        ObDereferenceObject(targetProcess);
        return;
    }

    flags = BK_ENTERPRISE_FLAG_HIGH_SIGNAL |
            BkchdlEnterpriseAccessFlags(DesiredAccess, IsThreadObject, IsDuplicateOperation) | targetFlags;
    if ((targetFlags & BK_ENTERPRISE_FLAG_CREDENTIAL_PROCESS) != 0)
    {
        flags |= BK_ENTERPRISE_FLAG_CRITICAL;
    }
    if (Class == BkchdlHandleDirectSyscallSuspect)
    {
        flags |= BK_ENTERPRISE_FLAG_DIRECT_SYSCALL_SUSPECT;
    }

    RtlZeroMemory(&event, sizeof(event));
    event.ProcessId = (UINT64)(ULONG_PTR)CallerPid;
    event.ThreadId = (UINT64)(ULONG_PTR)CallerTid;
    event.TargetProcessId = (UINT64)(ULONG_PTR)TargetPid;
    event.TargetThreadId = (UINT64)(ULONG_PTR)TargetTid;
    event.ObjectAddress = ObjectAddress;
    event.Aux0 = (Telemetry != NULL) ? (UINT64)(ULONG_PTR)Telemetry->OriginAddress : 0;
    event.Aux1 = (Telemetry != NULL) ? Telemetry->CaptureFlags : 0;
    event.Operation = ((targetFlags & BK_ENTERPRISE_FLAG_CREDENTIAL_PROCESS) != 0)
                          ? BkEnterpriseOperationProcessCredentialAccess
                          : BkEnterpriseOperationProcessPrivilegedAccess;
    event.SubOperation = (Class == BkchdlHandleDirectSyscallSuspect) ? BlackbirdHandleClassDirectSyscallSuspect
                                                                     : BlackbirdHandleClassUnknown;
    event.Flags = flags;
    event.DesiredAccess = (UINT32)DesiredAccess;
    BkctlPublishEnterpriseEvent(&event);
    ObDereferenceObject(targetProcess);
}

static UINT32 BkchdlCountHandleAnomalySignals(_In_ BOOLEAN ExecProtect, _In_ BOOLEAN FromSyscallModule,
                                              _In_ const BK_HANDLE_TELEMETRY *Telemetry)
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

static VOID BkchdlLogHandleTelemetry(_In_ BK_HANDLE_CLASSIFICATION Class, _In_ HANDLE CallerPid, _In_ HANDLE CallerTid,
                                     _In_ HANDLE TargetPid, _In_ HANDLE TargetTid, _In_ UINT64 ObjectAddress,
                                     _In_ ACCESS_MASK DesiredAccess, _In_ BOOLEAN IsThreadObject,
                                     _In_ BOOLEAN IsDuplicateOperation, _In_ BOOLEAN ExecProtect,
                                     _In_ BOOLEAN FromNtdll, _In_ BOOLEAN FromExe, _In_ PBK_HANDLE_TELEMETRY Telemetry)
{
    UINT32 flags = 0;
    BOOLEAN memoryRelated;
    BOOLEAN stackIntegrityAnomaly;
    BOOLEAN highRiskAccess;
    BOOLEAN fromSyscallModule;
    BOOLEAN directSyscallEntryAnomaly;
    UINT32 anomalySignals;
    UINT32 classId;
    UINT32 handleStream;
    UNICODE_STRING originPathUs;
    BK_HANDLE_EVENT handleEvent;
    UINT32 i;
    UINT32 safeFrameCount;
    UINT32 safeFullFrameCount;
    UINT32 safeStackBytes;

    BketwLogHandleEvent(BkchdlClassToString(Class), CallerPid, TargetPid, DesiredAccess, Telemetry->OriginAddress,
                        Telemetry->OriginProtect, ExecProtect, FromNtdll, FromExe,
                        (Telemetry->OriginPath[0] != L'\0') ? Telemetry->OriginPath : NULL, Telemetry->FrameCount,
                        Telemetry->Frames, Telemetry->OpenProcessStatus, Telemetry->BasicInfoStatus,
                        Telemetry->SectionNameStatus, (UINT64)(ULONG_PTR)Telemetry->AllocationBase,
                        (UINT64)Telemetry->RegionSize, Telemetry->OriginProtect, Telemetry->RegionState,
                        Telemetry->RegionType, Telemetry->DeepSampleSize, Telemetry->DeepSample);

    if (ExecProtect)
    {
        flags |= BK_HANDLE_FLAG_EXEC_PROTECT;
    }
    if (FromNtdll)
    {
        flags |= BK_HANDLE_FLAG_FROM_NTDLL;
    }
    if (FromExe)
    {
        flags |= BK_HANDLE_FLAG_FROM_EXE;
    }

    memoryRelated = ((DesiredAccess & PROCESS_VM_OPERATION) != 0) || ((DesiredAccess & PROCESS_VM_READ) != 0) ||
                    ((DesiredAccess & PROCESS_VM_WRITE) != 0) || ((DesiredAccess & PROCESS_CREATE_THREAD) != 0) ||
                    ((DesiredAccess & PROCESS_DUP_HANDLE) != 0) ||
                    ((DesiredAccess & PROCESS_ALL_ACCESS) == PROCESS_ALL_ACCESS);
    highRiskAccess = BkchdlHandleAccessIsHighRisk(DesiredAccess, IsThreadObject);
    RtlInitUnicodeString(&originPathUs, Telemetry->OriginPath);
    fromSyscallModule = BkchdlIsSyscallStubModulePath(&originPathUs);
    anomalySignals = BkchdlCountHandleAnomalySignals(ExecProtect, fromSyscallModule, Telemetry);
    directSyscallEntryAnomaly =
        ExecProtect && (!fromSyscallModule || (Telemetry->SyscallExportChecked && !Telemetry->SyscallExportMatch));
    if (memoryRelated)
    {
        flags |= BK_HANDLE_FLAG_MEMORY_RELATED;
    }
    if (IsThreadObject)
    {
        flags |= BK_HANDLE_FLAG_THREAD_OBJECT;
    }
    if (IsDuplicateOperation)
    {
        flags |= BK_HANDLE_FLAG_DUPLICATE_OPERATION;
    }
    if (Telemetry->DeepPathCandidate)
    {
        flags |= BK_HANDLE_FLAG_DEEP_PATH_CANDIDATE;
    }
    if (Telemetry->DeepPathCaptured)
    {
        flags |= BK_HANDLE_FLAG_DEEP_PATH_CAPTURED;
    }
    if (Telemetry->DeepPathCacheHit)
    {
        flags |= BK_HANDLE_FLAG_DEEP_PATH_CACHE_HIT;
    }
    if (Telemetry->ReturnAddressValid)
    {
        flags |= BK_HANDLE_FLAG_RETURN_ADDRESS_VALID;
    }
    if (Telemetry->StackValidated)
    {
        flags |= BK_HANDLE_FLAG_STACK_VALIDATED;
    }
    if (Telemetry->StackSpoofSuspect)
    {
        flags |= BK_HANDLE_FLAG_STACK_SPOOF_SUSPECT;
    }
    if (Telemetry->SyscallExportChecked && Telemetry->SyscallExportMatch)
    {
        flags |= BK_HANDLE_FLAG_SYSCALL_EXPORT_MATCH;
    }
    if (Telemetry->SyscallExportChecked && !Telemetry->SyscallExportMatch)
    {
        flags |= BK_HANDLE_FLAG_SYSCALL_EXPORT_MISMATCH;
    }
    if (Telemetry->ModuleChainChecked && Telemetry->ModuleChainSane)
    {
        flags |= BK_HANDLE_FLAG_MODULE_CHAIN_SANE;
    }
    if (Telemetry->UnwindMetadataChecked && Telemetry->UnwindMetadataValid)
    {
        flags |= BK_HANDLE_FLAG_UNWIND_METADATA_VALID;
    }
    if (Telemetry->TebStackBoundsChecked && Telemetry->TebStackBoundsValid)
    {
        flags |= BK_HANDLE_FLAG_TEB_STACK_BOUNDS_VALID;
    }
    if (Telemetry->TebStackBoundsChecked && Telemetry->FramesOutsideTebStack)
    {
        flags |= BK_HANDLE_FLAG_FRAMES_OUTSIDE_TEB_STACK;
    }

    classId = BlackbirdHandleClassUnknown;
    if (Class == BkchdlHandleLegitimateSyscall)
    {
        classId = BlackbirdHandleClassLegitimateSyscall;
    }
    else if (Class == BkchdlHandleDirectSyscallSuspect)
    {
        classId = BlackbirdHandleClassDirectSyscallSuspect;
    }

    if (Class == BkchdlHandleDirectSyscallSuspect && highRiskAccess &&
        (directSyscallEntryAnomaly || anomalySignals >= 2))
    {
        BketwLogDetectionEvent(
            "DIRECT_SYSCALL_SUSPECT_HANDLE_OPERATION", 5, CallerPid, TargetPid, 0, (UINT32)DesiredAccess, 0,
            L"high-risk handle operation reached the kernel from outside the expected ntdll syscall export");
    }

    stackIntegrityAnomaly =
        (Telemetry->StackSpoofSuspect || !Telemetry->StackValidated || !Telemetry->ReturnAddressValid ||
         (Telemetry->ModuleChainChecked && !Telemetry->ModuleChainSane) ||
         (Telemetry->UnwindMetadataChecked && !Telemetry->UnwindMetadataValid) ||
         (Telemetry->TebStackBoundsChecked && (!Telemetry->TebStackBoundsValid || !Telemetry->FramesOutsideTebStack)));
    if (stackIntegrityAnomaly && (Class == BkchdlHandleDirectSyscallSuspect) && highRiskAccess && anomalySignals >= 3 &&
        CallerPid != TargetPid)
    {
        BketwLogDetectionEvent("STACK_INTEGRITY_ANOMALY_ON_HANDLE_OP", 6, CallerPid, TargetPid, 0,
                               (UINT32)DesiredAccess, 0,
                               L"high-confidence stack integrity anomaly on high-risk handle operation");
    }

    /* Credential-access: process-memory handle to lsass.exe */
    if (!IsThreadObject &&
        (DesiredAccess & (PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD)) != 0 &&
        CallerPid != TargetPid)
    {
        PEPROCESS targetProc = NULL;
        NTSTATUS lookupSt = PsLookupProcessByProcessId(TargetPid, &targetProc);
        if (NT_SUCCESS(lookupSt))
        {
            PCHAR imageName = PsGetProcessImageFileName(targetProc);
            if (imageName != NULL)
            {
                /* Case-insensitive byte compare against "lsass.exe" */
                static const CHAR kLsass[] = "lsass.exe";
                BOOLEAN isLsass = TRUE;
                ULONG ci;
                for (ci = 0; ci < sizeof(kLsass) - 1u; ++ci)
                {
                    CHAR c = imageName[ci];
                    if (c >= 'A' && c <= 'Z')
                        c = (CHAR)(c + 32);
                    if (c != kLsass[ci])
                    {
                        isLsass = FALSE;
                        break;
                    }
                }
                if (isLsass && imageName[sizeof(kLsass) - 1u] == '\0')
                {
                    ULONG sev = (Class == BkchdlHandleDirectSyscallSuspect) ? 8u : 7u;
                    BketwLogDetectionEvent("CREDENTIAL_ACCESS_LSASS_HANDLE", sev, CallerPid, TargetPid, 0,
                                           (UINT32)DesiredAccess, 0,
                                           L"cross-process memory handle to lsass.exe — credential access attempt");
                }

                /* Winlogon memory access is also high-value — holds logon tokens */
                {
                    static const CHAR kWinlogon[] = "winlogon.exe";
                    BOOLEAN isWinlogon = TRUE;
                    for (ci = 0; ci < sizeof(kWinlogon) - 1u; ++ci)
                    {
                        CHAR c = imageName[ci];
                        if (c >= 'A' && c <= 'Z')
                            c = (CHAR)(c + 32);
                        if (c != kWinlogon[ci])
                        {
                            isWinlogon = FALSE;
                            break;
                        }
                    }
                    if (isWinlogon && imageName[sizeof(kWinlogon) - 1u] == '\0' &&
                        (DesiredAccess & (PROCESS_VM_READ | PROCESS_VM_WRITE)) != 0)
                    {
                        BketwLogDetectionEvent("CREDENTIAL_ACCESS_WINLOGON_HANDLE", 6, CallerPid, TargetPid, 0,
                                               (UINT32)DesiredAccess, 0,
                                               L"cross-process memory handle to winlogon.exe");
                    }
                }
            }
            ObDereferenceObject(targetProc);
        }
    }

    /* Hardware breakpoint register detection.
     * DR7 enable bits: L0/G0=0x3, L1/G1=0xC, L2/G2=0x30, L3/G3=0xC0 */
    if (Telemetry->CaptureFlags & BK_HANDLE_CAPTURE_DEBUG_REGS_VALID)
    {
        UINT32 dr7EnableBits = (UINT32)(Telemetry->RegDr7 & 0xFFu);
        UINT32 activeCount = 0;
        if ((dr7EnableBits & 0x03u) && Telemetry->RegDr0 != 0)
            activeCount++;
        if ((dr7EnableBits & 0x0Cu) && Telemetry->RegDr1 != 0)
            activeCount++;
        if ((dr7EnableBits & 0x30u) && Telemetry->RegDr2 != 0)
            activeCount++;
        if ((dr7EnableBits & 0xC0u) && Telemetry->RegDr3 != 0)
            activeCount++;
        if (activeCount == 4)
        {
            BketwLogDetectionEvent(
                "HW_BREAKPOINT_SATURATION", 6, CallerPid, TargetPid, activeCount, (UINT32)Telemetry->RegDr7, 0,
                L"all four hardware breakpoint registers occupied — possible anti-debug or memory breakpoint abuse");
        }
        else if (activeCount >= 1)
        {
            BketwLogDetectionEvent("HARDWARE_BREAKPOINT_HOGGING", 5, CallerPid, TargetPid, activeCount,
                                   (UINT32)Telemetry->RegDr7, 0,
                                   L"hardware breakpoint register(s) occupied on process making sensitive handle call");
        }
    }

    BkchdlPublishEnterpriseHandleEvent(Class, CallerPid, CallerTid, TargetPid, TargetTid, ObjectAddress, DesiredAccess,
                                       IsThreadObject, IsDuplicateOperation, Telemetry);

    handleStream = BK_STREAM_HANDLE;
    if (memoryRelated)
    {
        handleStream |= BK_STREAM_MEMORY;
    }
    if (BkctlHasPidInterest(
            (UINT32)(ULONG_PTR)CallerPid,
            ((UINT32)(ULONG_PTR)TargetPid != (UINT32)(ULONG_PTR)CallerPid) ? (UINT32)(ULONG_PTR)TargetPid : 0,
            handleStream))
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

        BkctlPublishHandleEvent(&handleEvent);
    }
}

static VOID BkchdlCaptureDeepPathData(_In_ HANDLE CallerProcessId, _In_ BOOLEAN ShouldCapture,
                                      _In_ const MEMORY_BASIC_INFORMATION *Mbi, _In_opt_ const BK_HANDLE_WORK *Work,
                                      _Inout_ PBK_HANDLE_TELEMETRY Telemetry)
{
    NTSTATUS status;
    PEPROCESS sourceProcess = NULL;
    PEPROCESS localProcess;
    SIZE_T bytesRead = 0;
    SIZE_T bytesToRead;
    ULONG_PTR regionBase;
    ULONG_PTR sampleAddress;
    ULONG_PTR regionOffset;
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
        BkchdlDeepCacheStore(CallerProcessId, Mbi->BaseAddress, Telemetry->OriginAddress, Mbi->RegionSize, Mbi->Protect,
                             Mbi->State, Mbi->Type, Telemetry->DeepSample, Telemetry->DeepSampleSize);
        return;
    }

    if (Mbi->BaseAddress == NULL || Mbi->RegionSize == 0)
    {
        return;
    }

    if (BkchdlDeepCacheLookup(CallerProcessId, Mbi->BaseAddress,
                              (Telemetry->OriginAddress != NULL) ? Telemetry->OriginAddress : Mbi->BaseAddress,
                              Mbi->RegionSize, Mbi->Protect, Mbi->State, Mbi->Type, Telemetry->DeepSample, &sampleSize))
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

    sampleAddress =
        (Telemetry->OriginAddress != NULL) ? (ULONG_PTR)Telemetry->OriginAddress : (ULONG_PTR)Mbi->BaseAddress;
    regionBase = (ULONG_PTR)Mbi->BaseAddress;
    if (sampleAddress < regionBase || Mbi->RegionSize == 0)
    {
        ObDereferenceObject(sourceProcess);
        return;
    }

    regionOffset = sampleAddress - regionBase;
    if (regionOffset >= Mbi->RegionSize)
    {
        ObDereferenceObject(sourceProcess);
        return;
    }

    bytesToRead = Mbi->RegionSize - regionOffset;
    if (bytesToRead > sizeof(Telemetry->DeepSample))
    {
        bytesToRead = sizeof(Telemetry->DeepSample);
    }
    if (bytesToRead == 0)
    {
        ObDereferenceObject(sourceProcess);
        return;
    }

    localProcess = PsGetCurrentProcess();
    status = MmCopyVirtualMemory(sourceProcess, (const VOID *)sampleAddress, localProcess, Telemetry->DeepSample,
                                 bytesToRead, KernelMode, &bytesRead);
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
    BkchdlDeepCacheStore(CallerProcessId, Mbi->BaseAddress,
                         (Telemetry->OriginAddress != NULL) ? Telemetry->OriginAddress : Mbi->BaseAddress,
                         Mbi->RegionSize, Mbi->Protect, Mbi->State, Mbi->Type, Telemetry->DeepSample,
                         Telemetry->DeepSampleSize);
}

static VOID BkchdlClassifyUserOrigin(_In_ HANDLE CallerProcessId, _In_ HANDLE CallerThreadId,
                                     _In_ BOOLEAN IsThreadObject, _In_ BOOLEAN IsDuplicateOperation,
                                     _In_ ULONG FrameCount, _In_reads_(FrameCount) PVOID *Frames,
                                     _In_opt_ const BK_HANDLE_WORK *Work, _Out_ PBK_HANDLE_TELEMETRY Telemetry)
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
    BOOLEAN originInsideExpectedExport;
    ULONG_PTR stackLimit;
    ULONG_PTR stackBase;

    RtlZeroMemory(Telemetry, sizeof(*Telemetry));
    Telemetry->OpenProcessStatus = STATUS_UNSUCCESSFUL;
    Telemetry->BasicInfoStatus = STATUS_UNSUCCESSFUL;
    Telemetry->SectionNameStatus = STATUS_UNSUCCESSFUL;
    BkchdlApplyWorkCaptureToTelemetry(Work, Telemetry);

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
        BK_DBG_PRINT(DPFLTR_TRACE_LEVEL, "BK[DBG]: ZwOpenProcess failed callerPid=%p status=0x%08X.\n", CallerProcessId,
                     (ULONG)status);
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
    status = ZwQueryVirtualMemory(processHandle, Telemetry->OriginAddress, BkchdlMemoryBasicInformation, &mbi,
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
        BK_DBG_PRINT(DPFLTR_TRACE_LEVEL, "BK[DBG]: ZwQueryVirtualMemory(basic) failed callerPid=%p status=0x%08X.\n",
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
    status = ZwQueryVirtualMemory(processHandle, Telemetry->OriginAddress, BkchdlMemorySectionName, sectionNameRaw,
                                  sizeof(sectionNameRaw), NULL);
    Telemetry->SectionNameStatus = status;
    if (NT_SUCCESS(status))
    {
        sectionName = (PUNICODE_STRING)sectionNameRaw;
        BkstrSafeCopyUnicode(sectionName, Telemetry->OriginPath, RTL_NUMBER_OF(Telemetry->OriginPath));
    }
    else
    {
        BK_DBG_PRINT(DPFLTR_TRACE_LEVEL, "BK[DBG]: ZwQueryVirtualMemory(section) failed callerPid=%p status=0x%08X.\n",
                     CallerProcessId, (ULONG)status);
    }

    RtlInitUnicodeString(&originPathUs, Telemetry->OriginPath);
    execProtect = BkprotIsExecutableProtection(Telemetry->OriginProtect);
    fromNtdll = BkchdlIsNtdllPath(&originPathUs);
    fromSyscallModule = BkchdlIsSyscallStubModulePath(&originPathUs);
    // Capture sample bytes for executable origins, including ntdll/win32u stubs, so UI can disassemble real origin
    // bytes.
    deepPathGate = execProtect;
    BkchdlCaptureDeepPathData(CallerProcessId, deepPathGate, &mbi, Work, Telemetry);

    Telemetry->StackValidated = BkchdlValidateStackFrames(processHandle, Telemetry->FrameCount, Telemetry->Frames,
                                                          &Telemetry->StackSpoofSuspect);
    if (sourceProcess != NULL && Telemetry->FrameCount > 1 && Telemetry->Frames[1] != NULL)
    {
        Telemetry->ReturnAddressValid = BkchdlValidateReturnAddress(sourceProcess, Telemetry->Frames[1]);
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
        (void)BkchdlGetNtdllBaseFromFrames(processHandle, Telemetry->FrameCount, Telemetry->Frames, &ntdllBase);
    }

    expectedExportName = BkchdlGetExpectedSyscallExport(IsThreadObject, IsDuplicateOperation);
    hasExpectedSyscall =
        BkchdlResolveExpectedSyscallExport(sourceProcess, ntdllBase, expectedExportName, Telemetry->OriginAddress,
                                           &expectedSyscallNumber, &originInsideExpectedExport);
    hasObservedSyscall =
        BkchdlExtractSyscallNumberNearAddress(sourceProcess, Telemetry->OriginAddress, &observedSyscallNumber);
    Telemetry->SyscallExportChecked = hasExpectedSyscall;
    Telemetry->SyscallExportMatch = fromNtdll && originInsideExpectedExport && hasExpectedSyscall &&
                                    hasObservedSyscall && (expectedSyscallNumber == observedSyscallNumber);

    Telemetry->ModuleChainChecked = TRUE;
    Telemetry->ModuleChainSane =
        BkchdlValidateModuleChainSanity(processHandle, Telemetry->FrameCount, Telemetry->Frames);

    Telemetry->UnwindMetadataChecked = (sourceProcess != NULL);
    Telemetry->UnwindMetadataValid =
        Telemetry->UnwindMetadataChecked &&
        BkchdlValidateUnwindMetadata(processHandle, sourceProcess, Telemetry->FrameCount, Telemetry->Frames);

    stackLimit = 0;
    stackBase = 0;
    Telemetry->TebStackBoundsChecked = (sourceProcess != NULL && CallerThreadId != NULL);
    Telemetry->TebStackBoundsValid =
        Telemetry->TebStackBoundsChecked &&
        BkchdlQueryTebStackBounds(CallerProcessId, CallerThreadId, sourceProcess, &stackLimit, &stackBase);
    Telemetry->FramesOutsideTebStack =
        Telemetry->TebStackBoundsValid &&
        BkchdlFramesOutsideStackBounds(Telemetry->FrameCount, Telemetry->Frames, stackLimit, stackBase);

    if (sourceProcess != NULL && (Telemetry->CaptureFlags & BK_HANDLE_CAPTURE_CONTEXT_VALID) != 0 &&
        Telemetry->RegRsp != 0)
    {
        BkchdlCaptureStackSnapshot(sourceProcess, Telemetry->RegRsp, Telemetry);
    }

    if (sourceProcess != NULL)
    {
        ObDereferenceObject(sourceProcess);
    }
    ZwClose(processHandle);
}

static VOID BkchdlHandleWorkRoutine(_In_ PVOID Context)
{
    PBK_HANDLE_WORK work = (PBK_HANDLE_WORK)Context;
    BK_HANDLE_TELEMETRY telemetry;
    UNICODE_STRING originPathUs;
    BOOLEAN execProtect;
    BOOLEAN fromNtdll;
    BOOLEAN fromSyscallModule;
    BOOLEAN fromExe;
    BOOLEAN highRiskAccess;
    BOOLEAN directSyscallEntryAnomaly;
    UINT32 anomalySignals;
    BK_HANDLE_CLASSIFICATION classification = BkchdlHandleUnknown;

    PAGED_CODE();
    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        goto Exit;
    }
    if (InterlockedCompareExchange(&g_HandleMonitorStopping, 0, 0) != 0)
    {
        goto Exit;
    }
    if (!BkctlIsArmedFast())
    {
        goto Exit;
    }

    BkchdlClassifyUserOrigin(work->CallerPid, work->CallerTid, work->IsThreadObject, work->IsDuplicateOperation,
                             work->FrameCount, work->Frames, work, &telemetry);

    RtlInitUnicodeString(&originPathUs, telemetry.OriginPath);
    execProtect = BkprotIsExecutableProtection(telemetry.OriginProtect);

    fromNtdll = BkchdlIsNtdllPath(&originPathUs);
    fromSyscallModule = BkchdlIsSyscallStubModulePath(&originPathUs);
    fromExe = BkstrUnicodeContainsInsensitive(&originPathUs, L".exe", 4);
    highRiskAccess = BkchdlHandleAccessIsHighRisk(work->DesiredAccess, work->IsThreadObject);
    anomalySignals = BkchdlCountHandleAnomalySignals(execProtect, fromSyscallModule, &telemetry);
    directSyscallEntryAnomaly =
        execProtect && (!fromSyscallModule || (telemetry.SyscallExportChecked && !telemetry.SyscallExportMatch));
    if (fromSyscallModule && telemetry.StackValidated && !telemetry.StackSpoofSuspect && telemetry.ReturnAddressValid &&
        telemetry.SyscallExportChecked && telemetry.SyscallExportMatch && telemetry.ModuleChainChecked &&
        telemetry.ModuleChainSane && telemetry.UnwindMetadataChecked && telemetry.UnwindMetadataValid &&
        telemetry.TebStackBoundsChecked && telemetry.TebStackBoundsValid && telemetry.FramesOutsideTebStack)
    {
        classification = BkchdlHandleLegitimateSyscall;
    }
    else if (highRiskAccess && execProtect && (directSyscallEntryAnomaly || anomalySignals >= 2))
    {
        classification = BkchdlHandleDirectSyscallSuspect;
    }
    else
    {
        classification = BkchdlHandleUnknown;
    }

    BkchdlLogHandleTelemetry(classification, work->CallerPid, work->CallerTid, work->TargetPid, work->TargetTid,
                             work->ObjectAddress, work->DesiredAccess, work->IsThreadObject, work->IsDuplicateOperation,
                             execProtect, fromNtdll, fromExe, &telemetry);

    BK_DBG_PRINT(DPFLTR_INFO_LEVEL,
                 "BK[DBG]: handle event caller=%p target=%p access=0x%08X class=%s open=0x%08X "
                 "basic=0x%08X section=0x%08X frames=%lu.\n",
                 work->CallerPid, work->TargetPid, work->DesiredAccess, BkchdlClassToString(classification),
                 (ULONG)telemetry.OpenProcessStatus, (ULONG)telemetry.BasicInfoStatus,
                 (ULONG)telemetry.SectionNameStatus, work->FrameCount);

Exit:
    BkchdlHandleReleaseWorkSlot();
    ExFreePoolWithTag(work, 'hdtT');
}

static OB_PREOP_CALLBACK_STATUS BkchdlProcessPreOperation(_In_ PVOID RegistrationContext,
                                                          _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation)
{
    ULONGLONG tempusStartQpc = BktmpEnter(BktmpSubsystemHandleMonitor);
    ACCESS_MASK desiredAccess;
    ACCESS_MASK originalDesiredAccess;
    ACCESS_MASK sanitizedAccess;
    HANDLE callerPid;
    HANDLE callerTid;
    HANDLE targetPid;
    HANDLE targetTid = NULL;
    PEPROCESS targetProcess;
    PETHREAD targetThread;
    PBK_HANDLE_WORK work;
    PVOID userFrames[BK_MAX_FULL_EVENT_FRAMES] = {0};
    ULONG frameCount;
    ULONG copyCount;
    ULONG fullCopyCount;
    BOOLEAN hasVmWriteOrFull;
    BOOLEAN hasThreadContextAccess;
    BOOLEAN enterpriseCandidate;
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
        BktmpLeave(BktmpSubsystemHandleMonitor, tempusStartQpc);
        return OB_PREOP_SUCCESS;
    }

    if (OperationInformation == NULL || OperationInformation->KernelHandle)
    {
        BktmpLeave(BktmpSubsystemHandleMonitor, tempusStartQpc);
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
        BktmpLeave(BktmpSubsystemHandleMonitor, tempusStartQpc);
        return OB_PREOP_SUCCESS;
    }

    originalDesiredAccess = desiredAccess;
    sanitizedAccess = desiredAccess;
    hasVmWriteOrFull = FALSE;
    hasThreadContextAccess = FALSE;
    enterpriseCandidate = FALSE;
    if (OperationInformation->ObjectType == *PsProcessType)
    {
        targetProcess = (PEPROCESS)OperationInformation->Object;
        targetPid = PsGetProcessId(targetProcess);

        hasVmWriteOrFull = ((originalDesiredAccess & PROCESS_VM_OPERATION) != 0) ||
                           ((originalDesiredAccess & PROCESS_VM_WRITE) != 0) ||
                           ((originalDesiredAccess & PROCESS_CREATE_THREAD) != 0) ||
                           ((originalDesiredAccess & PROCESS_DUP_HANDLE) != 0) ||
                           ((originalDesiredAccess & PROCESS_ALL_ACCESS) == PROCESS_ALL_ACCESS);
        enterpriseCandidate =
            BkchdlProcessEnterpriseCandidate(targetProcess, PsGetCurrentProcessId(), targetPid, originalDesiredAccess);
    }
    else if (OperationInformation->ObjectType == *PsThreadType)
    {
        isThreadObject = TRUE;
        targetThread = (PETHREAD)OperationInformation->Object;
        targetPid = PsGetThreadProcessId(targetThread);
        targetTid = PsGetThreadId(targetThread);

        hasThreadContextAccess = ((originalDesiredAccess & THREAD_SET_CONTEXT) != 0) ||
                                 ((originalDesiredAccess & THREAD_GET_CONTEXT) != 0) ||
                                 ((originalDesiredAccess & THREAD_SUSPEND_RESUME) != 0) ||
                                 ((originalDesiredAccess & THREAD_ALL_ACCESS) == THREAD_ALL_ACCESS);
        enterpriseCandidate = (hasThreadContextAccess && PsGetCurrentProcessId() != targetPid);
    }
    else
    {
        BktmpLeave(BktmpSubsystemHandleMonitor, tempusStartQpc);
        return OB_PREOP_SUCCESS;
    }

    callerPid = PsGetCurrentProcessId();
    callerTid = PsGetCurrentThreadId();
    callerPid32 = (UINT32)(ULONG_PTR)callerPid;
    targetPid32 = (UINT32)(ULONG_PTR)targetPid;
    isProtectedTarget = BkcprocIsProtectedPid(targetPid32);
    trustedProtectedCaller = isProtectedTarget && BkcprocIsTrustedProtectedCaller(callerPid32, targetPid32);
    if (isProtectedTarget && !trustedProtectedCaller)
    {
        sanitizedAccess &= isThreadObject ? BK_PROTECTED_THREAD_ALLOWED_ACCESS : BK_PROTECTED_PROCESS_ALLOWED_ACCESS;
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

    if (!hasVmWriteOrFull && !hasThreadContextAccess && !enterpriseCandidate)
    {
        BktmpLeave(BktmpSubsystemHandleMonitor, tempusStartQpc);
        return OB_PREOP_SUCCESS;
    }
    if (!BkctlIsArmedFast())
    {
        BktmpLeave(BktmpSubsystemHandleMonitor, tempusStartQpc);
        return OB_PREOP_SUCCESS;
    }

    secondaryPid32 = (targetPid32 != callerPid32) ? targetPid32 : 0;
    streamMask = (hasVmWriteOrFull || hasThreadContextAccess) ? BK_STREAM_HANDLE : 0;
    if (hasVmWriteOrFull)
    {
        streamMask |= BK_STREAM_MEMORY;
    }
    if (enterpriseCandidate)
    {
        streamMask |= BK_STREAM_ENTERPRISE;
    }

    if (!BkctlHasPidInterest(callerPid32, secondaryPid32, streamMask))
    {
        BktmpLeave(BktmpSubsystemHandleMonitor, tempusStartQpc);
        return OB_PREOP_SUCCESS;
    }

    intentFlags = 0;
    if (hasVmWriteOrFull)
    {
        intentFlags |= BK_INTENT_PROCESS_MEMORY;
    }
    if (hasThreadContextAccess)
    {
        intentFlags |= BK_INTENT_THREAD_CONTEXT;
    }
    if (isDuplicateOperation && (intentFlags != 0))
    {
        intentFlags |= BK_INTENT_DUP_HANDLE;
    }

    if (intentFlags != 0)
    {
        BkcorRecordHandleIntent(callerPid, targetPid, originalDesiredAccess, intentFlags);
    }
    if (isThreadObject)
    {
        BkapcRecordThreadHandleIntent(callerPid, targetPid, originalDesiredAccess, isDuplicateOperation);
    }

    if (!BkchdlHandleTryAcquireWorkSlot())
    {
        failureCounter = InterlockedIncrement(&g_HandleCallbackDropLogCounter);
        if (failureCounter == 1 || ((failureCounter & 0xFF) == 0))
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "BK: handle callback drop caller=%p target=%p access=0x%08X total=%lu.\n", callerPid, targetPid,
                       originalDesiredAccess, (ULONG)failureCounter);
        }
        BK_DBG_PRINT(DPFLTR_WARNING_LEVEL,
                     "BK[DBG]: dropping handle preop caller=%p target=%p access=0x%08X (work slot unavailable).\n",
                     callerPid, targetPid, originalDesiredAccess);
        BktmpLeave(BktmpSubsystemHandleMonitor, tempusStartQpc);
        return OB_PREOP_SUCCESS;
    }

    work = (PBK_HANDLE_WORK)BkpoolAllocateCompat(POOL_FLAG_NON_PAGED, sizeof(*work), 'hdtT');
    if (work == NULL)
    {
        failureCounter = InterlockedIncrement(&g_HandleAllocFailureCounter);
        if (failureCounter == 1 || ((failureCounter & 0xFF) == 0))
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                       "BK: handle callback alloc failure caller=%p target=%p access=0x%08X total=%lu.\n", callerPid,
                       targetPid, originalDesiredAccess, (ULONG)failureCounter);
        }
        BK_DBG_PRINT(DPFLTR_ERROR_LEVEL, "BK[DBG]: ExAllocatePool2 failed for handle work item.\n");
        BkchdlHandleReleaseWorkSlot();
        BktmpLeave(BktmpSubsystemHandleMonitor, tempusStartQpc);
        return OB_PREOP_SUCCESS;
    }

    RtlZeroMemory(work, sizeof(*work));
    work->CallerPid = callerPid;
    work->CallerTid = callerTid;
    work->TargetPid = targetPid;
    work->TargetTid = targetTid;
    work->ObjectAddress = (UINT64)(ULONG_PTR)OperationInformation->Object;
    work->DesiredAccess = originalDesiredAccess;
    work->IsThreadObject = isThreadObject;
    work->IsDuplicateOperation = isDuplicateOperation;

    frameCount = 0;
    copyCount = 0;
    fullCopyCount = 0;
    BkchdlCaptureRegisterSnapshot(work);
    shouldCaptureStack = isDuplicateOperation ||
                         ((originalDesiredAccess & (PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD |
                                                    PROCESS_DUP_HANDLE | THREAD_SET_CONTEXT | THREAD_GET_CONTEXT |
                                                    THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION)) != 0) ||
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
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                           "BK: handle callback stack capture fault caller=%p target=%p access=0x%08X total=%lu.\n",
                           callerPid, targetPid, desiredAccess, (ULONG)failureCounter);
            }
            BK_DBG_PRINT(DPFLTR_WARNING_LEVEL, "BK[DBG]: RtlWalkFrameChain fault caller=%p target=%p access=0x%08X.\n",
                         callerPid, targetPid, desiredAccess);
        }
    }

    work->FrameCount = copyCount;
    work->FullFrameCount = fullCopyCount;
    if (copyCount != 0 && work->Frames[0] != NULL)
    {
        BkchdlCaptureImmediateOriginSample(callerPid, work->Frames[0], work);
    }

    ExInitializeWorkItem(&work->WorkItem, BkchdlHandleWorkRoutine, work);
    ExQueueWorkItem(&work->WorkItem, DelayedWorkQueue);
    BK_DBG_PRINT(DPFLTR_TRACE_LEVEL, "BK[DBG]: queued handle work caller=%p target=%p access=0x%08X frames=%lu.\n",
                 callerPid, targetPid, desiredAccess, copyCount);

    BktmpLeave(BktmpSubsystemHandleMonitor, tempusStartQpc);
    return OB_PREOP_SUCCESS;
}

NTSTATUS
BkchdlInitialize(VOID)
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
    g_OperationRegistration[0].PreOperation = BkchdlProcessPreOperation;
    g_OperationRegistration[0].PostOperation = NULL;

    g_OperationRegistration[1].ObjectType = PsThreadType;
    g_OperationRegistration[1].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    g_OperationRegistration[1].PreOperation = BkchdlProcessPreOperation;
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
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "BK: ObRegisterCallbacks failed (0x%08X).\n", status);
        return status;
    }

    g_HandleMonitorRegistered = TRUE;
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "BK: process handle monitor initialized.\n");
    return STATUS_SUCCESS;
}

VOID BkchdlUninitialize(VOID)
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
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "BK: handle monitor draining (outstanding=%ld).\n",
                       InterlockedCompareExchange(&g_HandleOutstandingWork, 0, 0));
        }
    }

    InterlockedExchange(&g_HandleMonitorStopping, 0);
    RtlZeroMemory(g_DeepCache, sizeof(g_DeepCache));
    InterlockedExchange(&g_DeepCacheWriteIndex, -1);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "BK: process handle monitor uninitialized (dropped=%ld, stackCaptureFaults=%ld).\n",
               InterlockedCompareExchange(&g_HandleDroppedWork, 0, 0),
               InterlockedCompareExchange(&g_HandleStackCaptureFaults, 0, 0));
}

BOOLEAN
BkchdlSelfCheck(VOID)
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
    if (g_OperationRegistration[0].PreOperation != BkchdlProcessPreOperation ||
        g_OperationRegistration[1].PreOperation != BkchdlProcessPreOperation)
    {
        return FALSE;
    }
    if (InterlockedCompareExchange(&g_HandleOutstandingWork, 0, 0) < 0)
    {
        return FALSE;
    }

    return TRUE;
}
