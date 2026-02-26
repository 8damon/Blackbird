#include <ntddk.h>
#include "..\core\control.h"
#include "..\telemetry\etw.h"
#include "apc_monitor.h"
#include "correlation.h"
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

#ifndef _MEMORY_BASIC_INFORMATION
typedef struct _MEMORY_BASIC_INFORMATION {
    PVOID BaseAddress;
    PVOID AllocationBase;
    ULONG AllocationProtect;
    SIZE_T RegionSize;
    ULONG State;
    ULONG Protect;
    ULONG Type;
} MEMORY_BASIC_INFORMATION, *PMEMORY_BASIC_INFORMATION;
#endif

typedef enum _STINGER_MEMORY_INFORMATION_CLASS {
    STINGERMemoryBasicInformation = 0,
    STINGERMemorySectionName = 2
} STINGER_MEMORY_INFORMATION_CLASS;

NTSYSAPI NTSTATUS NTAPI ZwQueryVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress,
    _In_ STINGER_MEMORY_INFORMATION_CLASS MemoryInformationClass,
    _Out_writes_bytes_(MemoryInformationLength) PVOID MemoryInformation,
    _In_ SIZE_T MemoryInformationLength,
    _Out_opt_ PSIZE_T ReturnLength
);

#ifndef RTL_WALK_USER_MODE_STACK
#define RTL_WALK_USER_MODE_STACK 0x00000001
#endif

NTKERNELAPI HANDLE PsGetThreadProcessId(_In_ PETHREAD Thread);

#define STINGER_HANDLE_MAX_OUTSTANDING_WORK 2048

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

/*
 * Hot-path debug tracing is disabled by default to prevent KD console flooding.
 * Define STINGER_VERBOSE_HOTPATH_DEBUG=1 for local deep diagnostics.
 */
#if !defined(STINGER_VERBOSE_HOTPATH_DEBUG)
#define STINGER_VERBOSE_HOTPATH_DEBUG 0
#endif

#if defined(DBG) && DBG && STINGER_VERBOSE_HOTPATH_DEBUG
#define STINGER_DBG_PRINT(_level, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, (_level), __VA_ARGS__)
#else
#define STINGER_DBG_PRINT(_level, ...) ((void)0)
#endif

typedef struct _STINGER_HANDLE_WORK {
    WORK_QUEUE_ITEM WorkItem;
    HANDLE CallerPid;
    HANDLE TargetPid;
    ACCESS_MASK DesiredAccess;
    BOOLEAN IsThreadObject;
    BOOLEAN IsDuplicateOperation;
    ULONG FrameCount;
    PVOID Frames[8];
} STINGER_HANDLE_WORK, *PSTINGER_HANDLE_WORK;

typedef enum _STINGER_HANDLE_CLASSIFICATION {
    STINGERHandleUnknown = 0,
    STINGERHandleLegitimateSyscall,
    STINGERHandleDirectSyscallSuspect
} STINGER_HANDLE_CLASSIFICATION;

typedef struct _STINGER_HANDLE_TELEMETRY {
    PVOID OriginAddress;
    ULONG OriginProtect;
    WCHAR OriginPath[512];
    ULONG FrameCount;
    PVOID Frames[8];
    NTSTATUS OpenProcessStatus;
    NTSTATUS BasicInfoStatus;
    NTSTATUS SectionNameStatus;
} STINGER_HANDLE_TELEMETRY, *PSTINGER_HANDLE_TELEMETRY;

static
BOOLEAN
STINGERHandleTryAcquireWorkSlot(
    VOID
)
{
    LONG current;

    for (;;) {
        current = InterlockedCompareExchange(&g_HandleOutstandingWork, 0, 0);
        if (current >= STINGER_HANDLE_MAX_OUTSTANDING_WORK) {
            InterlockedIncrement(&g_HandleDroppedWork);
            STINGER_DBG_PRINT(
                DPFLTR_WARNING_LEVEL,
                "STINGER[DBG]: handle monitor work queue full (max=%lu).\n",
                STINGER_HANDLE_MAX_OUTSTANDING_WORK
            );
            return FALSE;
        }

        if (InterlockedCompareExchange(&g_HandleOutstandingWork, current + 1, current) == current) {
            if (current == 0) {
                KeClearEvent(&g_HandleAllWorkDone);
            }
            return TRUE;
        }
    }
}

static
VOID
STINGERHandleReleaseWorkSlot(
    VOID
)
{
    if (InterlockedDecrement(&g_HandleOutstandingWork) == 0) {
        KeSetEvent(&g_HandleAllWorkDone, IO_NO_INCREMENT, FALSE);
    }
}

static
PCSTR
STINGERHandleClassToString(
    _In_ STINGER_HANDLE_CLASSIFICATION Class
)
{
    if (Class == STINGERHandleLegitimateSyscall) {
        return "LEGITIMATE-SYSCALL";
    }
    if (Class == STINGERHandleDirectSyscallSuspect) {
        return "DIRECT-SYSCALL-SUSPECT";
    }
    return "UNKNOWN-ORIGIN";
}

static
VOID
STINGERLogHandleTelemetry(
    _In_ STINGER_HANDLE_CLASSIFICATION Class,
    _In_ HANDLE CallerPid,
    _In_ HANDLE TargetPid,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ BOOLEAN IsThreadObject,
    _In_ BOOLEAN IsDuplicateOperation,
    _In_ BOOLEAN ExecProtect,
    _In_ BOOLEAN FromNtdll,
    _In_ BOOLEAN FromExe,
    _In_ PSTINGER_HANDLE_TELEMETRY Telemetry
)
{
    UNREFERENCED_PARAMETER(Class);

    STINGEREtwLogHandleEvent(
        STINGERHandleClassToString(Class),
        CallerPid,
        TargetPid,
        DesiredAccess,
        Telemetry->OriginAddress,
        Telemetry->OriginProtect,
        ExecProtect,
        FromNtdll,
        FromExe,
        (Telemetry->OriginPath[0] != L'\0') ? Telemetry->OriginPath : NULL,
        Telemetry->FrameCount,
        Telemetry->Frames,
        Telemetry->OpenProcessStatus,
        Telemetry->BasicInfoStatus,
        Telemetry->SectionNameStatus
    );

    {
        UINT32 flags = 0;
        UINT32 classId = StingerHandleClassUnknown;
        BOOLEAN memoryRelated;
        UINT32 intentFlags = 0;

        if (ExecProtect) {
            flags |= STINGER_HANDLE_FLAG_EXEC_PROTECT;
        }
        if (FromNtdll) {
            flags |= STINGER_HANDLE_FLAG_FROM_NTDLL;
        }
        if (FromExe) {
            flags |= STINGER_HANDLE_FLAG_FROM_EXE;
        }

        memoryRelated =
            ((DesiredAccess & PROCESS_VM_OPERATION) != 0) ||
            ((DesiredAccess & PROCESS_VM_READ) != 0) ||
            ((DesiredAccess & PROCESS_VM_WRITE) != 0) ||
            ((DesiredAccess & PROCESS_ALL_ACCESS) != 0);
        if (memoryRelated) {
            flags |= STINGER_HANDLE_FLAG_MEMORY_RELATED;
            intentFlags |= STINGER_INTENT_PROCESS_MEMORY;
        }
        if (IsThreadObject) {
            flags |= STINGER_HANDLE_FLAG_THREAD_OBJECT;
            if ((DesiredAccess & THREAD_SET_CONTEXT) != 0 ||
                (DesiredAccess & THREAD_GET_CONTEXT) != 0 ||
                (DesiredAccess & THREAD_SUSPEND_RESUME) != 0) {
                intentFlags |= STINGER_INTENT_THREAD_CONTEXT;
            }
        }
        if (IsDuplicateOperation) {
            flags |= STINGER_HANDLE_FLAG_DUPLICATE_OPERATION;
            intentFlags |= STINGER_INTENT_DUP_HANDLE;
        }

        if (Class == STINGERHandleLegitimateSyscall) {
            classId = StingerHandleClassLegitimateSyscall;
        } else if (Class == STINGERHandleDirectSyscallSuspect) {
            classId = StingerHandleClassDirectSyscallSuspect;
        }

        STINGERControlPublishHandleEvent(
            (UINT64)(ULONG_PTR)CallerPid,
            (UINT64)(ULONG_PTR)TargetPid,
            (UINT32)DesiredAccess,
            classId,
            (UINT64)(ULONG_PTR)Telemetry->OriginAddress,
            Telemetry->OriginProtect,
            flags,
            (Telemetry->OriginPath[0] != L'\0') ? Telemetry->OriginPath : NULL,
            Telemetry->FrameCount,
            Telemetry->Frames,
            (INT32)Telemetry->OpenProcessStatus,
            (INT32)Telemetry->BasicInfoStatus,
            (INT32)Telemetry->SectionNameStatus
        );

        if (Class == STINGERHandleDirectSyscallSuspect) {
            ULONG severity = 3;

            if (memoryRelated || ((intentFlags & STINGER_INTENT_THREAD_CONTEXT) != 0)) {
                severity = 4;
            }

            STINGEREtwLogDetectionEvent(
                "DIRECT_SYSCALL_SUSPECT_HANDLE_OPERATION",
                severity,
                CallerPid,
                TargetPid,
                intentFlags,
                (UINT32)DesiredAccess,
                0,
                L"sensitive handle operation originated from executable user region outside ntdll"
            );
        }

        if (intentFlags != 0) {
            UINT32 priorIntentFlags = 0;
            BOOLEAN hadPriorIntent;

            hadPriorIntent = STINGERCorrelationQueryRecentIntent(
                CallerPid,
                TargetPid,
                10000,
                &priorIntentFlags,
                NULL,
                NULL
            );

            STINGERCorrelationRecordHandleIntent(
                CallerPid,
                TargetPid,
                DesiredAccess,
                intentFlags
            );

            if (!hadPriorIntent) {
                priorIntentFlags = 0;
            }

            if ((priorIntentFlags & (STINGER_INTENT_PROCESS_MEMORY | STINGER_INTENT_THREAD_CONTEXT)) !=
                    (STINGER_INTENT_PROCESS_MEMORY | STINGER_INTENT_THREAD_CONTEXT) &&
                ((priorIntentFlags | intentFlags) & (STINGER_INTENT_PROCESS_MEMORY | STINGER_INTENT_THREAD_CONTEXT)) ==
                    (STINGER_INTENT_PROCESS_MEMORY | STINGER_INTENT_THREAD_CONTEXT)) {
                UINT32 corrFlags = 0;
                UINT32 corrAccess = 0;
                UINT32 corrAgeMs = 0;
                ULONG severity = 3;

                (void)STINGERCorrelationQueryRecentIntent(
                    CallerPid,
                    TargetPid,
                    10000,
                    &corrFlags,
                    &corrAccess,
                    &corrAgeMs
                );

                if ((corrFlags & STINGER_INTENT_DUP_HANDLE) != 0) {
                    severity = 4;
                }

                STINGEREtwLogDetectionEvent(
                    "POSSIBLE_PROCESS_HOLLOWING_OR_INJECTION_INTENT_CHAIN",
                    severity,
                    CallerPid,
                    TargetPid,
                    corrFlags,
                    corrAccess,
                    corrAgeMs,
                    L"observed process-memory and thread-context handle intent chain against target process"
                );
            }
        }

        if (IsThreadObject) {
            STINGERApcMonitorRecordThreadHandleIntent(
                CallerPid,
                TargetPid,
                DesiredAccess,
                IsDuplicateOperation
            );
        }
    }
}

static
BOOLEAN
STINGERUnicodeContainsInsensitive(
    _In_ PCUNICODE_STRING Haystack,
    _In_reads_(NeedleChars) PCWSTR Needle,
    _In_ USHORT NeedleChars
)
{
    USHORT hayChars;
    USHORT i;
    USHORT j;

    if (Haystack == NULL || Haystack->Buffer == NULL || Needle == NULL || NeedleChars == 0) {
        return FALSE;
    }

    hayChars = Haystack->Length / sizeof(WCHAR);
    if (hayChars < NeedleChars) {
        return FALSE;
    }

    for (i = 0; i <= (USHORT)(hayChars - NeedleChars); ++i) {
        BOOLEAN match = TRUE;
        for (j = 0; j < NeedleChars; ++j) {
            if (RtlDowncaseUnicodeChar(Haystack->Buffer[i + j]) != RtlDowncaseUnicodeChar(Needle[j])) {
                match = FALSE;
                break;
            }
        }
        if (match) {
            return TRUE;
        }
    }

    return FALSE;
}

static
VOID
STINGERClassifyUserOrigin(
    _In_ HANDLE CallerProcessId,
    _In_ ULONG FrameCount,
    _In_reads_(FrameCount) PVOID* Frames,
    _Out_ PSTINGER_HANDLE_TELEMETRY Telemetry
)
{
    NTSTATUS status;
    OBJECT_ATTRIBUTES objectAttributes;
    CLIENT_ID clientId;
    HANDLE processHandle = NULL;
    MEMORY_BASIC_INFORMATION mbi;
    UCHAR sectionNameRaw[1024];
    PUNICODE_STRING sectionName;

    RtlZeroMemory(Telemetry, sizeof(*Telemetry));
    Telemetry->OpenProcessStatus = STATUS_UNSUCCESSFUL;
    Telemetry->BasicInfoStatus = STATUS_UNSUCCESSFUL;
    Telemetry->SectionNameStatus = STATUS_UNSUCCESSFUL;

    if (FrameCount == 0 || Frames == NULL || Frames[0] == NULL) {
        return;
    }
    Telemetry->OriginAddress = Frames[0];
    Telemetry->FrameCount = (FrameCount > RTL_NUMBER_OF(Telemetry->Frames)) ? RTL_NUMBER_OF(Telemetry->Frames) : FrameCount;
    RtlCopyMemory(Telemetry->Frames, Frames, Telemetry->FrameCount * sizeof(PVOID));

    InitializeObjectAttributes(&objectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    clientId.UniqueProcess = CallerProcessId;
    clientId.UniqueThread = NULL;

    status = ZwOpenProcess(&processHandle, PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, &objectAttributes, &clientId);
    Telemetry->OpenProcessStatus = status;
    if (!NT_SUCCESS(status)) {
        STINGER_DBG_PRINT(
            DPFLTR_TRACE_LEVEL,
            "STINGER[DBG]: ZwOpenProcess failed callerPid=%p status=0x%08X.\n",
            CallerProcessId,
            (ULONG)status
        );
        return;
    }

    RtlZeroMemory(&mbi, sizeof(mbi));
    status = ZwQueryVirtualMemory(
        processHandle,
        Telemetry->OriginAddress,
        STINGERMemoryBasicInformation,
        &mbi,
        sizeof(mbi),
        NULL
    );
    Telemetry->BasicInfoStatus = status;
    if (NT_SUCCESS(status)) {
        Telemetry->OriginProtect = mbi.Protect;
    } else {
        STINGER_DBG_PRINT(
            DPFLTR_TRACE_LEVEL,
            "STINGER[DBG]: ZwQueryVirtualMemory(basic) failed callerPid=%p status=0x%08X.\n",
            CallerProcessId,
            (ULONG)status
        );
    }

    RtlZeroMemory(sectionNameRaw, sizeof(sectionNameRaw));
    status = ZwQueryVirtualMemory(
        processHandle,
        Telemetry->OriginAddress,
        STINGERMemorySectionName,
        sectionNameRaw,
        sizeof(sectionNameRaw),
        NULL
    );
    Telemetry->SectionNameStatus = status;
    if (NT_SUCCESS(status)) {
        sectionName = (PUNICODE_STRING)sectionNameRaw;
        if (sectionName->Buffer != NULL && sectionName->Length > 0) {
            SIZE_T maxChars = RTL_NUMBER_OF(Telemetry->OriginPath) - 1;
            SIZE_T copyChars = sectionName->Length / sizeof(WCHAR);
            if (copyChars > maxChars) {
                copyChars = maxChars;
            }
            RtlCopyMemory(Telemetry->OriginPath, sectionName->Buffer, copyChars * sizeof(WCHAR));
            Telemetry->OriginPath[copyChars] = L'\0';
        }
    } else {
        STINGER_DBG_PRINT(
            DPFLTR_TRACE_LEVEL,
            "STINGER[DBG]: ZwQueryVirtualMemory(section) failed callerPid=%p status=0x%08X.\n",
            CallerProcessId,
            (ULONG)status
        );
    }

    ZwClose(processHandle);
}

static
VOID
STINGERHandleWorkRoutine(
    _In_ PVOID Context
)
{
    PSTINGER_HANDLE_WORK work = (PSTINGER_HANDLE_WORK)Context;
    STINGER_HANDLE_TELEMETRY telemetry;
    UNICODE_STRING originPathUs;
    BOOLEAN execProtect;
    BOOLEAN fromNtdll;
    BOOLEAN fromExe;
    STINGER_HANDLE_CLASSIFICATION classification;

    PAGED_CODE();
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        goto Exit;
    }

    STINGERClassifyUserOrigin(work->CallerPid, work->FrameCount, work->Frames, &telemetry);

    RtlInitUnicodeString(&originPathUs, telemetry.OriginPath);
    execProtect =
        (telemetry.OriginProtect & PAGE_EXECUTE) ||
        (telemetry.OriginProtect & PAGE_EXECUTE_READ) ||
        (telemetry.OriginProtect & PAGE_EXECUTE_READWRITE) ||
        (telemetry.OriginProtect & PAGE_EXECUTE_WRITECOPY);

    fromNtdll = STINGERUnicodeContainsInsensitive(&originPathUs, L"ntdll.dll", 9);
    fromExe = STINGERUnicodeContainsInsensitive(&originPathUs, L".exe", 4);

    if (fromNtdll && execProtect) {
        classification = STINGERHandleLegitimateSyscall;
    } else if (fromExe && execProtect) {
        classification = STINGERHandleDirectSyscallSuspect;
    } else {
        classification = STINGERHandleUnknown;
    }

    STINGERLogHandleTelemetry(
        classification,
        work->CallerPid,
        work->TargetPid,
        work->DesiredAccess,
        work->IsThreadObject,
        work->IsDuplicateOperation,
        execProtect,
        fromNtdll,
        fromExe,
        &telemetry
    );

    STINGER_DBG_PRINT(
        DPFLTR_INFO_LEVEL,
        "STINGER[DBG]: handle event caller=%p target=%p access=0x%08X class=%s open=0x%08X basic=0x%08X section=0x%08X frames=%lu.\n",
        work->CallerPid,
        work->TargetPid,
        work->DesiredAccess,
        STINGERHandleClassToString(classification),
        (ULONG)telemetry.OpenProcessStatus,
        (ULONG)telemetry.BasicInfoStatus,
        (ULONG)telemetry.SectionNameStatus,
        work->FrameCount
    );

Exit:
    STINGERHandleReleaseWorkSlot();
    ExFreePoolWithTag(work, 'hdtT');
}

static
OB_PREOP_CALLBACK_STATUS
STINGERProcessPreOperation(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation
)
{
    ACCESS_MASK desiredAccess;
    HANDLE callerPid;
    HANDLE targetPid;
    PEPROCESS targetProcess;
    PETHREAD targetThread;
    PSTINGER_HANDLE_WORK work;
    PVOID userFrames[16] = { 0 };
    ULONG frameCount;
    ULONG copyCount;
    BOOLEAN hasVmWriteOrFull;
    BOOLEAN hasThreadContextAccess;
    BOOLEAN shouldCaptureStack;
    BOOLEAN isThreadObject = FALSE;
    BOOLEAN isDuplicateOperation = FALSE;
    LONG failureCounter;

    UNREFERENCED_PARAMETER(RegistrationContext);

    if (InterlockedCompareExchange(&g_HandleMonitorStopping, 0, 0) != 0) {
        return OB_PREOP_SUCCESS;
    }

    if (OperationInformation == NULL || OperationInformation->KernelHandle) {
        return OB_PREOP_SUCCESS;
    }

    if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
        desiredAccess = OperationInformation->Parameters->CreateHandleInformation.DesiredAccess;
    } else if (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
        desiredAccess = OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess;
        isDuplicateOperation = TRUE;
    } else {
        return OB_PREOP_SUCCESS;
    }

    hasVmWriteOrFull = FALSE;
    hasThreadContextAccess = FALSE;
    if (OperationInformation->ObjectType == *PsProcessType) {
        targetProcess = (PEPROCESS)OperationInformation->Object;
        targetPid = PsGetProcessId(targetProcess);

        hasVmWriteOrFull =
            ((desiredAccess & PROCESS_VM_OPERATION) != 0) ||
            ((desiredAccess & PROCESS_VM_WRITE) != 0) ||
            ((desiredAccess & PROCESS_ALL_ACCESS) != 0);
    } else if (OperationInformation->ObjectType == *PsThreadType) {
        isThreadObject = TRUE;
        targetThread = (PETHREAD)OperationInformation->Object;
        targetPid = PsGetThreadProcessId(targetThread);

        hasThreadContextAccess =
            ((desiredAccess & THREAD_SET_CONTEXT) != 0) ||
            ((desiredAccess & THREAD_GET_CONTEXT) != 0) ||
            ((desiredAccess & THREAD_SUSPEND_RESUME) != 0);
    } else {
        return OB_PREOP_SUCCESS;
    }

    if (!hasVmWriteOrFull && !hasThreadContextAccess) {
        return OB_PREOP_SUCCESS;
    }

    callerPid = PsGetCurrentProcessId();
    if (callerPid == targetPid) {
        return OB_PREOP_SUCCESS;
    }

    if (!STINGERHandleTryAcquireWorkSlot()) {
        failureCounter = InterlockedIncrement(&g_HandleCallbackDropLogCounter);
        if (failureCounter == 1 || ((failureCounter & 0xFF) == 0)) {
            DbgPrintEx(
                DPFLTR_IHVDRIVER_ID,
                DPFLTR_WARNING_LEVEL,
                "STINGER: handle callback drop caller=%p target=%p access=0x%08X total=%lu.\n",
                callerPid,
                targetPid,
                desiredAccess,
                (ULONG)failureCounter
            );
        }
        STINGER_DBG_PRINT(
            DPFLTR_WARNING_LEVEL,
            "STINGER[DBG]: dropping handle preop caller=%p target=%p access=0x%08X (work slot unavailable).\n",
            callerPid,
            targetPid,
            desiredAccess
        );
        return OB_PREOP_SUCCESS;
    }

    work = (PSTINGER_HANDLE_WORK)ExAllocatePool2(
        POOL_FLAG_NON_PAGED | POOL_FLAG_UNINITIALIZED,
        sizeof(*work),
        'hdtT'
    );
    if (work == NULL) {
        failureCounter = InterlockedIncrement(&g_HandleAllocFailureCounter);
        if (failureCounter == 1 || ((failureCounter & 0xFF) == 0)) {
            DbgPrintEx(
                DPFLTR_IHVDRIVER_ID,
                DPFLTR_ERROR_LEVEL,
                "STINGER: handle callback alloc failure caller=%p target=%p access=0x%08X total=%lu.\n",
                callerPid,
                targetPid,
                desiredAccess,
                (ULONG)failureCounter
            );
        }
        STINGER_DBG_PRINT(
            DPFLTR_ERROR_LEVEL,
            "STINGER[DBG]: ExAllocatePool2 failed for handle work item.\n"
        );
        STINGERHandleReleaseWorkSlot();
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
    if (shouldCaptureStack) {
        __try {
            frameCount = RtlWalkFrameChain(userFrames, RTL_NUMBER_OF(userFrames), RTL_WALK_USER_MODE_STACK);
            copyCount = (frameCount > RTL_NUMBER_OF(work->Frames)) ? RTL_NUMBER_OF(work->Frames) : frameCount;
            if (copyCount != 0) {
                RtlCopyMemory(work->Frames, userFrames, copyCount * sizeof(PVOID));
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            copyCount = 0;
            RtlZeroMemory(work->Frames, sizeof(work->Frames));
            InterlockedIncrement(&g_HandleStackCaptureFaults);
            failureCounter = InterlockedIncrement(&g_HandleStackFaultLogCounter);
            if (failureCounter == 1 || ((failureCounter & 0xFF) == 0)) {
                DbgPrintEx(
                    DPFLTR_IHVDRIVER_ID,
                    DPFLTR_WARNING_LEVEL,
                    "STINGER: handle callback stack capture fault caller=%p target=%p access=0x%08X total=%lu.\n",
                    callerPid,
                    targetPid,
                    desiredAccess,
                    (ULONG)failureCounter
                );
            }
            STINGER_DBG_PRINT(
                DPFLTR_WARNING_LEVEL,
                "STINGER[DBG]: RtlWalkFrameChain fault caller=%p target=%p access=0x%08X.\n",
                callerPid,
                targetPid,
                desiredAccess
            );
        }
    }

    work->FrameCount = copyCount;

    ExInitializeWorkItem(&work->WorkItem, STINGERHandleWorkRoutine, work);
    ExQueueWorkItem(&work->WorkItem, DelayedWorkQueue);
    STINGER_DBG_PRINT(
        DPFLTR_TRACE_LEVEL,
        "STINGER[DBG]: queued handle work caller=%p target=%p access=0x%08X frames=%lu.\n",
        callerPid,
        targetPid,
        desiredAccess,
        copyCount
    );

    return OB_PREOP_SUCCESS;
}

NTSTATUS
STINGERHandleMonitorInitialize(
    VOID
)
{
    NTSTATUS status;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (g_HandleMonitorRegistered) {
        return STATUS_SUCCESS;
    }
    KeInitializeEvent(&g_HandleAllWorkDone, NotificationEvent, TRUE);
    InterlockedExchange(&g_HandleMonitorStopping, 0);
    InterlockedExchange(&g_HandleOutstandingWork, 0);
    InterlockedExchange(&g_HandleDroppedWork, 0);
    InterlockedExchange(&g_HandleStackCaptureFaults, 0);

    RtlZeroMemory(&g_OperationRegistration, sizeof(g_OperationRegistration));
    g_OperationRegistration[0].ObjectType = PsProcessType;
    g_OperationRegistration[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    g_OperationRegistration[0].PreOperation = STINGERProcessPreOperation;
    g_OperationRegistration[0].PostOperation = NULL;

    g_OperationRegistration[1].ObjectType = PsThreadType;
    g_OperationRegistration[1].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    g_OperationRegistration[1].PreOperation = STINGERProcessPreOperation;
    g_OperationRegistration[1].PostOperation = NULL;

    RtlZeroMemory(&g_CallbackRegistration, sizeof(g_CallbackRegistration));
    g_CallbackRegistration.Version = OB_FLT_REGISTRATION_VERSION;
    g_CallbackRegistration.OperationRegistrationCount = RTL_NUMBER_OF(g_OperationRegistration);
    g_CallbackRegistration.RegistrationContext = NULL;
    g_CallbackRegistration.OperationRegistration = g_OperationRegistration;
    RtlInitUnicodeString(&g_CallbackAltitude, g_CallbackAltitudeBuffer);
    g_CallbackRegistration.Altitude = g_CallbackAltitude;

    status = ObRegisterCallbacks(&g_CallbackRegistration, &g_ProcessObRegistrationHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_ERROR_LEVEL,
            "STINGER: ObRegisterCallbacks failed (0x%08X).\n",
            status
        );
        return status;
    }

    g_HandleMonitorRegistered = TRUE;
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "STINGER: process handle monitor initialized.\n");
    return STATUS_SUCCESS;
}

VOID
STINGERHandleMonitorUninitialize(
    VOID
)
{
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return;
    }
    if (!g_HandleMonitorRegistered) {
        return;
    }

    InterlockedExchange(&g_HandleMonitorStopping, 1);
    if (g_ProcessObRegistrationHandle != NULL) {
        ObUnRegisterCallbacks(g_ProcessObRegistrationHandle);
        g_ProcessObRegistrationHandle = NULL;
    }
    g_HandleMonitorRegistered = FALSE;

    if (InterlockedCompareExchange(&g_HandleOutstandingWork, 0, 0) != 0) {
        KeWaitForSingleObject(&g_HandleAllWorkDone, Executive, KernelMode, FALSE, NULL);
    }

    InterlockedExchange(&g_HandleMonitorStopping, 0);
    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_INFO_LEVEL,
        "STINGER: process handle monitor uninitialized (dropped=%ld, stackCaptureFaults=%ld).\n",
        InterlockedCompareExchange(&g_HandleDroppedWork, 0, 0),
        InterlockedCompareExchange(&g_HandleStackCaptureFaults, 0, 0)
    );
}

BOOLEAN
STINGERHandleMonitorSelfCheck(
    VOID
)
{
    if (!g_HandleMonitorRegistered) {
        return FALSE;
    }
    if (g_ProcessObRegistrationHandle == NULL) {
        return FALSE;
    }
    if (g_CallbackRegistration.OperationRegistrationCount != RTL_NUMBER_OF(g_OperationRegistration)) {
        return FALSE;
    }
    if (g_CallbackRegistration.OperationRegistration != g_OperationRegistration) {
        return FALSE;
    }
    if (g_OperationRegistration[0].PreOperation != STINGERProcessPreOperation ||
        g_OperationRegistration[1].PreOperation != STINGERProcessPreOperation) {
        return FALSE;
    }
    if (InterlockedCompareExchange(&g_HandleOutstandingWork, 0, 0) < 0) {
        return FALSE;
    }

    return TRUE;
}
