#include <ntddk.h>
#include "..\core\control.h"
#include "..\telemetry\etw.h"
#include "handle_monitor.h"

#ifndef PROCESS_VM_READ
#define PROCESS_VM_READ 0x0010
#endif

#ifndef PROCESS_VM_WRITE
#define PROCESS_VM_WRITE 0x0020
#endif

#ifndef PROCESS_QUERY_LIMITED_INFORMATION
#define PROCESS_QUERY_LIMITED_INFORMATION 0x1000
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

#define STINGER_HANDLE_MAX_OUTSTANDING_WORK 2048

static PVOID g_ProcessObRegistrationHandle = NULL;
static OB_OPERATION_REGISTRATION g_OperationRegistration;
static OB_CALLBACK_REGISTRATION g_CallbackRegistration;
static UNICODE_STRING g_CallbackAltitude;
static const WCHAR g_CallbackAltitudeBuffer[] = L"385000.424242";
static volatile LONG g_HandleOutstandingWork = 0;
static volatile LONG g_HandleDroppedWork = 0;
static volatile LONG g_HandleStackCaptureFaults = 0;
static KEVENT g_HandleAllWorkDone;
static volatile LONG g_HandleMonitorStopping = 0;
static BOOLEAN g_HandleMonitorRegistered = FALSE;

#if defined(DBG) && DBG
#define STINGER_DBG_PRINT(_level, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, (_level), __VA_ARGS__)
#else
#define STINGER_DBG_PRINT(_level, ...) ((void)0)
#endif

typedef struct _STINGER_HANDLE_WORK {
    WORK_QUEUE_ITEM WorkItem;
    HANDLE CallerPid;
    HANDLE TargetPid;
    ACCESS_MASK DesiredAccess;
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
            ((DesiredAccess & PROCESS_VM_READ) != 0) ||
            ((DesiredAccess & PROCESS_VM_WRITE) != 0) ||
            ((DesiredAccess & PROCESS_ALL_ACCESS) != 0);
        if (memoryRelated) {
            flags |= STINGER_HANDLE_FLAG_MEMORY_RELATED;
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
    PSTINGER_HANDLE_WORK work;
    PVOID userFrames[16] = { 0 };
    ULONG frameCount;
    ULONG copyCount;
    BOOLEAN hasVmWriteOrFull;

    UNREFERENCED_PARAMETER(RegistrationContext);

    if (InterlockedCompareExchange(&g_HandleMonitorStopping, 0, 0) != 0) {
        return OB_PREOP_SUCCESS;
    }

    if (OperationInformation == NULL || OperationInformation->KernelHandle) {
        return OB_PREOP_SUCCESS;
    }

    if (OperationInformation->ObjectType != *PsProcessType) {
        return OB_PREOP_SUCCESS;
    }

    if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
        desiredAccess = OperationInformation->Parameters->CreateHandleInformation.DesiredAccess;
    } else if (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
        desiredAccess = OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess;
    } else {
        return OB_PREOP_SUCCESS;
    }

    hasVmWriteOrFull =
        ((desiredAccess & PROCESS_VM_WRITE) != 0) ||
        ((desiredAccess & PROCESS_ALL_ACCESS) != 0);
    if (!hasVmWriteOrFull) {
        return OB_PREOP_SUCCESS;
    }

    callerPid = PsGetCurrentProcessId();
    targetProcess = (PEPROCESS)OperationInformation->Object;
    targetPid = PsGetProcessId(targetProcess);
    if (callerPid == targetPid) {
        return OB_PREOP_SUCCESS;
    }

    if (!STINGERHandleTryAcquireWorkSlot()) {
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

    frameCount = 0;
    copyCount = 0;
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
        STINGER_DBG_PRINT(
            DPFLTR_WARNING_LEVEL,
            "STINGER[DBG]: RtlWalkFrameChain fault caller=%p target=%p access=0x%08X.\n",
            callerPid,
            targetPid,
            desiredAccess
        );
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
    g_OperationRegistration.ObjectType = PsProcessType;
    g_OperationRegistration.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    g_OperationRegistration.PreOperation = STINGERProcessPreOperation;
    g_OperationRegistration.PostOperation = NULL;

    RtlZeroMemory(&g_CallbackRegistration, sizeof(g_CallbackRegistration));
    g_CallbackRegistration.Version = OB_FLT_REGISTRATION_VERSION;
    g_CallbackRegistration.OperationRegistrationCount = 1;
    g_CallbackRegistration.RegistrationContext = NULL;
    g_CallbackRegistration.OperationRegistration = &g_OperationRegistration;
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
