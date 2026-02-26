#include <ntddk.h>
#include "..\telemetry\etw.h"
#include "process_monitor.h"

static volatile LONG g_ProcessMonitorRegistered = 0;
static volatile LONG g_ProcessMonitorFailureCounter = 0;

NTKERNELAPI ULONGLONG PsGetProcessStartKey(_In_ PEPROCESS Process);
NTKERNELAPI ULONG PsGetProcessSessionIdEx(_In_ PEPROCESS Process);

static
VOID
STINGERProcessNotifyRoutineEx(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
)
{
    WCHAR imagePath[512];
    WCHAR commandLine[512];
    HANDLE parentPid = NULL;
    HANDLE creatorPid = NULL;
    HANDLE creatorTid = NULL;
    ULONGLONG startKey = 0;
    ULONG sessionId = 0;
    NTSTATUS createStatus = STATUS_SUCCESS;
    BOOLEAN isCreate = FALSE;

    imagePath[0] = L'\0';
    commandLine[0] = L'\0';

    if (Process != NULL) {
        startKey = PsGetProcessStartKey(Process);
        sessionId = PsGetProcessSessionIdEx(Process);
    }

    if (CreateInfo != NULL) {
        SIZE_T copyChars;
        isCreate = TRUE;
        parentPid = CreateInfo->ParentProcessId;
        creatorPid = CreateInfo->CreatingThreadId.UniqueProcess;
        creatorTid = CreateInfo->CreatingThreadId.UniqueThread;
        createStatus = CreateInfo->CreationStatus;

        if (CreateInfo->ImageFileName != NULL && CreateInfo->ImageFileName->Buffer != NULL) {
            copyChars = CreateInfo->ImageFileName->Length / sizeof(WCHAR);
            if (copyChars >= RTL_NUMBER_OF(imagePath)) {
                copyChars = RTL_NUMBER_OF(imagePath) - 1;
            }
            if (copyChars > 0) {
                RtlCopyMemory(imagePath, CreateInfo->ImageFileName->Buffer, copyChars * sizeof(WCHAR));
                imagePath[copyChars] = L'\0';
            }
        }

        if (CreateInfo->CommandLine != NULL && CreateInfo->CommandLine->Buffer != NULL) {
            copyChars = CreateInfo->CommandLine->Length / sizeof(WCHAR);
            if (copyChars >= RTL_NUMBER_OF(commandLine)) {
                copyChars = RTL_NUMBER_OF(commandLine) - 1;
            }
            if (copyChars > 0) {
                RtlCopyMemory(commandLine, CreateInfo->CommandLine->Buffer, copyChars * sizeof(WCHAR));
                commandLine[copyChars] = L'\0';
            }
        }
    }

    STINGEREtwLogProcessEvent(
        ProcessId,
        parentPid,
        creatorPid,
        creatorTid,
        startKey,
        sessionId,
        isCreate,
        createStatus,
        (imagePath[0] != L'\0') ? imagePath : NULL,
        (commandLine[0] != L'\0') ? commandLine : NULL
    );
}

NTSTATUS
STINGERProcessMonitorInitialize(
    VOID
)
{
    NTSTATUS status;
    LONG failures;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (InterlockedCompareExchange(&g_ProcessMonitorRegistered, 0, 0) != 0) {
        return STATUS_SUCCESS;
    }

    status = PsSetCreateProcessNotifyRoutineEx(STINGERProcessNotifyRoutineEx, FALSE);
    if (!NT_SUCCESS(status)) {
        failures = InterlockedIncrement(&g_ProcessMonitorFailureCounter);
        if (failures == 1 || ((failures & 0xFF) == 0)) {
            DbgPrintEx(
                DPFLTR_IHVDRIVER_ID,
                DPFLTR_ERROR_LEVEL,
                "STINGER: process monitor callback registration failed status=0x%08X total=%lu.\n",
                status,
                (ULONG)failures
            );
        }
        return status;
    }

    InterlockedExchange(&g_ProcessMonitorRegistered, 1);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "STINGER: process monitor initialized.\n");
    return STATUS_SUCCESS;
}

VOID
STINGERProcessMonitorUninitialize(
    VOID
)
{
    NTSTATUS status;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return;
    }
    if (InterlockedExchange(&g_ProcessMonitorRegistered, 0) == 0) {
        return;
    }

    status = PsSetCreateProcessNotifyRoutineEx(STINGERProcessNotifyRoutineEx, TRUE);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_WARNING_LEVEL,
            "STINGER: process monitor callback removal failed status=0x%08X.\n",
            status
        );
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "STINGER: process monitor uninitialized.\n");
}

BOOLEAN
STINGERProcessMonitorSelfCheck(
    VOID
)
{
    return (InterlockedCompareExchange(&g_ProcessMonitorRegistered, 0, 0) != 0);
}
