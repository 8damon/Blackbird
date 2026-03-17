#include <ntddk.h>
#include <ntstrsafe.h>
#include "..\core\control.h"
#include "..\core\pool_compat.h"
#include "..\telemetry\etw.h"
#include "..\core\unicode_utils.h"
#include "process_monitor.h"

static volatile LONG g_ProcessMonitorRegistered = 0;
static volatile LONG g_ProcessMonitorFailureCounter = 0;

NTKERNELAPI ULONGLONG PsGetProcessStartKey(_In_ PEPROCESS Process);
NTKERNELAPI ULONG PsGetProcessSessionIdEx(_In_ PEPROCESS Process);
NTSYSAPI NTSTATUS NTAPI SeLocateProcessImageName(_In_ PEPROCESS Process, _Out_ PUNICODE_STRING *pImageFileName);
NTSYSAPI NTSTATUS NTAPI ObQueryNameString(_In_ PVOID Object, _Out_writes_bytes_opt_(Length) POBJECT_NAME_INFORMATION ObjectNameInfo,
                                          _In_ ULONG Length, _Out_ PULONG ReturnLength);

static VOID BLACKBIRDFillImagePathFromFileObject(_In_opt_ PFILE_OBJECT FileObject, _Out_writes_z_(OutputChars) PWSTR Output,
                                                   _In_ size_t OutputChars)
{
    NTSTATUS status;
    ULONG bytes = 0;
    POBJECT_NAME_INFORMATION nameInfo = NULL;

    if (FileObject == NULL || Output == NULL || OutputChars == 0 || Output[0] != L'\0')
    {
        return;
    }

    status = ObQueryNameString(FileObject, NULL, 0, &bytes);
    if ((status != STATUS_INFO_LENGTH_MISMATCH && status != STATUS_BUFFER_TOO_SMALL) || bytes < sizeof(*nameInfo))
    {
        return;
    }

    nameInfo = (POBJECT_NAME_INFORMATION)BLACKBIRDAllocatePoolCompat(POOL_FLAG_PAGED, bytes, 'pNbB');
    if (nameInfo == NULL)
    {
        return;
    }

    status = ObQueryNameString(FileObject, nameInfo, bytes, &bytes);
    if (NT_SUCCESS(status) && nameInfo->Name.Buffer != NULL && nameInfo->Name.Length != 0)
    {
        (void)RtlStringCchCopyNW(Output, OutputChars, nameInfo->Name.Buffer, nameInfo->Name.Length / sizeof(WCHAR));
    }

    ExFreePoolWithTag(nameInfo, 'pNbB');
}

static VOID BLACKBIRDFillImagePathFromProcessObject(_In_ PEPROCESS Process, _Out_writes_z_(OutputChars) PWSTR Output,
                                                      _In_ size_t OutputChars)
{
    NTSTATUS status;
    PUNICODE_STRING imageName = NULL;

    if (Process == NULL || Output == NULL || OutputChars == 0 || Output[0] != L'\0')
    {
        return;
    }

    status = SeLocateProcessImageName(Process, &imageName);
    if (!NT_SUCCESS(status) || imageName == NULL || imageName->Buffer == NULL || imageName->Length == 0)
    {
        if (imageName != NULL)
        {
            ExFreePool(imageName);
        }
        return;
    }

    (void)RtlStringCchCopyNW(Output, OutputChars, imageName->Buffer, imageName->Length / sizeof(WCHAR));
    ExFreePool(imageName);
}

static VOID BLACKBIRDProcessNotifyRoutineEx(_Inout_ PEPROCESS Process, _In_ HANDLE ProcessId,
                                              _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    WCHAR imagePath[BLACKBIRD_MAX_IMAGE_PATH_CHARS];
    WCHAR commandLine[512];
    HANDLE parentPid = NULL;
    HANDLE creatorPid = NULL;
    HANDLE creatorTid = NULL;
    ULONGLONG startKey = 0;
    ULONG sessionId = 0;
    NTSTATUS createStatus = STATUS_SUCCESS;
    BOOLEAN isCreate = FALSE;
    BOOLEAN launchBound = FALSE;

    imagePath[0] = L'\0';
    commandLine[0] = L'\0';

    if (Process != NULL)
    {
        startKey = PsGetProcessStartKey(Process);
        sessionId = PsGetProcessSessionIdEx(Process);
    }

    if (CreateInfo != NULL)
    {
        isCreate = TRUE;
        parentPid = CreateInfo->ParentProcessId;
        creatorPid = CreateInfo->CreatingThreadId.UniqueProcess;
        creatorTid = CreateInfo->CreatingThreadId.UniqueThread;
        createStatus = CreateInfo->CreationStatus;

        if (NT_SUCCESS(createStatus) && ProcessId != NULL && CreateInfo->FileObject != NULL)
        {
            BLACKBIRDFillImagePathFromFileObject(CreateInfo->FileObject, imagePath, RTL_NUMBER_OF(imagePath));
            if (imagePath[0] != L'\0')
            {
                UNICODE_STRING fileObjectImagePath;

                RtlInitUnicodeString(&fileObjectImagePath, imagePath);
                launchBound = BLACKBIRDControlBindPendingLaunchProcess((UINT32)(ULONG_PTR)ProcessId,
                                                                       &fileObjectImagePath);
            }
        }

        if (!launchBound && NT_SUCCESS(createStatus) && ProcessId != NULL && CreateInfo->ImageFileName != NULL)
        {
            launchBound = BLACKBIRDControlBindPendingLaunchProcess((UINT32)(ULONG_PTR)ProcessId,
                                                                   CreateInfo->ImageFileName);
        }

        if (imagePath[0] == L'\0')
        {
            BLACKBIRDSafeCopyUnicode(CreateInfo->ImageFileName, imagePath, RTL_NUMBER_OF(imagePath));
        }

        BLACKBIRDSafeCopyUnicode(CreateInfo->CommandLine, commandLine, RTL_NUMBER_OF(commandLine));

        BLACKBIRDFillImagePathFromProcessObject(Process, imagePath, RTL_NUMBER_OF(imagePath));
        if (!launchBound && NT_SUCCESS(createStatus) && ProcessId != NULL && imagePath[0] != L'\0')
        {
            UNICODE_STRING resolvedImagePath;

            RtlInitUnicodeString(&resolvedImagePath, imagePath);
            (void)BLACKBIRDControlBindPendingLaunchProcess((UINT32)(ULONG_PTR)ProcessId, &resolvedImagePath);
        }
    }

    BLACKBIRDEtwLogProcessEvent(ProcessId, parentPid, creatorPid, creatorTid, startKey, sessionId, isCreate,
                                  createStatus, (imagePath[0] != L'\0') ? imagePath : NULL,
                                  (commandLine[0] != L'\0') ? commandLine : NULL);
}

NTSTATUS
BLACKBIRDProcessMonitorInitialize(VOID)
{
    NTSTATUS status;
    LONG failures;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (InterlockedCompareExchange(&g_ProcessMonitorRegistered, 0, 0) != 0)
    {
        return STATUS_SUCCESS;
    }

    status = PsSetCreateProcessNotifyRoutineEx(BLACKBIRDProcessNotifyRoutineEx, FALSE);
    if (!NT_SUCCESS(status))
    {
        failures = InterlockedIncrement(&g_ProcessMonitorFailureCounter);
        if (failures == 1 || ((failures & 0xFF) == 0))
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                       "BLACKBIRD: process monitor callback registration failed status=0x%08X total=%lu.\n", status,
                       (ULONG)failures);
        }
        return status;
    }

    InterlockedExchange(&g_ProcessMonitorRegistered, 1);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "BLACKBIRD: process monitor initialized.\n");
    return STATUS_SUCCESS;
}

VOID BLACKBIRDProcessMonitorUninitialize(VOID)
{
    NTSTATUS status;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        return;
    }
    if (InterlockedCompareExchange(&g_ProcessMonitorRegistered, 0, 0) == 0)
    {
        return;
    }

    status = PsSetCreateProcessNotifyRoutineEx(BLACKBIRDProcessNotifyRoutineEx, TRUE);
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(
            DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "BLACKBIRD: process monitor callback removal failed; monitor remains registered (status=0x%08X).\n",
            status);
        return;
    }

    InterlockedExchange(&g_ProcessMonitorRegistered, 0);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "BLACKBIRD: process monitor uninitialized.\n");
}

BOOLEAN
BLACKBIRDProcessMonitorSelfCheck(VOID)
{
    return (InterlockedCompareExchange(&g_ProcessMonitorRegistered, 0, 0) != 0);
}

