#include <ntddk.h>
#include <ntstrsafe.h>
#include "..\core\control.h"
#include "..\core\pool_compat.h"
#include "..\core\runtime_config.h"
#include "..\telemetry\etw.h"
#include "..\core\unicode_utils.h"
#include "process_monitor.h"

static volatile LONG g_ProcessMonitorRegistered = 0;
static volatile LONG g_ProcessMonitorFailureCounter = 0;
static volatile ULONG g_BlackbirdInterfacePid = 0;
static volatile LONG g_BlackbirdInterfaceReady = 0;
static volatile ULONG g_BlackbirdControllerPid = 0;
static volatile LONG g_BlackbirdControllerReady = 0;
static volatile ULONG g_ServicesPid = 0;

NTKERNELAPI ULONGLONG PsGetProcessStartKey(_In_ PEPROCESS Process);
NTKERNELAPI ULONG PsGetProcessSessionIdEx(_In_ PEPROCESS Process);
NTSYSAPI NTSTATUS NTAPI SeLocateProcessImageName(_In_ PEPROCESS Process, _Out_ PUNICODE_STRING *pImageFileName);
NTSYSAPI NTSTATUS NTAPI ObQueryNameString(_In_ PVOID Object,
                                          _Out_writes_bytes_opt_(Length) POBJECT_NAME_INFORMATION ObjectNameInfo,
                                          _In_ ULONG Length, _Out_ PULONG ReturnLength);

static BOOLEAN BLACKBIRDProcessPathMatchesImage(_In_z_ PCWSTR ImageName, _In_opt_ PCUNICODE_STRING Candidate)
{
    UNICODE_STRING expected;
    UNICODE_STRING baseName;
    USHORT i;

    if (Candidate == NULL || Candidate->Buffer == NULL || Candidate->Length == 0 || ImageName == NULL ||
        ImageName[0] == L'\0')
    {
        return FALSE;
    }

    RtlInitUnicodeString(&expected, ImageName);
    if (BLACKBIRDUnicodeEquals(Candidate, &expected, TRUE))
    {
        return TRUE;
    }

    baseName = *Candidate;
    for (i = (USHORT)(Candidate->Length / sizeof(WCHAR)); i > 0; --i)
    {
        if (Candidate->Buffer[i - 1] == L'\\' || Candidate->Buffer[i - 1] == L'/')
        {
            baseName.Buffer = Candidate->Buffer + i;
            baseName.Length = Candidate->Length - (USHORT)(i * sizeof(WCHAR));
            baseName.MaximumLength = baseName.Length;
            break;
        }
    }

    return BLACKBIRDUnicodeEquals(&baseName, &expected, TRUE);
}

static VOID BLACKBIRDProcessMonitorTrackProtectedPid(_In_ UINT32 ProcessId, _In_reads_z_(ImageChars) PCWSTR ImagePath,
                                                     _In_ USHORT ImageChars)
{
    UNICODE_STRING image;

    if (ProcessId == 0 || ImagePath == NULL || ImageChars == 0)
    {
        return;
    }

    image.Buffer = (PWSTR)ImagePath;
    image.Length = (USHORT)(ImageChars * sizeof(WCHAR));
    image.MaximumLength = image.Length;

    if (BLACKBIRDProcessPathMatchesImage(L"BlackbirdInterface.exe", &image))
    {
        InterlockedExchange((volatile LONG *)&g_BlackbirdInterfacePid, (LONG)ProcessId);
        InterlockedExchange(&g_BlackbirdInterfaceReady, 0);
    }
    if (BLACKBIRDProcessPathMatchesImage(L"BlackbirdController.exe", &image))
    {
        InterlockedExchange((volatile LONG *)&g_BlackbirdControllerPid, (LONG)ProcessId);
        InterlockedExchange(&g_BlackbirdControllerReady, 0);
    }
    if (BLACKBIRDProcessPathMatchesImage(L"services.exe", &image))
    {
        InterlockedExchange((volatile LONG *)&g_ServicesPid, (LONG)ProcessId);
    }
}

static VOID BLACKBIRDProcessMonitorClearProtectedPid(_In_ UINT32 ProcessId)
{
    if (ProcessId == 0)
    {
        return;
    }

    if ((UINT32)InterlockedCompareExchange((volatile LONG *)&g_BlackbirdInterfacePid, 0, 0) == ProcessId)
    {
        InterlockedCompareExchange((volatile LONG *)&g_BlackbirdInterfacePid, 0, (LONG)ProcessId);
        InterlockedExchange(&g_BlackbirdInterfaceReady, 0);
    }
    if ((UINT32)InterlockedCompareExchange((volatile LONG *)&g_BlackbirdControllerPid, 0, 0) == ProcessId)
    {
        InterlockedCompareExchange((volatile LONG *)&g_BlackbirdControllerPid, 0, (LONG)ProcessId);
        InterlockedExchange(&g_BlackbirdControllerReady, 0);
    }
    if ((UINT32)InterlockedCompareExchange((volatile LONG *)&g_ServicesPid, 0, 0) == ProcessId)
    {
        InterlockedCompareExchange((volatile LONG *)&g_ServicesPid, 0, (LONG)ProcessId);
    }
}

static VOID BLACKBIRDFillImagePathFromFileObject(_In_opt_ PFILE_OBJECT FileObject,
                                                 _Out_writes_z_(OutputChars) PWSTR Output, _In_ size_t OutputChars)
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

static VOID BLACKBIRDProcessMonitorDetectImageTampering(_In_ HANDLE ProcessId,
                                                        _Inout_ PPS_CREATE_NOTIFY_INFO CreateInfo,
                                                        _In_opt_z_ PCWSTR ImagePath)
{
    WCHAR reason[512];
    ULONG indicators = 0;
    ULONG severity;

    if (CreateInfo == NULL || CreateInfo->FileObject == NULL || ProcessId == NULL)
    {
        return;
    }

    if (CreateInfo->FileObject->DeletePending)
    {
        indicators |= 0x1u;
    }
    if (CreateInfo->FileObject->WriteAccess || CreateInfo->FileObject->SharedWrite)
    {
        indicators |= 0x2u;
    }
    if (CreateInfo->FileObject->DeleteAccess || CreateInfo->FileObject->SharedDelete)
    {
        indicators |= 0x4u;
    }

    if (indicators == 0)
    {
        return;
    }

    severity = ((indicators & 0x1u) != 0u) ? 7u : 6u;
    reason[0] = L'\0';
    (void)RtlStringCchPrintfW(
        reason, RTL_NUMBER_OF(reason),
        L"process image FILE_OBJECT abnormality deletePending=%u writeAccess=%u sharedWrite=%u deleteAccess=%u sharedDelete=%u path=%ws — associated with image tampering techniques such as Ghosting, Herpaderping, and Doppelganging",
        (unsigned int)(CreateInfo->FileObject->DeletePending ? 1u : 0u),
        (unsigned int)(CreateInfo->FileObject->WriteAccess ? 1u : 0u),
        (unsigned int)(CreateInfo->FileObject->SharedWrite ? 1u : 0u),
        (unsigned int)(CreateInfo->FileObject->DeleteAccess ? 1u : 0u),
        (unsigned int)(CreateInfo->FileObject->SharedDelete ? 1u : 0u),
        (ImagePath != NULL && ImagePath[0] != L'\0') ? ImagePath : L"(unknown)");

    if ((indicators & 0x1u) != 0u)
    {
        BLACKBIRDEtwLogDetectionEvent("PROCESS_IMAGE_GHOSTING_SUSPECT", severity, ProcessId, ProcessId, 0, indicators,
                                      0, reason);
    }
    else
    {
        BLACKBIRDEtwLogDetectionEvent("PROCESS_IMAGE_TAMPER_SUSPECT", severity, ProcessId, ProcessId, 0, indicators, 0,
                                      reason);
    }
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
                launchBound =
                    BLACKBIRDControlBindPendingLaunchProcess((UINT32)(ULONG_PTR)ProcessId, &fileObjectImagePath);
                BLACKBIRDProcessMonitorTrackProtectedPid((UINT32)(ULONG_PTR)ProcessId, imagePath,
                                                         (USHORT)wcslen(imagePath));
            }
        }

        if (!launchBound && NT_SUCCESS(createStatus) && ProcessId != NULL && CreateInfo->ImageFileName != NULL)
        {
            launchBound =
                BLACKBIRDControlBindPendingLaunchProcess((UINT32)(ULONG_PTR)ProcessId, CreateInfo->ImageFileName);
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
        if (ProcessId != NULL && imagePath[0] != L'\0')
        {
            BLACKBIRDProcessMonitorTrackProtectedPid((UINT32)(ULONG_PTR)ProcessId, imagePath,
                                                     (USHORT)wcslen(imagePath));
        }
    }
    else if (ProcessId != NULL)
    {
        BLACKBIRDProcessMonitorClearProtectedPid((UINT32)(ULONG_PTR)ProcessId);
    }

    if (isCreate && NT_SUCCESS(createStatus))
    {
        BLACKBIRDProcessMonitorDetectImageTampering(ProcessId, CreateInfo, imagePath);
    }

    BLACKBIRDEtwLogProcessEvent(ProcessId, parentPid, creatorPid, creatorTid, startKey, sessionId, isCreate,
                                createStatus, (imagePath[0] != L'\0') ? imagePath : NULL,
                                (commandLine[0] != L'\0') ? commandLine : NULL);

    /* PPID spoofing: when a caller uses PROC_THREAD_ATTRIBUTE_PARENT_PROCESS to override
     * the inherited parent, the kernel-reported ParentProcessId diverges from the
     * CreatingThreadId.UniqueProcess field.  Normal CreateProcess always has them equal.
     * Only flag in user sessions (sessionId > 0) to suppress noise from SCM/WMI patterns
     * and skip the System process (PID 4). */
    if (isCreate && NT_SUCCESS(createStatus) && ProcessId != NULL && sessionId > 0 && parentPid != NULL &&
        creatorPid != NULL && parentPid != creatorPid && (ULONG_PTR)parentPid > 4 && (ULONG_PTR)creatorPid > 4)
    {
        BLACKBIRDEtwLogDetectionEvent(
            "PARENT_PID_SPOOF_SUSPECT", 5, ProcessId, ProcessId, 0, 0, 0,
            L"process has explicit parent-process override — ParentPid differs from CreatorPid");
    }
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

    InterlockedExchange((volatile LONG *)&g_BlackbirdInterfacePid, 0);
    InterlockedExchange(&g_BlackbirdInterfaceReady, 0);
    InterlockedExchange((volatile LONG *)&g_BlackbirdControllerPid, 0);
    InterlockedExchange(&g_BlackbirdControllerReady, 0);

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
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "BLACKBIRD: process monitor callback removal failed; monitor remains registered (status=0x%08X).\n",
                   status);
        return;
    }

    InterlockedExchange(&g_ProcessMonitorRegistered, 0);
    InterlockedExchange((volatile LONG *)&g_BlackbirdInterfacePid, 0);
    InterlockedExchange(&g_BlackbirdInterfaceReady, 0);
    InterlockedExchange((volatile LONG *)&g_BlackbirdControllerPid, 0);
    InterlockedExchange(&g_BlackbirdControllerReady, 0);
    InterlockedExchange((volatile LONG *)&g_ServicesPid, 0);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "BLACKBIRD: process monitor uninitialized.\n");
}

BOOLEAN
BLACKBIRDProcessMonitorSelfCheck(VOID)
{
    return (InterlockedCompareExchange(&g_ProcessMonitorRegistered, 0, 0) != 0);
}

BOOLEAN BLACKBIRDProcessMonitorIsInterfacePid(_In_ UINT32 ProcessId)
{
    if (ProcessId == 0)
    {
        return FALSE;
    }

    return (UINT32)InterlockedCompareExchange((volatile LONG *)&g_BlackbirdInterfacePid, 0, 0) == ProcessId;
}

BOOLEAN BLACKBIRDProcessMonitorIsControllerPid(_In_ UINT32 ProcessId)
{
    if (ProcessId == 0)
    {
        return FALSE;
    }

    return (UINT32)InterlockedCompareExchange((volatile LONG *)&g_BlackbirdControllerPid, 0, 0) == ProcessId;
}

BOOLEAN BLACKBIRDProcessMonitorIsProtectedPid(_In_ UINT32 ProcessId)
{
    if (ProcessId == 0)
    {
        return FALSE;
    }

    if (BLACKBIRDProcessMonitorIsInterfacePid(ProcessId) && BLACKBIRDRuntimeConfigIsInterfaceProtectedAccessEnabled() &&
        (InterlockedCompareExchange(&g_BlackbirdInterfaceReady, 0, 0) != 0))
    {
        return TRUE;
    }

    return BLACKBIRDProcessMonitorIsControllerPid(ProcessId) &&
           BLACKBIRDRuntimeConfigIsControllerProtectedAccessEnabled() &&
           (InterlockedCompareExchange(&g_BlackbirdControllerReady, 0, 0) != 0);
}

BOOLEAN BLACKBIRDProcessMonitorMarkInterfaceReady(_In_ UINT32 ProcessId)
{
    UINT32 trackedInterfacePid;

    if (ProcessId == 0)
    {
        return FALSE;
    }

    trackedInterfacePid = (UINT32)InterlockedCompareExchange((volatile LONG *)&g_BlackbirdInterfacePid, 0, 0);
    if (trackedInterfacePid != ProcessId)
    {
        return FALSE;
    }

    InterlockedExchange(&g_BlackbirdInterfaceReady, 1);
    return TRUE;
}

BOOLEAN BLACKBIRDProcessMonitorMarkControllerReady(_In_ UINT32 ProcessId)
{
    UINT32 trackedControllerPid;

    if (ProcessId == 0)
    {
        return FALSE;
    }

    trackedControllerPid = (UINT32)InterlockedCompareExchange((volatile LONG *)&g_BlackbirdControllerPid, 0, 0);
    if (trackedControllerPid != ProcessId)
    {
        return FALSE;
    }

    InterlockedExchange(&g_BlackbirdControllerReady, 1);
    return TRUE;
}
BOOLEAN BLACKBIRDProcessMonitorIsTrustedProtectedCaller(_In_ UINT32 CallerPid, _In_ UINT32 TargetPid)
{
    UINT32 interfacePid;
    UINT32 controllerPid;
    UINT32 servicesPid;

    if (CallerPid == 0 || TargetPid == 0)
    {
        return FALSE;
    }
    if (CallerPid == TargetPid)
    {
        return TRUE;
    }

    interfacePid = (UINT32)InterlockedCompareExchange((volatile LONG *)&g_BlackbirdInterfacePid, 0, 0);
    controllerPid = (UINT32)InterlockedCompareExchange((volatile LONG *)&g_BlackbirdControllerPid, 0, 0);
    servicesPid = (UINT32)InterlockedCompareExchange((volatile LONG *)&g_ServicesPid, 0, 0);

    if (CallerPid == servicesPid)
    {
        return TRUE;
    }

    if (CallerPid == interfacePid && TargetPid == controllerPid)
    {
        return TRUE;
    }
    if (CallerPid == controllerPid && TargetPid == interfacePid)
    {
        return TRUE;
    }

    return FALSE;
}
