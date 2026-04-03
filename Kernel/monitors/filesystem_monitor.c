#include <fltkernel.h>
#include <ntstrsafe.h>
#include "..\core\control.h"
#include "..\core\runtime_config.h"
#include "..\core\unicode_utils.h"
#include "filesystem_monitor.h"

static PFLT_FILTER g_FileSystemFilter = NULL;
static volatile LONG g_FileSystemMonitorRegistered = 0;
static volatile LONG g_FileSystemMonitorFailureCounter = 0;

static BOOLEAN BLACKBIRDFsShouldHidePath(_In_opt_z_ PCWSTR Path)
{
    UNICODE_STRING pathUs;

    if (Path == NULL || Path[0] == L'\0' || !BLACKBIRDRuntimeConfigIsAntiVirtualizationEnabled())
    {
        return FALSE;
    }

    RtlInitUnicodeString(&pathUs, Path);
    return (BLACKBIRDUnicodeContainsInsensitive(&pathUs, L"\\windows\\system32\\drivers\\vmhgfs.sys", 35) ||
            BLACKBIRDUnicodeContainsInsensitive(&pathUs, L"\\windows\\system32\\drivers\\vmmouse.sys", 36) ||
            BLACKBIRDUnicodeContainsInsensitive(&pathUs, L"\\windows\\system32\\drivers\\vmrawdsk.sys", 37) ||
            BLACKBIRDUnicodeContainsInsensitive(&pathUs, L"\\windows\\system32\\drivers\\vmusbmouse.sys", 39) ||
            BLACKBIRDUnicodeContainsInsensitive(&pathUs, L"\\windows\\system32\\drivers\\vmci.sys", 33) ||
            BLACKBIRDUnicodeContainsInsensitive(&pathUs, L"\\windows\\system32\\drivers\\vsock.sys", 34) ||
            BLACKBIRDUnicodeContainsInsensitive(&pathUs, L"\\windows\\system32\\drivers\\vmbus.sys", 34) ||
            BLACKBIRDUnicodeContainsInsensitive(&pathUs, L"\\windows\\system32\\drivers\\hyperkbd.sys", 37) ||
            BLACKBIRDUnicodeContainsInsensitive(&pathUs, L"\\windows\\system32\\drivers\\vmstorfl.sys", 37) ||
            BLACKBIRDUnicodeContainsInsensitive(&pathUs, L"\\program files\\vmware\\vmware tools", 34));
}

static UINT32 BLACKBIRDMapMajorToFileOperation(_In_ UCHAR MajorFunction)
{
    switch (MajorFunction)
    {
    case IRP_MJ_CREATE:
        return BlackbirdFileOperationCreate;
    case IRP_MJ_READ:
        return BlackbirdFileOperationRead;
    case IRP_MJ_WRITE:
        return BlackbirdFileOperationWrite;
    case IRP_MJ_CLOSE:
        return BlackbirdFileOperationClose;
    case IRP_MJ_CLEANUP:
        return BlackbirdFileOperationCleanup;
    case IRP_MJ_SET_INFORMATION:
        return BlackbirdFileOperationSetInformation;
    case IRP_MJ_QUERY_INFORMATION:
        return BlackbirdFileOperationQueryInformation;
    case IRP_MJ_DIRECTORY_CONTROL:
        return BlackbirdFileOperationDirectoryControl;
    case IRP_MJ_FILE_SYSTEM_CONTROL:
        return BlackbirdFileOperationFsControl;
    default:
        return BlackbirdFileOperationUnknown;
    }
}

static VOID BLACKBIRDCaptureFilePath(_In_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
                                     _Out_writes_z_(PathChars) PWSTR Path, _In_ size_t PathChars)
{
    NTSTATUS status;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;

    if (Path == NULL || PathChars == 0)
    {
        return;
    }
    Path[0] = L'\0';

    if (KeGetCurrentIrql() <= APC_LEVEL)
    {
        status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
        if (NT_SUCCESS(status) && nameInfo != NULL)
        {
            (void)FltParseFileNameInformation(nameInfo);
            if (nameInfo->Name.Buffer != NULL && nameInfo->Name.Length != 0)
            {
                (void)RtlStringCchCopyNW(Path, PathChars, nameInfo->Name.Buffer, nameInfo->Name.Length / sizeof(WCHAR));
            }
            FltReleaseFileNameInformation(nameInfo);
            if (Path[0] != L'\0')
            {
                return;
            }
        }
    }

    if (FltObjects != NULL && FltObjects->FileObject != NULL && FltObjects->FileObject->FileName.Buffer != NULL &&
        FltObjects->FileObject->FileName.Length != 0)
    {
        (void)RtlStringCchCopyNW(Path, PathChars, FltObjects->FileObject->FileName.Buffer,
                                 FltObjects->FileObject->FileName.Length / sizeof(WCHAR));
    }
}

static VOID BLACKBIRDFillCommonFileEventFields(_In_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
                                               _Out_ BLACKBIRD_FILE_EVENT *Event)
{
    const FLT_IO_PARAMETER_BLOCK *iopb;
    UINT32 flags = 0;
    ULONG createOptionsRaw = 0;

    iopb = Data->Iopb;
    Event->ProcessId = (UINT64)(ULONG_PTR)PsGetCurrentProcessId();
    Event->ThreadId = (UINT64)(ULONG_PTR)PsGetCurrentThreadId();
    Event->Operation = BLACKBIRDMapMajorToFileOperation(iopb->MajorFunction);
    Event->MajorCode = iopb->MajorFunction;
    Event->MinorCode = iopb->MinorFunction;
    Event->IrpFlags = iopb->IrpFlags;
    Event->Status = (UINT64)(UINT32)Data->IoStatus.Status;
    Event->Information = (UINT64)Data->IoStatus.Information;
    Event->FileObject = (UINT64)(ULONG_PTR)FltObjects->FileObject;
    Event->FileId = (FltObjects->FileObject != NULL) ? (UINT64)(ULONG_PTR)FltObjects->FileObject->FsContext : 0;
    Event->Flags = BLACKBIRD_FILE_FLAG_PRE_OPERATION;

    if ((iopb->IrpFlags & IRP_PAGING_IO) != 0)
    {
        flags |= BLACKBIRD_FILE_FLAG_PAGING_IO;
    }
    if ((iopb->IrpFlags & IRP_SYNCHRONOUS_PAGING_IO) != 0)
    {
        flags |= BLACKBIRD_FILE_FLAG_SYNCHRONOUS_IO;
    }
    if ((iopb->IrpFlags & IRP_NOCACHE) != 0)
    {
        flags |= BLACKBIRD_FILE_FLAG_NON_CACHED_IO;
    }

    if (iopb->MajorFunction == IRP_MJ_CREATE)
    {
        if (iopb->Parameters.Create.SecurityContext != NULL)
        {
            Event->DesiredAccess = iopb->Parameters.Create.SecurityContext->DesiredAccess;
        }
        Event->ShareAccess = iopb->Parameters.Create.ShareAccess;
        createOptionsRaw = iopb->Parameters.Create.Options;
        Event->CreateDisposition = (createOptionsRaw >> 24) & 0xFFu;
        Event->CreateOptions = createOptionsRaw & 0x00FFFFFFu;

        if ((Event->CreateOptions & FILE_DIRECTORY_FILE) != 0)
        {
            flags |= BLACKBIRD_FILE_FLAG_DIRECTORY_FILE;
        }
        if ((Event->CreateOptions & FILE_DELETE_ON_CLOSE) != 0)
        {
            flags |= BLACKBIRD_FILE_FLAG_DELETE_ON_CLOSE;
        }
        if ((Event->CreateOptions & FILE_OPEN_REPARSE_POINT) != 0)
        {
            flags |= BLACKBIRD_FILE_FLAG_REPARSE_POINT;
        }
    }
    else if (iopb->MajorFunction == IRP_MJ_READ)
    {
        Event->Length = iopb->Parameters.Read.Length;
        Event->ByteOffset = (UINT64)iopb->Parameters.Read.ByteOffset.QuadPart;
    }
    else if (iopb->MajorFunction == IRP_MJ_WRITE)
    {
        Event->Length = iopb->Parameters.Write.Length;
        Event->ByteOffset = (UINT64)iopb->Parameters.Write.ByteOffset.QuadPart;
    }
    else if (iopb->MajorFunction == IRP_MJ_SET_INFORMATION)
    {
        Event->Length = iopb->Parameters.SetFileInformation.Length;
    }
    else if (iopb->MajorFunction == IRP_MJ_QUERY_INFORMATION)
    {
        Event->Length = iopb->Parameters.QueryFileInformation.Length;
    }
    else if (iopb->MajorFunction == IRP_MJ_DIRECTORY_CONTROL)
    {
        if (iopb->MinorFunction == IRP_MN_QUERY_DIRECTORY)
        {
            Event->Length = iopb->Parameters.DirectoryControl.QueryDirectory.Length;
        }
        else if (iopb->MinorFunction == IRP_MN_NOTIFY_CHANGE_DIRECTORY)
        {
            Event->Length = iopb->Parameters.DirectoryControl.NotifyDirectory.Length;
        }
    }

    Event->Flags |= flags;
}

_Function_class_(FLT_PRE_OPERATION_CALLBACK) static FLT_PREOP_CALLBACK_STATUS
    BLACKBIRDFsPreOperation(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
                            _Outptr_result_maybenull_ PVOID *CompletionContext)
{
    BLACKBIRD_FILE_EVENT event;
    UINT32 processPid32;

    UNREFERENCED_PARAMETER(CompletionContext);

    if (Data == NULL || FltObjects == NULL || Data->Iopb == NULL)
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (!BLACKBIRDControlHasClientsFast())
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    processPid32 = (UINT32)(ULONG_PTR)PsGetCurrentProcessId();
    if (!BLACKBIRDControlHasPidInterest(processPid32, 0, BLACKBIRD_STREAM_FILESYSTEM))
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    RtlZeroMemory(&event, sizeof(event));
    BLACKBIRDFillCommonFileEventFields(Data, FltObjects, &event);
    BLACKBIRDCaptureFilePath(Data, FltObjects, event.Path, RTL_NUMBER_OF(event.Path));

    if (BLACKBIRDFsShouldHidePath(event.Path))
    {
        Data->IoStatus.Status = STATUS_OBJECT_NAME_NOT_FOUND;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    BLACKBIRDControlPublishFileEvent(&event);

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

_Function_class_(PFLT_FILTER_UNLOAD_CALLBACK) static NTSTATUS
    BLACKBIRDFsFilterUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Flags);
    return STATUS_SUCCESS;
}

_Function_class_(PFLT_INSTANCE_SETUP_CALLBACK) static NTSTATUS
    BLACKBIRDFsInstanceSetup(_In_ PCFLT_RELATED_OBJECTS FltObjects, _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
                             _In_ DEVICE_TYPE VolumeDeviceType, _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeDeviceType);
    UNREFERENCED_PARAMETER(VolumeFilesystemType);
    return STATUS_SUCCESS;
}

static const FLT_OPERATION_REGISTRATION g_BlackbirdFsCallbacks[] = {
    {IRP_MJ_CREATE, 0, BLACKBIRDFsPreOperation, NULL},
    {IRP_MJ_READ, 0, BLACKBIRDFsPreOperation, NULL},
    {IRP_MJ_WRITE, 0, BLACKBIRDFsPreOperation, NULL},
    {IRP_MJ_CLOSE, 0, BLACKBIRDFsPreOperation, NULL},
    {IRP_MJ_CLEANUP, 0, BLACKBIRDFsPreOperation, NULL},
    {IRP_MJ_SET_INFORMATION, 0, BLACKBIRDFsPreOperation, NULL},
    {IRP_MJ_QUERY_INFORMATION, 0, BLACKBIRDFsPreOperation, NULL},
    {IRP_MJ_DIRECTORY_CONTROL, 0, BLACKBIRDFsPreOperation, NULL},
    {IRP_MJ_FILE_SYSTEM_CONTROL, 0, BLACKBIRDFsPreOperation, NULL},
    {IRP_MJ_OPERATION_END}};

static const FLT_REGISTRATION g_BlackbirdFsRegistration = {sizeof(FLT_REGISTRATION),
                                                           FLT_REGISTRATION_VERSION,
                                                           0,
                                                           NULL,
                                                           g_BlackbirdFsCallbacks,
                                                           BLACKBIRDFsFilterUnload,
                                                           BLACKBIRDFsInstanceSetup,
                                                           NULL,
                                                           NULL,
                                                           NULL,
                                                           NULL,
                                                           NULL,
                                                           NULL,
                                                           NULL};

NTSTATUS
BLACKBIRDFileSystemMonitorInitialize(_In_ PDRIVER_OBJECT DriverObject)
{
    NTSTATUS status;
    LONG failures;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (DriverObject == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (InterlockedCompareExchange(&g_FileSystemMonitorRegistered, 0, 0) != 0)
    {
        return STATUS_SUCCESS;
    }

    status = FltRegisterFilter(DriverObject, &g_BlackbirdFsRegistration, &g_FileSystemFilter);
    if (!NT_SUCCESS(status))
    {
        failures = InterlockedIncrement(&g_FileSystemMonitorFailureCounter);
        if (failures == 1 || ((failures & 0xFF) == 0))
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                       "BLACKBIRD: filesystem monitor filter registration failed status=0x%08X total=%lu.\n", status,
                       (ULONG)failures);
        }
        g_FileSystemFilter = NULL;
        return status;
    }

    status = FltStartFiltering(g_FileSystemFilter);
    if (!NT_SUCCESS(status))
    {
        failures = InterlockedIncrement(&g_FileSystemMonitorFailureCounter);
        if (failures == 1 || ((failures & 0xFF) == 0))
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                       "BLACKBIRD: filesystem monitor start filtering failed status=0x%08X total=%lu.\n", status,
                       (ULONG)failures);
        }
        FltUnregisterFilter(g_FileSystemFilter);
        g_FileSystemFilter = NULL;
        return status;
    }

    InterlockedExchange(&g_FileSystemMonitorRegistered, 1);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "BLACKBIRD: filesystem monitor initialized.\n");
    return STATUS_SUCCESS;
}

VOID BLACKBIRDFileSystemMonitorUninitialize(VOID)
{
    PFLT_FILTER filter;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        return;
    }
    if (InterlockedCompareExchange(&g_FileSystemMonitorRegistered, 0, 0) == 0)
    {
        return;
    }

    InterlockedExchange(&g_FileSystemMonitorRegistered, 0);
    filter = g_FileSystemFilter;
    g_FileSystemFilter = NULL;
    if (filter != NULL)
    {
        FltUnregisterFilter(filter);
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "BLACKBIRD: filesystem monitor uninitialized.\n");
}

BOOLEAN
BLACKBIRDFileSystemMonitorSelfCheck(VOID)
{
    if (InterlockedCompareExchange(&g_FileSystemMonitorRegistered, 0, 0) == 0)
    {
        return FALSE;
    }

    return (g_FileSystemFilter != NULL);
}
