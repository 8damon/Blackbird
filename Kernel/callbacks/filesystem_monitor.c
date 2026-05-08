#include <fltkernel.h>
#include <ntstrsafe.h>
#include "..\core\control.h"
#include "..\core\tempus_debug.h"
#include "..\core\runtime_config.h"
#include "..\core\unicode_utils.h"
#include "..\hooks\monitor\ntapi_monitor.h"
#include "filesystem_monitor.h"

static PFLT_FILTER g_FileSystemFilter = NULL;
static volatile LONG g_FileSystemMonitorRegistered = 0;
static volatile LONG g_FileSystemMonitorFailureCounter = 0;

#define BK_FS_TARGET_STREAM_MASK                                                                          \
    (BK_STREAM_HANDLE | BK_STREAM_MEMORY | BK_STREAM_THREAD | BK_STREAM_FILESYSTEM | BK_STREAM_REGISTRY | \
     BK_STREAM_TIMING | BK_STREAM_ENTERPRISE)
#define BK_FS_LIT_CHARS(_Literal) ((USHORT)(RTL_NUMBER_OF(_Literal) - 1))

static BOOLEAN BkcfsPathContainsBlackbirdArtifact(_In_opt_z_ PCWSTR Path)
{
    UNICODE_STRING pathUs;

    if (Path == NULL || Path[0] == L'\0')
    {
        return FALSE;
    }

    RtlInitUnicodeString(&pathUs, Path);
    return (
        BkstrUnicodeContainsInsensitive(&pathUs, L"\\programdata\\blackbird",
                                        BK_FS_LIT_CHARS(L"\\programdata\\blackbird")) ||
        BkstrUnicodeContainsInsensitive(&pathUs, L"\\blackbird\\", BK_FS_LIT_CHARS(L"\\blackbird\\")) ||
        BkstrUnicodeContainsInsensitive(&pathUs, L"\\blackbird", BK_FS_LIT_CHARS(L"\\blackbird")) ||
        BkstrUnicodeContainsInsensitive(&pathUs, L"blackbird.sys", BK_FS_LIT_CHARS(L"blackbird.sys")) ||
        BkstrUnicodeContainsInsensitive(&pathUs, L"blackbirdcontroller.exe",
                                        BK_FS_LIT_CHARS(L"blackbirdcontroller.exe")) ||
        BkstrUnicodeContainsInsensitive(&pathUs, L"blackbirdinterface.exe",
                                        BK_FS_LIT_CHARS(L"blackbirdinterface.exe")) ||
        BkstrUnicodeContainsInsensitive(&pathUs, L"blackbirdnetsvc.exe", BK_FS_LIT_CHARS(L"blackbirdnetsvc.exe")) ||
        BkstrUnicodeContainsInsensitive(&pathUs, L"blackbirddllhost.exe", BK_FS_LIT_CHARS(L"blackbirddllhost.exe")) ||
        BkstrUnicodeContainsInsensitive(&pathUs, L"sr71.dll", BK_FS_LIT_CHARS(L"sr71.dll")) ||
        BkstrUnicodeContainsInsensitive(&pathUs, L"j58.dll", BK_FS_LIT_CHARS(L"j58.dll")) ||
        BkstrUnicodeContainsInsensitive(&pathUs, L"bkdc.dll", BK_FS_LIT_CHARS(L"bkdc.dll")));
}

static BOOLEAN BkcfsPathContainsBlackbirdRuntimeAccessArtifact(_In_opt_z_ PCWSTR Path)
{
    UNICODE_STRING pathUs;

    if (Path == NULL || Path[0] == L'\0')
    {
        return FALSE;
    }

    RtlInitUnicodeString(&pathUs, Path);
    return (BkstrUnicodeContainsInsensitive(&pathUs, L"sr71.dll", BK_FS_LIT_CHARS(L"sr71.dll")) ||
            BkstrUnicodeContainsInsensitive(&pathUs, L"j58.dll", BK_FS_LIT_CHARS(L"j58.dll")) ||
            BkstrUnicodeContainsInsensitive(&pathUs, L"bkdc.dll", BK_FS_LIT_CHARS(L"bkdc.dll")) ||
            BkstrUnicodeContainsInsensitive(&pathUs, L"sr71-", BK_FS_LIT_CHARS(L"sr71-")));
}

static BOOLEAN BkcfsShouldConcealBlackbirdArtifact(_In_ const BK_FILE_EVENT *Event)
{
    if (Event == NULL || !BkcfsPathContainsBlackbirdArtifact(Event->Path))
    {
        return FALSE;
    }

    return !BkcfsPathContainsBlackbirdRuntimeAccessArtifact(Event->Path);
}

static BOOLEAN BkcfsShouldHidePath(_In_opt_z_ PCWSTR Path)
{
    UNICODE_STRING pathUs;

    if (Path == NULL || Path[0] == L'\0' || !BkrtIsAntiVirtualizationEnabled())
    {
        return FALSE;
    }

    RtlInitUnicodeString(&pathUs, Path);
    return (BkstrUnicodeContainsInsensitive(&pathUs, L"\\windows\\system32\\drivers\\vmhgfs.sys", 35) ||
            BkstrUnicodeContainsInsensitive(&pathUs, L"\\windows\\system32\\drivers\\vmmouse.sys", 36) ||
            BkstrUnicodeContainsInsensitive(&pathUs, L"\\windows\\system32\\drivers\\vmrawdsk.sys", 37) ||
            BkstrUnicodeContainsInsensitive(&pathUs, L"\\windows\\system32\\drivers\\vmusbmouse.sys", 39) ||
            BkstrUnicodeContainsInsensitive(&pathUs, L"\\windows\\system32\\drivers\\vmci.sys", 33) ||
            BkstrUnicodeContainsInsensitive(&pathUs, L"\\windows\\system32\\drivers\\vsock.sys", 34) ||
            BkstrUnicodeContainsInsensitive(&pathUs, L"\\windows\\system32\\drivers\\vmbus.sys", 34) ||
            BkstrUnicodeContainsInsensitive(&pathUs, L"\\windows\\system32\\drivers\\hyperkbd.sys", 37) ||
            BkstrUnicodeContainsInsensitive(&pathUs, L"\\windows\\system32\\drivers\\vmstorfl.sys", 37) ||
            BkstrUnicodeContainsInsensitive(&pathUs, L"\\program files\\vmware\\vmware tools", 34));
}

static BOOLEAN BkcfsFileOperationIsWriteLike(_In_ const BK_FILE_EVENT *Event)
{
    if (Event == NULL)
    {
        return FALSE;
    }

    if (Event->Operation == BlackbirdFileOperationWrite || Event->Operation == BlackbirdFileOperationSetInformation ||
        Event->Operation == BlackbirdFileOperationFsControl)
    {
        return TRUE;
    }

    if (Event->Operation != BlackbirdFileOperationCreate)
    {
        return FALSE;
    }

    if ((Event->DesiredAccess &
         (FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES | DELETE)) != 0)
    {
        return TRUE;
    }

    return (Event->CreateDisposition == FILE_CREATE || Event->CreateDisposition == FILE_OPEN_IF ||
            Event->CreateDisposition == FILE_OVERWRITE || Event->CreateDisposition == FILE_OVERWRITE_IF ||
            Event->CreateDisposition == FILE_SUPERSEDE);
}

static UINT32 BkcfsEnterpriseAccessFlags(_In_ const BK_FILE_EVENT *Event)
{
    UINT32 flags = 0;
    BOOLEAN writeLike = BkcfsFileOperationIsWriteLike(Event);

    if (Event == NULL)
    {
        return 0;
    }

    if (writeLike)
    {
        flags |= BK_ENTERPRISE_FLAG_WRITE;
    }
    else
    {
        flags |= BK_ENTERPRISE_FLAG_QUERY;
    }
    if (Event->Operation == BlackbirdFileOperationCreate)
    {
        flags |= BK_ENTERPRISE_FLAG_CREATE;
    }

    return flags;
}

static BOOLEAN BkcfsClassifyEnterprisePath(_In_opt_z_ PCWSTR Path, _In_ const BK_FILE_EVENT *Event,
                                           _Out_ UINT32 *Operation, _Out_ UINT32 *Flags)
{
    UNICODE_STRING pathUs;
    UINT32 accessFlags;

    if (Path == NULL || Path[0] == L'\0' || Event == NULL || Operation == NULL || Flags == NULL)
    {
        return FALSE;
    }

    RtlInitUnicodeString(&pathUs, Path);
    accessFlags = BkcfsEnterpriseAccessFlags(Event);

    if (BkstrUnicodeContainsInsensitive(&pathUs, L"\\windows\\system32\\config\\sam",
                                        BK_FS_LIT_CHARS(L"\\windows\\system32\\config\\sam")) ||
        BkstrUnicodeContainsInsensitive(&pathUs, L"\\windows\\system32\\config\\security",
                                        BK_FS_LIT_CHARS(L"\\windows\\system32\\config\\security")) ||
        BkstrUnicodeContainsInsensitive(&pathUs, L"\\windows\\system32\\config\\system",
                                        BK_FS_LIT_CHARS(L"\\windows\\system32\\config\\system")) ||
        BkstrUnicodeContainsInsensitive(&pathUs, L"\\windows\\system32\\config\\regback\\sam",
                                        BK_FS_LIT_CHARS(L"\\windows\\system32\\config\\regback\\sam")) ||
        BkstrUnicodeContainsInsensitive(&pathUs, L"\\windows\\system32\\config\\regback\\security",
                                        BK_FS_LIT_CHARS(L"\\windows\\system32\\config\\regback\\security")) ||
        BkstrUnicodeContainsInsensitive(&pathUs, L"\\windows\\system32\\config\\regback\\system",
                                        BK_FS_LIT_CHARS(L"\\windows\\system32\\config\\regback\\system")))
    {
        *Operation = BkEnterpriseOperationFileCredentialStoreAccess;
        *Flags = BK_ENTERPRISE_FLAG_HIGH_SIGNAL | BK_ENTERPRISE_FLAG_CRITICAL | accessFlags |
                 BK_ENTERPRISE_FLAG_CREDENTIAL_FILE | BK_ENTERPRISE_FLAG_SECURITY_HIVE |
                 BK_ENTERPRISE_FLAG_KERBEROS_NTLM;
        return TRUE;
    }

    if (BkstrUnicodeContainsInsensitive(&pathUs, L"\\ntds.dit", BK_FS_LIT_CHARS(L"\\ntds.dit")) ||
        BkstrUnicodeContainsInsensitive(&pathUs, L"\\windows\\ntds\\", BK_FS_LIT_CHARS(L"\\windows\\ntds\\")))
    {
        *Operation = BkEnterpriseOperationFileCredentialStoreAccess;
        *Flags = BK_ENTERPRISE_FLAG_HIGH_SIGNAL | BK_ENTERPRISE_FLAG_CRITICAL | accessFlags |
                 BK_ENTERPRISE_FLAG_CREDENTIAL_FILE | BK_ENTERPRISE_FLAG_KERBEROS_NTLM;
        return TRUE;
    }

    if (BkstrUnicodeContainsInsensitive(&pathUs, L"\\microsoft\\credentials\\",
                                        BK_FS_LIT_CHARS(L"\\microsoft\\credentials\\")) ||
        BkstrUnicodeContainsInsensitive(&pathUs, L"\\microsoft\\protect\\",
                                        BK_FS_LIT_CHARS(L"\\microsoft\\protect\\")) ||
        BkstrUnicodeContainsInsensitive(&pathUs, L"\\microsoft\\vault\\", BK_FS_LIT_CHARS(L"\\microsoft\\vault\\")))
    {
        *Operation = BkEnterpriseOperationFileDirectoryCredentialAccess;
        *Flags = BK_ENTERPRISE_FLAG_HIGH_SIGNAL | accessFlags | BK_ENTERPRISE_FLAG_CREDENTIAL_FILE;
        return TRUE;
    }

    if (BkcfsFileOperationIsWriteLike(Event) &&
        BkstrUnicodeContainsInsensitive(&pathUs, L"\\windows\\system32\\drivers\\",
                                        BK_FS_LIT_CHARS(L"\\windows\\system32\\drivers\\")))
    {
        *Operation = BkEnterpriseOperationFileDriverArtifactAccess;
        *Flags = BK_ENTERPRISE_FLAG_HIGH_SIGNAL | accessFlags | BK_ENTERPRISE_FLAG_DRIVER_ARTIFACT;
        return TRUE;
    }

    return FALSE;
}

static VOID BkcfsPublishEnterpriseEvent(_In_ const BK_FILE_EVENT *FileEvent)
{
    BK_ENTERPRISE_EVENT event;
    UINT32 operation = BkEnterpriseOperationUnknown;
    UINT32 flags = 0;
    UINT32 pid32;

    if (FileEvent == NULL)
    {
        return;
    }

    pid32 = (UINT32)FileEvent->ProcessId;
    if (pid32 == 0 || !BkctlHasPidInterest(pid32, 0, BK_STREAM_ENTERPRISE))
    {
        return;
    }
    if (!BkcfsClassifyEnterprisePath(FileEvent->Path, FileEvent, &operation, &flags))
    {
        return;
    }

    RtlZeroMemory(&event, sizeof(event));
    event.ProcessId = FileEvent->ProcessId;
    event.ThreadId = FileEvent->ThreadId;
    event.ObjectAddress = FileEvent->FileObject;
    event.Aux0 = FileEvent->Length;
    event.Aux1 = FileEvent->FileId;
    event.Operation = operation;
    event.SubOperation = FileEvent->Operation;
    event.Flags = flags;
    event.DesiredAccess = FileEvent->DesiredAccess;
    event.Status = (UINT32)FileEvent->Status;
    BkctlPublishEnterpriseEvent(&event);
}

static UINT32 BkcfsMapMajorToFileOperation(_In_ UCHAR MajorFunction)
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

static VOID BkcfsCaptureFilePath(_In_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
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

static VOID BkcfsFillCommonFileEventFields(_In_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
                                           _Out_ BK_FILE_EVENT *Event)
{
    const FLT_IO_PARAMETER_BLOCK *iopb;
    UINT32 flags = 0;
    ULONG createOptionsRaw = 0;

    iopb = Data->Iopb;
    Event->ProcessId = (UINT64)(ULONG_PTR)PsGetCurrentProcessId();
    Event->ThreadId = (UINT64)(ULONG_PTR)PsGetCurrentThreadId();
    Event->Operation = BkcfsMapMajorToFileOperation(iopb->MajorFunction);
    Event->MajorCode = iopb->MajorFunction;
    Event->MinorCode = iopb->MinorFunction;
    Event->IrpFlags = iopb->IrpFlags;
    Event->Status = (UINT64)(UINT32)Data->IoStatus.Status;
    Event->Information = (UINT64)Data->IoStatus.Information;
    Event->FileObject = (UINT64)(ULONG_PTR)FltObjects->FileObject;
    Event->FileId = (FltObjects->FileObject != NULL) ? (UINT64)(ULONG_PTR)FltObjects->FileObject->FsContext : 0;
    Event->Flags = BK_FILE_FLAG_PRE_OPERATION;

    if ((iopb->IrpFlags & IRP_PAGING_IO) != 0)
    {
        flags |= BK_FILE_FLAG_PAGING_IO;
    }
    if ((iopb->IrpFlags & IRP_SYNCHRONOUS_PAGING_IO) != 0)
    {
        flags |= BK_FILE_FLAG_SYNCHRONOUS_IO;
    }
    if ((iopb->IrpFlags & IRP_NOCACHE) != 0)
    {
        flags |= BK_FILE_FLAG_NON_CACHED_IO;
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
            flags |= BK_FILE_FLAG_DIRECTORY_FILE;
        }
        if ((Event->CreateOptions & FILE_DELETE_ON_CLOSE) != 0)
        {
            flags |= BK_FILE_FLAG_DELETE_ON_CLOSE;
        }
        if ((Event->CreateOptions & FILE_OPEN_REPARSE_POINT) != 0)
        {
            flags |= BK_FILE_FLAG_REPARSE_POINT;
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
    BkcfsPreOperation(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
                      _Outptr_result_maybenull_ PVOID *CompletionContext)
{
    ULONGLONG tempusStartQpc = BktmpEnter(BktmpSubsystemFileSystemMonitor);
    BK_FILE_EVENT event;
    UINT32 processPid32;
    UINT32 matchedStreamMask;
    BOOLEAN hasFilesystemInterest;
    BOOLEAN hasEnterpriseInterest;
    BOOLEAN isTargetProcess;

    UNREFERENCED_PARAMETER(CompletionContext);

    if (Data == NULL || FltObjects == NULL || Data->Iopb == NULL)
    {
        BktmpLeave(BktmpSubsystemFileSystemMonitor, tempusStartQpc);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (!BkctlIsArmedFast())
    {
        BktmpLeave(BktmpSubsystemFileSystemMonitor, tempusStartQpc);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    processPid32 = (UINT32)(ULONG_PTR)PsGetCurrentProcessId();
    matchedStreamMask = BkctlQueryPidInterest(processPid32, 0, BK_FS_TARGET_STREAM_MASK);
    hasFilesystemInterest = ((matchedStreamMask & BK_STREAM_FILESYSTEM) != 0);
    hasEnterpriseInterest = ((matchedStreamMask & BK_STREAM_ENTERPRISE) != 0);
    isTargetProcess = (matchedStreamMask != 0);
    if (!hasFilesystemInterest && !hasEnterpriseInterest && !isTargetProcess)
    {
        BktmpLeave(BktmpSubsystemFileSystemMonitor, tempusStartQpc);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    RtlZeroMemory(&event, sizeof(event));
    BkcfsFillCommonFileEventFields(Data, FltObjects, &event);
    BkcfsCaptureFilePath(Data, FltObjects, event.Path, RTL_NUMBER_OF(event.Path));

    if (isTargetProcess && (BkcfsShouldHidePath(event.Path) || BkcfsShouldConcealBlackbirdArtifact(&event)))
    {
        BkntkiRecordSanitizerHit(BkcfsShouldConcealBlackbirdArtifact(&event) ? BkDiagSanitizerFilesystemBlackbird
                                                                             : BkDiagSanitizerFilesystemAntiVm);
        Data->IoStatus.Status = STATUS_OBJECT_NAME_NOT_FOUND;
        Data->IoStatus.Information = 0;
        BktmpLeave(BktmpSubsystemFileSystemMonitor, tempusStartQpc);
        return FLT_PREOP_COMPLETE;
    }

    if (hasFilesystemInterest)
    {
        BkctlPublishFileEvent(&event);
    }
    if (hasEnterpriseInterest)
    {
        BkcfsPublishEnterpriseEvent(&event);
    }

    BktmpLeave(BktmpSubsystemFileSystemMonitor, tempusStartQpc);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

_Function_class_(PFLT_FILTER_UNLOAD_CALLBACK) static NTSTATUS BkcfsFilterUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Flags);
    return STATUS_SUCCESS;
}

_Function_class_(PFLT_INSTANCE_SETUP_CALLBACK) static NTSTATUS
    BkcfsInstanceSetup(_In_ PCFLT_RELATED_OBJECTS FltObjects, _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
                       _In_ DEVICE_TYPE VolumeDeviceType, _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeDeviceType);
    UNREFERENCED_PARAMETER(VolumeFilesystemType);
    return STATUS_SUCCESS;
}

static const FLT_OPERATION_REGISTRATION g_BlackbirdFsCallbacks[] = {
    {IRP_MJ_CREATE, 0, BkcfsPreOperation, NULL},
    {IRP_MJ_READ, 0, BkcfsPreOperation, NULL},
    {IRP_MJ_WRITE, 0, BkcfsPreOperation, NULL},
    {IRP_MJ_CLOSE, 0, BkcfsPreOperation, NULL},
    {IRP_MJ_CLEANUP, 0, BkcfsPreOperation, NULL},
    {IRP_MJ_SET_INFORMATION, 0, BkcfsPreOperation, NULL},
    {IRP_MJ_QUERY_INFORMATION, 0, BkcfsPreOperation, NULL},
    {IRP_MJ_DIRECTORY_CONTROL, 0, BkcfsPreOperation, NULL},
    {IRP_MJ_FILE_SYSTEM_CONTROL, 0, BkcfsPreOperation, NULL},
    {IRP_MJ_OPERATION_END}};

static const FLT_REGISTRATION g_BlackbirdFsRegistration = {sizeof(FLT_REGISTRATION),
                                                           FLT_REGISTRATION_VERSION,
                                                           0,
                                                           NULL,
                                                           g_BlackbirdFsCallbacks,
                                                           BkcfsFilterUnload,
                                                           BkcfsInstanceSetup,
                                                           NULL,
                                                           NULL,
                                                           NULL,
                                                           NULL,
                                                           NULL,
                                                           NULL,
                                                           NULL};

NTSTATUS
BkcfsInitialize(_In_ PDRIVER_OBJECT DriverObject)
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
                       "BK: filesystem monitor filter registration failed status=0x%08X total=%lu.\n", status,
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
                       "BK: filesystem monitor start filtering failed status=0x%08X total=%lu.\n", status,
                       (ULONG)failures);
        }
        FltUnregisterFilter(g_FileSystemFilter);
        g_FileSystemFilter = NULL;
        return status;
    }

    InterlockedExchange(&g_FileSystemMonitorRegistered, 1);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "BK: filesystem monitor initialized.\n");
    return STATUS_SUCCESS;
}

VOID BkcfsUninitialize(VOID)
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

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "BK: filesystem monitor uninitialized.\n");
}

BOOLEAN
BkcfsSelfCheck(VOID)
{
    if (InterlockedCompareExchange(&g_FileSystemMonitorRegistered, 0, 0) == 0)
    {
        return FALSE;
    }

    return (g_FileSystemFilter != NULL);
}
