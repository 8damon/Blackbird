#include "control_private.h"
#include "..\..\monitors\process_monitor.h"

static BOOLEAN BLACKBIRDControlRequestorAllowed(_In_ ULONG RequesterPid)
{
    return (BLACKBIRDProcessMonitorIsControllerPid(RequesterPid) ||
            BLACKBIRDProcessMonitorIsInterfacePid(RequesterPid));
}

_Use_decl_annotations_ VOID BLACKBIRDEvtIoDeviceControl(WDFQUEUE Queue, WDFREQUEST Request, size_t OutputBufferLength,
                                                        size_t InputBufferLength, ULONG IoControlCode)
{
    WDFOBJECT fileObj;
    PBLACKBIRD_FILE_CONTEXT ctx;
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    size_t bytesOut = 0;
    ULONG requesterPid;

    UNREFERENCED_PARAMETER(Queue);
    UNREFERENCED_PARAMETER(OutputBufferLength);
    UNREFERENCED_PARAMETER(InputBufferLength);
    requesterPid = BLACKBIRDGetRequestorPid();

    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "BLACKBIRD: ioctl rejected requesterPid=%lu ioctl=%s(0x%08X) reason=IRQL.\n", requesterPid,
                   BLACKBIRDIoctlName(IoControlCode), IoControlCode);
        WdfRequestComplete(Request, STATUS_INVALID_DEVICE_STATE);
        return;
    }

    if (!BLACKBIRDModeAllowed(Request))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "BLACKBIRD: ioctl denied requesterPid=%lu ioctl=%s(0x%08X) reason=non-usermode.\n", requesterPid,
                   BLACKBIRDIoctlName(IoControlCode), IoControlCode);
        WdfRequestComplete(Request, STATUS_ACCESS_DENIED);
        return;
    }

    fileObj = WdfRequestGetFileObject(Request);
    if (fileObj == NULL)
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "BLACKBIRD: ioctl invalid file-object requesterPid=%lu ioctl=%s(0x%08X).\n", requesterPid,
                   BLACKBIRDIoctlName(IoControlCode), IoControlCode);
        WdfRequestComplete(Request, STATUS_INVALID_HANDLE);
        return;
    }

    ctx = BLACKBIRDGetFileContext(fileObj);
    if (ctx->Client == NULL)
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "BLACKBIRD: ioctl invalid client context requesterPid=%lu ioctl=%s(0x%08X).\n", requesterPid,
                   BLACKBIRDIoctlName(IoControlCode), IoControlCode);
        WdfRequestComplete(Request, STATUS_INVALID_HANDLE);
        return;
    }

    if (BLACKBIRDControlIsShutdown() && IoControlCode != IOCTL_BLACKBIRD_GET_STATS &&
        IoControlCode != IOCTL_BLACKBIRD_GET_HEALTH && IoControlCode != IOCTL_BLACKBIRD_SET_SHUTDOWN_MODE &&
        IoControlCode != IOCTL_BLACKBIRD_GET_RUNTIME_CONFIG)
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                   "BLACKBIRD: ioctl rejected during shutdown requesterPid=%lu ioctl=%s(0x%08X).\n", requesterPid,
                   BLACKBIRDIoctlName(IoControlCode), IoControlCode);
        WdfRequestComplete(Request, STATUS_DEVICE_NOT_READY);
        return;
    }
    if (!BLACKBIRDControlRequestorAllowed(requesterPid))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "BLACKBIRD: ioctl denied requesterPid=%lu ioctl=%s(0x%08X) reason=untrusted-requestor.\n",
                   requesterPid, BLACKBIRDIoctlName(IoControlCode), IoControlCode);
        WdfRequestComplete(Request, STATUS_ACCESS_DENIED);
        return;
    }

    switch (IoControlCode)
    {
    case IOCTL_BLACKBIRD_SUBSCRIBE:
        status = BLACKBIRDHandleSubscribeIoctl(ctx->Client, Request);
        break;
    case IOCTL_BLACKBIRD_UNSUBSCRIBE:
        status = BLACKBIRDHandleUnsubscribeIoctl(ctx->Client, Request);
        break;
    case IOCTL_BLACKBIRD_GET_EVENT:
        status = BLACKBIRDHandleGetEventIoctl(ctx->Client, Request, &bytesOut);
        break;
    case IOCTL_BLACKBIRD_GET_STATS:
        status = BLACKBIRDHandleGetStatsIoctl(ctx->Client, Request, &bytesOut);
        break;
    case IOCTL_BLACKBIRD_GET_HEALTH:
        status = BLACKBIRDHandleGetHealthIoctl(ctx->Client, Request, &bytesOut);
        break;
    case IOCTL_BLACKBIRD_SET_PIDS:
        status = BLACKBIRDHandleSetPidsIoctl(ctx->Client, Request);
        break;
    case IOCTL_BLACKBIRD_ARM_PENDING_LAUNCH:
        status = BLACKBIRDHandleArmPendingLaunchIoctl(ctx->Client, Request);
        break;
    case IOCTL_BLACKBIRD_QUERY_PROCESS_IMAGE:
        status = BLACKBIRDHandleQueryProcessImageIoctl(ctx->Client, Request, &bytesOut);
        break;
    case IOCTL_BLACKBIRD_SET_SHUTDOWN_MODE:
        status = BLACKBIRDHandleSetShutdownModeIoctl(ctx->Client, Request);
        break;
    case IOCTL_BLACKBIRD_CONTROL_EXECUTION:
        status = BLACKBIRDHandleControlExecutionIoctl(ctx->Client, Request);
        break;
    case IOCTL_BLACKBIRD_SET_RUNTIME_CONFIG:
        status = BLACKBIRDHandleSetRuntimeConfigIoctl(ctx->Client, Request);
        break;
    case IOCTL_BLACKBIRD_GET_RUNTIME_CONFIG:
        status = BLACKBIRDHandleGetRuntimeConfigIoctl(ctx->Client, Request, &bytesOut);
        break;
    case IOCTL_BLACKBIRD_MARK_INTERFACE_READY:
        status = BLACKBIRDHandleMarkInterfaceReadyIoctl(ctx->Client, Request);
        break;
    case IOCTL_BLACKBIRD_MARK_CONTROLLER_READY:
        status = BLACKBIRDHandleMarkControllerReadyIoctl(ctx->Client, Request);
        break;
    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "BLACKBIRD: unsupported ioctl requesterPid=%lu ioctl=0x%08X.\n", requesterPid, IoControlCode);
        break;
    }

    if (status == STATUS_PENDING)
    {
        return;
    }

    if (IoControlCode != IOCTL_BLACKBIRD_GET_EVENT || (!NT_SUCCESS(status) && status != STATUS_NO_MORE_ENTRIES))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, NT_SUCCESS(status) ? DPFLTR_INFO_LEVEL : DPFLTR_WARNING_LEVEL,
                   "BLACKBIRD: ioctl complete requesterPid=%lu ioctl=%s(0x%08X) status=0x%08X bytes=%Iu.\n",
                   requesterPid, BLACKBIRDIoctlName(IoControlCode), IoControlCode, status, bytesOut);
    }

    WdfRequestCompleteWithInformation(Request, status, bytesOut);
}

NTSTATUS
BLACKBIRDControlInitialize(_In_ WDFDRIVER Driver)
{
    NTSTATUS status;
    WDFDEVICE device;
    WDF_IO_QUEUE_CONFIG queueConfig;
    WDF_OBJECT_ATTRIBUTES attrs;
    WDF_FILEOBJECT_CONFIG fileConfig;
    PWDFDEVICE_INIT devInit;
    UNICODE_STRING deviceName;
    UNICODE_STRING globalSymlink;
    UNICODE_STRING sddl;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        return STATUS_INVALID_DEVICE_STATE;
    }

    if (InterlockedCompareExchange(&g_ControlInitialized, 1, 0) != 0)
    {
        return STATUS_SUCCESS;
    }

    ExInitializeFastMutex(&g_ClientListLock);
    InitializeListHead(&g_ClientList);
    g_ClientCount = 0;
    InterlockedExchange(&g_ControlShutdown, 0);
    InterlockedExchange(&g_ControlTelemetryArmed, 0);
    InterlockedExchange(&g_ControlQueueDropLogCounter, 0);
    InterlockedExchange(&g_ControlTotalQueuedEvents, 0);
    InterlockedExchange(&g_QueryImageInflight, 0);
    InterlockedExchange(&g_QueryImageThrottleCounter, 0);
    InterlockedExchange(&g_IoctlGetEventDeliverCounter, 0);
    InterlockedExchange(&g_IoctlGetEventEmptyCounter, 0);
    InterlockedExchange(&g_IoctlGetStatsCounter, 0);

    RtlInitUnicodeString(&sddl, L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");
    devInit = WdfControlDeviceInitAllocate(Driver, &sddl);
    if (devInit == NULL)
    {
        InterlockedExchange(&g_ControlInitialized, 0);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    WdfDeviceInitSetDeviceType(devInit, FILE_DEVICE_BLACKBIRD);
    WdfDeviceInitSetExclusive(devInit, FALSE);

    RtlInitUnicodeString(&deviceName, L"\\Device\\BlackbirdCtl");
    status = WdfDeviceInitAssignName(devInit, &deviceName);
    if (!NT_SUCCESS(status))
    {
        WdfDeviceInitFree(devInit);
        InterlockedExchange(&g_ControlInitialized, 0);
        return status;
    }

    WDF_FILEOBJECT_CONFIG_INIT(&fileConfig, BLACKBIRDEvtFileCreate, BLACKBIRDEvtFileCleanup, WDF_NO_EVENT_CALLBACK);
    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attrs, BLACKBIRD_FILE_CONTEXT);
    attrs.ExecutionLevel = WdfExecutionLevelPassive;
    WdfDeviceInitSetFileObjectConfig(devInit, &fileConfig, &attrs);

    WDF_OBJECT_ATTRIBUTES_INIT(&attrs);
    attrs.ExecutionLevel = WdfExecutionLevelPassive;
    status = WdfDeviceCreate(&devInit, &attrs, &device);
    if (!NT_SUCCESS(status))
    {
        InterlockedExchange(&g_ControlInitialized, 0);
        return status;
    }

    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queueConfig, WdfIoQueueDispatchParallel);
    queueConfig.EvtIoDeviceControl = BLACKBIRDEvtIoDeviceControl;
    status = WdfIoQueueCreate(device, &queueConfig, WDF_NO_OBJECT_ATTRIBUTES, WDF_NO_HANDLE);
    if (!NT_SUCCESS(status))
    {
        WdfObjectDelete(device);
        InterlockedExchange(&g_ControlInitialized, 0);
        return status;
    }

    RtlInitUnicodeString(&globalSymlink, L"\\DosDevices\\Global\\BlackbirdCtl");
    status = WdfDeviceCreateSymbolicLink(device, &globalSymlink);
    if (!NT_SUCCESS(status))
    {
        WdfObjectDelete(device);
        InterlockedExchange(&g_ControlInitialized, 0);
        return status;
    }

    g_ControlDevice = device;
    WdfControlFinishInitializing(device);
    return STATUS_SUCCESS;
}
