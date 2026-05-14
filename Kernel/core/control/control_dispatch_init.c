#include "control_private.h"
#include "..\..\callbacks\process_monitor.h"

static BOOLEAN BkctlRequestorAllowed(_In_ ULONG RequesterPid)
{
    return (BkcprocIsControllerReadyPid(RequesterPid) || BkcprocIsInterfacePid(RequesterPid));
}

_Use_decl_annotations_ VOID BkctlEvtIoDeviceControl(WDFQUEUE Queue, WDFREQUEST Request, size_t OutputBufferLength,
                                                    size_t InputBufferLength, ULONG IoControlCode)
{
    WDFOBJECT fileObj;
    PBK_FILE_CONTEXT ctx;
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    size_t bytesOut = 0;
    ULONG requesterPid;

    UNREFERENCED_PARAMETER(Queue);
    UNREFERENCED_PARAMETER(OutputBufferLength);
    UNREFERENCED_PARAMETER(InputBufferLength);
    requesterPid = BkctlGetRequestorPid();

    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "BK: ioctl rejected requesterPid=%lu ioctl=%s(0x%08X) reason=IRQL.\n", requesterPid,
                   BkctlIoctlName(IoControlCode), IoControlCode);
        WdfRequestComplete(Request, STATUS_INVALID_DEVICE_STATE);
        return;
    }

    if (!BkctlModeAllowed(Request))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "BK: ioctl denied requesterPid=%lu ioctl=%s(0x%08X) reason=non-usermode.\n", requesterPid,
                   BkctlIoctlName(IoControlCode), IoControlCode);
        WdfRequestComplete(Request, STATUS_ACCESS_DENIED);
        return;
    }

    fileObj = WdfRequestGetFileObject(Request);
    if (fileObj == NULL)
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "BK: ioctl invalid file-object requesterPid=%lu ioctl=%s(0x%08X).\n", requesterPid,
                   BkctlIoctlName(IoControlCode), IoControlCode);
        WdfRequestComplete(Request, STATUS_INVALID_HANDLE);
        return;
    }

    ctx = BkctlGetFileContext(fileObj);
    if (ctx->Client == NULL)
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "BK: ioctl invalid client context requesterPid=%lu ioctl=%s(0x%08X).\n", requesterPid,
                   BkctlIoctlName(IoControlCode), IoControlCode);
        WdfRequestComplete(Request, STATUS_INVALID_HANDLE);
        return;
    }

    if (BkctlIsShutdown() && IoControlCode != IOCTL_BK_GET_STATS && IoControlCode != IOCTL_BK_GET_HEALTH &&
        IoControlCode != IOCTL_BK_GET_DIAGNOSTICS && IoControlCode != IOCTL_BK_SET_SHUTDOWN_MODE &&
        IoControlCode != IOCTL_BK_GET_RUNTIME_CONFIG && IoControlCode != IOCTL_BK_GET_QPC_TIMING_STATE)
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                   "BK: ioctl rejected during shutdown requesterPid=%lu ioctl=%s(0x%08X).\n", requesterPid,
                   BkctlIoctlName(IoControlCode), IoControlCode);
        WdfRequestComplete(Request, STATUS_DEVICE_NOT_READY);
        return;
    }
    if (IoControlCode != IOCTL_BK_MARK_CONTROLLER_READY && !BkctlRequestorAllowed(requesterPid))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "BK: ioctl denied requesterPid=%lu ioctl=%s(0x%08X) reason=untrusted-requestor.\n", requesterPid,
                   BkctlIoctlName(IoControlCode), IoControlCode);
        WdfRequestComplete(Request, STATUS_ACCESS_DENIED);
        return;
    }

    switch (IoControlCode)
    {
    case IOCTL_BK_SUBSCRIBE:
        status = BkctlHandleSubscribeIoctl(ctx->Client, Request);
        break;
    case IOCTL_BK_UNSUBSCRIBE:
        status = BkctlHandleUnsubscribeIoctl(ctx->Client, Request);
        break;
    case IOCTL_BK_GET_EVENT:
        status = BkctlHandleGetEventIoctl(ctx->Client, Request, &bytesOut);
        break;
    case IOCTL_BK_GET_STATS:
        status = BkctlHandleGetStatsIoctl(ctx->Client, Request, &bytesOut);
        break;
    case IOCTL_BK_GET_HEALTH:
        status = BkctlHandleGetHealthIoctl(ctx->Client, Request, &bytesOut);
        break;
    case IOCTL_BK_GET_DIAGNOSTICS:
        status = BkctlHandleGetDiagnosticsIoctl(ctx->Client, Request, &bytesOut);
        break;
    case IOCTL_BK_SET_PIDS:
        status = BkctlHandleSetPidsIoctl(ctx->Client, Request);
        break;
    case IOCTL_BK_ARM_PENDING_LAUNCH:
        status = BkctlHandleArmPendingLaunchIoctl(ctx->Client, Request);
        break;
    case IOCTL_BK_QUERY_PROCESS_IMAGE:
        status = BkctlHandleQueryProcessImageIoctl(ctx->Client, Request, &bytesOut);
        break;
    case IOCTL_BK_SET_SHUTDOWN_MODE:
        status = BkctlHandleSetShutdownModeIoctl(ctx->Client, Request);
        break;
    case IOCTL_BK_CONTROL_EXECUTION:
        status = BkctlHandleControlExecutionIoctl(ctx->Client, Request);
        break;
    case IOCTL_BK_SET_RUNTIME_CONFIG:
        status = BkctlHandleSetRuntimeConfigIoctl(ctx->Client, Request);
        break;
    case IOCTL_BK_GET_RUNTIME_CONFIG:
        status = BkctlHandleGetRuntimeConfigIoctl(ctx->Client, Request, &bytesOut);
        break;
    case IOCTL_BK_SET_QPC_TIMING_CONFIG:
        status = BkctlHandleSetQpcTimingConfigIoctl(ctx->Client, Request);
        break;
    case IOCTL_BK_GET_QPC_TIMING_STATE:
        status = BkctlHandleGetQpcTimingStateIoctl(ctx->Client, Request, &bytesOut);
        break;
    case IOCTL_BK_MARK_CONTROLLER_READY:
        status = BkctlHandleMarkControllerReadyIoctl(ctx->Client, Request);
        break;
    case IOCTL_BK_REGISTER_INSTRUMENTATION_RANGE:
        status = BkctlHandleRegisterInstrumentationRangeIoctl(ctx->Client, Request);
        break;
    case IOCTL_BK_REGISTER_HOOK_PATCH:
        status = BkctlHandleRegisterHookPatchIoctl(ctx->Client, Request);
        break;
    case IOCTL_BK_REGISTER_PROCESS_INSTRUMENTATION_CALLBACK:
        status = BkctlHandleRegisterProcessInstrumentationCallbackIoctl(ctx->Client, Request);
        break;
    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        BkdiagRecord(BktmpSubsystemControl, BkDiagEventSelfCheckFailed, status, 0, BK_DIAG_FLAG_FAILURE, IoControlCode,
                     BK_DIAG_COMPONENT_CONTROL);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL, "BK: unsupported ioctl requesterPid=%lu ioctl=0x%08X.\n",
                   requesterPid, IoControlCode);
        break;
    }

    if (status == STATUS_PENDING)
    {
        return;
    }

    if (IoControlCode != IOCTL_BK_GET_EVENT || (!NT_SUCCESS(status) && status != STATUS_NO_MORE_ENTRIES))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, NT_SUCCESS(status) ? DPFLTR_INFO_LEVEL : DPFLTR_WARNING_LEVEL,
                   "BK: ioctl complete requesterPid=%lu ioctl=%s(0x%08X) status=0x%08X bytes=%Iu.\n", requesterPid,
                   BkctlIoctlName(IoControlCode), IoControlCode, status, bytesOut);
    }

    WdfRequestCompleteWithInformation(Request, status, bytesOut);
}

NTSTATUS
BkctlInitialize(_In_ WDFDRIVER Driver)
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
    BkctlInitializePidInterestIndex();

    RtlInitUnicodeString(&sddl, L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");
    devInit = WdfControlDeviceInitAllocate(Driver, &sddl);
    if (devInit == NULL)
    {
        InterlockedExchange(&g_ControlInitialized, 0);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    WdfDeviceInitSetDeviceType(devInit, FILE_DEVICE_BK);
    WdfDeviceInitSetExclusive(devInit, FALSE);

    RtlInitUnicodeString(&deviceName, L"\\Device\\BlackbirdCtl");
    status = WdfDeviceInitAssignName(devInit, &deviceName);
    if (!NT_SUCCESS(status))
    {
        WdfDeviceInitFree(devInit);
        InterlockedExchange(&g_ControlInitialized, 0);
        return status;
    }

    WDF_FILEOBJECT_CONFIG_INIT(&fileConfig, BkctlEvtFileCreate, BkctlEvtFileCleanup, WDF_NO_EVENT_CALLBACK);
    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attrs, BK_FILE_CONTEXT);
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
    queueConfig.EvtIoDeviceControl = BkctlEvtIoDeviceControl;
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
    BkctlInitializeEventNodeLookaside();
    WdfControlFinishInitializing(device);
    return STATUS_SUCCESS;
}
