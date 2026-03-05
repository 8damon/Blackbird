_Use_decl_annotations_ VOID SLEEPWALKEREvtIoDeviceControl(WDFQUEUE Queue, WDFREQUEST Request, size_t OutputBufferLength,
                                                          size_t InputBufferLength, ULONG IoControlCode)
{
    WDFOBJECT fileObj;
    PSLEEPWALKER_FILE_CONTEXT ctx;
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    size_t bytesOut = 0;
    ULONG requesterPid;

    UNREFERENCED_PARAMETER(Queue);
    UNREFERENCED_PARAMETER(OutputBufferLength);
    UNREFERENCED_PARAMETER(InputBufferLength);
    requesterPid = SLEEPWALKERGetRequestorPid(Request);

    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID,
                   DPFLTR_ERROR_LEVEL,
                   "SLEEPWALKER: ioctl rejected requesterPid=%lu ioctl=%s(0x%08X) reason=IRQL.\n",
                   requesterPid,
                   SLEEPWALKERIoctlName(IoControlCode),
                   IoControlCode);
        WdfRequestComplete(Request, STATUS_INVALID_DEVICE_STATE);
        return;
    }

    if (!SLEEPWALKERModeAllowed(Request))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID,
                   DPFLTR_WARNING_LEVEL,
                   "SLEEPWALKER: ioctl denied requesterPid=%lu ioctl=%s(0x%08X) reason=non-usermode.\n",
                   requesterPid,
                   SLEEPWALKERIoctlName(IoControlCode),
                   IoControlCode);
        WdfRequestComplete(Request, STATUS_ACCESS_DENIED);
        return;
    }

    fileObj = WdfRequestGetFileObject(Request);
    if (fileObj == NULL)
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID,
                   DPFLTR_WARNING_LEVEL,
                   "SLEEPWALKER: ioctl invalid file-object requesterPid=%lu ioctl=%s(0x%08X).\n",
                   requesterPid,
                   SLEEPWALKERIoctlName(IoControlCode),
                   IoControlCode);
        WdfRequestComplete(Request, STATUS_INVALID_HANDLE);
        return;
    }

    ctx = SLEEPWALKERGetFileContext(fileObj);
    if (ctx->Client == NULL)
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID,
                   DPFLTR_WARNING_LEVEL,
                   "SLEEPWALKER: ioctl invalid client context requesterPid=%lu ioctl=%s(0x%08X).\n",
                   requesterPid,
                   SLEEPWALKERIoctlName(IoControlCode),
                   IoControlCode);
        WdfRequestComplete(Request, STATUS_INVALID_HANDLE);
        return;
    }

    if (SLEEPWALKERControlIsShutdown() && IoControlCode != IOCTL_SLEEPWALKER_GET_STATS &&
        IoControlCode != IOCTL_SLEEPWALKER_SET_SHUTDOWN_MODE)
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID,
                   DPFLTR_INFO_LEVEL,
                   "SLEEPWALKER: ioctl rejected during shutdown requesterPid=%lu ioctl=%s(0x%08X).\n",
                   requesterPid,
                   SLEEPWALKERIoctlName(IoControlCode),
                   IoControlCode);
        WdfRequestComplete(Request, STATUS_DEVICE_NOT_READY);
        return;
    }

    switch (IoControlCode)
    {
    case IOCTL_SLEEPWALKER_SUBSCRIBE:
        status = SLEEPWALKERHandleSubscribeIoctl(ctx->Client, Request);
        break;
    case IOCTL_SLEEPWALKER_UNSUBSCRIBE:
        status = SLEEPWALKERHandleUnsubscribeIoctl(ctx->Client, Request);
        break;
    case IOCTL_SLEEPWALKER_GET_EVENT:
        status = SLEEPWALKERHandleGetEventIoctl(ctx->Client, Request, &bytesOut);
        break;
    case IOCTL_SLEEPWALKER_GET_STATS:
        status = SLEEPWALKERHandleGetStatsIoctl(ctx->Client, Request, &bytesOut);
        break;
    case IOCTL_SLEEPWALKER_SET_PIDS:
        status = SLEEPWALKERHandleSetPidsIoctl(ctx->Client, Request);
        break;
    case IOCTL_SLEEPWALKER_QUERY_PROCESS_IMAGE:
        status = SLEEPWALKERHandleQueryProcessImageIoctl(ctx->Client, Request, &bytesOut);
        break;
    case IOCTL_SLEEPWALKER_SET_SHUTDOWN_MODE:
        status = SLEEPWALKERHandleSetShutdownModeIoctl(ctx->Client, Request);
        break;
    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        DbgPrintEx(DPFLTR_IHVDRIVER_ID,
                   DPFLTR_WARNING_LEVEL,
                   "SLEEPWALKER: unsupported ioctl requesterPid=%lu ioctl=0x%08X.\n",
                   requesterPid,
                   IoControlCode);
        break;
    }

    if (IoControlCode != IOCTL_SLEEPWALKER_GET_EVENT || (!NT_SUCCESS(status) && status != STATUS_NO_MORE_ENTRIES))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID,
                   NT_SUCCESS(status) ? DPFLTR_INFO_LEVEL : DPFLTR_WARNING_LEVEL,
                   "SLEEPWALKER: ioctl complete requesterPid=%lu ioctl=%s(0x%08X) status=0x%08X bytes=%Iu.\n",
                   requesterPid,
                   SLEEPWALKERIoctlName(IoControlCode),
                   IoControlCode,
                   status,
                   bytesOut);
    }

    WdfRequestCompleteWithInformation(Request, status, bytesOut);
}

NTSTATUS
SLEEPWALKERControlInitialize(_In_ WDFDRIVER Driver)
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

    WdfDeviceInitSetDeviceType(devInit, FILE_DEVICE_SLEEPWALKER);
    WdfDeviceInitSetExclusive(devInit, FALSE);

    RtlInitUnicodeString(&deviceName, L"\\Device\\SleepwalkerCtl");
    status = WdfDeviceInitAssignName(devInit, &deviceName);
    if (!NT_SUCCESS(status))
    {
        WdfDeviceInitFree(devInit);
        InterlockedExchange(&g_ControlInitialized, 0);
        return status;
    }

    WDF_FILEOBJECT_CONFIG_INIT(&fileConfig, SLEEPWALKEREvtFileCreate, SLEEPWALKEREvtFileCleanup, WDF_NO_EVENT_CALLBACK);
    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attrs, SLEEPWALKER_FILE_CONTEXT);
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
    queueConfig.EvtIoDeviceControl = SLEEPWALKEREvtIoDeviceControl;
    status = WdfIoQueueCreate(device, &queueConfig, WDF_NO_OBJECT_ATTRIBUTES, WDF_NO_HANDLE);
    if (!NT_SUCCESS(status))
    {
        WdfObjectDelete(device);
        InterlockedExchange(&g_ControlInitialized, 0);
        return status;
    }

    RtlInitUnicodeString(&globalSymlink, L"\\DosDevices\\Global\\SleepwalkerCtl");
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
