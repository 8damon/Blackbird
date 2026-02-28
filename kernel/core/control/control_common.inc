static BOOLEAN SLEEPWALKERModeAllowed(_In_ WDFREQUEST Request)
{
    return (WdfRequestGetRequestorMode(Request) == UserMode);
}

static ULONG SLEEPWALKERGetRequestorPid(_In_ WDFREQUEST Request)
{
    UNREFERENCED_PARAMETER(Request);
    return (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
}

static PCSTR SLEEPWALKERIoctlName(_In_ ULONG Ioctl)
{
    switch (Ioctl)
    {
    case IOCTL_SLEEPWALKER_SUBSCRIBE:
        return "SUBSCRIBE";
    case IOCTL_SLEEPWALKER_UNSUBSCRIBE:
        return "UNSUBSCRIBE";
    case IOCTL_SLEEPWALKER_GET_EVENT:
        return "GET_EVENT";
    case IOCTL_SLEEPWALKER_GET_STATS:
        return "GET_STATS";
    case IOCTL_SLEEPWALKER_SET_PIDS:
        return "SET_PIDS";
    case IOCTL_SLEEPWALKER_QUERY_PROCESS_IMAGE:
        return "QUERY_PROCESS_IMAGE";
    case IOCTL_SLEEPWALKER_SET_SHUTDOWN_MODE:
        return "SET_SHUTDOWN_MODE";
    default:
        return "UNKNOWN_IOCTL";
    }
}

static BOOLEAN SLEEPWALKERControlIsShutdown(VOID)
{
    return (InterlockedCompareExchange(&g_ControlShutdown, 0, 0) != 0);
}

static BOOLEAN SLEEPWALKERTryAcquireGlobalQueueSlot(VOID)
{
    LONG current;

    for (;;)
    {
        current = InterlockedCompareExchange(&g_ControlTotalQueuedEvents, 0, 0);
        if (current >= SLEEPWALKER_MAX_TOTAL_QUEUED_EVENTS)
        {
            return FALSE;
        }
        if (InterlockedCompareExchange(&g_ControlTotalQueuedEvents, current + 1, current) == current)
        {
            return TRUE;
        }
    }
}

static VOID SLEEPWALKERReleaseGlobalQueueSlot(VOID)
{
    LONG remaining;

    remaining = InterlockedDecrement(&g_ControlTotalQueuedEvents);
    if (remaining < 0)
    {
        InterlockedExchange(&g_ControlTotalQueuedEvents, 0);
    }
}

static BOOLEAN SLEEPWALKERClientConsumeQueryBudgetLocked(_Inout_ PSLEEPWALKER_CLIENT Client)
{
    ULONGLONG now;

    now = KeQueryInterruptTime();
    if (Client->QueryWindowStart100ns == 0 || now < Client->QueryWindowStart100ns ||
        (now - Client->QueryWindowStart100ns) >= SLEEPWALKER_QUERY_IMAGE_WINDOW_100NS)
    {
        Client->QueryWindowStart100ns = now;
        Client->QueryWindowCount = 1;
        return TRUE;
    }

    if (Client->QueryWindowCount >= SLEEPWALKER_QUERY_IMAGE_MAX_PER_WINDOW)
    {
        return FALSE;
    }

    Client->QueryWindowCount += 1;
    return TRUE;
}

static BOOLEAN SLEEPWALKERTryAcquireQueryInflightSlot(VOID)
{
    LONG current;

    for (;;)
    {
        current = InterlockedCompareExchange(&g_QueryImageInflight, 0, 0);
        if (current >= SLEEPWALKER_QUERY_IMAGE_MAX_INFLIGHT)
        {
            return FALSE;
        }
        if (InterlockedCompareExchange(&g_QueryImageInflight, current + 1, current) == current)
        {
            return TRUE;
        }
    }
}

static VOID SLEEPWALKERReleaseQueryInflightSlot(VOID)
{
    LONG remaining;

    remaining = InterlockedDecrement(&g_QueryImageInflight);
    if (remaining < 0)
    {
        InterlockedExchange(&g_QueryImageInflight, 0);
    }
}

static VOID SLEEPWALKERClientFreeQueuedEvents(_Inout_ PSLEEPWALKER_CLIENT Client)
{
    while (!IsListEmpty(&Client->EventQueue))
    {
        PLIST_ENTRY entry = RemoveHeadList(&Client->EventQueue);
        PSLEEPWALKER_EVENT_NODE node = CONTAINING_RECORD(entry, SLEEPWALKER_EVENT_NODE, Link);
        ExFreePoolWithTag(node, SLEEPWALKER_POOL_TAG);
        SLEEPWALKERReleaseGlobalQueueSlot();
    }
    Client->QueueDepth = 0;
}

static VOID SLEEPWALKERClientRelease(_Inout_ PSLEEPWALKER_CLIENT Client)
{
    if (InterlockedDecrement(&Client->RefCount) != 0)
    {
        return;
    }

    ExAcquireFastMutex(&Client->Lock);
    SLEEPWALKERClientFreeQueuedEvents(Client);
    ExReleaseFastMutex(&Client->Lock);
    ExFreePoolWithTag(Client, SLEEPWALKER_POOL_TAG);
}

static VOID SLEEPWALKERClientReference(_Inout_ PSLEEPWALKER_CLIENT Client)
{
    (void)InterlockedIncrement(&Client->RefCount);
}

static VOID SLEEPWALKERControlFlushAllClientState(VOID)
{
    PSLEEPWALKER_CLIENT snapshot[SLEEPWALKER_MAX_TOTAL_CLIENTS];
    UINT32 snapshotCount = 0;
    UINT32 i;
    PLIST_ENTRY e;

    ExAcquireFastMutex(&g_ClientListLock);
    for (e = g_ClientList.Flink; e != &g_ClientList; e = e->Flink)
    {
        PSLEEPWALKER_CLIENT c = CONTAINING_RECORD(e, SLEEPWALKER_CLIENT, Link);
        if (snapshotCount >= RTL_NUMBER_OF(snapshot))
        {
            break;
        }
        SLEEPWALKERClientReference(c);
        snapshot[snapshotCount++] = c;
    }
    ExReleaseFastMutex(&g_ClientListLock);

    for (i = 0; i < snapshotCount; ++i)
    {
        PSLEEPWALKER_CLIENT c = snapshot[i];
        ExAcquireFastMutex(&c->Lock);
        c->SubscriptionCount = 0;
        SLEEPWALKERClientFreeQueuedEvents(c);
        ExReleaseFastMutex(&c->Lock);
        SLEEPWALKERClientRelease(c);
    }
}

VOID SLEEPWALKERControlBeginShutdown(VOID)
{
    if (InterlockedExchange(&g_ControlShutdown, 1) == 0)
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "SLEEPWALKER: control plane entering shutdown mode.\n");
    }
    SLEEPWALKERControlFlushAllClientState();
}

static PSLEEPWALKER_CLIENT SLEEPWALKERClientCreate(VOID)
{
    PSLEEPWALKER_CLIENT client;

    client = (PSLEEPWALKER_CLIENT)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*client), SLEEPWALKER_POOL_TAG);
    if (client == NULL)
    {
        return NULL;
    }

    RtlZeroMemory(client, sizeof(*client));
    InitializeListHead(&client->EventQueue);
    ExInitializeFastMutex(&client->Lock);
    client->RefCount = 1;
    return client;
}

static BOOLEAN SLEEPWALKERClientMatchSubscriptionEither(_In_ PSLEEPWALKER_CLIENT Client, _In_ UINT32 PrimaryProcessId,
                                                        _In_ UINT32 SecondaryProcessId, _In_ UINT32 StreamMask)
{
    UINT32 i;

    for (i = 0; i < Client->SubscriptionCount; ++i)
    {
        UINT32 subscribedPid;
        UINT32 subscribedMask;

        subscribedPid = Client->Subscriptions[i].ProcessId;
        subscribedMask = Client->Subscriptions[i].StreamMask;
        if ((subscribedMask & StreamMask) == 0)
        {
            continue;
        }

        if (subscribedPid == PrimaryProcessId || (SecondaryProcessId != 0 && subscribedPid == SecondaryProcessId))
        {
            return TRUE;
        }
    }

    return FALSE;
}

static VOID SLEEPWALKERClientEnqueueEvent(_Inout_ PSLEEPWALKER_CLIENT Client,
                                          _In_ const SLEEPWALKER_EVENT_RECORD *Source)
{
    PSLEEPWALKER_EVENT_NODE node;
    LONG dropLogCounter;

    if (Client->QueueDepth >= SLEEPWALKER_MAX_CLIENT_QUEUE_DEPTH)
    {
        Client->DroppedEvents += 1;
        dropLogCounter = InterlockedIncrement(&g_ControlQueueDropLogCounter);
        if (dropLogCounter == 1 || ((dropLogCounter & 0xFF) == 0))
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "SLEEPWALKER: queue drop (client depth cap=%lu) totalDrops=%lu clientDrops=%u queueDepth=%u.\n",
                       SLEEPWALKER_MAX_CLIENT_QUEUE_DEPTH, (ULONG)dropLogCounter, Client->DroppedEvents,
                       Client->QueueDepth);
        }
        return;
    }

    if (!SLEEPWALKERTryAcquireGlobalQueueSlot())
    {
        Client->DroppedEvents += 1;
        dropLogCounter = InterlockedIncrement(&g_ControlQueueDropLogCounter);
        if (dropLogCounter == 1 || ((dropLogCounter & 0xFF) == 0))
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "SLEEPWALKER: queue drop (global cap=%lu) totalDrops=%lu clientDrops=%u globalQueued=%ld.\n",
                       SLEEPWALKER_MAX_TOTAL_QUEUED_EVENTS, (ULONG)dropLogCounter, Client->DroppedEvents,
                       InterlockedCompareExchange(&g_ControlTotalQueuedEvents, 0, 0));
        }
        return;
    }

    node = (PSLEEPWALKER_EVENT_NODE)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*node), SLEEPWALKER_POOL_TAG);
    if (node == NULL)
    {
        SLEEPWALKERReleaseGlobalQueueSlot();
        Client->DroppedEvents += 1;
        dropLogCounter = InterlockedIncrement(&g_ControlQueueDropLogCounter);
        if (dropLogCounter == 1 || ((dropLogCounter & 0xFF) == 0))
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "SLEEPWALKER: queue drop (alloc failure) totalDrops=%lu clientDrops=%u queueDepth=%u.\n",
                       (ULONG)dropLogCounter, Client->DroppedEvents, Client->QueueDepth);
        }
        return;
    }

    RtlZeroMemory(node, sizeof(*node));
    RtlCopyMemory(&node->Record, Source, sizeof(node->Record));
    InsertTailList(&Client->EventQueue, &node->Link);
    Client->QueueDepth += 1;
}

static VOID SLEEPWALKERPublishRecordToSubscribers(_In_ UINT32 PrimaryPid, _In_ UINT32 SecondaryPid,
                                                  _In_ UINT32 StreamMask, _In_ SLEEPWALKER_EVENT_RECORD *Record)
{
    PSLEEPWALKER_CLIENT snapshot[SLEEPWALKER_MAX_TOTAL_CLIENTS];
    UINT32 snapshotCount = 0;
    UINT32 i;
    PLIST_ENTRY e;

    if (InterlockedCompareExchange(&g_ControlInitialized, 0, 0) == 0)
    {
        return;
    }
    if (SLEEPWALKERControlIsShutdown())
    {
        return;
    }

    ExAcquireFastMutex(&g_ClientListLock);
    for (e = g_ClientList.Flink; e != &g_ClientList; e = e->Flink)
    {
        PSLEEPWALKER_CLIENT c = CONTAINING_RECORD(e, SLEEPWALKER_CLIENT, Link);
        if (snapshotCount >= RTL_NUMBER_OF(snapshot))
        {
            break;
        }
        SLEEPWALKERClientReference(c);
        snapshot[snapshotCount++] = c;
    }
    ExReleaseFastMutex(&g_ClientListLock);

    for (i = 0; i < snapshotCount; ++i)
    {
        PSLEEPWALKER_CLIENT c = snapshot[i];
        ExAcquireFastMutex(&c->Lock);
        if (SLEEPWALKERClientMatchSubscriptionEither(c, PrimaryPid, SecondaryPid, StreamMask))
        {
            Record->Header.Sequence = ++c->Sequence;
            SLEEPWALKERClientEnqueueEvent(c, Record);
        }
        ExReleaseFastMutex(&c->Lock);
        SLEEPWALKERClientRelease(c);
    }
}

EVT_WDF_DEVICE_FILE_CREATE SLEEPWALKEREvtFileCreate;
EVT_WDF_FILE_CLEANUP SLEEPWALKEREvtFileCleanup;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL SLEEPWALKEREvtIoDeviceControl;

_Use_decl_annotations_ VOID SLEEPWALKEREvtFileCreate(WDFDEVICE Device, WDFREQUEST Request, WDFFILEOBJECT FileObject)
{
    PSLEEPWALKER_FILE_CONTEXT ctx;
    PSLEEPWALKER_CLIENT client;
    ULONG requesterPid;
    LONG clientCountSnapshot;

    UNREFERENCED_PARAMETER(Device);

    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        WdfRequestComplete(Request, STATUS_INVALID_DEVICE_STATE);
        return;
    }
    if (SLEEPWALKERControlIsShutdown())
    {
        WdfRequestComplete(Request, STATUS_DELETE_PENDING);
        return;
    }

    client = SLEEPWALKERClientCreate();
    if (client == NULL)
    {
        WdfRequestComplete(Request, STATUS_INSUFFICIENT_RESOURCES);
        return;
    }

    ExAcquireFastMutex(&g_ClientListLock);
    if (g_ClientCount >= SLEEPWALKER_MAX_TOTAL_CLIENTS)
    {
        ExReleaseFastMutex(&g_ClientListLock);
        SLEEPWALKERClientRelease(client);
        WdfRequestComplete(Request, STATUS_QUOTA_EXCEEDED);
        return;
    }
    InsertTailList(&g_ClientList, &client->Link);
    g_ClientCount += 1;
    clientCountSnapshot = g_ClientCount;
    ExReleaseFastMutex(&g_ClientListLock);

    ctx = SLEEPWALKERGetFileContext(FileObject);
    ctx->Client = client;

    requesterPid = SLEEPWALKERGetRequestorPid(Request);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID,
               DPFLTR_INFO_LEVEL,
               "SLEEPWALKER: client attached pid=%lu activeClients=%ld fileObj=0x%p.\n",
               requesterPid,
               clientCountSnapshot,
               FileObject);

    WdfRequestComplete(Request, STATUS_SUCCESS);
}

_Use_decl_annotations_ VOID SLEEPWALKEREvtFileCleanup(WDFFILEOBJECT FileObject)
{
    PSLEEPWALKER_FILE_CONTEXT ctx = SLEEPWALKERGetFileContext(FileObject);
    PSLEEPWALKER_CLIENT client = ctx->Client;
    PLIST_ENTRY e;
    LONG clientCountSnapshot = 0;
    UINT32 subscriptionCountSnapshot = 0;
    UINT32 queueDepthSnapshot = 0;
    UINT32 droppedSnapshot = 0;
    ULONG requesterPid;

    if (client == NULL)
    {
        return;
    }
    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        return;
    }

    ExAcquireFastMutex(&g_ClientListLock);
    for (e = g_ClientList.Flink; e != &g_ClientList; e = e->Flink)
    {
        if (CONTAINING_RECORD(e, SLEEPWALKER_CLIENT, Link) == client)
        {
            RemoveEntryList(e);
            if (g_ClientCount > 0)
            {
                g_ClientCount -= 1;
            }
            clientCountSnapshot = g_ClientCount;
            break;
        }
    }
    ExReleaseFastMutex(&g_ClientListLock);

    ExAcquireFastMutex(&client->Lock);
    subscriptionCountSnapshot = client->SubscriptionCount;
    queueDepthSnapshot = client->QueueDepth;
    droppedSnapshot = client->DroppedEvents;
    ExReleaseFastMutex(&client->Lock);

    requesterPid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
    DbgPrintEx(DPFLTR_IHVDRIVER_ID,
               DPFLTR_INFO_LEVEL,
               "SLEEPWALKER: client detached pid=%lu activeClients=%ld subscriptions=%lu queueDepth=%lu dropped=%lu fileObj=0x%p.\n",
               requesterPid,
               clientCountSnapshot,
               subscriptionCountSnapshot,
               queueDepthSnapshot,
               droppedSnapshot,
               FileObject);

    SLEEPWALKERClientRelease(client);
    ctx->Client = NULL;
}

