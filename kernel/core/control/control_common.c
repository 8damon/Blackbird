#include "control_private.h"

BOOLEAN BLACKBIRDModeAllowed(_In_ WDFREQUEST Request)
{
    return (WdfRequestGetRequestorMode(Request) == UserMode);
}

ULONG BLACKBIRDGetRequestorPid(_In_ WDFREQUEST Request)
{
    UNREFERENCED_PARAMETER(Request);
    return (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
}

PCSTR BLACKBIRDIoctlName(_In_ ULONG Ioctl)
{
    switch (Ioctl)
    {
    case IOCTL_BLACKBIRD_SUBSCRIBE:
        return "SUBSCRIBE";
    case IOCTL_BLACKBIRD_UNSUBSCRIBE:
        return "UNSUBSCRIBE";
    case IOCTL_BLACKBIRD_GET_EVENT:
        return "GET_EVENT";
    case IOCTL_BLACKBIRD_GET_STATS:
        return "GET_STATS";
    case IOCTL_BLACKBIRD_SET_PIDS:
        return "SET_PIDS";
    case IOCTL_BLACKBIRD_QUERY_PROCESS_IMAGE:
        return "QUERY_PROCESS_IMAGE";
    case IOCTL_BLACKBIRD_SET_SHUTDOWN_MODE:
        return "SET_SHUTDOWN_MODE";
    case IOCTL_BLACKBIRD_GET_HEALTH:
        return "GET_HEALTH";
    default:
        return "UNKNOWN_IOCTL";
    }
}

BOOLEAN BLACKBIRDControlIsShutdown(VOID)
{
    return (InterlockedCompareExchange(&g_ControlShutdown, 0, 0) != 0);
}

static BOOLEAN BLACKBIRDTryAcquireGlobalQueueSlot(VOID)
{
    LONG current;

    for (;;)
    {
        current = InterlockedCompareExchange(&g_ControlTotalQueuedEvents, 0, 0);
        if (current >= BLACKBIRD_MAX_TOTAL_QUEUED_EVENTS)
        {
            return FALSE;
        }
        if (InterlockedCompareExchange(&g_ControlTotalQueuedEvents, current + 1, current) == current)
        {
            return TRUE;
        }
    }
}

VOID BLACKBIRDReleaseGlobalQueueSlot(VOID)
{
    LONG remaining;

    remaining = InterlockedDecrement(&g_ControlTotalQueuedEvents);
    if (remaining < 0)
    {
        InterlockedExchange(&g_ControlTotalQueuedEvents, 0);
    }
}

BOOLEAN BLACKBIRDClientConsumeQueryBudgetLocked(_Inout_ PBLACKBIRD_CLIENT Client)
{
    ULONGLONG now;

    now = KeQueryInterruptTime();
    if (Client->QueryWindowStart100ns == 0 || now < Client->QueryWindowStart100ns ||
        (now - Client->QueryWindowStart100ns) >= BLACKBIRD_QUERY_IMAGE_WINDOW_100NS)
    {
        Client->QueryWindowStart100ns = now;
        Client->QueryWindowCount = 1;
        return TRUE;
    }

    if (Client->QueryWindowCount >= BLACKBIRD_QUERY_IMAGE_MAX_PER_WINDOW)
    {
        return FALSE;
    }

    Client->QueryWindowCount += 1;
    return TRUE;
}

BOOLEAN BLACKBIRDTryAcquireQueryInflightSlot(VOID)
{
    LONG current;

    for (;;)
    {
        current = InterlockedCompareExchange(&g_QueryImageInflight, 0, 0);
        if (current >= BLACKBIRD_QUERY_IMAGE_MAX_INFLIGHT)
        {
            return FALSE;
        }
        if (InterlockedCompareExchange(&g_QueryImageInflight, current + 1, current) == current)
        {
            return TRUE;
        }
    }
}

VOID BLACKBIRDReleaseQueryInflightSlot(VOID)
{
    LONG remaining;

    remaining = InterlockedDecrement(&g_QueryImageInflight);
    if (remaining < 0)
    {
        InterlockedExchange(&g_QueryImageInflight, 0);
    }
}

VOID BLACKBIRDClientFreeQueuedEvents(_Inout_ PBLACKBIRD_CLIENT Client)
{
    while (!IsListEmpty(&Client->EventQueue))
    {
        PLIST_ENTRY entry = RemoveHeadList(&Client->EventQueue);
        PBLACKBIRD_EVENT_NODE node = CONTAINING_RECORD(entry, BLACKBIRD_EVENT_NODE, Link);
        ExFreePoolWithTag(node, BLACKBIRD_POOL_TAG);
        BLACKBIRDReleaseGlobalQueueSlot();
    }
    Client->QueueDepth = 0;
}

VOID BLACKBIRDClientRelease(_Inout_ PBLACKBIRD_CLIENT Client)
{
    if (InterlockedDecrement(&Client->RefCount) != 0)
    {
        return;
    }

    ExAcquireFastMutex(&Client->Lock);
    BLACKBIRDClientFreeQueuedEvents(Client);
    ExReleaseFastMutex(&Client->Lock);
    ExFreePoolWithTag(Client, BLACKBIRD_POOL_TAG);
}

VOID BLACKBIRDClientReference(_Inout_ PBLACKBIRD_CLIENT Client)
{
    (void)InterlockedIncrement(&Client->RefCount);
}

static VOID BLACKBIRDControlFlushAllClientState(VOID)
{
    PBLACKBIRD_CLIENT snapshot[BLACKBIRD_MAX_TOTAL_CLIENTS];
    UINT32 snapshotCount = 0;
    UINT32 i;
    PLIST_ENTRY e;

    ExAcquireFastMutex(&g_ClientListLock);
    for (e = g_ClientList.Flink; e != &g_ClientList; e = e->Flink)
    {
        PBLACKBIRD_CLIENT c = CONTAINING_RECORD(e, BLACKBIRD_CLIENT, Link);
        if (snapshotCount >= RTL_NUMBER_OF(snapshot))
        {
            break;
        }
        BLACKBIRDClientReference(c);
        snapshot[snapshotCount++] = c;
    }
    ExReleaseFastMutex(&g_ClientListLock);

    for (i = 0; i < snapshotCount; ++i)
    {
        PBLACKBIRD_CLIENT c = snapshot[i];
        ExAcquireFastMutex(&c->Lock);
        c->SubscriptionCount = 0;
        BLACKBIRDClientFreeQueuedEvents(c);
        ExReleaseFastMutex(&c->Lock);
        BLACKBIRDClientRelease(c);
    }
}

VOID BLACKBIRDControlBeginShutdown(VOID)
{
    if (InterlockedExchange(&g_ControlShutdown, 1) == 0)
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "BLACKBIRD: control plane entering shutdown mode.\n");
    }
    BLACKBIRDControlFlushAllClientState();
}

static PBLACKBIRD_CLIENT BLACKBIRDClientCreate(VOID)
{
    PBLACKBIRD_CLIENT client;

    client = (PBLACKBIRD_CLIENT)BLACKBIRDAllocatePoolCompat(POOL_FLAG_NON_PAGED, sizeof(*client), BLACKBIRD_POOL_TAG);
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

BOOLEAN BLACKBIRDClientMatchSubscriptionEither(_In_ PBLACKBIRD_CLIENT Client, _In_ UINT32 PrimaryProcessId,
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

static VOID BLACKBIRDClientEnqueueEvent(_Inout_ PBLACKBIRD_CLIENT Client,
                                          _In_ const BLACKBIRD_EVENT_RECORD *Source)
{
    PBLACKBIRD_EVENT_NODE node;
    LONG dropLogCounter;

    if (Client->QueueDepth >= BLACKBIRD_MAX_CLIENT_QUEUE_DEPTH)
    {
        Client->DroppedEvents += 1;
        dropLogCounter = InterlockedIncrement(&g_ControlQueueDropLogCounter);
        if (dropLogCounter == 1 || ((dropLogCounter & 0xFF) == 0))
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "BLACKBIRD: queue drop (client depth cap=%lu) totalDrops=%lu clientDrops=%u queueDepth=%u.\n",
                       BLACKBIRD_MAX_CLIENT_QUEUE_DEPTH, (ULONG)dropLogCounter, Client->DroppedEvents,
                       Client->QueueDepth);
        }
        return;
    }

    if (!BLACKBIRDTryAcquireGlobalQueueSlot())
    {
        Client->DroppedEvents += 1;
        dropLogCounter = InterlockedIncrement(&g_ControlQueueDropLogCounter);
        if (dropLogCounter == 1 || ((dropLogCounter & 0xFF) == 0))
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "BLACKBIRD: queue drop (global cap=%lu) totalDrops=%lu clientDrops=%u globalQueued=%ld.\n",
                       BLACKBIRD_MAX_TOTAL_QUEUED_EVENTS, (ULONG)dropLogCounter, Client->DroppedEvents,
                       InterlockedCompareExchange(&g_ControlTotalQueuedEvents, 0, 0));
        }
        return;
    }

    node = (PBLACKBIRD_EVENT_NODE)BLACKBIRDAllocatePoolCompat(POOL_FLAG_NON_PAGED, sizeof(*node), BLACKBIRD_POOL_TAG);
    if (node == NULL)
    {
        BLACKBIRDReleaseGlobalQueueSlot();
        Client->DroppedEvents += 1;
        dropLogCounter = InterlockedIncrement(&g_ControlQueueDropLogCounter);
        if (dropLogCounter == 1 || ((dropLogCounter & 0xFF) == 0))
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "BLACKBIRD: queue drop (alloc failure) totalDrops=%lu clientDrops=%u queueDepth=%u.\n",
                       (ULONG)dropLogCounter, Client->DroppedEvents, Client->QueueDepth);
        }
        return;
    }

    RtlZeroMemory(node, sizeof(*node));
    RtlCopyMemory(&node->Record, Source, sizeof(node->Record));
    InsertTailList(&Client->EventQueue, &node->Link);
    Client->QueueDepth += 1;
}

VOID BLACKBIRDPublishRecordToSubscribers(_In_ UINT32 PrimaryPid, _In_ UINT32 SecondaryPid, _In_ UINT32 StreamMask,
                                           _In_ BLACKBIRD_EVENT_RECORD *Record)
{
    PBLACKBIRD_CLIENT snapshot[BLACKBIRD_MAX_TOTAL_CLIENTS];
    UINT32 snapshotCount = 0;
    UINT32 i;
    PLIST_ENTRY e;

    if (InterlockedCompareExchange(&g_ControlInitialized, 0, 0) == 0)
    {
        return;
    }
    if (BLACKBIRDControlIsShutdown())
    {
        return;
    }

    ExAcquireFastMutex(&g_ClientListLock);
    for (e = g_ClientList.Flink; e != &g_ClientList; e = e->Flink)
    {
        PBLACKBIRD_CLIENT c = CONTAINING_RECORD(e, BLACKBIRD_CLIENT, Link);
        if (snapshotCount >= RTL_NUMBER_OF(snapshot))
        {
            break;
        }
        BLACKBIRDClientReference(c);
        snapshot[snapshotCount++] = c;
    }
    ExReleaseFastMutex(&g_ClientListLock);

    for (i = 0; i < snapshotCount; ++i)
    {
        PBLACKBIRD_CLIENT c = snapshot[i];
        ExAcquireFastMutex(&c->Lock);
        if (BLACKBIRDClientMatchSubscriptionEither(c, PrimaryPid, SecondaryPid, StreamMask))
        {
            Record->Header.Sequence = ++c->Sequence;
            BLACKBIRDClientEnqueueEvent(c, Record);
        }
        ExReleaseFastMutex(&c->Lock);
        BLACKBIRDClientRelease(c);
    }
}

EVT_WDF_DEVICE_FILE_CREATE BLACKBIRDEvtFileCreate;
EVT_WDF_FILE_CLEANUP BLACKBIRDEvtFileCleanup;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL BLACKBIRDEvtIoDeviceControl;

_Use_decl_annotations_ VOID BLACKBIRDEvtFileCreate(WDFDEVICE Device, WDFREQUEST Request, WDFFILEOBJECT FileObject)
{
    PBLACKBIRD_FILE_CONTEXT ctx;
    PBLACKBIRD_CLIENT client;
    ULONG requesterPid;
    LONG clientCountSnapshot;

    UNREFERENCED_PARAMETER(Device);

    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        WdfRequestComplete(Request, STATUS_INVALID_DEVICE_STATE);
        return;
    }
    if (BLACKBIRDControlIsShutdown())
    {
        WdfRequestComplete(Request, STATUS_DELETE_PENDING);
        return;
    }

    client = BLACKBIRDClientCreate();
    if (client == NULL)
    {
        WdfRequestComplete(Request, STATUS_INSUFFICIENT_RESOURCES);
        return;
    }

    ExAcquireFastMutex(&g_ClientListLock);
    if (g_ClientCount >= BLACKBIRD_MAX_TOTAL_CLIENTS)
    {
        ExReleaseFastMutex(&g_ClientListLock);
        BLACKBIRDClientRelease(client);
        WdfRequestComplete(Request, STATUS_QUOTA_EXCEEDED);
        return;
    }
    InsertTailList(&g_ClientList, &client->Link);
    g_ClientCount += 1;
    clientCountSnapshot = g_ClientCount;
    ExReleaseFastMutex(&g_ClientListLock);

    ctx = BLACKBIRDGetFileContext(FileObject);
    ctx->Client = client;

    requesterPid = BLACKBIRDGetRequestorPid(Request);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID,
               DPFLTR_INFO_LEVEL,
               "BLACKBIRD: client attached pid=%lu activeClients=%ld fileObj=0x%p.\n",
               requesterPid,
               clientCountSnapshot,
               FileObject);

    WdfRequestComplete(Request, STATUS_SUCCESS);
}

_Use_decl_annotations_ VOID BLACKBIRDEvtFileCleanup(WDFFILEOBJECT FileObject)
{
    PBLACKBIRD_FILE_CONTEXT ctx = BLACKBIRDGetFileContext(FileObject);
    PBLACKBIRD_CLIENT client = ctx->Client;
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
        if (CONTAINING_RECORD(e, BLACKBIRD_CLIENT, Link) == client)
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
               "BLACKBIRD: client detached pid=%lu activeClients=%ld subscriptions=%lu queueDepth=%lu dropped=%lu fileObj=0x%p.\n",
               requesterPid,
               clientCountSnapshot,
               subscriptionCountSnapshot,
               queueDepthSnapshot,
               droppedSnapshot,
               FileObject);

    BLACKBIRDClientRelease(client);
    ctx->Client = NULL;
}
