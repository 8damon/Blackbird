#include "control_private.h"

BOOLEAN BLACKBIRDModeAllowed(_In_ WDFREQUEST Request)
{
    return (WdfRequestGetRequestorMode(Request) == UserMode);
}

ULONG BLACKBIRDGetRequestorPid(VOID)
{
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
    case IOCTL_BLACKBIRD_ARM_PENDING_LAUNCH:
        return "ARM_PENDING_LAUNCH";
    case IOCTL_BLACKBIRD_CONTROL_EXECUTION:
        return "CONTROL_EXECUTION";
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
    NT_ASSERT(remaining >= 0);
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
    NT_ASSERT(remaining >= 0);
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

static VOID BLACKBIRDClientClearPendingLaunchLocked(_Inout_ PBLACKBIRD_CLIENT Client)
{
    if (Client == NULL)
    {
        return;
    }

    Client->PendingLaunchArmed = FALSE;
    Client->PendingLaunchStreamMask = 0;
    Client->PendingLaunchPathNormDos[0] = L'\0';
    Client->PendingLaunchPathNormNt[0] = L'\0';
    Client->PendingLaunchPathTail[0] = L'\0';
}

static PCWSTR BLACKBIRDSkipKnownPathPrefixes(_In_opt_z_ PCWSTR Input)
{
    if (Input == NULL)
    {
        return NULL;
    }

    if ((Input[0] == L'\\' && Input[1] == L'\\' && Input[2] == L'?' && Input[3] == L'\\') ||
        (Input[0] == L'\\' && Input[1] == L'?' && Input[2] == L'?' && Input[3] == L'\\'))
    {
        return Input + 4;
    }

    return Input;
}

static VOID BLACKBIRDNormalizeWidePathForCompare(_In_opt_z_ PCWSTR Input,
                                                 _Out_writes_z_(OutputChars) PWSTR Output,
                                                 _In_ SIZE_T OutputChars)
{
    SIZE_T i;
    SIZE_T written = 0;

    if (Output == NULL || OutputChars == 0)
    {
        return;
    }
    Output[0] = L'\0';

    if (Input == NULL)
    {
        return;
    }

    Input = BLACKBIRDSkipKnownPathPrefixes(Input);
    if (Input == NULL)
    {
        return;
    }

    for (i = 0; Input[i] != L'\0' && (written + 1) < OutputChars; ++i)
    {
        WCHAR ch = Input[i];
        if (ch == L'/')
        {
            ch = L'\\';
        }
        Output[written++] = RtlDowncaseUnicodeChar(ch);
    }
    Output[written] = L'\0';
}

static VOID BLACKBIRDNormalizeUnicodePathForCompare(_In_opt_ PCUNICODE_STRING Input,
                                                    _Out_writes_z_(OutputChars) PWSTR Output,
                                                    _In_ SIZE_T OutputChars)
{
    SIZE_T i;
    SIZE_T inputChars;
    SIZE_T written = 0;
    PCWSTR inputBuffer;

    if (Output == NULL || OutputChars == 0)
    {
        return;
    }
    Output[0] = L'\0';

    if (Input == NULL || Input->Buffer == NULL || Input->Length == 0)
    {
        return;
    }

    inputBuffer = BLACKBIRDSkipKnownPathPrefixes(Input->Buffer);
    if (inputBuffer == NULL)
    {
        return;
    }
    inputChars = Input->Length / sizeof(WCHAR);
    if (inputBuffer > Input->Buffer)
    {
        SIZE_T skippedChars = (SIZE_T)(inputBuffer - Input->Buffer);
        if (skippedChars >= inputChars)
        {
            return;
        }
        inputChars -= skippedChars;
    }

    for (i = 0; i < inputChars && (written + 1) < OutputChars; ++i)
    {
        WCHAR ch = inputBuffer[i];
        if (ch == L'/')
        {
            ch = L'\\';
        }
        Output[written++] = RtlDowncaseUnicodeChar(ch);
    }
    Output[written] = L'\0';
}

static BOOLEAN BLACKBIRDPathHasTrailingSegmentInsensitive(_In_z_ PCWSTR Path, _In_z_ PCWSTR Tail)
{
    SIZE_T pathLen;
    SIZE_T tailLen;
    PCWSTR end;

    if (Path == NULL || Tail == NULL || Tail[0] == L'\0')
    {
        return FALSE;
    }

    pathLen = wcslen(Path);
    tailLen = wcslen(Tail);
    if (tailLen > pathLen)
    {
        return FALSE;
    }

    end = Path + (pathLen - tailLen);
    if (_wcsicmp(end, Tail) != 0)
    {
        return FALSE;
    }

    if (end == Path)
    {
        return TRUE;
    }
    return (end[-1] == L'\\');
}

static BOOLEAN BLACKBIRDClientPathMatchesPendingLaunchLocked(_In_ const BLACKBIRD_CLIENT *Client,
                                                             _In_z_ PCWSTR CandidateNorm)
{
    if (Client == NULL || CandidateNorm == NULL || CandidateNorm[0] == L'\0' || !Client->PendingLaunchArmed)
    {
        return FALSE;
    }

    if (Client->PendingLaunchPathNormNt[0] != L'\0' &&
        _wcsicmp(Client->PendingLaunchPathNormNt, CandidateNorm) == 0)
    {
        return TRUE;
    }

    if (Client->PendingLaunchPathNormDos[0] != L'\0' &&
        _wcsicmp(Client->PendingLaunchPathNormDos, CandidateNorm) == 0)
    {
        return TRUE;
    }

    if (Client->PendingLaunchPathTail[0] != L'\0' &&
        BLACKBIRDPathHasTrailingSegmentInsensitive(CandidateNorm, Client->PendingLaunchPathTail))
    {
        return TRUE;
    }

    return FALSE;
}

static BOOLEAN BLACKBIRDClientAddOrUpdateSubscriptionLocked(_Inout_ PBLACKBIRD_CLIENT Client,
                                                            _In_ UINT32 ProcessId,
                                                            _In_ UINT32 StreamMask)
{
    UINT32 i;

    if (Client == NULL || ProcessId == 0 || StreamMask == 0)
    {
        return FALSE;
    }

    for (i = 0; i < Client->SubscriptionCount; ++i)
    {
        if (Client->Subscriptions[i].ProcessId == ProcessId)
        {
            Client->Subscriptions[i].StreamMask |= StreamMask;
            return TRUE;
        }
    }

    if (Client->SubscriptionCount >= BLACKBIRD_MAX_CLIENT_SUBSCRIPTIONS)
    {
        return FALSE;
    }

    Client->Subscriptions[Client->SubscriptionCount].ProcessId = ProcessId;
    Client->Subscriptions[Client->SubscriptionCount].StreamMask = StreamMask;
    Client->SubscriptionCount += 1;
    return TRUE;
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
        WDFQUEUE pendingQueue = NULL;
        ExAcquireFastMutex(&c->Lock);
        pendingQueue = c->PendingGetEventQueue;
        c->PendingGetEventQueue = NULL;
        c->SubscriptionCount = 0;
        BLACKBIRDClientClearPendingLaunchLocked(c);
        BLACKBIRDClientFreeQueuedEvents(c);
        ExReleaseFastMutex(&c->Lock);
        if (pendingQueue != NULL)
        {
            WdfIoQueuePurgeSynchronously(pendingQueue);
        }
        BLACKBIRDClientRelease(c);
    }
}

VOID BLACKBIRDControlRefreshArmedState(VOID)
{
    PBLACKBIRD_CLIENT snapshot[BLACKBIRD_MAX_TOTAL_CLIENTS];
    UINT32 snapshotCount = 0;
    UINT32 i;
    PLIST_ENTRY entry;
    BOOLEAN armed = FALSE;

    ExAcquireFastMutex(&g_ClientListLock);
    for (entry = g_ClientList.Flink; entry != &g_ClientList; entry = entry->Flink)
    {
        PBLACKBIRD_CLIENT client = CONTAINING_RECORD(entry, BLACKBIRD_CLIENT, Link);
        if (snapshotCount >= RTL_NUMBER_OF(snapshot))
        {
            break;
        }
        BLACKBIRDClientReference(client);
        snapshot[snapshotCount++] = client;
    }
    ExReleaseFastMutex(&g_ClientListLock);

    for (i = 0; i < snapshotCount; ++i)
    {
        PBLACKBIRD_CLIENT client = snapshot[i];
        ExAcquireFastMutex(&client->Lock);
        if (client->SubscriptionCount != 0)
        {
            armed = TRUE;
        }
        ExReleaseFastMutex(&client->Lock);
        BLACKBIRDClientRelease(client);
        if (armed)
        {
            break;
        }
    }

    for (++i; i < snapshotCount; ++i)
    {
        BLACKBIRDClientRelease(snapshot[i]);
    }

    InterlockedExchange(&g_ControlTelemetryArmed, armed ? 1 : 0);
}

VOID BLACKBIRDControlBeginShutdown(VOID)
{
    if (InterlockedExchange(&g_ControlShutdown, 1) == 0)
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "BLACKBIRD: control plane entering shutdown mode.\n");
    }
    BLACKBIRDControlFlushAllClientState();
    InterlockedExchange(&g_ControlTelemetryArmed, 0);
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
    client->PendingGetEventQueue = NULL;
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

BOOLEAN
BLACKBIRDControlBindPendingLaunchProcess(_In_ UINT32 ProcessId, _In_opt_ PCUNICODE_STRING ImagePath)
{
    PBLACKBIRD_CLIENT snapshot[BLACKBIRD_MAX_TOTAL_CLIENTS];
    WCHAR candidateNorm[BLACKBIRD_MAX_IMAGE_PATH_CHARS];
    UINT32 snapshotCount = 0;
    UINT32 i;
    PLIST_ENTRY entry;
    BOOLEAN matchedAny = FALSE;

    if (ProcessId == 0 || ImagePath == NULL || ImagePath->Buffer == NULL || ImagePath->Length == 0)
    {
        return FALSE;
    }
    if (!BLACKBIRDControlHasClientsFast())
    {
        return FALSE;
    }

    BLACKBIRDNormalizeUnicodePathForCompare(ImagePath, candidateNorm, RTL_NUMBER_OF(candidateNorm));
    if (candidateNorm[0] == L'\0')
    {
        return FALSE;
    }

    ExAcquireFastMutex(&g_ClientListLock);
    for (entry = g_ClientList.Flink; entry != &g_ClientList; entry = entry->Flink)
    {
        PBLACKBIRD_CLIENT client = CONTAINING_RECORD(entry, BLACKBIRD_CLIENT, Link);
        if (snapshotCount >= RTL_NUMBER_OF(snapshot))
        {
            break;
        }
        BLACKBIRDClientReference(client);
        snapshot[snapshotCount++] = client;
    }
    ExReleaseFastMutex(&g_ClientListLock);

    for (i = 0; i < snapshotCount; ++i)
    {
        PBLACKBIRD_CLIENT client = snapshot[i];
        ExAcquireFastMutex(&client->Lock);
        if (BLACKBIRDClientPathMatchesPendingLaunchLocked(client, candidateNorm))
        {
            UINT32 streamMask = client->PendingLaunchStreamMask;
            BOOLEAN subscribed = BLACKBIRDClientAddOrUpdateSubscriptionLocked(client, ProcessId, streamMask);

            BLACKBIRDClientClearPendingLaunchLocked(client);
            if (subscribed)
            {
                matchedAny = TRUE;
                InterlockedExchange(&g_ControlTelemetryArmed, 1);
                DbgPrintEx(DPFLTR_IHVDRIVER_ID,
                           DPFLTR_INFO_LEVEL,
                           "BLACKBIRD: pending launch bound targetPid=%lu streamMask=0x%08X image=%ws.\n",
                           ProcessId,
                           streamMask,
                           candidateNorm);
            }
            else
            {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID,
                           DPFLTR_WARNING_LEVEL,
                           "BLACKBIRD: pending launch match could not bind targetPid=%lu image=%ws reason=subscription-capacity.\n",
                           ProcessId,
                           candidateNorm);
            }
        }
        ExReleaseFastMutex(&client->Lock);
        BLACKBIRDClientRelease(client);
    }

    return matchedAny;
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

static BOOLEAN BLACKBIRDClientTryTakePendingGetEventRequestLocked(_In_ PBLACKBIRD_CLIENT Client,
                                                                   _Out_ WDFREQUEST *Request)
{
    NTSTATUS status;

    if (Request == NULL)
    {
        return FALSE;
    }

    *Request = NULL;
    if (Client == NULL || Client->PendingGetEventQueue == NULL)
    {
        return FALSE;
    }

    status = WdfIoQueueRetrieveNextRequest(Client->PendingGetEventQueue, Request);
    return NT_SUCCESS(status);
}

static NTSTATUS BLACKBIRDCompleteGetEventRequestWithRecord(_In_ WDFREQUEST Request,
                                                           _In_ const BLACKBIRD_EVENT_RECORD *Record)
{
    NTSTATUS status;
    PBLACKBIRD_EVENT_RECORD out;
    size_t outSize;
    LONG deliverCounter;
    ULONG requesterPid;

    if (Request == NULL || Record == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    status = WdfRequestRetrieveOutputBuffer(Request, sizeof(*out), (PVOID *)&out, &outSize);
    if (!NT_SUCCESS(status))
    {
        WdfRequestComplete(Request, status);
        return status;
    }
    if (outSize < sizeof(*out))
    {
        WdfRequestComplete(Request, STATUS_BUFFER_TOO_SMALL);
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlCopyMemory(out, Record, sizeof(*out));
    WdfRequestCompleteWithInformation(Request, STATUS_SUCCESS, sizeof(*out));

    deliverCounter = InterlockedIncrement(&g_IoctlGetEventDeliverCounter);
    if (deliverCounter == 1 || ((deliverCounter & 0x1FF) == 0))
    {
        requesterPid = BLACKBIRDGetRequestorPid();
        DbgPrintEx(DPFLTR_IHVDRIVER_ID,
                   DPFLTR_INFO_LEVEL,
                   "BLACKBIRD: get-event delivered(pended) requesterPid=%lu deliveredCount=%ld eventType=%lu seq=%lu.\n",
                   requesterPid,
                   deliverCounter,
                   Record->Header.Type,
                   Record->Header.Sequence);
    }

    return STATUS_SUCCESS;
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
        WDFREQUEST pendingRequest = NULL;
        BLACKBIRD_EVENT_RECORD stagedRecord;
        BOOLEAN matched = FALSE;
        NTSTATUS deliverStatus = STATUS_UNSUCCESSFUL;

        RtlZeroMemory(&stagedRecord, sizeof(stagedRecord));
        ExAcquireFastMutex(&c->Lock);
        if (BLACKBIRDClientMatchSubscriptionEither(c, PrimaryPid, SecondaryPid, StreamMask))
        {
            matched = TRUE;
            RtlCopyMemory(&stagedRecord, Record, sizeof(stagedRecord));
            stagedRecord.Header.Sequence = ++c->Sequence;

            if (!BLACKBIRDClientTryTakePendingGetEventRequestLocked(c, &pendingRequest))
            {
                BLACKBIRDClientEnqueueEvent(c, &stagedRecord);
            }
        }
        ExReleaseFastMutex(&c->Lock);

        if (matched && pendingRequest != NULL)
        {
            deliverStatus = BLACKBIRDCompleteGetEventRequestWithRecord(pendingRequest, &stagedRecord);
            if (!NT_SUCCESS(deliverStatus) && !BLACKBIRDControlIsShutdown())
            {
                ExAcquireFastMutex(&c->Lock);
                BLACKBIRDClientEnqueueEvent(c, &stagedRecord);
                ExReleaseFastMutex(&c->Lock);
            }
        }

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
    WDF_IO_QUEUE_CONFIG queueConfig;
    WDF_OBJECT_ATTRIBUTES queueAttrs;
    WDFQUEUE pendingQueue = NULL;
    NTSTATUS queueStatus = STATUS_SUCCESS;
    ULONG requesterPid;
    LONG clientCountSnapshot;

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

    WDF_IO_QUEUE_CONFIG_INIT(&queueConfig, WdfIoQueueDispatchManual);
    queueConfig.PowerManaged = WdfFalse;
    WDF_OBJECT_ATTRIBUTES_INIT(&queueAttrs);
    queueAttrs.ParentObject = FileObject;
    queueStatus = WdfIoQueueCreate(Device, &queueConfig, &queueAttrs, &pendingQueue);
    if (!NT_SUCCESS(queueStatus))
    {
        ExAcquireFastMutex(&g_ClientListLock);
        RemoveEntryList(&client->Link);
        InitializeListHead(&client->Link);
        if (g_ClientCount > 0)
        {
            g_ClientCount -= 1;
        }
        ExReleaseFastMutex(&g_ClientListLock);
        BLACKBIRDClientRelease(client);
        WdfRequestComplete(Request, queueStatus);
        return;
    }
    client->PendingGetEventQueue = pendingQueue;

    ctx = BLACKBIRDGetFileContext(FileObject);
    ctx->Client = client;

    requesterPid = BLACKBIRDGetRequestorPid();
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

    if (clientCountSnapshot == 0)
    {
        InterlockedExchange(&g_ControlTelemetryArmed, 0);
    }
    else
    {
        BLACKBIRDControlRefreshArmedState();
    }

    ExAcquireFastMutex(&client->Lock);
    {
        WDFQUEUE pendingQueue = client->PendingGetEventQueue;
        client->PendingGetEventQueue = NULL;
        subscriptionCountSnapshot = client->SubscriptionCount;
        queueDepthSnapshot = client->QueueDepth;
        droppedSnapshot = client->DroppedEvents;
        ExReleaseFastMutex(&client->Lock);
        if (pendingQueue != NULL)
        {
            WdfIoQueuePurgeSynchronously(pendingQueue);
        }
    }

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

