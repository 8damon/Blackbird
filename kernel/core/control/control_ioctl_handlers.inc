static NTSTATUS SLEEPWALKERHandleSubscribeIoctl(_In_ PSLEEPWALKER_CLIENT Client, _In_ WDFREQUEST Request)
{
    NTSTATUS status;
    PSLEEPWALKER_SUBSCRIBE_REQUEST in;
    size_t inSize;
    UINT32 i;
    ULONG requesterPid;
    UINT32 subscriptionCountSnapshot;
    UINT32 mergedMask;

    status = WdfRequestRetrieveInputBuffer(Request, sizeof(*in), (PVOID *)&in, &inSize);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    UNREFERENCED_PARAMETER(inSize);

    if ((in->StreamMask & (SLEEPWALKER_STREAM_HANDLE | SLEEPWALKER_STREAM_MEMORY | SLEEPWALKER_STREAM_THREAD)) == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (SLEEPWALKERControlIsShutdown())
    {
        return STATUS_DEVICE_NOT_READY;
    }

    ExAcquireFastMutex(&Client->Lock);
    for (i = 0; i < Client->SubscriptionCount; ++i)
    {
        if (Client->Subscriptions[i].ProcessId == in->ProcessId)
        {
            Client->Subscriptions[i].StreamMask |= in->StreamMask;
            mergedMask = Client->Subscriptions[i].StreamMask;
            subscriptionCountSnapshot = Client->SubscriptionCount;
            ExReleaseFastMutex(&Client->Lock);
            requesterPid = SLEEPWALKERGetRequestorPid(Request);
            DbgPrintEx(DPFLTR_IHVDRIVER_ID,
                       DPFLTR_INFO_LEVEL,
                       "SLEEPWALKER: subscribe update requesterPid=%lu targetPid=%lu streamMask=0x%08X mergedMask=0x%08X subscriptions=%lu.\n",
                       requesterPid,
                       in->ProcessId,
                       in->StreamMask,
                       mergedMask,
                       subscriptionCountSnapshot);
            return STATUS_SUCCESS;
        }
    }

    if (Client->SubscriptionCount >= SLEEPWALKER_MAX_CLIENT_SUBSCRIPTIONS)
    {
        ExReleaseFastMutex(&Client->Lock);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Client->Subscriptions[Client->SubscriptionCount].ProcessId = in->ProcessId;
    Client->Subscriptions[Client->SubscriptionCount].StreamMask = in->StreamMask;
    Client->SubscriptionCount += 1;
    subscriptionCountSnapshot = Client->SubscriptionCount;
    ExReleaseFastMutex(&Client->Lock);

    requesterPid = SLEEPWALKERGetRequestorPid(Request);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID,
               DPFLTR_INFO_LEVEL,
               "SLEEPWALKER: subscribe add requesterPid=%lu targetPid=%lu streamMask=0x%08X subscriptions=%lu.\n",
               requesterPid,
               in->ProcessId,
               in->StreamMask,
               subscriptionCountSnapshot);

    return STATUS_SUCCESS;
}

static NTSTATUS SLEEPWALKERHandleUnsubscribeIoctl(_In_ PSLEEPWALKER_CLIENT Client, _In_ WDFREQUEST Request)
{
    NTSTATUS status;
    PSLEEPWALKER_UNSUBSCRIBE_REQUEST in;
    size_t inSize;
    UINT32 i;
    ULONG requesterPid;
    UINT32 subscriptionCountSnapshot;

    status = WdfRequestRetrieveInputBuffer(Request, sizeof(*in), (PVOID *)&in, &inSize);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    UNREFERENCED_PARAMETER(inSize);
    if (SLEEPWALKERControlIsShutdown())
    {
        return STATUS_DEVICE_NOT_READY;
    }

    ExAcquireFastMutex(&Client->Lock);
    for (i = 0; i < Client->SubscriptionCount; ++i)
    {
        if (Client->Subscriptions[i].ProcessId == in->ProcessId)
        {
            UINT32 tail = Client->SubscriptionCount - 1;
            if (i != tail)
            {
                Client->Subscriptions[i] = Client->Subscriptions[tail];
            }
            Client->SubscriptionCount -= 1;
            subscriptionCountSnapshot = Client->SubscriptionCount;
            ExReleaseFastMutex(&Client->Lock);
            requesterPid = SLEEPWALKERGetRequestorPid(Request);
            DbgPrintEx(DPFLTR_IHVDRIVER_ID,
                       DPFLTR_INFO_LEVEL,
                       "SLEEPWALKER: unsubscribe requesterPid=%lu targetPid=%lu subscriptions=%lu.\n",
                       requesterPid,
                       in->ProcessId,
                       subscriptionCountSnapshot);
            return STATUS_SUCCESS;
        }
    }
    ExReleaseFastMutex(&Client->Lock);
    requesterPid = SLEEPWALKERGetRequestorPid(Request);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID,
               DPFLTR_WARNING_LEVEL,
               "SLEEPWALKER: unsubscribe miss requesterPid=%lu targetPid=%lu status=STATUS_NOT_FOUND.\n",
               requesterPid,
               in->ProcessId);
    return STATUS_NOT_FOUND;
}

static NTSTATUS SLEEPWALKERHandleGetStatsIoctl(_In_ PSLEEPWALKER_CLIENT Client, _In_ WDFREQUEST Request,
                                               _Out_ size_t *BytesOut)
{
    NTSTATUS status;
    PSLEEPWALKER_STATS_RESPONSE out;
    size_t outSize;
    LONG statsCounter;
    ULONG requesterPid;

    *BytesOut = 0;

    status = WdfRequestRetrieveOutputBuffer(Request, sizeof(*out), (PVOID *)&out, &outSize);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    if (outSize < sizeof(*out))
    {
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlZeroMemory(out, sizeof(*out));
    ExAcquireFastMutex(&Client->Lock);
    out->SubscriptionCount = Client->SubscriptionCount;
    out->QueueDepth = Client->QueueDepth;
    out->DroppedEvents = Client->DroppedEvents;
    ExReleaseFastMutex(&Client->Lock);

    *BytesOut = sizeof(*out);
    statsCounter = InterlockedIncrement(&g_IoctlGetStatsCounter);
    if (statsCounter == 1 || ((statsCounter & 0x7F) == 0))
    {
        requesterPid = SLEEPWALKERGetRequestorPid(Request);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID,
                   DPFLTR_INFO_LEVEL,
                   "SLEEPWALKER: get-stats requesterPid=%lu count=%ld subscriptions=%lu queueDepth=%lu dropped=%lu.\n",
                   requesterPid,
                   statsCounter,
                   out->SubscriptionCount,
                   out->QueueDepth,
                   out->DroppedEvents);
    }
    return STATUS_SUCCESS;
}

static NTSTATUS SLEEPWALKERHandleSetPidsIoctl(_In_ PSLEEPWALKER_CLIENT Client, _In_ WDFREQUEST Request)
{
    NTSTATUS status;
    PSLEEPWALKER_SET_PIDS_REQUEST in;
    size_t inSize;
    UINT32 i;
    UINT32 streamMask;
    UINT32 appliedCount;
    ULONG requesterPid;

    status = WdfRequestRetrieveInputBuffer(Request, sizeof(*in), (PVOID *)&in, &inSize);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    UNREFERENCED_PARAMETER(inSize);

    streamMask = in->StreamMask;
    if ((streamMask & (SLEEPWALKER_STREAM_HANDLE | SLEEPWALKER_STREAM_MEMORY | SLEEPWALKER_STREAM_THREAD)) == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (in->ProcessCount == 0 || in->ProcessCount > SLEEPWALKER_MAX_PID_LIST)
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (SLEEPWALKERControlIsShutdown())
    {
        return STATUS_DEVICE_NOT_READY;
    }

    ExAcquireFastMutex(&Client->Lock);
    Client->SubscriptionCount = 0;

    for (i = 0; i < in->ProcessCount; ++i)
    {
        UINT32 pid = in->ProcessIds[i];
        UINT32 j;
        BOOLEAN seen = FALSE;

        if (pid == 0)
        {
            continue;
        }

        for (j = 0; j < Client->SubscriptionCount; ++j)
        {
            if (Client->Subscriptions[j].ProcessId == pid)
            {
                Client->Subscriptions[j].StreamMask |= streamMask;
                seen = TRUE;
                break;
            }
        }

        if (!seen && Client->SubscriptionCount < SLEEPWALKER_MAX_CLIENT_SUBSCRIPTIONS)
        {
            Client->Subscriptions[Client->SubscriptionCount].ProcessId = pid;
            Client->Subscriptions[Client->SubscriptionCount].StreamMask = streamMask;
            Client->SubscriptionCount += 1;
        }
    }

    appliedCount = Client->SubscriptionCount;
    ExReleaseFastMutex(&Client->Lock);
    requesterPid = SLEEPWALKERGetRequestorPid(Request);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID,
               DPFLTR_INFO_LEVEL,
               "SLEEPWALKER: set-pids requesterPid=%lu requestedCount=%lu appliedCount=%lu streamMask=0x%08X.\n",
               requesterPid,
               in->ProcessCount,
               appliedCount,
               streamMask);

    return (appliedCount != 0) ? STATUS_SUCCESS : STATUS_INVALID_PARAMETER;
}

static NTSTATUS SLEEPWALKERResolveProcessImagePath(_In_ UINT32 ProcessId, _Out_writes_z_(OutputChars) PWSTR Output,
                                                   _In_ size_t OutputChars)
{
    NTSTATUS status;
    PEPROCESS process = NULL;
    PUNICODE_STRING imageName = NULL;

    if (Output == NULL || OutputChars == 0 || ProcessId == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }
    Output[0] = L'\0';

    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId, &process);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    status = SeLocateProcessImageName(process, &imageName);
    ObDereferenceObject(process);
    process = NULL;
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    if (imageName == NULL || imageName->Buffer == NULL || imageName->Length == 0)
    {
        if (imageName != NULL)
        {
            ExFreePool(imageName);
        }
        return STATUS_NOT_FOUND;
    }

    status = RtlStringCchCopyNW(Output, OutputChars, imageName->Buffer, imageName->Length / sizeof(WCHAR));
    ExFreePool(imageName);
    if (status == STATUS_BUFFER_OVERFLOW)
    {
        return STATUS_SUCCESS;
    }
    return status;
}

static NTSTATUS SLEEPWALKERHandleQueryProcessImageIoctl(_In_ PSLEEPWALKER_CLIENT Client, _In_ WDFREQUEST Request,
                                                        _Out_ size_t *BytesOut)
{
    NTSTATUS status;
    PSLEEPWALKER_QUERY_PROCESS_IMAGE_REQUEST in;
    PSLEEPWALKER_QUERY_PROCESS_IMAGE_RESPONSE out;
    size_t inSize;
    size_t outSize;
    ULONG requesterPid;

    *BytesOut = 0;
    if (SLEEPWALKERControlIsShutdown())
    {
        return STATUS_DEVICE_NOT_READY;
    }

    ExAcquireFastMutex(&Client->Lock);
    if (!SLEEPWALKERClientConsumeQueryBudgetLocked(Client))
    {
        LONG throttleCounter = InterlockedIncrement(&g_QueryImageThrottleCounter);
        ExReleaseFastMutex(&Client->Lock);
        if (throttleCounter == 1 || ((throttleCounter & 0xFF) == 0))
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "SLEEPWALKER: throttling IOCTL_SLEEPWALKER_QUERY_PROCESS_IMAGE total=%lu.\n",
                       (ULONG)throttleCounter);
        }
        return STATUS_QUOTA_EXCEEDED;
    }
    ExReleaseFastMutex(&Client->Lock);

    if (!SLEEPWALKERTryAcquireQueryInflightSlot())
    {
        InterlockedIncrement(&g_QueryImageThrottleCounter);
        return STATUS_DEVICE_BUSY;
    }

    status = WdfRequestRetrieveInputBuffer(Request, sizeof(*in), (PVOID *)&in, &inSize);
    if (!NT_SUCCESS(status))
    {
        SLEEPWALKERReleaseQueryInflightSlot();
        return status;
    }
    UNREFERENCED_PARAMETER(inSize);

    status = WdfRequestRetrieveOutputBuffer(Request, sizeof(*out), (PVOID *)&out, &outSize);
    if (!NT_SUCCESS(status))
    {
        SLEEPWALKERReleaseQueryInflightSlot();
        return status;
    }
    if (outSize < sizeof(*out))
    {
        SLEEPWALKERReleaseQueryInflightSlot();
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlZeroMemory(out, sizeof(*out));
    out->ProcessId = in->ProcessId;
    out->Status = SLEEPWALKERResolveProcessImagePath(in->ProcessId, out->ImagePath, RTL_NUMBER_OF(out->ImagePath));

    SLEEPWALKERReleaseQueryInflightSlot();
    *BytesOut = sizeof(*out);
    requesterPid = SLEEPWALKERGetRequestorPid(Request);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID,
               NT_SUCCESS(out->Status) ? DPFLTR_INFO_LEVEL : DPFLTR_WARNING_LEVEL,
               "SLEEPWALKER: query-process-image requesterPid=%lu targetPid=%lu status=0x%08X.\n",
               requesterPid,
               in->ProcessId,
               out->Status);
    return STATUS_SUCCESS;
}

static NTSTATUS SLEEPWALKERHandleGetEventIoctl(_In_ PSLEEPWALKER_CLIENT Client, _In_ WDFREQUEST Request,
                                               _Out_ size_t *BytesOut)
{
    NTSTATUS status;
    PSLEEPWALKER_EVENT_RECORD out;
    size_t outSize;
    UINT32 queueDepthSnapshot = 0;
    LONG emptyCounter;
    LONG deliverCounter;
    ULONG requesterPid;

    *BytesOut = 0;
    if (SLEEPWALKERControlIsShutdown())
    {
        return STATUS_DEVICE_NOT_READY;
    }
    status = WdfRequestRetrieveOutputBuffer(Request, sizeof(*out), (PVOID *)&out, &outSize);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    if (outSize < sizeof(*out))
    {
        return STATUS_BUFFER_TOO_SMALL;
    }

    ExAcquireFastMutex(&Client->Lock);
    if (IsListEmpty(&Client->EventQueue))
    {
        ExReleaseFastMutex(&Client->Lock);
        emptyCounter = InterlockedIncrement(&g_IoctlGetEventEmptyCounter);
        if (emptyCounter == 1 || ((emptyCounter & 0x1FF) == 0))
        {
            requesterPid = SLEEPWALKERGetRequestorPid(Request);
            DbgPrintEx(DPFLTR_IHVDRIVER_ID,
                       DPFLTR_INFO_LEVEL,
                       "SLEEPWALKER: get-event empty requesterPid=%lu emptyCount=%ld.\n",
                       requesterPid,
                       emptyCounter);
        }
        return STATUS_NO_MORE_ENTRIES;
    }

    {
        PLIST_ENTRY entry = RemoveHeadList(&Client->EventQueue);
        PSLEEPWALKER_EVENT_NODE node = CONTAINING_RECORD(entry, SLEEPWALKER_EVENT_NODE, Link);
        RtlCopyMemory(out, &node->Record, sizeof(*out));
        if (Client->QueueDepth > 0)
        {
            Client->QueueDepth -= 1;
        }
        queueDepthSnapshot = Client->QueueDepth;
        ExFreePoolWithTag(node, SLEEPWALKER_POOL_TAG);
        SLEEPWALKERReleaseGlobalQueueSlot();
    }
    ExReleaseFastMutex(&Client->Lock);

    *BytesOut = sizeof(*out);
    deliverCounter = InterlockedIncrement(&g_IoctlGetEventDeliverCounter);
    if (deliverCounter == 1 || ((deliverCounter & 0x1FF) == 0))
    {
        requesterPid = SLEEPWALKERGetRequestorPid(Request);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID,
                   DPFLTR_INFO_LEVEL,
                   "SLEEPWALKER: get-event delivered requesterPid=%lu deliveredCount=%ld queueDepthNow=%lu eventType=%lu seq=%lu.\n",
                   requesterPid,
                   deliverCounter,
                   queueDepthSnapshot,
                   out->Header.Type,
                   out->Header.Sequence);
    }
    return STATUS_SUCCESS;
}

static NTSTATUS SLEEPWALKERHandleSetShutdownModeIoctl(_In_ PSLEEPWALKER_CLIENT Client, _In_ WDFREQUEST Request)
{
    ULONG requesterPid;

    UNREFERENCED_PARAMETER(Client);
    requesterPid = SLEEPWALKERGetRequestorPid(Request);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID,
               DPFLTR_WARNING_LEVEL,
               "SLEEPWALKER: shutdown mode requested by requesterPid=%lu.\n",
               requesterPid);
    SLEEPWALKERControlBeginShutdown();
    return STATUS_SUCCESS;
}

