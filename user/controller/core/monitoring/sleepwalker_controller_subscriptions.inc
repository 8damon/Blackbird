static BOOL ControllerIsValidStreamMask(_In_ DWORD StreamMask)
{
    return ((StreamMask & SLEEPWALKER_CONTROLLER_DRIVER_STREAM_MASK) != 0);
}

static BOOL ControllerApplyDriverSubscriptions(VOID);
static VOID ControllerMarkDriverSubscriptionsDirty(VOID)
{
    (void)InterlockedExchange(&g_DriverSubscriptionsDirty, 1);
}

static BOOL ControllerApplyDriverSubscriptionsIfDirty(VOID)
{
    if (InterlockedCompareExchange(&g_DriverSubscriptionsDirty, 0, 1) == 1)
    {
        return ControllerApplyDriverSubscriptions();
    }
    return TRUE;
}

static LONG ControllerFindSubscriptionIndexLocked(_In_ const SLEEPWALKER_CONTROLLER_CLIENT *Client, _In_ DWORD ProcessId)
{
    DWORD i;

    if (Client == NULL || ProcessId == 0)
    {
        return -1;
    }

    for (i = 0; i < Client->SubscriptionCount; ++i)
    {
        if (Client->Subscriptions[i].ProcessId == ProcessId)
        {
            return (LONG)i;
        }
    }

    return -1;
}

static VOID ControllerRemoveSubscriptionAtLocked(_Inout_ SLEEPWALKER_CONTROLLER_CLIENT *Client, _In_ DWORD Index)
{
    DWORD tail;

    if (Client == NULL || Client->SubscriptionCount == 0 || Index >= Client->SubscriptionCount)
    {
        return;
    }

    tail = Client->SubscriptionCount - 1;
    if (Index != tail)
    {
        Client->Subscriptions[Index] = Client->Subscriptions[tail];
    }
    ZeroMemory(&Client->Subscriptions[tail], sizeof(Client->Subscriptions[tail]));
    Client->SubscriptionCount -= 1;
}

static BOOL ControllerPruneDynamicSubscriptionsLocked(_Inout_ SLEEPWALKER_CONTROLLER_CLIENT *Client, _In_ ULONGLONG NowTick)
{
    BOOL changed = FALSE;
    DWORD i = 0;

    if (Client == NULL)
    {
        return FALSE;
    }

    while (i < Client->SubscriptionCount)
    {
        const SLEEPWALKER_CONTROLLER_SUBSCRIPTION *sub = &Client->Subscriptions[i];
        if (sub->Dynamic &&
            (sub->LastSeenTick == 0 ||
             (NowTick - sub->LastSeenTick) > (ULONGLONG)SLEEPWALKER_CONTROLLER_DYNAMIC_SUBSCRIPTION_TTL_MS))
        {
            DWORD expiredPid = sub->ProcessId;
            ControllerRemoveSubscriptionAtLocked(Client, i);
            changed = TRUE;
            ControllerLog("[MON] dynamic subscription expired clientPid=%lu targetPid=%lu\n", Client->ProcessId,
                          expiredPid);
            continue;
        }
        i += 1;
    }

    return changed;
}

static BOOL ControllerDropDynamicDescendantsLocked(_Inout_ SLEEPWALKER_CONTROLLER_CLIENT *Client, _In_ DWORD RootProcessId)
{
    DWORD pending[SLEEPWALKER_CONTROLLER_MAX_CLIENT_SUBSCRIPTIONS];
    DWORD pendingHead = 0;
    DWORD pendingTail = 0;
    BOOL changed = FALSE;

    if (Client == NULL || RootProcessId == 0)
    {
        return FALSE;
    }

    pending[pendingTail++] = RootProcessId;
    while (pendingHead < pendingTail)
    {
        DWORD current = pending[pendingHead++];
        DWORD i = 0;

        while (i < Client->SubscriptionCount)
        {
            const SLEEPWALKER_CONTROLLER_SUBSCRIPTION *sub = &Client->Subscriptions[i];
            if (sub->Dynamic && sub->SourceProcessId == current)
            {
                DWORD removedPid = sub->ProcessId;
                if (pendingTail < RTL_NUMBER_OF(pending) && removedPid != 0 && removedPid != current)
                {
                    pending[pendingTail++] = removedPid;
                }
                ControllerRemoveSubscriptionAtLocked(Client, i);
                changed = TRUE;
                ControllerLog("[MON] dynamic subscription removed clientPid=%lu targetPid=%lu sourcePid=%lu\n",
                              Client->ProcessId, removedPid, current);
                continue;
            }
            i += 1;
        }
    }

    return changed;
}

static BOOL ControllerTryExpandClientRelationLocked(_Inout_ SLEEPWALKER_CONTROLLER_CLIENT *Client, _In_ DWORD SourceProcessId,
                                                    _In_ DWORD TargetProcessId, _In_ DWORD RelationStreamMask)
{
    ULONGLONG nowTick;
    LONG sourceIndex;
    LONG targetIndex;
    PSLEEPWALKER_CONTROLLER_SUBSCRIPTION sourceSub;
    BOOL changed = FALSE;

    if (Client == NULL || SourceProcessId == 0 || TargetProcessId == 0 || SourceProcessId == TargetProcessId ||
        RelationStreamMask == 0)
    {
        return FALSE;
    }

    nowTick = GetTickCount64();
    changed = ControllerPruneDynamicSubscriptionsLocked(Client, nowTick);

    sourceIndex = ControllerFindSubscriptionIndexLocked(Client, SourceProcessId);
    if (sourceIndex < 0)
    {
        return changed;
    }

    sourceSub = &Client->Subscriptions[sourceIndex];
    if ((sourceSub->StreamMask & RelationStreamMask) == 0)
    {
        return changed;
    }

    if (sourceSub->Dynamic)
    {
        sourceSub->LastSeenTick = nowTick;
    }

    targetIndex = ControllerFindSubscriptionIndexLocked(Client, TargetProcessId);
    if (targetIndex >= 0)
    {
        PSLEEPWALKER_CONTROLLER_SUBSCRIPTION targetSub = &Client->Subscriptions[targetIndex];
        const DWORD mergedMask = (targetSub->StreamMask | sourceSub->StreamMask);
        if (mergedMask != targetSub->StreamMask)
        {
            targetSub->StreamMask = mergedMask;
            changed = TRUE;
        }

        if (targetSub->Dynamic)
        {
            UINT32 candidateDepth = sourceSub->Dynamic ? (sourceSub->Depth + 1u) : 1u;
            if (candidateDepth <= SLEEPWALKER_CONTROLLER_DYNAMIC_SUBSCRIPTION_MAX_DEPTH)
            {
                if (targetSub->Depth == 0 || candidateDepth < targetSub->Depth ||
                    (candidateDepth == targetSub->Depth && targetSub->SourceProcessId != SourceProcessId))
                {
                    targetSub->Depth = candidateDepth;
                    targetSub->SourceProcessId = SourceProcessId;
                    changed = TRUE;
                }
            }
            targetSub->LastSeenTick = nowTick;
        }

        return changed;
    }
    else
    {
        UINT32 targetDepth = sourceSub->Dynamic ? (sourceSub->Depth + 1u) : 1u;
        DWORD slot;

        if (targetDepth > SLEEPWALKER_CONTROLLER_DYNAMIC_SUBSCRIPTION_MAX_DEPTH ||
            Client->SubscriptionCount >= SLEEPWALKER_CONTROLLER_MAX_CLIENT_SUBSCRIPTIONS)
        {
            return changed;
        }

        slot = Client->SubscriptionCount;
        Client->Subscriptions[slot].ProcessId = TargetProcessId;
        Client->Subscriptions[slot].StreamMask = sourceSub->StreamMask;
        Client->Subscriptions[slot].Dynamic = TRUE;
        Client->Subscriptions[slot].SourceProcessId = SourceProcessId;
        Client->Subscriptions[slot].Depth = targetDepth;
        Client->Subscriptions[slot].LastSeenTick = nowTick;
        Client->SubscriptionCount += 1;
        ControllerLog("[MON] dynamic subscription add clientPid=%lu sourcePid=%lu targetPid=%lu depth=%u mask=0x%08lX\n",
                      Client->ProcessId, SourceProcessId, TargetProcessId, targetDepth, Client->Subscriptions[slot].StreamMask);
        return TRUE;
    }
}

static VOID ControllerExpandMonitoringGraph(_In_ DWORD SourceProcessId, _In_ DWORD TargetProcessId,
                                            _In_ DWORD RelationStreamMask)
{
    PSLEEPWALKER_CONTROLLER_CLIENT client;
    BOOL changed = FALSE;

    if (SourceProcessId == 0 || TargetProcessId == 0 || SourceProcessId == TargetProcessId || RelationStreamMask == 0)
    {
        return;
    }

    EnterCriticalSection(&g_ClientListLock);
    for (client = g_ClientList; client != NULL; client = client->Next)
    {
        EnterCriticalSection(&client->Lock);
        if (ControllerTryExpandClientRelationLocked(client, SourceProcessId, TargetProcessId, RelationStreamMask))
        {
            changed = TRUE;
        }
        LeaveCriticalSection(&client->Lock);
    }
    LeaveCriticalSection(&g_ClientListLock);

    if (changed)
    {
        (void)ControllerApplyDriverSubscriptions();
    }
}

static BOOL ControllerRecordMatchesSubscription(_In_ const SLEEPWALKER_EVENT_RECORD *Record, _In_ DWORD ProcessId,
                                                _In_ DWORD StreamMask)
{
    UINT32 recordMask;
    DWORD primary = 0;
    DWORD secondary = 0;

    if (Record == NULL || ProcessId == 0)
    {
        return FALSE;
    }

    recordMask = Record->Header.StreamMask;
    if ((recordMask & StreamMask) == 0)
    {
        return FALSE;
    }

    if (Record->Header.Type == SleepwalkerEventTypeHandle)
    {
        primary = (DWORD)Record->Data.Handle.CallerPid;
        secondary = (DWORD)Record->Data.Handle.TargetPid;
    }
    else if (Record->Header.Type == SleepwalkerEventTypeThread)
    {
        primary = (DWORD)Record->Data.Thread.ProcessId;
        secondary = (DWORD)Record->Data.Thread.CreatorPid;
    }
    else
    {
        return FALSE;
    }

    return (ProcessId == primary || ProcessId == secondary);
}

static BOOL ControllerClientHasMatchLocked(_In_ const SLEEPWALKER_CONTROLLER_CLIENT *Client,
                                           _In_ const SLEEPWALKER_EVENT_RECORD *Record)
{
    DWORD i;

    for (i = 0; i < Client->SubscriptionCount; ++i)
    {
        if (ControllerRecordMatchesSubscription(Record, Client->Subscriptions[i].ProcessId,
                                                Client->Subscriptions[i].StreamMask))
        {
            return TRUE;
        }
    }

    return FALSE;
}

static VOID ControllerClientFreeQueueLocked(_Inout_ SLEEPWALKER_CONTROLLER_CLIENT *Client)
{
    PSLEEPWALKER_CONTROLLER_EVENT_NODE node = Client->QueueHead;

    while (node != NULL)
    {
        PSLEEPWALKER_CONTROLLER_EVENT_NODE next = node->Next;
        free(node);
        node = next;
    }

    Client->QueueHead = NULL;
    Client->QueueTail = NULL;
    Client->QueueDepth = 0;
}

static VOID ControllerClientFreeEtwQueueLocked(_Inout_ SLEEPWALKER_CONTROLLER_CLIENT *Client)
{
    PSLEEPWALKER_CONTROLLER_ETW_EVENT_NODE node = Client->EtwQueueHead;

    while (node != NULL)
    {
        PSLEEPWALKER_CONTROLLER_ETW_EVENT_NODE next = node->Next;
        free(node);
        node = next;
    }

    Client->EtwQueueHead = NULL;
    Client->EtwQueueTail = NULL;
    Client->EtwQueueDepth = 0;
}

static BOOL ControllerClientEnqueueRecordLocked(_Inout_ SLEEPWALKER_CONTROLLER_CLIENT *Client,
                                                _In_ const SLEEPWALKER_EVENT_RECORD *Record)
{
    PSLEEPWALKER_CONTROLLER_EVENT_NODE node;

    if (Client->QueueDepth >= SLEEPWALKER_CONTROLLER_MAX_CLIENT_QUEUE_DEPTH)
    {
        Client->DroppedEvents += 1;
        return FALSE;
    }

    node = (PSLEEPWALKER_CONTROLLER_EVENT_NODE)calloc(1, sizeof(*node));
    if (node == NULL)
    {
        Client->DroppedEvents += 1;
        return FALSE;
    }

    (void)CopyMemory(&node->Record, Record, sizeof(node->Record));
    node->Next = NULL;
    if (Client->QueueTail == NULL)
    {
        Client->QueueHead = node;
        Client->QueueTail = node;
    }
    else
    {
        Client->QueueTail->Next = node;
        Client->QueueTail = node;
    }
    Client->QueueDepth += 1;
    return TRUE;
}

static BOOL ControllerClientDequeueRecordLocked(_Inout_ SLEEPWALKER_CONTROLLER_CLIENT *Client,
                                                _Out_ SLEEPWALKER_EVENT_RECORD *Record)
{
    PSLEEPWALKER_CONTROLLER_EVENT_NODE node;

    if (Client->QueueHead == NULL)
    {
        return FALSE;
    }

    node = Client->QueueHead;
    Client->QueueHead = node->Next;
    if (Client->QueueHead == NULL)
    {
        Client->QueueTail = NULL;
    }
    if (Client->QueueDepth > 0)
    {
        Client->QueueDepth -= 1;
    }

    (void)CopyMemory(Record, &node->Record, sizeof(*Record));
    free(node);
    return TRUE;
}

static BOOL ControllerClientEnqueueEtwEventLocked(_Inout_ SLEEPWALKER_CONTROLLER_CLIENT *Client,
                                                  _In_ const SLEEPWALKER_IPC_ETW_EVENT *Event)
{
    PSLEEPWALKER_CONTROLLER_ETW_EVENT_NODE node;

    if (Client->EtwQueueDepth >= SLEEPWALKER_CONTROLLER_MAX_CLIENT_ETW_QUEUE_DEPTH)
    {
        Client->EtwDroppedEvents += 1;
        return FALSE;
    }

    node = (PSLEEPWALKER_CONTROLLER_ETW_EVENT_NODE)calloc(1, sizeof(*node));
    if (node == NULL)
    {
        Client->EtwDroppedEvents += 1;
        return FALSE;
    }

    (void)CopyMemory(&node->Event, Event, sizeof(node->Event));
    node->Next = NULL;
    if (Client->EtwQueueTail == NULL)
    {
        Client->EtwQueueHead = node;
        Client->EtwQueueTail = node;
    }
    else
    {
        Client->EtwQueueTail->Next = node;
        Client->EtwQueueTail = node;
    }
    Client->EtwQueueDepth += 1;
    return TRUE;
}

static BOOL ControllerClientDequeueEtwEventLocked(_Inout_ SLEEPWALKER_CONTROLLER_CLIENT *Client,
                                                  _Out_ SLEEPWALKER_IPC_ETW_EVENT *Event)
{
    PSLEEPWALKER_CONTROLLER_ETW_EVENT_NODE node;

    if (Client->EtwQueueHead == NULL)
    {
        return FALSE;
    }

    node = Client->EtwQueueHead;
    Client->EtwQueueHead = node->Next;
    if (Client->EtwQueueHead == NULL)
    {
        Client->EtwQueueTail = NULL;
    }
    if (Client->EtwQueueDepth > 0)
    {
        Client->EtwQueueDepth -= 1;
    }

    (void)CopyMemory(Event, &node->Event, sizeof(*Event));
    free(node);
    return TRUE;
}

static BOOL ControllerCollectUnionPidSet(_Out_writes_(SLEEPWALKER_MAX_PID_LIST) DWORD *ProcessIds,
                                         _Out_ DWORD *ProcessCount)
{
    PSLEEPWALKER_CONTROLLER_CLIENT client;
    DWORD outCount = 0;
    ULONGLONG nowTick = GetTickCount64();

    if (ProcessIds == NULL || ProcessCount == NULL)
    {
        return FALSE;
    }

    EnterCriticalSection(&g_ClientListLock);
    for (client = g_ClientList; client != NULL; client = client->Next)
    {
        DWORD i;

        EnterCriticalSection(&client->Lock);
        (void)ControllerPruneDynamicSubscriptionsLocked(client, nowTick);
        for (i = 0; i < client->SubscriptionCount; ++i)
        {
            DWORD pid = client->Subscriptions[i].ProcessId;
            DWORD j;
            BOOL seen = FALSE;

            if (pid == 0)
            {
                continue;
            }

            for (j = 0; j < outCount; ++j)
            {
                if (ProcessIds[j] == pid)
                {
                    seen = TRUE;
                    break;
                }
            }

            if (!seen && outCount < SLEEPWALKER_MAX_PID_LIST)
            {
                ProcessIds[outCount++] = pid;
            }
        }
        LeaveCriticalSection(&client->Lock);
    }
    LeaveCriticalSection(&g_ClientListLock);

    *ProcessCount = outCount;
    return TRUE;
}

static BOOL ControllerApplyDriverSubscriptions(VOID)
{
    DWORD desiredPids[SLEEPWALKER_MAX_PID_LIST];
    DWORD desiredCount = 0;
    BOOL ok = TRUE;
    DWORD i;

    ZeroMemory(desiredPids, sizeof(desiredPids));
    if (!ControllerCollectUnionPidSet(desiredPids, &desiredCount))
    {
        return FALSE;
    }

    EnterCriticalSection(&g_DriverConfigLock);
    EnterCriticalSection(&g_DriverLock);

    if (g_DriverHandle == INVALID_HANDLE_VALUE)
    {
        SetLastError(ERROR_DEVICE_NOT_CONNECTED);
        ControllerMarkDriverSubscriptionsDirty();
        ok = FALSE;
        goto Exit;
    }

    if (desiredCount == 0)
    {
        for (i = 0; i < g_ProgrammedPidCount; ++i)
        {
            (void)SLEEPWALKERSCUnsubscribe(g_DriverHandle, g_ProgrammedPids[i]);
        }
        g_ProgrammedPidCount = 0;
        ZeroMemory(g_ProgrammedPids, sizeof(g_ProgrammedPids));
        ControllerLog("[DRIVER] subscription set cleared\n");
        goto Exit;
    }

    ok = SLEEPWALKERSCSetPids(g_DriverHandle, desiredPids, desiredCount, SLEEPWALKER_CONTROLLER_DRIVER_STREAM_MASK);
    if (ok)
    {
        g_ProgrammedPidCount = desiredCount;
        ZeroMemory(g_ProgrammedPids, sizeof(g_ProgrammedPids));
        for (i = 0; i < desiredCount; ++i)
        {
            g_ProgrammedPids[i] = desiredPids[i];
        }
        ControllerLog("[DRIVER] programmed pid subscriptions count=%lu streamMask=0x%08lX\n", desiredCount,
                      SLEEPWALKER_CONTROLLER_DRIVER_STREAM_MASK);
    }
    else
    {
        ControllerLog("[DRIVER][WARN] failed to program pid subscriptions count=%lu (%lu)\n", desiredCount,
                      GetLastError());
        ControllerMarkDriverSubscriptionsDirty();
    }

Exit:
    LeaveCriticalSection(&g_DriverLock);
    LeaveCriticalSection(&g_DriverConfigLock);
    return ok;
}

static VOID ControllerDispatchDriverRecord(_In_ const SLEEPWALKER_EVENT_RECORD *Record)
{
    PSLEEPWALKER_CONTROLLER_CLIENT client;
    DWORD sourcePid = 0;
    DWORD targetPid = 0;
    DWORD relationMask = 0;

    if (Record == NULL)
    {
        return;
    }

    if (Record->Header.Type == SleepwalkerEventTypeHandle)
    {
        sourcePid = (DWORD)Record->Data.Handle.CallerPid;
        targetPid = (DWORD)Record->Data.Handle.TargetPid;
        relationMask = SLEEPWALKER_STREAM_HANDLE;
    }
    else if (Record->Header.Type == SleepwalkerEventTypeThread)
    {
        sourcePid = (DWORD)Record->Data.Thread.CreatorPid;
        targetPid = (DWORD)Record->Data.Thread.ProcessId;
        relationMask = SLEEPWALKER_STREAM_THREAD;
    }

    ControllerExpandMonitoringGraph(sourcePid, targetPid, relationMask);

    EnterCriticalSection(&g_ClientListLock);
    for (client = g_ClientList; client != NULL; client = client->Next)
    {
        EnterCriticalSection(&client->Lock);
        if (ControllerClientHasMatchLocked(client, Record))
        {
            (void)ControllerClientEnqueueRecordLocked(client, Record);
        }
        LeaveCriticalSection(&client->Lock);
    }
    LeaveCriticalSection(&g_ClientListLock);
}
