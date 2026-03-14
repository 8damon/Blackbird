#include "../blackbird_controller_private.h"
BOOL ControllerIsValidStreamMask(_In_ DWORD StreamMask)
{
    return ((StreamMask & BLACKBIRD_CONTROLLER_DRIVER_STREAM_MASK) != 0);
}
BOOL ControllerApplyDriverSubscriptions(VOID);
static BOOL ControllerPruneDynamicSubscriptionsLocked(_Inout_ BLACKBIRD_CONTROLLER_CLIENT *Client,
                                                      _In_ ULONGLONG NowTick);
VOID ControllerMarkDriverSubscriptionsDirty(VOID)
{
    (void) InterlockedExchange(&g_DriverSubscriptionsDirty, 1);
}
BOOL ControllerApplyDriverSubscriptionsIfDirty(VOID)
{
    if (InterlockedCompareExchange(&g_DriverSubscriptionsDirty, 0, 1) == 1)
    {
        return ControllerApplyDriverSubscriptions();
    }
    return TRUE;
}
DWORD ControllerAllocateClientSlotLocked(VOID)
{
    DWORD i;

    for (i = 0; i < RTL_NUMBER_OF(g_ClientSlots); ++i)
    {
        if (g_ClientSlots[i] == NULL)
        {
            return i;
        }
    }

    return BLACKBIRD_CONTROLLER_INVALID_SLOT;
}
VOID ControllerReleaseClientSlotLocked(_In_ DWORD SlotIndex)
{
    if (SlotIndex >= RTL_NUMBER_OF(g_ClientSlots))
    {
        return;
    }

    g_ClientSlots[SlotIndex] = NULL;
}

BOOL ControllerClientRetainForDispatchLocked(_Inout_ BLACKBIRD_CONTROLLER_CLIENT *Client)
{
    if (Client == NULL || Client->Detached)
    {
        return FALSE;
    }

    if (InterlockedIncrement(&Client->DispatchRefCount) == 1)
    {
        if (Client->DispatchIdleEvent != NULL)
        {
            (void) ResetEvent(Client->DispatchIdleEvent);
        }
    }
    return TRUE;
}

VOID ControllerClientReleaseFromDispatch(_Inout_ BLACKBIRD_CONTROLLER_CLIENT *Client)
{
    LONG remaining;

    if (Client == NULL)
    {
        return;
    }

    remaining = InterlockedDecrement(&Client->DispatchRefCount);
    if (remaining <= 0)
    {
        InterlockedExchange(&Client->DispatchRefCount, 0);
        if (Client->DispatchIdleEvent != NULL)
        {
            (void) SetEvent(Client->DispatchIdleEvent);
        }
    }
}

static VOID ControllerPidMaskSetBit(_Inout_updates_(BLACKBIRD_CONTROLLER_CLIENT_MASK_DWORDS) DWORD *Mask,
                                    _In_ DWORD Bit)
{
    DWORD wordIndex;
    DWORD bitIndex;

    if (Mask == NULL || Bit >= BLACKBIRD_CONTROLLER_MAX_CLIENTS)
    {
        return;
    }

    wordIndex = Bit / 32u;
    bitIndex = Bit % 32u;
    Mask[wordIndex] |= (1u << bitIndex);
}

static LONG ControllerFindPidIndexEntryLocked(_In_ DWORD ProcessId)
{
    DWORD i;

    if (ProcessId == 0)
    {
        return -1;
    }

    for (i = 0; i < g_PidIndexCount; ++i)
    {
        if (g_PidIndex[i].ProcessId == ProcessId)
        {
            return (LONG) i;
        }
    }

    return -1;
}

static BOOL ControllerAddPidIndexSubscriptionLocked(_In_ const BLACKBIRD_CONTROLLER_CLIENT *Client,
                                                    _In_ DWORD ProcessId,
                                                    _In_ DWORD StreamMask)
{
    LONG entryIndex;
    PBLACKBIRD_CONTROLLER_PID_INDEX_ENTRY entry;

    if (Client == NULL || ProcessId == 0 || StreamMask == 0 || Client->SlotIndex >= BLACKBIRD_CONTROLLER_MAX_CLIENTS)
    {
        return FALSE;
    }

    entryIndex = ControllerFindPidIndexEntryLocked(ProcessId);
    if (entryIndex < 0)
    {
        if (g_PidIndexCount >= RTL_NUMBER_OF(g_PidIndex))
        {
            return FALSE;
        }

        entry = &g_PidIndex[g_PidIndexCount];
        ZeroMemory(entry, sizeof(*entry));
        entry->ProcessId = ProcessId;
        entry->StreamMask = StreamMask;
        ControllerPidMaskSetBit(entry->ClientMask, Client->SlotIndex);
        g_PidIndexCount += 1;
        return TRUE;
    }

    entry = &g_PidIndex[(DWORD) entryIndex];
    entry->StreamMask |= StreamMask;
    ControllerPidMaskSetBit(entry->ClientMask, Client->SlotIndex);
    return TRUE;
}
VOID ControllerRebuildPidIndexLocked(_Out_opt_ BOOL *DynamicPruned)
{
    PBLACKBIRD_CONTROLLER_CLIENT client;
    ULONGLONG nowTick = GetTickCount64();
    BOOL prunedAny = FALSE;
    DWORD droppedPidCount = 0;

    g_PidIndexCount = 0;
    ZeroMemory(g_PidIndex, sizeof(g_PidIndex));

    for (client = g_ClientList; client != NULL; client = client->Next)
    {
        DWORD i;

        EnterCriticalSection(&client->Lock);
        if (ControllerPruneDynamicSubscriptionsLocked(client, nowTick))
        {
            prunedAny = TRUE;
        }

        for (i = 0; i < client->SubscriptionCount; ++i)
        {
            const BLACKBIRD_CONTROLLER_SUBSCRIPTION *sub = &client->Subscriptions[i];
            if (sub->ProcessId == 0 || (sub->StreamMask & BLACKBIRD_CONTROLLER_DRIVER_STREAM_MASK) == 0)
            {
                continue;
            }

            if (!ControllerAddPidIndexSubscriptionLocked(client, sub->ProcessId, sub->StreamMask))
            {
                droppedPidCount += 1;
            }
        }
        LeaveCriticalSection(&client->Lock);
    }

    if (droppedPidCount != 0)
    {
        ControllerLog("[MON][WARN] pid index capacity reached, droppedSubscriptions=%lu\n", droppedPidCount);
    }
    if (DynamicPruned != NULL)
    {
        *DynamicPruned = prunedAny;
    }
}

static LONG ControllerFindSubscriptionIndexLocked(_In_ const BLACKBIRD_CONTROLLER_CLIENT *Client, _In_ DWORD ProcessId)
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
            return (LONG) i;
        }
    }

    return -1;
}
VOID ControllerRemoveSubscriptionAtLocked(_Inout_ BLACKBIRD_CONTROLLER_CLIENT *Client, _In_ DWORD Index)
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

static BOOL ControllerPruneDynamicSubscriptionsLocked(_Inout_ BLACKBIRD_CONTROLLER_CLIENT *Client,
                                                      _In_ ULONGLONG NowTick)
{
    BOOL changed = FALSE;
    DWORD i = 0;

    if (Client == NULL)
    {
        return FALSE;
    }

    while (i < Client->SubscriptionCount)
    {
        const BLACKBIRD_CONTROLLER_SUBSCRIPTION *sub = &Client->Subscriptions[i];
        if (sub->Dynamic
            && (sub->LastSeenTick == 0
                || (NowTick - sub->LastSeenTick) > (ULONGLONG) BLACKBIRD_CONTROLLER_DYNAMIC_SUBSCRIPTION_TTL_MS))
        {
            DWORD expiredPid = sub->ProcessId;
            ControllerRemoveSubscriptionAtLocked(Client, i);
            changed = TRUE;
            ControllerLog(
                    "[MON] dynamic subscription expired clientPid=%lu targetPid=%lu\n", Client->ProcessId, expiredPid);
            continue;
        }
        i += 1;
    }

    return changed;
}
BOOL ControllerDropDynamicDescendantsLocked(_Inout_ BLACKBIRD_CONTROLLER_CLIENT *Client, _In_ DWORD RootProcessId)
{
    DWORD pending[BLACKBIRD_CONTROLLER_MAX_CLIENT_SUBSCRIPTIONS];
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
            const BLACKBIRD_CONTROLLER_SUBSCRIPTION *sub = &Client->Subscriptions[i];
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
                              Client->ProcessId,
                              removedPid,
                              current);
                continue;
            }
            i += 1;
        }
    }

    return changed;
}

static BOOL ControllerTryExpandClientRelationLocked(_Inout_ BLACKBIRD_CONTROLLER_CLIENT *Client,
                                                    _In_ DWORD SourceProcessId,
                                                    _In_ DWORD TargetProcessId,
                                                    _In_ DWORD RelationStreamMask)
{
    ULONGLONG nowTick;
    LONG sourceIndex;
    LONG targetIndex;
    PBLACKBIRD_CONTROLLER_SUBSCRIPTION sourceSub;
    BOOL changed = FALSE;

    if (Client == NULL || SourceProcessId == 0 || TargetProcessId == 0 || SourceProcessId == TargetProcessId
        || RelationStreamMask == 0)
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
        PBLACKBIRD_CONTROLLER_SUBSCRIPTION targetSub = &Client->Subscriptions[targetIndex];
        const DWORD mergedMask = (targetSub->StreamMask | sourceSub->StreamMask);
        if (mergedMask != targetSub->StreamMask)
        {
            targetSub->StreamMask = mergedMask;
            changed = TRUE;
        }

        if (targetSub->Dynamic)
        {
            UINT32 candidateDepth = sourceSub->Dynamic ? (sourceSub->Depth + 1u) : 1u;
            if (candidateDepth <= BLACKBIRD_CONTROLLER_DYNAMIC_SUBSCRIPTION_MAX_DEPTH)
            {
                if (targetSub->Depth == 0 || candidateDepth < targetSub->Depth
                    || (candidateDepth == targetSub->Depth && targetSub->SourceProcessId != SourceProcessId))
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

        if (targetDepth > BLACKBIRD_CONTROLLER_DYNAMIC_SUBSCRIPTION_MAX_DEPTH
            || Client->SubscriptionCount >= BLACKBIRD_CONTROLLER_MAX_CLIENT_SUBSCRIPTIONS)
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
        ControllerLog(
                "[MON] dynamic subscription add clientPid=%lu sourcePid=%lu targetPid=%lu depth=%u mask=0x%08lX\n",
                Client->ProcessId,
                SourceProcessId,
                TargetProcessId,
                targetDepth,
                Client->Subscriptions[slot].StreamMask);
        return TRUE;
    }
}
VOID ControllerExpandMonitoringGraph(_In_ DWORD SourceProcessId,
                                     _In_ DWORD TargetProcessId,
                                     _In_ DWORD RelationStreamMask)
{
    PBLACKBIRD_CONTROLLER_CLIENT client;
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
        (void) ControllerApplyDriverSubscriptions();
    }
}

static BOOL ControllerRecordMatchesSubscription(_In_ const BLACKBIRD_EVENT_RECORD *Record,
                                                _In_ DWORD ProcessId,
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

    if (Record->Header.Type == BlackbirdEventTypeHandle)
    {
        primary = (DWORD) Record->Data.Handle.CallerPid;
        secondary = (DWORD) Record->Data.Handle.TargetPid;
    }
    else if (Record->Header.Type == BlackbirdEventTypeThread)
    {
        primary = (DWORD) Record->Data.Thread.ProcessId;
        secondary = (DWORD) Record->Data.Thread.CreatorPid;
    }
    else if (Record->Header.Type == BlackbirdEventTypeFileSystem)
    {
        primary = (DWORD) Record->Data.FileSystem.ProcessId;
        secondary = 0;
    }
    else
    {
        return FALSE;
    }

    return (ProcessId == primary || ProcessId == secondary);
}

static BOOL ControllerClientHasMatchLocked(_In_ const BLACKBIRD_CONTROLLER_CLIENT *Client,
                                           _In_ const BLACKBIRD_EVENT_RECORD *Record)
{
    DWORD i;

    for (i = 0; i < Client->SubscriptionCount; ++i)
    {
        if (ControllerRecordMatchesSubscription(
                    Record, Client->Subscriptions[i].ProcessId, Client->Subscriptions[i].StreamMask))
        {
            return TRUE;
        }
    }

    return FALSE;
}

static BOOL ControllerSharedRingPushLocked(_Inout_ volatile BLACKBIRD_IPC_SHARED_RING_HEADER *Header,
                                           _Inout_updates_bytes_(Header->Capacity * Header->RecordSize) PBYTE Records,
                                           _In_ HANDLE DataEvent,
                                           _In_reads_bytes_(RecordSize) const VOID *Record,
                                           _In_ UINT32 RecordSize)
{
    LONG writeIndex;
    LONG readIndex;
    LONG nextIndex;

    if (Header == NULL || Records == NULL || Record == NULL || DataEvent == NULL || DataEvent == INVALID_HANDLE_VALUE
        || RecordSize == 0 || Header->Capacity == 0 || Header->RecordSize != RecordSize)
    {
        return FALSE;
    }

    writeIndex = Header->WriteIndex;
    readIndex = Header->ReadIndex;
    if (writeIndex < 0 || readIndex < 0 || writeIndex >= (LONG) Header->Capacity
        || readIndex >= (LONG) Header->Capacity)
    {
        Header->WriteIndex = 0;
        Header->ReadIndex = 0;
        writeIndex = 0;
        readIndex = 0;
    }

    nextIndex = writeIndex + 1;
    if (nextIndex >= (LONG) Header->Capacity)
    {
        nextIndex = 0;
    }

    if (nextIndex == readIndex)
    {
        Header->DroppedCount += 1;
        return FALSE;
    }

    (void) CopyMemory(Records + ((SIZE_T) writeIndex * (SIZE_T) RecordSize), Record, RecordSize);
    MemoryBarrier();
    Header->WriteIndex = nextIndex;
    (void) SetEvent(DataEvent);
    return TRUE;
}

static BOOL ControllerSharedRingPopLocked(_Inout_ volatile BLACKBIRD_IPC_SHARED_RING_HEADER *Header,
                                          _In_reads_bytes_(Header->Capacity * Header->RecordSize) const BYTE *Records,
                                          _In_ HANDLE DataEvent,
                                          _Out_writes_bytes_(RecordSize) VOID *Record,
                                          _In_ UINT32 RecordSize)
{
    LONG writeIndex;
    LONG readIndex;
    LONG nextIndex;

    if (Header == NULL || Records == NULL || Record == NULL || DataEvent == NULL || DataEvent == INVALID_HANDLE_VALUE
        || RecordSize == 0 || Header->Capacity == 0 || Header->RecordSize != RecordSize)
    {
        return FALSE;
    }

    writeIndex = Header->WriteIndex;
    readIndex = Header->ReadIndex;
    if (writeIndex < 0 || readIndex < 0 || writeIndex >= (LONG) Header->Capacity
        || readIndex >= (LONG) Header->Capacity)
    {
        Header->WriteIndex = 0;
        Header->ReadIndex = 0;
        return FALSE;
    }

    if (readIndex == writeIndex)
    {
        return FALSE;
    }

    (void) CopyMemory(Record, Records + ((SIZE_T) readIndex * (SIZE_T) RecordSize), RecordSize);
    MemoryBarrier();
    nextIndex = readIndex + 1;
    if (nextIndex >= (LONG) Header->Capacity)
    {
        nextIndex = 0;
    }
    Header->ReadIndex = nextIndex;
    if (nextIndex == Header->WriteIndex)
    {
        (void) ResetEvent(DataEvent);
        MemoryBarrier();
        if (nextIndex != Header->WriteIndex)
        {
            (void) SetEvent(DataEvent);
        }
    }
    return TRUE;
}
VOID ControllerClientDestroySharedRingsLocked(_Inout_ BLACKBIRD_CONTROLLER_CLIENT *Client)
{
    if (Client == NULL)
    {
        return;
    }

    Client->SharedRingEnabled = FALSE;

    if (Client->IoctlSharedHeader != NULL)
    {
        (void) UnmapViewOfFile((PVOID) Client->IoctlSharedHeader);
        Client->IoctlSharedHeader = NULL;
    }
    if (Client->IoctlSharedMapping != NULL && Client->IoctlSharedMapping != INVALID_HANDLE_VALUE)
    {
        (void) CloseHandle(Client->IoctlSharedMapping);
        Client->IoctlSharedMapping = NULL;
    }
    if (Client->IoctlSharedDataEvent != NULL && Client->IoctlSharedDataEvent != INVALID_HANDLE_VALUE)
    {
        (void) CloseHandle(Client->IoctlSharedDataEvent);
        Client->IoctlSharedDataEvent = NULL;
    }
    Client->IoctlSharedRecords = NULL;

    if (Client->EtwSharedHeader != NULL)
    {
        (void) UnmapViewOfFile((PVOID) Client->EtwSharedHeader);
        Client->EtwSharedHeader = NULL;
    }
    if (Client->EtwSharedMapping != NULL && Client->EtwSharedMapping != INVALID_HANDLE_VALUE)
    {
        (void) CloseHandle(Client->EtwSharedMapping);
        Client->EtwSharedMapping = NULL;
    }
    if (Client->EtwSharedDataEvent != NULL && Client->EtwSharedDataEvent != INVALID_HANDLE_VALUE)
    {
        (void) CloseHandle(Client->EtwSharedDataEvent);
        Client->EtwSharedDataEvent = NULL;
    }
    Client->EtwSharedRecords = NULL;
}
VOID ControllerClientFreeQueueLocked(_Inout_ BLACKBIRD_CONTROLLER_CLIENT *Client)
{
    PBLACKBIRD_CONTROLLER_EVENT_NODE node = Client->QueueHead;

    while (node != NULL)
    {
        PBLACKBIRD_CONTROLLER_EVENT_NODE next = node->Next;
        free(node);
        node = next;
    }

    Client->QueueHead = NULL;
    Client->QueueTail = NULL;
    Client->QueueDepth = 0;
    if (Client->IoctlQueueDataEvent != NULL)
    {
        (void) ResetEvent(Client->IoctlQueueDataEvent);
    }
}
VOID ControllerClientFreeEtwQueueLocked(_Inout_ BLACKBIRD_CONTROLLER_CLIENT *Client)
{
    PBLACKBIRD_CONTROLLER_ETW_EVENT_NODE node = Client->EtwQueueHead;

    while (node != NULL)
    {
        PBLACKBIRD_CONTROLLER_ETW_EVENT_NODE next = node->Next;
        free(node);
        node = next;
    }

    Client->EtwQueueHead = NULL;
    Client->EtwQueueTail = NULL;
    Client->EtwQueueDepth = 0;
    if (Client->EtwQueueDataEvent != NULL)
    {
        (void) ResetEvent(Client->EtwQueueDataEvent);
    }
}

static BOOL ControllerClientEnqueueRecordLocked(_Inout_ BLACKBIRD_CONTROLLER_CLIENT *Client,
                                                _In_ const BLACKBIRD_EVENT_RECORD *Record)
{
    PBLACKBIRD_CONTROLLER_EVENT_NODE node;

    if (Client->SharedRingEnabled && Client->IoctlSharedHeader != NULL)
    {
        if (!ControllerSharedRingPushLocked(Client->IoctlSharedHeader,
                                            Client->IoctlSharedRecords,
                                            Client->IoctlSharedDataEvent,
                                            Record,
                                            sizeof(*Record)))
        {
            Client->DroppedEvents += 1;
            return FALSE;
        }
        return TRUE;
    }

    if (Client->QueueDepth >= BLACKBIRD_CONTROLLER_MAX_CLIENT_QUEUE_DEPTH)
    {
        Client->DroppedEvents += 1;
        return FALSE;
    }

    node = (PBLACKBIRD_CONTROLLER_EVENT_NODE) calloc(1, sizeof(*node));
    if (node == NULL)
    {
        Client->DroppedEvents += 1;
        return FALSE;
    }

    (void) CopyMemory(&node->Record, Record, sizeof(node->Record));
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
    if (Client->IoctlQueueDataEvent != NULL)
    {
        (void) SetEvent(Client->IoctlQueueDataEvent);
    }
    return TRUE;
}
BOOL ControllerClientDequeueRecordLocked(_Inout_ BLACKBIRD_CONTROLLER_CLIENT *Client,
                                         _Out_ BLACKBIRD_EVENT_RECORD *Record)
{
    PBLACKBIRD_CONTROLLER_EVENT_NODE node;

    if (Client->SharedRingEnabled && Client->IoctlSharedHeader != NULL)
    {
        return ControllerSharedRingPopLocked(Client->IoctlSharedHeader,
                                             Client->IoctlSharedRecords,
                                             Client->IoctlSharedDataEvent,
                                             Record,
                                             sizeof(*Record));
    }

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
    if (Client->QueueHead == NULL && Client->IoctlQueueDataEvent != NULL)
    {
        (void) ResetEvent(Client->IoctlQueueDataEvent);
    }

    (void) CopyMemory(Record, &node->Record, sizeof(*Record));
    free(node);
    return TRUE;
}
BOOL ControllerClientEnqueueEtwEventLocked(_Inout_ BLACKBIRD_CONTROLLER_CLIENT *Client,
                                           _In_ const BLACKBIRD_IPC_ETW_EVENT *Event)
{
    PBLACKBIRD_CONTROLLER_ETW_EVENT_NODE node;

    if (Client->SharedRingEnabled && Client->EtwSharedHeader != NULL)
    {
        if (!ControllerSharedRingPushLocked(Client->EtwSharedHeader,
                                            Client->EtwSharedRecords,
                                            Client->EtwSharedDataEvent,
                                            Event,
                                            sizeof(*Event)))
        {
            Client->EtwDroppedEvents += 1;
            return FALSE;
        }
        return TRUE;
    }

    if (Client->EtwQueueDepth >= BLACKBIRD_CONTROLLER_MAX_CLIENT_ETW_QUEUE_DEPTH)
    {
        Client->EtwDroppedEvents += 1;
        return FALSE;
    }

    node = (PBLACKBIRD_CONTROLLER_ETW_EVENT_NODE) calloc(1, sizeof(*node));
    if (node == NULL)
    {
        Client->EtwDroppedEvents += 1;
        return FALSE;
    }

    (void) CopyMemory(&node->Event, Event, sizeof(node->Event));
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
    if (Client->EtwQueueDataEvent != NULL)
    {
        (void) SetEvent(Client->EtwQueueDataEvent);
    }
    return TRUE;
}
BOOL ControllerClientDequeueEtwEventLocked(_Inout_ BLACKBIRD_CONTROLLER_CLIENT *Client,
                                           _Out_ BLACKBIRD_IPC_ETW_EVENT *Event)
{
    PBLACKBIRD_CONTROLLER_ETW_EVENT_NODE node;

    if (Client->SharedRingEnabled && Client->EtwSharedHeader != NULL)
    {
        return ControllerSharedRingPopLocked(
                Client->EtwSharedHeader, Client->EtwSharedRecords, Client->EtwSharedDataEvent, Event, sizeof(*Event));
    }

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
    if (Client->EtwQueueHead == NULL && Client->EtwQueueDataEvent != NULL)
    {
        (void) ResetEvent(Client->EtwQueueDataEvent);
    }

    (void) CopyMemory(Event, &node->Event, sizeof(*Event));
    free(node);
    return TRUE;
}

static BOOL ControllerCollectUnionPidSet(_Out_writes_(BLACKBIRD_MAX_PID_LIST) DWORD *ProcessIds,
                                         _Out_ DWORD *ProcessCount)
{
    DWORD i;

    if (ProcessIds == NULL || ProcessCount == NULL)
    {
        return FALSE;
    }

    EnterCriticalSection(&g_ClientListLock);
    ControllerRebuildPidIndexLocked(NULL);
    *ProcessCount = g_PidIndexCount;
    for (i = 0; i < g_PidIndexCount; ++i)
    {
        ProcessIds[i] = g_PidIndex[i].ProcessId;
    }
    LeaveCriticalSection(&g_ClientListLock);
    return TRUE;
}
BOOL ControllerApplyDriverSubscriptions(VOID)
{
    DWORD desiredPids[BLACKBIRD_MAX_PID_LIST];
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
            (void) BLACKBIRDSCUnsubscribe(g_DriverHandle, g_ProgrammedPids[i]);
        }
        g_ProgrammedPidCount = 0;
        ZeroMemory(g_ProgrammedPids, sizeof(g_ProgrammedPids));
        ControllerLog("[DRIVER] subscription set cleared\n");
        goto Exit;
    }

    ok = BLACKBIRDSCSetPids(g_DriverHandle, desiredPids, desiredCount, BLACKBIRD_CONTROLLER_DRIVER_STREAM_MASK);
    if (ok)
    {
        g_ProgrammedPidCount = desiredCount;
        ZeroMemory(g_ProgrammedPids, sizeof(g_ProgrammedPids));
        for (i = 0; i < desiredCount; ++i)
        {
            g_ProgrammedPids[i] = desiredPids[i];
        }
        ControllerLog("[DRIVER] programmed pid subscriptions count=%lu streamMask=0x%08lX\n",
                      desiredCount,
                      BLACKBIRD_CONTROLLER_DRIVER_STREAM_MASK);
    }
    else
    {
        ControllerLog(
                "[DRIVER][WARN] failed to program pid subscriptions count=%lu (%lu)\n", desiredCount, GetLastError());
        ControllerMarkDriverSubscriptionsDirty();
    }

Exit:
    LeaveCriticalSection(&g_DriverLock);
    LeaveCriticalSection(&g_DriverConfigLock);
    return ok;
}
VOID ControllerDispatchDriverRecord(_In_ const BLACKBIRD_EVENT_RECORD *Record)
{
    PBLACKBIRD_CONTROLLER_CLIENT client;
    PBLACKBIRD_CONTROLLER_CLIENT dispatchClients[BLACKBIRD_CONTROLLER_MAX_CLIENTS];
    DWORD dispatchCount = 0;
    DWORD sourcePid = 0;
    DWORD targetPid = 0;
    DWORD relationMask = 0;
    DWORD recordMask;
    DWORD candidateMask[BLACKBIRD_CONTROLLER_CLIENT_MASK_DWORDS];
    LONG entryIndex;
    DWORD i;
    BOOL useSlowPath;

    if (Record == NULL)
    {
        return;
    }
    recordMask = Record->Header.StreamMask;

    if (Record->Header.Type == BlackbirdEventTypeHandle)
    {
        sourcePid = (DWORD) Record->Data.Handle.CallerPid;
        targetPid = (DWORD) Record->Data.Handle.TargetPid;
        relationMask = BLACKBIRD_STREAM_HANDLE;
    }
    else if (Record->Header.Type == BlackbirdEventTypeThread)
    {
        sourcePid = (DWORD) Record->Data.Thread.CreatorPid;
        targetPid = (DWORD) Record->Data.Thread.ProcessId;
        relationMask = BLACKBIRD_STREAM_THREAD;
    }
    else if (Record->Header.Type == BlackbirdEventTypeFileSystem)
    {
        sourcePid = (DWORD) Record->Data.FileSystem.ProcessId;
        targetPid = 0;
        relationMask = 0;
    }

    ControllerExpandMonitoringGraph(sourcePid, targetPid, relationMask);

    useSlowPath = (InterlockedCompareExchange(&g_DriverSubscriptionsDirty, 0, 0) != 0);
    EnterCriticalSection(&g_ClientListLock);
    if (useSlowPath)
    {
        for (client = g_ClientList; client != NULL && dispatchCount < RTL_NUMBER_OF(dispatchClients);
             client = client->Next)
        {
            if (ControllerClientRetainForDispatchLocked(client))
            {
                dispatchClients[dispatchCount++] = client;
            }
        }
        LeaveCriticalSection(&g_ClientListLock);
    }
    else
    {
        ZeroMemory(candidateMask, sizeof(candidateMask));
        if (sourcePid != 0)
        {
            entryIndex = ControllerFindPidIndexEntryLocked(sourcePid);
            if (entryIndex >= 0 && (g_PidIndex[(DWORD) entryIndex].StreamMask & recordMask) != 0)
            {
                for (i = 0; i < RTL_NUMBER_OF(candidateMask); ++i)
                {
                    candidateMask[i] |= g_PidIndex[(DWORD) entryIndex].ClientMask[i];
                }
            }
        }
        if (targetPid != 0 && targetPid != sourcePid)
        {
            entryIndex = ControllerFindPidIndexEntryLocked(targetPid);
            if (entryIndex >= 0 && (g_PidIndex[(DWORD) entryIndex].StreamMask & recordMask) != 0)
            {
                for (i = 0; i < RTL_NUMBER_OF(candidateMask); ++i)
                {
                    candidateMask[i] |= g_PidIndex[(DWORD) entryIndex].ClientMask[i];
                }
            }
        }

        for (i = 0; i < RTL_NUMBER_OF(g_ClientSlots) && dispatchCount < RTL_NUMBER_OF(dispatchClients); ++i)
        {
            DWORD wordIndex = i / 32u;
            DWORD bitMask = (1u << (i % 32u));

            if ((candidateMask[wordIndex] & bitMask) == 0)
            {
                continue;
            }

            client = g_ClientSlots[i];
            if (client == NULL)
            {
                continue;
            }

            if (ControllerClientRetainForDispatchLocked(client))
            {
                dispatchClients[dispatchCount++] = client;
            }
        }
        LeaveCriticalSection(&g_ClientListLock);
    }

    for (i = 0; i < dispatchCount; ++i)
    {
        client = dispatchClients[i];
        EnterCriticalSection(&client->Lock);
        if (ControllerClientHasMatchLocked(client, Record))
        {
            (void) ControllerClientEnqueueRecordLocked(client, Record);
        }
        LeaveCriticalSection(&client->Lock);
        ControllerClientReleaseFromDispatch(client);
    }
}
