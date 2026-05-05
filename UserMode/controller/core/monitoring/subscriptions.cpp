#include "../controller_private.h"

static volatile LONG g_PidIndexDirty = 1;
static HANDLE g_DriverSubscriptionApplyEvent = NULL;
static HANDLE g_DriverSubscriptionApplyCompleteEvent = NULL;
static HANDLE g_DriverSubscriptionApplyThread = NULL;
static volatile LONG g_DriverSubscriptionApplyGeneration = 0;
static volatile LONG g_DriverSubscriptionAppliedGeneration = 0;
static volatile LONG g_DriverSubscriptionApplyLastError = ERROR_SUCCESS;
static volatile LONG g_DriverSubscriptionApplyPhase = 0;
static volatile LONG g_DriverSubscriptionApplyThreadId = 0;
static volatile LONG g_DriverSubscriptionApplyDesiredCount = 0;
static volatile LONG g_DriverSubscriptionApplyProgrammedCount = 0;
static volatile LONG g_DriverSubscriptionApplyIoctlCount = 0;
static volatile LONG64 g_DriverSubscriptionApplyPhaseTick = 0;

typedef enum _BK_CONTROLLER_DRIVER_SUBSCRIPTION_APPLY_PHASE
{
    BkControllerDriverSubscriptionApplyIdle = 0,
    BkControllerDriverSubscriptionApplyWaiting,
    BkControllerDriverSubscriptionApplyCollecting,
    BkControllerDriverSubscriptionApplySnapshotting,
    BkControllerDriverSubscriptionApplyIoctlClear,
    BkControllerDriverSubscriptionApplyIoctlProgram,
    BkControllerDriverSubscriptionApplyUpdating,
    BkControllerDriverSubscriptionApplyStopping
} BK_CONTROLLER_DRIVER_SUBSCRIPTION_APPLY_PHASE;

static PCSTR ControllerDriverSubscriptionApplyPhaseName(_In_ LONG Phase)
{
    switch ((BK_CONTROLLER_DRIVER_SUBSCRIPTION_APPLY_PHASE)Phase)
    {
    case BkControllerDriverSubscriptionApplyIdle:
        return "idle";
    case BkControllerDriverSubscriptionApplyWaiting:
        return "waiting";
    case BkControllerDriverSubscriptionApplyCollecting:
        return "collecting";
    case BkControllerDriverSubscriptionApplySnapshotting:
        return "snapshotting";
    case BkControllerDriverSubscriptionApplyIoctlClear:
        return "ioctl-clear";
    case BkControllerDriverSubscriptionApplyIoctlProgram:
        return "ioctl-program";
    case BkControllerDriverSubscriptionApplyUpdating:
        return "updating";
    case BkControllerDriverSubscriptionApplyStopping:
        return "stopping";
    default:
        return "unknown";
    }
}

static VOID ControllerSetDriverSubscriptionApplyPhase(_In_ BK_CONTROLLER_DRIVER_SUBSCRIPTION_APPLY_PHASE Phase,
                                                      _In_ DWORD DesiredCount, _In_ DWORD ProgrammedCount,
                                                      _In_ DWORD IoctlCount)
{
    (void)InterlockedExchange(&g_DriverSubscriptionApplyDesiredCount, (LONG)DesiredCount);
    (void)InterlockedExchange(&g_DriverSubscriptionApplyProgrammedCount, (LONG)ProgrammedCount);
    (void)InterlockedExchange(&g_DriverSubscriptionApplyIoctlCount, (LONG)IoctlCount);
    (void)InterlockedExchange64(&g_DriverSubscriptionApplyPhaseTick, (LONG64)GetTickCount64());
    (void)InterlockedExchange(&g_DriverSubscriptionApplyPhase, (LONG)Phase);
}

static VOID ControllerLogDriverSubscriptionApplyState(_In_z_ PCSTR Prefix)
{
    LONG phase = InterlockedCompareExchange(&g_DriverSubscriptionApplyPhase, 0, 0);
    LONG64 phaseTick = InterlockedCompareExchange64(&g_DriverSubscriptionApplyPhaseTick, 0, 0);
    ULONGLONG nowTick = GetTickCount64();
    ULONGLONG elapsedMs = (phaseTick > 0 && nowTick >= (ULONGLONG)phaseTick) ? nowTick - (ULONGLONG)phaseTick : 0;

    ControllerLog(
        "[DRIVER][WARN] %s phase=%s phaseId=%ld elapsedMs=%llu workerTid=%lu dirty=%ld generation=%ld appliedGeneration=%ld lastErr=%ld desired=%ld programmed=%ld ioctlCount=%ld stop=%u\n",
        Prefix, ControllerDriverSubscriptionApplyPhaseName(phase), phase, (unsigned long long)elapsedMs,
        (DWORD)InterlockedCompareExchange(&g_DriverSubscriptionApplyThreadId, 0, 0),
        InterlockedCompareExchange(&g_DriverSubscriptionsDirty, 0, 0),
        InterlockedCompareExchange(&g_DriverSubscriptionApplyGeneration, 0, 0),
        InterlockedCompareExchange(&g_DriverSubscriptionAppliedGeneration, 0, 0),
        InterlockedCompareExchange(&g_DriverSubscriptionApplyLastError, 0, 0),
        InterlockedCompareExchange(&g_DriverSubscriptionApplyDesiredCount, 0, 0),
        InterlockedCompareExchange(&g_DriverSubscriptionApplyProgrammedCount, 0, 0),
        InterlockedCompareExchange(&g_DriverSubscriptionApplyIoctlCount, 0, 0), ControllerShouldStop() ? 1u : 0u);
}

BOOL ControllerIsValidStreamMask(_In_ DWORD StreamMask)
{
    return ((StreamMask & BK_CONTROLLER_DRIVER_STREAM_MASK) != 0);
}
static BOOL ControllerApplyDriverSubscriptionsNow(VOID);
static BOOL ControllerPruneDynamicSubscriptionsLocked(_Inout_ BK_CONTROLLER_CLIENT *Client, _In_ ULONGLONG NowTick);
static BOOL ControllerApplyDriverSubscriptionsIfDirtyNow(VOID);
static VOID ControllerKeepDriverSubscriptionsDirty(VOID)
{
    (void)InterlockedExchange(&g_DriverSubscriptionsDirty, 1);
    (void)InterlockedExchange(&g_PidIndexDirty, 1);
}

static VOID ControllerSignalDriverSubscriptionWorker(VOID)
{
    HANDLE applyEvent = g_DriverSubscriptionApplyEvent;
    if (applyEvent != NULL)
    {
        (void)SetEvent(applyEvent);
    }
}

VOID ControllerMarkDriverSubscriptionsDirty(VOID)
{
    (void)InterlockedExchange(&g_DriverSubscriptionsDirty, 1);
    (void)InterlockedExchange(&g_PidIndexDirty, 1);
    (void)InterlockedIncrement(&g_DriverSubscriptionApplyGeneration);
    if (g_DriverSubscriptionApplyCompleteEvent != NULL)
    {
        (void)ResetEvent(g_DriverSubscriptionApplyCompleteEvent);
    }
    ControllerSignalDriverSubscriptionWorker();
}

static DWORD WINAPI ControllerDriverSubscriptionWorkerThreadProc(_In_ LPVOID Context)
{
    UNREFERENCED_PARAMETER(Context);

    (void)InterlockedExchange(&g_DriverSubscriptionApplyThreadId, (LONG)GetCurrentThreadId());
    for (;;)
    {
        HANDLE waits[2];
        DWORD waitCount = 0;
        DWORD waitResult;

        if (g_StopEvent != NULL)
        {
            waits[waitCount++] = g_StopEvent;
        }
        if (g_DriverSubscriptionApplyEvent != NULL)
        {
            waits[waitCount++] = g_DriverSubscriptionApplyEvent;
        }
        if (waitCount == 0)
        {
            Sleep(100);
            if (ControllerShouldStop())
            {
                break;
            }
            continue;
        }

        ControllerSetDriverSubscriptionApplyPhase(BkControllerDriverSubscriptionApplyWaiting, 0, 0, 0);
        waitResult = WaitForMultipleObjects(waitCount, waits, FALSE, 250);
        if (ControllerShouldStop() || (g_StopEvent != NULL && waitResult == WAIT_OBJECT_0))
        {
            break;
        }

        while (!ControllerShouldStop() && InterlockedCompareExchange(&g_DriverSubscriptionsDirty, 0, 0) != 0)
        {
            LONG requestedGeneration;
            BOOL ok;

            ok = ControllerApplyDriverSubscriptionsIfDirtyNow();
            requestedGeneration = InterlockedCompareExchange(&g_DriverSubscriptionApplyGeneration, 0, 0);
            if (ok)
            {
                InterlockedExchange(&g_DriverSubscriptionApplyLastError, ERROR_SUCCESS);
                InterlockedExchange(&g_DriverSubscriptionAppliedGeneration, requestedGeneration);
                if (g_DriverSubscriptionApplyCompleteEvent != NULL)
                {
                    (void)SetEvent(g_DriverSubscriptionApplyCompleteEvent);
                }
            }
            else
            {
                DWORD err = GetLastError();
                if (err == ERROR_SUCCESS)
                {
                    err = ERROR_GEN_FAILURE;
                }
                InterlockedExchange(&g_DriverSubscriptionApplyLastError, (LONG)err);
                Sleep(100);
                break;
            }
        }
    }

    ControllerSetDriverSubscriptionApplyPhase(BkControllerDriverSubscriptionApplyIdle, 0, 0, 0);
    (void)InterlockedExchange(&g_DriverSubscriptionApplyThreadId, 0);
    return 0;
}

BOOL ControllerStartDriverSubscriptionWorker(VOID)
{
    if (g_DriverSubscriptionApplyThread != NULL)
    {
        return TRUE;
    }

    if (g_DriverSubscriptionApplyEvent == NULL)
    {
        g_DriverSubscriptionApplyEvent = CreateEventW(NULL, FALSE, FALSE, NULL);
        if (g_DriverSubscriptionApplyEvent == NULL)
        {
            return FALSE;
        }
    }
    if (g_DriverSubscriptionApplyCompleteEvent == NULL)
    {
        g_DriverSubscriptionApplyCompleteEvent = CreateEventW(NULL, TRUE, TRUE, NULL);
        if (g_DriverSubscriptionApplyCompleteEvent == NULL)
        {
            return FALSE;
        }
    }

    g_DriverSubscriptionApplyThread =
        CreateThread(NULL, 0, ControllerDriverSubscriptionWorkerThreadProc, NULL, 0, NULL);
    if (g_DriverSubscriptionApplyThread == NULL)
    {
        return FALSE;
    }

    ControllerLog("[DRIVER] subscription apply worker started\n");
    ControllerSignalDriverSubscriptionWorker();
    return TRUE;
}

VOID ControllerStopDriverSubscriptionWorker(VOID)
{
    if (g_DriverSubscriptionApplyEvent != NULL)
    {
        (void)SetEvent(g_DriverSubscriptionApplyEvent);
    }
    if (g_DriverSubscriptionApplyThread != NULL)
    {
        DWORD wait = WaitForSingleObject(g_DriverSubscriptionApplyThread, 3000);
        if (wait == WAIT_TIMEOUT)
        {
            ControllerLogDriverSubscriptionApplyState("subscription apply worker did not stop within timeout");
        }
        CloseHandle(g_DriverSubscriptionApplyThread);
        g_DriverSubscriptionApplyThread = NULL;
    }
    if (g_DriverSubscriptionApplyCompleteEvent != NULL)
    {
        CloseHandle(g_DriverSubscriptionApplyCompleteEvent);
        g_DriverSubscriptionApplyCompleteEvent = NULL;
    }
    if (g_DriverSubscriptionApplyEvent != NULL)
    {
        CloseHandle(g_DriverSubscriptionApplyEvent);
        g_DriverSubscriptionApplyEvent = NULL;
    }
}

BOOL ControllerRequestDriverSubscriptionApply(_In_ BOOL WaitForCompletion, _In_ DWORD TimeoutMs)
{
    LONG requestedGeneration;
    ULONGLONG deadline;

    ControllerMarkDriverSubscriptionsDirty();
    if (!WaitForCompletion || ControllerShouldStop())
    {
        return TRUE;
    }

    if (g_DriverSubscriptionApplyThread == NULL || g_DriverSubscriptionApplyCompleteEvent == NULL)
    {
        SetLastError(ERROR_SERVICE_NOT_ACTIVE);
        return FALSE;
    }

    requestedGeneration = InterlockedCompareExchange(&g_DriverSubscriptionApplyGeneration, 0, 0);
    deadline = GetTickCount64() + TimeoutMs;
    for (;;)
    {
        LONG appliedGeneration = InterlockedCompareExchange(&g_DriverSubscriptionAppliedGeneration, 0, 0);
        if (appliedGeneration >= requestedGeneration &&
            InterlockedCompareExchange(&g_DriverSubscriptionsDirty, 0, 0) == 0)
        {
            return TRUE;
        }

        ULONGLONG now = GetTickCount64();
        if (now >= deadline)
        {
            DWORD lastApplyError = (DWORD)InterlockedCompareExchange(&g_DriverSubscriptionApplyLastError, 0, 0);
            ControllerLogDriverSubscriptionApplyState("subscription apply wait timed out");
            SetLastError(lastApplyError == ERROR_SUCCESS ? ERROR_TIMEOUT : lastApplyError);
            return FALSE;
        }

        ULONGLONG remainingTicks = deadline - now;
        DWORD remaining = (DWORD)(remainingTicks > 250 ? 250 : remainingTicks);
        DWORD wait = WaitForSingleObject(g_DriverSubscriptionApplyCompleteEvent, remaining);
        if (wait == WAIT_FAILED)
        {
            return FALSE;
        }
    }
}

BOOL ControllerApplyDriverSubscriptionsIfDirty(VOID)
{
    if (InterlockedCompareExchange(&g_DriverSubscriptionsDirty, 0, 0) == 1)
    {
        ControllerSignalDriverSubscriptionWorker();
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

    return BK_CONTROLLER_INVALID_SLOT;
}
VOID ControllerReleaseClientSlotLocked(_In_ DWORD SlotIndex)
{
    if (SlotIndex >= RTL_NUMBER_OF(g_ClientSlots))
    {
        return;
    }

    g_ClientSlots[SlotIndex] = NULL;
}

BOOL ControllerClientRetainForDispatchLocked(_Inout_ BK_CONTROLLER_CLIENT *Client)
{
    if (Client == NULL || Client->Detached)
    {
        return FALSE;
    }

    if (InterlockedIncrement(&Client->DispatchRefCount) == 1)
    {
        if (Client->DispatchIdleEvent != NULL)
        {
            (void)ResetEvent(Client->DispatchIdleEvent);
        }
    }
    return TRUE;
}

VOID ControllerClientReleaseFromDispatch(_Inout_ BK_CONTROLLER_CLIENT *Client)
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
            (void)SetEvent(Client->DispatchIdleEvent);
        }
    }
}

static VOID ControllerPidMaskSetBit(_Inout_updates_(BK_CONTROLLER_CLIENT_MASK_DWORDS) DWORD *Mask, _In_ DWORD Bit)
{
    DWORD wordIndex;
    DWORD bitIndex;

    if (Mask == NULL || Bit >= BK_CONTROLLER_MAX_CLIENTS)
    {
        return;
    }

    wordIndex = Bit / 32u;
    bitIndex = Bit % 32u;
    Mask[wordIndex] |= (1u << bitIndex);
}

static LONG ControllerFindPidIndexEntryLocked(_In_ DWORD ProcessId)
{
    LONG lo = 0;
    LONG hi = (LONG)g_PidIndexCount - 1;

    if (ProcessId == 0)
    {
        return -1;
    }

    while (lo <= hi)
    {
        LONG mid = lo + ((hi - lo) / 2);
        DWORD midPid = g_PidIndex[(DWORD)mid].ProcessId;

        if (midPid == ProcessId)
        {
            return mid;
        }
        if (midPid < ProcessId)
        {
            lo = mid + 1;
        }
        else
        {
            hi = mid - 1;
        }
    }

    return -1;
}

static LONG ControllerFindPidIndexEntryLinearLocked(_In_ DWORD ProcessId)
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
            return (LONG)i;
        }
    }

    return -1;
}

static int __cdecl ControllerComparePidIndexEntry(_In_ const void *Left, _In_ const void *Right)
{
    const BK_CONTROLLER_PID_INDEX_ENTRY *left = (const BK_CONTROLLER_PID_INDEX_ENTRY *)Left;
    const BK_CONTROLLER_PID_INDEX_ENTRY *right = (const BK_CONTROLLER_PID_INDEX_ENTRY *)Right;

    if (left->ProcessId < right->ProcessId)
    {
        return -1;
    }
    if (left->ProcessId > right->ProcessId)
    {
        return 1;
    }
    return 0;
}

static BOOL ControllerAddPidIndexSubscriptionLocked(_In_ const BK_CONTROLLER_CLIENT *Client, _In_ DWORD ProcessId,
                                                    _In_ DWORD StreamMask)
{
    LONG entryIndex;
    PBK_CONTROLLER_PID_INDEX_ENTRY entry;

    if (Client == NULL || ProcessId == 0 || StreamMask == 0 || Client->SlotIndex >= BK_CONTROLLER_MAX_CLIENTS)
    {
        return FALSE;
    }

    entryIndex = ControllerFindPidIndexEntryLinearLocked(ProcessId);
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
        entry->ClientStreamMask[Client->SlotIndex] = StreamMask;
        g_PidIndexCount += 1;
        return TRUE;
    }

    entry = &g_PidIndex[(DWORD)entryIndex];
    entry->StreamMask |= StreamMask;
    ControllerPidMaskSetBit(entry->ClientMask, Client->SlotIndex);
    entry->ClientStreamMask[Client->SlotIndex] |= StreamMask;
    return TRUE;
}
VOID ControllerRebuildPidIndexLocked(_Out_opt_ BOOL *DynamicPruned)
{
    PBK_CONTROLLER_CLIENT client;
    ULONGLONG nowTick = GetTickCount64();
    BOOL prunedAny = FALSE;
    DWORD droppedPidCount = 0;

    if (BK_CONTROLLER_DYNAMIC_SUBSCRIPTION_TTL_MS != 0u)
    {
        static volatile LONG s_LastPruneTickLow = 0;
        DWORD nowLow = (DWORD)GetTickCount64();
        DWORD lastLow = (DWORD)InterlockedCompareExchange(&s_LastPruneTickLow, 0, 0);
        if ((DWORD)(nowLow - lastLow) >= (BK_CONTROLLER_DYNAMIC_SUBSCRIPTION_TTL_MS / 4))
        {
            (void)InterlockedExchange(&s_LastPruneTickLow, nowLow);
            (void)InterlockedExchange(&g_PidIndexDirty, 1);
        }
    }

    if (InterlockedCompareExchange(&g_PidIndexDirty, 0, 1) == 0)
    {
        if (DynamicPruned != NULL)
        {
            *DynamicPruned = FALSE;
        }
        return;
    }

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
            const BK_CONTROLLER_SUBSCRIPTION *sub = &client->Subscriptions[i];
            if (sub->ProcessId == 0 || (sub->StreamMask & BK_CONTROLLER_DRIVER_STREAM_MASK) == 0)
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
    if (g_PidIndexCount > 1)
    {
        qsort(g_PidIndex, g_PidIndexCount, sizeof(g_PidIndex[0]), ControllerComparePidIndexEntry);
    }
    if (DynamicPruned != NULL)
    {
        *DynamicPruned = prunedAny;
    }
}

static LONG ControllerFindSubscriptionIndexLocked(_In_ const BK_CONTROLLER_CLIENT *Client, _In_ DWORD ProcessId)
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
VOID ControllerRemoveSubscriptionAtLocked(_Inout_ BK_CONTROLLER_CLIENT *Client, _In_ DWORD Index)
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

static BOOL ControllerPruneDynamicSubscriptionsLocked(_Inout_ BK_CONTROLLER_CLIENT *Client, _In_ ULONGLONG NowTick)
{
    BOOL changed = FALSE;
    DWORD i = 0;

    if (Client == NULL)
    {
        return FALSE;
    }

    while (i < Client->SubscriptionCount)
    {
        const BK_CONTROLLER_SUBSCRIPTION *sub = &Client->Subscriptions[i];
        if (sub->Dynamic && BK_CONTROLLER_DYNAMIC_SUBSCRIPTION_TTL_MS != 0u &&
            (sub->LastSeenTick == 0 ||
             (NowTick - sub->LastSeenTick) > (ULONGLONG)BK_CONTROLLER_DYNAMIC_SUBSCRIPTION_TTL_MS))
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
BOOL ControllerDropDynamicDescendantsLocked(_Inout_ BK_CONTROLLER_CLIENT *Client, _In_ DWORD RootProcessId)
{
    DWORD pending[BK_CONTROLLER_MAX_CLIENT_SUBSCRIPTIONS];
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
            const BK_CONTROLLER_SUBSCRIPTION *sub = &Client->Subscriptions[i];
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

BOOL ControllerDropProcessSubscriptions(_In_ DWORD ProcessId, _In_z_ PCSTR Reason)
{
    PBK_CONTROLLER_CLIENT client;
    BOOL changed = FALSE;
    PCSTR reason = (Reason != NULL && Reason[0] != '\0') ? Reason : "process-cleanup";

    if (ProcessId == 0)
    {
        return FALSE;
    }

    EnterCriticalSection(g_ClientListLock.get());
    for (client = g_ClientList; client != NULL; client = client->Next)
    {
        BOOL clientChanged = FALSE;
        DWORD i = 0;

        EnterCriticalSection(&client->Lock);
        clientChanged |= ControllerDropDynamicDescendantsLocked(client, ProcessId);
        while (i < client->SubscriptionCount)
        {
            if (client->Subscriptions[i].ProcessId == ProcessId)
            {
                ControllerRemoveSubscriptionAtLocked(client, i);
                clientChanged = TRUE;
                ControllerLog("[MON] subscription removed clientPid=%lu targetPid=%lu reason=%s\n", client->ProcessId,
                              ProcessId, reason);
                continue;
            }
            i += 1;
        }

        if (client->PendingLaunchPid == ProcessId)
        {
            client->PendingLaunchPid = 0;
            client->PendingLaunchArmed = FALSE;
            client->PendingAnalysisSubjectKind = BlackbirdAnalysisSubjectProcess;
            client->PendingLaunchArmedTick = 0;
            client->PendingLaunchImagePath[0] = L'\0';
            client->PendingAnalysisSubjectPath[0] = L'\0';
        }
        if (client->AnalysisRootProcessId == ProcessId)
        {
            ControllerLog("[MON] analysis session ended clientPid=%lu sessionId=%llu rootPid=%lu reason=%s\n",
                          client->ProcessId, (unsigned long long)client->AnalysisSessionId, ProcessId, reason);
            client->AnalysisSessionId = 0;
            client->AnalysisRootProcessId = 0;
            client->AnalysisLaunchOwned = FALSE;
            client->AnalysisActive = FALSE;
            client->AnalysisStartedTick = 0;
        }
        if (client->Role == BkctlrClientRoleHook && client->ProcessId == ProcessId && client->OwnedRangeCount != 0)
        {
            client->OwnedRangeCount = 0;
            ZeroMemory(client->OwnedRanges, sizeof(client->OwnedRanges));
        }
        LeaveCriticalSection(&client->Lock);

        changed |= clientChanged;
    }

    if (changed)
    {
        ControllerMarkDriverSubscriptionsDirty();
    }
    LeaveCriticalSection(g_ClientListLock.get());

    if (changed)
    {
        (void)ControllerRequestDriverSubscriptionApply(FALSE, 0);
    }
    return changed;
}

static BOOL ControllerTryExpandClientRelationLocked(_Inout_ BK_CONTROLLER_CLIENT *Client, _In_ DWORD SourceProcessId,
                                                    _In_ DWORD TargetProcessId, _In_ DWORD RelationStreamMask)
{
    ULONGLONG nowTick;
    LONG sourceIndex;
    LONG targetIndex;
    PBK_CONTROLLER_SUBSCRIPTION sourceSub;
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
        PBK_CONTROLLER_SUBSCRIPTION targetSub = &Client->Subscriptions[targetIndex];
        const DWORD mergedMask = (targetSub->StreamMask | sourceSub->StreamMask);
        if (mergedMask != targetSub->StreamMask)
        {
            targetSub->StreamMask = mergedMask;
            changed = TRUE;
        }

        if (targetSub->Dynamic)
        {
            UINT32 candidateDepth = sourceSub->Dynamic ? (sourceSub->Depth + 1u) : 1u;
            if (BK_CONTROLLER_DYNAMIC_SUBSCRIPTION_MAX_DEPTH == 0xFFFFFFFFu ||
                candidateDepth <= BK_CONTROLLER_DYNAMIC_SUBSCRIPTION_MAX_DEPTH)
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

        if ((BK_CONTROLLER_DYNAMIC_SUBSCRIPTION_MAX_DEPTH != 0xFFFFFFFFu &&
             targetDepth > BK_CONTROLLER_DYNAMIC_SUBSCRIPTION_MAX_DEPTH) ||
            Client->SubscriptionCount >= BK_CONTROLLER_MAX_CLIENT_SUBSCRIPTIONS)
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
            Client->ProcessId, SourceProcessId, TargetProcessId, targetDepth, Client->Subscriptions[slot].StreamMask);
        return TRUE;
    }
}
VOID ControllerExpandMonitoringGraph(_In_ DWORD SourceProcessId, _In_ DWORD TargetProcessId,
                                     _In_ DWORD RelationStreamMask)
{
    PBK_CONTROLLER_CLIENT snapshot[BK_CONTROLLER_MAX_CLIENTS];
    DWORD snapshotCount = 0;
    DWORD i;
    PBK_CONTROLLER_CLIENT client;
    BOOL changed = FALSE;

    if (SourceProcessId == 0 || TargetProcessId == 0 || SourceProcessId == TargetProcessId || RelationStreamMask == 0)
    {
        return;
    }

    EnterCriticalSection(g_ClientListLock.get());
    for (client = g_ClientList; client != NULL && snapshotCount < RTL_NUMBER_OF(snapshot); client = client->Next)
    {
        if (ControllerClientRetainForDispatchLocked(client))
        {
            snapshot[snapshotCount++] = client;
        }
    }
    LeaveCriticalSection(g_ClientListLock.get());

    for (i = 0; i < snapshotCount; ++i)
    {
        client = snapshot[i];
        EnterCriticalSection(&client->Lock);
        if (ControllerTryExpandClientRelationLocked(client, SourceProcessId, TargetProcessId, RelationStreamMask))
        {
            changed = TRUE;
        }
        LeaveCriticalSection(&client->Lock);
        ControllerClientReleaseFromDispatch(client);
    }

    if (changed)
    {
        (void)ControllerRequestDriverSubscriptionApply(FALSE, 0);
    }
}

static BOOL ControllerRecordMatchesSubscription(_In_ const BK_EVENT_RECORD *Record, _In_ DWORD ProcessId,
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
        primary = (DWORD)Record->Data.Handle.CallerPid;
        secondary = (DWORD)Record->Data.Handle.TargetPid;
    }
    else if (Record->Header.Type == BlackbirdEventTypeThread)
    {
        primary = (DWORD)Record->Data.Thread.ProcessId;
        secondary = (DWORD)Record->Data.Thread.CreatorPid;
    }
    else if (Record->Header.Type == BlackbirdEventTypeFileSystem)
    {
        primary = (DWORD)Record->Data.FileSystem.ProcessId;
        secondary = 0;
    }
    else if (Record->Header.Type == BlackbirdEventTypeRegistry)
    {
        primary = (DWORD)Record->Data.Registry.ProcessId;
        secondary = 0;
    }
    else if (Record->Header.Type == BlackbirdEventTypeEnterprise)
    {
        primary = (DWORD)Record->Data.Enterprise.ProcessId;
        secondary = (DWORD)Record->Data.Enterprise.TargetProcessId;
    }
    else
    {
        return FALSE;
    }

    return (ProcessId == primary || ProcessId == secondary);
}

static BOOL ControllerClientHasMatchLocked(_In_ const BK_CONTROLLER_CLIENT *Client, _In_ const BK_EVENT_RECORD *Record)
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

static BOOL ControllerSharedRingPushLocked(_Inout_ volatile BKIPC_SHARED_RING_HEADER *Header,
                                           _Inout_updates_bytes_(Header->Capacity * Header->RecordSize) PBYTE Records,
                                           _In_ HANDLE DataEvent, _In_reads_bytes_(RecordSize) const VOID *Record,
                                           _In_ UINT32 RecordSize)
{
    LONG writeIndex;
    LONG readIndex;
    LONG nextIndex;

    if (Header == NULL || Records == NULL || Record == NULL || DataEvent == NULL || DataEvent == INVALID_HANDLE_VALUE ||
        RecordSize == 0 || Header->Capacity == 0 || Header->RecordSize != RecordSize)
    {
        return FALSE;
    }

    writeIndex = Header->WriteIndex;
    readIndex = Header->ReadIndex;
    if (writeIndex < 0 || readIndex < 0 || writeIndex >= (LONG)Header->Capacity || readIndex >= (LONG)Header->Capacity)
    {
        Header->WriteIndex = 0;
        Header->ReadIndex = 0;
        writeIndex = 0;
        readIndex = 0;
    }

    nextIndex = writeIndex + 1;
    if (nextIndex >= (LONG)Header->Capacity)
    {
        nextIndex = 0;
    }

    if (nextIndex == readIndex)
    {
        Header->DroppedCount += 1;
        return FALSE;
    }

    (void)CopyMemory(Records + ((SIZE_T)writeIndex * (SIZE_T)RecordSize), Record, RecordSize);
    MemoryBarrier();
    Header->WriteIndex = nextIndex;
    if (writeIndex == readIndex)
    {
        (void)SetEvent(DataEvent);
    }
    return TRUE;
}

static BOOL ControllerSharedRingPopLocked(_Inout_ volatile BKIPC_SHARED_RING_HEADER *Header,
                                          _In_reads_bytes_(Header->Capacity * Header->RecordSize) const BYTE *Records,
                                          _In_ HANDLE DataEvent, _Out_writes_bytes_(RecordSize) VOID *Record,
                                          _In_ UINT32 RecordSize)
{
    LONG writeIndex;
    LONG readIndex;
    LONG nextIndex;

    if (Header == NULL || Records == NULL || Record == NULL || DataEvent == NULL || DataEvent == INVALID_HANDLE_VALUE ||
        RecordSize == 0 || Header->Capacity == 0 || Header->RecordSize != RecordSize)
    {
        return FALSE;
    }

    writeIndex = Header->WriteIndex;
    readIndex = Header->ReadIndex;
    if (writeIndex < 0 || readIndex < 0 || writeIndex >= (LONG)Header->Capacity || readIndex >= (LONG)Header->Capacity)
    {
        Header->WriteIndex = 0;
        Header->ReadIndex = 0;
        return FALSE;
    }

    if (readIndex == writeIndex)
    {
        return FALSE;
    }

    (void)CopyMemory(Record, Records + ((SIZE_T)readIndex * (SIZE_T)RecordSize), RecordSize);
    MemoryBarrier();
    nextIndex = readIndex + 1;
    if (nextIndex >= (LONG)Header->Capacity)
    {
        nextIndex = 0;
    }
    Header->ReadIndex = nextIndex;
    if (nextIndex == Header->WriteIndex)
    {
        (void)ResetEvent(DataEvent);
        MemoryBarrier();
        if (nextIndex != Header->WriteIndex)
        {
            (void)SetEvent(DataEvent);
        }
    }
    return TRUE;
}
VOID ControllerClientDestroySharedRingsLocked(_Inout_ BK_CONTROLLER_CLIENT *Client)
{
    if (Client == NULL)
    {
        return;
    }

    Client->SharedRingEnabled = FALSE;

    if (Client->IoctlSharedHeader != NULL)
    {
        (void)UnmapViewOfFile((PVOID)Client->IoctlSharedHeader);
        Client->IoctlSharedHeader = NULL;
    }
    if (Client->IoctlSharedMapping != NULL && Client->IoctlSharedMapping != INVALID_HANDLE_VALUE)
    {
        (void)CloseHandle(Client->IoctlSharedMapping);
        Client->IoctlSharedMapping = NULL;
    }
    if (Client->IoctlSharedDataEvent != NULL && Client->IoctlSharedDataEvent != INVALID_HANDLE_VALUE)
    {
        (void)CloseHandle(Client->IoctlSharedDataEvent);
        Client->IoctlSharedDataEvent = NULL;
    }
    Client->IoctlSharedRecords = NULL;

    if (Client->EtwSharedHeader != NULL)
    {
        (void)UnmapViewOfFile((PVOID)Client->EtwSharedHeader);
        Client->EtwSharedHeader = NULL;
    }
    if (Client->EtwSharedMapping != NULL && Client->EtwSharedMapping != INVALID_HANDLE_VALUE)
    {
        (void)CloseHandle(Client->EtwSharedMapping);
        Client->EtwSharedMapping = NULL;
    }
    if (Client->EtwSharedDataEvent != NULL && Client->EtwSharedDataEvent != INVALID_HANDLE_VALUE)
    {
        (void)CloseHandle(Client->EtwSharedDataEvent);
        Client->EtwSharedDataEvent = NULL;
    }
    Client->EtwSharedRecords = NULL;
}
VOID ControllerClientFreeQueueLocked(_Inout_ BK_CONTROLLER_CLIENT *Client)
{
    PBK_CONTROLLER_EVENT_NODE node = Client->QueueHead;

    while (node != NULL)
    {
        PBK_CONTROLLER_EVENT_NODE next = node->Next;
        if (Client->IoctlNodeSlab != NULL)
        {
            node->Next = Client->IoctlNodeFreeHead;
            Client->IoctlNodeFreeHead = node;
        }
        else
        {
            free(node);
        }
        node = next;
    }

    Client->QueueHead = NULL;
    Client->QueueTail = NULL;
    Client->QueueDepth = 0;
    if (Client->IoctlQueueDataEvent != NULL)
    {
        (void)ResetEvent(Client->IoctlQueueDataEvent);
    }
}
VOID ControllerClientFreeEtwQueueLocked(_Inout_ BK_CONTROLLER_CLIENT *Client)
{
    if (Client->EtwNodeSlab != NULL)
    {
        DWORD i;
        for (i = 0; i < BK_CONTROLLER_MAX_CLIENT_ETW_QUEUE_DEPTH - 1; i++)
        {
            Client->EtwNodeSlab[i].Next = &Client->EtwNodeSlab[i + 1];
        }
        Client->EtwNodeSlab[BK_CONTROLLER_MAX_CLIENT_ETW_QUEUE_DEPTH - 1].Next = NULL;
        Client->EtwNodeFreeHead = &Client->EtwNodeSlab[0];
    }
    else
    {
        PBK_CONTROLLER_ETW_EVENT_NODE node = Client->EtwQueueHead;
        while (node != NULL)
        {
            PBK_CONTROLLER_ETW_EVENT_NODE next = node->Next;
            free(node);
            node = next;
        }
    }

    Client->EtwQueueHead = NULL;
    Client->EtwQueueTail = NULL;
    Client->EtwQueueDepth = 0;
    if (Client->EtwQueueDataEvent != NULL)
    {
        (void)ResetEvent(Client->EtwQueueDataEvent);
    }
}

static BOOL ControllerClientEnqueueRecordLocked(_Inout_ BK_CONTROLLER_CLIENT *Client,
                                                _In_ const BK_EVENT_RECORD *Record)
{
    PBK_CONTROLLER_EVENT_NODE node;

    if (Client->SharedRingEnabled && Client->IoctlSharedHeader != NULL)
    {
        if (!ControllerSharedRingPushLocked(Client->IoctlSharedHeader, Client->IoctlSharedRecords,
                                            Client->IoctlSharedDataEvent, Record, sizeof(*Record)))
        {
            Client->DroppedEvents += 1;
            return FALSE;
        }
        return TRUE;
    }

    if (Client->QueueDepth >= BK_CONTROLLER_MAX_CLIENT_QUEUE_DEPTH)
    {
        Client->DroppedEvents += 1;
        return FALSE;
    }

    if (Client->IoctlNodeSlab != NULL)
    {
        node = Client->IoctlNodeFreeHead;
        if (node == NULL)
        {
            Client->DroppedEvents += 1;
            return FALSE;
        }
        Client->IoctlNodeFreeHead = node->Next;
    }
    else
    {
        node = (PBK_CONTROLLER_EVENT_NODE)calloc(1, sizeof(*node));
        if (node == NULL)
        {
            Client->DroppedEvents += 1;
            return FALSE;
        }
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
    if (Client->IoctlQueueDataEvent != NULL)
    {
        (void)SetEvent(Client->IoctlQueueDataEvent);
    }
    return TRUE;
}
BOOL ControllerClientDequeueRecordLocked(_Inout_ BK_CONTROLLER_CLIENT *Client, _Out_ BK_EVENT_RECORD *Record)
{
    PBK_CONTROLLER_EVENT_NODE node;

    if (Client->SharedRingEnabled && Client->IoctlSharedHeader != NULL)
    {
        return ControllerSharedRingPopLocked(Client->IoctlSharedHeader, Client->IoctlSharedRecords,
                                             Client->IoctlSharedDataEvent, Record, sizeof(*Record));
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
        (void)ResetEvent(Client->IoctlQueueDataEvent);
    }

    (void)CopyMemory(Record, &node->Record, sizeof(*Record));
    if (Client->IoctlNodeSlab != NULL)
    {
        node->Next = Client->IoctlNodeFreeHead;
        Client->IoctlNodeFreeHead = node;
    }
    else
    {
        free(node);
    }
    return TRUE;
}
BOOL ControllerClientEnqueueEtwEventLocked(_Inout_ BK_CONTROLLER_CLIENT *Client, _In_ const BKIPC_ETW_EVENT *Event)
{
    PBK_CONTROLLER_ETW_EVENT_NODE node;

    if (Client->SharedRingEnabled && Client->EtwSharedHeader != NULL)
    {
        if (!ControllerSharedRingPushLocked(Client->EtwSharedHeader, Client->EtwSharedRecords,
                                            Client->EtwSharedDataEvent, Event, sizeof(*Event)))
        {
            Client->EtwDroppedEvents += 1;
            return FALSE;
        }
        return TRUE;
    }

    if (Client->EtwQueueDepth >= BK_CONTROLLER_MAX_CLIENT_ETW_QUEUE_DEPTH)
    {
        Client->EtwDroppedEvents += 1;
        return FALSE;
    }

    if (Client->EtwNodeSlab != NULL)
    {
        node = Client->EtwNodeFreeHead;
        if (node == NULL)
        {
            Client->EtwDroppedEvents += 1;
            return FALSE;
        }
        Client->EtwNodeFreeHead = node->Next;
    }
    else
    {
        node = (PBK_CONTROLLER_ETW_EVENT_NODE)calloc(1, sizeof(*node));
        if (node == NULL)
        {
            Client->EtwDroppedEvents += 1;
            return FALSE;
        }
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
    if (Client->EtwQueueDataEvent != NULL)
    {
        (void)SetEvent(Client->EtwQueueDataEvent);
    }
    return TRUE;
}
BOOL ControllerClientDequeueEtwEventLocked(_Inout_ BK_CONTROLLER_CLIENT *Client, _Out_ BKIPC_ETW_EVENT *Event)
{
    PBK_CONTROLLER_ETW_EVENT_NODE node;

    if (Client->SharedRingEnabled && Client->EtwSharedHeader != NULL)
    {
        return ControllerSharedRingPopLocked(Client->EtwSharedHeader, Client->EtwSharedRecords,
                                             Client->EtwSharedDataEvent, Event, sizeof(*Event));
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
        (void)ResetEvent(Client->EtwQueueDataEvent);
    }

    (void)CopyMemory(Event, &node->Event, sizeof(*Event));
    if (Client->EtwNodeSlab != NULL)
    {
        node->Next = Client->EtwNodeFreeHead;
        Client->EtwNodeFreeHead = node;
    }
    else
    {
        free(node);
    }
    return TRUE;
}

static BOOL ControllerCollectUnionPidSet(_Out_writes_(BK_MAX_PID_LIST) DWORD *ProcessIds, _Out_ DWORD *ProcessCount)
{
    DWORD i;

    if (ProcessIds == NULL || ProcessCount == NULL)
    {
        return FALSE;
    }

    EnterCriticalSection(g_ClientListLock.get());
    ControllerRebuildPidIndexLocked(NULL);
    *ProcessCount = g_PidIndexCount;
    for (i = 0; i < g_PidIndexCount; ++i)
    {
        ProcessIds[i] = g_PidIndex[i].ProcessId;
    }
    LeaveCriticalSection(g_ClientListLock.get());
    return TRUE;
}
static BOOL ControllerApplyDriverSubscriptionsIfDirtyNow(VOID)
{
    if (InterlockedCompareExchange(&g_DriverSubscriptionsDirty, 0, 1) == 1)
    {
        return ControllerApplyDriverSubscriptionsNow();
    }
    return TRUE;
}

BOOL ControllerApplyDriverSubscriptions(VOID)
{
    return ControllerRequestDriverSubscriptionApply(TRUE, BK_CONTROLLER_SUBSCRIPTION_APPLY_SYNC_TIMEOUT_MS);
}

static BOOL ControllerApplyDriverSubscriptionsNow(VOID)
{
    DWORD desiredPids[BK_MAX_PID_LIST];
    DWORD desiredCount = 0;
    DWORD ioctlPids[BK_MAX_PID_LIST];
    DWORD ioctlCount = 0;
    BOOL ok = TRUE;
    BOOL needIoctl = FALSE;
    BOOL clearIoctl = FALSE;
    BOOL unchanged;
    DWORD i;
    HANDLE ioctlHandle = NULL;
    DWORD ioctlErr = ERROR_SUCCESS;

    ZeroMemory(desiredPids, sizeof(desiredPids));
    ZeroMemory(ioctlPids, sizeof(ioctlPids));
    ControllerSetDriverSubscriptionApplyPhase(BkControllerDriverSubscriptionApplyCollecting, 0,
                                              (DWORD)g_ProgrammedPidCount, 0);
    if (!ControllerCollectUnionPidSet(desiredPids, &desiredCount))
    {
        ControllerSetDriverSubscriptionApplyPhase(BkControllerDriverSubscriptionApplyIdle, desiredCount,
                                                  (DWORD)g_ProgrammedPidCount, 0);
        return FALSE;
    }

    ControllerSetDriverSubscriptionApplyPhase(BkControllerDriverSubscriptionApplySnapshotting, desiredCount,
                                              (DWORD)g_ProgrammedPidCount, 0);
    EnterCriticalSection(g_DriverConfigLock.get());
    EnterCriticalSection(g_DriverLock.get());

    if (g_DriverHandle == INVALID_HANDLE_VALUE)
    {
        SetLastError(ERROR_DEVICE_NOT_CONNECTED);
        ControllerKeepDriverSubscriptionsDirty();
        ok = FALSE;
        goto Exit;
    }

    if (desiredCount == 0)
    {
        if (g_ProgrammedPidCount == 0)
        {
            goto Exit;
        }

        needIoctl = TRUE;
        clearIoctl = TRUE;
        goto Exit;
    }

    unchanged = (desiredCount == g_ProgrammedPidCount) &&
                (memcmp(g_ProgrammedPids, desiredPids, desiredCount * sizeof(DWORD)) == 0);
    if (unchanged)
    {
        goto Exit;
    }

    needIoctl = TRUE;
    ioctlCount = desiredCount;
    for (i = 0; i < desiredCount; ++i)
    {
        ioctlPids[i] = desiredPids[i];
    }

Exit:
    if (ok && needIoctl)
    {
        HANDLE currentProcess = GetCurrentProcess();
        if (!DuplicateHandle(currentProcess, g_DriverHandle, currentProcess, &ioctlHandle, 0, FALSE,
                             DUPLICATE_SAME_ACCESS))
        {
            ok = FALSE;
            ioctlErr = GetLastError();
            ControllerLog("[DRIVER][WARN] failed to duplicate driver handle for pid subscription apply (%lu)\n",
                          ioctlErr);
            ControllerKeepDriverSubscriptionsDirty();
        }
    }

    LeaveCriticalSection(g_DriverLock.get());
    LeaveCriticalSection(g_DriverConfigLock.get());

    if (!ok || !needIoctl)
    {
        ControllerSetDriverSubscriptionApplyPhase(BkControllerDriverSubscriptionApplyIdle, desiredCount,
                                                  (DWORD)g_ProgrammedPidCount, 0);
        if (!ok && ioctlErr != ERROR_SUCCESS)
        {
            SetLastError(ioctlErr);
        }
        return ok;
    }

    ControllerSetDriverSubscriptionApplyPhase(clearIoctl ? BkControllerDriverSubscriptionApplyIoctlClear
                                                         : BkControllerDriverSubscriptionApplyIoctlProgram,
                                              desiredCount, (DWORD)g_ProgrammedPidCount, ioctlCount);
    {
        ULONGLONG ioctlStartTick = GetTickCount64();
        ok = BkscSetPids(ioctlHandle, ioctlPids, ioctlCount, BK_CONTROLLER_DRIVER_STREAM_MASK);
        ioctlErr = ok ? ERROR_SUCCESS : GetLastError();
        ULONGLONG ioctlElapsedMs = GetTickCount64() - ioctlStartTick;
        if (!ok || ioctlElapsedMs >= 500)
        {
            ControllerLog("[DRIVER]%s pid subscription ioctl op=%s count=%lu elapsedMs=%llu err=%lu\n",
                          ok ? "" : "[WARN]", clearIoctl ? "clear" : "program", ioctlCount,
                          (unsigned long long)ioctlElapsedMs, ioctlErr);
        }
    }
    CloseHandle(ioctlHandle);
    ioctlHandle = NULL;

    ControllerSetDriverSubscriptionApplyPhase(BkControllerDriverSubscriptionApplyUpdating, desiredCount,
                                              (DWORD)g_ProgrammedPidCount, ioctlCount);
    EnterCriticalSection(g_DriverConfigLock.get());
    EnterCriticalSection(g_DriverLock.get());

    if (ok)
    {
        if (clearIoctl)
        {
            g_ProgrammedPidCount = 0;
            ZeroMemory(g_ProgrammedPids, sizeof(g_ProgrammedPids));
            ControllerLog("[DRIVER] subscription set cleared\n");
        }
        else
        {
            g_ProgrammedPidCount = desiredCount;
            ZeroMemory(g_ProgrammedPids, sizeof(g_ProgrammedPids));
            for (i = 0; i < desiredCount; ++i)
            {
                g_ProgrammedPids[i] = desiredPids[i];
            }
            ControllerLog("[DRIVER] programmed pid subscriptions count=%lu streamMask=0x%08lX\n", desiredCount,
                          BK_CONTROLLER_DRIVER_STREAM_MASK);
        }
    }
    else
    {
        if (clearIoctl)
        {
            ControllerLog("[DRIVER][WARN] failed to clear pid subscriptions (%lu)\n", ioctlErr);
        }
        else
        {
            ControllerLog("[DRIVER][WARN] failed to program pid subscriptions count=%lu (%lu)\n", desiredCount,
                          ioctlErr);
        }
        ControllerKeepDriverSubscriptionsDirty();
    }

    LeaveCriticalSection(g_DriverLock.get());
    LeaveCriticalSection(g_DriverConfigLock.get());
    ControllerSetDriverSubscriptionApplyPhase(BkControllerDriverSubscriptionApplyIdle, desiredCount,
                                              (DWORD)g_ProgrammedPidCount, 0);
    if (!ok && ioctlErr != ERROR_SUCCESS)
    {
        SetLastError(ioctlErr);
    }
    return ok;
}
VOID ControllerDispatchDriverRecord(_In_ const BK_EVENT_RECORD *Record)
{
    PBK_CONTROLLER_CLIENT client;
    PBK_CONTROLLER_CLIENT dispatchClients[BK_CONTROLLER_MAX_CLIENTS];
    DWORD dispatchCount = 0;
    DWORD sourcePid = 0;
    DWORD targetPid = 0;
    DWORD relationMask = 0;
    DWORD recordMask;
    DWORD candidateMask[BK_CONTROLLER_CLIENT_MASK_DWORDS];
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
        sourcePid = (DWORD)Record->Data.Handle.CallerPid;
        targetPid = (DWORD)Record->Data.Handle.TargetPid;
        relationMask = BK_STREAM_HANDLE;
    }
    else if (Record->Header.Type == BlackbirdEventTypeThread)
    {
        sourcePid = (DWORD)Record->Data.Thread.CreatorPid;
        targetPid = (DWORD)Record->Data.Thread.ProcessId;
        relationMask = BK_STREAM_THREAD;
    }
    else if (Record->Header.Type == BlackbirdEventTypeFileSystem)
    {
        sourcePid = (DWORD)Record->Data.FileSystem.ProcessId;
        targetPid = 0;
        relationMask = 0;
    }
    else if (Record->Header.Type == BlackbirdEventTypeRegistry)
    {
        sourcePid = (DWORD)Record->Data.Registry.ProcessId;
        targetPid = 0;
        relationMask = 0;
    }
    else if (Record->Header.Type == BlackbirdEventTypeEnterprise)
    {
        sourcePid = (DWORD)Record->Data.Enterprise.ProcessId;
        targetPid = (DWORD)Record->Data.Enterprise.TargetProcessId;
        relationMask = BK_STREAM_ENTERPRISE;
    }

    ControllerExpandMonitoringGraph(sourcePid, targetPid, relationMask);

    useSlowPath = (InterlockedCompareExchange(&g_DriverSubscriptionsDirty, 0, 0) != 0);
    EnterCriticalSection(g_ClientListLock.get());
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
        LeaveCriticalSection(g_ClientListLock.get());
    }
    else
    {
        ZeroMemory(candidateMask, sizeof(candidateMask));
        if (sourcePid != 0)
        {
            entryIndex = ControllerFindPidIndexEntryLocked(sourcePid);
            if (entryIndex >= 0 && (g_PidIndex[(DWORD)entryIndex].StreamMask & recordMask) != 0)
            {
                PBK_CONTROLLER_PID_INDEX_ENTRY entry = &g_PidIndex[(DWORD)entryIndex];
                for (i = 0; i < RTL_NUMBER_OF(g_ClientSlots); ++i)
                {
                    if ((entry->ClientStreamMask[i] & recordMask) != 0)
                    {
                        ControllerPidMaskSetBit(candidateMask, i);
                    }
                }
            }
        }
        if (targetPid != 0 && targetPid != sourcePid)
        {
            entryIndex = ControllerFindPidIndexEntryLocked(targetPid);
            if (entryIndex >= 0 && (g_PidIndex[(DWORD)entryIndex].StreamMask & recordMask) != 0)
            {
                PBK_CONTROLLER_PID_INDEX_ENTRY entry = &g_PidIndex[(DWORD)entryIndex];
                for (i = 0; i < RTL_NUMBER_OF(g_ClientSlots); ++i)
                {
                    if ((entry->ClientStreamMask[i] & recordMask) != 0)
                    {
                        ControllerPidMaskSetBit(candidateMask, i);
                    }
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
        LeaveCriticalSection(g_ClientListLock.get());
    }

    for (i = 0; i < dispatchCount; ++i)
    {
        client = dispatchClients[i];
        EnterCriticalSection(&client->Lock);
        if (!useSlowPath || ControllerClientHasMatchLocked(client, Record))
        {
            (void)ControllerClientEnqueueRecordLocked(client, Record);
        }
        LeaveCriticalSection(&client->Lock);
        ControllerClientReleaseFromDispatch(client);
    }
}
