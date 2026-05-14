#include "control_private.h"
#include "..\..\hooks\monitor\ntapi_monitor.h"

static volatile LONG g_BkctlClientLockBusyCounter = 0;
static volatile LONG g_BkctlPidInterestRebuildCounter = 0;
static volatile LONG g_BkctlPidInterestFallbackCounter = 0;
static volatile LONG g_BkctlEventNodeLookasideReady = 0;
static EX_PUSH_LOCK g_BkctlPidInterestLock;
static BK_PID_INTEREST_ENTRY g_BkctlPidInterestIndex[BK_PID_INTEREST_INDEX_BUCKETS];
static UINT32 g_BkctlPidInterestCount = 0;
static BOOLEAN g_BkctlPidInterestOverflow = FALSE;

NPAGED_LOOKASIDE_LIST g_BkctlEventNodeLookaside;

static UINT32 BkctlPidInterestHash(_In_ UINT32 ProcessId)
{
    return (ProcessId * 2654435761u) & (BK_PID_INTEREST_INDEX_BUCKETS - 1u);
}

static BOOLEAN BkctlPidInterestInsert(_Inout_updates_(BK_PID_INTEREST_INDEX_BUCKETS) PBK_PID_INTEREST_ENTRY Table,
                                      _Inout_ UINT32 *Count, _In_ UINT32 ProcessId, _In_ UINT32 StreamMask)
{
    UINT32 slot;
    UINT32 probe;

    if (Table == NULL || Count == NULL || ProcessId == 0 || StreamMask == 0)
    {
        return TRUE;
    }

    slot = BkctlPidInterestHash(ProcessId);
    for (probe = 0; probe < BK_PID_INTEREST_INDEX_BUCKETS; ++probe)
    {
        PBK_PID_INTEREST_ENTRY entry = &Table[(slot + probe) & (BK_PID_INTEREST_INDEX_BUCKETS - 1u)];
        if (entry->ProcessId == ProcessId)
        {
            entry->StreamMask |= StreamMask;
            return TRUE;
        }
        if (entry->ProcessId == 0)
        {
            entry->ProcessId = ProcessId;
            entry->StreamMask = StreamMask;
            *Count += 1;
            return TRUE;
        }
    }

    return FALSE;
}

static UINT32 BkctlPidInterestLookupLocked(_In_ UINT32 ProcessId)
{
    UINT32 slot;
    UINT32 probe;

    if (ProcessId == 0)
    {
        return 0;
    }

    slot = BkctlPidInterestHash(ProcessId);
    for (probe = 0; probe < BK_PID_INTEREST_INDEX_BUCKETS; ++probe)
    {
        const BK_PID_INTEREST_ENTRY *entry =
            &g_BkctlPidInterestIndex[(slot + probe) & (BK_PID_INTEREST_INDEX_BUCKETS - 1u)];
        if (entry->ProcessId == ProcessId)
        {
            return entry->StreamMask;
        }
        if (entry->ProcessId == 0)
        {
            return 0;
        }
    }

    return 0;
}

VOID BkctlInitializeEventNodeLookaside(VOID)
{
    if (InterlockedCompareExchange(&g_BkctlEventNodeLookasideReady, 1, 0) == 0)
    {
        ExInitializeNPagedLookasideList(&g_BkctlEventNodeLookaside, NULL, NULL, 0, sizeof(BK_EVENT_NODE), BK_POOL_TAG,
                                        0);
    }
}

VOID BkctlUninitializeEventNodeLookaside(VOID)
{
    if (InterlockedExchange(&g_BkctlEventNodeLookasideReady, 0) != 0)
    {
        ExDeleteNPagedLookasideList(&g_BkctlEventNodeLookaside);
    }
}

PBK_EVENT_NODE BkctlAllocateEventNode(VOID)
{
    if (InterlockedCompareExchange(&g_BkctlEventNodeLookasideReady, 0, 0) == 0)
    {
        return (PBK_EVENT_NODE)BkpoolAllocateCompat(POOL_FLAG_NON_PAGED, sizeof(BK_EVENT_NODE), BK_POOL_TAG);
    }

    return (PBK_EVENT_NODE)ExAllocateFromNPagedLookasideList(&g_BkctlEventNodeLookaside);
}

VOID BkctlFreeEventNode(_Inout_ PBK_EVENT_NODE Node)
{
    if (Node == NULL)
    {
        return;
    }
    if (InterlockedCompareExchange(&g_BkctlEventNodeLookasideReady, 0, 0) == 0)
    {
        ExFreePoolWithTag(Node, BK_POOL_TAG);
        return;
    }

    ExFreeToNPagedLookasideList(&g_BkctlEventNodeLookaside, Node);
}

VOID BkctlInitializePidInterestIndex(VOID)
{
    ExInitializePushLock(&g_BkctlPidInterestLock);
    BkctlClearPidInterestIndex();
}

VOID BkctlClearPidInterestIndex(VOID)
{
    ExAcquirePushLockExclusiveEx(&g_BkctlPidInterestLock, 0);
    RtlZeroMemory(g_BkctlPidInterestIndex, sizeof(g_BkctlPidInterestIndex));
    g_BkctlPidInterestCount = 0;
    g_BkctlPidInterestOverflow = FALSE;
    ExReleasePushLockExclusiveEx(&g_BkctlPidInterestLock, 0);
}

BOOLEAN BkctlModeAllowed(_In_ WDFREQUEST Request)
{
    return (WdfRequestGetRequestorMode(Request) == UserMode);
}

ULONG BkctlGetRequestorPid(VOID)
{
    return (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
}

PCSTR BkctlIoctlName(_In_ ULONG Ioctl)
{
    switch (Ioctl)
    {
    case IOCTL_BK_SUBSCRIBE:
        return "SUBSCRIBE";
    case IOCTL_BK_UNSUBSCRIBE:
        return "UNSUBSCRIBE";
    case IOCTL_BK_GET_EVENT:
        return "GET_EVENT";
    case IOCTL_BK_GET_STATS:
        return "GET_STATS";
    case IOCTL_BK_SET_PIDS:
        return "SET_PIDS";
    case IOCTL_BK_QUERY_PROCESS_IMAGE:
        return "QUERY_PROCESS_IMAGE";
    case IOCTL_BK_SET_SHUTDOWN_MODE:
        return "SET_SHUTDOWN_MODE";
    case IOCTL_BK_GET_HEALTH:
        return "GET_HEALTH";
    case IOCTL_BK_GET_DIAGNOSTICS:
        return "GET_DIAGNOSTICS";
    case IOCTL_BK_ARM_PENDING_LAUNCH:
        return "ARM_PENDING_LAUNCH";
    case IOCTL_BK_CONTROL_EXECUTION:
        return "CONTROL_EXECUTION";
    case IOCTL_BK_SET_RUNTIME_CONFIG:
        return "SET_RUNTIME_CONFIG";
    case IOCTL_BK_GET_RUNTIME_CONFIG:
        return "GET_RUNTIME_CONFIG";
    case IOCTL_BK_REGISTER_INSTRUMENTATION_RANGE:
        return "REGISTER_INSTRUMENTATION_RANGE";
    case IOCTL_BK_REGISTER_HOOK_PATCH:
        return "REGISTER_HOOK_PATCH";
    case IOCTL_BK_SET_QPC_TIMING_CONFIG:
        return "SET_QPC_TIMING_CONFIG";
    case IOCTL_BK_GET_QPC_TIMING_STATE:
        return "GET_QPC_TIMING_STATE";
    case IOCTL_BK_REGISTER_PROCESS_INSTRUMENTATION_CALLBACK:
        return "REGISTER_PROCESS_INSTRUMENTATION_CALLBACK";
    default:
        return "UNKNOWN_IOCTL";
    }
}

BOOLEAN BkctlIsShutdown(VOID)
{
    return (InterlockedCompareExchange(&g_ControlShutdown, 0, 0) != 0);
}

VOID BkctlSetTelemetryArmed(_In_ BOOLEAN Armed)
{
    InterlockedExchange(&g_ControlTelemetryArmed, Armed ? 1 : 0);
    if (KeGetCurrentIrql() == PASSIVE_LEVEL)
    {
        BkntkiMonitorSetArmedState(Armed);
    }
}

static BOOLEAN BkctlTryAcquireClientLock(_Inout_ PBK_CLIENT Client, _In_z_ PCSTR Reason)
{
    LONG busyCount;

    if (Client == NULL)
    {
        return FALSE;
    }
    if (ExTryToAcquireFastMutex(&Client->Lock))
    {
        return TRUE;
    }

    busyCount = InterlockedIncrement(&g_BkctlClientLockBusyCounter);
    if (busyCount == 1 || ((busyCount & 0xFF) == 0))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "BK: client lock busy reason=%s busyCount=%ld client=0x%p subscriptions=%lu queueDepth=%lu.\n",
                   Reason, busyCount, Client, Client->SubscriptionCount, Client->QueueDepth);
    }
    return FALSE;
}

static BOOLEAN BkctlTryAcquireGlobalQueueSlot(VOID)
{
    LONG current;

    for (;;)
    {
        current = InterlockedCompareExchange(&g_ControlTotalQueuedEvents, 0, 0);
        if (current >= BK_MAX_TOTAL_QUEUED_EVENTS)
        {
            return FALSE;
        }
        if (InterlockedCompareExchange(&g_ControlTotalQueuedEvents, current + 1, current) == current)
        {
            return TRUE;
        }
    }
}

VOID BkctlReleaseGlobalQueueSlot(VOID)
{
    LONG remaining;

    remaining = InterlockedDecrement(&g_ControlTotalQueuedEvents);
    NT_ASSERT(remaining >= 0);
    if (remaining < 0)
    {
        InterlockedExchange(&g_ControlTotalQueuedEvents, 0);
    }
}

BOOLEAN BkctlClientConsumeQueryBudgetLocked(_Inout_ PBK_CLIENT Client)
{
    ULONGLONG now;

    now = KeQueryInterruptTime();
    if (Client->QueryWindowStart100ns == 0 || now < Client->QueryWindowStart100ns ||
        (now - Client->QueryWindowStart100ns) >= BK_QUERY_IMAGE_WINDOW_100NS)
    {
        Client->QueryWindowStart100ns = now;
        Client->QueryWindowCount = 1;
        return TRUE;
    }

    if (Client->QueryWindowCount >= BK_QUERY_IMAGE_MAX_PER_WINDOW)
    {
        return FALSE;
    }

    Client->QueryWindowCount += 1;
    return TRUE;
}

BOOLEAN BkctlTryAcquireQueryInflightSlot(VOID)
{
    LONG current;

    for (;;)
    {
        current = InterlockedCompareExchange(&g_QueryImageInflight, 0, 0);
        if (current >= BK_QUERY_IMAGE_MAX_INFLIGHT)
        {
            return FALSE;
        }
        if (InterlockedCompareExchange(&g_QueryImageInflight, current + 1, current) == current)
        {
            return TRUE;
        }
    }
}

VOID BkctlReleaseQueryInflightSlot(VOID)
{
    LONG remaining;

    remaining = InterlockedDecrement(&g_QueryImageInflight);
    NT_ASSERT(remaining >= 0);
    if (remaining < 0)
    {
        InterlockedExchange(&g_QueryImageInflight, 0);
    }
}

VOID BkctlClientFreeQueuedEvents(_Inout_ PBK_CLIENT Client)
{
    while (!IsListEmpty(&Client->EventQueue))
    {
        PLIST_ENTRY entry = RemoveHeadList(&Client->EventQueue);
        PBK_EVENT_NODE node = CONTAINING_RECORD(entry, BK_EVENT_NODE, Link);
        BkctlFreeEventNode(node);
        BkctlReleaseGlobalQueueSlot();
    }
    Client->QueueDepth = 0;
}

static VOID BkctlClientFreeSubscriptions(_Inout_ PBK_CLIENT Client)
{
    if (Client == NULL || Client->Subscriptions == NULL)
    {
        return;
    }

    ExFreePoolWithTag(Client->Subscriptions, BK_POOL_TAG);
    Client->Subscriptions = NULL;
    Client->SubscriptionCount = 0;
    Client->SubscriptionCapacity = 0;
}

static BOOLEAN BkctlClientEnsureSubscriptionCapacityLocked(_Inout_ PBK_CLIENT Client, _In_ UINT32 RequiredCount)
{
    PBK_SUBSCRIPTION newSubscriptions;
    UINT32 newCapacity;
    SIZE_T bytes;

    if (Client == NULL || RequiredCount == 0 || RequiredCount > BK_MAX_CLIENT_SUBSCRIPTIONS)
    {
        return FALSE;
    }
    if (Client->SubscriptionCapacity >= RequiredCount && Client->Subscriptions != NULL)
    {
        return TRUE;
    }

    newCapacity = Client->SubscriptionCapacity;
    if (newCapacity == 0)
    {
        newCapacity = BK_INITIAL_CLIENT_SUBSCRIPTIONS;
    }
    while (newCapacity < RequiredCount && newCapacity < BK_MAX_CLIENT_SUBSCRIPTIONS)
    {
        UINT32 grown = newCapacity * 2;
        if (grown <= newCapacity)
        {
            newCapacity = BK_MAX_CLIENT_SUBSCRIPTIONS;
            break;
        }
        newCapacity = (grown > BK_MAX_CLIENT_SUBSCRIPTIONS) ? BK_MAX_CLIENT_SUBSCRIPTIONS : grown;
    }
    if (newCapacity < RequiredCount)
    {
        return FALSE;
    }

    bytes = sizeof(BK_SUBSCRIPTION) * (SIZE_T)newCapacity;
    newSubscriptions = (PBK_SUBSCRIPTION)BkpoolAllocateCompat(POOL_FLAG_NON_PAGED, bytes, BK_POOL_TAG);
    if (newSubscriptions == NULL)
    {
        return FALSE;
    }

    RtlZeroMemory(newSubscriptions, bytes);
    if (Client->Subscriptions != NULL && Client->SubscriptionCount != 0)
    {
        RtlCopyMemory(newSubscriptions, Client->Subscriptions,
                      sizeof(BK_SUBSCRIPTION) * (SIZE_T)Client->SubscriptionCount);
        ExFreePoolWithTag(Client->Subscriptions, BK_POOL_TAG);
    }

    Client->Subscriptions = newSubscriptions;
    Client->SubscriptionCapacity = newCapacity;
    return TRUE;
}

VOID BkctlClientRelease(_Inout_ PBK_CLIENT Client)
{
    if (InterlockedDecrement(&Client->RefCount) != 0)
    {
        return;
    }

    ExAcquireFastMutex(&Client->Lock);
    BkctlClientFreeQueuedEvents(Client);
    BkctlClientFreeSubscriptions(Client);
    ExReleaseFastMutex(&Client->Lock);
    ExFreePoolWithTag(Client, BK_POOL_TAG);
}

VOID BkctlClientReference(_Inout_ PBK_CLIENT Client)
{
    (void)InterlockedIncrement(&Client->RefCount);
}

BOOLEAN BkctlIsValidStreamMask(_In_ UINT32 StreamMask)
{
    return ((StreamMask & (BK_STREAM_HANDLE | BK_STREAM_MEMORY | BK_STREAM_THREAD | BK_STREAM_FILESYSTEM |
                           BK_STREAM_REGISTRY | BK_STREAM_TIMING)) != 0);
}

VOID BkctlClientClearPendingLaunchLocked(_Inout_ PBK_CLIENT Client)
{
    if (Client == NULL)
    {
        return;
    }

    Client->PendingLaunchArmed = FALSE;
    Client->PendingLaunchStreamMask = 0;
    Client->PendingAnalysisSubjectKind = BlackbirdAnalysisSubjectProcess;
    Client->PendingLaunchPathNormDos[0] = L'\0';
    Client->PendingLaunchPathNormNt[0] = L'\0';
    Client->PendingLaunchPathTail[0] = L'\0';
    Client->PendingSubjectPathNormDos[0] = L'\0';
    Client->PendingSubjectPathNormNt[0] = L'\0';
    Client->PendingSubjectPathTail[0] = L'\0';
}

VOID BkctlClientConfigurePendingLaunchLocked(_Inout_ PBK_CLIENT Client,
                                             _In_opt_ const BK_ARM_PENDING_LAUNCH_REQUEST *Request)
{
    BkctlClientClearPendingLaunchLocked(Client);
    if (Client == NULL || Request == NULL)
    {
        return;
    }

    Client->PendingLaunchStreamMask = Request->StreamMask;
    Client->PendingAnalysisSubjectKind = Request->AnalysisSubjectKind;
    Client->PendingLaunchArmed = TRUE;
    (void)RtlStringCchCopyW(Client->PendingLaunchPathNormDos, RTL_NUMBER_OF(Client->PendingLaunchPathNormDos),
                            Request->ImagePathNormDos);
    (void)RtlStringCchCopyW(Client->PendingLaunchPathNormNt, RTL_NUMBER_OF(Client->PendingLaunchPathNormNt),
                            Request->ImagePathNormNt);
    (void)RtlStringCchCopyW(Client->PendingLaunchPathTail, RTL_NUMBER_OF(Client->PendingLaunchPathTail),
                            Request->ImagePathTail);
    (void)RtlStringCchCopyW(Client->PendingSubjectPathNormDos, RTL_NUMBER_OF(Client->PendingSubjectPathNormDos),
                            Request->AnalysisSubjectNormDos);
    (void)RtlStringCchCopyW(Client->PendingSubjectPathNormNt, RTL_NUMBER_OF(Client->PendingSubjectPathNormNt),
                            Request->AnalysisSubjectNormNt);
    (void)RtlStringCchCopyW(Client->PendingSubjectPathTail, RTL_NUMBER_OF(Client->PendingSubjectPathTail),
                            Request->AnalysisSubjectTail);
}

static SIZE_T BkctlKnownPathPrefixChars(_In_reads_opt_(InputChars) PCWSTR Input, _In_ SIZE_T InputChars)
{
    if (Input == NULL || InputChars < 4)
    {
        return 0;
    }

    if ((Input[0] == L'\\' && Input[1] == L'\\' && Input[2] == L'?' && Input[3] == L'\\') ||
        (Input[0] == L'\\' && Input[1] == L'?' && Input[2] == L'?' && Input[3] == L'\\'))
    {
        return 4;
    }

    return 0;
}

static VOID BkctlNormalizeWidePathForCompare(_In_opt_z_ PCWSTR Input, _Out_writes_z_(OutputChars) PWSTR Output,
                                             _In_ SIZE_T OutputChars)
{
    SIZE_T i;
    SIZE_T inputChars = 0;
    SIZE_T skippedChars;
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

    if (!NT_SUCCESS(RtlStringCchLengthW(Input, OutputChars * 2, &inputChars)))
    {
        return;
    }
    skippedChars = BkctlKnownPathPrefixChars(Input, inputChars);
    Input += skippedChars;
    inputChars -= skippedChars;

    for (i = 0; i < inputChars && (written + 1) < OutputChars; ++i)
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

static VOID BkctlNormalizeUnicodePathForCompare(_In_opt_ PCUNICODE_STRING Input,
                                                _Out_writes_z_(OutputChars) PWSTR Output, _In_ SIZE_T OutputChars)
{
    SIZE_T i;
    SIZE_T inputChars;
    SIZE_T skippedChars;
    SIZE_T written = 0;
    PCWSTR inputBuffer;

    if (Output == NULL || OutputChars == 0)
    {
        return;
    }
    Output[0] = L'\0';

    __try
    {
        if (Input == NULL || Input->Buffer == NULL || Input->Length == 0)
        {
            return;
        }

        inputBuffer = Input->Buffer;
        inputChars = Input->Length / sizeof(WCHAR);
        skippedChars = BkctlKnownPathPrefixChars(inputBuffer, inputChars);
        inputBuffer += skippedChars;
        inputChars -= skippedChars;

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
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        Output[0] = L'\0';
    }
}

static BOOLEAN BkctlPathHasTrailingSegmentInsensitive(_In_z_ PCWSTR Path, _In_z_ PCWSTR Tail)
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

static BOOLEAN BkctlClientPathMatchesPendingLaunchLocked(_In_ const BK_CLIENT *Client, _In_z_ PCWSTR CandidateNorm)
{
    if (Client == NULL || CandidateNorm == NULL || CandidateNorm[0] == L'\0' || !Client->PendingLaunchArmed)
    {
        return FALSE;
    }

    if (Client->PendingLaunchPathNormNt[0] != L'\0' && _wcsicmp(Client->PendingLaunchPathNormNt, CandidateNorm) == 0)
    {
        return TRUE;
    }

    if (Client->PendingLaunchPathNormDos[0] != L'\0' && _wcsicmp(Client->PendingLaunchPathNormDos, CandidateNorm) == 0)
    {
        return TRUE;
    }

    if (Client->PendingLaunchPathTail[0] != L'\0' &&
        BkctlPathHasTrailingSegmentInsensitive(CandidateNorm, Client->PendingLaunchPathTail))
    {
        return TRUE;
    }

    return FALSE;
}

static BOOLEAN BkctlClientPathMatchesAnalysisSubjectLocked(_In_ const BK_CLIENT *Client, _In_z_ PCWSTR CandidateNorm)
{
    if (Client == NULL || CandidateNorm == NULL || CandidateNorm[0] == L'\0' || Client->AnalysisSubjectProcessId == 0 ||
        Client->AnalysisSubjectKind != BlackbirdAnalysisSubjectDll)
    {
        return FALSE;
    }

    if (Client->AnalysisSubjectPathNormNt[0] != L'\0' &&
        _wcsicmp(Client->AnalysisSubjectPathNormNt, CandidateNorm) == 0)
    {
        return TRUE;
    }

    if (Client->AnalysisSubjectPathNormDos[0] != L'\0' &&
        _wcsicmp(Client->AnalysisSubjectPathNormDos, CandidateNorm) == 0)
    {
        return TRUE;
    }

    if (Client->AnalysisSubjectPathTail[0] != L'\0' &&
        BkctlPathHasTrailingSegmentInsensitive(CandidateNorm, Client->AnalysisSubjectPathTail))
    {
        return TRUE;
    }

    return FALSE;
}

static VOID BkctlClientBindAnalysisSubjectLocked(_Inout_ PBK_CLIENT Client, _In_ UINT32 ProcessId)
{
    if (Client == NULL || ProcessId == 0)
    {
        return;
    }

    Client->AnalysisSubjectProcessId = 0;
    Client->AnalysisSubjectKind = BlackbirdAnalysisSubjectProcess;
    Client->AnalysisSubjectImageBase = 0;
    Client->AnalysisSubjectImageSize = 0;
    Client->AnalysisSubjectPathNormDos[0] = L'\0';
    Client->AnalysisSubjectPathNormNt[0] = L'\0';
    Client->AnalysisSubjectPathTail[0] = L'\0';

    if (Client->PendingAnalysisSubjectKind != BlackbirdAnalysisSubjectDll ||
        (Client->PendingSubjectPathNormDos[0] == L'\0' && Client->PendingSubjectPathNormNt[0] == L'\0' &&
         Client->PendingSubjectPathTail[0] == L'\0'))
    {
        return;
    }

    Client->AnalysisSubjectProcessId = ProcessId;
    Client->AnalysisSubjectKind = Client->PendingAnalysisSubjectKind;
    (void)RtlStringCchCopyW(Client->AnalysisSubjectPathNormDos, RTL_NUMBER_OF(Client->AnalysisSubjectPathNormDos),
                            Client->PendingSubjectPathNormDos);
    (void)RtlStringCchCopyW(Client->AnalysisSubjectPathNormNt, RTL_NUMBER_OF(Client->AnalysisSubjectPathNormNt),
                            Client->PendingSubjectPathNormNt);
    (void)RtlStringCchCopyW(Client->AnalysisSubjectPathTail, RTL_NUMBER_OF(Client->AnalysisSubjectPathTail),
                            Client->PendingSubjectPathTail);
}

BOOLEAN BkctlClientAddOrUpdateSubscriptionLocked(_Inout_ PBK_CLIENT Client, _In_ UINT32 ProcessId,
                                                 _In_ UINT32 StreamMask)
{
    UINT32 i;

    if (Client == NULL || ProcessId == 0 || StreamMask == 0)
    {
        return FALSE;
    }
    if (Client->Subscriptions == NULL && !BkctlClientEnsureSubscriptionCapacityLocked(Client, 1))
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

    if (!BkctlClientEnsureSubscriptionCapacityLocked(Client, Client->SubscriptionCount + 1))
    {
        return FALSE;
    }

    Client->Subscriptions[Client->SubscriptionCount].ProcessId = ProcessId;
    Client->Subscriptions[Client->SubscriptionCount].StreamMask = StreamMask;
    Client->SubscriptionCount += 1;
    return TRUE;
}

BOOLEAN BkctlClientRemoveSubscriptionLocked(_Inout_ PBK_CLIENT Client, _In_ UINT32 ProcessId)
{
    UINT32 i;

    if (Client == NULL || ProcessId == 0)
    {
        return FALSE;
    }
    if (Client->Subscriptions == NULL || Client->SubscriptionCount == 0)
    {
        return FALSE;
    }

    for (i = 0; i < Client->SubscriptionCount; ++i)
    {
        if (Client->Subscriptions[i].ProcessId == ProcessId)
        {
            UINT32 tail = Client->SubscriptionCount - 1;
            if (i != tail)
            {
                Client->Subscriptions[i] = Client->Subscriptions[tail];
            }
            Client->SubscriptionCount -= 1;
            return TRUE;
        }
    }

    return FALSE;
}

UINT32 BkctlClientReplaceSubscriptionsLocked(_Inout_ PBK_CLIENT Client,
                                             _In_reads_(ProcessCount) const UINT32 *ProcessIds,
                                             _In_ UINT32 ProcessCount, _In_ UINT32 StreamMask)
{
    UINT32 i;

    if (Client == NULL || ProcessIds == NULL || ProcessCount == 0 || StreamMask == 0)
    {
        if (Client != NULL)
        {
            Client->SubscriptionCount = 0;
        }
        return 0;
    }

    Client->SubscriptionCount = 0;
    if (!BkctlClientEnsureSubscriptionCapacityLocked(
            Client, (ProcessCount > BK_MAX_CLIENT_SUBSCRIPTIONS) ? BK_MAX_CLIENT_SUBSCRIPTIONS : ProcessCount))
    {
        return 0;
    }
    for (i = 0; i < ProcessCount; ++i)
    {
        UINT32 pid = ProcessIds[i];
        if (pid == 0)
        {
            continue;
        }

        (void)BkctlClientAddOrUpdateSubscriptionLocked(Client, pid, StreamMask);
    }

    return Client->SubscriptionCount;
}

VOID BkctlRebuildPidInterestIndex(VOID)
{
    PBK_PID_INTEREST_ENTRY table;
    PBK_CLIENT snapshot[BK_MAX_TOTAL_CLIENTS];
    UINT32 snapshotCount = 0;
    UINT32 count = 0;
    UINT32 i;
    PLIST_ENTRY entry;
    BOOLEAN overflow = FALSE;
    LONG rebuildCount;

    table = (PBK_PID_INTEREST_ENTRY)BkpoolAllocateCompat(
        POOL_FLAG_NON_PAGED, sizeof(BK_PID_INTEREST_ENTRY) * BK_PID_INTEREST_INDEX_BUCKETS, BK_POOL_TAG);
    if (table == NULL)
    {
        ExAcquirePushLockExclusiveEx(&g_BkctlPidInterestLock, 0);
        RtlZeroMemory(g_BkctlPidInterestIndex, sizeof(g_BkctlPidInterestIndex));
        g_BkctlPidInterestCount = 0;
        g_BkctlPidInterestOverflow = TRUE;
        ExReleasePushLockExclusiveEx(&g_BkctlPidInterestLock, 0);
        return;
    }

    RtlZeroMemory(table, sizeof(BK_PID_INTEREST_ENTRY) * BK_PID_INTEREST_INDEX_BUCKETS);

    ExAcquireFastMutex(&g_ClientListLock);
    for (entry = g_ClientList.Flink; entry != &g_ClientList; entry = entry->Flink)
    {
        PBK_CLIENT client = CONTAINING_RECORD(entry, BK_CLIENT, Link);
        if (snapshotCount >= RTL_NUMBER_OF(snapshot))
        {
            overflow = TRUE;
            break;
        }
        BkctlClientReference(client);
        snapshot[snapshotCount++] = client;
    }
    ExReleaseFastMutex(&g_ClientListLock);

    for (i = 0; i < snapshotCount; ++i)
    {
        PBK_CLIENT client = snapshot[i];
        UINT32 subIndex;

        ExAcquireFastMutex(&client->Lock);
        for (subIndex = 0; subIndex < client->SubscriptionCount; ++subIndex)
        {
            if (!BkctlPidInterestInsert(table, &count, client->Subscriptions[subIndex].ProcessId,
                                        client->Subscriptions[subIndex].StreamMask))
            {
                overflow = TRUE;
            }
        }
        ExReleaseFastMutex(&client->Lock);
        BkctlClientRelease(client);
    }

    ExAcquirePushLockExclusiveEx(&g_BkctlPidInterestLock, 0);
    RtlCopyMemory(g_BkctlPidInterestIndex, table, sizeof(BK_PID_INTEREST_ENTRY) * BK_PID_INTEREST_INDEX_BUCKETS);
    g_BkctlPidInterestCount = count;
    g_BkctlPidInterestOverflow = overflow;
    ExReleasePushLockExclusiveEx(&g_BkctlPidInterestLock, 0);

    ExFreePoolWithTag(table, BK_POOL_TAG);

    rebuildCount = InterlockedIncrement(&g_BkctlPidInterestRebuildCounter);
    if (overflow && (rebuildCount == 1 || ((rebuildCount & 0x3F) == 0)))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "BK: pid-interest index overflow rebuild=%ld indexed=%lu buckets=%lu; using slow fallback.\n",
                   rebuildCount, count, BK_PID_INTEREST_INDEX_BUCKETS);
    }
}

UINT32 BkctlClientQuerySubscriptionMaskEither(_In_ PBK_CLIENT Client, _In_ UINT32 PrimaryProcessId,
                                              _In_ UINT32 SecondaryProcessId, _In_ UINT32 StreamMask)
{
    UINT32 i;
    UINT32 matchedMask = 0;

    if (Client == NULL || Client->Subscriptions == NULL || Client->SubscriptionCount == 0 || StreamMask == 0)
    {
        return 0;
    }

    for (i = 0; i < Client->SubscriptionCount; ++i)
    {
        UINT32 subscribedPid = Client->Subscriptions[i].ProcessId;
        UINT32 subscribedMask = Client->Subscriptions[i].StreamMask & StreamMask;

        if (subscribedMask == 0)
        {
            continue;
        }

        if (subscribedPid == PrimaryProcessId || (SecondaryProcessId != 0 && subscribedPid == SecondaryProcessId))
        {
            matchedMask |= subscribedMask;
        }
    }

    return matchedMask;
}

static VOID BkctlFlushAllClientState(VOID)
{
    PBK_CLIENT snapshot[BK_MAX_TOTAL_CLIENTS];
    UINT32 snapshotCount = 0;
    UINT32 i;
    PLIST_ENTRY e;

    ExAcquireFastMutex(&g_ClientListLock);
    for (e = g_ClientList.Flink; e != &g_ClientList; e = e->Flink)
    {
        PBK_CLIENT c = CONTAINING_RECORD(e, BK_CLIENT, Link);
        if (snapshotCount >= RTL_NUMBER_OF(snapshot))
        {
            break;
        }
        BkctlClientReference(c);
        snapshot[snapshotCount++] = c;
    }
    ExReleaseFastMutex(&g_ClientListLock);

    for (i = 0; i < snapshotCount; ++i)
    {
        PBK_CLIENT c = snapshot[i];
        WDFQUEUE pendingQueue = NULL;
        ExAcquireFastMutex(&c->Lock);
        pendingQueue = c->PendingGetEventQueue;
        c->PendingGetEventQueue = NULL;
        c->SubscriptionCount = 0;
        BkctlClientClearPendingLaunchLocked(c);
        BkctlClientFreeQueuedEvents(c);
        ExReleaseFastMutex(&c->Lock);
        if (pendingQueue != NULL)
        {
            WdfIoQueuePurgeSynchronously(pendingQueue);
        }
        BkctlClientRelease(c);
    }

    BkctlClearPidInterestIndex();
}

VOID BkctlRefreshArmedState(VOID)
{
    PBK_CLIENT snapshot[BK_MAX_TOTAL_CLIENTS];
    UINT32 snapshotCount = 0;
    UINT32 i;
    PLIST_ENTRY entry;
    BOOLEAN armed = FALSE;

    ExAcquireFastMutex(&g_ClientListLock);
    for (entry = g_ClientList.Flink; entry != &g_ClientList; entry = entry->Flink)
    {
        PBK_CLIENT client = CONTAINING_RECORD(entry, BK_CLIENT, Link);
        if (snapshotCount >= RTL_NUMBER_OF(snapshot))
        {
            break;
        }
        BkctlClientReference(client);
        snapshot[snapshotCount++] = client;
    }
    ExReleaseFastMutex(&g_ClientListLock);

    for (i = 0; i < snapshotCount; ++i)
    {
        PBK_CLIENT client = snapshot[i];
        if (!BkctlTryAcquireClientLock(client, "refresh-armed"))
        {
            armed = TRUE;
            BkctlClientRelease(client);
            break;
        }
        if (client->SubscriptionCount != 0 || client->PendingLaunchArmed)
        {
            armed = TRUE;
        }
        ExReleaseFastMutex(&client->Lock);
        BkctlClientRelease(client);
        if (armed)
        {
            break;
        }
    }

    for (++i; i < snapshotCount; ++i)
    {
        BkctlClientRelease(snapshot[i]);
    }

    BkctlSetTelemetryArmed(armed);
}

VOID BkctlBeginShutdown(VOID)
{
    if (InterlockedExchange(&g_ControlShutdown, 1) == 0)
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "BK: control plane entering shutdown mode.\n");
    }
    BkctlFlushAllClientState();
    BkctlSetTelemetryArmed(FALSE);
}

static PBK_CLIENT BkctlClientCreate(VOID)
{
    PBK_CLIENT client;

    client = (PBK_CLIENT)BkpoolAllocateCompat(POOL_FLAG_NON_PAGED, sizeof(*client), BK_POOL_TAG);
    if (client == NULL)
    {
        return NULL;
    }

    RtlZeroMemory(client, sizeof(*client));
    InitializeListHead(&client->EventQueue);
    client->PendingGetEventQueue = NULL;
    ExInitializeFastMutex(&client->Lock);
    client->RefCount = 1;
    if (!BkctlClientEnsureSubscriptionCapacityLocked(client, BK_INITIAL_CLIENT_SUBSCRIPTIONS))
    {
        ExFreePoolWithTag(client, BK_POOL_TAG);
        return NULL;
    }
    return client;
}

BOOLEAN BkctlClientMatchSubscriptionEither(_In_ PBK_CLIENT Client, _In_ UINT32 PrimaryProcessId,
                                           _In_ UINT32 SecondaryProcessId, _In_ UINT32 StreamMask)
{
    return (BkctlClientQuerySubscriptionMaskEither(Client, PrimaryProcessId, SecondaryProcessId, StreamMask) != 0);
}

static UINT32 BkctlScanPidInterestSlow(_In_ UINT32 PrimaryProcessId, _In_ UINT32 SecondaryProcessId,
                                       _In_ UINT32 StreamMask)
{
    PBK_CLIENT snapshot[BK_MAX_TOTAL_CLIENTS];
    UINT32 snapshotCount = 0;
    UINT32 matchedMask = 0;
    UINT32 i;
    PLIST_ENTRY entry;

    ExAcquireFastMutex(&g_ClientListLock);
    for (entry = g_ClientList.Flink; entry != &g_ClientList; entry = entry->Flink)
    {
        PBK_CLIENT client = CONTAINING_RECORD(entry, BK_CLIENT, Link);
        if (snapshotCount >= RTL_NUMBER_OF(snapshot))
        {
            break;
        }
        BkctlClientReference(client);
        snapshot[snapshotCount++] = client;
    }
    ExReleaseFastMutex(&g_ClientListLock);

    for (i = 0; i < snapshotCount; ++i)
    {
        PBK_CLIENT client = snapshot[i];
        if (BkctlTryAcquireClientLock(client, "pid-interest-fallback"))
        {
            matchedMask |=
                BkctlClientQuerySubscriptionMaskEither(client, PrimaryProcessId, SecondaryProcessId, StreamMask);
            ExReleaseFastMutex(&client->Lock);
        }
        BkctlClientRelease(client);
    }

    return matchedMask & StreamMask;
}

UINT32
BkctlQueryPidInterest(_In_ UINT32 PrimaryProcessId, _In_ UINT32 SecondaryProcessId, _In_ UINT32 StreamMask)
{
    UINT32 matchedMask = 0;
    BOOLEAN useSlowFallback = FALSE;

    if (StreamMask == 0 || PrimaryProcessId == 0)
    {
        return 0;
    }
    if (!BkctlIsArmedFast())
    {
        return 0;
    }

    ExAcquirePushLockSharedEx(&g_BkctlPidInterestLock, 0);
    useSlowFallback = g_BkctlPidInterestOverflow;
    if (!useSlowFallback && g_BkctlPidInterestCount != 0)
    {
        matchedMask = BkctlPidInterestLookupLocked(PrimaryProcessId);
        if (SecondaryProcessId != 0 && SecondaryProcessId != PrimaryProcessId)
        {
            matchedMask |= BkctlPidInterestLookupLocked(SecondaryProcessId);
        }
    }
    ExReleasePushLockSharedEx(&g_BkctlPidInterestLock, 0);

    if (useSlowFallback)
    {
        LONG fallbackCount = InterlockedIncrement(&g_BkctlPidInterestFallbackCounter);
        if (fallbackCount == 1 || ((fallbackCount & 0x3FF) == 0))
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "BK: pid-interest slow fallback count=%ld primaryPid=%lu secondaryPid=%lu streamMask=0x%08X.\n",
                       fallbackCount, PrimaryProcessId, SecondaryProcessId, StreamMask);
        }
        matchedMask = BkctlScanPidInterestSlow(PrimaryProcessId, SecondaryProcessId, StreamMask);
    }

    return matchedMask & StreamMask;
}

BOOLEAN
BkctlBindPendingLaunchProcess(_In_ UINT32 ProcessId, _In_opt_ PCUNICODE_STRING ImagePath)
{
    PBK_CLIENT snapshot[BK_MAX_TOTAL_CLIENTS];
    WCHAR candidateNorm[BK_MAX_IMAGE_PATH_CHARS];
    UINT32 snapshotCount = 0;
    UINT32 i;
    PLIST_ENTRY entry;
    BOOLEAN matchedAny = FALSE;

    if (ProcessId == 0 || ImagePath == NULL || ImagePath->Buffer == NULL || ImagePath->Length == 0)
    {
        return FALSE;
    }
    if (!BkctlIsArmedFast())
    {
        return FALSE;
    }

    BkctlNormalizeUnicodePathForCompare(ImagePath, candidateNorm, RTL_NUMBER_OF(candidateNorm));
    if (candidateNorm[0] == L'\0')
    {
        return FALSE;
    }

    ExAcquireFastMutex(&g_ClientListLock);
    for (entry = g_ClientList.Flink; entry != &g_ClientList; entry = entry->Flink)
    {
        PBK_CLIENT client = CONTAINING_RECORD(entry, BK_CLIENT, Link);
        if (snapshotCount >= RTL_NUMBER_OF(snapshot))
        {
            break;
        }
        BkctlClientReference(client);
        snapshot[snapshotCount++] = client;
    }
    ExReleaseFastMutex(&g_ClientListLock);

    for (i = 0; i < snapshotCount; ++i)
    {
        PBK_CLIENT client = snapshot[i];
        ExAcquireFastMutex(&client->Lock);
        if (BkctlClientPathMatchesPendingLaunchLocked(client, candidateNorm))
        {
            UINT32 streamMask = client->PendingLaunchStreamMask;
            BOOLEAN subscribed = BkctlClientAddOrUpdateSubscriptionLocked(client, ProcessId, streamMask);
            BkctlClientBindAnalysisSubjectLocked(client, ProcessId);

            BkctlClientClearPendingLaunchLocked(client);
            if (subscribed)
            {
                matchedAny = TRUE;
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                           "BK: pending launch bound targetPid=%lu streamMask=0x%08X image=%ws.\n", ProcessId,
                           streamMask, candidateNorm);
            }
            else
            {
                DbgPrintEx(
                    DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                    "BK: pending launch match could not bind targetPid=%lu image=%ws reason=subscription-capacity.\n",
                    ProcessId, candidateNorm);
            }
        }
        ExReleaseFastMutex(&client->Lock);
        BkctlClientRelease(client);
    }

    if (matchedAny)
    {
        BkctlRebuildPidInterestIndex();
        BkctlSetTelemetryArmed(TRUE);
    }

    return matchedAny;
}

BOOLEAN
BkctlMarkAnalysisSubjectImageLoad(_In_ UINT32 ProcessId, _In_opt_ PCUNICODE_STRING ImagePath, _In_ UINT64 ImageBase,
                                  _In_ UINT64 ImageSize)
{
    PBK_CLIENT snapshot[BK_MAX_TOTAL_CLIENTS];
    WCHAR candidateNorm[BK_MAX_IMAGE_PATH_CHARS];
    UINT32 snapshotCount = 0;
    UINT32 i;
    PLIST_ENTRY entry;
    BOOLEAN matchedAny = FALSE;

    if (ProcessId == 0 || ImagePath == NULL || ImagePath->Buffer == NULL || ImagePath->Length == 0)
    {
        return FALSE;
    }
    if (!BkctlIsArmedFast())
    {
        return FALSE;
    }

    BkctlNormalizeUnicodePathForCompare(ImagePath, candidateNorm, RTL_NUMBER_OF(candidateNorm));
    if (candidateNorm[0] == L'\0')
    {
        return FALSE;
    }

    ExAcquireFastMutex(&g_ClientListLock);
    for (entry = g_ClientList.Flink; entry != &g_ClientList; entry = entry->Flink)
    {
        PBK_CLIENT client = CONTAINING_RECORD(entry, BK_CLIENT, Link);
        if (snapshotCount >= RTL_NUMBER_OF(snapshot))
        {
            break;
        }
        BkctlClientReference(client);
        snapshot[snapshotCount++] = client;
    }
    ExReleaseFastMutex(&g_ClientListLock);

    for (i = 0; i < snapshotCount; ++i)
    {
        PBK_CLIENT client = snapshot[i];
        ExAcquireFastMutex(&client->Lock);
        if (client->AnalysisSubjectProcessId == ProcessId &&
            BkctlClientPathMatchesAnalysisSubjectLocked(client, candidateNorm))
        {
            client->AnalysisSubjectImageBase = ImageBase;
            client->AnalysisSubjectImageSize = ImageSize;
            matchedAny = TRUE;
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                       "BK: analysis subject image loaded targetPid=%lu base=0x%llX size=0x%llX image=%ws.\n",
                       ProcessId, ImageBase, ImageSize, candidateNorm);
        }
        ExReleaseFastMutex(&client->Lock);
        BkctlClientRelease(client);
    }

    return matchedAny;
}

static VOID BkctlClientEnqueueEvent(_Inout_ PBK_CLIENT Client, _In_ const BK_EVENT_RECORD *Source)
{
    PBK_EVENT_NODE node;
    LONG dropLogCounter;

    if (Client->QueueDepth >= BK_MAX_CLIENT_QUEUE_DEPTH)
    {
        Client->DroppedEvents += 1;
        dropLogCounter = InterlockedIncrement(&g_ControlQueueDropLogCounter);
        if (dropLogCounter == 1 || ((dropLogCounter & 0xFF) == 0))
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "BK: queue drop (client depth cap=%lu) totalDrops=%lu clientDrops=%u queueDepth=%u.\n",
                       BK_MAX_CLIENT_QUEUE_DEPTH, (ULONG)dropLogCounter, Client->DroppedEvents, Client->QueueDepth);
        }
        return;
    }

    if (!BkctlTryAcquireGlobalQueueSlot())
    {
        Client->DroppedEvents += 1;
        dropLogCounter = InterlockedIncrement(&g_ControlQueueDropLogCounter);
        if (dropLogCounter == 1 || ((dropLogCounter & 0xFF) == 0))
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "BK: queue drop (global cap=%lu) totalDrops=%lu clientDrops=%u globalQueued=%ld.\n",
                       BK_MAX_TOTAL_QUEUED_EVENTS, (ULONG)dropLogCounter, Client->DroppedEvents,
                       InterlockedCompareExchange(&g_ControlTotalQueuedEvents, 0, 0));
        }
        return;
    }

    node = BkctlAllocateEventNode();
    if (node == NULL)
    {
        BkctlReleaseGlobalQueueSlot();
        Client->DroppedEvents += 1;
        dropLogCounter = InterlockedIncrement(&g_ControlQueueDropLogCounter);
        if (dropLogCounter == 1 || ((dropLogCounter & 0xFF) == 0))
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "BK: queue drop (alloc failure) totalDrops=%lu clientDrops=%u queueDepth=%u.\n",
                       (ULONG)dropLogCounter, Client->DroppedEvents, Client->QueueDepth);
        }
        return;
    }

    RtlZeroMemory(node, sizeof(*node));
    RtlCopyMemory(&node->Record, Source, sizeof(node->Record));
    InsertTailList(&Client->EventQueue, &node->Link);
    Client->QueueDepth += 1;
}

static BOOLEAN BkctlClientTryTakePendingGetEventRequestLocked(_In_ PBK_CLIENT Client, _Out_ WDFREQUEST *Request)
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

static NTSTATUS BkctlCompleteGetEventRequestWithRecord(_In_ WDFREQUEST Request, _In_ const BK_EVENT_RECORD *Record)
{
    NTSTATUS status;
    PBK_EVENT_RECORD out;
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
        requesterPid = BkctlGetRequestorPid();
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                   "BK: get-event delivered(pended) requesterPid=%lu deliveredCount=%ld eventType=%lu seq=%lu.\n",
                   requesterPid, deliverCounter, Record->Header.Type, Record->Header.Sequence);
    }

    return STATUS_SUCCESS;
}

VOID BkctlPublishRecordToSubscribers(_In_ UINT32 PrimaryPid, _In_ UINT32 SecondaryPid, _In_ UINT32 StreamMask,
                                     _In_ BK_EVENT_RECORD *Record)
{
    ULONGLONG tempusStartQpc = BktmpEnter(BktmpSubsystemControl);
    PBK_CLIENT snapshot[BK_MAX_TOTAL_CLIENTS];
    UINT32 snapshotCount = 0;
    UINT32 i;
    PLIST_ENTRY e;

    if (InterlockedCompareExchange(&g_ControlInitialized, 0, 0) == 0)
    {
        BktmpLeave(BktmpSubsystemControl, tempusStartQpc);
        return;
    }
    if (BkctlIsShutdown())
    {
        BktmpLeave(BktmpSubsystemControl, tempusStartQpc);
        return;
    }

    ExAcquireFastMutex(&g_ClientListLock);
    for (e = g_ClientList.Flink; e != &g_ClientList; e = e->Flink)
    {
        PBK_CLIENT c = CONTAINING_RECORD(e, BK_CLIENT, Link);
        if (snapshotCount >= RTL_NUMBER_OF(snapshot))
        {
            break;
        }
        BkctlClientReference(c);
        snapshot[snapshotCount++] = c;
    }
    ExReleaseFastMutex(&g_ClientListLock);

    for (i = 0; i < snapshotCount; ++i)
    {
        PBK_CLIENT c = snapshot[i];
        WDFREQUEST pendingRequest = NULL;
        BK_EVENT_RECORD stagedRecord;
        BOOLEAN matched = FALSE;
        NTSTATUS deliverStatus = STATUS_UNSUCCESSFUL;

        RtlZeroMemory(&stagedRecord, sizeof(stagedRecord));
        if (!BkctlTryAcquireClientLock(c, "publish-record"))
        {
            BkctlClientRelease(c);
            continue;
        }
        if (BkctlClientMatchSubscriptionEither(c, PrimaryPid, SecondaryPid, StreamMask))
        {
            matched = TRUE;
            RtlCopyMemory(&stagedRecord, Record, sizeof(stagedRecord));
            stagedRecord.Header.Sequence = ++c->Sequence;

            if (!BkctlClientTryTakePendingGetEventRequestLocked(c, &pendingRequest))
            {
                BkctlClientEnqueueEvent(c, &stagedRecord);
            }
        }
        ExReleaseFastMutex(&c->Lock);

        if (matched && pendingRequest != NULL)
        {
            deliverStatus = BkctlCompleteGetEventRequestWithRecord(pendingRequest, &stagedRecord);
            if (!NT_SUCCESS(deliverStatus) && !BkctlIsShutdown())
            {
                ExAcquireFastMutex(&c->Lock);
                BkctlClientEnqueueEvent(c, &stagedRecord);
                ExReleaseFastMutex(&c->Lock);
            }
        }

        BkctlClientRelease(c);
    }

    BktmpLeave(BktmpSubsystemControl, tempusStartQpc);
}

EVT_WDF_DEVICE_FILE_CREATE BkctlEvtFileCreate;
EVT_WDF_FILE_CLEANUP BkctlEvtFileCleanup;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL BkctlEvtIoDeviceControl;

_Use_decl_annotations_ VOID BkctlEvtFileCreate(WDFDEVICE Device, WDFREQUEST Request, WDFFILEOBJECT FileObject)
{
    PBK_FILE_CONTEXT ctx;
    PBK_CLIENT client;
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
    if (BkctlIsShutdown())
    {
        WdfRequestComplete(Request, STATUS_DELETE_PENDING);
        return;
    }

    client = BkctlClientCreate();
    if (client == NULL)
    {
        WdfRequestComplete(Request, STATUS_INSUFFICIENT_RESOURCES);
        return;
    }

    ExAcquireFastMutex(&g_ClientListLock);
    if (g_ClientCount >= BK_MAX_TOTAL_CLIENTS)
    {
        ExReleaseFastMutex(&g_ClientListLock);
        BkctlClientRelease(client);
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
        BkctlClientRelease(client);
        WdfRequestComplete(Request, queueStatus);
        return;
    }
    client->PendingGetEventQueue = pendingQueue;

    ctx = BkctlGetFileContext(FileObject);
    ctx->Client = client;

    requesterPid = BkctlGetRequestorPid();
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "BK: client attached pid=%lu activeClients=%ld fileObj=0x%p.\n",
               requesterPid, clientCountSnapshot, FileObject);

    WdfRequestComplete(Request, STATUS_SUCCESS);
}

_Use_decl_annotations_ VOID BkctlEvtFileCleanup(WDFFILEOBJECT FileObject)
{
    PBK_FILE_CONTEXT ctx = BkctlGetFileContext(FileObject);
    PBK_CLIENT client = ctx->Client;
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
        if (CONTAINING_RECORD(e, BK_CLIENT, Link) == client)
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

    BkctlRebuildPidInterestIndex();
    if (clientCountSnapshot == 0)
    {
        BkctlSetTelemetryArmed(FALSE);
    }
    else
    {
        BkctlRefreshArmedState();
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
    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "BK: client detached pid=%lu activeClients=%ld subscriptions=%lu queueDepth=%lu dropped=%lu fileObj=0x%p.\n",
        requesterPid, clientCountSnapshot, subscriptionCountSnapshot, queueDepthSnapshot, droppedSnapshot, FileObject);

    BkctlClientRelease(client);
    ctx->Client = NULL;
}
