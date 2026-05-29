#include "diagnostics.h"

static volatile LONG g_BkdiagInitialized = 0;
static UINT64 g_BkdiagQpcFrequency = 1;
static volatile LONG64 g_BkdiagLastSequence = 0;
static KSPIN_LOCK g_BkdiagRingLock;
static BK_DIAGNOSTIC_EVENT g_BkdiagRing[BK_DIAGNOSTIC_MAX_EVENTS];

static ULONGLONG BkdiagQueryQpc(VOID)
{
    LARGE_INTEGER qpc;

    qpc = KeQueryPerformanceCounter(NULL);
    return (ULONGLONG)qpc.QuadPart;
}

static UINT32 BkdiagSaturatingOverwriteCount(_In_ UINT64 Sequence)
{
    UINT64 overwritten;

    if (Sequence <= BK_DIAGNOSTIC_MAX_EVENTS)
    {
        return 0;
    }

    overwritten = Sequence - BK_DIAGNOSTIC_MAX_EVENTS;
    return overwritten > MAXULONG ? MAXULONG : (UINT32)overwritten;
}

NTSTATUS
BkdiagInitialize(VOID)
{
    LARGE_INTEGER frequency;

    if (InterlockedCompareExchange(&g_BkdiagInitialized, 1, 0) != 0)
    {
        return STATUS_SUCCESS;
    }

    (void)KeQueryPerformanceCounter(&frequency);
    KeInitializeSpinLock(&g_BkdiagRingLock);
    RtlZeroMemory(g_BkdiagRing, sizeof(g_BkdiagRing));
    g_BkdiagQpcFrequency = frequency.QuadPart > 0 ? (UINT64)frequency.QuadPart : 1;
    InterlockedExchange64(&g_BkdiagLastSequence, 0);
    return STATUS_SUCCESS;
}

VOID BkdiagUninitialize(VOID)
{
    InterlockedExchange(&g_BkdiagInitialized, 0);
}

BOOLEAN
BkdiagSelfCheck(VOID)
{
    return (InterlockedCompareExchange(&g_BkdiagInitialized, 0, 0) != 0 && g_BkdiagQpcFrequency != 0);
}

ULONGLONG
BkdiagBegin(_In_ UINT32 SubsystemId, _In_ UINT32 EventType, _In_ UINT32 ComponentId)
{
    if (KeGetCurrentIrql() > DISPATCH_LEVEL)
    {
        return 0;
    }

    UNREFERENCED_PARAMETER(SubsystemId);
    UNREFERENCED_PARAMETER(EventType);
    UNREFERENCED_PARAMETER(ComponentId);

    return BkdiagQueryQpc();
}

VOID BkdiagComplete(_In_ UINT32 SubsystemId, _In_ UINT32 EventType, _In_ NTSTATUS Status, _In_ ULONGLONG StartQpc,
                    _In_ UINT32 Flags, _In_ UINT32 DetailCode, _In_ UINT32 ComponentId)
{
    ULONGLONG nowQpc;
    UINT64 elapsedQpc;

    if (StartQpc == 0 || KeGetCurrentIrql() > DISPATCH_LEVEL)
    {
        return;
    }

    nowQpc = BkdiagQueryQpc();
    elapsedQpc = nowQpc >= StartQpc ? (UINT64)(nowQpc - StartQpc) : 0;
    BkdiagRecord(SubsystemId, EventType, Status, elapsedQpc, Flags, DetailCode, ComponentId);
}

VOID BkdiagRecord(_In_ UINT32 SubsystemId, _In_ UINT32 EventType, _In_ NTSTATUS Status, _In_ UINT64 ElapsedQpc,
                  _In_ UINT32 Flags, _In_ UINT32 DetailCode, _In_ UINT32 ComponentId)
{
    BK_DIAGNOSTIC_EVENT event;
    UINT64 sequence;
    UINT32 index;
    BK_DIAGNOSTIC_EVENT *slot;
    KIRQL oldIrql;

    if (InterlockedCompareExchange(&g_BkdiagInitialized, 0, 0) == 0)
    {
        return;
    }
    if (KeGetCurrentIrql() > DISPATCH_LEVEL)
    {
        return;
    }

    RtlZeroMemory(&event, sizeof(event));
    event.TimestampQpc = (INT64)BkdiagQueryQpc();
    event.ElapsedQpc = ElapsedQpc;
    event.SubsystemId = SubsystemId;
    event.EventType = EventType;
    event.Status = (INT32)Status;
    event.Flags = Flags;
    event.DetailCode = DetailCode;
    event.ComponentId = ComponentId;

    KeAcquireSpinLock(&g_BkdiagRingLock, &oldIrql);
    sequence = (UINT64)InterlockedIncrement64(&g_BkdiagLastSequence);
    index = (UINT32)((sequence - 1) % BK_DIAGNOSTIC_MAX_EVENTS);
    slot = &g_BkdiagRing[index];

    event.Sequence = sequence;
    slot->Sequence = 0;
    *slot = event;
    KeMemoryBarrier();
    slot->Sequence = sequence;
    KeReleaseSpinLock(&g_BkdiagRingLock, oldIrql);
}

VOID BkdiagQuery(_Out_ PBK_DIAGNOSTICS_RESPONSE Response)
{
    UINT64 nextSequence;
    UINT64 oldestSequence;
    UINT64 lastSequence;
    UINT32 count;
    UINT32 i;
    UINT32 copied;
    UINT64 sequence;
    UINT32 index;
    KIRQL oldIrql;

    if (Response == NULL)
    {
        return;
    }

    RtlZeroMemory(Response, sizeof(*Response));
    if (InterlockedCompareExchange(&g_BkdiagInitialized, 0, 0) == 0)
    {
        return;
    }

    KeAcquireSpinLock(&g_BkdiagRingLock, &oldIrql);
    lastSequence = (UINT64)InterlockedCompareExchange64(&g_BkdiagLastSequence, 0, 0);
    nextSequence = lastSequence + 1;
    count = lastSequence > BK_DIAGNOSTIC_MAX_EVENTS ? BK_DIAGNOSTIC_MAX_EVENTS : (UINT32)lastSequence;

    oldestSequence = (nextSequence > count) ? (nextSequence - count) : 1;
    Response->QpcFrequency = g_BkdiagQpcFrequency;
    Response->OldestSequence = oldestSequence;
    Response->NextSequence = nextSequence;
    Response->DroppedCount = BkdiagSaturatingOverwriteCount(lastSequence);
    copied = 0;
    for (i = 0; i < count; ++i)
    {
        sequence = oldestSequence + i;
        index = (UINT32)((sequence - 1) % BK_DIAGNOSTIC_MAX_EVENTS);
        if (g_BkdiagRing[index].Sequence != sequence)
        {
            continue;
        }

        Response->Events[copied++] = g_BkdiagRing[index];
    }
    KeReleaseSpinLock(&g_BkdiagRingLock, oldIrql);
    Response->EventCount = copied;
}
