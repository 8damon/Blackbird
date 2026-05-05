#include <ntddk.h>
#include "qpc_timing.h"
#include "..\core\control.h"
#include "..\core\runtime_config.h"

#define BK_QPC_MAX_THREAD_SLOTS 1024u
#define BK_QPC_MAX_PROCESS_SLOTS 256u
#define BK_QPC_DEFAULT_PAIR_WINDOW_MS 50u
#define BK_QPC_DEFAULT_MAX_CORRECTION_US 2000u
#define BK_QPC_TIGHT_PAIR_MAX_DELTA_US 2000u
#define BK_QPC_TIGHT_PAIR_CLAMP_FLOOR_US 1000u
#define BK_QPC_TIGHT_PAIR_MIN_SAMPLES 16u
#define BK_QPC_TIGHT_PAIR_BASELINE_WEIGHT 15
#define BK_QPC_TIGHT_PAIR_BASELINE_DIVISOR 16
#define BK_QPC_TIGHT_PAIR_OUTLIER_MULTIPLIER 8

typedef struct _BK_QPC_THREAD_SLOT
{
    BOOLEAN Active;
    UINT8 Reserved0[3];
    UINT32 ProcessId;
    UINT32 ThreadId;
    INT64 LastRawTicks;
    INT64 LastVirtualTicks;
    INT64 CumulativeCorrectionTicks;
    INT64 AppliedPauseTicks;
    INT64 PendingBlackbirdTicks;
    INT64 TightPairBaselineTicks;
    UINT32 TightPairSampleCount;
    UINT32 ConsecutiveTightPairs;
    UINT64 LastSeenTick;
} BK_QPC_THREAD_SLOT, *PBK_QPC_THREAD_SLOT;

typedef struct _BK_QPC_PROCESS_SLOT
{
    BOOLEAN Active;
    BOOLEAN Suspended;
    UINT8 Reserved0[2];
    UINT32 ProcessId;
    INT64 SuspendStartTicks;
    INT64 TotalPauseTicks;
    UINT64 LastSeenTick;
} BK_QPC_PROCESS_SLOT, *PBK_QPC_PROCESS_SLOT;

static FAST_MUTEX g_QpcLock;
static volatile LONG g_QpcInitialized = 0;
static UINT32 g_QpcPairWindowMs = BK_QPC_DEFAULT_PAIR_WINDOW_MS;
static UINT32 g_QpcMaxCorrectionUs = BK_QPC_DEFAULT_MAX_CORRECTION_US;
static UINT32 g_QpcConfigFlags = BK_QPC_TIMING_CONFIG_FLAG_ENABLED;
static INT64 g_QpcManualBiasTicks = 0;
static INT64 g_QpcAutoBiasTicks = 0;
static INT64 g_QpcFrequencyTicks = 0;
static volatile LONG64 g_QpcAgingTick = 0;
static BK_QPC_THREAD_SLOT g_QpcThreadSlots[BK_QPC_MAX_THREAD_SLOTS];
static BK_QPC_PROCESS_SLOT g_QpcProcessSlots[BK_QPC_MAX_PROCESS_SLOTS];
static volatile LONG64 g_QpcQueryCount = 0;
static volatile LONG64 g_QpcPairCount = 0;
static volatile LONG64 g_QpcCorrectedCount = 0;
static volatile LONG64 g_QpcTotalCorrectionTicks = 0;
static volatile LONG64 g_QpcPauseCorrectionTicks = 0;
static volatile LONG64 g_QpcLastCorrectionTicks = 0;

static INT64 BkqpcClampPositiveI64(_In_ INT64 Value)
{
    return Value > 0 ? Value : 0;
}

static INT64 BkqpcMaxI64(_In_ INT64 Left, _In_ INT64 Right)
{
    return Left > Right ? Left : Right;
}

static INT64 BkqpcUsToTicks(_In_ UINT32 Microseconds, _In_ INT64 Frequency)
{
    if (Microseconds == 0 || Frequency <= 0)
    {
        return 0;
    }

    return (INT64)(((UINT64)Frequency * (UINT64)Microseconds) / 1000000ull);
}

static INT64 BkqpcMsToTicks(_In_ UINT32 Milliseconds, _In_ INT64 Frequency)
{
    if (Milliseconds == 0 || Frequency <= 0)
    {
        return 0;
    }

    return (INT64)(((UINT64)Frequency * (UINT64)Milliseconds) / 1000ull);
}

static INT64 BkqpcCurrentTicks(VOID)
{
    return KeQueryPerformanceCounter(NULL).QuadPart;
}

static VOID BkqpcResetTightPairProfileLocked(_Inout_ PBK_QPC_THREAD_SLOT Slot)
{
    if (Slot == NULL)
    {
        return;
    }

    Slot->TightPairBaselineTicks = 0;
    Slot->TightPairSampleCount = 0;
    Slot->ConsecutiveTightPairs = 0;
}

static VOID BkqpcRecordTightPairSampleLocked(_Inout_ PBK_QPC_THREAD_SLOT Slot, _In_ INT64 RawDelta)
{
    if (Slot == NULL || RawDelta <= 0)
    {
        return;
    }

    if (Slot->TightPairBaselineTicks <= 0)
    {
        Slot->TightPairBaselineTicks = RawDelta;
    }
    else
    {
        Slot->TightPairBaselineTicks = ((Slot->TightPairBaselineTicks * BK_QPC_TIGHT_PAIR_BASELINE_WEIGHT) + RawDelta) /
                                       BK_QPC_TIGHT_PAIR_BASELINE_DIVISOR;
        if (Slot->TightPairBaselineTicks <= 0)
        {
            Slot->TightPairBaselineTicks = RawDelta;
        }
    }

    if (Slot->TightPairSampleCount < (UINT32)-1)
    {
        Slot->TightPairSampleCount += 1;
    }
    if (Slot->ConsecutiveTightPairs < (UINT32)-1)
    {
        Slot->ConsecutiveTightPairs += 1;
    }
}

static INT64 BkqpcComputeTightPairClampLocked(_In_ const BK_QPC_THREAD_SLOT *Slot, _In_ INT64 RawDelta,
                                              _In_ INT64 ClampFloorTicks)
{
    INT64 targetDelta;

    if (Slot == NULL || RawDelta <= 0 || Slot->TightPairSampleCount < BK_QPC_TIGHT_PAIR_MIN_SAMPLES ||
        Slot->ConsecutiveTightPairs < BK_QPC_TIGHT_PAIR_MIN_SAMPLES || Slot->TightPairBaselineTicks <= 0)
    {
        return 0;
    }

    targetDelta = Slot->TightPairBaselineTicks * BK_QPC_TIGHT_PAIR_OUTLIER_MULTIPLIER;
    targetDelta = BkqpcMaxI64(targetDelta, ClampFloorTicks);
    if (targetDelta <= 0)
    {
        targetDelta = 1;
    }
    if (RawDelta <= targetDelta)
    {
        return 0;
    }

    return RawDelta - targetDelta;
}

static UINT32 BkqpcFindThreadSlotLocked(_In_ UINT32 ProcessId, _In_ UINT32 ThreadId, _In_ BOOLEAN Create)
{
    UINT32 i;
    UINT32 freeIndex = BK_QPC_MAX_THREAD_SLOTS;
    UINT32 oldestIndex = 0;
    UINT64 oldestSeen = (UINT64)-1;

    for (i = 0; i < BK_QPC_MAX_THREAD_SLOTS; ++i)
    {
        PBK_QPC_THREAD_SLOT slot = &g_QpcThreadSlots[i];
        if (!slot->Active)
        {
            if (freeIndex == BK_QPC_MAX_THREAD_SLOTS)
            {
                freeIndex = i;
            }
            continue;
        }

        if (slot->ProcessId == ProcessId && slot->ThreadId == ThreadId)
        {
            return i;
        }

        if (slot->LastSeenTick < oldestSeen)
        {
            oldestSeen = slot->LastSeenTick;
            oldestIndex = i;
        }
    }

    if (!Create)
    {
        return BK_QPC_MAX_THREAD_SLOTS;
    }

    if (freeIndex != BK_QPC_MAX_THREAD_SLOTS)
    {
        oldestIndex = freeIndex;
    }

    RtlZeroMemory(&g_QpcThreadSlots[oldestIndex], sizeof(g_QpcThreadSlots[oldestIndex]));
    g_QpcThreadSlots[oldestIndex].ProcessId = ProcessId;
    g_QpcThreadSlots[oldestIndex].ThreadId = ThreadId;
    g_QpcThreadSlots[oldestIndex].Active = TRUE;
    return oldestIndex;
}

static UINT32 BkqpcFindProcessSlotLocked(_In_ UINT32 ProcessId, _In_ BOOLEAN Create)
{
    UINT32 i;
    UINT32 freeIndex = BK_QPC_MAX_PROCESS_SLOTS;
    UINT32 oldestIndex = 0;
    UINT64 oldestSeen = (UINT64)-1;

    for (i = 0; i < BK_QPC_MAX_PROCESS_SLOTS; ++i)
    {
        PBK_QPC_PROCESS_SLOT slot = &g_QpcProcessSlots[i];
        if (!slot->Active)
        {
            if (freeIndex == BK_QPC_MAX_PROCESS_SLOTS)
            {
                freeIndex = i;
            }
            continue;
        }

        if (slot->ProcessId == ProcessId)
        {
            return i;
        }

        if (slot->LastSeenTick < oldestSeen)
        {
            oldestSeen = slot->LastSeenTick;
            oldestIndex = i;
        }
    }

    if (!Create)
    {
        return BK_QPC_MAX_PROCESS_SLOTS;
    }

    if (freeIndex != BK_QPC_MAX_PROCESS_SLOTS)
    {
        oldestIndex = freeIndex;
    }

    RtlZeroMemory(&g_QpcProcessSlots[oldestIndex], sizeof(g_QpcProcessSlots[oldestIndex]));
    g_QpcProcessSlots[oldestIndex].ProcessId = ProcessId;
    g_QpcProcessSlots[oldestIndex].Active = TRUE;
    return oldestIndex;
}

static BOOLEAN BkqpcRuntimeEnabledForPid(_In_ UINT32 ProcessId)
{
    if (ProcessId == 0 || KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        return FALSE;
    }
    if (InterlockedCompareExchange(&g_QpcInitialized, 0, 0) == 0 ||
        ((g_QpcConfigFlags & BK_QPC_TIMING_CONFIG_FLAG_ENABLED) == 0) || !BkrtIsQpcTimingCompensationEnabled() ||
        !BkctlIsArmedFast())
    {
        return FALSE;
    }

    return BkctlHasPidInterest(ProcessId, 0, BK_STREAM_TIMING);
}

NTSTATUS BkqpcInitialize(VOID)
{
    LARGE_INTEGER frequency;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        return STATUS_INVALID_DEVICE_STATE;
    }

    ExInitializeFastMutex(&g_QpcLock);
    RtlZeroMemory(g_QpcThreadSlots, sizeof(g_QpcThreadSlots));
    RtlZeroMemory(g_QpcProcessSlots, sizeof(g_QpcProcessSlots));
    frequency.QuadPart = 0;
    (void)KeQueryPerformanceCounter(&frequency);
    g_QpcFrequencyTicks = frequency.QuadPart;
    g_QpcPairWindowMs = BK_QPC_DEFAULT_PAIR_WINDOW_MS;
    g_QpcMaxCorrectionUs = BK_QPC_DEFAULT_MAX_CORRECTION_US;
    g_QpcConfigFlags = BK_QPC_TIMING_CONFIG_FLAG_ENABLED;
    g_QpcManualBiasTicks = 0;
    g_QpcAutoBiasTicks = 0;
    InterlockedExchange64(&g_QpcAgingTick, 0);
    InterlockedExchange64(&g_QpcQueryCount, 0);
    InterlockedExchange64(&g_QpcPairCount, 0);
    InterlockedExchange64(&g_QpcCorrectedCount, 0);
    InterlockedExchange64(&g_QpcTotalCorrectionTicks, 0);
    InterlockedExchange64(&g_QpcPauseCorrectionTicks, 0);
    InterlockedExchange64(&g_QpcLastCorrectionTicks, 0);
    InterlockedExchange(&g_QpcInitialized, 1);
    return STATUS_SUCCESS;
}

VOID BkqpcUninitialize(VOID)
{
    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        return;
    }

    InterlockedExchange(&g_QpcInitialized, 0);
    ExAcquireFastMutex(&g_QpcLock);
    RtlZeroMemory(g_QpcThreadSlots, sizeof(g_QpcThreadSlots));
    RtlZeroMemory(g_QpcProcessSlots, sizeof(g_QpcProcessSlots));
    ExReleaseFastMutex(&g_QpcLock);
}

NTSTATUS BkqpcSetConfig(_In_ const BK_QPC_TIMING_CONFIG *Config)
{
    UINT32 flags;
    UINT32 mask;

    if (Config == NULL || KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (InterlockedCompareExchange(&g_QpcInitialized, 0, 0) == 0)
    {
        return STATUS_DEVICE_NOT_READY;
    }

    flags = Config->Flags & (BK_QPC_TIMING_CONFIG_FLAG_ENABLED | BK_QPC_TIMING_CONFIG_FLAG_MANUAL_BIAS);
    mask = Config->Mask & (BK_QPC_TIMING_CONFIG_FLAG_ENABLED | BK_QPC_TIMING_CONFIG_FLAG_MANUAL_BIAS);

    ExAcquireFastMutex(&g_QpcLock);
    g_QpcConfigFlags = (g_QpcConfigFlags & ~mask) | (flags & mask);
    if (Config->PairWindowMs != 0)
    {
        g_QpcPairWindowMs = Config->PairWindowMs > 1000u ? 1000u : Config->PairWindowMs;
    }
    if (Config->MaxCorrectionUs != 0)
    {
        g_QpcMaxCorrectionUs = Config->MaxCorrectionUs > 1000000u ? 1000000u : Config->MaxCorrectionUs;
    }
    g_QpcManualBiasTicks = Config->ManualBiasTicks;
    ExReleaseFastMutex(&g_QpcLock);
    return STATUS_SUCCESS;
}

VOID BkqpcQueryState(_Out_ BK_QPC_TIMING_STATE *State)
{
    UINT32 i;
    UINT32 active = 0;

    if (State == NULL)
    {
        return;
    }

    RtlZeroMemory(State, sizeof(*State));
    if (KeGetCurrentIrql() != PASSIVE_LEVEL || InterlockedCompareExchange(&g_QpcInitialized, 0, 0) == 0)
    {
        return;
    }

    ExAcquireFastMutex(&g_QpcLock);
    for (i = 0; i < BK_QPC_MAX_THREAD_SLOTS; ++i)
    {
        if (g_QpcThreadSlots[i].Active)
        {
            active += 1;
        }
    }
    State->Flags = g_QpcConfigFlags;
    State->PairWindowMs = g_QpcPairWindowMs;
    State->MaxCorrectionUs = g_QpcMaxCorrectionUs;
    State->ActiveThreadSlots = active;
    State->ManualBiasTicks = g_QpcManualBiasTicks;
    State->AutoBiasTicks = g_QpcAutoBiasTicks;
    State->Frequency = (UINT64)g_QpcFrequencyTicks;
    ExReleaseFastMutex(&g_QpcLock);

    State->QueryCount = (UINT64)InterlockedCompareExchange64(&g_QpcQueryCount, 0, 0);
    State->PairCount = (UINT64)InterlockedCompareExchange64(&g_QpcPairCount, 0, 0);
    State->CorrectedCount = (UINT64)InterlockedCompareExchange64(&g_QpcCorrectedCount, 0, 0);
    State->TotalCorrectionTicks = (UINT64)InterlockedCompareExchange64(&g_QpcTotalCorrectionTicks, 0, 0);
    State->PauseCorrectionTicks = (UINT64)InterlockedCompareExchange64(&g_QpcPauseCorrectionTicks, 0, 0);
    State->LastCorrectionTicks = (UINT64)InterlockedCompareExchange64(&g_QpcLastCorrectionTicks, 0, 0);
}

BOOLEAN BkqpcApplyTimingAdjustment(_In_ UINT32 ProcessId, _In_ UINT32 ThreadId, _In_ LARGE_INTEGER RawCounter,
                                   _In_ LARGE_INTEGER Frequency, _Out_ LARGE_INTEGER *VirtualCounter,
                                   _Out_opt_ BK_QPC_TIMING_APPLY_INFO *Info)
{
    UINT32 threadIndex;
    UINT32 processIndex;
    UINT64 seenTick;
    INT64 frequency;
    INT64 pairWindowTicks;
    INT64 maxCorrectionTicks;
    INT64 tightPairMaxTicks;
    INT64 tightPairClampFloorTicks;
    INT64 rawTicks;
    INT64 rawDelta = 0;
    INT64 virtualDelta = 0;
    INT64 pauseCorrection = 0;
    INT64 pairCorrection = 0;
    INT64 pairOutlierCorrection = 0;
    INT64 correctionDelta = 0;
    INT64 biasTicks = 0;
    INT64 candidateCumulative;
    INT64 virtualTicks;
    UINT32 sourceFlags = 0;
    BOOLEAN pairMatched = FALSE;
    PBK_QPC_THREAD_SLOT slot;

    if (VirtualCounter == NULL)
    {
        return FALSE;
    }
    VirtualCounter->QuadPart = RawCounter.QuadPart;
    if (Info != NULL)
    {
        RtlZeroMemory(Info, sizeof(*Info));
    }

    if (!BkqpcRuntimeEnabledForPid(ProcessId))
    {
        return FALSE;
    }

    frequency = Frequency.QuadPart > 0 ? Frequency.QuadPart : g_QpcFrequencyTicks;
    if (frequency <= 0)
    {
        return FALSE;
    }

    rawTicks = RawCounter.QuadPart;
    pairWindowTicks = BkqpcMsToTicks(g_QpcPairWindowMs, frequency);
    maxCorrectionTicks = BkqpcUsToTicks(g_QpcMaxCorrectionUs, frequency);
    tightPairMaxTicks = BkqpcUsToTicks(BK_QPC_TIGHT_PAIR_MAX_DELTA_US, frequency);
    tightPairClampFloorTicks = BkqpcUsToTicks(BK_QPC_TIGHT_PAIR_CLAMP_FLOOR_US, frequency);
    if (tightPairMaxTicks <= 0)
    {
        tightPairMaxTicks = 1;
    }
    if (tightPairClampFloorTicks <= 0)
    {
        tightPairClampFloorTicks = 1;
    }
    seenTick = (UINT64)InterlockedIncrement64(&g_QpcAgingTick);

    ExAcquireFastMutex(&g_QpcLock);
    threadIndex = BkqpcFindThreadSlotLocked(ProcessId, ThreadId, TRUE);
    if (threadIndex == BK_QPC_MAX_THREAD_SLOTS)
    {
        ExReleaseFastMutex(&g_QpcLock);
        return FALSE;
    }

    slot = &g_QpcThreadSlots[threadIndex];
    slot->LastSeenTick = seenTick;
    InterlockedIncrement64(&g_QpcQueryCount);

    processIndex = BkqpcFindProcessSlotLocked(ProcessId, FALSE);
    if (processIndex != BK_QPC_MAX_PROCESS_SLOTS)
    {
        PBK_QPC_PROCESS_SLOT processSlot = &g_QpcProcessSlots[processIndex];
        processSlot->LastSeenTick = seenTick;
        if (processSlot->TotalPauseTicks > slot->AppliedPauseTicks)
        {
            pauseCorrection = processSlot->TotalPauseTicks - slot->AppliedPauseTicks;
            slot->AppliedPauseTicks = processSlot->TotalPauseTicks;
            sourceFlags |= BK_QPC_TIMING_SOURCE_SUSPEND_PAUSE;
        }
    }

    if (slot->LastRawTicks != 0 && rawTicks >= slot->LastRawTicks)
    {
        rawDelta = rawTicks - slot->LastRawTicks;
        pairMatched = (rawDelta > 0 && rawDelta <= pairWindowTicks);
    }

    if (pairMatched)
    {
        INT64 pendingBlackbird = BkqpcClampPositiveI64(slot->PendingBlackbirdTicks);
        INT64 availablePairCorrection = rawDelta > 1 ? rawDelta - 1 : 0;

        if (pendingBlackbird > 0)
        {
            pairCorrection += pendingBlackbird;
            sourceFlags |= BK_QPC_TIMING_SOURCE_BLACKBIRD_OVERHEAD;
        }

        if ((g_QpcConfigFlags & BK_QPC_TIMING_CONFIG_FLAG_MANUAL_BIAS) != 0)
        {
            biasTicks = BkqpcClampPositiveI64(g_QpcManualBiasTicks);
            if (biasTicks > 0)
            {
                sourceFlags |= BK_QPC_TIMING_SOURCE_MANUAL_BIAS;
            }
        }
        else
        {
            biasTicks = BkqpcClampPositiveI64(g_QpcAutoBiasTicks);
            if (biasTicks > 0)
            {
                sourceFlags |= BK_QPC_TIMING_SOURCE_AUTO_BIAS;
            }
        }

        pairCorrection += biasTicks;
        if (maxCorrectionTicks > 0 && pairCorrection > maxCorrectionTicks)
        {
            pairCorrection = maxCorrectionTicks;
        }
        if (rawDelta <= tightPairMaxTicks)
        {
            BkqpcRecordTightPairSampleLocked(slot, rawDelta);
        }
        else
        {
            pairOutlierCorrection = BkqpcComputeTightPairClampLocked(slot, rawDelta, tightPairClampFloorTicks);
            if (pairOutlierCorrection > 0)
            {
                if (pairOutlierCorrection > pairCorrection)
                {
                    pairCorrection = pairOutlierCorrection;
                }
                sourceFlags |= BK_QPC_TIMING_SOURCE_TIGHT_PAIR_CLAMP;
            }
            else
            {
                slot->ConsecutiveTightPairs = 0;
            }
        }
        if (pairCorrection > availablePairCorrection)
        {
            pairCorrection = availablePairCorrection;
        }
        sourceFlags |= BK_QPC_TIMING_SOURCE_PAIR_MATCH;
        InterlockedIncrement64(&g_QpcPairCount);
    }
    else
    {
        BkqpcResetTightPairProfileLocked(slot);
    }

    slot->PendingBlackbirdTicks = 0;
    correctionDelta = pauseCorrection + pairCorrection;
    candidateCumulative = slot->CumulativeCorrectionTicks + correctionDelta;
    virtualTicks = rawTicks - candidateCumulative;

    if (slot->LastVirtualTicks != 0 && virtualTicks <= slot->LastVirtualTicks)
    {
        if (rawTicks > slot->LastVirtualTicks)
        {
            virtualTicks = slot->LastVirtualTicks + 1;
            candidateCumulative = rawTicks - virtualTicks;
        }
        else
        {
            virtualTicks = slot->LastVirtualTicks;
            candidateCumulative = rawTicks - virtualTicks;
        }
        sourceFlags |= BK_QPC_TIMING_SOURCE_MONOTONIC_CLAMP;
    }

    correctionDelta = candidateCumulative - slot->CumulativeCorrectionTicks;
    if (correctionDelta < 0)
    {
        correctionDelta = 0;
    }

    slot->CumulativeCorrectionTicks = candidateCumulative;
    if (slot->LastVirtualTicks != 0 && virtualTicks >= slot->LastVirtualTicks)
    {
        virtualDelta = virtualTicks - slot->LastVirtualTicks;
    }
    slot->LastRawTicks = rawTicks;
    slot->LastVirtualTicks = virtualTicks;
    VirtualCounter->QuadPart = virtualTicks;

    if (correctionDelta > 0 || (sourceFlags & BK_QPC_TIMING_SOURCE_MONOTONIC_CLAMP) != 0)
    {
        InterlockedIncrement64(&g_QpcCorrectedCount);
        InterlockedAdd64(&g_QpcTotalCorrectionTicks, correctionDelta);
        InterlockedExchange64(&g_QpcLastCorrectionTicks, correctionDelta);
        if (pauseCorrection > 0)
        {
            InterlockedAdd64(&g_QpcPauseCorrectionTicks, pauseCorrection);
        }
    }

    if (Info != NULL)
    {
        Info->RawDeltaTicks = (UINT64)rawDelta;
        Info->VirtualDeltaTicks = (UINT64)virtualDelta;
        Info->CorrectionTicks = correctionDelta;
        Info->SourceFlags = sourceFlags;
        Info->AutoBiasTicks = g_QpcAutoBiasTicks;
    }
    ExReleaseFastMutex(&g_QpcLock);

    return (VirtualCounter->QuadPart != RawCounter.QuadPart ||
            (sourceFlags & BK_QPC_TIMING_SOURCE_MONOTONIC_CLAMP) != 0);
}

VOID BkqpcRecordPostQueryOverhead(_In_ UINT32 ProcessId, _In_ UINT32 ThreadId, _In_ INT64 OverheadTicks)
{
    UINT32 threadIndex;
    INT64 maxCorrectionTicks;
    INT64 overhead;
    INT64 oldBias;

    overhead = BkqpcClampPositiveI64(OverheadTicks);
    if (overhead == 0 || !BkqpcRuntimeEnabledForPid(ProcessId))
    {
        return;
    }

    maxCorrectionTicks = BkqpcUsToTicks(g_QpcMaxCorrectionUs, g_QpcFrequencyTicks);
    if (maxCorrectionTicks > 0 && overhead > maxCorrectionTicks)
    {
        overhead = maxCorrectionTicks;
    }

    ExAcquireFastMutex(&g_QpcLock);
    threadIndex = BkqpcFindThreadSlotLocked(ProcessId, ThreadId, FALSE);
    if (threadIndex != BK_QPC_MAX_THREAD_SLOTS)
    {
        g_QpcThreadSlots[threadIndex].PendingBlackbirdTicks = overhead;
    }

    oldBias = g_QpcAutoBiasTicks;
    if (oldBias <= 0)
    {
        g_QpcAutoBiasTicks = overhead / 2;
    }
    else
    {
        g_QpcAutoBiasTicks = ((oldBias * 7) + (overhead / 2)) / 8;
    }
    ExReleaseFastMutex(&g_QpcLock);
}

VOID BkqpcNotifyProcessExecutionControl(_In_ UINT32 ProcessId, _In_ BOOLEAN Suspend)
{
    UINT32 processIndex;
    INT64 nowTicks;

    if (ProcessId == 0 || KeGetCurrentIrql() != PASSIVE_LEVEL ||
        InterlockedCompareExchange(&g_QpcInitialized, 0, 0) == 0)
    {
        return;
    }

    nowTicks = BkqpcCurrentTicks();
    ExAcquireFastMutex(&g_QpcLock);
    processIndex = BkqpcFindProcessSlotLocked(ProcessId, TRUE);
    if (processIndex != BK_QPC_MAX_PROCESS_SLOTS)
    {
        PBK_QPC_PROCESS_SLOT slot = &g_QpcProcessSlots[processIndex];
        slot->LastSeenTick = (UINT64)InterlockedIncrement64(&g_QpcAgingTick);
        if (Suspend)
        {
            if (!slot->Suspended)
            {
                slot->Suspended = TRUE;
                slot->SuspendStartTicks = nowTicks;
            }
        }
        else if (slot->Suspended)
        {
            INT64 delta = nowTicks - slot->SuspendStartTicks;
            if (delta > 0)
            {
                slot->TotalPauseTicks += delta;
            }
            slot->Suspended = FALSE;
            slot->SuspendStartTicks = 0;
        }
    }
    ExReleaseFastMutex(&g_QpcLock);
}
