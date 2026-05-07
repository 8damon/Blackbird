#include "../controller_private.h"
#include "heuristics.h"
#include <math.h>
#include <limits.h>

#define HEUR_LEDGER_SLOTS 128u
#define HEUR_EVENT_SLOTS 64u
#define HEUR_WINDOW_MS 60000u
#define HEUR_SHELLCODE_WIN_MS 30000u
#define HEUR_BEACON_MIN_OBS 4u
#define HEUR_BEACON_MAX_SLOTS 16u
#define HEUR_BEACON_MIN_ITVL_MS 1000u
#define HEUR_BEACON_MAX_ITVL_MS 300000u
#define HEUR_BEACON_VAR_THRESH 0.30
#define HEUR_COOLDOWN_AGG_MS 30000u
#define HEUR_COOLDOWN_SHELL_MS 20000u
#define HEUR_COOLDOWN_BEACON_MS 60000u
#define HEUR_COOLDOWN_DNS_TUNNEL_MS 60000u
#define HEUR_COOLDOWN_SUSP_PORT_MS 15000u
#define HEUR_DNS_CACHE_SLOTS 8u
#define HEUR_DNS_CORR_WINDOW_MS 5000u

typedef struct _BK_HEURISTIC_EVENT
{
    ULONGLONG Tick;
    UINT32 Severity;
    UINT32 Flags;
} BK_HEURISTIC_EVENT;

typedef struct _BK_DNS_CACHE_ENTRY
{
    CHAR Hostname[64];
    ULONGLONG Tick;
} BK_DNS_CACHE_ENTRY;

typedef struct _BK_CONTROLLER_PID_LEDGER
{
    BOOL Active;
    DWORD Pid;
    ULONGLONG LastSeenTick;

    BK_HEURISTIC_EVENT Events[HEUR_EVENT_SLOTS];
    UINT32 EventHead;
    UINT32 EventCount;

    ULONGLONG BeaconTicks[HEUR_BEACON_MAX_SLOTS];
    UINT32 BeaconHead;
    UINT32 BeaconCount;

    ULONGLONG LastAggrHighTick;
    ULONGLONG LastAggrMedTick;
    ULONGLONG LastShellcodeTick;
    ULONGLONG LastBeaconTick;

    INT32 LotlScore;
    ULONGLONG LastLotlDecayTick;
    ULONGLONG LastLotlLowEmitTick;
    ULONGLONG LastLotlHighEmitTick;

    BK_DNS_CACHE_ENTRY DnsCache[HEUR_DNS_CACHE_SLOTS];
    UINT32 DnsCacheHead;

    UINT32 DnsCallCount60s;
    ULONGLONG DnsWindowStartTick;
    UINT32 DnsMaxHostnameLen;
    ULONGLONG LastDnsTunnelEmitTick;

    ULONGLONG LastSuspPortEmitTick;
} BK_CONTROLLER_PID_LEDGER;

static SRWLOCK g_HeurLock;
static BK_CONTROLLER_PID_LEDGER g_Ledger[HEUR_LEDGER_SLOTS];
static volatile LONG g_HeurInitialized = 0;

#define CHAIN_RING_SLOTS 32u
#define CHAIN_WINDOW_MS 10000u

typedef struct _INJECTION_CHAIN_ENTRY
{
    BOOL Active;
    DWORD CallerPid;
    DWORD TargetPid;
    ULONGLONG FirstStageTick;
    ULONGLONG LastStageTick;
    UINT32 StageMask;
    BOOL EmittedPartial;
    BOOL EmittedComplete;
} INJECTION_CHAIN_ENTRY;

static INJECTION_CHAIN_ENTRY g_ChainRing[CHAIN_RING_SLOTS];

static BK_CONTROLLER_PID_LEDGER *HeurFindOrCreateLedger(_In_ DWORD Pid, _In_ ULONGLONG Now)
{
    UINT32 idx;
    UINT32 emptySlot = HEUR_LEDGER_SLOTS;

    idx = (UINT32)((Pid >> 2) % HEUR_LEDGER_SLOTS);

    for (UINT32 i = 0; i < HEUR_LEDGER_SLOTS; ++i)
    {
        UINT32 probe = (idx + i) % HEUR_LEDGER_SLOTS;

        if (g_Ledger[probe].Active && g_Ledger[probe].Pid == Pid)
        {
            g_Ledger[probe].LastSeenTick = Now;
            return &g_Ledger[probe];
        }
        if (!g_Ledger[probe].Active && emptySlot == HEUR_LEDGER_SLOTS)
        {
            emptySlot = probe;
        }
    }

    if (emptySlot == HEUR_LEDGER_SLOTS)
    {
        ULONGLONG oldest = ULLONG_MAX;
        emptySlot = idx;
        for (UINT32 i = 0; i < HEUR_LEDGER_SLOTS; ++i)
        {
            if (g_Ledger[i].LastSeenTick < oldest)
            {
                oldest = g_Ledger[i].LastSeenTick;
                emptySlot = i;
            }
        }
    }

    ZeroMemory(&g_Ledger[emptySlot], sizeof(g_Ledger[emptySlot]));
    g_Ledger[emptySlot].Active = TRUE;
    g_Ledger[emptySlot].Pid = Pid;
    g_Ledger[emptySlot].LastSeenTick = Now;
    return &g_Ledger[emptySlot];
}

static VOID HeurRecordEvent(_Inout_ BK_CONTROLLER_PID_LEDGER *L, _In_ ULONGLONG Now, _In_ UINT32 Severity,
                            _In_ UINT32 Flags)
{
    UINT32 slot = L->EventHead % HEUR_EVENT_SLOTS;
    L->Events[slot].Tick = Now;
    L->Events[slot].Severity = Severity;
    L->Events[slot].Flags = Flags;
    L->EventHead = (L->EventHead + 1) % HEUR_EVENT_SLOTS;
    if (L->EventCount < HEUR_EVENT_SLOTS)
    {
        L->EventCount++;
    }
}

static UINT32 HeurComputeScore(_In_ const BK_CONTROLLER_PID_LEDGER *L, _In_ ULONGLONG Now)
{
    UINT32 score = 0;
    for (UINT32 i = 0; i < L->EventCount; ++i)
    {
        const BK_HEURISTIC_EVENT *ev = &L->Events[i];
        if (ev->Tick != 0 && (Now - ev->Tick) <= HEUR_WINDOW_MS)
        {
            score += ev->Severity;
        }
    }
    return score;
}

static UINT32 HeurCountEventsByFlag(_In_ const BK_CONTROLLER_PID_LEDGER *L, _In_ ULONGLONG Now, _In_ UINT32 FlagMask)
{
    UINT32 count = 0;

    for (UINT32 i = 0; i < L->EventCount; ++i)
    {
        const BK_HEURISTIC_EVENT *ev = &L->Events[i];
        if (ev->Tick != 0 && (Now - ev->Tick) <= HEUR_WINDOW_MS && (ev->Flags & FlagMask) != 0)
        {
            count++;
        }
    }

    return count;
}

static BOOL HeurCheckShellcodeStage(_In_ const BK_CONTROLLER_PID_LEDGER *L, _In_ ULONGLONG Now)
{
    UINT32 seenFlags = 0;
    for (UINT32 i = 0; i < L->EventCount; ++i)
    {
        const BK_HEURISTIC_EVENT *ev = &L->Events[i];
        if (ev->Tick != 0 && (Now - ev->Tick) <= HEUR_SHELLCODE_WIN_MS)
        {
            seenFlags |= ev->Flags;
        }
    }
    return (seenFlags & (BK_HEUR_FLAG_ALLOC_RW | BK_HEUR_FLAG_PROTECT_RX | BK_HEUR_FLAG_WRITE_VM)) ==
           (BK_HEUR_FLAG_ALLOC_RW | BK_HEUR_FLAG_PROTECT_RX | BK_HEUR_FLAG_WRITE_VM);
}

static BOOL HeurCheckBeacon(_Inout_ BK_CONTROLLER_PID_LEDGER *L, _In_ ULONGLONG Now)
{
    UINT32 n;
    ULONGLONG intervals[HEUR_BEACON_MAX_SLOTS - 1];
    UINT32 intCount;
    double sum;
    double mean;
    double variance;
    double stddev;

    L->BeaconTicks[L->BeaconHead % HEUR_BEACON_MAX_SLOTS] = Now;
    L->BeaconHead = (L->BeaconHead + 1) % HEUR_BEACON_MAX_SLOTS;
    if (L->BeaconCount < HEUR_BEACON_MAX_SLOTS)
    {
        L->BeaconCount++;
    }

    n = L->BeaconCount;
    if (n < HEUR_BEACON_MIN_OBS)
    {
        return FALSE;
    }

    ULONGLONG sorted[HEUR_BEACON_MAX_SLOTS];
    UINT32 base = (L->BeaconHead) % HEUR_BEACON_MAX_SLOTS;
    for (UINT32 i = 0; i < n; ++i)
    {
        sorted[i] = L->BeaconTicks[(base + i) % HEUR_BEACON_MAX_SLOTS];
    }

    intCount = 0;
    sum = 0.0;
    for (UINT32 i = 1; i < n; ++i)
    {
        ULONGLONG delta = (sorted[i] >= sorted[i - 1]) ? (sorted[i] - sorted[i - 1]) : 0u;
        if (delta < HEUR_BEACON_MIN_ITVL_MS || delta > HEUR_BEACON_MAX_ITVL_MS)
        {
            return FALSE;
        }
        intervals[intCount] = delta;
        sum += (double)delta;
        intCount++;
    }

    if (intCount == 0)
    {
        return FALSE;
    }

    mean = sum / (double)intCount;
    if (mean < (double)HEUR_BEACON_MIN_ITVL_MS)
    {
        return FALSE;
    }

    variance = 0.0;
    for (UINT32 i = 0; i < intCount; ++i)
    {
        double diff = (double)intervals[i] - mean;
        variance += diff * diff;
    }
    variance /= (double)intCount;
    stddev = sqrt(variance);

    return (stddev / mean) < HEUR_BEACON_VAR_THRESH;
}

static VOID HeurEmitDetection(_In_ DWORD Pid, _In_ UINT32 Severity, _In_z_ PCSTR DetectionName, _In_z_ PCWSTR Reason)
{
    BKIPC_ETW_EVENT ev;

    ZeroMemory(&ev, sizeof(ev));
    ev.Source = BlackbirdIpcEtwSourceBlackbird;
    ev.Family = BlackbirdIpcEtwFamilyDetection;
    ev.Severity = Severity;
    ev.ProcessId = Pid;
    ev.CallerPid = Pid;
    ev.TargetPid = Pid;

    (void)StringCchCopyA(ev.DetectionName, RTL_NUMBER_OF(ev.DetectionName), DetectionName);
    (void)StringCchCopyW(ev.Reason, RTL_NUMBER_OF(ev.Reason), Reason);
    (void)StringCchPrintfW(ev.EventName, RTL_NUMBER_OF(ev.EventName), L"%S", DetectionName);
    (void)StringCchCopyA(ev.ClassName, RTL_NUMBER_OF(ev.ClassName), "HeuristicsEngine");
    (void)StringCchCopyA(ev.Operation, RTL_NUMBER_OF(ev.Operation), DetectionName);
    ev.Reserved2 = ControllerComputeEtwDetectionTraits(ev);

    ControllerDispatchEtwEvent(&ev);
}

VOID ControllerHeuristicsInitialize(VOID)
{
    if (InterlockedCompareExchange(&g_HeurInitialized, 1, 0) != 0)
    {
        return;
    }
    InitializeSRWLock(&g_HeurLock);
    ZeroMemory(g_Ledger, sizeof(g_Ledger));
    ZeroMemory(g_ChainRing, sizeof(g_ChainRing));
}

VOID ControllerHeuristicsUninitialize(VOID)
{
    if (InterlockedCompareExchange(&g_HeurInitialized, 0, 1) == 0)
    {
        return;
    }
    AcquireSRWLockExclusive(&g_HeurLock);
    ZeroMemory(g_Ledger, sizeof(g_Ledger));
    ZeroMemory(g_ChainRing, sizeof(g_ChainRing));
    ReleaseSRWLockExclusive(&g_HeurLock);
}

VOID ControllerHeuristicsObserveEvent(_In_ DWORD Pid, _In_ UINT32 Severity, _In_ UINT32 HeurFlags)
{
    BK_CONTROLLER_PID_LEDGER *ledger;
    ULONGLONG now;
    UINT32 score;
    BOOL shellcode;
    BOOL beacon = FALSE;
    BOOL lotlLow = FALSE;
    BOOL lotlHigh = FALSE;
    UINT32 networkCount;
    UINT32 detectionCount;
    UINT32 lolbinCount;
    UINT32 memoryStageCount;
    ULONGLONG lastLotlLow;
    ULONGLONG lastLotlHigh;
    INT32 lotlScore;

    if (InterlockedCompareExchange(&g_HeurInitialized, 0, 0) == 0)
    {
        return;
    }
    if (Pid == 0 || Severity == 0)
    {
        return;
    }

    now = GetTickCount64();

    AcquireSRWLockExclusive(&g_HeurLock);

    ledger = HeurFindOrCreateLedger(Pid, now);
    if (ledger == NULL)
    {
        ReleaseSRWLockExclusive(&g_HeurLock);
        return;
    }

    HeurRecordEvent(ledger, now, Severity, HeurFlags);

    if (HeurFlags & BK_HEUR_FLAG_NETWORK)
    {
        beacon = HeurCheckBeacon(ledger, now);
    }

    score = HeurComputeScore(ledger, now);
    shellcode = HeurCheckShellcodeStage(ledger, now);
    networkCount = HeurCountEventsByFlag(ledger, now, BK_HEUR_FLAG_NETWORK);
    detectionCount = HeurCountEventsByFlag(ledger, now, BK_HEUR_FLAG_DETECTION);
    lolbinCount = HeurCountEventsByFlag(ledger, now, BK_HEUR_FLAG_LOLBIN);
    memoryStageCount =
        HeurCountEventsByFlag(ledger, now, BK_HEUR_FLAG_ALLOC_RW | BK_HEUR_FLAG_WRITE_VM | BK_HEUR_FLAG_PROTECT_RX);

    {
        ULONGLONG elapsed = (ledger->LastLotlDecayTick != 0) ? (now - ledger->LastLotlDecayTick) : 0u;
        INT32 decay = (INT32)(elapsed / 30000u);
        if (decay > 0)
        {
            ledger->LotlScore -= decay;
            if (ledger->LotlScore < 0)
                ledger->LotlScore = 0;
            ledger->LastLotlDecayTick = now;
        }
        else if (ledger->LastLotlDecayTick == 0)
        {
            ledger->LastLotlDecayTick = now;
        }

        if (HeurFlags & BK_HEUR_FLAG_LOLBIN)
            ledger->LotlScore += 5;
        else if (HeurFlags & BK_HEUR_FLAG_DETECTION)
            ledger->LotlScore += 2;
        else if (HeurFlags & (BK_HEUR_FLAG_ALLOC_RW | BK_HEUR_FLAG_WRITE_VM | BK_HEUR_FLAG_PROTECT_RX))
            ledger->LotlScore += 1;
    }

    lotlScore = ledger->LotlScore;
    lastLotlLow = ledger->LastLotlLowEmitTick;
    lastLotlHigh = ledger->LastLotlHighEmitTick;

    ULONGLONG lastAggrHigh = ledger->LastAggrHighTick;
    ULONGLONG lastAggrMed = ledger->LastAggrMedTick;
    ULONGLONG lastShell = ledger->LastShellcodeTick;
    ULONGLONG lastBeacon = ledger->LastBeaconTick;

    if (score >= BK_HEUR_AGGREGATE_HIGH_SCORE && detectionCount >= 2 &&
        (lolbinCount >= 2 || memoryStageCount >= 2 || networkCount >= 3) &&
        (now - lastAggrHigh) >= HEUR_COOLDOWN_AGG_MS)
    {
        ledger->LastAggrHighTick = now;
    }
    else if (score >= BK_HEUR_AGGREGATE_MED_SCORE &&
             ((detectionCount >= 1 && (lolbinCount >= 2 || networkCount >= 2)) || memoryStageCount >= 2) &&
             (now - lastAggrMed) >= HEUR_COOLDOWN_AGG_MS)
    {
        ledger->LastAggrMedTick = now;
    }

    if (shellcode && (now - lastShell) >= HEUR_COOLDOWN_SHELL_MS)
    {
        ledger->LastShellcodeTick = now;
    }

    if (beacon && (now - lastBeacon) >= HEUR_COOLDOWN_BEACON_MS)
    {
        ledger->LastBeaconTick = now;
    }

    if (lotlScore >= (INT32)BK_HEUR_LOTL_HIGH_SCORE && lolbinCount >= 3 && (detectionCount >= 2 || networkCount >= 3) &&
        (now - lastLotlHigh) >= 30000u)
    {
        ledger->LastLotlHighEmitTick = now;
        lotlHigh = TRUE;
    }
    else if (lotlScore >= (INT32)BK_HEUR_LOTL_LOW_SCORE && lolbinCount >= 2 &&
             (detectionCount >= 1 || networkCount >= 2) && (now - lastLotlLow) >= 30000u)
    {
        ledger->LastLotlLowEmitTick = now;
        lotlLow = TRUE;
    }

    ReleaseSRWLockExclusive(&g_HeurLock);

    if (score >= BK_HEUR_AGGREGATE_HIGH_SCORE && detectionCount >= 2 &&
        (lolbinCount >= 2 || memoryStageCount >= 2 || networkCount >= 3) &&
        (now - lastAggrHigh) >= HEUR_COOLDOWN_AGG_MS)
    {
        WCHAR reason[256];
        (void)StringCchPrintfW(
            reason, RTL_NUMBER_OF(reason),
            L"pid=%lu rollingScore=%lu highEvidence detections=%lu lolbins=%lu network=%lu memoryStages=%lu",
            (unsigned long)Pid, (unsigned long)score, (unsigned long)detectionCount, (unsigned long)lolbinCount,
            (unsigned long)networkCount, (unsigned long)memoryStageCount);
        HeurEmitDetection(Pid, 7u, "AGGREGATE_THREAT_SIGNAL_HIGH", reason);
    }
    else if (score >= BK_HEUR_AGGREGATE_MED_SCORE &&
             ((detectionCount >= 1 && (lolbinCount >= 2 || networkCount >= 2)) || memoryStageCount >= 2) &&
             (now - lastAggrMed) >= HEUR_COOLDOWN_AGG_MS)
    {
        WCHAR reason[256];
        (void)StringCchPrintfW(
            reason, RTL_NUMBER_OF(reason),
            L"pid=%lu rollingScore=%lu mediumEvidence detections=%lu lolbins=%lu network=%lu memoryStages=%lu",
            (unsigned long)Pid, (unsigned long)score, (unsigned long)detectionCount, (unsigned long)lolbinCount,
            (unsigned long)networkCount, (unsigned long)memoryStageCount);
        HeurEmitDetection(Pid, 5u, "AGGREGATE_THREAT_SIGNAL_MEDIUM", reason);
    }

    if (shellcode && (now - lastShell) >= HEUR_COOLDOWN_SHELL_MS)
    {
        WCHAR reason[256];
        (void)StringCchPrintfW(
            reason, RTL_NUMBER_OF(reason),
            L"pid=%lu observed RW alloc + VM write + RX protect within %lu second window — classic shellcode staging pattern",
            (unsigned long)Pid, (unsigned long)(HEUR_SHELLCODE_WIN_MS / 1000u));
        HeurEmitDetection(Pid, 7u, "SHELLCODE_STAGE_PATTERN", reason);
    }

    if (beacon && (now - lastBeacon) >= HEUR_COOLDOWN_BEACON_MS)
    {
        WCHAR reason[256];
        (void)StringCchPrintfW(
            reason, RTL_NUMBER_OF(reason),
            L"pid=%lu outbound network connects show regular periodicity (CV < %.0f%%) — C2 beacon candidate",
            (unsigned long)Pid, HEUR_BEACON_VAR_THRESH * 100.0);
        HeurEmitDetection(Pid, 4u, "PERIODIC_BEACON_PATTERN", reason);
    }

    if (lotlHigh)
    {
        WCHAR reason[256];
        (void)StringCchPrintfW(reason, RTL_NUMBER_OF(reason),
                               L"pid=%lu lotlScore=%ld lotlEvidence lolbins=%lu detections=%lu network=%lu",
                               (unsigned long)Pid, (long)lotlScore, (unsigned long)lolbinCount,
                               (unsigned long)detectionCount, (unsigned long)networkCount);
        HeurEmitDetection(Pid, 7u, "LOTL_LOW_AND_SLOW_HIGH_CONFIDENCE", reason);
    }
    else if (lotlLow)
    {
        WCHAR reason[256];
        (void)StringCchPrintfW(reason, RTL_NUMBER_OF(reason),
                               L"pid=%lu lotlScore=%ld lotlEvidence lolbins=%lu detections=%lu network=%lu",
                               (unsigned long)Pid, (long)lotlScore, (unsigned long)lolbinCount,
                               (unsigned long)detectionCount, (unsigned long)networkCount);
        HeurEmitDetection(Pid, 5u, "LOTL_LOW_AND_SLOW_SUSPECT", reason);
    }
}

static UINT32 ChainCountBits(_In_ UINT32 Mask)
{
    UINT32 n = 0;
    UINT32 m = Mask;
    while (m != 0)
    {
        n += m & 1u;
        m >>= 1;
    }
    return n;
}

VOID ControllerInjectionChainObserve(_In_ DWORD CallerPid, _In_ DWORD TargetPid, _In_ UINT32 StageBit)
{
    UINT32 i;
    UINT32 evictSlot = 0;
    ULONGLONG evictTick = ULLONG_MAX;
    INJECTION_CHAIN_ENTRY *entry = NULL;
    ULONGLONG now;
    UINT32 stageCount;
    BOOL emitPartial;
    BOOL emitComplete;
    DWORD callerPidSnap;
    DWORD targetPidSnap;
    UINT32 stageMaskSnap;

    if (InterlockedCompareExchange(&g_HeurInitialized, 0, 0) == 0 || CallerPid == 0 || StageBit == 0)
    {
        return;
    }

    now = GetTickCount64();

    AcquireSRWLockExclusive(&g_HeurLock);

    for (i = 0; i < CHAIN_RING_SLOTS; ++i)
    {
        INJECTION_CHAIN_ENTRY *slot = &g_ChainRing[i];

        if (!slot->Active)
        {
            if (evictTick != 0)
            {
                evictSlot = i;
                evictTick = 0;
            }
            continue;
        }

        if ((now - slot->LastStageTick) > CHAIN_WINDOW_MS)
        {
            ZeroMemory(slot, sizeof(*slot));
            if (evictTick != 0)
            {
                evictSlot = i;
                evictTick = 0;
            }
            continue;
        }

        if (slot->CallerPid == CallerPid)
        {
            if (StageBit == BK_CHAIN_STAGE_OPEN)
            {
                if (slot->TargetPid == TargetPid)
                {
                    entry = slot;
                    break;
                }
            }
            else
            {
                entry = slot;
                break;
            }
        }

        if (slot->LastStageTick < evictTick)
        {
            evictTick = slot->LastStageTick;
            evictSlot = i;
        }
    }

    if (entry == NULL)
    {
        if (StageBit != BK_CHAIN_STAGE_OPEN)
        {
            ReleaseSRWLockExclusive(&g_HeurLock);
            return;
        }

        ZeroMemory(&g_ChainRing[evictSlot], sizeof(g_ChainRing[evictSlot]));
        g_ChainRing[evictSlot].Active = TRUE;
        g_ChainRing[evictSlot].CallerPid = CallerPid;
        g_ChainRing[evictSlot].TargetPid = TargetPid;
        g_ChainRing[evictSlot].FirstStageTick = now;
        entry = &g_ChainRing[evictSlot];
    }

    entry->StageMask |= StageBit;
    entry->LastStageTick = now;

    stageCount = ChainCountBits(entry->StageMask);
    emitPartial = (stageCount >= 3u && !entry->EmittedPartial);
    emitComplete = (stageCount >= 5u && !entry->EmittedComplete);

    if (emitPartial)
        entry->EmittedPartial = TRUE;
    if (emitComplete)
        entry->EmittedComplete = TRUE;

    callerPidSnap = entry->CallerPid;
    targetPidSnap = entry->TargetPid;
    stageMaskSnap = entry->StageMask;

    ReleaseSRWLockExclusive(&g_HeurLock);

    if (emitComplete)
    {
        WCHAR reason[256];
        (void)StringCchPrintfW(
            reason, RTL_NUMBER_OF(reason),
            L"pid=%lu->%lu all five injection stages observed within %lu second window (stageMask=0x%X)",
            (unsigned long)callerPidSnap, (unsigned long)targetPidSnap, (unsigned long)(CHAIN_WINDOW_MS / 1000u),
            (unsigned int)stageMaskSnap);
        HeurEmitDetection(callerPidSnap, 9u, "INJECTION_CHAIN_COMPLETE", reason);
    }
    else if (emitPartial)
    {
        WCHAR reason[256];
        (void)StringCchPrintfW(
            reason, RTL_NUMBER_OF(reason),
            L"pid=%lu->%lu %lu of 5 injection stages observed within %lu second window (stageMask=0x%X)",
            (unsigned long)callerPidSnap, (unsigned long)targetPidSnap, (unsigned long)stageCount,
            (unsigned long)(CHAIN_WINDOW_MS / 1000u), (unsigned int)stageMaskSnap);
        HeurEmitDetection(callerPidSnap, 6u, "INJECTION_CHAIN_PARTIAL", reason);
    }
}

static BOOL HeurIsSuspiciousPort(_In_ UINT16 Port)
{
    static const UINT16 kSuspPorts[] = {31337u, 4444u, 1234u, 8888u, 1337u, 9999u, 6666u,
                                        2222u,  4321u, 5555u, 7777u, 9090u, 1111u, 3333u};
    UINT32 i;
    for (i = 0; i < RTL_NUMBER_OF(kSuspPorts); ++i)
    {
        if (Port == kSuspPorts[i])
        {
            return TRUE;
        }
    }
    return FALSE;
}

VOID ControllerHeuristicsObserveDns(_In_ DWORD Pid, _In_z_ PCSTR Hostname)
{
    BK_CONTROLLER_PID_LEDGER *ledger;
    ULONGLONG now;
    UINT32 slot;
    UINT32 nameLen;
    BOOL emitTunnel = FALSE;

    if (InterlockedCompareExchange(&g_HeurInitialized, 0, 0) == 0 || Pid == 0 || Hostname == NULL ||
        Hostname[0] == '\0')
    {
        return;
    }

    nameLen = 0;
    while (Hostname[nameLen] != '\0' && nameLen < 128u)
    {
        nameLen++;
    }

    now = GetTickCount64();

    AcquireSRWLockExclusive(&g_HeurLock);

    ledger = HeurFindOrCreateLedger(Pid, now);
    if (ledger == NULL)
    {
        ReleaseSRWLockExclusive(&g_HeurLock);
        return;
    }

    slot = ledger->DnsCacheHead % HEUR_DNS_CACHE_SLOTS;
    (void)StringCchCopyA(ledger->DnsCache[slot].Hostname, RTL_NUMBER_OF(ledger->DnsCache[slot].Hostname), Hostname);
    ledger->DnsCache[slot].Tick = now;
    ledger->DnsCacheHead = (ledger->DnsCacheHead + 1) % HEUR_DNS_CACHE_SLOTS;

    if ((now - ledger->DnsWindowStartTick) >= HEUR_WINDOW_MS)
    {
        ledger->DnsCallCount60s = 0;
        ledger->DnsWindowStartTick = now;
        ledger->DnsMaxHostnameLen = 0;
    }
    ledger->DnsCallCount60s++;
    if (nameLen > ledger->DnsMaxHostnameLen)
    {
        ledger->DnsMaxHostnameLen = nameLen;
    }

    if ((ledger->DnsCallCount60s >= BK_HEUR_DNS_CALL_TUNNEL_THRESHOLD ||
         ledger->DnsMaxHostnameLen >= BK_HEUR_DNS_NAME_TUNNEL_LENGTH) &&
        (now - ledger->LastDnsTunnelEmitTick) >= HEUR_COOLDOWN_DNS_TUNNEL_MS)
    {
        ledger->LastDnsTunnelEmitTick = now;
        emitTunnel = TRUE;
    }

    HeurRecordEvent(ledger, now, 1u, BK_HEUR_FLAG_DNS_QUERY);

    ReleaseSRWLockExclusive(&g_HeurLock);

    if (emitTunnel)
    {
        WCHAR reason[256];
        (void)StringCchPrintfW(reason, RTL_NUMBER_OF(reason),
                               L"pid=%lu dns.calls=%lu maxHostnameLen=%lu within 60s window — DNS tunneling suspect",
                               (unsigned long)Pid, (unsigned long)ledger->DnsCallCount60s,
                               (unsigned long)ledger->DnsMaxHostnameLen);
        HeurEmitDetection(Pid, 6u, "DNS_TUNNELING_SUSPECT", reason);
    }
}

VOID ControllerHeuristicsLookupDns(_In_ DWORD Pid, _In_z_ PCSTR IpStr, _Out_writes_z_(OutChars) PSTR HostnameOut,
                                   _In_ size_t OutChars)
{
    BK_CONTROLLER_PID_LEDGER *ledger;
    ULONGLONG now;
    UINT32 i;

    if (HostnameOut == NULL || OutChars == 0)
    {
        return;
    }
    HostnameOut[0] = '\0';

    if (InterlockedCompareExchange(&g_HeurInitialized, 0, 0) == 0 || Pid == 0 || IpStr == NULL || IpStr[0] == '\0')
    {
        return;
    }

    now = GetTickCount64();

    AcquireSRWLockShared(&g_HeurLock);

    ledger = HeurFindOrCreateLedger(Pid, now);
    if (ledger == NULL)
    {
        ReleaseSRWLockShared(&g_HeurLock);
        return;
    }

    /* Post-call DNS results are unavailable here; use the recent resolution window as the correlation source. */
    for (i = 0; i < HEUR_DNS_CACHE_SLOTS; ++i)
    {
        if (ledger->DnsCache[i].Hostname[0] != '\0' && ledger->DnsCache[i].Tick != 0 &&
            (now - ledger->DnsCache[i].Tick) <= HEUR_DNS_CORR_WINDOW_MS)
        {
            (void)StringCchCopyA(HostnameOut, OutChars, ledger->DnsCache[i].Hostname);
            break;
        }
    }

    ReleaseSRWLockShared(&g_HeurLock);
}

VOID ControllerHeuristicsObserveDirectIpConnect(_In_ DWORD Pid, _In_z_ PCSTR IpStr, _In_ UINT16 Port)
{
    BK_CONTROLLER_PID_LEDGER *ledger;
    ULONGLONG now;
    BOOL emitSuspPort = FALSE;

    if (InterlockedCompareExchange(&g_HeurInitialized, 0, 0) == 0 || Pid == 0)
    {
        return;
    }

    (void)IpStr;

    now = GetTickCount64();

    AcquireSRWLockExclusive(&g_HeurLock);

    ledger = HeurFindOrCreateLedger(Pid, now);
    if (ledger != NULL)
    {
        HeurRecordEvent(ledger, now, 3u, BK_HEUR_FLAG_DIRECT_IP | BK_HEUR_FLAG_NETWORK);

        if (HeurIsSuspiciousPort(Port) && (now - ledger->LastSuspPortEmitTick) >= HEUR_COOLDOWN_SUSP_PORT_MS)
        {
            ledger->LastSuspPortEmitTick = now;
            emitSuspPort = TRUE;
            HeurRecordEvent(ledger, now, 4u, BK_HEUR_FLAG_SUSP_PORT | BK_HEUR_FLAG_NETWORK);
        }
    }

    ReleaseSRWLockExclusive(&g_HeurLock);

    if (emitSuspPort)
    {
        WCHAR reason[192];
        (void)StringCchPrintfW(reason, RTL_NUMBER_OF(reason),
                               L"pid=%lu direct IP connect to high-risk port %u (no prior DNS — possible C2 staging)",
                               (unsigned long)Pid, (unsigned int)Port);
        HeurEmitDetection(Pid, 4u, "SUSPICIOUS_PORT_CONNECT", reason);
    }
}
