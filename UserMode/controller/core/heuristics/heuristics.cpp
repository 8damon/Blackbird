#include "../Blackbird_controller_private.h"
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

typedef struct _BLACKBIRD_HEURISTIC_EVENT
{
    ULONGLONG Tick;
    UINT32 Severity;
    UINT32 Flags;
} BLACKBIRD_HEURISTIC_EVENT;

typedef struct _BLACKBIRD_CONTROLLER_PID_LEDGER
{
    BOOL Active;
    DWORD Pid;
    ULONGLONG LastSeenTick;

    BLACKBIRD_HEURISTIC_EVENT Events[HEUR_EVENT_SLOTS];
    UINT32 EventHead;
    UINT32 EventCount;

    ULONGLONG BeaconTicks[HEUR_BEACON_MAX_SLOTS];
    UINT32 BeaconHead;
    UINT32 BeaconCount;

    ULONGLONG LastAggrHighTick;
    ULONGLONG LastAggrMedTick;
    ULONGLONG LastShellcodeTick;
    ULONGLONG LastBeaconTick;
} BLACKBIRD_CONTROLLER_PID_LEDGER;

static SRWLOCK g_HeurLock;
static BLACKBIRD_CONTROLLER_PID_LEDGER g_Ledger[HEUR_LEDGER_SLOTS];
static volatile LONG g_HeurInitialized = 0;

static BLACKBIRD_CONTROLLER_PID_LEDGER *HeurFindOrCreateLedger(_In_ DWORD Pid, _In_ ULONGLONG Now)
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

static VOID HeurRecordEvent(_Inout_ BLACKBIRD_CONTROLLER_PID_LEDGER *L, _In_ ULONGLONG Now, _In_ UINT32 Severity,
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

static UINT32 HeurComputeScore(_In_ const BLACKBIRD_CONTROLLER_PID_LEDGER *L, _In_ ULONGLONG Now)
{
    UINT32 score = 0;
    for (UINT32 i = 0; i < L->EventCount; ++i)
    {
        const BLACKBIRD_HEURISTIC_EVENT *ev = &L->Events[i];
        if (ev->Tick != 0 && (Now - ev->Tick) <= HEUR_WINDOW_MS)
        {
            score += ev->Severity;
        }
    }
    return score;
}

static BOOL HeurCheckShellcodeStage(_In_ const BLACKBIRD_CONTROLLER_PID_LEDGER *L, _In_ ULONGLONG Now)
{
    UINT32 seenFlags = 0;
    for (UINT32 i = 0; i < L->EventCount; ++i)
    {
        const BLACKBIRD_HEURISTIC_EVENT *ev = &L->Events[i];
        if (ev->Tick != 0 && (Now - ev->Tick) <= HEUR_SHELLCODE_WIN_MS)
        {
            seenFlags |= ev->Flags;
        }
    }
    return (seenFlags &
            (BLACKBIRD_HEUR_FLAG_ALLOC_RW | BLACKBIRD_HEUR_FLAG_PROTECT_RX | BLACKBIRD_HEUR_FLAG_WRITE_VM)) ==
           (BLACKBIRD_HEUR_FLAG_ALLOC_RW | BLACKBIRD_HEUR_FLAG_PROTECT_RX | BLACKBIRD_HEUR_FLAG_WRITE_VM);
}

static BOOL HeurCheckBeacon(_Inout_ BLACKBIRD_CONTROLLER_PID_LEDGER *L, _In_ ULONGLONG Now)
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
    BLACKBIRD_IPC_ETW_EVENT ev;

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
}

VOID ControllerHeuristicsUninitialize(VOID)
{
    if (InterlockedCompareExchange(&g_HeurInitialized, 0, 1) == 0)
    {
        return;
    }
    AcquireSRWLockExclusive(&g_HeurLock);
    ZeroMemory(g_Ledger, sizeof(g_Ledger));
    ReleaseSRWLockExclusive(&g_HeurLock);
}

VOID ControllerHeuristicsObserveEvent(_In_ DWORD Pid, _In_ UINT32 Severity, _In_ UINT32 HeurFlags)
{
    BLACKBIRD_CONTROLLER_PID_LEDGER *ledger;
    ULONGLONG now;
    UINT32 score;
    BOOL shellcode;
    BOOL beacon = FALSE;

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

    if (HeurFlags & BLACKBIRD_HEUR_FLAG_NETWORK)
    {
        beacon = HeurCheckBeacon(ledger, now);
    }

    score = HeurComputeScore(ledger, now);
    shellcode = HeurCheckShellcodeStage(ledger, now);

    ULONGLONG lastAggrHigh = ledger->LastAggrHighTick;
    ULONGLONG lastAggrMed = ledger->LastAggrMedTick;
    ULONGLONG lastShell = ledger->LastShellcodeTick;
    ULONGLONG lastBeacon = ledger->LastBeaconTick;

    if (score >= BLACKBIRD_HEUR_AGGREGATE_HIGH_SCORE && (now - lastAggrHigh) >= HEUR_COOLDOWN_AGG_MS)
    {
        ledger->LastAggrHighTick = now;
    }
    else if (score >= BLACKBIRD_HEUR_AGGREGATE_MED_SCORE && (now - lastAggrMed) >= HEUR_COOLDOWN_AGG_MS)
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

    ReleaseSRWLockExclusive(&g_HeurLock);

    if (score >= BLACKBIRD_HEUR_AGGREGATE_HIGH_SCORE && (now - lastAggrHigh) >= HEUR_COOLDOWN_AGG_MS)
    {
        WCHAR reason[256];
        (void)StringCchPrintfW(reason, RTL_NUMBER_OF(reason),
                               L"pid=%lu rollingScore=%lu exceeds high-threat threshold %lu over %lu second window",
                               (unsigned long)Pid, (unsigned long)score,
                               (unsigned long)BLACKBIRD_HEUR_AGGREGATE_HIGH_SCORE,
                               (unsigned long)(HEUR_WINDOW_MS / 1000u));
        HeurEmitDetection(Pid, 7u, "AGGREGATE_THREAT_SIGNAL_HIGH", reason);
    }
    else if (score >= BLACKBIRD_HEUR_AGGREGATE_MED_SCORE && (now - lastAggrMed) >= HEUR_COOLDOWN_AGG_MS)
    {
        WCHAR reason[256];
        (void)StringCchPrintfW(reason, RTL_NUMBER_OF(reason),
                               L"pid=%lu rollingScore=%lu exceeds medium-threat threshold %lu over %lu second window",
                               (unsigned long)Pid, (unsigned long)score,
                               (unsigned long)BLACKBIRD_HEUR_AGGREGATE_MED_SCORE,
                               (unsigned long)(HEUR_WINDOW_MS / 1000u));
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
}
