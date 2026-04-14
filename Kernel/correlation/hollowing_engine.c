#include <ntddk.h>
#include "intent_store.h"
#include "hollowing_engine.h"
#include "..\core\tempus_debug.h"
#include "..\telemetry\etw.h"

#define BLACKBIRD_HOLLOW_RING_SIZE 256
#define BLACKBIRD_HOLLOW_WINDOW_MS 30000u
#define BLACKBIRD_HOLLOW_EMIT_COOLDOWN_MS 3000u

#define BLACKBIRD_HOLLOW_MARK_REMOTE_THREAD 0x00000001u
#define BLACKBIRD_HOLLOW_MARK_OUTSIDE_IMAGE 0x00000002u
#define BLACKBIRD_HOLLOW_MARK_NON_IMAGE_EXEC 0x00000004u
#define BLACKBIRD_HOLLOW_MARK_MEMORY_INTENT 0x00000008u
#define BLACKBIRD_HOLLOW_MARK_THREAD_CONTEXT_INTENT 0x00000010u
#define BLACKBIRD_HOLLOW_MARK_DUP_HANDLE_INTENT 0x00000020u

typedef struct _BLACKBIRD_HOLLOW_ENTRY
{
    BOOLEAN Active;
    UINT64 ActorPid;
    UINT64 TargetPid;
    UINT32 Marks;
    UINT32 CorrelationFlags;
    UINT32 CorrelationAccessMask;
    UINT32 CorrelationAgeMs;
    INT64 FirstSeenQpc;
    INT64 LastSeenQpc;
    INT64 LastMediumEmitQpc;
    INT64 LastStrongEmitQpc;
} BLACKBIRD_HOLLOW_ENTRY, *PBLACKBIRD_HOLLOW_ENTRY;

static BLACKBIRD_HOLLOW_ENTRY g_HollowRing[BLACKBIRD_HOLLOW_RING_SIZE];
static KSPIN_LOCK g_HollowLock;
static volatile LONG g_HollowInitialized = 0;
static ULONGLONG g_HollowQpcFrequency = 1;

typedef struct _BLACKBIRD_HOLLOW_EMIT
{
    BOOLEAN Emit;
    PCSTR DetectionName;
    ULONG Severity;
    HANDLE ActorPid;
    HANDLE TargetPid;
    UINT32 CorrelationFlags;
    UINT32 CorrelationAccessMask;
    UINT32 CorrelationAgeMs;
    PCWSTR Reason;
} BLACKBIRD_HOLLOW_EMIT, *PBLACKBIRD_HOLLOW_EMIT;

static ULONGLONG BLACKBIRDHollowMsToQpc(_In_ UINT32 Ms)
{
    ULONGLONG ticks;

    if (Ms == 0)
    {
        return 0;
    }

    ticks = ((ULONGLONG)Ms * g_HollowQpcFrequency) / 1000ULL;
    if (ticks == 0)
    {
        ticks = 1;
    }

    return ticks;
}

static PBLACKBIRD_HOLLOW_ENTRY BLACKBIRDHollowGetEntryLocked(_In_ HANDLE ActorPid, _In_ HANDLE TargetPid,
                                                             _In_ INT64 NowQpc)
{
    UINT64 actor;
    UINT64 target;
    ULONGLONG staleQpc = BLACKBIRDHollowMsToQpc(BLACKBIRD_HOLLOW_WINDOW_MS * 2u);
    INT64 oldestQpc = MAXLONGLONG;
    LONG candidate = -1;
    UINT32 i;

    target = (UINT64)(ULONG_PTR)TargetPid;
    actor = (UINT64)(ULONG_PTR)ActorPid;
    if (target == 0)
    {
        return NULL;
    }
    if (actor == 0)
    {
        actor = target;
    }

    for (i = 0; i < BLACKBIRD_HOLLOW_RING_SIZE; ++i)
    {
        ULONGLONG ageQpc;

        if (!g_HollowRing[i].Active)
        {
            candidate = (LONG)i;
            break;
        }

        if (g_HollowRing[i].ActorPid == actor && g_HollowRing[i].TargetPid == target)
        {
            return &g_HollowRing[i];
        }

        ageQpc = (NowQpc > g_HollowRing[i].LastSeenQpc) ? (ULONGLONG)(NowQpc - g_HollowRing[i].LastSeenQpc) : 0;
        if (ageQpc > staleQpc)
        {
            candidate = (LONG)i;
            break;
        }

        if (g_HollowRing[i].LastSeenQpc < oldestQpc)
        {
            oldestQpc = g_HollowRing[i].LastSeenQpc;
            candidate = (LONG)i;
        }
    }

    if (candidate < 0 || candidate >= BLACKBIRD_HOLLOW_RING_SIZE)
    {
        return NULL;
    }

    RtlZeroMemory(&g_HollowRing[candidate], sizeof(g_HollowRing[candidate]));
    g_HollowRing[candidate].Active = TRUE;
    g_HollowRing[candidate].ActorPid = actor;
    g_HollowRing[candidate].TargetPid = target;
    g_HollowRing[candidate].FirstSeenQpc = NowQpc;
    g_HollowRing[candidate].LastSeenQpc = NowQpc;

    return &g_HollowRing[candidate];
}

static VOID BLACKBIRDHollowEvaluateMarkDetectionsLocked(_Inout_ PBLACKBIRD_HOLLOW_ENTRY Entry, _In_ INT64 NowQpc,
                                                        _Out_ PBLACKBIRD_HOLLOW_EMIT Emit)
{
    ULONGLONG ageQpc;
    ULONGLONG windowQpc;
    ULONGLONG cooldownQpc;
    BOOLEAN hasRemote;
    BOOLEAN hasOutside;
    BOOLEAN hasNonImageExec;
    BOOLEAN hasMemoryIntent;
    BOOLEAN hasThreadCtxIntent;
    BOOLEAN hasDupIntent;
    BOOLEAN suspiciousStart;
    BOOLEAN medium;
    BOOLEAN strong;

    if (Emit == NULL)
    {
        return;
    }

    RtlZeroMemory(Emit, sizeof(*Emit));
    if (Entry == NULL)
    {
        return;
    }

    windowQpc = BLACKBIRDHollowMsToQpc(BLACKBIRD_HOLLOW_WINDOW_MS);
    cooldownQpc = BLACKBIRDHollowMsToQpc(BLACKBIRD_HOLLOW_EMIT_COOLDOWN_MS);
    ageQpc = (NowQpc > Entry->FirstSeenQpc) ? (ULONGLONG)(NowQpc - Entry->FirstSeenQpc) : 0;
    if (ageQpc > windowQpc)
    {
        Entry->Marks = 0;
        Entry->CorrelationFlags = 0;
        Entry->CorrelationAccessMask = 0;
        Entry->CorrelationAgeMs = 0;
        Entry->FirstSeenQpc = NowQpc;
        return;
    }

    hasRemote = ((Entry->Marks & BLACKBIRD_HOLLOW_MARK_REMOTE_THREAD) != 0);
    hasOutside = ((Entry->Marks & BLACKBIRD_HOLLOW_MARK_OUTSIDE_IMAGE) != 0);
    hasNonImageExec = ((Entry->Marks & BLACKBIRD_HOLLOW_MARK_NON_IMAGE_EXEC) != 0);
    hasMemoryIntent = ((Entry->Marks & BLACKBIRD_HOLLOW_MARK_MEMORY_INTENT) != 0);
    hasThreadCtxIntent = ((Entry->Marks & BLACKBIRD_HOLLOW_MARK_THREAD_CONTEXT_INTENT) != 0);
    hasDupIntent = ((Entry->Marks & BLACKBIRD_HOLLOW_MARK_DUP_HANDLE_INTENT) != 0);
    suspiciousStart = (hasOutside || hasNonImageExec);

    medium = hasRemote && suspiciousStart && hasMemoryIntent && (hasThreadCtxIntent || hasDupIntent);
    strong = hasRemote && hasNonImageExec && hasMemoryIntent && (hasThreadCtxIntent || hasDupIntent);

    if (strong)
    {
        ULONGLONG sinceStrongQpc =
            (NowQpc > Entry->LastStrongEmitQpc) ? (ULONGLONG)(NowQpc - Entry->LastStrongEmitQpc) : 0;
        if (Entry->LastStrongEmitQpc == 0 || sinceStrongQpc >= cooldownQpc)
        {
            Entry->LastStrongEmitQpc = NowQpc;
            Emit->Emit = TRUE;
            Emit->DetectionName = "KERNEL_PROCESS_HOLLOWING_MARK_CHAIN_STRONG";
            Emit->Severity = 7;
            Emit->ActorPid = (HANDLE)(ULONG_PTR)Entry->ActorPid;
            Emit->TargetPid = (HANDLE)(ULONG_PTR)Entry->TargetPid;
            Emit->CorrelationFlags = Entry->CorrelationFlags;
            Emit->CorrelationAccessMask = Entry->CorrelationAccessMask;
            Emit->CorrelationAgeMs = Entry->CorrelationAgeMs;
            Emit->Reason = L"kernel hollowing mark-chain strong (remote non-image exec + memory/thread intent)";
            return;
        }
    }

    if (medium)
    {
        ULONGLONG sinceMediumQpc =
            (NowQpc > Entry->LastMediumEmitQpc) ? (ULONGLONG)(NowQpc - Entry->LastMediumEmitQpc) : 0;
        if (Entry->LastMediumEmitQpc == 0 || sinceMediumQpc >= cooldownQpc)
        {
            Entry->LastMediumEmitQpc = NowQpc;
            Emit->Emit = TRUE;
            Emit->DetectionName = "KERNEL_PROCESS_HOLLOWING_MARK_CHAIN_MEDIUM";
            Emit->Severity = 5;
            Emit->ActorPid = (HANDLE)(ULONG_PTR)Entry->ActorPid;
            Emit->TargetPid = (HANDLE)(ULONG_PTR)Entry->TargetPid;
            Emit->CorrelationFlags = Entry->CorrelationFlags;
            Emit->CorrelationAccessMask = Entry->CorrelationAccessMask;
            Emit->CorrelationAgeMs = Entry->CorrelationAgeMs;
            Emit->Reason = L"kernel hollowing mark-chain medium (memory intent + suspicious remote start)";
        }
    }
}

static VOID BLACKBIRDHollowApplyMarks(_In_ HANDLE ActorPid, _In_ HANDLE TargetPid, _In_ UINT32 Marks,
                                      _In_ UINT32 CorrelationFlags, _In_ UINT32 CorrelationAccessMask,
                                      _In_ UINT32 CorrelationAgeMs)
{
    PBLACKBIRD_HOLLOW_ENTRY entry;
    BLACKBIRD_HOLLOW_EMIT emit;
    KIRQL oldIrql;
    INT64 nowQpc;

    if (Marks == 0 || TargetPid == NULL)
    {
        return;
    }
    if (InterlockedCompareExchange(&g_HollowInitialized, 0, 0) == 0)
    {
        return;
    }

    RtlZeroMemory(&emit, sizeof(emit));
    nowQpc = KeQueryPerformanceCounter(NULL).QuadPart;

    KeAcquireSpinLock(&g_HollowLock, &oldIrql);
    entry = BLACKBIRDHollowGetEntryLocked(ActorPid, TargetPid, nowQpc);
    if (entry != NULL)
    {
        entry->Marks |= Marks;
        entry->CorrelationFlags |= CorrelationFlags;
        entry->CorrelationAccessMask |= CorrelationAccessMask;
        if (CorrelationAgeMs != 0)
        {
            entry->CorrelationAgeMs = CorrelationAgeMs;
        }
        entry->LastSeenQpc = nowQpc;
        if (entry->FirstSeenQpc == 0)
        {
            entry->FirstSeenQpc = nowQpc;
        }
        BLACKBIRDHollowEvaluateMarkDetectionsLocked(entry, nowQpc, &emit);
    }
    KeReleaseSpinLock(&g_HollowLock, oldIrql);

    if (emit.Emit)
    {
        BLACKBIRDEtwLogDetectionEvent(emit.DetectionName, emit.Severity, emit.ActorPid, emit.TargetPid,
                                      emit.CorrelationFlags, emit.CorrelationAccessMask, emit.CorrelationAgeMs,
                                      emit.Reason);
    }
}

NTSTATUS
BLACKBIRDHollowingEngineInitialize(VOID)
{
    LARGE_INTEGER freq;

    if (InterlockedCompareExchange(&g_HollowInitialized, 1, 0) != 0)
    {
        return STATUS_SUCCESS;
    }

    KeQueryPerformanceCounter(&freq);
    g_HollowQpcFrequency = (freq.QuadPart > 0) ? (ULONGLONG)freq.QuadPart : 1;
    KeInitializeSpinLock(&g_HollowLock);
    RtlZeroMemory(g_HollowRing, sizeof(g_HollowRing));

    return STATUS_SUCCESS;
}

VOID BLACKBIRDHollowingEngineUninitialize(VOID)
{
    if (InterlockedExchange(&g_HollowInitialized, 0) == 0)
    {
        return;
    }

    RtlZeroMemory(g_HollowRing, sizeof(g_HollowRing));
}

BOOLEAN
BLACKBIRDHollowingEngineSelfCheck(VOID)
{
    return (InterlockedCompareExchange(&g_HollowInitialized, 0, 0) != 0);
}

BOOLEAN
BLACKBIRDHollowingResolveThreadCorrelation(_In_ HANDLE ProcessId, _In_opt_ HANDLE PreferredCreatorPid,
                                           _In_ UINT32 WindowMs, _Out_opt_ HANDLE *ResolvedActorPid,
                                           _Out_opt_ UINT32 *CorrelationFlags, _Out_opt_ UINT32 *CorrelationAccessMask,
                                           _Out_opt_ UINT32 *CorrelationAgeMs)
{
    ULONGLONG tempusStartQpc = BLACKBIRDTempusEnter(BlackbirdTempusSubsystemHollowingEngine);
    HANDLE actor;
    HANDLE correlatedCaller = NULL;
    UINT32 flags = 0;
    UINT32 accessMask = 0;
    UINT32 ageMs = 0;
    BOOLEAN found = FALSE;

    if (ProcessId == NULL)
    {
        BLACKBIRDTempusLeave(BlackbirdTempusSubsystemHollowingEngine, tempusStartQpc);
        return FALSE;
    }

    actor = (PreferredCreatorPid != NULL) ? PreferredCreatorPid : ProcessId;

    if (BLACKBIRDCorrelationQueryRecentIntent(actor, ProcessId, WindowMs, &flags, &accessMask, &ageMs))
    {
        found = TRUE;
    }
    else if (BLACKBIRDCorrelationQueryRecentIntentForTarget(ProcessId, WindowMs, TRUE, &correlatedCaller, &flags,
                                                            &accessMask, &ageMs))
    {
        found = TRUE;
        if (correlatedCaller != NULL)
        {
            actor = correlatedCaller;
        }
    }

    if (!found)
    {
        flags = 0;
        accessMask = 0;
        ageMs = 0;
    }

    if (ResolvedActorPid != NULL)
    {
        *ResolvedActorPid = actor;
    }
    if (CorrelationFlags != NULL)
    {
        *CorrelationFlags = flags;
    }
    if (CorrelationAccessMask != NULL)
    {
        *CorrelationAccessMask = accessMask;
    }
    if (CorrelationAgeMs != NULL)
    {
        *CorrelationAgeMs = ageMs;
    }

    BLACKBIRDTempusLeave(BlackbirdTempusSubsystemHollowingEngine, tempusStartQpc);
    return found;
}

VOID BLACKBIRDHollowingObserveThread(_In_ HANDLE ProcessId, _In_opt_ HANDLE ActorPid, _In_ BOOLEAN OutsideMainImage,
                                     _In_ BOOLEAN GotStart, _In_ BOOLEAN StartRegionExecutable,
                                     _In_ BOOLEAN StartRegionNonImage, _In_ UINT32 CorrelationFlags,
                                     _In_ UINT32 CorrelationAccessMask, _In_ UINT32 CorrelationAgeMs)
{
    ULONGLONG tempusStartQpc = BLACKBIRDTempusEnter(BlackbirdTempusSubsystemHollowingEngine);
    HANDLE actor;
    BOOLEAN isRemoteCreator;
    BOOLEAN remoteNonImageExec;
    BOOLEAN hasThreadContextIntent;
    BOOLEAN hasMemoryIntent;
    BOOLEAN hasDuplicateIntent;
    UINT32 marks = 0;

    if (ProcessId == NULL)
    {
        BLACKBIRDTempusLeave(BlackbirdTempusSubsystemHollowingEngine, tempusStartQpc);
        return;
    }

    actor = (ActorPid != NULL) ? ActorPid : ProcessId;
    isRemoteCreator = (actor != ProcessId);
    remoteNonImageExec = isRemoteCreator && GotStart && StartRegionExecutable && StartRegionNonImage;
    hasThreadContextIntent = ((CorrelationFlags & BLACKBIRD_INTENT_THREAD_CONTEXT) != 0);
    hasMemoryIntent = ((CorrelationFlags & BLACKBIRD_INTENT_PROCESS_MEMORY) != 0);
    hasDuplicateIntent = ((CorrelationFlags & BLACKBIRD_INTENT_DUP_HANDLE) != 0);

    if (isRemoteCreator && hasMemoryIntent && (hasThreadContextIntent || hasDuplicateIntent))
    {
        BLACKBIRDEtwLogDetectionEvent("REMOTE_THREAD_WITH_RECENT_HANDLE_INTENT", 5, actor, ProcessId, CorrelationFlags,
                                      CorrelationAccessMask, CorrelationAgeMs,
                                      L"remote thread correlated with memory+thread-context/dup handle intent");
    }
    if (remoteNonImageExec && hasMemoryIntent)
    {
        BLACKBIRDEtwLogDetectionEvent(
            "REMOTE_THREAD_START_IN_NON_IMAGE_EXECUTABLE_REGION", 6, actor, ProcessId, CorrelationFlags,
            CorrelationAccessMask, CorrelationAgeMs,
            L"remote thread start resolved to executable non-image memory with memory intent");
    }
    if (isRemoteCreator && hasThreadContextIntent && hasMemoryIntent && (OutsideMainImage || remoteNonImageExec))
    {
        BLACKBIRDEtwLogDetectionEvent("THREAD_HIJACK_INTENT", 6, actor, ProcessId, CorrelationFlags,
                                      CorrelationAccessMask, CorrelationAgeMs,
                                      L"thread-context + memory intent combined with suspicious remote execution");
    }
    if (isRemoteCreator && (OutsideMainImage || remoteNonImageExec) && hasMemoryIntent &&
        (hasThreadContextIntent || hasDuplicateIntent))
    {
        BLACKBIRDEtwLogDetectionEvent(
            "POSSIBLE_PROCESS_HOLLOWING_OR_INJECTION_INTENT_CHAIN", 7, actor, ProcessId, CorrelationFlags,
            CorrelationAccessMask, CorrelationAgeMs,
            L"memory + thread intent chain with suspicious remote start indicates hollowing/injection");
    }
    if (isRemoteCreator && remoteNonImageExec && hasMemoryIntent && hasThreadContextIntent)
    {
        BLACKBIRDEtwLogDetectionEvent("POSSIBLE_MANUAL_MAP_OR_HOLLOWING_EXECUTION", 6, actor, ProcessId,
                                      CorrelationFlags, CorrelationAccessMask, CorrelationAgeMs,
                                      L"remote non-image execution with memory+thread context intent");
    }

    if (isRemoteCreator)
    {
        marks |= BLACKBIRD_HOLLOW_MARK_REMOTE_THREAD;
    }
    if (OutsideMainImage)
    {
        marks |= BLACKBIRD_HOLLOW_MARK_OUTSIDE_IMAGE;
    }
    if (remoteNonImageExec)
    {
        marks |= BLACKBIRD_HOLLOW_MARK_NON_IMAGE_EXEC;
    }
    if (hasMemoryIntent)
    {
        marks |= BLACKBIRD_HOLLOW_MARK_MEMORY_INTENT;
    }
    if (hasThreadContextIntent)
    {
        marks |= BLACKBIRD_HOLLOW_MARK_THREAD_CONTEXT_INTENT;
    }
    if (hasDuplicateIntent)
    {
        marks |= BLACKBIRD_HOLLOW_MARK_DUP_HANDLE_INTENT;
    }

    BLACKBIRDHollowApplyMarks(actor, ProcessId, marks, CorrelationFlags, CorrelationAccessMask, CorrelationAgeMs);
    BLACKBIRDTempusLeave(BlackbirdTempusSubsystemHollowingEngine, tempusStartQpc);
}
