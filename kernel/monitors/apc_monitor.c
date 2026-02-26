#include <ntddk.h>
#include "apc_monitor.h"
#include "correlation.h"
#include "..\telemetry\etw.h"

#ifndef THREAD_SET_CONTEXT
#define THREAD_SET_CONTEXT 0x0010
#endif

#ifndef THREAD_SUSPEND_RESUME
#define THREAD_SUSPEND_RESUME 0x0002
#endif

#define STINGER_APC_COOLDOWN_MS 2000
#define STINGER_APC_RING_SIZE 64

typedef struct _STINGER_APC_RING_ENTRY {
    UINT64 CallerPid;
    UINT64 TargetPid;
    UINT32 Kind;
    INT64 TimestampQpc;
} STINGER_APC_RING_ENTRY;

typedef enum _STINGER_APC_EVENT_KIND {
    STINGERApcKindRemoteApc = 1,
    STINGERApcKindRemoteApcWithMemory = 2,
    STINGERApcKindThreadHijack = 3
} STINGER_APC_EVENT_KIND;

static STINGER_APC_RING_ENTRY g_ApcRing[STINGER_APC_RING_SIZE];
static volatile LONG g_ApcRingWriteIndex = -1;
static KSPIN_LOCK g_ApcRingLock;
static volatile LONG g_ApcMonitorInitialized = 0;
static ULONGLONG g_ApcQpcFrequency = 1;

static
ULONGLONG
STINGERApcMsToQpc(
    _In_ UINT32 Ms
)
{
    ULONGLONG ticks;

    if (Ms == 0) {
        return 0;
    }

    ticks = ((ULONGLONG)Ms * g_ApcQpcFrequency) / 1000ULL;
    if (ticks == 0) {
        ticks = 1;
    }
    return ticks;
}

static
BOOLEAN
STINGERApcShouldEmit(
    _In_ HANDLE CallerPid,
    _In_ HANDLE TargetPid,
    _In_ STINGER_APC_EVENT_KIND Kind
)
{
    UINT64 caller = (UINT64)(ULONG_PTR)CallerPid;
    UINT64 target = (UINT64)(ULONG_PTR)TargetPid;
    INT64 nowQpc = KeQueryPerformanceCounter(NULL).QuadPart;
    BOOLEAN allow = TRUE;
    UINT32 i;
    KIRQL oldIrql;
    LONG writeIndex;
    ULONGLONG cooldownQpc;

    cooldownQpc = STINGERApcMsToQpc(STINGER_APC_COOLDOWN_MS);
    KeAcquireSpinLock(&g_ApcRingLock, &oldIrql);

    for (i = 0; i < STINGER_APC_RING_SIZE; ++i) {
        INT64 deltaQpc;

        if (g_ApcRing[i].TimestampQpc == 0) {
            continue;
        }
        if (g_ApcRing[i].CallerPid != caller ||
            g_ApcRing[i].TargetPid != target ||
            g_ApcRing[i].Kind != (UINT32)Kind) {
            continue;
        }

        deltaQpc = nowQpc - g_ApcRing[i].TimestampQpc;
        if (deltaQpc < 0) {
            continue;
        }

        if ((ULONGLONG)deltaQpc < cooldownQpc) {
            allow = FALSE;
            break;
        }
    }

    if (allow) {
        writeIndex = InterlockedIncrement(&g_ApcRingWriteIndex);
        writeIndex %= STINGER_APC_RING_SIZE;
        if (writeIndex < 0) {
            writeIndex += STINGER_APC_RING_SIZE;
        }

        g_ApcRing[writeIndex].CallerPid = caller;
        g_ApcRing[writeIndex].TargetPid = target;
        g_ApcRing[writeIndex].Kind = (UINT32)Kind;
        g_ApcRing[writeIndex].TimestampQpc = nowQpc;
    }

    KeReleaseSpinLock(&g_ApcRingLock, oldIrql);
    return allow;
}

NTSTATUS
STINGERApcMonitorInitialize(
    VOID
)
{
    LARGE_INTEGER freq;

    if (InterlockedCompareExchange(&g_ApcMonitorInitialized, 1, 0) != 0) {
        return STATUS_SUCCESS;
    }

    freq = KeQueryPerformanceCounter(NULL);
    g_ApcQpcFrequency = (freq.QuadPart > 0) ? (ULONGLONG)freq.QuadPart : 1;
    KeInitializeSpinLock(&g_ApcRingLock);
    RtlZeroMemory(g_ApcRing, sizeof(g_ApcRing));
    InterlockedExchange(&g_ApcRingWriteIndex, -1);
    return STATUS_SUCCESS;
}

VOID
STINGERApcMonitorUninitialize(
    VOID
)
{
    if (InterlockedExchange(&g_ApcMonitorInitialized, 0) == 0) {
        return;
    }

    RtlZeroMemory(g_ApcRing, sizeof(g_ApcRing));
    InterlockedExchange(&g_ApcRingWriteIndex, -1);
}

VOID
STINGERApcMonitorRecordThreadHandleIntent(
    _In_ HANDLE CallerPid,
    _In_ HANDLE TargetPid,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ BOOLEAN IsDuplicateOperation
)
{
    BOOLEAN hasSetContext;
    BOOLEAN hasSuspendResume;
    UINT32 corrFlags = 0;
    UINT32 corrAccess = 0;
    UINT32 corrAgeMs = 0;
    BOOLEAN correlated = FALSE;
    BOOLEAN hasMemoryIntent;

    if (InterlockedCompareExchange(&g_ApcMonitorInitialized, 0, 0) == 0) {
        return;
    }

    if (CallerPid == TargetPid) {
        return;
    }

    hasSetContext = ((DesiredAccess & THREAD_SET_CONTEXT) != 0);
    hasSuspendResume = ((DesiredAccess & THREAD_SUSPEND_RESUME) != 0);
    if (!hasSetContext && !hasSuspendResume) {
        return;
    }

    correlated = STINGERCorrelationQueryRecentIntent(
        CallerPid,
        TargetPid,
        10000,
        &corrFlags,
        &corrAccess,
        &corrAgeMs
    );
    hasMemoryIntent = ((corrFlags & STINGER_INTENT_PROCESS_MEMORY) != 0);

    if (hasSetContext && STINGERApcShouldEmit(CallerPid, TargetPid, STINGERApcKindRemoteApc)) {
        STINGEREtwLogApcEvent(
            "REMOTE_APC_INTENT",
            CallerPid,
            TargetPid,
            DesiredAccess,
            IsDuplicateOperation,
            corrFlags,
            corrAccess,
            corrAgeMs
        );
    }

    if (hasSetContext && hasMemoryIntent &&
        STINGERApcShouldEmit(CallerPid, TargetPid, STINGERApcKindRemoteApcWithMemory)) {
        STINGEREtwLogDetectionEvent(
            "REMOTE_APC_CREATION_SUSPECT",
            4,
            CallerPid,
            TargetPid,
            corrFlags,
            corrAccess,
            correlated ? corrAgeMs : 0,
            L"thread set-context intent against remote process with recent process-memory intent; compatible with queued APC injection semantics"
        );
    }

    if (hasSetContext && hasSuspendResume &&
        STINGERApcShouldEmit(CallerPid, TargetPid, STINGERApcKindThreadHijack)) {
        STINGEREtwLogDetectionEvent(
            "THREAD_HIJACK_INTENT",
            hasMemoryIntent ? 4 : 3,
            CallerPid,
            TargetPid,
            corrFlags,
            corrAccess,
            correlated ? corrAgeMs : 0,
            L"remote thread set-context and suspend/resume intent observed; possible thread hijack workflow"
        );
    }
}

BOOLEAN
STINGERApcMonitorSelfCheck(
    VOID
)
{
    return (InterlockedCompareExchange(&g_ApcMonitorInitialized, 0, 0) != 0);
}
