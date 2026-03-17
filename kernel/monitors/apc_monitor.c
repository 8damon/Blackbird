#include <ntddk.h>
#include "apc_monitor.h"
#include "..\correlation\intent_store.h"
#include "..\telemetry\etw.h"

#ifndef THREAD_SET_CONTEXT
#define THREAD_SET_CONTEXT 0x0010
#endif

#ifndef THREAD_SUSPEND_RESUME
#define THREAD_SUSPEND_RESUME 0x0002
#endif

#ifndef THREAD_GET_CONTEXT
#define THREAD_GET_CONTEXT 0x0008
#endif

#ifndef THREAD_ALL_ACCESS
#define THREAD_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xFFFF)
#endif

#define BLACKBIRD_APC_COOLDOWN_MS 7000
#define BLACKBIRD_APC_RING_SIZE 64
#define BLACKBIRD_APC_INTENT_WINDOW_MS 12000

typedef struct _BLACKBIRD_APC_RING_ENTRY
{
    UINT64 CallerPid;
    UINT64 TargetPid;
    UINT32 Kind;
    INT64 TimestampQpc;
} BLACKBIRD_APC_RING_ENTRY;

typedef enum _BLACKBIRD_APC_EVENT_KIND
{
    BLACKBIRDApcKindRemoteApc = 1,
    BLACKBIRDApcKindThreadHijack = 2
} BLACKBIRD_APC_EVENT_KIND;

static BLACKBIRD_APC_RING_ENTRY g_ApcRing[BLACKBIRD_APC_RING_SIZE];
static volatile LONG g_ApcRingWriteIndex = -1;
static KSPIN_LOCK g_ApcRingLock;
static volatile LONG g_ApcMonitorInitialized = 0;
static ULONGLONG g_ApcQpcFrequency = 1;

static ULONGLONG BLACKBIRDApcMsToQpc(_In_ UINT32 Ms)
{
    ULONGLONG ticks;

    if (Ms == 0)
    {
        return 0;
    }

    ticks = ((ULONGLONG)Ms * g_ApcQpcFrequency) / 1000ULL;
    if (ticks == 0)
    {
        ticks = 1;
    }
    return ticks;
}

static BOOLEAN BLACKBIRDApcShouldEmit(_In_ HANDLE CallerPid, _In_ HANDLE TargetPid,
                                        _In_ BLACKBIRD_APC_EVENT_KIND Kind)
{
    UINT64 caller = (UINT64)(ULONG_PTR)CallerPid;
    UINT64 target = (UINT64)(ULONG_PTR)TargetPid;
    INT64 nowQpc = KeQueryPerformanceCounter(NULL).QuadPart;
    BOOLEAN allow = TRUE;
    UINT32 i;
    KIRQL oldIrql;
    LONG writeIndex;
    ULONGLONG cooldownQpc;

    cooldownQpc = BLACKBIRDApcMsToQpc(BLACKBIRD_APC_COOLDOWN_MS);
    KeAcquireSpinLock(&g_ApcRingLock, &oldIrql);

    for (i = 0; i < BLACKBIRD_APC_RING_SIZE; ++i)
    {
        INT64 deltaQpc;

        if (g_ApcRing[i].TimestampQpc == 0)
        {
            continue;
        }
        if (g_ApcRing[i].CallerPid != caller || g_ApcRing[i].TargetPid != target || g_ApcRing[i].Kind != (UINT32)Kind)
        {
            continue;
        }

        deltaQpc = nowQpc - g_ApcRing[i].TimestampQpc;
        if (deltaQpc < 0)
        {
            continue;
        }

        if ((ULONGLONG)deltaQpc < cooldownQpc)
        {
            allow = FALSE;
            break;
        }
    }

    if (allow)
    {
        writeIndex = InterlockedIncrement(&g_ApcRingWriteIndex);
        writeIndex %= BLACKBIRD_APC_RING_SIZE;
        if (writeIndex < 0)
        {
            writeIndex += BLACKBIRD_APC_RING_SIZE;
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
BLACKBIRDApcMonitorInitialize(VOID)
{
    LARGE_INTEGER freq;

    if (InterlockedCompareExchange(&g_ApcMonitorInitialized, 1, 0) != 0)
    {
        return STATUS_SUCCESS;
    }

    freq = KeQueryPerformanceCounter(NULL);
    g_ApcQpcFrequency = (freq.QuadPart > 0) ? (ULONGLONG)freq.QuadPart : 1;
    KeInitializeSpinLock(&g_ApcRingLock);
    RtlZeroMemory(g_ApcRing, sizeof(g_ApcRing));
    InterlockedExchange(&g_ApcRingWriteIndex, -1);
    return STATUS_SUCCESS;
}

VOID BLACKBIRDApcMonitorUninitialize(VOID)
{
    if (InterlockedExchange(&g_ApcMonitorInitialized, 0) == 0)
    {
        return;
    }

    RtlZeroMemory(g_ApcRing, sizeof(g_ApcRing));
    InterlockedExchange(&g_ApcRingWriteIndex, -1);
}

VOID BLACKBIRDApcMonitorRecordThreadHandleIntent(_In_ HANDLE CallerPid, _In_ HANDLE TargetPid,
                                                   _In_ ACCESS_MASK DesiredAccess, _In_ BOOLEAN IsDuplicateOperation)
{
    BOOLEAN hasSetContext;
    BOOLEAN hasSuspendResume;
    BOOLEAN hasRecentIntent;
    BOOLEAN hasMemoryIntent;
    UINT32 intentFlags = 0;
    UINT32 intentAccessMask = 0;
    UINT32 intentAgeMs = 0;

    if (InterlockedCompareExchange(&g_ApcMonitorInitialized, 0, 0) == 0)
    {
        return;
    }

    if (CallerPid == TargetPid)
    {
        return;
    }

    hasSetContext = ((DesiredAccess & THREAD_SET_CONTEXT) != 0);
    hasSuspendResume = ((DesiredAccess & THREAD_SUSPEND_RESUME) != 0);
    if (!hasSetContext && !hasSuspendResume)
    {
        return;
    }
    hasRecentIntent = BLACKBIRDCorrelationQueryRecentIntent(CallerPid, TargetPid, BLACKBIRD_APC_INTENT_WINDOW_MS,
                                                              &intentFlags, &intentAccessMask, &intentAgeMs);
    hasMemoryIntent = hasRecentIntent && ((intentFlags & BLACKBIRD_INTENT_PROCESS_MEMORY) != 0);

    if (hasSetContext && hasSuspendResume && hasMemoryIntent &&
        BLACKBIRDApcShouldEmit(CallerPid, TargetPid, BLACKBIRDApcKindRemoteApc))
    {
        BLACKBIRDEtwLogApcEvent("REMOTE_APC_INTENT", CallerPid, TargetPid, DesiredAccess, IsDuplicateOperation,
                                  intentFlags, intentAccessMask, intentAgeMs);
        BLACKBIRDEtwLogDetectionEvent("REMOTE_APC_CREATION_SUSPECT", 5, CallerPid, TargetPid, intentFlags,
                                        intentAccessMask, intentAgeMs,
                                        L"set-context plus suspend/resume with recent process-memory intent");
    }

    if (hasSetContext && hasSuspendResume && hasMemoryIntent &&
        BLACKBIRDApcShouldEmit(CallerPid, TargetPid, BLACKBIRDApcKindThreadHijack))
    {
        BLACKBIRDEtwLogApcEvent("THREAD_CONTEXT_INTENT", CallerPid, TargetPid, DesiredAccess, IsDuplicateOperation,
                                  intentFlags, intentAccessMask, intentAgeMs);
        BLACKBIRDEtwLogDetectionEvent("THREAD_HIJACK_INTENT", 6, CallerPid, TargetPid, intentFlags,
                                        intentAccessMask, intentAgeMs,
                                        L"high-confidence hijack intent chain (thread context + memory intent)");
    }
}

BOOLEAN
BLACKBIRDApcMonitorSelfCheck(VOID)
{
    return (InterlockedCompareExchange(&g_ApcMonitorInitialized, 0, 0) != 0);
}

