#include <ntddk.h>
#include "apc_monitor.h"
#include "..\correlation\intent_store.h"
#include "..\core\tempus_debug.h"
#include "..\telemetry\etw.h"
#include "..\callbacks\process_monitor.h"

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

#define BK_APC_COOLDOWN_MS 7000
#define BK_APC_RING_SIZE 64
#define BK_APC_INTENT_WINDOW_MS 12000

typedef struct _BK_APC_RING_ENTRY
{
    UINT64 CallerPid;
    UINT64 TargetPid;
    UINT32 Kind;
    INT64 TimestampQpc;
} BK_APC_RING_ENTRY;

typedef enum _BK_APC_EVENT_KIND
{
    BkapcKindRemoteApc = 1,
    BkapcKindThreadHijack = 2
} BK_APC_EVENT_KIND;

static BK_APC_RING_ENTRY g_ApcRing[BK_APC_RING_SIZE];
static volatile LONG g_ApcRingWriteIndex = -1;
static KSPIN_LOCK g_ApcRingLock;
static volatile LONG g_ApcMonitorInitialized = 0;
static ULONGLONG g_ApcQpcFrequency = 1;

static ULONGLONG BkapcMsToQpc(_In_ UINT32 Ms)
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

static BOOLEAN BkapcShouldEmit(_In_ HANDLE CallerPid, _In_ HANDLE TargetPid, _In_ BK_APC_EVENT_KIND Kind)
{
    UINT64 caller = (UINT64)(ULONG_PTR)CallerPid;
    UINT64 target = (UINT64)(ULONG_PTR)TargetPid;
    INT64 nowQpc = KeQueryPerformanceCounter(NULL).QuadPart;
    BOOLEAN allow = TRUE;
    UINT32 i;
    KIRQL oldIrql;
    LONG writeIndex;
    ULONGLONG cooldownQpc;

    cooldownQpc = BkapcMsToQpc(BK_APC_COOLDOWN_MS);
    KeAcquireSpinLock(&g_ApcRingLock, &oldIrql);

    for (i = 0; i < BK_APC_RING_SIZE; ++i)
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
        writeIndex %= BK_APC_RING_SIZE;
        if (writeIndex < 0)
        {
            writeIndex += BK_APC_RING_SIZE;
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
BkapcInitialize(VOID)
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

VOID BkapcUninitialize(VOID)
{
    if (InterlockedExchange(&g_ApcMonitorInitialized, 0) == 0)
    {
        return;
    }

    RtlZeroMemory(g_ApcRing, sizeof(g_ApcRing));
    InterlockedExchange(&g_ApcRingWriteIndex, -1);
}

VOID BkapcRecordThreadHandleIntent(_In_ HANDLE CallerPid, _In_ HANDLE TargetPid, _In_ ACCESS_MASK DesiredAccess,
                                   _In_ BOOLEAN IsDuplicateOperation)
{
    ULONGLONG tempusStartQpc = BktmpEnter(BktmpSubsystemApcMonitor);
    BOOLEAN hasSetContext;
    BOOLEAN hasSuspendResume;
    BOOLEAN hasRecentIntent;
    BOOLEAN hasMemoryIntent;
    BOOLEAN suppressSystemBrokerNoise;
    UINT32 intentFlags = 0;
    UINT32 intentAccessMask = 0;
    UINT32 intentAgeMs = 0;

    if (InterlockedCompareExchange(&g_ApcMonitorInitialized, 0, 0) == 0)
    {
        BktmpLeave(BktmpSubsystemApcMonitor, tempusStartQpc);
        return;
    }

    if (CallerPid == TargetPid)
    {
        BktmpLeave(BktmpSubsystemApcMonitor, tempusStartQpc);
        return;
    }

    hasSetContext = ((DesiredAccess & THREAD_SET_CONTEXT) != 0);
    hasSuspendResume = ((DesiredAccess & THREAD_SUSPEND_RESUME) != 0);
    if (!hasSetContext && !hasSuspendResume)
    {
        BktmpLeave(BktmpSubsystemApcMonitor, tempusStartQpc);
        return;
    }
    hasRecentIntent = BkcorQueryRecentIntent(CallerPid, TargetPid, BK_APC_INTENT_WINDOW_MS, &intentFlags,
                                             &intentAccessMask, &intentAgeMs);
    hasMemoryIntent = hasRecentIntent && ((intentFlags & BK_INTENT_PROCESS_MEMORY) != 0);
    suppressSystemBrokerNoise = BkcprocIsKnownSystemBrokerPid((UINT32)(ULONG_PTR)CallerPid) &&
                                !BkcprocIsProtectedPid((UINT32)(ULONG_PTR)TargetPid);

    if (suppressSystemBrokerNoise)
    {
        BktmpLeave(BktmpSubsystemApcMonitor, tempusStartQpc);
        return;
    }

    UNREFERENCED_PARAMETER(IsDuplicateOperation);

    if (BkapcShouldEmit(CallerPid, TargetPid, hasSetContext ? BkapcKindRemoteApc : BkapcKindThreadHijack))
    {
        BketwLogApcEvent(hasSetContext ? "REMOTE_THREAD_HANDLE_APC_INTENT" : "REMOTE_THREAD_HANDLE_CONTEXT_INTENT",
                         CallerPid, TargetPid, DesiredAccess, IsDuplicateOperation, intentFlags, intentAccessMask,
                         intentAgeMs);

        if (hasSetContext && hasMemoryIntent)
        {
            BketwLogDetectionEvent(
                "REMOTE_APC_CREATION", hasSuspendResume ? 6u : 5u, CallerPid, TargetPid, intentFlags, intentAccessMask,
                intentAgeMs,
                hasSuspendResume
                    ? L"remote thread handle has THREAD_SET_CONTEXT plus suspend/resume after memory intent"
                    : L"remote thread handle has THREAD_SET_CONTEXT after memory intent");
        }
    }
    BktmpLeave(BktmpSubsystemApcMonitor, tempusStartQpc);
}

BOOLEAN
BkapcSelfCheck(VOID)
{
    return (InterlockedCompareExchange(&g_ApcMonitorInitialized, 0, 0) != 0);
}
