#include <ntddk.h>
#include "apc_monitor.h"
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

#define SLEEPWALKER_APC_COOLDOWN_MS 2000
#define SLEEPWALKER_APC_RING_SIZE 64

typedef struct _SLEEPWALKER_APC_RING_ENTRY
{
    UINT64 CallerPid;
    UINT64 TargetPid;
    UINT32 Kind;
    INT64 TimestampQpc;
} SLEEPWALKER_APC_RING_ENTRY;

typedef enum _SLEEPWALKER_APC_EVENT_KIND
{
    SLEEPWALKERApcKindRemoteApc = 1,
    SLEEPWALKERApcKindThreadHijack = 2
} SLEEPWALKER_APC_EVENT_KIND;

static SLEEPWALKER_APC_RING_ENTRY g_ApcRing[SLEEPWALKER_APC_RING_SIZE];
static volatile LONG g_ApcRingWriteIndex = -1;
static KSPIN_LOCK g_ApcRingLock;
static volatile LONG g_ApcMonitorInitialized = 0;
static ULONGLONG g_ApcQpcFrequency = 1;

static ULONGLONG SLEEPWALKERApcMsToQpc(_In_ UINT32 Ms)
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

static BOOLEAN SLEEPWALKERApcShouldEmit(_In_ HANDLE CallerPid, _In_ HANDLE TargetPid,
                                        _In_ SLEEPWALKER_APC_EVENT_KIND Kind)
{
    UINT64 caller = (UINT64)(ULONG_PTR)CallerPid;
    UINT64 target = (UINT64)(ULONG_PTR)TargetPid;
    INT64 nowQpc = KeQueryPerformanceCounter(NULL).QuadPart;
    BOOLEAN allow = TRUE;
    UINT32 i;
    KIRQL oldIrql;
    LONG writeIndex;
    ULONGLONG cooldownQpc;

    cooldownQpc = SLEEPWALKERApcMsToQpc(SLEEPWALKER_APC_COOLDOWN_MS);
    KeAcquireSpinLock(&g_ApcRingLock, &oldIrql);

    for (i = 0; i < SLEEPWALKER_APC_RING_SIZE; ++i)
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
        writeIndex %= SLEEPWALKER_APC_RING_SIZE;
        if (writeIndex < 0)
        {
            writeIndex += SLEEPWALKER_APC_RING_SIZE;
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
SLEEPWALKERApcMonitorInitialize(VOID)
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

VOID SLEEPWALKERApcMonitorUninitialize(VOID)
{
    if (InterlockedExchange(&g_ApcMonitorInitialized, 0) == 0)
    {
        return;
    }

    RtlZeroMemory(g_ApcRing, sizeof(g_ApcRing));
    InterlockedExchange(&g_ApcRingWriteIndex, -1);
}

VOID SLEEPWALKERApcMonitorRecordThreadHandleIntent(_In_ HANDLE CallerPid, _In_ HANDLE TargetPid,
                                                   _In_ ACCESS_MASK DesiredAccess, _In_ BOOLEAN IsDuplicateOperation)
{
    BOOLEAN hasSetContext;
    BOOLEAN hasSuspendResume;

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

    if (hasSetContext && !hasSuspendResume &&
        SLEEPWALKERApcShouldEmit(CallerPid, TargetPid, SLEEPWALKERApcKindRemoteApc))
    {
        SLEEPWALKEREtwLogApcEvent("REMOTE_APC_INTENT", CallerPid, TargetPid, DesiredAccess, IsDuplicateOperation, 0, 0,
                                  0);
        SLEEPWALKEREtwLogDetectionEvent("REMOTE_APC_CREATION_SUSPECT", 4, CallerPid, TargetPid, 0,
                                        (UINT32)DesiredAccess, 0,
                                        L"remote thread handle set-context intent suggests APC-style execution");
    }

    if (hasSetContext && hasSuspendResume &&
        SLEEPWALKERApcShouldEmit(CallerPid, TargetPid, SLEEPWALKERApcKindThreadHijack))
    {
        SLEEPWALKEREtwLogApcEvent("THREAD_CONTEXT_INTENT", CallerPid, TargetPid, DesiredAccess, IsDuplicateOperation, 0,
                                  0, 0);
        SLEEPWALKEREtwLogDetectionEvent("THREAD_HIJACK_INTENT", 5, CallerPid, TargetPid, 0, (UINT32)DesiredAccess, 0,
                                        L"thread set-context plus suspend/resume intent indicates hijack pattern");
    }
}

BOOLEAN
SLEEPWALKERApcMonitorSelfCheck(VOID)
{
    return (InterlockedCompareExchange(&g_ApcMonitorInitialized, 0, 0) != 0);
}
