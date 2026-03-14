#include <ntddk.h>
#include "intent_store.h"

#define BLACKBIRD_CORRELATION_RING_SIZE 256

typedef struct _BLACKBIRD_INTENT_ENTRY
{
    UINT64 CallerPid;
    UINT64 TargetPid;
    UINT32 AccessMask;
    UINT32 IntentFlags;
    INT64 TimestampQpc;
} BLACKBIRD_INTENT_ENTRY, *PBLACKBIRD_INTENT_ENTRY;

static BLACKBIRD_INTENT_ENTRY g_IntentRing[BLACKBIRD_CORRELATION_RING_SIZE];
static volatile LONG g_IntentWriteIndex = -1;
static KSPIN_LOCK g_IntentLock;
static volatile LONG g_CorrelationInitialized = 0;
static ULONGLONG g_QpcFrequency = 1;

static UINT32 BLACKBIRDCorrelationQpcDeltaToMs(_In_ INT64 DeltaQpc)
{
    ULONGLONG deltaValue;

    if (DeltaQpc <= 0)
    {
        return 0;
    }

    deltaValue = (ULONGLONG) DeltaQpc;
    return (UINT32) ((deltaValue * 1000ULL) / g_QpcFrequency);
}

static ULONGLONG BLACKBIRDCorrelationMsToQpc(_In_ UINT32 Ms)
{
    ULONGLONG ticks;

    if (Ms == 0)
    {
        return 0;
    }

    ticks = ((ULONGLONG) Ms * g_QpcFrequency) / 1000ULL;
    if (ticks == 0)
    {
        ticks = 1;
    }
    return ticks;
}

NTSTATUS
BLACKBIRDCorrelationInitialize(VOID)
{
    LARGE_INTEGER freq;

    if (InterlockedCompareExchange(&g_CorrelationInitialized, 1, 0) != 0)
    {
        return STATUS_SUCCESS;
    }

    KeQueryPerformanceCounter(&freq);
    g_QpcFrequency = (freq.QuadPart > 0) ? (ULONGLONG) freq.QuadPart : 1;
    KeInitializeSpinLock(&g_IntentLock);
    RtlZeroMemory(g_IntentRing, sizeof(g_IntentRing));
    InterlockedExchange(&g_IntentWriteIndex, -1);
    return STATUS_SUCCESS;
}

VOID BLACKBIRDCorrelationUninitialize(VOID)
{
    if (InterlockedExchange(&g_CorrelationInitialized, 0) == 0)
    {
        return;
    }

    RtlZeroMemory(g_IntentRing, sizeof(g_IntentRing));
    InterlockedExchange(&g_IntentWriteIndex, -1);
}

VOID BLACKBIRDCorrelationRecordHandleIntent(_In_ HANDLE CallerPid,
                                            _In_ HANDLE TargetPid,
                                            _In_ ACCESS_MASK AccessMask,
                                            _In_ UINT32 IntentFlags)
{
    LONG idx;
    KIRQL oldIrql;
    INT64 nowQpc;

    if (InterlockedCompareExchange(&g_CorrelationInitialized, 0, 0) == 0)
    {
        return;
    }

    idx = InterlockedIncrement(&g_IntentWriteIndex);
    idx = idx % BLACKBIRD_CORRELATION_RING_SIZE;
    if (idx < 0)
    {
        idx += BLACKBIRD_CORRELATION_RING_SIZE;
    }

    nowQpc = KeQueryPerformanceCounter(NULL).QuadPart;
    KeAcquireSpinLock(&g_IntentLock, &oldIrql);

    g_IntentRing[idx].CallerPid = (UINT64) (ULONG_PTR) CallerPid;
    g_IntentRing[idx].TargetPid = (UINT64) (ULONG_PTR) TargetPid;
    g_IntentRing[idx].AccessMask = (UINT32) AccessMask;
    g_IntentRing[idx].IntentFlags = IntentFlags;

    g_IntentRing[idx].TimestampQpc = nowQpc;

    KeReleaseSpinLock(&g_IntentLock, oldIrql);
}

BOOLEAN
BLACKBIRDCorrelationQueryRecentIntent(_In_ HANDLE CallerPid,
                                      _In_ HANDLE TargetPid,
                                      _In_ UINT32 WindowMs,
                                      _Out_opt_ UINT32 *IntentFlags,
                                      _Out_opt_ UINT32 *AccessMask,
                                      _Out_opt_ UINT32 *AgeMs)
{
    UINT64 caller = (UINT64) (ULONG_PTR) CallerPid;
    UINT64 target = (UINT64) (ULONG_PTR) TargetPid;
    INT64 nowQpc = KeQueryPerformanceCounter(NULL).QuadPart;
    INT64 newestDeltaQpc = MAXLONGLONG;
    UINT32 aggregateIntentFlags = 0;
    UINT32 aggregateAccessMask = 0;
    UINT32 i;
    BOOLEAN found = FALSE;
    KIRQL oldIrql;
    ULONGLONG windowQpc;

    if (IntentFlags != NULL)
    {
        *IntentFlags = 0;
    }
    if (AccessMask != NULL)
    {
        *AccessMask = 0;
    }
    if (AgeMs != NULL)
    {
        *AgeMs = 0;
    }

    if (InterlockedCompareExchange(&g_CorrelationInitialized, 0, 0) == 0)
    {
        return FALSE;
    }

    windowQpc = BLACKBIRDCorrelationMsToQpc(WindowMs);
    KeAcquireSpinLock(&g_IntentLock, &oldIrql);
    for (i = 0; i < BLACKBIRD_CORRELATION_RING_SIZE; ++i)
    {
        INT64 deltaQpc;

        if (g_IntentRing[i].TimestampQpc == 0)
        {
            continue;
        }
        if (g_IntentRing[i].CallerPid != caller || g_IntentRing[i].TargetPid != target)
        {
            continue;
        }

        deltaQpc = nowQpc - g_IntentRing[i].TimestampQpc;
        if (deltaQpc < 0)
        {
            continue;
        }

        if ((ULONGLONG) deltaQpc > windowQpc)
        {
            continue;
        }

        found = TRUE;
        aggregateIntentFlags |= g_IntentRing[i].IntentFlags;
        aggregateAccessMask |= g_IntentRing[i].AccessMask;
        if (deltaQpc < newestDeltaQpc)
        {
            newestDeltaQpc = deltaQpc;
        }
    }
    KeReleaseSpinLock(&g_IntentLock, oldIrql);

    if (!found)
    {
        return FALSE;
    }

    if (IntentFlags != NULL)
    {
        *IntentFlags = aggregateIntentFlags;
    }
    if (AccessMask != NULL)
    {
        *AccessMask = aggregateAccessMask;
    }
    if (AgeMs != NULL)
    {
        *AgeMs = BLACKBIRDCorrelationQpcDeltaToMs(newestDeltaQpc);
    }
    return TRUE;
}

BOOLEAN
BLACKBIRDCorrelationQueryRecentIntentForTarget(_In_ HANDLE TargetPid,
                                               _In_ UINT32 WindowMs,
                                               _In_ BOOLEAN PreferExternalCaller,
                                               _Out_opt_ HANDLE *CallerPid,
                                               _Out_opt_ UINT32 *IntentFlags,
                                               _Out_opt_ UINT32 *AccessMask,
                                               _Out_opt_ UINT32 *AgeMs)
{
    UINT64 target = (UINT64) (ULONG_PTR) TargetPid;
    INT64 nowQpc = KeQueryPerformanceCounter(NULL).QuadPart;
    INT64 bestDeltaQpcAny = MAXLONGLONG;
    UINT64 bestCallerAny = 0;
    BOOLEAN foundAny = FALSE;
    INT64 bestDeltaQpcExternal = MAXLONGLONG;
    UINT64 bestCallerExternal = 0;
    BOOLEAN foundExternal = FALSE;
    UINT64 selectedCaller = 0;
    INT64 newestDeltaQpc = MAXLONGLONG;
    UINT32 aggregateIntentFlags = 0;
    UINT32 aggregateAccessMask = 0;
    UINT32 i;
    KIRQL oldIrql;
    ULONGLONG windowQpc;

    if (CallerPid != NULL)
    {
        *CallerPid = NULL;
    }
    if (IntentFlags != NULL)
    {
        *IntentFlags = 0;
    }
    if (AccessMask != NULL)
    {
        *AccessMask = 0;
    }
    if (AgeMs != NULL)
    {
        *AgeMs = 0;
    }

    if (InterlockedCompareExchange(&g_CorrelationInitialized, 0, 0) == 0)
    {
        return FALSE;
    }

    windowQpc = BLACKBIRDCorrelationMsToQpc(WindowMs);
    KeAcquireSpinLock(&g_IntentLock, &oldIrql);
    for (i = 0; i < BLACKBIRD_CORRELATION_RING_SIZE; ++i)
    {
        INT64 deltaQpc;
        BOOLEAN isExternal;

        if (g_IntentRing[i].TimestampQpc == 0)
        {
            continue;
        }
        if (g_IntentRing[i].TargetPid != target)
        {
            continue;
        }

        deltaQpc = nowQpc - g_IntentRing[i].TimestampQpc;
        if (deltaQpc < 0)
        {
            continue;
        }

        if ((ULONGLONG) deltaQpc > windowQpc)
        {
            continue;
        }

        if (deltaQpc < bestDeltaQpcAny)
        {
            bestDeltaQpcAny = deltaQpc;
            bestCallerAny = g_IntentRing[i].CallerPid;
            foundAny = TRUE;
        }

        isExternal = (g_IntentRing[i].CallerPid != g_IntentRing[i].TargetPid);
        if (isExternal && deltaQpc < bestDeltaQpcExternal)
        {
            bestDeltaQpcExternal = deltaQpc;
            bestCallerExternal = g_IntentRing[i].CallerPid;
            foundExternal = TRUE;
        }
    }

    if (PreferExternalCaller && foundExternal)
    {
        selectedCaller = bestCallerExternal;
    }
    else if (foundAny)
    {
        selectedCaller = bestCallerAny;
    }
    else
    {
        selectedCaller = 0;
    }

    if (selectedCaller != 0)
    {
        for (i = 0; i < BLACKBIRD_CORRELATION_RING_SIZE; ++i)
        {
            INT64 deltaQpc;

            if (g_IntentRing[i].TimestampQpc == 0)
            {
                continue;
            }
            if (g_IntentRing[i].TargetPid != target || g_IntentRing[i].CallerPid != selectedCaller)
            {
                continue;
            }

            deltaQpc = nowQpc - g_IntentRing[i].TimestampQpc;
            if (deltaQpc < 0)
            {
                continue;
            }

            if ((ULONGLONG) deltaQpc > windowQpc)
            {
                continue;
            }

            aggregateIntentFlags |= g_IntentRing[i].IntentFlags;
            aggregateAccessMask |= g_IntentRing[i].AccessMask;
            if (deltaQpc < newestDeltaQpc)
            {
                newestDeltaQpc = deltaQpc;
            }
            foundAny = TRUE;
        }
    }
    KeReleaseSpinLock(&g_IntentLock, oldIrql);

    if (!foundAny || selectedCaller == 0)
    {
        return FALSE;
    }

    if (CallerPid != NULL)
    {
        *CallerPid = (HANDLE) (ULONG_PTR) selectedCaller;
    }
    if (IntentFlags != NULL)
    {
        *IntentFlags = aggregateIntentFlags;
    }
    if (AccessMask != NULL)
    {
        *AccessMask = aggregateAccessMask;
    }
    if (AgeMs != NULL)
    {
        *AgeMs = BLACKBIRDCorrelationQpcDeltaToMs(newestDeltaQpc);
    }
    return TRUE;
}

BOOLEAN
BLACKBIRDCorrelationSelfCheck(VOID)
{
    return (InterlockedCompareExchange(&g_CorrelationInitialized, 0, 0) != 0);
}
