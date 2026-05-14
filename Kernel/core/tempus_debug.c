#include "tempus_debug.h"

#ifdef BK_TEMPUS_DEBUG

typedef struct _BK_TEMPUS_BUCKET_STATE
{
    volatile LONG64 SampleCount;
    volatile LONG64 TotalQpc;
    volatile LONG64 MaxQpc;
    volatile LONG64 LastQpc;
} BK_TEMPUS_BUCKET_STATE;

static volatile LONG g_BlackbirdTempusEnabled = 0;
static UINT64 g_BlackbirdTempusQpcFrequency = 0;
static BK_TEMPUS_BUCKET_STATE g_BlackbirdTempusBuckets[BK_TEMPUS_SUBSYSTEM_COUNT];

static VOID BktmpUpdateMax(_Inout_ volatile LONG64 *Target, _In_ LONG64 Candidate)
{
    LONG64 observed;

    do
    {
        observed = InterlockedCompareExchange64(Target, 0, 0);
        if (Candidate <= observed)
        {
            return;
        }
    } while (InterlockedCompareExchange64(Target, Candidate, observed) != observed);
}

NTSTATUS BktmpInitialize(VOID)
{
    LARGE_INTEGER counter;

    counter = KeQueryPerformanceCounter(NULL);
    g_BlackbirdTempusQpcFrequency = (counter.QuadPart > 0) ? (UINT64)counter.QuadPart : 1ULL;
    RtlZeroMemory(g_BlackbirdTempusBuckets, sizeof(g_BlackbirdTempusBuckets));
    InterlockedExchange(&g_BlackbirdTempusEnabled, 1);
    return STATUS_SUCCESS;
}

VOID BktmpUninitialize(VOID)
{
    InterlockedExchange(&g_BlackbirdTempusEnabled, 0);
}

BOOLEAN BktmpIsEnabled(VOID)
{
    return (InterlockedCompareExchange(&g_BlackbirdTempusEnabled, 0, 0) != 0);
}

UINT64 BktmpGetQpcFrequency(VOID)
{
    return g_BlackbirdTempusQpcFrequency;
}

ULONGLONG BktmpEnter(_In_ UINT32 SubsystemId)
{
    UNREFERENCED_PARAMETER(SubsystemId);

    if (!BktmpIsEnabled())
    {
        return 0;
    }

    return (ULONGLONG)KeQueryPerformanceCounter(NULL).QuadPart;
}

VOID BktmpLeave(_In_ UINT32 SubsystemId, _In_ ULONGLONG StartQpc)
{
    ULONGLONG endQpc;
    ULONGLONG elapsedQpc;

    if (!BktmpIsEnabled() || StartQpc == 0 || SubsystemId >= BK_TEMPUS_SUBSYSTEM_COUNT)
    {
        return;
    }

    endQpc = (ULONGLONG)KeQueryPerformanceCounter(NULL).QuadPart;
    elapsedQpc = (endQpc >= StartQpc) ? (endQpc - StartQpc) : 0ULL;

    InterlockedIncrement64(&g_BlackbirdTempusBuckets[SubsystemId].SampleCount);
    InterlockedAdd64(&g_BlackbirdTempusBuckets[SubsystemId].TotalQpc, (LONG64)elapsedQpc);
    InterlockedExchange64(&g_BlackbirdTempusBuckets[SubsystemId].LastQpc, (LONG64)elapsedQpc);
    BktmpUpdateMax(&g_BlackbirdTempusBuckets[SubsystemId].MaxQpc, (LONG64)elapsedQpc);
}

VOID BktmpQueryStats(_Out_writes_(BucketCount) PBK_TEMPUS_BUCKET Buckets, _In_ UINT32 BucketCount,
                     _Out_opt_ UINT64 *QpcFrequency)
{
    UINT32 i;
    UINT32 safeCount;

    if (Buckets == NULL || BucketCount == 0)
    {
        return;
    }

    safeCount = (BucketCount < BK_TEMPUS_SUBSYSTEM_COUNT) ? BucketCount : BK_TEMPUS_SUBSYSTEM_COUNT;
    RtlZeroMemory(Buckets, sizeof(*Buckets) * BucketCount);

    for (i = 0; i < safeCount; ++i)
    {
        Buckets[i].SampleCount = (UINT64)InterlockedCompareExchange64(&g_BlackbirdTempusBuckets[i].SampleCount, 0, 0);
        Buckets[i].TotalQpc = (UINT64)InterlockedCompareExchange64(&g_BlackbirdTempusBuckets[i].TotalQpc, 0, 0);
        Buckets[i].MaxQpc = (UINT64)InterlockedCompareExchange64(&g_BlackbirdTempusBuckets[i].MaxQpc, 0, 0);
        Buckets[i].LastQpc = (UINT64)InterlockedCompareExchange64(&g_BlackbirdTempusBuckets[i].LastQpc, 0, 0);
    }

    if (QpcFrequency != NULL)
    {
        *QpcFrequency = g_BlackbirdTempusQpcFrequency;
    }
}

#endif
