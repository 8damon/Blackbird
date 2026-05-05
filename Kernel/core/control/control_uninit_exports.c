#include "control_private.h"

static volatile LONG g_BkctlInterestLockBusyCounter = 0;

VOID BkctlUninitialize(VOID)
{
    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        return;
    }

    if (InterlockedExchange(&g_ControlInitialized, 0) == 0)
    {
        return;
    }

    BkctlBeginShutdown();
    if (g_ControlDevice != NULL)
    {
        WdfObjectDelete(g_ControlDevice);
        g_ControlDevice = NULL;
    }
    InterlockedExchange(&g_ControlTotalQueuedEvents, 0);
    InterlockedExchange(&g_QueryImageInflight, 0);
    BkctlSetTelemetryArmed(FALSE);
    g_ClientCount = 0;
}

VOID BkctlPublishHandleEvent(_In_ const BK_HANDLE_EVENT *HandleEvent)
{
    ULONGLONG tempusStartQpc = BktmpEnter(BktmpSubsystemControl);
    BK_EVENT_RECORD record;
    UINT32 stream = BK_STREAM_HANDLE;

    if (KeGetCurrentIrql() > APC_LEVEL)
    {
        BktmpLeave(BktmpSubsystemControl, tempusStartQpc);
        return;
    }
    if (HandleEvent == NULL)
    {
        BktmpLeave(BktmpSubsystemControl, tempusStartQpc);
        return;
    }

    RtlZeroMemory(&record, sizeof(record));
    record.Header.Size = sizeof(record);
    record.Header.Type = BlackbirdEventTypeHandle;
    record.Header.TimestampQpc = KeQueryPerformanceCounter(NULL).QuadPart;

    if ((HandleEvent->Flags & BK_HANDLE_FLAG_MEMORY_RELATED) != 0)
    {
        stream |= BK_STREAM_MEMORY;
    }
    record.Header.StreamMask = stream;
    record.Data.Handle = *HandleEvent;

    BkctlPublishRecordToSubscribers(
        (UINT32)HandleEvent->CallerPid,
        ((UINT32)HandleEvent->TargetPid != (UINT32)HandleEvent->CallerPid) ? (UINT32)HandleEvent->TargetPid : 0, stream,
        &record);
    BktmpLeave(BktmpSubsystemControl, tempusStartQpc);
}

VOID BkctlPublishThreadEvent(_In_ UINT64 ProcessId, _In_ UINT64 ThreadId, _In_ UINT64 CreatorPid,
                             _In_ UINT64 StartAddress, _In_ UINT64 ImageBase, _In_ UINT64 ImageSize, _In_ UINT32 Flags,
                             _In_ UINT32 FrameCount, _In_reads_opt_(FrameCount) PVOID const *Frames)
{
    ULONGLONG tempusStartQpc = BktmpEnter(BktmpSubsystemControl);
    BK_EVENT_RECORD record;
    UINT32 i;
    UINT32 safeCount;

    if (KeGetCurrentIrql() > APC_LEVEL)
    {
        BktmpLeave(BktmpSubsystemControl, tempusStartQpc);
        return;
    }

    RtlZeroMemory(&record, sizeof(record));
    record.Header.Size = sizeof(record);
    record.Header.Type = BlackbirdEventTypeThread;
    record.Header.StreamMask = BK_STREAM_THREAD;
    record.Header.TimestampQpc = KeQueryPerformanceCounter(NULL).QuadPart;

    record.Data.Thread.ProcessId = ProcessId;
    record.Data.Thread.ThreadId = ThreadId;
    record.Data.Thread.CreatorPid = CreatorPid;
    record.Data.Thread.StartAddress = StartAddress;
    record.Data.Thread.ImageBase = ImageBase;
    record.Data.Thread.ImageSize = ImageSize;
    record.Data.Thread.Flags = Flags;

    safeCount = (FrameCount > BK_MAX_EVENT_FRAMES) ? BK_MAX_EVENT_FRAMES : FrameCount;
    record.Data.Thread.FrameCount = safeCount;
    if (Frames != NULL)
    {
        for (i = 0; i < safeCount; ++i)
        {
            record.Data.Thread.Frames[i] = (UINT64)(ULONG_PTR)Frames[i];
        }
    }

    BkctlPublishRecordToSubscribers((UINT32)ProcessId,
                                    ((UINT32)CreatorPid != (UINT32)ProcessId) ? (UINT32)CreatorPid : 0,
                                    BK_STREAM_THREAD, &record);
    BktmpLeave(BktmpSubsystemControl, tempusStartQpc);
}

VOID BkctlPublishFileEvent(_In_ const BK_FILE_EVENT *FileEvent)
{
    ULONGLONG tempusStartQpc = BktmpEnter(BktmpSubsystemControl);
    BK_EVENT_RECORD record;

    if (KeGetCurrentIrql() > APC_LEVEL)
    {
        BktmpLeave(BktmpSubsystemControl, tempusStartQpc);
        return;
    }
    if (FileEvent == NULL)
    {
        BktmpLeave(BktmpSubsystemControl, tempusStartQpc);
        return;
    }

    RtlZeroMemory(&record, sizeof(record));
    record.Header.Size = sizeof(record);
    record.Header.Type = BlackbirdEventTypeFileSystem;
    record.Header.StreamMask = BK_STREAM_FILESYSTEM;
    record.Header.TimestampQpc = KeQueryPerformanceCounter(NULL).QuadPart;
    record.Data.FileSystem = *FileEvent;

    BkctlPublishRecordToSubscribers((UINT32)FileEvent->ProcessId, 0, BK_STREAM_FILESYSTEM, &record);
    BktmpLeave(BktmpSubsystemControl, tempusStartQpc);
}

VOID BkctlPublishRegistryEvent(_In_ const BK_REGISTRY_EVENT *RegistryEvent)
{
    ULONGLONG tempusStartQpc = BktmpEnter(BktmpSubsystemControl);
    BK_EVENT_RECORD record;

    if (KeGetCurrentIrql() > APC_LEVEL)
    {
        BktmpLeave(BktmpSubsystemControl, tempusStartQpc);
        return;
    }
    if (RegistryEvent == NULL)
    {
        BktmpLeave(BktmpSubsystemControl, tempusStartQpc);
        return;
    }

    RtlZeroMemory(&record, sizeof(record));
    record.Header.Size = sizeof(record);
    record.Header.Type = BlackbirdEventTypeRegistry;
    record.Header.StreamMask = BK_STREAM_REGISTRY;
    record.Header.TimestampQpc = KeQueryPerformanceCounter(NULL).QuadPart;
    record.Data.Registry = *RegistryEvent;

    BkctlPublishRecordToSubscribers((UINT32)RegistryEvent->ProcessId, 0, BK_STREAM_REGISTRY, &record);
    BktmpLeave(BktmpSubsystemControl, tempusStartQpc);
}

VOID BkctlPublishEnterpriseEvent(_In_ const BK_ENTERPRISE_EVENT *EnterpriseEvent)
{
    ULONGLONG tempusStartQpc = BktmpEnter(BktmpSubsystemControl);
    BK_EVENT_RECORD record;

    if (KeGetCurrentIrql() > APC_LEVEL)
    {
        BktmpLeave(BktmpSubsystemControl, tempusStartQpc);
        return;
    }
    if (EnterpriseEvent == NULL || EnterpriseEvent->ProcessId == 0)
    {
        BktmpLeave(BktmpSubsystemControl, tempusStartQpc);
        return;
    }

    RtlZeroMemory(&record, sizeof(record));
    record.Header.Size = sizeof(record);
    record.Header.Type = BlackbirdEventTypeEnterprise;
    record.Header.StreamMask = BK_STREAM_ENTERPRISE;
    record.Header.TimestampQpc = KeQueryPerformanceCounter(NULL).QuadPart;
    record.Data.Enterprise = *EnterpriseEvent;

    BkctlPublishRecordToSubscribers((UINT32)EnterpriseEvent->ProcessId, (UINT32)EnterpriseEvent->TargetProcessId,
                                    BK_STREAM_ENTERPRISE, &record);
    BktmpLeave(BktmpSubsystemControl, tempusStartQpc);
}

BOOLEAN
BkctlSelfCheck(VOID)
{
    PDEVICE_OBJECT deviceObject;

    if (InterlockedCompareExchange(&g_ControlInitialized, 0, 0) == 0)
    {
        return FALSE;
    }
    if (g_ControlDevice == NULL)
    {
        return FALSE;
    }

    deviceObject = WdfDeviceWdmGetDeviceObject(g_ControlDevice);
    if (deviceObject == NULL)
    {
        return FALSE;
    }

    if ((deviceObject->Flags & DO_DEVICE_INITIALIZING) != 0)
    {
        return FALSE;
    }

    return TRUE;
}

PDEVICE_OBJECT
BkctlGetWdmDeviceObject(VOID)
{
    if (InterlockedCompareExchange(&g_ControlInitialized, 0, 0) == 0 || g_ControlDevice == NULL)
    {
        return NULL;
    }

    return WdfDeviceWdmGetDeviceObject(g_ControlDevice);
}

BOOLEAN
BkctlHasClientsFast(VOID)
{
    if (InterlockedCompareExchange(&g_ControlInitialized, 0, 0) == 0)
    {
        return FALSE;
    }
    if (InterlockedCompareExchange(&g_ControlShutdown, 0, 0) != 0)
    {
        return FALSE;
    }

    return (InterlockedCompareExchange(&g_ClientCount, 0, 0) > 0);
}

BOOLEAN
BkctlHasPidInterest(_In_ UINT32 PrimaryProcessId, _In_ UINT32 SecondaryProcessId, _In_ UINT32 StreamMask)
{
    PBK_CLIENT snapshot[BK_MAX_TOTAL_CLIENTS];
    UINT32 snapshotCount = 0;
    UINT32 i;
    PLIST_ENTRY entry;
    BOOLEAN hasInterest = FALSE;

    if (StreamMask == 0)
    {
        return FALSE;
    }
    if (!BkctlIsArmedFast())
    {
        return FALSE;
    }

    ExAcquireFastMutex(&g_ClientListLock);
    for (entry = g_ClientList.Flink; entry != &g_ClientList; entry = entry->Flink)
    {
        PBK_CLIENT client = CONTAINING_RECORD(entry, BK_CLIENT, Link);
        if (snapshotCount >= RTL_NUMBER_OF(snapshot))
        {
            break;
        }
        BkctlClientReference(client);
        snapshot[snapshotCount++] = client;
    }
    ExReleaseFastMutex(&g_ClientListLock);

    for (i = 0; i < snapshotCount; ++i)
    {
        PBK_CLIENT client = snapshot[i];
        if (!ExTryToAcquireFastMutex(&client->Lock))
        {
            LONG busyCount = InterlockedIncrement(&g_BkctlInterestLockBusyCounter);
            if (busyCount == 1 || ((busyCount & 0xFF) == 0))
            {
                DbgPrintEx(
                    DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                    "BK: pid-interest client lock busy busyCount=%ld primaryPid=%lu secondaryPid=%lu streamMask=0x%08X client=0x%p.\n",
                    busyCount, PrimaryProcessId, SecondaryProcessId, StreamMask, client);
            }
            BkctlClientRelease(client);
            continue;
        }
        if (BkctlClientMatchSubscriptionEither(client, PrimaryProcessId, SecondaryProcessId, StreamMask))
        {
            hasInterest = TRUE;
        }
        ExReleaseFastMutex(&client->Lock);
        BkctlClientRelease(client);
        if (hasInterest)
        {
            break;
        }
    }

    for (++i; i < snapshotCount; ++i)
    {
        BkctlClientRelease(snapshot[i]);
    }

    return hasInterest;
}

BOOLEAN
BkctlIsArmedFast(VOID)
{
    if (InterlockedCompareExchange(&g_ControlInitialized, 0, 0) == 0)
    {
        return FALSE;
    }
    if (InterlockedCompareExchange(&g_ControlShutdown, 0, 0) != 0)
    {
        return FALSE;
    }

    return (InterlockedCompareExchange(&g_ControlTelemetryArmed, 0, 0) != 0);
}
