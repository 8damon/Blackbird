VOID SLEEPWALKERControlUninitialize(VOID)
{
    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        return;
    }

    if (InterlockedExchange(&g_ControlInitialized, 0) == 0)
    {
        return;
    }

    SLEEPWALKERControlBeginShutdown();
    if (g_ControlDevice != NULL)
    {
        WdfObjectDelete(g_ControlDevice);
        g_ControlDevice = NULL;
    }
    InterlockedExchange(&g_ControlTotalQueuedEvents, 0);
    InterlockedExchange(&g_QueryImageInflight, 0);
    g_ClientCount = 0;
}

VOID SLEEPWALKERControlPublishHandleEvent(_In_ const SLEEPWALKER_HANDLE_EVENT *HandleEvent)
{
    SLEEPWALKER_EVENT_RECORD record;
    UINT32 stream = SLEEPWALKER_STREAM_HANDLE;

    if (KeGetCurrentIrql() > APC_LEVEL)
    {
        return;
    }
    if (HandleEvent == NULL)
    {
        return;
    }

    RtlZeroMemory(&record, sizeof(record));
    record.Header.Size = sizeof(record);
    record.Header.Type = SleepwalkerEventTypeHandle;
    record.Header.TimestampQpc = KeQueryPerformanceCounter(NULL).QuadPart;

    if ((HandleEvent->Flags & SLEEPWALKER_HANDLE_FLAG_MEMORY_RELATED) != 0)
    {
        stream |= SLEEPWALKER_STREAM_MEMORY;
    }
    record.Header.StreamMask = stream;
    record.Data.Handle = *HandleEvent;

    SLEEPWALKERPublishRecordToSubscribers(
        (UINT32)HandleEvent->CallerPid,
        ((UINT32)HandleEvent->TargetPid != (UINT32)HandleEvent->CallerPid) ? (UINT32)HandleEvent->TargetPid : 0,
        stream, &record);
}

VOID SLEEPWALKERControlPublishThreadEvent(_In_ UINT64 ProcessId, _In_ UINT64 ThreadId, _In_ UINT64 CreatorPid,
                                          _In_ UINT64 StartAddress, _In_ UINT64 ImageBase, _In_ UINT64 ImageSize,
                                          _In_ UINT32 Flags, _In_ UINT32 FrameCount,
                                          _In_reads_opt_(FrameCount) PVOID const *Frames)
{
    SLEEPWALKER_EVENT_RECORD record;
    UINT32 i;
    UINT32 safeCount;

    if (KeGetCurrentIrql() > APC_LEVEL)
    {
        return;
    }

    RtlZeroMemory(&record, sizeof(record));
    record.Header.Size = sizeof(record);
    record.Header.Type = SleepwalkerEventTypeThread;
    record.Header.StreamMask = SLEEPWALKER_STREAM_THREAD;
    record.Header.TimestampQpc = KeQueryPerformanceCounter(NULL).QuadPart;

    record.Data.Thread.ProcessId = ProcessId;
    record.Data.Thread.ThreadId = ThreadId;
    record.Data.Thread.CreatorPid = CreatorPid;
    record.Data.Thread.StartAddress = StartAddress;
    record.Data.Thread.ImageBase = ImageBase;
    record.Data.Thread.ImageSize = ImageSize;
    record.Data.Thread.Flags = Flags;

    safeCount = (FrameCount > SLEEPWALKER_MAX_EVENT_FRAMES) ? SLEEPWALKER_MAX_EVENT_FRAMES : FrameCount;
    record.Data.Thread.FrameCount = safeCount;
    if (Frames != NULL)
    {
        for (i = 0; i < safeCount; ++i)
        {
            record.Data.Thread.Frames[i] = (UINT64)(ULONG_PTR)Frames[i];
        }
    }

    SLEEPWALKERPublishRecordToSubscribers((UINT32)ProcessId,
                                          ((UINT32)CreatorPid != (UINT32)ProcessId) ? (UINT32)CreatorPid : 0,
                                          SLEEPWALKER_STREAM_THREAD, &record);
}

VOID SLEEPWALKERControlPublishFileEvent(_In_ const SLEEPWALKER_FILE_EVENT *FileEvent)
{
    SLEEPWALKER_EVENT_RECORD record;

    if (KeGetCurrentIrql() > APC_LEVEL)
    {
        return;
    }
    if (FileEvent == NULL)
    {
        return;
    }

    RtlZeroMemory(&record, sizeof(record));
    record.Header.Size = sizeof(record);
    record.Header.Type = SleepwalkerEventTypeFileSystem;
    record.Header.StreamMask = SLEEPWALKER_STREAM_FILESYSTEM;
    record.Header.TimestampQpc = KeQueryPerformanceCounter(NULL).QuadPart;
    record.Data.FileSystem = *FileEvent;

    SLEEPWALKERPublishRecordToSubscribers((UINT32)FileEvent->ProcessId, 0, SLEEPWALKER_STREAM_FILESYSTEM, &record);
}

BOOLEAN
SLEEPWALKERControlSelfCheck(VOID)
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

BOOLEAN
SLEEPWALKERControlHasClientsFast(VOID)
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
SLEEPWALKERControlHasPidInterest(_In_ UINT32 PrimaryProcessId, _In_ UINT32 SecondaryProcessId, _In_ UINT32 StreamMask)
{
    PSLEEPWALKER_CLIENT snapshot[SLEEPWALKER_MAX_TOTAL_CLIENTS];
    UINT32 snapshotCount = 0;
    UINT32 i;
    PLIST_ENTRY entry;
    BOOLEAN hasInterest = FALSE;

    if (StreamMask == 0)
    {
        return FALSE;
    }
    if (!SLEEPWALKERControlHasClientsFast())
    {
        return FALSE;
    }

    ExAcquireFastMutex(&g_ClientListLock);
    for (entry = g_ClientList.Flink; entry != &g_ClientList; entry = entry->Flink)
    {
        PSLEEPWALKER_CLIENT client = CONTAINING_RECORD(entry, SLEEPWALKER_CLIENT, Link);
        if (snapshotCount >= RTL_NUMBER_OF(snapshot))
        {
            break;
        }
        SLEEPWALKERClientReference(client);
        snapshot[snapshotCount++] = client;
    }
    ExReleaseFastMutex(&g_ClientListLock);

    for (i = 0; i < snapshotCount; ++i)
    {
        PSLEEPWALKER_CLIENT client = snapshot[i];
        ExAcquireFastMutex(&client->Lock);
        if (SLEEPWALKERClientMatchSubscriptionEither(client, PrimaryProcessId, SecondaryProcessId, StreamMask))
        {
            hasInterest = TRUE;
        }
        ExReleaseFastMutex(&client->Lock);
        SLEEPWALKERClientRelease(client);
        if (hasInterest)
        {
            break;
        }
    }

    for (++i; i < snapshotCount; ++i)
    {
        SLEEPWALKERClientRelease(snapshot[i]);
    }

    return hasInterest;
}
