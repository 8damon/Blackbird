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

VOID SLEEPWALKERControlPublishHandleEvent(_In_ UINT64 CallerPid, _In_ UINT64 TargetPid, _In_ UINT32 DesiredAccess,
                                          _In_ UINT32 ClassId, _In_ UINT64 OriginAddress, _In_ UINT32 OriginProtect,
                                          _In_ UINT32 Flags, _In_opt_z_ PCWSTR OriginPath, _In_ UINT32 FrameCount,
                                          _In_reads_opt_(FrameCount) PVOID const *Frames, _In_ INT32 StatusOpenProcess,
                                          _In_ INT32 StatusBasicInfo, _In_ INT32 StatusSectionName,
                                          _In_ UINT64 DeepAllocationBase, _In_ UINT64 DeepRegionSize,
                                          _In_ UINT32 DeepRegionProtect, _In_ UINT32 DeepRegionState,
                                          _In_ UINT32 DeepRegionType, _In_ UINT32 DeepSampleSize,
                                          _In_reads_bytes_opt_(DeepSampleSize) const UCHAR *DeepSample)
{
    SLEEPWALKER_EVENT_RECORD record;
    UINT32 stream = SLEEPWALKER_STREAM_HANDLE;
    UINT32 i;
    UINT32 safeCount;

    if (KeGetCurrentIrql() > APC_LEVEL)
    {
        return;
    }

    RtlZeroMemory(&record, sizeof(record));
    record.Header.Size = sizeof(record);
    record.Header.Type = SleepwalkerEventTypeHandle;
    record.Header.TimestampQpc = KeQueryPerformanceCounter(NULL).QuadPart;

    if ((Flags & SLEEPWALKER_HANDLE_FLAG_MEMORY_RELATED) != 0)
    {
        stream |= SLEEPWALKER_STREAM_MEMORY;
    }
    record.Header.StreamMask = stream;

    record.Data.Handle.CallerPid = CallerPid;
    record.Data.Handle.TargetPid = TargetPid;
    record.Data.Handle.DesiredAccess = DesiredAccess;
    record.Data.Handle.ClassId = ClassId;
    record.Data.Handle.OriginAddress = OriginAddress;
    record.Data.Handle.OriginProtect = OriginProtect;
    record.Data.Handle.Flags = Flags;
    record.Data.Handle.StatusOpenProcess = StatusOpenProcess;
    record.Data.Handle.StatusBasicInfo = StatusBasicInfo;
    record.Data.Handle.StatusSectionName = StatusSectionName;
    record.Data.Handle.DeepAllocationBase = DeepAllocationBase;
    record.Data.Handle.DeepRegionSize = DeepRegionSize;
    record.Data.Handle.DeepRegionProtect = DeepRegionProtect;
    record.Data.Handle.DeepRegionState = DeepRegionState;
    record.Data.Handle.DeepRegionType = DeepRegionType;

    if (DeepSample != NULL && DeepSampleSize != 0)
    {
        UINT32 safeDeepBytes =
            (DeepSampleSize > SLEEPWALKER_MAX_DEEP_SAMPLE_BYTES) ? SLEEPWALKER_MAX_DEEP_SAMPLE_BYTES : DeepSampleSize;
        record.Data.Handle.DeepSampleSize = safeDeepBytes;
        RtlCopyMemory(record.Data.Handle.DeepSample, DeepSample, safeDeepBytes);
    }

    safeCount = (FrameCount > SLEEPWALKER_MAX_EVENT_FRAMES) ? SLEEPWALKER_MAX_EVENT_FRAMES : FrameCount;
    record.Data.Handle.FrameCount = safeCount;
    if (Frames != NULL)
    {
        for (i = 0; i < safeCount; ++i)
        {
            record.Data.Handle.Frames[i] = (UINT64)(ULONG_PTR)Frames[i];
        }
    }

    if (OriginPath != NULL)
    {
        (void)RtlStringCchCopyW(record.Data.Handle.OriginPath, RTL_NUMBER_OF(record.Data.Handle.OriginPath),
                                OriginPath);
    }

    SLEEPWALKERPublishRecordToSubscribers(
        (UINT32)CallerPid, ((UINT32)TargetPid != (UINT32)CallerPid) ? (UINT32)TargetPid : 0, stream, &record);
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
