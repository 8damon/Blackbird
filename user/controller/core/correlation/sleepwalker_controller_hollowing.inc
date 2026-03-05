#define SLEEPWALKER_HOLLOW_MARK_CREATE_SUSPENDED 0x00000001ull
#define SLEEPWALKER_HOLLOW_MARK_TI_ALLOC_RW_LARGE 0x00000002ull
#define SLEEPWALKER_HOLLOW_MARK_TI_WRITE_VM 0x00000004ull
#define SLEEPWALKER_HOLLOW_MARK_TI_PROTECT_RX 0x00000008ull
#define SLEEPWALKER_HOLLOW_MARK_THREAD_START_NON_IMAGE_EXEC 0x00000010ull
#define SLEEPWALKER_HOLLOW_MARK_THREAD_START_OUTSIDE_IMAGE 0x00000020ull
#define SLEEPWALKER_HOLLOW_MARK_THREAD_CONTEXT_INTENT 0x00000040ull
#define SLEEPWALKER_HOLLOW_MARK_REMOTE_THREAD_INTENT 0x00000080ull
#define SLEEPWALKER_HOLLOW_MARK_IMAGE_DRIFT 0x00000100ull
#define SLEEPWALKER_HOLLOW_MARK_TXF_SUSPECT 0x00000200ull

#ifndef SLEEPWALKER_INTENT_THREAD_CONTEXT
#define SLEEPWALKER_INTENT_THREAD_CONTEXT 0x00000002u
#endif

static BOOL ControllerWideContainsInsensitive(_In_opt_z_ PCWSTR Haystack, _In_z_ PCWSTR Needle)
{
    size_t hayLen;
    size_t needleLen;
    size_t i;

    if (Haystack == NULL || Needle == NULL || Needle[0] == L'\0')
    {
        return FALSE;
    }

    hayLen = wcslen(Haystack);
    needleLen = wcslen(Needle);
    if (needleLen == 0 || hayLen < needleLen)
    {
        return FALSE;
    }

    for (i = 0; i <= (hayLen - needleLen); ++i)
    {
        if (_wcsnicmp(Haystack + i, Needle, needleLen) == 0)
        {
            return TRUE;
        }
    }

    return FALSE;
}

static BOOL ControllerEtwTryGetU64Any(_In_ PEVENT_RECORD Record, _In_reads_(NameCount) const PCWSTR *Names,
                                      _In_ size_t NameCount, _Out_ ULONGLONG *Value)
{
    size_t i;

    if (Value == NULL)
    {
        return FALSE;
    }
    *Value = 0;

    for (i = 0; i < NameCount; ++i)
    {
        if (ControllerEtwGetU64Property(Record, Names[i], Value))
        {
            return TRUE;
        }
    }

    return FALSE;
}

static BOOL ControllerEtwTryGetU32Any(_In_ PEVENT_RECORD Record, _In_reads_(NameCount) const PCWSTR *Names,
                                      _In_ size_t NameCount, _Out_ ULONG *Value)
{
    size_t i;

    if (Value == NULL)
    {
        return FALSE;
    }
    *Value = 0;

    for (i = 0; i < NameCount; ++i)
    {
        if (ControllerEtwGetU32Property(Record, Names[i], Value))
        {
            return TRUE;
        }
    }

    return FALSE;
}

static BOOL ControllerIsWritableProtect(_In_ ULONG Protect)
{
    switch (Protect & 0xFF)
    {
    case PAGE_READWRITE:
    case PAGE_WRITECOPY:
    case PAGE_EXECUTE_READWRITE:
    case PAGE_EXECUTE_WRITECOPY:
        return TRUE;
    default:
        return FALSE;
    }
}

static BOOL ControllerIsExecutableProtect(_In_ ULONG Protect)
{
    switch (Protect & 0xFF)
    {
    case PAGE_EXECUTE:
    case PAGE_EXECUTE_READ:
    case PAGE_EXECUTE_READWRITE:
    case PAGE_EXECUTE_WRITECOPY:
        return TRUE;
    default:
        return FALSE;
    }
}

static PSLEEPWALKER_CONTROLLER_HOLLOW_ENTRY ControllerGetHollowEntryLocked(_In_ DWORD ActorPid, _In_ DWORD TargetPid,
                                                                           _In_ ULONGLONG NowTick)
{
    DWORD i;
    DWORD candidate = SLEEPWALKER_CONTROLLER_HOLLOW_MAX_ENTRIES;
    ULONGLONG oldestTick = ~0ull;

    if (TargetPid == 0)
    {
        return NULL;
    }
    if (ActorPid == 0)
    {
        ActorPid = TargetPid;
    }

    for (i = 0; i < SLEEPWALKER_CONTROLLER_HOLLOW_MAX_ENTRIES; ++i)
    {
        if (!g_HollowEntries[i].Active)
        {
            candidate = i;
            break;
        }

        if (g_HollowEntries[i].TargetPid == TargetPid && g_HollowEntries[i].ActorPid == ActorPid)
        {
            return &g_HollowEntries[i];
        }

        if ((NowTick - g_HollowEntries[i].LastSeenTick) > (SLEEPWALKER_CONTROLLER_HOLLOW_WINDOW_MS * 2ull))
        {
            candidate = i;
            break;
        }

        if (g_HollowEntries[i].LastSeenTick < oldestTick)
        {
            oldestTick = g_HollowEntries[i].LastSeenTick;
            candidate = i;
        }
    }

    if (candidate >= SLEEPWALKER_CONTROLLER_HOLLOW_MAX_ENTRIES)
    {
        return NULL;
    }

    ZeroMemory(&g_HollowEntries[candidate], sizeof(g_HollowEntries[candidate]));
    g_HollowEntries[candidate].Active = TRUE;
    g_HollowEntries[candidate].ActorPid = ActorPid;
    g_HollowEntries[candidate].TargetPid = TargetPid;
    g_HollowEntries[candidate].FirstSeenTick = NowTick;
    g_HollowEntries[candidate].LastSeenTick = NowTick;
    return &g_HollowEntries[candidate];
}

static VOID ControllerEmitSyntheticDetection(_In_ DWORD ActorPid, _In_ DWORD TargetPid, _In_z_ PCSTR DetectionName,
                                             _In_ DWORD Severity, _In_ UINT64 Marks)
{
    SLEEPWALKER_IPC_ETW_EVENT event;

    if (DetectionName == NULL || DetectionName[0] == '\0' || TargetPid == 0)
    {
        return;
    }

    ZeroMemory(&event, sizeof(event));
    event.Source = SleepwalkerIpcEtwSourceSleepwalker;
    event.EventId = 0;
    event.Opcode = 0;
    event.Task = 0;
    event.EventProcessId = (ActorPid != 0) ? ActorPid : TargetPid;
    event.EventThreadId = 0;
    event.Severity = Severity;
    event.PrimaryPid = (ActorPid != 0) ? (UINT64)ActorPid : (UINT64)TargetPid;
    event.SecondaryPid = (UINT64)TargetPid;
    event.CorrelationFlags = 0;
    event.CorrelationAccessMask = 0;
    event.CorrelationAgeMs = 0;
    (void)StringCchCopyW(event.EventName, RTL_NUMBER_OF(event.EventName), L"DetectionTelemetry");
    (void)StringCchCopyA(event.DetectionName, RTL_NUMBER_OF(event.DetectionName), DetectionName);
    (void)StringCchPrintfW(event.Reason, RTL_NUMBER_OF(event.Reason), L"synthetic chain marks=0x%llX", Marks);

    (void)InterlockedIncrement(&g_EtwDetectionEvents);
    ControllerDispatchEtwEvent(&event);
    ControllerLog("[ETW][SYNTH] detection=%s severity=%lu actor=%lu target=%lu marks=0x%llX\n", DetectionName,
                  Severity, ActorPid, TargetPid, Marks);
}

static VOID ControllerEvaluateHollowEntryLocked(_Inout_ PSLEEPWALKER_CONTROLLER_HOLLOW_ENTRY Entry, _In_ ULONGLONG NowTick)
{
    const UINT64 marks = Entry->Marks;
    const BOOL hasSuspended = ((marks & SLEEPWALKER_HOLLOW_MARK_CREATE_SUSPENDED) != 0);
    const BOOL hasAlloc = ((marks & SLEEPWALKER_HOLLOW_MARK_TI_ALLOC_RW_LARGE) != 0);
    const BOOL hasWrite = ((marks & SLEEPWALKER_HOLLOW_MARK_TI_WRITE_VM) != 0);
    const BOOL hasProtect = ((marks & SLEEPWALKER_HOLLOW_MARK_TI_PROTECT_RX) != 0);
    const BOOL hasThreadSuspicious =
        ((marks & (SLEEPWALKER_HOLLOW_MARK_THREAD_START_NON_IMAGE_EXEC | SLEEPWALKER_HOLLOW_MARK_THREAD_START_OUTSIDE_IMAGE)) != 0);
    const BOOL hasThreadContext = ((marks & SLEEPWALKER_HOLLOW_MARK_THREAD_CONTEXT_INTENT) != 0);
    const BOOL hasImageDrift = ((marks & SLEEPWALKER_HOLLOW_MARK_IMAGE_DRIFT) != 0);
    const BOOL hasTxf = ((marks & SLEEPWALKER_HOLLOW_MARK_TXF_SUSPECT) != 0);
    BOOL strong;
    BOOL medium;

    if ((NowTick - Entry->FirstSeenTick) > SLEEPWALKER_CONTROLLER_HOLLOW_WINDOW_MS)
    {
        Entry->Marks = 0;
        Entry->FirstSeenTick = NowTick;
        return;
    }

    strong = hasSuspended && hasAlloc && hasWrite && hasProtect && hasThreadSuspicious && (hasThreadContext || hasImageDrift);
    medium = (hasAlloc && hasWrite && hasProtect && hasThreadSuspicious) ||
             (hasSuspended && hasThreadSuspicious && hasThreadContext);

    if (strong && ((NowTick - Entry->LastStrongEmitTick) > 3000ull))
    {
        Entry->LastStrongEmitTick = NowTick;
        if (hasTxf)
        {
            ControllerEmitSyntheticDetection(Entry->ActorPid, Entry->TargetPid, "PROCESS_HOLLOWING_TXF_SUSPECT_CHAIN",
                                             8, Entry->Marks);
            return;
        }
        ControllerEmitSyntheticDetection(Entry->ActorPid, Entry->TargetPid, "PROCESS_HOLLOWING_MARK_CHAIN_STRONG", 7,
                                         Entry->Marks);
        return;
    }

    if (medium && ((NowTick - Entry->LastMediumEmitTick) > 3000ull))
    {
        Entry->LastMediumEmitTick = NowTick;
        ControllerEmitSyntheticDetection(Entry->ActorPid, Entry->TargetPid, "PROCESS_HOLLOWING_MARK_CHAIN_MEDIUM", 5,
                                         Entry->Marks);
    }
}

static VOID ControllerApplyHollowMark(_In_ DWORD ActorPid, _In_ DWORD TargetPid, _In_ UINT64 Mark, _In_ ULONGLONG AuxBase,
                                      _In_ ULONGLONG AuxSize, _In_ ULONG AuxProtect)
{
    PSLEEPWALKER_CONTROLLER_HOLLOW_ENTRY entry;
    ULONGLONG nowTick = GetTickCount64();

    if (TargetPid == 0 || Mark == 0)
    {
        return;
    }

    AcquireSRWLockExclusive(&g_HollowLock);
    entry = ControllerGetHollowEntryLocked(ActorPid, TargetPid, nowTick);
    if (entry != NULL)
    {
        entry->Marks |= Mark;
        entry->LastSeenTick = nowTick;
        if (entry->FirstSeenTick == 0)
        {
            entry->FirstSeenTick = nowTick;
        }
        if (AuxSize != 0)
        {
            entry->LastAllocBase = AuxBase;
            entry->LastAllocSize = AuxSize;
            entry->LastAllocProtect = AuxProtect;
        }
        ControllerEvaluateHollowEntryLocked(entry, nowTick);
    }
    ReleaseSRWLockExclusive(&g_HollowLock);
}

static VOID ControllerHandleSleepwalkerHollowRecord(_In_ PEVENT_RECORD Record, _In_opt_z_ PCWSTR EventName,
                                                    _In_ const SLEEPWALKER_IPC_ETW_EVENT *BrokerEvent)
{
    ULONGLONG processId = 0;
    ULONGLONG creatorPid = 0;
    ULONGLONG startAddress = 0;
    ULONGLONG imageBase = 0;
    ULONGLONG imageSize = 0;
    ULONG startRegionType = 0;
    ULONG startRegionProtect = 0;
    ULONG correlationFlags = 0;
    CHAR detectionName[128];

    if (Record == NULL || EventName == NULL || EventName[0] == L'\0')
    {
        return;
    }

    if (wcscmp(EventName, L"ThreadTelemetry") == 0)
    {
        (void)ControllerEtwGetU64Property(Record, L"processId", &processId);
        (void)ControllerEtwGetU64Property(Record, L"creatorPid", &creatorPid);
        (void)ControllerEtwGetU64Property(Record, L"startAddress", &startAddress);
        (void)ControllerEtwGetU64Property(Record, L"imageBase", &imageBase);
        (void)ControllerEtwGetU64Property(Record, L"imageSize", &imageSize);
        (void)ControllerEtwGetU32Property(Record, L"startRegionType", &startRegionType);
        (void)ControllerEtwGetU32Property(Record, L"startRegionProtect", &startRegionProtect);
        (void)ControllerEtwGetU32Property(Record, L"correlationFlags", &correlationFlags);

        if (processId == 0)
        {
            return;
        }

        if (imageBase != 0 && imageSize != 0 && startAddress != 0)
        {
            ULONGLONG end = imageBase + imageSize;
            if (end < imageBase || startAddress < imageBase || startAddress >= end)
            {
                ControllerApplyHollowMark((DWORD)creatorPid, (DWORD)processId,
                                          SLEEPWALKER_HOLLOW_MARK_THREAD_START_OUTSIDE_IMAGE |
                                              SLEEPWALKER_HOLLOW_MARK_IMAGE_DRIFT,
                                          0, 0, 0);
            }
        }

        if ((startRegionType != MEM_IMAGE) && ControllerIsExecutableProtect(startRegionProtect))
        {
            ControllerApplyHollowMark((DWORD)creatorPid, (DWORD)processId,
                                      SLEEPWALKER_HOLLOW_MARK_THREAD_START_NON_IMAGE_EXEC |
                                          SLEEPWALKER_HOLLOW_MARK_IMAGE_DRIFT,
                                      0, 0, 0);
        }

        if ((correlationFlags & SLEEPWALKER_INTENT_THREAD_CONTEXT) != 0)
        {
            ControllerApplyHollowMark((DWORD)creatorPid, (DWORD)processId, SLEEPWALKER_HOLLOW_MARK_THREAD_CONTEXT_INTENT,
                                      0, 0, 0);
        }
        if (creatorPid != 0 && processId != 0 && creatorPid != processId && correlationFlags != 0)
        {
            ControllerApplyHollowMark((DWORD)creatorPid, (DWORD)processId, SLEEPWALKER_HOLLOW_MARK_REMOTE_THREAD_INTENT,
                                      0, 0, 0);
        }
        return;
    }

    if (wcscmp(EventName, L"DetectionTelemetry") == 0)
    {
        if (BrokerEvent != NULL && BrokerEvent->DetectionName[0] != '\0')
        {
            (void)StringCchCopyA(detectionName, RTL_NUMBER_OF(detectionName), BrokerEvent->DetectionName);
        }
        else
        {
            detectionName[0] = '\0';
            (void)ControllerEtwGetAnsiProperty(Record, L"detectionName", detectionName, RTL_NUMBER_OF(detectionName));
        }

        if (detectionName[0] == '\0')
        {
            return;
        }

        processId = (BrokerEvent != NULL) ? BrokerEvent->PrimaryPid : 0;
        creatorPid = (BrokerEvent != NULL) ? BrokerEvent->PrimaryPid : 0;
        if (BrokerEvent != NULL && BrokerEvent->SecondaryPid != 0)
        {
            processId = BrokerEvent->SecondaryPid;
        }

        if (strcmp(detectionName, "THREAD_HIJACK_INTENT") == 0 ||
            strcmp(detectionName, "THREAD_ACTIVITY_WITH_THREAD_CONTEXT_INTENT") == 0 ||
            strcmp(detectionName, "REMOTE_APC_CREATION_SUSPECT") == 0)
        {
            ControllerApplyHollowMark((DWORD)creatorPid, (DWORD)processId, SLEEPWALKER_HOLLOW_MARK_THREAD_CONTEXT_INTENT,
                                      0, 0, 0);
        }
        if (strcmp(detectionName, "REMOTE_THREAD_WITH_RECENT_HANDLE_INTENT") == 0)
        {
            ControllerApplyHollowMark((DWORD)creatorPid, (DWORD)processId, SLEEPWALKER_HOLLOW_MARK_REMOTE_THREAD_INTENT,
                                      0, 0, 0);
        }
        if (strcmp(detectionName, "REMOTE_THREAD_OUTSIDE_MAIN_IMAGE") == 0 ||
            strcmp(detectionName, "REMOTE_THREAD_START_IN_NON_IMAGE_EXECUTABLE_REGION") == 0 ||
            strcmp(detectionName, "POSSIBLE_MANUAL_MAP_OR_HOLLOWING_EXECUTION") == 0)
        {
            ControllerApplyHollowMark((DWORD)creatorPid, (DWORD)processId,
                                      SLEEPWALKER_HOLLOW_MARK_THREAD_START_OUTSIDE_IMAGE |
                                          SLEEPWALKER_HOLLOW_MARK_THREAD_START_NON_IMAGE_EXEC |
                                          SLEEPWALKER_HOLLOW_MARK_IMAGE_DRIFT,
                                      0, 0, 0);
        }
    }
}

static VOID ControllerHandleThreatIntelHollowRecord(_In_ PEVENT_RECORD Record, _In_opt_z_ PCWSTR EventName)
{
    static const PCWSTR callerPidNames[] = {L"CallingProcessId", L"CallerProcessId", L"SourceProcessId", L"ProcessId"};
    static const PCWSTR targetPidNames[] = {L"TargetProcessId", L"NewProcessId", L"DestProcessId", L"ProcessId"};
    static const PCWSTR baseAddressNames[] = {L"BaseAddress", L"AllocationBase", L"Address", L"RegionBase"};
    static const PCWSTR sizeNames[] = {L"RegionSize", L"AllocationSize", L"ViewSize", L"Size", L"DataSize"};
    static const PCWSTR protectNames[] = {L"Protection", L"Protect", L"AllocationProtect", L"NewProtect"};
    static const PCWSTR oldProtectNames[] = {L"OldProtect", L"PreviousProtect", L"ProtectOld"};
    static const PCWSTR newProtectNames[] = {L"NewProtect", L"Protect", L"Protection"};
    static const PCWSTR creationFlagsNames[] = {L"CreationFlags", L"CreateFlags", L"ProcessFlags"};

    USHORT task;
    ULONGLONG callerPid = 0;
    ULONGLONG targetPid = 0;
    ULONGLONG baseAddress = 0;
    ULONGLONG regionSize = 0;
    ULONG protect = 0;
    ULONG oldProtect = 0;
    ULONG newProtect = 0;
    ULONG creationFlags = 0;

    if (Record == NULL)
    {
        return;
    }

    task = Record->EventHeader.EventDescriptor.Task;
    (void)ControllerEtwTryGetU64Any(Record, callerPidNames, RTL_NUMBER_OF(callerPidNames), &callerPid);
    (void)ControllerEtwTryGetU64Any(Record, targetPidNames, RTL_NUMBER_OF(targetPidNames), &targetPid);
    if (targetPid == 0)
    {
        targetPid = callerPid;
    }

    if (EventName != NULL && EventName[0] != L'\0' && ControllerWideContainsInsensitive(EventName, L"createprocess"))
    {
        (void)ControllerEtwTryGetU32Any(Record, creationFlagsNames, RTL_NUMBER_OF(creationFlagsNames), &creationFlags);
        if (((creationFlags & CREATE_SUSPENDED) != 0) || ControllerWideContainsInsensitive(EventName, L"suspend"))
        {
            ControllerApplyHollowMark((DWORD)callerPid, (DWORD)targetPid, SLEEPWALKER_HOLLOW_MARK_CREATE_SUSPENDED, 0, 0,
                                      0);
        }
    }
    if (EventName != NULL && EventName[0] != L'\0' &&
        (ControllerWideContainsInsensitive(EventName, L"txf") ||
         ControllerWideContainsInsensitive(EventName, L"transact") ||
         ControllerWideContainsInsensitive(EventName, L"ktransaction") ||
         ControllerWideContainsInsensitive(EventName, L"rollback")))
    {
        ControllerApplyHollowMark((DWORD)callerPid, (DWORD)targetPid, SLEEPWALKER_HOLLOW_MARK_TXF_SUSPECT, 0, 0, 0);
    }

    if (targetPid == 0)
    {
        return;
    }

    switch (task)
    {
    case 1:
        (void)ControllerEtwTryGetU64Any(Record, baseAddressNames, RTL_NUMBER_OF(baseAddressNames), &baseAddress);
        (void)ControllerEtwTryGetU64Any(Record, sizeNames, RTL_NUMBER_OF(sizeNames), &regionSize);
        (void)ControllerEtwTryGetU32Any(Record, protectNames, RTL_NUMBER_OF(protectNames), &protect);
        if (regionSize >= SLEEPWALKER_CONTROLLER_HOLLOW_LARGE_ALLOC_BYTES && ControllerIsWritableProtect(protect))
        {
            ControllerApplyHollowMark((DWORD)callerPid, (DWORD)targetPid, SLEEPWALKER_HOLLOW_MARK_TI_ALLOC_RW_LARGE,
                                      baseAddress, regionSize, protect);
        }
        break;
    case 7:
        ControllerApplyHollowMark((DWORD)callerPid, (DWORD)targetPid, SLEEPWALKER_HOLLOW_MARK_TI_WRITE_VM, 0, 0, 0);
        break;
    case 2:
        (void)ControllerEtwTryGetU32Any(Record, oldProtectNames, RTL_NUMBER_OF(oldProtectNames), &oldProtect);
        (void)ControllerEtwTryGetU32Any(Record, newProtectNames, RTL_NUMBER_OF(newProtectNames), &newProtect);
        if ((newProtect != 0 && ControllerIsExecutableProtect(newProtect)) &&
            (oldProtect == 0 || ControllerIsWritableProtect(oldProtect)))
        {
            ControllerApplyHollowMark((DWORD)callerPid, (DWORD)targetPid, SLEEPWALKER_HOLLOW_MARK_TI_PROTECT_RX, 0, 0,
                                      newProtect);
        }
        break;
    default:
        break;
    }
}

static VOID ControllerProcessHollowingEtwRecord(_In_ PEVENT_RECORD Record, _In_opt_z_ PCWSTR EventName,
                                                _In_ const SLEEPWALKER_IPC_ETW_EVENT *BrokerEvent)
{
    if (Record == NULL)
    {
        return;
    }

    if (IsEqualGUID(&Record->EventHeader.ProviderId, &SLEEPWALKERSC_PROVIDER_GUID_SLEEPWALKER))
    {
        ControllerHandleSleepwalkerHollowRecord(Record, EventName, BrokerEvent);
    }
    else if (IsEqualGUID(&Record->EventHeader.ProviderId, &SLEEPWALKERSC_PROVIDER_GUID_TI))
    {
        ControllerHandleThreatIntelHollowRecord(Record, EventName);
    }
}

static VOID ControllerResetHollowingState(VOID)
{
    AcquireSRWLockExclusive(&g_HollowLock);
    ZeroMemory(g_HollowEntries, sizeof(g_HollowEntries));
    ReleaseSRWLockExclusive(&g_HollowLock);
}
