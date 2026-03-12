#include "../blackbird_controller_private.h"

#define BLACKBIRD_HOLLOW_MARK_CREATE_SUSPENDED 0x00000001ull
#define BLACKBIRD_HOLLOW_MARK_TI_ALLOC_RW_LARGE 0x00000002ull
#define BLACKBIRD_HOLLOW_MARK_TI_WRITE_VM 0x00000004ull
#define BLACKBIRD_HOLLOW_MARK_TI_PROTECT_RX 0x00000008ull
#define BLACKBIRD_HOLLOW_MARK_THREAD_START_NON_IMAGE_EXEC 0x00000010ull
#define BLACKBIRD_HOLLOW_MARK_THREAD_START_OUTSIDE_IMAGE 0x00000020ull
#define BLACKBIRD_HOLLOW_MARK_THREAD_CONTEXT_INTENT 0x00000040ull
#define BLACKBIRD_HOLLOW_MARK_REMOTE_THREAD_INTENT 0x00000080ull
#define BLACKBIRD_HOLLOW_MARK_IMAGE_DRIFT 0x00000100ull
#define BLACKBIRD_HOLLOW_MARK_TXF_SUSPECT 0x00000200ull

#ifndef BLACKBIRD_INTENT_THREAD_CONTEXT
#define BLACKBIRD_INTENT_THREAD_CONTEXT 0x00000002u
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

static BOOL ControllerRangesOverlap(_In_ ULONGLONG BaseA, _In_ ULONGLONG SizeA, _In_ ULONGLONG BaseB,
                                    _In_ ULONGLONG SizeB)
{
    ULONGLONG endA;
    ULONGLONG endB;

    if (SizeA == 0 || SizeB == 0)
    {
        return FALSE;
    }

    endA = BaseA + SizeA;
    endB = BaseB + SizeB;
    if (endA < BaseA || endB < BaseB)
    {
        return FALSE;
    }

    return !(endA <= BaseB || endB <= BaseA);
}

static BOOL ControllerProbePeHeaderAtBase(_In_ HANDLE ProcessHandle, _In_ ULONGLONG BaseAddress)
{
    BYTE header[0x1000];
    SIZE_T bytesRead = 0;
    IMAGE_DOS_HEADER dos;
    LONG peOffset;
    DWORD peSignature = 0;
    WORD optionalMagic = 0;
    SIZE_T minNtHeaderBytes;

    if (ProcessHandle == NULL || ProcessHandle == INVALID_HANDLE_VALUE || BaseAddress == 0)
    {
        return FALSE;
    }

    ZeroMemory(header, sizeof(header));
    if (!ReadProcessMemory(ProcessHandle, (LPCVOID)(ULONG_PTR)BaseAddress, header, sizeof(header), &bytesRead))
    {
        return FALSE;
    }
    if (bytesRead < sizeof(IMAGE_DOS_HEADER))
    {
        return FALSE;
    }

    CopyMemory(&dos, header, sizeof(dos));
    if (dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew <= 0)
    {
        return FALSE;
    }

    peOffset = dos.e_lfanew;
    minNtHeaderBytes = (SIZE_T)peOffset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + sizeof(WORD);
    if ((SIZE_T)peOffset >= bytesRead || minNtHeaderBytes > bytesRead)
    {
        return FALSE;
    }

    CopyMemory(&peSignature, header + peOffset, sizeof(peSignature));
    if (peSignature != IMAGE_NT_SIGNATURE)
    {
        return FALSE;
    }

    CopyMemory(&optionalMagic, header + peOffset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER), sizeof(optionalMagic));
    return (optionalMagic == IMAGE_NT_OPTIONAL_HDR32_MAGIC || optionalMagic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);
}

static BOOL ControllerProbeManualMapRegion(_In_ DWORD TargetPid, _In_ ULONGLONG CandidateBase, _In_ ULONGLONG CandidateSize,
                                           _In_ ULONGLONG ThreadStartAddress, _Out_ BOOL *PrivateExecutableRegion,
                                           _Out_ BOOL *HasPeHeader, _Out_ BOOL *ThreadStartInsideRegion,
                                           _Out_opt_ ULONGLONG *ResolvedBase, _Out_opt_ ULONGLONG *ResolvedSize,
                                           _Out_opt_ ULONG *ResolvedProtect, _Out_opt_ ULONG *ResolvedType)
{
    HANDLE process = NULL;
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T queried = 0;
    ULONGLONG regionBase = 0;
    ULONGLONG regionSize = 0;
    BOOL privateExec = FALSE;
    BOOL hasPe = FALSE;
    BOOL startInside = FALSE;

    if (PrivateExecutableRegion == NULL || HasPeHeader == NULL || ThreadStartInsideRegion == NULL || TargetPid == 0 ||
        CandidateBase == 0)
    {
        return FALSE;
    }

    *PrivateExecutableRegion = FALSE;
    *HasPeHeader = FALSE;
    *ThreadStartInsideRegion = FALSE;
    if (ResolvedBase != NULL)
    {
        *ResolvedBase = 0;
    }
    if (ResolvedSize != NULL)
    {
        *ResolvedSize = 0;
    }
    if (ResolvedProtect != NULL)
    {
        *ResolvedProtect = 0;
    }
    if (ResolvedType != NULL)
    {
        *ResolvedType = 0;
    }

    process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, TargetPid);
    if (process == NULL)
    {
        return FALSE;
    }

    ZeroMemory(&mbi, sizeof(mbi));
    queried = VirtualQueryEx(process, (LPCVOID)(ULONG_PTR)CandidateBase, &mbi, sizeof(mbi));
    if (queried < sizeof(mbi))
    {
        (void)CloseHandle(process);
        return FALSE;
    }

    regionBase = (ULONGLONG)(ULONG_PTR)mbi.BaseAddress;
    regionSize = (ULONGLONG)mbi.RegionSize;
    privateExec = (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE && ControllerIsExecutableProtect(mbi.Protect));

    if (CandidateSize != 0 && !ControllerRangesOverlap(CandidateBase, CandidateSize, regionBase, regionSize))
    {
        privateExec = FALSE;
    }

    if (ThreadStartAddress != 0 && regionSize != 0)
    {
        ULONGLONG end = regionBase + regionSize;
        if (end >= regionBase)
        {
            startInside = (ThreadStartAddress >= regionBase && ThreadStartAddress < end);
        }
    }

    if (privateExec)
    {
        hasPe = ControllerProbePeHeaderAtBase(process, CandidateBase);
    }

    (void)CloseHandle(process);

    *PrivateExecutableRegion = privateExec;
    *HasPeHeader = hasPe;
    *ThreadStartInsideRegion = startInside;
    if (ResolvedBase != NULL)
    {
        *ResolvedBase = regionBase;
    }
    if (ResolvedSize != NULL)
    {
        *ResolvedSize = regionSize;
    }
    if (ResolvedProtect != NULL)
    {
        *ResolvedProtect = mbi.Protect;
    }
    if (ResolvedType != NULL)
    {
        *ResolvedType = mbi.Type;
    }
    return TRUE;
}

static PBLACKBIRD_CONTROLLER_HOLLOW_ENTRY ControllerFindHollowEntryLocked(_In_ DWORD ActorPid, _In_ DWORD TargetPid)
{
    DWORD effectiveActor;
    DWORD i;

    if (TargetPid == 0)
    {
        return NULL;
    }

    effectiveActor = (ActorPid != 0) ? ActorPid : TargetPid;
    for (i = 0; i < BLACKBIRD_CONTROLLER_HOLLOW_MAX_ENTRIES; ++i)
    {
        if (!g_HollowEntries[i].Active)
        {
            continue;
        }
        if (g_HollowEntries[i].TargetPid == TargetPid && g_HollowEntries[i].ActorPid == effectiveActor)
        {
            return &g_HollowEntries[i];
        }
    }

    return NULL;
}

static PBLACKBIRD_CONTROLLER_HOLLOW_ENTRY ControllerGetHollowEntryLocked(_In_ DWORD ActorPid, _In_ DWORD TargetPid,
                                                                           _In_ ULONGLONG NowTick)
{
    DWORD i;
    DWORD candidate = BLACKBIRD_CONTROLLER_HOLLOW_MAX_ENTRIES;
    ULONGLONG oldestTick = ~0ull;

    if (TargetPid == 0)
    {
        return NULL;
    }
    if (ActorPid == 0)
    {
        ActorPid = TargetPid;
    }

    for (i = 0; i < BLACKBIRD_CONTROLLER_HOLLOW_MAX_ENTRIES; ++i)
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

        if ((NowTick - g_HollowEntries[i].LastSeenTick) > (BLACKBIRD_CONTROLLER_HOLLOW_WINDOW_MS * 2ull))
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

    if (candidate >= BLACKBIRD_CONTROLLER_HOLLOW_MAX_ENTRIES)
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

static VOID ControllerEmitSyntheticDetectionEx(_In_ DWORD ActorPid, _In_ DWORD TargetPid, _In_z_ PCSTR DetectionName,
                                               _In_ DWORD Severity, _In_ UINT64 Marks, _In_opt_z_ PCWSTR ReasonText)
{
    BLACKBIRD_IPC_ETW_EVENT event;

    if (DetectionName == NULL || DetectionName[0] == '\0' || TargetPid == 0)
    {
        return;
    }

    ZeroMemory(&event, sizeof(event));
    event.Source = BlackbirdIpcEtwSourceBlackbird;
    event.EventId = 0;
    event.Opcode = 0;
    event.Task = 0;
    event.EventProcessId = (ActorPid != 0) ? ActorPid : TargetPid;
    event.EventThreadId = 0;
    event.Severity = Severity;
    event.ProcessId = (ActorPid != 0) ? (UINT64)ActorPid : (UINT64)TargetPid;
    event.TargetPid = (UINT64)TargetPid;
    event.CorrelationFlags = 0;
    event.CorrelationAccessMask = 0;
    event.CorrelationAgeMs = 0;
    (void)StringCchCopyW(event.EventName, RTL_NUMBER_OF(event.EventName), L"DetectionTelemetry");
    (void)StringCchCopyA(event.DetectionName, RTL_NUMBER_OF(event.DetectionName), DetectionName);
    if (ReasonText != NULL && ReasonText[0] != L'\0')
    {
        (void)StringCchCopyW(event.Reason, RTL_NUMBER_OF(event.Reason), ReasonText);
    }
    else
    {
        (void)StringCchPrintfW(event.Reason, RTL_NUMBER_OF(event.Reason), L"synthetic chain marks=0x%llX", Marks);
    }

    (void)InterlockedIncrement(&g_EtwDetectionEvents);
    ControllerDispatchEtwEvent(&event);
    ControllerLog("[ETW][SYNTH] detection=%s severity=%lu actor=%lu target=%lu marks=0x%llX\n", DetectionName,
                  Severity, ActorPid, TargetPid, Marks);
}

static VOID ControllerEmitSyntheticDetection(_In_ DWORD ActorPid, _In_ DWORD TargetPid, _In_z_ PCSTR DetectionName,
                                             _In_ DWORD Severity, _In_ UINT64 Marks)
{
    ControllerEmitSyntheticDetectionEx(ActorPid, TargetPid, DetectionName, Severity, Marks, NULL);
}

static VOID ControllerEvaluateHollowEntryLocked(_Inout_ PBLACKBIRD_CONTROLLER_HOLLOW_ENTRY Entry, _In_ ULONGLONG NowTick)
{
    const UINT64 marks = Entry->Marks;
    const BOOL hasSuspended = ((marks & BLACKBIRD_HOLLOW_MARK_CREATE_SUSPENDED) != 0);
    const BOOL hasAlloc = ((marks & BLACKBIRD_HOLLOW_MARK_TI_ALLOC_RW_LARGE) != 0);
    const BOOL hasWrite = ((marks & BLACKBIRD_HOLLOW_MARK_TI_WRITE_VM) != 0);
    const BOOL hasProtect = ((marks & BLACKBIRD_HOLLOW_MARK_TI_PROTECT_RX) != 0);
    const BOOL hasThreadSuspicious =
        ((marks & (BLACKBIRD_HOLLOW_MARK_THREAD_START_NON_IMAGE_EXEC | BLACKBIRD_HOLLOW_MARK_THREAD_START_OUTSIDE_IMAGE)) != 0);
    const BOOL hasThreadContext = ((marks & BLACKBIRD_HOLLOW_MARK_THREAD_CONTEXT_INTENT) != 0);
    const BOOL hasImageDrift = ((marks & BLACKBIRD_HOLLOW_MARK_IMAGE_DRIFT) != 0);
    const BOOL hasTxf = ((marks & BLACKBIRD_HOLLOW_MARK_TXF_SUSPECT) != 0);
    BOOL strong;
    BOOL medium;

    if ((NowTick - Entry->FirstSeenTick) > BLACKBIRD_CONTROLLER_HOLLOW_WINDOW_MS)
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

static VOID ControllerRememberThreadStart(_In_ DWORD ActorPid, _In_ DWORD TargetPid, _In_ ULONGLONG StartAddress)
{
    PBLACKBIRD_CONTROLLER_HOLLOW_ENTRY entry;
    ULONGLONG nowTick = GetTickCount64();

    if (TargetPid == 0 || StartAddress == 0)
    {
        return;
    }

    AcquireSRWLockExclusive(&g_HollowLock);
    entry = ControllerGetHollowEntryLocked(ActorPid, TargetPid, nowTick);
    if (entry != NULL)
    {
        entry->LastThreadStartAddress = StartAddress;
        entry->LastThreadStartTick = nowTick;
        entry->LastSeenTick = nowTick;
    }
    ReleaseSRWLockExclusive(&g_HollowLock);
}

static VOID ControllerTryEmitManualMapDetection(_In_ DWORD ActorPid, _In_ DWORD TargetPid, _In_ ULONGLONG BaseHint,
                                                _In_ ULONGLONG SizeHint)
{
    PBLACKBIRD_CONTROLLER_HOLLOW_ENTRY entry;
    ULONGLONG nowTick;
    DWORD effectiveActor = 0;
    DWORD effectiveTarget = 0;
    UINT64 marks = 0;
    ULONGLONG candidateBase = 0;
    ULONGLONG candidateSize = 0;
    ULONGLONG threadStartAddress = 0;
    ULONGLONG lastWriteTick = 0;
    ULONGLONG lastProtectTick = 0;
    BOOL hasAlloc;
    BOOL hasWrite;
    BOOL hasProtect;
    BOOL hasThreadSuspicious;
    BOOL remoteActor;
    BOOL privateExecutableRegion = FALSE;
    BOOL hasPeHeader = FALSE;
    BOOL threadStartInsideRegion = FALSE;
    ULONGLONG resolvedBase = 0;
    ULONGLONG resolvedSize = 0;
    ULONG resolvedProtect = 0;
    ULONG resolvedType = 0;
    const CHAR *detectionName = NULL;
    DWORD severity = 0;
    DWORD kind = 0;
    ULONGLONG *cooldownTick = NULL;
    WCHAR reasonText[256];

    if (TargetPid == 0)
    {
        return;
    }

    nowTick = GetTickCount64();
    AcquireSRWLockShared(&g_HollowLock);
    entry = ControllerFindHollowEntryLocked(ActorPid, TargetPid);
    if (entry != NULL)
    {
        effectiveActor = entry->ActorPid;
        effectiveTarget = entry->TargetPid;
        marks = entry->Marks;
        candidateBase = (BaseHint != 0)
                            ? BaseHint
                            : ((entry->LastProtectRxBase != 0) ? entry->LastProtectRxBase : entry->LastAllocBase);
        candidateSize = (SizeHint != 0)
                            ? SizeHint
                            : ((entry->LastProtectRxSize != 0) ? entry->LastProtectRxSize : entry->LastAllocSize);
        threadStartAddress = entry->LastThreadStartAddress;
        lastWriteTick = entry->LastWriteTick;
        lastProtectTick = entry->LastProtectRxTick;
    }
    ReleaseSRWLockShared(&g_HollowLock);

    if (entry == NULL || effectiveTarget == 0 || candidateBase == 0)
    {
        return;
    }

    hasAlloc = ((marks & BLACKBIRD_HOLLOW_MARK_TI_ALLOC_RW_LARGE) != 0);
    hasWrite = ((marks & BLACKBIRD_HOLLOW_MARK_TI_WRITE_VM) != 0) || (lastWriteTick != 0);
    hasProtect = ((marks & BLACKBIRD_HOLLOW_MARK_TI_PROTECT_RX) != 0) || (lastProtectTick != 0);
    hasThreadSuspicious =
        ((marks & (BLACKBIRD_HOLLOW_MARK_THREAD_START_NON_IMAGE_EXEC | BLACKBIRD_HOLLOW_MARK_THREAD_START_OUTSIDE_IMAGE)) != 0);
    remoteActor = (effectiveActor != 0 && effectiveActor != effectiveTarget);

    if (!remoteActor || !hasAlloc || !hasWrite || !hasProtect || !hasThreadSuspicious)
    {
        return;
    }
    if (lastWriteTick != 0 && (nowTick - lastWriteTick) > BLACKBIRD_CONTROLLER_HOLLOW_WINDOW_MS)
    {
        return;
    }
    if (lastProtectTick != 0 && (nowTick - lastProtectTick) > BLACKBIRD_CONTROLLER_HOLLOW_WINDOW_MS)
    {
        return;
    }

    if (!ControllerProbeManualMapRegion(effectiveTarget, candidateBase, candidateSize, threadStartAddress,
                                        &privateExecutableRegion, &hasPeHeader, &threadStartInsideRegion, &resolvedBase,
                                        &resolvedSize, &resolvedProtect, &resolvedType))
    {
        return;
    }
    if (!privateExecutableRegion)
    {
        return;
    }

    if (hasPeHeader)
    {
        detectionName = "MANUAL_MAP_CONFIRMED_PRIVATE_EXEC_PE";
        severity = 8;
        kind = 3;
    }
    else if (threadStartInsideRegion || ((marks & BLACKBIRD_HOLLOW_MARK_THREAD_CONTEXT_INTENT) != 0))
    {
        detectionName = "MANUAL_MAP_HEADERLESS_PRIVATE_EXEC";
        severity = 7;
        kind = 2;
    }
    else
    {
        detectionName = "MANUAL_MAP_LIKELY_PRIVATE_EXEC_CHAIN";
        severity = 6;
        kind = 1;
    }

    AcquireSRWLockExclusive(&g_HollowLock);
    entry = ControllerFindHollowEntryLocked(effectiveActor, effectiveTarget);
    if (entry != NULL)
    {
        if (kind == 3)
        {
            cooldownTick = &entry->LastManualMapConfirmedEmitTick;
        }
        else if (kind == 2)
        {
            cooldownTick = &entry->LastManualMapHeaderlessEmitTick;
        }
        else
        {
            cooldownTick = &entry->LastManualMapLikelyEmitTick;
        }

        if (cooldownTick != NULL &&
            (nowTick - *cooldownTick) < BLACKBIRD_CONTROLLER_MANUAL_MAP_EMIT_COOLDOWN_MS)
        {
            entry = NULL;
        }
        else if (cooldownTick != NULL)
        {
            *cooldownTick = nowTick;
        }
    }
    ReleaseSRWLockExclusive(&g_HollowLock);

    if (entry == NULL || detectionName == NULL)
    {
        return;
    }

    (void)StringCchPrintfW(reasonText, RTL_NUMBER_OF(reasonText),
                           L"manual-map probe base=0x%llX size=0x%llX type=0x%lX protect=0x%lX pe=%u startInRegion=%u marks=0x%llX",
                           resolvedBase, resolvedSize, resolvedType, resolvedProtect, hasPeHeader ? 1u : 0u,
                           threadStartInsideRegion ? 1u : 0u, marks);
    ControllerEmitSyntheticDetectionEx(effectiveActor, effectiveTarget, detectionName, severity, marks, reasonText);
}

static VOID ControllerApplyHollowMark(_In_ DWORD ActorPid, _In_ DWORD TargetPid, _In_ UINT64 Mark, _In_ ULONGLONG AuxBase,
                                      _In_ ULONGLONG AuxSize, _In_ ULONG AuxProtect)
{
    PBLACKBIRD_CONTROLLER_HOLLOW_ENTRY entry;
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
        if ((Mark & BLACKBIRD_HOLLOW_MARK_TI_ALLOC_RW_LARGE) != 0 && (AuxBase != 0 || AuxSize != 0))
        {
            entry->LastAllocBase = AuxBase;
            entry->LastAllocSize = AuxSize;
            entry->LastAllocProtect = AuxProtect;
        }
        if ((Mark & BLACKBIRD_HOLLOW_MARK_TI_WRITE_VM) != 0)
        {
            if (AuxBase != 0)
            {
                entry->LastWriteBase = AuxBase;
            }
            if (AuxSize != 0)
            {
                entry->LastWriteSize = AuxSize;
            }
            entry->LastWriteTick = nowTick;
        }
        if ((Mark & BLACKBIRD_HOLLOW_MARK_TI_PROTECT_RX) != 0)
        {
            if (AuxBase != 0)
            {
                entry->LastProtectRxBase = AuxBase;
            }
            if (AuxSize != 0)
            {
                entry->LastProtectRxSize = AuxSize;
            }
            if (AuxProtect != 0)
            {
                entry->LastProtectRxProtect = AuxProtect;
            }
            entry->LastProtectRxTick = nowTick;
        }
        ControllerEvaluateHollowEntryLocked(entry, nowTick);
    }
    ReleaseSRWLockExclusive(&g_HollowLock);
}

static VOID ControllerHandleBlackbirdHollowRecord(_In_ PEVENT_RECORD Record, _In_opt_z_ PCWSTR EventName,
                                                    _In_ const BLACKBIRD_IPC_ETW_EVENT *BrokerEvent)
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

        if (startAddress != 0)
        {
            ControllerRememberThreadStart((DWORD)creatorPid, (DWORD)processId, startAddress);
        }

        if (imageBase != 0 && imageSize != 0 && startAddress != 0)
        {
            ULONGLONG end = imageBase + imageSize;
            if (end < imageBase || startAddress < imageBase || startAddress >= end)
            {
                ControllerApplyHollowMark((DWORD)creatorPid, (DWORD)processId,
                                          BLACKBIRD_HOLLOW_MARK_THREAD_START_OUTSIDE_IMAGE |
                                              BLACKBIRD_HOLLOW_MARK_IMAGE_DRIFT,
                                          0, 0, 0);
            }
        }

        if ((startRegionType != MEM_IMAGE) && ControllerIsExecutableProtect(startRegionProtect))
        {
            ControllerApplyHollowMark((DWORD)creatorPid, (DWORD)processId,
                                      BLACKBIRD_HOLLOW_MARK_THREAD_START_NON_IMAGE_EXEC |
                                          BLACKBIRD_HOLLOW_MARK_IMAGE_DRIFT,
                                      0, 0, 0);
        }

        if ((correlationFlags & BLACKBIRD_INTENT_THREAD_CONTEXT) != 0)
        {
            ControllerApplyHollowMark((DWORD)creatorPid, (DWORD)processId, BLACKBIRD_HOLLOW_MARK_THREAD_CONTEXT_INTENT,
                                      0, 0, 0);
        }
        if (creatorPid != 0 && processId != 0 && creatorPid != processId && correlationFlags != 0)
        {
            ControllerApplyHollowMark((DWORD)creatorPid, (DWORD)processId, BLACKBIRD_HOLLOW_MARK_REMOTE_THREAD_INTENT,
                                      0, 0, 0);
        }
        ControllerTryEmitManualMapDetection((DWORD)creatorPid, (DWORD)processId, startAddress, 0);
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

        processId = (BrokerEvent != NULL) ? BrokerEvent->ProcessId : 0;
        creatorPid = (BrokerEvent != NULL) ? BrokerEvent->ProcessId : 0;
        if (BrokerEvent != NULL && BrokerEvent->TargetPid != 0)
        {
            processId = BrokerEvent->TargetPid;
        }

        if (strcmp(detectionName, "THREAD_HIJACK_INTENT") == 0 ||
            strcmp(detectionName, "THREAD_ACTIVITY_WITH_THREAD_CONTEXT_INTENT") == 0 ||
            strcmp(detectionName, "REMOTE_APC_CREATION_SUSPECT") == 0)
        {
            ControllerApplyHollowMark((DWORD)creatorPid, (DWORD)processId, BLACKBIRD_HOLLOW_MARK_THREAD_CONTEXT_INTENT,
                                      0, 0, 0);
        }
        if (strcmp(detectionName, "REMOTE_THREAD_WITH_RECENT_HANDLE_INTENT") == 0)
        {
            ControllerApplyHollowMark((DWORD)creatorPid, (DWORD)processId, BLACKBIRD_HOLLOW_MARK_REMOTE_THREAD_INTENT,
                                      0, 0, 0);
        }
        if (strcmp(detectionName, "REMOTE_THREAD_OUTSIDE_MAIN_IMAGE") == 0 ||
            strcmp(detectionName, "REMOTE_THREAD_START_IN_NON_IMAGE_EXECUTABLE_REGION") == 0 ||
            strcmp(detectionName, "POSSIBLE_MANUAL_MAP_OR_HOLLOWING_EXECUTION") == 0)
        {
            ControllerApplyHollowMark((DWORD)creatorPid, (DWORD)processId,
                                      BLACKBIRD_HOLLOW_MARK_THREAD_START_OUTSIDE_IMAGE |
                                          BLACKBIRD_HOLLOW_MARK_THREAD_START_NON_IMAGE_EXEC |
                                          BLACKBIRD_HOLLOW_MARK_IMAGE_DRIFT,
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
            ControllerApplyHollowMark((DWORD)callerPid, (DWORD)targetPid, BLACKBIRD_HOLLOW_MARK_CREATE_SUSPENDED, 0, 0,
                                      0);
        }
    }
    if (EventName != NULL && EventName[0] != L'\0' &&
        (ControllerWideContainsInsensitive(EventName, L"txf") ||
         ControllerWideContainsInsensitive(EventName, L"transact") ||
         ControllerWideContainsInsensitive(EventName, L"ktransaction") ||
         ControllerWideContainsInsensitive(EventName, L"rollback")))
    {
        ControllerApplyHollowMark((DWORD)callerPid, (DWORD)targetPid, BLACKBIRD_HOLLOW_MARK_TXF_SUSPECT, 0, 0, 0);
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
        if (regionSize >= BLACKBIRD_CONTROLLER_HOLLOW_LARGE_ALLOC_BYTES && ControllerIsWritableProtect(protect))
        {
            ControllerApplyHollowMark((DWORD)callerPid, (DWORD)targetPid, BLACKBIRD_HOLLOW_MARK_TI_ALLOC_RW_LARGE,
                                      baseAddress, regionSize, protect);
        }
        break;
    case 7:
        (void)ControllerEtwTryGetU64Any(Record, baseAddressNames, RTL_NUMBER_OF(baseAddressNames), &baseAddress);
        (void)ControllerEtwTryGetU64Any(Record, sizeNames, RTL_NUMBER_OF(sizeNames), &regionSize);
        ControllerApplyHollowMark((DWORD)callerPid, (DWORD)targetPid, BLACKBIRD_HOLLOW_MARK_TI_WRITE_VM, baseAddress,
                                  regionSize, 0);
        ControllerTryEmitManualMapDetection((DWORD)callerPid, (DWORD)targetPid, baseAddress, regionSize);
        break;
    case 2:
        (void)ControllerEtwTryGetU64Any(Record, baseAddressNames, RTL_NUMBER_OF(baseAddressNames), &baseAddress);
        (void)ControllerEtwTryGetU64Any(Record, sizeNames, RTL_NUMBER_OF(sizeNames), &regionSize);
        (void)ControllerEtwTryGetU32Any(Record, oldProtectNames, RTL_NUMBER_OF(oldProtectNames), &oldProtect);
        (void)ControllerEtwTryGetU32Any(Record, newProtectNames, RTL_NUMBER_OF(newProtectNames), &newProtect);
        if ((newProtect != 0 && ControllerIsExecutableProtect(newProtect)) &&
            (oldProtect == 0 || ControllerIsWritableProtect(oldProtect)))
        {
            ControllerApplyHollowMark((DWORD)callerPid, (DWORD)targetPid, BLACKBIRD_HOLLOW_MARK_TI_PROTECT_RX,
                                      baseAddress, regionSize, newProtect);
            ControllerTryEmitManualMapDetection((DWORD)callerPid, (DWORD)targetPid, baseAddress, regionSize);
        }
        break;
    default:
        break;
    }
}
VOID ControllerProcessHollowingEtwRecord(_In_ PEVENT_RECORD Record, _In_opt_z_ PCWSTR EventName,
                                                _In_ const BLACKBIRD_IPC_ETW_EVENT *BrokerEvent)
{
    if (Record == NULL)
    {
        return;
    }

    if (IsEqualGUID(&Record->EventHeader.ProviderId, &BLACKBIRDSC_PROVIDER_GUID_BLACKBIRD))
    {
        ControllerHandleBlackbirdHollowRecord(Record, EventName, BrokerEvent);
    }
    else if (IsEqualGUID(&Record->EventHeader.ProviderId, &BLACKBIRDSC_PROVIDER_GUID_TI))
    {
        ControllerHandleThreatIntelHollowRecord(Record, EventName);
    }
}
VOID ControllerResetHollowingState(VOID)
{
    AcquireSRWLockExclusive(&g_HollowLock);
    ZeroMemory(g_HollowEntries, sizeof(g_HollowEntries));
    ReleaseSRWLockExclusive(&g_HollowLock);
}





