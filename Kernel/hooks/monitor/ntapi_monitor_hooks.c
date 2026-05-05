#include "ntapi_monitor_private.h"
#include "..\..\callbacks\image_monitor.h"
#include "..\..\core\unicode_utils.h"

#if defined(_AMD64_)

#ifndef ThreadQuerySetWin32StartAddress
#define ThreadQuerySetWin32StartAddress ((THREADINFOCLASS)9)
#endif
#ifndef THREAD_QUERY_LIMITED_INFORMATION
#define THREAD_QUERY_LIMITED_INFORMATION 0x0800
#endif
#define BK_OBJECT_INFORMATION_CLASS_NAME 1u

NTSYSAPI NTSTATUS NTAPI ZwQueryInformationThread(_In_ HANDLE ThreadHandle, _In_ THREADINFOCLASS ThreadInformationClass,
                                                 _Out_writes_bytes_(ThreadInformationLength) PVOID ThreadInformation,
                                                 _In_ ULONG ThreadInformationLength, _Out_opt_ PULONG ReturnLength);
NTKERNELAPI HANDLE PsGetThreadId(_In_ PETHREAD Thread);

#define BK_QPC_TIMING_TELEMETRY_MIN_INTERVAL_MS 250u
#define BK_MEMORY_BASIC_INFORMATION_CLASS 0u
#define BK_MEMORY_BASIC_INFORMATION_MIN_SIZE 44u
#define BK_MEMORY_BASIC_ALLOCATION_PROTECT_OFFSET 16u
#define BK_MEMORY_BASIC_PROTECT_OFFSET 36u
#define BK_MEMORY_BASIC_TYPE_OFFSET 40u
#define BK_MEM_IMAGE 0x01000000u

static volatile LONG64 g_QpcTimingTelemetryNextTick = 0;

static BOOLEAN BkntkiResolveThreadHandleToIdentity(_In_ HANDLE ThreadHandle, _Out_opt_ UINT32 *TargetPid,
                                                   _Out_opt_ UINT32 *TargetTid)
{
    PETHREAD thread = NULL;
    NTSTATUS status;

    if (TargetPid != NULL)
    {
        *TargetPid = 0;
    }
    if (TargetTid != NULL)
    {
        *TargetTid = 0;
    }
    if (ThreadHandle == NULL)
    {
        return FALSE;
    }
    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        return FALSE;
    }

    status = ObReferenceObjectByHandle(ThreadHandle, THREAD_QUERY_LIMITED_INFORMATION, *PsThreadType,
                                       ExGetPreviousMode(), (PVOID *)&thread, NULL);
    if (!NT_SUCCESS(status))
    {
        status = ObReferenceObjectByHandle(ThreadHandle, 0, *PsThreadType, ExGetPreviousMode(), (PVOID *)&thread, NULL);
        if (!NT_SUCCESS(status))
        {
            return FALSE;
        }
    }

    if (TargetPid != NULL)
    {
        *TargetPid = (UINT32)(ULONG_PTR)PsGetThreadProcessId(thread);
    }
    if (TargetTid != NULL)
    {
        *TargetTid = (UINT32)(ULONG_PTR)PsGetThreadId(thread);
    }
    ObDereferenceObject(thread);
    return TRUE;
}

static VOID BkntkiEmitRemoteNtApiDetection(_In_z_ PCSTR DetectionName, _In_ ULONG Severity, _In_ HANDLE CallerPid,
                                           _In_ UINT32 TargetPid, _In_z_ PCWSTR ApiName, _In_ UINT64 AddressOrFlags)
{
    WCHAR reason[192];

    if (DetectionName == NULL || ApiName == NULL || CallerPid == NULL || TargetPid == 0 ||
        TargetPid == (UINT32)(ULONG_PTR)CallerPid)
    {
        return;
    }

    RtlStringCbPrintfW(reason, sizeof(reason), L"%ws cross-process caller=%llu target=%lu value=0x%llX", ApiName,
                       (ULONGLONG)(ULONG_PTR)CallerPid, (ULONG)TargetPid, AddressOrFlags);
    BketwLogDetectionEvent(DetectionName, Severity, CallerPid, (HANDLE)(ULONG_PTR)TargetPid, 0, 0, 0, reason);
}

static BOOLEAN BkntkiReadLargeIntegerOutSafe(_In_opt_ PLARGE_INTEGER Value, _Out_ LARGE_INTEGER *Observed)
{
    if (Observed == NULL)
    {
        return FALSE;
    }
    Observed->QuadPart = 0;
    if (Value == NULL)
    {
        return FALSE;
    }

    __try
    {
        *Observed = *Value;
        return TRUE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        Observed->QuadPart = 0;
        return FALSE;
    }
}

static VOID BkntkiWriteLargeIntegerSafe(_In_opt_ PLARGE_INTEGER Value, _In_ LARGE_INTEGER NewValue)
{
    if (Value == NULL)
    {
        return;
    }

    __try
    {
        if (ExGetPreviousMode() != KernelMode)
        {
            ProbeForWrite(Value, sizeof(*Value), __alignof(LARGE_INTEGER));
        }
        *Value = NewValue;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
    }
}

static ULONG_PTR BkntkiReadIoStatusInformationSafe(_In_opt_ PIO_STATUS_BLOCK IoStatusBlock)
{
    ULONG_PTR information = 0;

    if (IoStatusBlock == NULL)
    {
        return 0;
    }

    __try
    {
        information = IoStatusBlock->Information;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        information = 0;
    }

    return information;
}

static VOID BkntkiWriteIoStatusSafe(_In_opt_ PIO_STATUS_BLOCK IoStatusBlock, _In_ NTSTATUS Status,
                                    _In_ ULONG_PTR Information)
{
    if (IoStatusBlock == NULL)
    {
        return;
    }

    __try
    {
        if (ExGetPreviousMode() != KernelMode)
        {
            ProbeForWrite(IoStatusBlock, sizeof(*IoStatusBlock), __alignof(IO_STATUS_BLOCK));
        }
        IoStatusBlock->Status = Status;
        IoStatusBlock->Information = Information;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
    }
}

#define BK_NTAPI_LIT_CHARS(_Literal) ((USHORT)(RTL_NUMBER_OF(_Literal) - 1))

static BOOLEAN BkntkiUnicodeContainsBlackbirdArtifact(_In_opt_ PCUNICODE_STRING Text)
{
    BOOLEAN match = FALSE;

    __try
    {
        if (Text == NULL || Text->Buffer == NULL || Text->Length == 0)
        {
            return FALSE;
        }

        match =
            (BkstrUnicodeContainsInsensitive(Text, L"blackbird", BK_NTAPI_LIT_CHARS(L"blackbird")) ||
             BkstrUnicodeContainsInsensitive(Text, L"BlackbirdCtl", BK_NTAPI_LIT_CHARS(L"BlackbirdCtl")) ||
             BkstrUnicodeContainsInsensitive(Text, L"BlackbirdHookIngest",
                                             BK_NTAPI_LIT_CHARS(L"BlackbirdHookIngest")) ||
             BkstrUnicodeContainsInsensitive(Text, L"BlackbirdController",
                                             BK_NTAPI_LIT_CHARS(L"BlackbirdController")) ||
             BkstrUnicodeContainsInsensitive(Text, L"BlackbirdInterface", BK_NTAPI_LIT_CHARS(L"BlackbirdInterface")) ||
             BkstrUnicodeContainsInsensitive(Text, L"BlackbirdNetSvc", BK_NTAPI_LIT_CHARS(L"BlackbirdNetSvc")) ||
             BkstrUnicodeContainsInsensitive(Text, L"sr71.dll", BK_NTAPI_LIT_CHARS(L"sr71.dll")) ||
             BkstrUnicodeContainsInsensitive(Text, L"j58.dll", BK_NTAPI_LIT_CHARS(L"j58.dll")) ||
             BkstrUnicodeContainsInsensitive(Text, L"bkdc.dll", BK_NTAPI_LIT_CHARS(L"bkdc.dll")));
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        match = FALSE;
    }

    return match;
}

static BOOLEAN BkntkiObjectAttributesNameContainsBlackbirdArtifact(_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes)
{
    BOOLEAN match = FALSE;
    PUNICODE_STRING objectName = NULL;

    if (ObjectAttributes == NULL)
    {
        return FALSE;
    }

    __try
    {
        objectName = ObjectAttributes->ObjectName;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        objectName = NULL;
    }

    if (objectName == NULL)
    {
        return FALSE;
    }

    match = BkntkiUnicodeContainsBlackbirdArtifact(objectName);
    return match;
}

static BOOLEAN BkntkiUnicodeContainsBlackbirdRuntimeAccessArtifact(_In_opt_ PCUNICODE_STRING Text)
{
    BOOLEAN match = FALSE;

    __try
    {
        if (Text == NULL || Text->Buffer == NULL || Text->Length == 0)
        {
            return FALSE;
        }

        match = (BkstrUnicodeContainsInsensitive(Text, L"BlackbirdHookIngest",
                                                 BK_NTAPI_LIT_CHARS(L"BlackbirdHookIngest")) ||
                 BkstrUnicodeContainsInsensitive(Text, L"sr71.dll", BK_NTAPI_LIT_CHARS(L"sr71.dll")) ||
                 BkstrUnicodeContainsInsensitive(Text, L"j58.dll", BK_NTAPI_LIT_CHARS(L"j58.dll")) ||
                 BkstrUnicodeContainsInsensitive(Text, L"bkdc.dll", BK_NTAPI_LIT_CHARS(L"bkdc.dll")) ||
                 BkstrUnicodeContainsInsensitive(Text, L"sr71-", BK_NTAPI_LIT_CHARS(L"sr71-")));
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        match = FALSE;
    }

    return match;
}

static BOOLEAN
BkntkiObjectAttributesNameContainsBlackbirdRuntimeAccessArtifact(_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes)
{
    PUNICODE_STRING objectName = NULL;

    if (ObjectAttributes == NULL)
    {
        return FALSE;
    }

    __try
    {
        objectName = ObjectAttributes->ObjectName;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        objectName = NULL;
    }

    return BkntkiUnicodeContainsBlackbirdRuntimeAccessArtifact(objectName);
}

static BOOLEAN BkntkiObjectAttributesNameShouldBeConcealed(_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes)
{
    return BkntkiObjectAttributesNameContainsBlackbirdArtifact(ObjectAttributes) &&
           !BkntkiObjectAttributesNameContainsBlackbirdRuntimeAccessArtifact(ObjectAttributes);
}

static BOOLEAN BkntkiShouldConcealCurrentFilesystemCaller(VOID)
{
    return BkntkiShouldSanitizeCurrentCaller(BK_STREAM_FILESYSTEM | BK_STREAM_HANDLE);
}

static VOID BkntkiSanitizeVirtualMemoryInformation(_In_ HANDLE ProcessHandle, _In_opt_ PVOID BaseAddress,
                                                   _In_ ULONG MemoryInformationClass,
                                                   _Inout_updates_bytes_opt_(MemoryInformationLength)
                                                       PVOID MemoryInformation,
                                                   _In_ SIZE_T MemoryInformationLength, _In_ NTSTATUS Status)
{
    UINT32 targetPid = 0;

    if (!NT_SUCCESS(Status) || MemoryInformation == NULL ||
        MemoryInformationClass != BK_MEMORY_BASIC_INFORMATION_CLASS ||
        MemoryInformationLength < BK_MEMORY_BASIC_INFORMATION_MIN_SIZE ||
        !BkntkiShouldSanitizeProcessQuery(ProcessHandle, &targetPid) ||
        !BkntkiAddressTouchesInstrumentationRangeForPid(targetPid, BaseAddress))
    {
        return;
    }

    __try
    {
        if (ExGetPreviousMode() != KernelMode)
        {
            ProbeForWrite(MemoryInformation, BK_MEMORY_BASIC_INFORMATION_MIN_SIZE, __alignof(ULONG));
        }
        *(PULONG)((PUCHAR)MemoryInformation + BK_MEMORY_BASIC_ALLOCATION_PROTECT_OFFSET) = PAGE_EXECUTE_READ;
        *(PULONG)((PUCHAR)MemoryInformation + BK_MEMORY_BASIC_PROTECT_OFFSET) = PAGE_EXECUTE_READ;
        *(PULONG)((PUCHAR)MemoryInformation + BK_MEMORY_BASIC_TYPE_OFFSET) = BK_MEM_IMAGE;
        BkntkiRecordSanitizerHit(BkDiagSanitizerVirtualMemoryBasicInfo);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
    }
}

static BOOLEAN BkntkiDirectoryInformationOffsets(_In_ FILE_INFORMATION_CLASS FileInformationClass,
                                                 _Out_ ULONG *NameLengthOffset, _Out_ ULONG *NameOffset)
{
    if (NameLengthOffset == NULL || NameOffset == NULL)
    {
        return FALSE;
    }

    switch (FileInformationClass)
    {
    case FileDirectoryInformation:
        *NameLengthOffset = 60u;
        *NameOffset = 64u;
        return TRUE;
    case FileFullDirectoryInformation:
        *NameLengthOffset = 60u;
        *NameOffset = 68u;
        return TRUE;
    case FileBothDirectoryInformation:
        *NameLengthOffset = 60u;
        *NameOffset = 94u;
        return TRUE;
    case FileNamesInformation:
        *NameLengthOffset = 8u;
        *NameOffset = 12u;
        return TRUE;
    case FileIdFullDirectoryInformation:
        *NameLengthOffset = 60u;
        *NameOffset = 80u;
        return TRUE;
    case FileIdBothDirectoryInformation:
        *NameLengthOffset = 60u;
        *NameOffset = 104u;
        return TRUE;
    default:
        return FALSE;
    }
}

static NTSTATUS BkntkiScrubDirectoryInformation(_Inout_updates_bytes_opt_(Length) PVOID FileInformation,
                                                _In_ ULONG Length, _In_ FILE_INFORMATION_CLASS FileInformationClass,
                                                _In_ NTSTATUS Status)
{
    ULONG nameLengthOffset;
    ULONG nameOffset;
    ULONG offset = 0;
    ULONG previousOffset = 0;
    BOOLEAN hasPrevious = FALSE;
    BOOLEAN removedAny = FALSE;

    if (!NT_SUCCESS(Status) || FileInformation == NULL || Length < sizeof(ULONG) ||
        !BkntkiShouldConcealCurrentFilesystemCaller() ||
        !BkntkiDirectoryInformationOffsets(FileInformationClass, &nameLengthOffset, &nameOffset))
    {
        return Status;
    }

    __try
    {
        if (ExGetPreviousMode() != KernelMode)
        {
            ProbeForWrite(FileInformation, Length, __alignof(ULONG));
        }

        while (offset + nameOffset <= Length)
        {
            PUCHAR entry = (PUCHAR)FileInformation + offset;
            PULONG nextEntryOffset = (PULONG)entry;
            PULONG nameLengthPtr = (PULONG)(entry + nameLengthOffset);
            ULONG next = *nextEntryOffset;
            ULONG nameLength = *nameLengthPtr;
            UNICODE_STRING name;

            if (nameLength != 0 && offset + nameOffset + nameLength <= Length)
            {
                name.Buffer = (PWCHAR)(entry + nameOffset);
                name.Length = (USHORT)((nameLength > MAXUSHORT) ? MAXUSHORT : nameLength);
                name.MaximumLength = name.Length;
                if (BkntkiUnicodeContainsBlackbirdArtifact(&name))
                {
                    removedAny = TRUE;
                    if (next != 0 && offset + next < Length)
                    {
                        BkntkiRecordSanitizerHit(BkDiagSanitizerDirectoryBlackbird);
                        RtlMoveMemory(entry, entry + next, Length - offset - next);
                        continue;
                    }
                    if (hasPrevious)
                    {
                        *(PULONG)((PUCHAR)FileInformation + previousOffset) = 0;
                    }
                    else
                    {
                        RtlZeroMemory(FileInformation, Length);
                        BkntkiRecordSanitizerHit(BkDiagSanitizerDirectoryBlackbird);
                        return STATUS_NO_MORE_FILES;
                    }
                    break;
                }
            }

            if (next == 0)
            {
                break;
            }
            if (next < sizeof(ULONG) || offset + next >= Length)
            {
                break;
            }
            previousOffset = offset;
            hasPrevious = TRUE;
            offset += next;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return Status;
    }

    return removedAny ? STATUS_SUCCESS : Status;
}

static BOOLEAN BkntkiShouldEmitQpcTimingTelemetry(_In_ const BK_QPC_TIMING_APPLY_INFO *Info,
                                                  _In_ LARGE_INTEGER Frequency, _In_ LARGE_INTEGER Now)
{
    UINT32 notableFlags;
    INT64 minIntervalTicks;
    LONG64 nextAllowed;
    LONG64 desiredNext;

    if (Info == NULL || Frequency.QuadPart <= 0 || Now.QuadPart <= 0)
    {
        return FALSE;
    }

    notableFlags = BK_QPC_TIMING_SOURCE_SUSPEND_PAUSE | BK_QPC_TIMING_SOURCE_MONOTONIC_CLAMP |
                   BK_QPC_TIMING_SOURCE_TIGHT_PAIR_CLAMP;
    if ((Info->SourceFlags & notableFlags) == 0)
    {
        return FALSE;
    }

    minIntervalTicks = (INT64)(((UINT64)Frequency.QuadPart * BK_QPC_TIMING_TELEMETRY_MIN_INTERVAL_MS) / 1000ull);
    if (minIntervalTicks <= 0)
    {
        minIntervalTicks = 1;
    }

    for (;;)
    {
        nextAllowed = InterlockedCompareExchange64(&g_QpcTimingTelemetryNextTick, 0, 0);
        if (Now.QuadPart < nextAllowed)
        {
            return FALSE;
        }

        desiredNext = Now.QuadPart + minIntervalTicks;
        if (InterlockedCompareExchange64(&g_QpcTimingTelemetryNextTick, desiredNext, nextAllowed) == nextAllowed)
        {
            return TRUE;
        }
    }
}

NTSTATUS NTAPI BkntkiNtQuerySystemInformationHook(_In_ ULONG SystemInformationClass,
                                                  _Out_writes_bytes_opt_(SystemInformationLength)
                                                      PVOID SystemInformation,
                                                  _In_ ULONG SystemInformationLength, _Out_opt_ PULONG ReturnLength)
{
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE callerPid = NULL;
    ULONG observedReturnLength;
    UINT32 execFlags = BkntkiBuildExecFlags(NULL, 0u);
    BOOLEAN logAcquired = FALSE;

    BkntkiHookEnter();

    if (g_OriginalNtQuerySystemInformation == NULL)
    {
        BK_NTAPI_LOG(DPFLTR_ERROR_LEVEL, "BK: ntapi hook original null api=NtQuerySystemInformation.\n");
        status = STATUS_INVALID_DEVICE_STATE;
        goto Exit;
    }
    status = g_OriginalNtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength,
                                                ReturnLength);
    BkntkiPostProcessSystemInformationQuery(SystemInformationClass, SystemInformation, SystemInformationLength, status);

    if (!BkntkiShouldLog(&callerPid))
    {
        goto Exit;
    }
    logAcquired = TRUE;

    observedReturnLength = BkntkiReadUlongSafe(ReturnLength);
    BketwLogSystemInfoEvent(callerPid, PsGetCurrentThreadId(), SystemInformationClass, SystemInformationLength,
                            observedReturnLength, status);
    BkntkiLog("NtQuerySystemInformation", callerPid, (UINT64)SystemInformationClass, (UINT64)SystemInformationLength,
              (UINT64)observedReturnLength, 0, 0, 0, 0, 0, execFlags, status);

Exit:
    if (logAcquired)
    {
        ExReleaseRundownProtection(&g_NtApiRundown);
    }
    BkntkiHookExit();
    return status;
}

NTSTATUS NTAPI BkntkiNtQueryInformationProcessHook(_In_ HANDLE ProcessHandle, _In_ ULONG ProcessInformationClass,
                                                   _Out_writes_bytes_opt_(ProcessInformationLength)
                                                       PVOID ProcessInformation,
                                                   _In_ ULONG ProcessInformationLength, _Out_opt_ PULONG ReturnLength)
{
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE callerPid = NULL;
    ULONG observedReturnLength;
    UINT32 execFlags = BkntkiBuildExecFlags(ProcessHandle, 0u);
    BOOLEAN logAcquired = FALSE;

    BkntkiHookEnter();

    if (g_OriginalNtQueryInformationProcess == NULL)
    {
        BK_NTAPI_LOG(DPFLTR_ERROR_LEVEL, "BK: ntapi hook original null api=NtQueryInformationProcess.\n");
        status = STATUS_INVALID_DEVICE_STATE;
        goto Exit;
    }
    status = g_OriginalNtQueryInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation,
                                                 ProcessInformationLength, ReturnLength);
    if (BkntkiShouldSanitizeProcessQuery(ProcessHandle, NULL))
    {
        BkntkiSanitizeProcessQueryInformation(ProcessInformationClass, ProcessInformation, ProcessInformationLength,
                                              ReturnLength, status);
    }

    if (!BkntkiShouldLog(&callerPid))
    {
        goto Exit;
    }
    logAcquired = TRUE;

    observedReturnLength = BkntkiReadUlongSafe(ReturnLength);
    BkntkiLog("NtQueryInformationProcess", callerPid, (UINT64)(ULONG_PTR)ProcessHandle, (UINT64)ProcessInformationClass,
              (UINT64)(ULONG_PTR)ProcessInformation, (UINT64)ProcessInformationLength, (UINT64)observedReturnLength, 0,
              0, 0, execFlags, status);

Exit:
    if (logAcquired)
    {
        ExReleaseRundownProtection(&g_NtApiRundown);
    }
    BkntkiHookExit();
    return status;
}

NTSTATUS NTAPI BkntkiNtQueryPerformanceCounterHook(_Out_ PLARGE_INTEGER PerformanceCounter,
                                                   _Out_opt_ PLARGE_INTEGER PerformanceFrequency)
{
    NTSTATUS status = STATUS_SUCCESS;
    LARGE_INTEGER rawCounter;
    LARGE_INTEGER virtualCounter;
    LARGE_INTEGER frequency;
    LARGE_INTEGER hookStart;
    LARGE_INTEGER afterOriginal;
    LARGE_INTEGER hookEnd;
    BK_QPC_TIMING_APPLY_INFO applyInfo;
    HANDLE callerPid;
    HANDLE callerTid;
    UINT32 processId;
    UINT32 threadId;
    BOOLEAN adjusted = FALSE;
    BOOLEAN logAcquired = FALSE;

    rawCounter.QuadPart = 0;
    virtualCounter.QuadPart = 0;
    frequency.QuadPart = 0;
    RtlZeroMemory(&applyInfo, sizeof(applyInfo));
    callerPid = PsGetCurrentProcessId();
    callerTid = PsGetCurrentThreadId();
    processId = (UINT32)(ULONG_PTR)callerPid;
    threadId = (UINT32)(ULONG_PTR)callerTid;

    hookStart = KeQueryPerformanceCounter(&frequency);
    afterOriginal = hookStart;

    BkntkiHookEnter();

    if (g_OriginalNtQueryPerformanceCounter == NULL)
    {
        BK_NTAPI_LOG(DPFLTR_ERROR_LEVEL, "BK: ntapi hook original null api=NtQueryPerformanceCounter.\n");
        status = STATUS_INVALID_DEVICE_STATE;
        goto Exit;
    }

    status = g_OriginalNtQueryPerformanceCounter(PerformanceCounter, PerformanceFrequency);
    afterOriginal = KeQueryPerformanceCounter(NULL);
    if (NT_SUCCESS(status) && BkntkiReadLargeIntegerOutSafe(PerformanceCounter, &rawCounter))
    {
        LARGE_INTEGER observedFrequency;
        if (BkntkiReadLargeIntegerOutSafe(PerformanceFrequency, &observedFrequency) && observedFrequency.QuadPart > 0)
        {
            frequency = observedFrequency;
        }

        adjusted = BkqpcApplyTimingAdjustment(processId, threadId, rawCounter, frequency, &virtualCounter, &applyInfo);
        if (adjusted)
        {
            BkntkiRecordSanitizerHit(BkDiagSanitizerQpcTiming);
            BkntkiWriteLargeIntegerSafe(PerformanceCounter, virtualCounter);
        }
        else
        {
            virtualCounter = rawCounter;
        }
    }

    if (adjusted && BkntkiShouldEmitQpcTimingTelemetry(&applyInfo, frequency, afterOriginal) &&
        ExAcquireRundownProtection(&g_NtApiRundown))
    {
        logAcquired = TRUE;
        BketwLogQpcTimingEvent(callerPid, callerTid, (UINT64)rawCounter.QuadPart, (UINT64)virtualCounter.QuadPart,
                               applyInfo.RawDeltaTicks, applyInfo.VirtualDeltaTicks, applyInfo.CorrectionTicks,
                               applyInfo.SourceFlags, applyInfo.AutoBiasTicks, status);
    }

Exit:
    hookEnd = KeQueryPerformanceCounter(NULL);
    if (NT_SUCCESS(status))
    {
        BkqpcRecordPostQueryOverhead(processId, threadId, hookEnd.QuadPart - afterOriginal.QuadPart);
    }
    if (logAcquired)
    {
        ExReleaseRundownProtection(&g_NtApiRundown);
    }
    BkntkiHookExit();
    return status;
}

NTSTATUS NTAPI BkntkiNtQueryVirtualMemoryHook(_In_ HANDLE ProcessHandle, _In_opt_ PVOID BaseAddress,
                                              _In_ ULONG MemoryInformationClass,
                                              _Out_writes_bytes_opt_(MemoryInformationLength) PVOID MemoryInformation,
                                              _In_ SIZE_T MemoryInformationLength, _Out_opt_ PSIZE_T ReturnLength)
{
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE callerPid = NULL;
    SIZE_T observedReturnLength = 0;
    UINT32 targetPid = 0;
    UINT32 execFlags = BkntkiBuildExecFlags(ProcessHandle, 0u);
    BOOLEAN logAcquired = FALSE;

    BkntkiHookEnter();

    if (g_OriginalNtQueryVirtualMemory == NULL)
    {
        BK_NTAPI_LOG(DPFLTR_ERROR_LEVEL, "BK: ntapi hook original null api=NtQueryVirtualMemory.\n");
        status = STATUS_INVALID_DEVICE_STATE;
        goto Exit;
    }

    status = g_OriginalNtQueryVirtualMemory(ProcessHandle, BaseAddress, MemoryInformationClass, MemoryInformation,
                                            MemoryInformationLength, ReturnLength);
    BkntkiSanitizeVirtualMemoryInformation(ProcessHandle, BaseAddress, MemoryInformationClass, MemoryInformation,
                                           MemoryInformationLength, status);
    (void)BkntkiResolveProcessHandleToPid(ProcessHandle, &targetPid);

    if (!BkntkiShouldLog(&callerPid))
    {
        goto Exit;
    }
    logAcquired = TRUE;

    observedReturnLength = BkntkiReadSizeTSafe(ReturnLength);
    BkntkiLog("NtQueryVirtualMemory", callerPid, (UINT64)(ULONG_PTR)ProcessHandle, (UINT64)(ULONG_PTR)BaseAddress,
              (UINT64)MemoryInformationClass, (UINT64)MemoryInformationLength, (UINT64)observedReturnLength,
              (UINT64)targetPid, 0, 0, execFlags, status);

Exit:
    if (logAcquired)
    {
        ExReleaseRundownProtection(&g_NtApiRundown);
    }
    BkntkiHookExit();
    return status;
}

static BOOLEAN BkntkiBlankObjectNameInformation(_Inout_updates_bytes_opt_(ObjectInformationLength)
                                                    PVOID ObjectInformation,
                                                _In_ ULONG ObjectInformationLength)
{
    POBJECT_NAME_INFORMATION nameInfo;

    if (ObjectInformation == NULL || ObjectInformationLength < sizeof(OBJECT_NAME_INFORMATION))
    {
        return FALSE;
    }

    __try
    {
        if (ExGetPreviousMode() != KernelMode)
        {
            ProbeForWrite(ObjectInformation, sizeof(OBJECT_NAME_INFORMATION), __alignof(OBJECT_NAME_INFORMATION));
        }

        nameInfo = (POBJECT_NAME_INFORMATION)ObjectInformation;
        nameInfo->Name.Length = 0;
        if (nameInfo->Name.Buffer != NULL && nameInfo->Name.MaximumLength >= sizeof(WCHAR))
        {
            if (ExGetPreviousMode() != KernelMode)
            {
                ProbeForWrite(nameInfo->Name.Buffer, sizeof(WCHAR), __alignof(WCHAR));
            }
            nameInfo->Name.Buffer[0] = UNICODE_NULL;
        }
        return TRUE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return FALSE;
    }
}

NTSTATUS NTAPI BkntkiNtQueryObjectHook(_In_opt_ HANDLE Handle, _In_ ULONG ObjectInformationClass,
                                       _Out_writes_bytes_opt_(ObjectInformationLength) PVOID ObjectInformation,
                                       _In_ ULONG ObjectInformationLength, _Out_opt_ PULONG ReturnLength)
{
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE callerPid = NULL;
    ULONG observedReturnLength;
    UINT32 execFlags = BkntkiBuildExecFlags(NULL, 0u);
    BOOLEAN logAcquired = FALSE;
    BOOLEAN sanitizedName = FALSE;

    BkntkiHookEnter();

    if (g_OriginalNtQueryObject == NULL)
    {
        BK_NTAPI_LOG(DPFLTR_ERROR_LEVEL, "BK: ntapi hook original null api=NtQueryObject.\n");
        status = STATUS_INVALID_DEVICE_STATE;
        goto Exit;
    }

    status = g_OriginalNtQueryObject(Handle, ObjectInformationClass, ObjectInformation, ObjectInformationLength,
                                     ReturnLength);
    if (NT_SUCCESS(status) && ObjectInformationClass == BK_OBJECT_INFORMATION_CLASS_NAME &&
        BkntkiShouldSanitizeCurrentCaller(BK_STREAM_HANDLE) && BkntkiHandleValueIsProtectedIpc(Handle))
    {
        sanitizedName = BkntkiBlankObjectNameInformation(ObjectInformation, ObjectInformationLength);
        if (sanitizedName)
        {
            BkntkiRecordSanitizerHit(BkDiagSanitizerObjectName);
        }
    }

    if (!BkntkiShouldLog(&callerPid))
    {
        goto Exit;
    }
    logAcquired = TRUE;

    observedReturnLength = BkntkiReadUlongSafe(ReturnLength);
    BkntkiLog("NtQueryObject", callerPid, (UINT64)(ULONG_PTR)Handle, (UINT64)ObjectInformationClass,
              (UINT64)(ULONG_PTR)ObjectInformation, (UINT64)ObjectInformationLength, (UINT64)observedReturnLength,
              (UINT64)sanitizedName, 0, 0, execFlags, status);

Exit:
    if (logAcquired)
    {
        ExReleaseRundownProtection(&g_NtApiRundown);
    }
    BkntkiHookExit();
    return status;
}

NTSTATUS NTAPI BkntkiNtWriteVirtualMemoryHook(_In_ HANDLE ProcessHandle, _In_ PVOID BaseAddress,
                                              _In_reads_bytes_(BufferSize) PVOID Buffer, _In_ SIZE_T BufferSize,
                                              _Out_opt_ PSIZE_T NumberOfBytesWritten)
{
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE callerPid = NULL;
    SIZE_T observedWritten;
    UINT32 targetPid = 0;
    UINT32 execFlags = BkntkiBuildExecFlags(ProcessHandle, 0u);
    BOOLEAN logAcquired = FALSE;
    BOOLEAN deniedInstrumentationWrite = FALSE;

    BkntkiHookEnter();

    if (g_OriginalNtWriteVirtualMemory == NULL)
    {
        BK_NTAPI_LOG(DPFLTR_ERROR_LEVEL, "BK: ntapi hook original null api=NtWriteVirtualMemory.\n");
        status = STATUS_INVALID_DEVICE_STATE;
        goto Exit;
    }

    deniedInstrumentationWrite =
        BkntkiApplyProtectedWriteToCloak(ProcessHandle, BaseAddress, Buffer, BufferSize, &targetPid);
    if (targetPid == 0)
    {
        (void)BkntkiResolveProcessHandleToPid(ProcessHandle, &targetPid);
    }
    if (deniedInstrumentationWrite)
    {
        BkntkiWriteSizeTSafe(NumberOfBytesWritten, BufferSize);
        BkntkiRecordSanitizerHit(BkDiagSanitizerWriteVirtualMemoryCloak);
        status = STATUS_SUCCESS;
    }
    else
    {
        status = g_OriginalNtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesWritten);
    }

    if (!BkntkiShouldLog(&callerPid))
    {
        goto Exit;
    }
    logAcquired = TRUE;

    observedWritten = BkntkiReadSizeTSafe(NumberOfBytesWritten);
    BkntkiLog("NtWriteVirtualMemory", callerPid, (UINT64)(ULONG_PTR)ProcessHandle, (UINT64)(ULONG_PTR)BaseAddress,
              (UINT64)(ULONG_PTR)Buffer, (UINT64)BufferSize, (UINT64)observedWritten,
              (UINT64)deniedInstrumentationWrite, (UINT64)targetPid, 0, execFlags, status);
    if (NT_SUCCESS(status) && observedWritten != 0 && targetPid != 0 && targetPid != (UINT32)(ULONG_PTR)callerPid)
    {
        BkntkiEmitRemoteNtApiDetection("REMOTE_PROCESS_MEMORY_WRITE", 5u, callerPid, targetPid, L"NtWriteVirtualMemory",
                                       (UINT64)(ULONG_PTR)BaseAddress);
    }

Exit:
    if (logAcquired)
    {
        ExReleaseRundownProtection(&g_NtApiRundown);
    }
    BkntkiHookExit();
    return status;
}

NTSTATUS NTAPI BkntkiNtReadVirtualMemoryHook(_In_ HANDLE ProcessHandle, _In_ PVOID BaseAddress,
                                             _Out_writes_bytes_(BufferSize) PVOID Buffer, _In_ SIZE_T BufferSize,
                                             _Out_opt_ PSIZE_T NumberOfBytesRead)
{
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE callerPid = NULL;
    SIZE_T observedRead = 0;
    UINT32 targetPid = 0;
    UINT32 execFlags = BkntkiBuildExecFlags(ProcessHandle, 0u);
    BOOLEAN logAcquired = FALSE;
    BOOLEAN deniedInstrumentationRead = FALSE;
    BOOLEAN overlaidHookPatch = FALSE;

    BkntkiHookEnter();

    if (g_OriginalNtReadVirtualMemory == NULL)
    {
        BK_NTAPI_LOG(DPFLTR_ERROR_LEVEL, "BK: ntapi hook original null api=NtReadVirtualMemory.\n");
        status = STATUS_INVALID_DEVICE_STATE;
        goto Exit;
    }

    status = g_OriginalNtReadVirtualMemory(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesRead);
    observedRead = BkntkiReadSizeTSafe(NumberOfBytesRead);
    if (NT_SUCCESS(status) && observedRead != 0)
    {
        overlaidHookPatch =
            BkntkiOverlayHookPatchBytesForHandle(ProcessHandle, BaseAddress, observedRead, Buffer, &targetPid);
    }
    if (!overlaidHookPatch)
    {
        deniedInstrumentationRead =
            BkntkiReadTouchesInstrumentationRange(ProcessHandle, BaseAddress, BufferSize, &targetPid);
    }

    if (!BkntkiShouldLog(&callerPid))
    {
        goto Exit;
    }
    logAcquired = TRUE;

    BkntkiLog("NtReadVirtualMemory", callerPid, (UINT64)(ULONG_PTR)ProcessHandle, (UINT64)(ULONG_PTR)BaseAddress,
              (UINT64)(ULONG_PTR)Buffer, (UINT64)BufferSize, (UINT64)observedRead, (UINT64)deniedInstrumentationRead,
              (UINT64)targetPid, (UINT64)overlaidHookPatch, execFlags, status);

Exit:
    if (logAcquired)
    {
        ExReleaseRundownProtection(&g_NtApiRundown);
    }
    BkntkiHookExit();
    return status;
}

NTSTATUS NTAPI BkntkiNtProtectVirtualMemoryHook(_In_ HANDLE ProcessHandle, _Inout_ PVOID *BaseAddress,
                                                _Inout_ PSIZE_T RegionSize, _In_ ULONG NewProtect,
                                                _Out_ PULONG OldProtect)
{
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE callerPid = NULL;
    PVOID observedBase;
    SIZE_T observedSize;
    ULONG observedOldProtect;
    UINT32 targetPid = 0;
    UINT32 execFlags = BkntkiBuildExecFlags(ProcessHandle, 0u);
    BOOLEAN logAcquired = FALSE;
    BOOLEAN deniedInstrumentationProtect = FALSE;

    BkntkiHookEnter();

    if (g_OriginalNtProtectVirtualMemory == NULL)
    {
        BK_NTAPI_LOG(DPFLTR_ERROR_LEVEL, "BK: ntapi hook original null api=NtProtectVirtualMemory.\n");
        status = STATUS_INVALID_DEVICE_STATE;
        goto Exit;
    }

    observedBase = BkntkiReadPointerSafe(BaseAddress);
    observedSize = BkntkiReadSizeTSafe(RegionSize);
    (void)BkntkiResolveProcessHandleToPid(ProcessHandle, &targetPid);
    if ((NewProtect == PAGE_READWRITE || NewProtect == PAGE_WRITECOPY || NewProtect == PAGE_EXECUTE_READWRITE ||
         NewProtect == PAGE_EXECUTE_WRITECOPY) &&
        BkntkiWriteTouchesProtectedRange(ProcessHandle, observedBase, observedSize, &targetPid))
    {
        deniedInstrumentationProtect = TRUE;
        BkntkiRecordSanitizerHit(BkDiagSanitizerProtectVirtualMemoryDeny);
        status = STATUS_ACCESS_DENIED;
    }
    else
    {
        status = g_OriginalNtProtectVirtualMemory(ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);
    }

    if (!BkntkiShouldLog(&callerPid))
    {
        goto Exit;
    }
    logAcquired = TRUE;

    observedOldProtect = BkntkiReadUlongSafe(OldProtect);
    BkntkiLog("NtProtectVirtualMemory", callerPid, (UINT64)(ULONG_PTR)ProcessHandle, (UINT64)(ULONG_PTR)observedBase,
              (UINT64)observedSize, (UINT64)NewProtect, (UINT64)observedOldProtect,
              (UINT64)deniedInstrumentationProtect, (UINT64)targetPid, 0, execFlags, status);
    if (NT_SUCCESS(status) && targetPid != 0 && targetPid != (UINT32)(ULONG_PTR)callerPid &&
        (NewProtect == PAGE_EXECUTE || NewProtect == PAGE_EXECUTE_READ || NewProtect == PAGE_EXECUTE_READWRITE ||
         NewProtect == PAGE_EXECUTE_WRITECOPY))
    {
        BkntkiEmitRemoteNtApiDetection("REMOTE_MEMORY_PROTECT_EXECUTE", 5u, callerPid, targetPid,
                                       L"NtProtectVirtualMemory", (UINT64)(ULONG_PTR)observedBase);
    }

Exit:
    if (logAcquired)
    {
        ExReleaseRundownProtection(&g_NtApiRundown);
    }
    BkntkiHookExit();
    return status;
}

NTSTATUS NTAPI BkntkiNtCreateSectionHook(_Out_ PHANDLE SectionHandle, _In_ ACCESS_MASK DesiredAccess,
                                         _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
                                         _In_opt_ PLARGE_INTEGER MaximumSize, _In_ ULONG SectionPageProtection,
                                         _In_ ULONG AllocationAttributes, _In_opt_ HANDLE FileHandle)
{
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE callerPid = NULL;
    HANDLE observedSectionHandle;
    ULONGLONG observedMaximumSize;
    UINT32 execFlags = BkntkiBuildExecFlags(NULL, AllocationAttributes);
    BOOLEAN logAcquired = FALSE;

    BkntkiHookEnter();

    if (g_OriginalNtCreateSection == NULL)
    {
        BK_NTAPI_LOG(DPFLTR_ERROR_LEVEL, "BK: ntapi hook original null api=NtCreateSection.\n");
        status = STATUS_INVALID_DEVICE_STATE;
        goto Exit;
    }
    status = g_OriginalNtCreateSection(SectionHandle, DesiredAccess, ObjectAttributes, MaximumSize,
                                       SectionPageProtection, AllocationAttributes, FileHandle);
    observedSectionHandle = BkntkiReadHandleSafe(SectionHandle);
    if (NT_SUCCESS(status) && observedSectionHandle != NULL && FileHandle != NULL &&
        BkntkiHandleValueNameContainsLiteral(FileHandle, L"ntdll.dll"))
    {
        BkntkiRememberNtdllSectionHandle(observedSectionHandle, AllocationAttributes);
    }

    if (!BkntkiShouldLog(&callerPid))
    {
        goto Exit;
    }
    logAcquired = TRUE;

    observedMaximumSize = BkntkiReadLargeIntegerSafe(MaximumSize);
    BkntkiLog("NtCreateSection", callerPid, (UINT64)(ULONG_PTR)observedSectionHandle, (UINT64)DesiredAccess,
              observedMaximumSize, (UINT64)SectionPageProtection, (UINT64)AllocationAttributes,
              (UINT64)(ULONG_PTR)FileHandle, (UINT64)(ULONG_PTR)ObjectAttributes, 0, execFlags, status);

Exit:
    if (logAcquired)
    {
        ExReleaseRundownProtection(&g_NtApiRundown);
    }
    BkntkiHookExit();
    return status;
}

NTSTATUS NTAPI BkntkiNtMapViewOfSectionHook(_In_ HANDLE SectionHandle, _In_ HANDLE ProcessHandle,
                                            _Inout_ PVOID *BaseAddress, _In_ ULONG_PTR ZeroBits, _In_ SIZE_T CommitSize,
                                            _Inout_opt_ PLARGE_INTEGER SectionOffset, _Inout_ PSIZE_T ViewSize,
                                            _In_ ULONG InheritDisposition, _In_ ULONG AllocationType,
                                            _In_ ULONG Win32Protect)
{
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE callerPid = NULL;
    PVOID observedBase;
    SIZE_T observedViewSize;
    ULONGLONG observedOffset;
    UINT32 targetPid = 0;
    UINT64 primaryNtdllBase = 0;
    UINT32 ntdllSectionAttributes = 0;
    UINT32 execFlags = BkntkiBuildExecFlags(ProcessHandle, 0u);
    BOOLEAN logAcquired = FALSE;
    BOOLEAN mirroredNtdllDataView = FALSE;

    BkntkiHookEnter();

    if (g_OriginalNtMapViewOfSection == NULL)
    {
        BK_NTAPI_LOG(DPFLTR_ERROR_LEVEL, "BK: ntapi hook original null api=NtMapViewOfSection.\n");
        status = STATUS_INVALID_DEVICE_STATE;
        goto Exit;
    }
    status = g_OriginalNtMapViewOfSection(SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize,
                                          SectionOffset, ViewSize, InheritDisposition, AllocationType, Win32Protect);
    observedBase = BkntkiReadPointerSafe(BaseAddress);
    observedViewSize = BkntkiReadSizeTSafe(ViewSize);
    (void)BkntkiResolveProcessHandleToPid(ProcessHandle, &targetPid);
    if (NT_SUCCESS(status) && observedBase != NULL && observedViewSize != 0 && targetPid != 0 &&
        BkntkiShouldSanitizeProcessQuery(ProcessHandle, NULL) &&
        BkntkiIsTrackedNtdllSectionHandle(SectionHandle, &ntdllSectionAttributes) &&
        BkcimgQueryPrimaryNtdll((HANDLE)(ULONG_PTR)targetPid, &primaryNtdllBase, NULL))
    {
        NTSTATUS mirrorStatus;
        if ((ntdllSectionAttributes & SEC_IMAGE) != 0)
        {
            mirrorStatus = BkntkiMirrorHookPatchesIntoImage(targetPid, primaryNtdllBase,
                                                            (UINT64)(ULONG_PTR)observedBase, (UINT64)observedViewSize);
        }
        else
        {
            mirrorStatus = BkntkiMirrorHookPatchesIntoDataView(
                targetPid, primaryNtdllBase, (UINT64)(ULONG_PTR)observedBase, (UINT64)observedViewSize);
        }
        mirroredNtdllDataView = NT_SUCCESS(mirrorStatus);
        BketwLogDetectionEvent(
            mirroredNtdllDataView ? "NTDLL_SECTION_MAPPING_CLOAKED" : "NTDLL_SECTION_MAPPING_CLOAK_FAILED",
            mirroredNtdllDataView ? 3u : 5u, PsGetCurrentProcessId(), (HANDLE)(ULONG_PTR)targetPid, 0,
            (UINT32)mirrorStatus, 0,
            mirroredNtdllDataView ? L"ntdll section mapping mirrored with BK hook patch bytes"
                                  : L"failed to mirror BK hook patch bytes into ntdll section mapping");
    }

    if (!BkntkiShouldLog(&callerPid))
    {
        goto Exit;
    }
    logAcquired = TRUE;

    observedOffset = BkntkiReadLargeIntegerSafe(SectionOffset);
    BkntkiLog("NtMapViewOfSection", callerPid, (UINT64)(ULONG_PTR)SectionHandle, (UINT64)(ULONG_PTR)ProcessHandle,
              (UINT64)(ULONG_PTR)observedBase, (UINT64)observedViewSize, (UINT64)Win32Protect, observedOffset,
              (UINT64)targetPid, (UINT64)mirroredNtdllDataView, execFlags, status);
    if (NT_SUCCESS(status) && targetPid != 0 && targetPid != (UINT32)(ULONG_PTR)callerPid &&
        (Win32Protect == PAGE_EXECUTE || Win32Protect == PAGE_EXECUTE_READ || Win32Protect == PAGE_EXECUTE_READWRITE ||
         Win32Protect == PAGE_EXECUTE_WRITECOPY))
    {
        BkntkiEmitRemoteNtApiDetection("REMOTE_SECTION_MAP_EXECUTE", 5u, callerPid, targetPid, L"NtMapViewOfSection",
                                       (UINT64)(ULONG_PTR)observedBase);
    }

Exit:
    if (logAcquired)
    {
        ExReleaseRundownProtection(&g_NtApiRundown);
    }
    BkntkiHookExit();
    return status;
}

NTSTATUS NTAPI BkntkiNtMapViewOfSectionExHook(_In_ HANDLE SectionHandle, _In_ HANDLE ProcessHandle,
                                              _Inout_ PVOID *BaseAddress, _Inout_opt_ PLARGE_INTEGER SectionOffset,
                                              _Inout_ PSIZE_T ViewSize, _In_ ULONG AllocationType,
                                              _In_ ULONG Win32Protect, _In_opt_ PVOID ExtendedParameters,
                                              _In_ ULONG ExtendedParameterCount)
{
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE callerPid = NULL;
    PVOID observedBase;
    SIZE_T observedViewSize;
    UINT32 targetPid = 0;
    UINT32 execFlags = BkntkiBuildExecFlags(ProcessHandle, 0u);
    BOOLEAN logAcquired = FALSE;

    UNREFERENCED_PARAMETER(SectionOffset);
    UNREFERENCED_PARAMETER(ExtendedParameters);
    UNREFERENCED_PARAMETER(ExtendedParameterCount);

    BkntkiHookEnter();

    if (g_OriginalNtMapViewOfSectionEx == NULL)
    {
        BK_NTAPI_LOG(DPFLTR_ERROR_LEVEL, "BK: ntapi hook original null api=NtMapViewOfSectionEx.\n");
        status = STATUS_INVALID_DEVICE_STATE;
        goto Exit;
    }

    status = g_OriginalNtMapViewOfSectionEx(SectionHandle, ProcessHandle, BaseAddress, SectionOffset, ViewSize,
                                            AllocationType, Win32Protect, ExtendedParameters, ExtendedParameterCount);
    observedBase = BkntkiReadPointerSafe(BaseAddress);
    observedViewSize = BkntkiReadSizeTSafe(ViewSize);
    (void)BkntkiResolveProcessHandleToPid(ProcessHandle, &targetPid);

    if (!BkntkiShouldLog(&callerPid))
    {
        goto Exit;
    }
    logAcquired = TRUE;

    BkntkiLog("NtMapViewOfSectionEx", callerPid, (UINT64)(ULONG_PTR)SectionHandle, (UINT64)(ULONG_PTR)ProcessHandle,
              (UINT64)(ULONG_PTR)observedBase, (UINT64)observedViewSize, (UINT64)Win32Protect, (UINT64)AllocationType,
              (UINT64)targetPid, 0, execFlags, status);
    if (NT_SUCCESS(status) && targetPid != 0 && targetPid != (UINT32)(ULONG_PTR)callerPid &&
        (Win32Protect == PAGE_EXECUTE || Win32Protect == PAGE_EXECUTE_READ || Win32Protect == PAGE_EXECUTE_READWRITE ||
         Win32Protect == PAGE_EXECUTE_WRITECOPY))
    {
        BkntkiEmitRemoteNtApiDetection("REMOTE_SECTION_MAP_EXECUTE", 5u, callerPid, targetPid, L"NtMapViewOfSectionEx",
                                       (UINT64)(ULONG_PTR)observedBase);
    }

Exit:
    if (logAcquired)
    {
        ExReleaseRundownProtection(&g_NtApiRundown);
    }
    BkntkiHookExit();
    return status;
}

NTSTATUS NTAPI BkntkiNtUnmapViewOfSectionHook(_In_ HANDLE ProcessHandle, _In_opt_ PVOID BaseAddress)
{
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE callerPid = NULL;
    UINT32 targetPid = 0;
    UINT32 execFlags = BkntkiBuildExecFlags(ProcessHandle, 0u);
    BOOLEAN logAcquired = FALSE;

    BkntkiHookEnter();

    if (g_OriginalNtUnmapViewOfSection == NULL)
    {
        BK_NTAPI_LOG(DPFLTR_ERROR_LEVEL, "BK: ntapi hook original null api=NtUnmapViewOfSection.\n");
        status = STATUS_INVALID_DEVICE_STATE;
        goto Exit;
    }

    (void)BkntkiResolveProcessHandleToPid(ProcessHandle, &targetPid);
    status = g_OriginalNtUnmapViewOfSection(ProcessHandle, BaseAddress);

    if (!BkntkiShouldLog(&callerPid))
    {
        goto Exit;
    }
    logAcquired = TRUE;

    BkntkiLog("NtUnmapViewOfSection", callerPid, (UINT64)(ULONG_PTR)ProcessHandle, (UINT64)(ULONG_PTR)BaseAddress,
              (UINT64)targetPid, 0, 0, 0, 0, 0, execFlags, status);
    if (NT_SUCCESS(status) && targetPid != 0 && targetPid != (UINT32)(ULONG_PTR)callerPid)
    {
        BkntkiEmitRemoteNtApiDetection("REMOTE_VIEW_UNMAP", 6u, callerPid, targetPid, L"NtUnmapViewOfSection",
                                       (UINT64)(ULONG_PTR)BaseAddress);
    }

Exit:
    if (logAcquired)
    {
        ExReleaseRundownProtection(&g_NtApiRundown);
    }
    BkntkiHookExit();
    return status;
}

NTSTATUS NTAPI BkntkiNtUnmapViewOfSectionExHook(_In_ HANDLE ProcessHandle, _In_opt_ PVOID BaseAddress, _In_ ULONG Flags)
{
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE callerPid = NULL;
    UINT32 targetPid = 0;
    UINT32 execFlags = BkntkiBuildExecFlags(ProcessHandle, 0u);
    BOOLEAN logAcquired = FALSE;

    BkntkiHookEnter();

    if (g_OriginalNtUnmapViewOfSectionEx == NULL)
    {
        BK_NTAPI_LOG(DPFLTR_ERROR_LEVEL, "BK: ntapi hook original null api=NtUnmapViewOfSectionEx.\n");
        status = STATUS_INVALID_DEVICE_STATE;
        goto Exit;
    }

    (void)BkntkiResolveProcessHandleToPid(ProcessHandle, &targetPid);
    status = g_OriginalNtUnmapViewOfSectionEx(ProcessHandle, BaseAddress, Flags);

    if (!BkntkiShouldLog(&callerPid))
    {
        goto Exit;
    }
    logAcquired = TRUE;

    BkntkiLog("NtUnmapViewOfSectionEx", callerPid, (UINT64)(ULONG_PTR)ProcessHandle, (UINT64)(ULONG_PTR)BaseAddress,
              (UINT64)targetPid, (UINT64)Flags, 0, 0, 0, 0, execFlags, status);
    if (NT_SUCCESS(status) && targetPid != 0 && targetPid != (UINT32)(ULONG_PTR)callerPid)
    {
        BkntkiEmitRemoteNtApiDetection("REMOTE_VIEW_UNMAP", 6u, callerPid, targetPid, L"NtUnmapViewOfSectionEx",
                                       (UINT64)(ULONG_PTR)BaseAddress);
    }

Exit:
    if (logAcquired)
    {
        ExReleaseRundownProtection(&g_NtApiRundown);
    }
    BkntkiHookExit();
    return status;
}

NTSTATUS NTAPI BkntkiNtQuerySystemInformationExHook(_In_ ULONG SystemInformationClass,
                                                    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
                                                    _In_ ULONG InputBufferLength,
                                                    _Out_writes_bytes_opt_(SystemInformationLength)
                                                        PVOID SystemInformation,
                                                    _In_ ULONG SystemInformationLength, _Out_opt_ PULONG ReturnLength)
{
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE callerPid = NULL;
    ULONG observedReturnLength;
    UINT32 execFlags = BkntkiBuildExecFlags(NULL, 0u);
    BOOLEAN logAcquired = FALSE;

    BkntkiHookEnter();

    if (g_OriginalNtQuerySystemInformationEx == NULL)
    {
        BK_NTAPI_LOG(DPFLTR_ERROR_LEVEL, "BK: ntapi hook original null api=NtQuerySystemInformationEx.\n");
        status = STATUS_INVALID_DEVICE_STATE;
        goto Exit;
    }
    status = g_OriginalNtQuerySystemInformationEx(SystemInformationClass, InputBuffer, InputBufferLength,
                                                  SystemInformation, SystemInformationLength, ReturnLength);
    BkntkiPostProcessSystemInformationExQuery(SystemInformationClass, SystemInformation, SystemInformationLength,
                                              status);

    if (!BkntkiShouldLog(&callerPid))
    {
        goto Exit;
    }
    logAcquired = TRUE;

    observedReturnLength = BkntkiReadUlongSafe(ReturnLength);
    BketwLogSystemInfoEvent(callerPid, PsGetCurrentThreadId(), SystemInformationClass, SystemInformationLength,
                            observedReturnLength, status);
    BkntkiLog("NtQuerySystemInformationEx", callerPid, (UINT64)SystemInformationClass, (UINT64)(ULONG_PTR)InputBuffer,
              (UINT64)InputBufferLength, (UINT64)(ULONG_PTR)SystemInformation, (UINT64)SystemInformationLength,
              (UINT64)observedReturnLength, 0, 0, execFlags, status);

Exit:
    if (logAcquired)
    {
        ExReleaseRundownProtection(&g_NtApiRundown);
    }
    BkntkiHookExit();
    return status;
}

NTSTATUS NTAPI BkntkiNtAllocateVirtualMemoryPreLog(_In_ HANDLE ProcessHandle, _Inout_ PVOID *BaseAddress,
                                                   _In_ ULONG_PTR ZeroBits, _Inout_ PSIZE_T RegionSize,
                                                   _In_ ULONG AllocationType, _In_ ULONG Protect)
{
    HANDLE callerPid = NULL;
    PVOID observedBase;
    SIZE_T observedRegionSize;
    UINT32 targetPid = 0;
    LONG remainingBudget;
    BOOLEAN logAcquired = FALSE;
    NTSTATUS status = STATUS_SUCCESS;
    UINT32 execFlags = BkntkiBuildExecFlags(ProcessHandle, 0u);

    remainingBudget = InterlockedDecrement(&g_NtApiAllocatePreLogBudget);
    if (remainingBudget >= 0)
    {
        BK_NTAPI_LOG(
            DPFLTR_INFO_LEVEL,
            "BK: ntapi allocate prelog original=%p process=%p basePtr=%p zeroBits=0x%p regionPtr=%p allocType=0x%08X protect=0x%08X.\n",
            g_OriginalNtAllocateVirtualMemory, ProcessHandle, BaseAddress, (PVOID)ZeroBits, RegionSize, AllocationType,
            Protect);
    }
    if (!BkntkiShouldLog(&callerPid))
    {
        goto Exit;
    }
    logAcquired = TRUE;

    observedBase = BkntkiReadPointerSafe(BaseAddress);
    observedRegionSize = BkntkiReadSizeTSafe(RegionSize);
    (void)BkntkiResolveProcessHandleToPid(ProcessHandle, &targetPid);
    BkntkiLog("NtAllocateVirtualMemory", callerPid, (UINT64)(ULONG_PTR)ProcessHandle, (UINT64)(ULONG_PTR)observedBase,
              (UINT64)observedRegionSize, (UINT64)ZeroBits, (UINT64)AllocationType, (UINT64)Protect, (UINT64)targetPid,
              0, execFlags, STATUS_SUCCESS);

Exit:
    if (logAcquired)
    {
        ExReleaseRundownProtection(&g_NtApiRundown);
    }
    return status;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Thread-context hooks
 *
 * ObRegisterCallbacks only fires on handle CREATE/DUPLICATE — it cannot
 * detect subsequent NtGetContextThread / NtSetContextThread calls on an
 * already-open handle.  These kernel NT-API hooks fill that gap.
 *
 * Cross-process NtSetContextThread is a direct indicator of thread context
 * hijacking.  Same-process calls are still logged for correlation with prior
 * alloc/write/hollow events.
 * ═══════════════════════════════════════════════════════════════════════════ */

NTSTATUS NTAPI BkntkiNtCreateThreadHook(_Out_ PHANDLE ThreadHandle, _In_ ACCESS_MASK DesiredAccess,
                                        _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes, _In_ HANDLE ProcessHandle,
                                        _Out_opt_ PCLIENT_ID ClientId, _In_ PCONTEXT ThreadContext,
                                        _In_ PVOID InitialTeb, _In_ BOOLEAN CreateSuspended)
{
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE callerPid = NULL;
    HANDLE observedThreadHandle = NULL;
    UINT32 targetPid = 0;
    UINT32 targetTid = 0;
    UINT32 execFlags = BkntkiBuildExecFlags(ProcessHandle, 0u);
    BOOLEAN logAcquired = FALSE;

    BkntkiHookEnter();

    if (g_OriginalNtCreateThread == NULL)
    {
        BK_NTAPI_LOG(DPFLTR_ERROR_LEVEL, "BK: ntapi hook original null api=NtCreateThread.\n");
        status = STATUS_INVALID_DEVICE_STATE;
        goto Exit;
    }

    (void)BkntkiResolveProcessHandleToPid(ProcessHandle, &targetPid);
    status = g_OriginalNtCreateThread(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, ClientId,
                                      ThreadContext, InitialTeb, CreateSuspended);
    if (NT_SUCCESS(status))
    {
        observedThreadHandle = BkntkiReadHandleSafe(ThreadHandle);
        if (observedThreadHandle != NULL)
        {
            (void)BkntkiResolveThreadHandleToIdentity(observedThreadHandle, &targetPid, &targetTid);
        }
    }

    if (!BkntkiShouldLog(&callerPid))
    {
        goto Exit;
    }
    logAcquired = TRUE;

    BkntkiLog("NtCreateThread", callerPid, (UINT64)(ULONG_PTR)ProcessHandle, (UINT64)(ULONG_PTR)observedThreadHandle,
              (UINT64)targetPid, (UINT64)targetTid, (UINT64)CreateSuspended, (UINT64)DesiredAccess, 0, 0, execFlags,
              status);
    if (NT_SUCCESS(status) && targetPid != 0 && targetPid != (UINT32)(ULONG_PTR)callerPid)
    {
        BkntkiEmitRemoteNtApiDetection("REMOTE_THREAD_CREATE_NTAPI", CreateSuspended ? 7u : 6u, callerPid, targetPid,
                                       L"NtCreateThread", (UINT64)targetTid);
    }

Exit:
    if (logAcquired)
    {
        ExReleaseRundownProtection(&g_NtApiRundown);
    }
    BkntkiHookExit();
    return status;
}

NTSTATUS NTAPI BkntkiNtCreateThreadExHook(_Out_ PHANDLE ThreadHandle, _In_ ACCESS_MASK DesiredAccess,
                                          _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes, _In_ HANDLE ProcessHandle,
                                          _In_ PVOID StartRoutine, _In_opt_ PVOID Argument, _In_ ULONG CreateFlags,
                                          _In_ SIZE_T ZeroBits, _In_ SIZE_T StackSize, _In_ SIZE_T MaximumStackSize,
                                          _In_opt_ PVOID AttributeList)
{
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE callerPid = NULL;
    HANDLE observedThreadHandle = NULL;
    UINT32 targetPid = 0;
    UINT32 targetTid = 0;
    UINT32 execFlags = BkntkiBuildExecFlags(ProcessHandle, 0u);
    BOOLEAN logAcquired = FALSE;

    BkntkiHookEnter();

    if (g_OriginalNtCreateThreadEx == NULL)
    {
        BK_NTAPI_LOG(DPFLTR_ERROR_LEVEL, "BK: ntapi hook original null api=NtCreateThreadEx.\n");
        status = STATUS_INVALID_DEVICE_STATE;
        goto Exit;
    }

    (void)BkntkiResolveProcessHandleToPid(ProcessHandle, &targetPid);
    status = g_OriginalNtCreateThreadEx(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine,
                                        Argument, CreateFlags, ZeroBits, StackSize, MaximumStackSize, AttributeList);
    if (NT_SUCCESS(status))
    {
        observedThreadHandle = BkntkiReadHandleSafe(ThreadHandle);
        if (observedThreadHandle != NULL)
        {
            (void)BkntkiResolveThreadHandleToIdentity(observedThreadHandle, &targetPid, &targetTid);
        }
    }

    if (!BkntkiShouldLog(&callerPid))
    {
        goto Exit;
    }
    logAcquired = TRUE;

    BkntkiLog("NtCreateThreadEx", callerPid, (UINT64)(ULONG_PTR)ProcessHandle, (UINT64)(ULONG_PTR)observedThreadHandle,
              (UINT64)targetPid, (UINT64)(ULONG_PTR)StartRoutine, (UINT64)(ULONG_PTR)Argument, (UINT64)CreateFlags,
              (UINT64)targetTid, (UINT64)DesiredAccess, execFlags, status);
    if (NT_SUCCESS(status) && targetPid != 0 && targetPid != (UINT32)(ULONG_PTR)callerPid)
    {
        BkntkiEmitRemoteNtApiDetection("REMOTE_THREAD_CREATE_NTAPI", ((CreateFlags & 0x4u) != 0) ? 7u : 6u, callerPid,
                                       targetPid, L"NtCreateThreadEx", (UINT64)(ULONG_PTR)StartRoutine);
    }

Exit:
    if (logAcquired)
    {
        ExReleaseRundownProtection(&g_NtApiRundown);
    }
    BkntkiHookExit();
    return status;
}

NTSTATUS NTAPI BkntkiNtQueueApcThreadHook(_In_ HANDLE ThreadHandle, _In_ PVOID ApcRoutine, _In_opt_ PVOID ApcArgument1,
                                          _In_opt_ PVOID ApcArgument2, _In_opt_ PVOID ApcArgument3)
{
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE callerPid = NULL;
    UINT32 targetPid = 0;
    UINT32 targetTid = 0;
    UINT32 execFlags = BkntkiBuildExecFlags(NULL, 0u);
    BOOLEAN logAcquired = FALSE;

    BkntkiHookEnter();

    if (g_OriginalNtQueueApcThread == NULL)
    {
        BK_NTAPI_LOG(DPFLTR_ERROR_LEVEL, "BK: ntapi hook original null api=NtQueueApcThread.\n");
        status = STATUS_INVALID_DEVICE_STATE;
        goto Exit;
    }

    (void)BkntkiResolveThreadHandleToIdentity(ThreadHandle, &targetPid, &targetTid);
    status = g_OriginalNtQueueApcThread(ThreadHandle, ApcRoutine, ApcArgument1, ApcArgument2, ApcArgument3);

    if (!BkntkiShouldLog(&callerPid))
    {
        goto Exit;
    }
    logAcquired = TRUE;

    BkntkiLog("NtQueueApcThread", callerPid, (UINT64)(ULONG_PTR)ThreadHandle, (UINT64)(ULONG_PTR)ApcRoutine,
              (UINT64)(ULONG_PTR)ApcArgument1, (UINT64)(ULONG_PTR)ApcArgument2, (UINT64)(ULONG_PTR)ApcArgument3,
              (UINT64)targetTid, (UINT64)targetPid, 0, execFlags, status);
    if (NT_SUCCESS(status) && targetPid != 0 && targetPid != (UINT32)(ULONG_PTR)callerPid)
    {
        BkntkiEmitRemoteNtApiDetection("REMOTE_APC_QUEUE_NTAPI", 6u, callerPid, targetPid, L"NtQueueApcThread",
                                       (UINT64)(ULONG_PTR)ApcRoutine);
    }

Exit:
    if (logAcquired)
    {
        ExReleaseRundownProtection(&g_NtApiRundown);
    }
    BkntkiHookExit();
    return status;
}

NTSTATUS NTAPI BkntkiNtQueueApcThreadExHook(_In_ HANDLE ThreadHandle, _In_opt_ HANDLE UserApcReserveHandle,
                                            _In_ PVOID ApcRoutine, _In_opt_ PVOID ApcArgument1,
                                            _In_opt_ PVOID ApcArgument2, _In_opt_ PVOID ApcArgument3)
{
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE callerPid = NULL;
    UINT32 targetPid = 0;
    UINT32 targetTid = 0;
    UINT32 execFlags = BkntkiBuildExecFlags(NULL, 0u);
    BOOLEAN logAcquired = FALSE;

    BkntkiHookEnter();

    if (g_OriginalNtQueueApcThreadEx == NULL)
    {
        BK_NTAPI_LOG(DPFLTR_ERROR_LEVEL, "BK: ntapi hook original null api=NtQueueApcThreadEx.\n");
        status = STATUS_INVALID_DEVICE_STATE;
        goto Exit;
    }

    (void)BkntkiResolveThreadHandleToIdentity(ThreadHandle, &targetPid, &targetTid);
    status = g_OriginalNtQueueApcThreadEx(ThreadHandle, UserApcReserveHandle, ApcRoutine, ApcArgument1, ApcArgument2,
                                          ApcArgument3);

    if (!BkntkiShouldLog(&callerPid))
    {
        goto Exit;
    }
    logAcquired = TRUE;

    BkntkiLog("NtQueueApcThreadEx", callerPid, (UINT64)(ULONG_PTR)ThreadHandle, (UINT64)(ULONG_PTR)UserApcReserveHandle,
              (UINT64)(ULONG_PTR)ApcRoutine, (UINT64)(ULONG_PTR)ApcArgument1, (UINT64)(ULONG_PTR)ApcArgument2,
              (UINT64)(ULONG_PTR)ApcArgument3, (UINT64)targetTid, (UINT64)targetPid, execFlags, status);
    if (NT_SUCCESS(status) && targetPid != 0 && targetPid != (UINT32)(ULONG_PTR)callerPid)
    {
        BkntkiEmitRemoteNtApiDetection("REMOTE_APC_QUEUE_NTAPI", 6u, callerPid, targetPid, L"NtQueueApcThreadEx",
                                       (UINT64)(ULONG_PTR)ApcRoutine);
    }

Exit:
    if (logAcquired)
    {
        ExReleaseRundownProtection(&g_NtApiRundown);
    }
    BkntkiHookExit();
    return status;
}

NTSTATUS NTAPI BkntkiNtQueueApcThreadEx2Hook(_In_ HANDLE ThreadHandle, _In_opt_ HANDLE UserApcReserveHandle,
                                             _In_ ULONG QueueUserApcFlags, _In_ PVOID ApcRoutine,
                                             _In_opt_ PVOID ApcArgument1, _In_opt_ PVOID ApcArgument2,
                                             _In_opt_ PVOID ApcArgument3)
{
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE callerPid = NULL;
    UINT32 targetPid = 0;
    UINT32 targetTid = 0;
    UINT32 execFlags = BkntkiBuildExecFlags(NULL, 0u);
    BOOLEAN logAcquired = FALSE;

    BkntkiHookEnter();

    if (g_OriginalNtQueueApcThreadEx2 == NULL)
    {
        BK_NTAPI_LOG(DPFLTR_ERROR_LEVEL, "BK: ntapi hook original null api=NtQueueApcThreadEx2.\n");
        status = STATUS_INVALID_DEVICE_STATE;
        goto Exit;
    }

    (void)BkntkiResolveThreadHandleToIdentity(ThreadHandle, &targetPid, &targetTid);
    status = g_OriginalNtQueueApcThreadEx2(ThreadHandle, UserApcReserveHandle, QueueUserApcFlags, ApcRoutine,
                                           ApcArgument1, ApcArgument2, ApcArgument3);

    if (!BkntkiShouldLog(&callerPid))
    {
        goto Exit;
    }
    logAcquired = TRUE;

    BkntkiLog("NtQueueApcThreadEx2", callerPid, (UINT64)(ULONG_PTR)ThreadHandle,
              (UINT64)(ULONG_PTR)UserApcReserveHandle, (UINT64)QueueUserApcFlags, (UINT64)(ULONG_PTR)ApcRoutine,
              (UINT64)(ULONG_PTR)ApcArgument1, (UINT64)(ULONG_PTR)ApcArgument2, (UINT64)targetTid, (UINT64)targetPid,
              execFlags, status);
    if (NT_SUCCESS(status) && targetPid != 0 && targetPid != (UINT32)(ULONG_PTR)callerPid)
    {
        BkntkiEmitRemoteNtApiDetection("REMOTE_APC_QUEUE_NTAPI", 6u, callerPid, targetPid, L"NtQueueApcThreadEx2",
                                       (UINT64)(ULONG_PTR)ApcRoutine);
    }

Exit:
    if (logAcquired)
    {
        ExReleaseRundownProtection(&g_NtApiRundown);
    }
    BkntkiHookExit();
    return status;
}

static HANDLE BkntkiThreadHandleToOwnerPid(_In_ HANDLE ThreadHandle)
{
    PETHREAD thread = NULL;
    HANDLE ownerPid = NULL;

    if (ThreadHandle == NULL || KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        return NULL;
    }

    if (NT_SUCCESS(ObReferenceObjectByHandle(ThreadHandle, THREAD_QUERY_LIMITED_INFORMATION, *PsThreadType,
                                             ExGetPreviousMode(), (PVOID *)&thread, NULL)))
    {
        ownerPid = PsGetThreadProcessId(thread);
        ObDereferenceObject(thread);
    }
    return ownerPid;
}

static BOOLEAN BkntkiThreadHandleLooksSr71Owned(_In_ HANDLE ThreadHandle, _In_ UINT32 ExpectedOwnerPid)
{
    PVOID startAddress = NULL;
    HANDLE ownerPid;

    if (ThreadHandle == NULL || ExpectedOwnerPid == 0)
    {
        return FALSE;
    }

    ownerPid = BkntkiThreadHandleToOwnerPid(ThreadHandle);
    if ((UINT32)(ULONG_PTR)ownerPid != ExpectedOwnerPid)
    {
        return FALSE;
    }

    if (!NT_SUCCESS(ZwQueryInformationThread(ThreadHandle, ThreadQuerySetWin32StartAddress, &startAddress,
                                             sizeof(startAddress), NULL)) ||
        startAddress == NULL)
    {
        return FALSE;
    }

    return BkntkiAddressTouchesInstrumentationRangeForPid(ExpectedOwnerPid, startAddress);
}

static ULONGLONG BkntkiReadContextRip(_In_ PCONTEXT UserContext)
{
    ULONGLONG rip = 0;
    if (UserContext == NULL)
        return 0;
    __try
    {
        if (ExGetPreviousMode() != KernelMode)
        {
            ProbeForRead(UserContext, sizeof(CONTEXT), __alignof(ULONG));
        }
        if ((UserContext->ContextFlags & CONTEXT_CONTROL) != 0)
        {
            rip = UserContext->Rip;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        rip = 0;
    }
    return rip;
}

NTSTATUS NTAPI BkntkiNtGetContextThreadHook(_In_ HANDLE ThreadHandle, _Inout_ PCONTEXT ThreadContext)
{
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE callerPid = NULL;
    HANDLE targetOwnerPid = NULL;
    UINT32 execFlags = 0;
    BOOLEAN logAcquired = FALSE;
    BOOLEAN crossProcess = FALSE;

    BkntkiHookEnter();

    if (g_OriginalNtGetContextThread == NULL)
    {
        BK_NTAPI_LOG(DPFLTR_ERROR_LEVEL, "BK: ntapi hook original null api=NtGetContextThread.\n");
        status = STATUS_INVALID_DEVICE_STATE;
        goto Exit;
    }
    status = g_OriginalNtGetContextThread(ThreadHandle, ThreadContext);

    if (!BkntkiShouldLog(&callerPid))
        goto Exit;
    logAcquired = TRUE;

    if (NT_SUCCESS(status))
    {
        targetOwnerPid = BkntkiThreadHandleToOwnerPid(ThreadHandle);
    }
    crossProcess = (targetOwnerPid != NULL && targetOwnerPid != callerPid);
    execFlags = (crossProcess ? 0u : BK_NTAPI_EXEC_FLAG_TARGET_CURRENT_PROCESS) | BK_NTAPI_EXEC_FLAG_CALLER_USER;

    BkntkiLog("NtGetContextThread", callerPid, (UINT64)(ULONG_PTR)ThreadHandle, (UINT64)(ULONG_PTR)targetOwnerPid,
              (crossProcess && NT_SUCCESS(status)) ? BkntkiReadContextRip(ThreadContext) : 0, (UINT64)crossProcess, 0,
              0, 0, 0, execFlags, status);

Exit:
    if (logAcquired)
        ExReleaseRundownProtection(&g_NtApiRundown);
    BkntkiHookExit();
    return status;
}

NTSTATUS NTAPI BkntkiNtSetContextThreadHook(_In_ HANDLE ThreadHandle, _In_ PCONTEXT ThreadContext)
{
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE callerPid = NULL;
    HANDLE targetOwnerPid = NULL;
    ULONGLONG newRip = 0;
    UINT32 execFlags = 0;
    BOOLEAN logAcquired = FALSE;
    BOOLEAN crossProcess = FALSE;
    WCHAR reason[192];

    BkntkiHookEnter();

    if (g_OriginalNtSetContextThread == NULL)
    {
        BK_NTAPI_LOG(DPFLTR_ERROR_LEVEL, "BK: ntapi hook original null api=NtSetContextThread.\n");
        status = STATUS_INVALID_DEVICE_STATE;
        goto Exit;
    }

    /* Capture new RIP and target PID before calling original */
    newRip = BkntkiReadContextRip(ThreadContext);
    targetOwnerPid = BkntkiThreadHandleToOwnerPid(ThreadHandle);

    status = g_OriginalNtSetContextThread(ThreadHandle, ThreadContext);

    if (!BkntkiShouldLog(&callerPid))
        goto Exit;
    logAcquired = TRUE;

    crossProcess = (targetOwnerPid != NULL && targetOwnerPid != callerPid);
    execFlags = (crossProcess ? 0u : BK_NTAPI_EXEC_FLAG_TARGET_CURRENT_PROCESS) | BK_NTAPI_EXEC_FLAG_CALLER_USER;

    BkntkiLog("NtSetContextThread", callerPid, (UINT64)(ULONG_PTR)ThreadHandle, (UINT64)(ULONG_PTR)targetOwnerPid,
              newRip, (UINT64)crossProcess, 0, 0, 0, 0, execFlags, status);

    /* Cross-process context write = thread hijacking.  Emit a high-severity
       detection event immediately so the controller/UI don't need to correlate. */
    if (crossProcess && NT_SUCCESS(status))
    {
        RtlStringCbPrintfW(reason, sizeof(reason),
                           L"NtSetContextThread cross-process: caller=%llu target=%llu new-rip=0x%llX",
                           (ULONGLONG)(ULONG_PTR)callerPid, (ULONGLONG)(ULONG_PTR)targetOwnerPid, newRip);
        BketwLogDetectionEvent("THREAD_CONTEXT_HIJACK", 8u, callerPid, targetOwnerPid, 0, 0, 0, reason);
    }

Exit:
    if (logAcquired)
        ExReleaseRundownProtection(&g_NtApiRundown);
    BkntkiHookExit();
    return status;
}

NTSTATUS NTAPI BkntkiNtGetNextThreadHook(_In_ HANDLE ProcessHandle, _In_opt_ HANDLE ThreadHandle,
                                         _In_ ACCESS_MASK DesiredAccess, _In_ ULONG HandleAttributes, _In_ ULONG Flags,
                                         _Out_ PHANDLE NewThreadHandle)
{
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE callerPid = NULL;
    HANDLE cursor = ThreadHandle;
    HANDLE candidate = NULL;
    UINT32 targetPid = 0;
    UINT32 execFlags = BkntkiBuildExecFlags(ProcessHandle, 0u);
    BOOLEAN logAcquired = FALSE;
    BOOLEAN cursorOwned = FALSE;
    BOOLEAN filter = FALSE;

    BkntkiHookEnter();

    if (g_OriginalNtGetNextThread == NULL)
    {
        BK_NTAPI_LOG(DPFLTR_ERROR_LEVEL, "BK: ntapi hook original null api=NtGetNextThread.\n");
        status = STATUS_INVALID_DEVICE_STATE;
        goto Exit;
    }

    filter = BkntkiShouldSanitizeProcessQuery(ProcessHandle, &targetPid);
    if (!filter)
    {
        status = g_OriginalNtGetNextThread(ProcessHandle, ThreadHandle, DesiredAccess, HandleAttributes, Flags,
                                           NewThreadHandle);
        goto Log;
    }

    for (;;)
    {
        candidate = NULL;
        status = g_OriginalNtGetNextThread(ProcessHandle, cursor, DesiredAccess, HandleAttributes, Flags, &candidate);
        if (cursorOwned)
        {
            ZwClose(cursor);
            cursorOwned = FALSE;
        }
        if (!NT_SUCCESS(status))
        {
            goto Log;
        }
        if (!BkntkiThreadHandleLooksSr71Owned(candidate, targetPid))
        {
            __try
            {
                *NewThreadHandle = candidate;
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                ZwClose(candidate);
                status = GetExceptionCode();
            }
            goto Log;
        }

        cursor = candidate;
        cursorOwned = TRUE;
        BkntkiRecordSanitizerHit(BkDiagSanitizerGetNextThreadFilter);
    }

Log:
    if (!BkntkiShouldLog(&callerPid))
    {
        goto Exit;
    }
    logAcquired = TRUE;
    BkntkiLog("NtGetNextThread", callerPid, (UINT64)(ULONG_PTR)ProcessHandle, (UINT64)(ULONG_PTR)ThreadHandle,
              (UINT64)DesiredAccess, (UINT64)(ULONG_PTR)NewThreadHandle, (UINT64)targetPid, (UINT64)filter, 0, 0,
              execFlags, status);

Exit:
    if (cursorOwned)
    {
        ZwClose(cursor);
    }
    if (logAcquired)
    {
        ExReleaseRundownProtection(&g_NtApiRundown);
    }
    BkntkiHookExit();
    return status;
}

NTSTATUS NTAPI BkntkiNtQueryInformationThreadHook(_In_ HANDLE ThreadHandle, _In_ THREADINFOCLASS ThreadInformationClass,
                                                  _Out_writes_bytes_opt_(ThreadInformationLength)
                                                      PVOID ThreadInformation,
                                                  _In_ ULONG ThreadInformationLength, _Out_opt_ PULONG ReturnLength)
{
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE callerPid = NULL;
    UINT32 targetPid = 0;
    UINT32 targetTid = 0;
    ULONG observedReturnLength = 0;
    UINT32 execFlags = BkntkiBuildExecFlags(NULL, 0u);
    BOOLEAN logAcquired = FALSE;

    BkntkiHookEnter();
    if (g_OriginalNtQueryInformationThread == NULL)
    {
        BK_NTAPI_LOG(DPFLTR_ERROR_LEVEL, "BK: ntapi hook original null api=NtQueryInformationThread.\n");
        status = STATUS_INVALID_DEVICE_STATE;
        goto Exit;
    }
    (void)BkntkiResolveThreadHandleToIdentity(ThreadHandle, &targetPid, &targetTid);
    status = g_OriginalNtQueryInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation,
                                                ThreadInformationLength, ReturnLength);

    if (!BkntkiShouldLog(&callerPid))
    {
        goto Exit;
    }
    logAcquired = TRUE;
    observedReturnLength = BkntkiReadUlongSafe(ReturnLength);
    BkntkiLog("NtQueryInformationThread", callerPid, (UINT64)(ULONG_PTR)ThreadHandle, (UINT64)ThreadInformationClass,
              (UINT64)ThreadInformationLength, (UINT64)observedReturnLength, (UINT64)targetPid, (UINT64)targetTid, 0, 0,
              execFlags, status);

Exit:
    if (logAcquired)
    {
        ExReleaseRundownProtection(&g_NtApiRundown);
    }
    BkntkiHookExit();
    return status;
}

NTSTATUS NTAPI BkntkiNtSetInformationThreadHook(_In_ HANDLE ThreadHandle, _In_ THREADINFOCLASS ThreadInformationClass,
                                                _In_reads_bytes_opt_(ThreadInformationLength) PVOID ThreadInformation,
                                                _In_ ULONG ThreadInformationLength)
{
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE callerPid = NULL;
    UINT32 targetPid = 0;
    UINT32 targetTid = 0;
    UINT32 execFlags = BkntkiBuildExecFlags(NULL, 0u);
    BOOLEAN logAcquired = FALSE;

    BkntkiHookEnter();
    if (g_OriginalNtSetInformationThread == NULL)
    {
        BK_NTAPI_LOG(DPFLTR_ERROR_LEVEL, "BK: ntapi hook original null api=NtSetInformationThread.\n");
        status = STATUS_INVALID_DEVICE_STATE;
        goto Exit;
    }
    (void)BkntkiResolveThreadHandleToIdentity(ThreadHandle, &targetPid, &targetTid);
    status = g_OriginalNtSetInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation,
                                              ThreadInformationLength);

    if (!BkntkiShouldLog(&callerPid))
    {
        goto Exit;
    }
    logAcquired = TRUE;
    BkntkiLog("NtSetInformationThread", callerPid, (UINT64)(ULONG_PTR)ThreadHandle, (UINT64)ThreadInformationClass,
              (UINT64)(ULONG_PTR)ThreadInformation, (UINT64)ThreadInformationLength, (UINT64)targetPid,
              (UINT64)targetTid, 0, 0, execFlags, status);
    if (NT_SUCCESS(status) && targetPid != 0 && targetPid != (UINT32)(ULONG_PTR)callerPid)
    {
        BkntkiEmitRemoteNtApiDetection("REMOTE_THREAD_SET_INFORMATION", 5u, callerPid, targetPid,
                                       L"NtSetInformationThread", (UINT64)ThreadInformationClass);
    }

Exit:
    if (logAcquired)
    {
        ExReleaseRundownProtection(&g_NtApiRundown);
    }
    BkntkiHookExit();
    return status;
}

NTSTATUS NTAPI BkntkiNtSetInformationProcessHook(_In_ HANDLE ProcessHandle,
                                                 _In_ PROCESSINFOCLASS ProcessInformationClass,
                                                 _In_reads_bytes_opt_(ProcessInformationLength)
                                                     PVOID ProcessInformation,
                                                 _In_ ULONG ProcessInformationLength)
{
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE callerPid = NULL;
    UINT32 targetPid = 0;
    UINT32 execFlags = BkntkiBuildExecFlags(ProcessHandle, 0u);
    BOOLEAN logAcquired = FALSE;

    BkntkiHookEnter();
    if (g_OriginalNtSetInformationProcess == NULL)
    {
        BK_NTAPI_LOG(DPFLTR_ERROR_LEVEL, "BK: ntapi hook original null api=NtSetInformationProcess.\n");
        status = STATUS_INVALID_DEVICE_STATE;
        goto Exit;
    }
    (void)BkntkiResolveProcessHandleToPid(ProcessHandle, &targetPid);
    status = g_OriginalNtSetInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation,
                                               ProcessInformationLength);

    if (!BkntkiShouldLog(&callerPid))
    {
        goto Exit;
    }
    logAcquired = TRUE;
    BkntkiLog("NtSetInformationProcess", callerPid, (UINT64)(ULONG_PTR)ProcessHandle, (UINT64)ProcessInformationClass,
              (UINT64)(ULONG_PTR)ProcessInformation, (UINT64)ProcessInformationLength, (UINT64)targetPid, 0, 0, 0,
              execFlags, status);
    if (NT_SUCCESS(status) && targetPid != 0 && targetPid != (UINT32)(ULONG_PTR)callerPid)
    {
        BkntkiEmitRemoteNtApiDetection("REMOTE_PROCESS_SET_INFORMATION", 5u, callerPid, targetPid,
                                       L"NtSetInformationProcess", (UINT64)ProcessInformationClass);
    }

Exit:
    if (logAcquired)
    {
        ExReleaseRundownProtection(&g_NtApiRundown);
    }
    BkntkiHookExit();
    return status;
}

static NTSTATUS BkntkiThreadControlHookCommon(_In_z_ PCSTR ApiName, _In_ PBK_NT_RESUME_THREAD Original,
                                              _In_ HANDLE ThreadHandle, _Out_opt_ PULONG PreviousSuspendCount)
{
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE callerPid = NULL;
    UINT32 targetPid = 0;
    UINT32 targetTid = 0;
    ULONG previousCount = 0;
    UINT32 execFlags = BkntkiBuildExecFlags(NULL, 0u);
    BOOLEAN logAcquired = FALSE;

    BkntkiHookEnter();
    if (Original == NULL)
    {
        BK_NTAPI_LOG(DPFLTR_ERROR_LEVEL, "BK: ntapi hook original null api=%s.\n", ApiName);
        status = STATUS_INVALID_DEVICE_STATE;
        goto Exit;
    }
    (void)BkntkiResolveThreadHandleToIdentity(ThreadHandle, &targetPid, &targetTid);
    status = Original(ThreadHandle, PreviousSuspendCount);

    if (!BkntkiShouldLog(&callerPid))
    {
        goto Exit;
    }
    logAcquired = TRUE;
    previousCount = BkntkiReadUlongSafe(PreviousSuspendCount);
    BkntkiLog(ApiName, callerPid, (UINT64)(ULONG_PTR)ThreadHandle, (UINT64)previousCount, (UINT64)targetPid,
              (UINT64)targetTid, 0, 0, 0, 0, execFlags, status);
    if (NT_SUCCESS(status) && targetPid != 0 && targetPid != (UINT32)(ULONG_PTR)callerPid)
    {
        BkntkiEmitRemoteNtApiDetection("REMOTE_THREAD_EXECUTION_CONTROL", 5u, callerPid, targetPid, L"NtThreadControl",
                                       (UINT64)targetTid);
    }

Exit:
    if (logAcquired)
    {
        ExReleaseRundownProtection(&g_NtApiRundown);
    }
    BkntkiHookExit();
    return status;
}

NTSTATUS NTAPI BkntkiNtResumeThreadHook(_In_ HANDLE ThreadHandle, _Out_opt_ PULONG PreviousSuspendCount)
{
    return BkntkiThreadControlHookCommon("NtResumeThread", g_OriginalNtResumeThread, ThreadHandle,
                                         PreviousSuspendCount);
}

NTSTATUS NTAPI BkntkiNtSuspendThreadHook(_In_ HANDLE ThreadHandle, _Out_opt_ PULONG PreviousSuspendCount)
{
    return BkntkiThreadControlHookCommon("NtSuspendThread", g_OriginalNtSuspendThread, ThreadHandle,
                                         PreviousSuspendCount);
}

NTSTATUS NTAPI BkntkiNtAlertResumeThreadHook(_In_ HANDLE ThreadHandle, _Out_opt_ PULONG PreviousSuspendCount)
{
    return BkntkiThreadControlHookCommon("NtAlertResumeThread", g_OriginalNtAlertResumeThread, ThreadHandle,
                                         PreviousSuspendCount);
}

NTSTATUS NTAPI BkntkiNtAlertThreadHook(_In_ HANDLE ThreadHandle)
{
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE callerPid = NULL;
    UINT32 targetPid = 0;
    UINT32 targetTid = 0;
    UINT32 execFlags = BkntkiBuildExecFlags(NULL, 0u);
    BOOLEAN logAcquired = FALSE;

    BkntkiHookEnter();
    if (g_OriginalNtAlertThread == NULL)
    {
        BK_NTAPI_LOG(DPFLTR_ERROR_LEVEL, "BK: ntapi hook original null api=NtAlertThread.\n");
        status = STATUS_INVALID_DEVICE_STATE;
        goto Exit;
    }
    (void)BkntkiResolveThreadHandleToIdentity(ThreadHandle, &targetPid, &targetTid);
    status = g_OriginalNtAlertThread(ThreadHandle);

    if (!BkntkiShouldLog(&callerPid))
    {
        goto Exit;
    }
    logAcquired = TRUE;
    BkntkiLog("NtAlertThread", callerPid, (UINT64)(ULONG_PTR)ThreadHandle, (UINT64)targetPid, (UINT64)targetTid, 0, 0,
              0, 0, 0, execFlags, status);

Exit:
    if (logAcquired)
    {
        ExReleaseRundownProtection(&g_NtApiRundown);
    }
    BkntkiHookExit();
    return status;
}

NTSTATUS NTAPI BkntkiNtTestAlertHook(VOID)
{
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE callerPid = NULL;
    UINT32 execFlags = BkntkiBuildExecFlags(NULL, 0u);
    BOOLEAN logAcquired = FALSE;

    BkntkiHookEnter();
    if (g_OriginalNtTestAlert == NULL)
    {
        BK_NTAPI_LOG(DPFLTR_ERROR_LEVEL, "BK: ntapi hook original null api=NtTestAlert.\n");
        status = STATUS_INVALID_DEVICE_STATE;
        goto Exit;
    }
    status = g_OriginalNtTestAlert();

    if (!BkntkiShouldLog(&callerPid))
    {
        goto Exit;
    }
    logAcquired = TRUE;
    BkntkiLog("NtTestAlert", callerPid, 0, 0, 0, 0, 0, 0, 0, 0, execFlags, status);

Exit:
    if (logAcquired)
    {
        ExReleaseRundownProtection(&g_NtApiRundown);
    }
    BkntkiHookExit();
    return status;
}

NTSTATUS NTAPI BkntkiNtCreateUserProcessHook(
    _Out_ PHANDLE ProcessHandle, _Out_ PHANDLE ThreadHandle, _In_ ACCESS_MASK ProcessDesiredAccess,
    _In_ ACCESS_MASK ThreadDesiredAccess, _In_opt_ POBJECT_ATTRIBUTES ProcessObjectAttributes,
    _In_opt_ POBJECT_ATTRIBUTES ThreadObjectAttributes, _In_ ULONG ProcessFlags, _In_ ULONG ThreadFlags,
    _In_opt_ PVOID ProcessParameters, _Inout_ PVOID CreateInfo, _In_opt_ PVOID AttributeList)
{
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE callerPid = NULL;
    HANDLE observedProcess = NULL;
    HANDLE observedThread = NULL;
    UINT32 execFlags = BkntkiBuildExecFlags(NULL, 0u);
    BOOLEAN logAcquired = FALSE;

    BkntkiHookEnter();
    if (g_OriginalNtCreateUserProcess == NULL)
    {
        BK_NTAPI_LOG(DPFLTR_ERROR_LEVEL, "BK: ntapi hook original null api=NtCreateUserProcess.\n");
        status = STATUS_INVALID_DEVICE_STATE;
        goto Exit;
    }
    status = g_OriginalNtCreateUserProcess(ProcessHandle, ThreadHandle, ProcessDesiredAccess, ThreadDesiredAccess,
                                           ProcessObjectAttributes, ThreadObjectAttributes, ProcessFlags, ThreadFlags,
                                           ProcessParameters, CreateInfo, AttributeList);
    observedProcess = BkntkiReadHandleSafe(ProcessHandle);
    observedThread = BkntkiReadHandleSafe(ThreadHandle);

    if (!BkntkiShouldLog(&callerPid))
    {
        goto Exit;
    }
    logAcquired = TRUE;
    BkntkiLog("NtCreateUserProcess", callerPid, (UINT64)(ULONG_PTR)observedProcess, (UINT64)(ULONG_PTR)observedThread,
              (UINT64)ProcessFlags, (UINT64)ThreadFlags, (UINT64)ProcessDesiredAccess, (UINT64)ThreadDesiredAccess,
              (UINT64)(ULONG_PTR)AttributeList, 0, execFlags, status);

Exit:
    if (logAcquired)
    {
        ExReleaseRundownProtection(&g_NtApiRundown);
    }
    BkntkiHookExit();
    return status;
}

NTSTATUS NTAPI BkntkiNtCreateProcessExHook(_Out_ PHANDLE ProcessHandle, _In_ ACCESS_MASK DesiredAccess,
                                           _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes, _In_ HANDLE ParentProcess,
                                           _In_ ULONG Flags, _In_opt_ HANDLE SectionHandle, _In_opt_ HANDLE DebugPort,
                                           _In_opt_ HANDLE ExceptionPort, _In_ BOOLEAN InJob)
{
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE callerPid = NULL;
    HANDLE observedProcess = NULL;
    UINT32 parentPid = 0;
    UINT32 execFlags = BkntkiBuildExecFlags(ParentProcess, 0u);
    BOOLEAN logAcquired = FALSE;

    BkntkiHookEnter();
    if (g_OriginalNtCreateProcessEx == NULL)
    {
        BK_NTAPI_LOG(DPFLTR_ERROR_LEVEL, "BK: ntapi hook original null api=NtCreateProcessEx.\n");
        status = STATUS_INVALID_DEVICE_STATE;
        goto Exit;
    }
    (void)BkntkiResolveProcessHandleToPid(ParentProcess, &parentPid);
    status = g_OriginalNtCreateProcessEx(ProcessHandle, DesiredAccess, ObjectAttributes, ParentProcess, Flags,
                                         SectionHandle, DebugPort, ExceptionPort, InJob);
    observedProcess = BkntkiReadHandleSafe(ProcessHandle);

    if (!BkntkiShouldLog(&callerPid))
    {
        goto Exit;
    }
    logAcquired = TRUE;
    BkntkiLog("NtCreateProcessEx", callerPid, (UINT64)(ULONG_PTR)observedProcess, (UINT64)(ULONG_PTR)ParentProcess,
              (UINT64)parentPid, (UINT64)Flags, (UINT64)(ULONG_PTR)SectionHandle, (UINT64)(ULONG_PTR)DebugPort,
              (UINT64)(ULONG_PTR)ExceptionPort, (UINT64)InJob, execFlags, status);

Exit:
    if (logAcquired)
    {
        ExReleaseRundownProtection(&g_NtApiRundown);
    }
    BkntkiHookExit();
    return status;
}

NTSTATUS NTAPI BkntkiNtCreateFileHook(_Out_ PHANDLE FileHandle, _In_ ACCESS_MASK DesiredAccess,
                                      _In_ POBJECT_ATTRIBUTES ObjectAttributes, _Out_ PIO_STATUS_BLOCK IoStatusBlock,
                                      _In_opt_ PLARGE_INTEGER AllocationSize, _In_ ULONG FileAttributes,
                                      _In_ ULONG ShareAccess, _In_ ULONG CreateDisposition, _In_ ULONG CreateOptions,
                                      _In_reads_bytes_opt_(EaLength) PVOID EaBuffer, _In_ ULONG EaLength)
{
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE callerPid = NULL;
    HANDLE observedFile = NULL;
    BOOLEAN concealed = FALSE;
    UINT32 execFlags = BkntkiBuildExecFlags(NULL, 0u);
    BOOLEAN logAcquired = FALSE;

    BkntkiHookEnter();
    if (g_OriginalNtCreateFile == NULL)
    {
        BK_NTAPI_LOG(DPFLTR_ERROR_LEVEL, "BK: ntapi hook original null api=NtCreateFile.\n");
        status = STATUS_INVALID_DEVICE_STATE;
        goto Exit;
    }
    concealed =
        BkntkiShouldConcealCurrentFilesystemCaller() && BkntkiObjectAttributesNameShouldBeConcealed(ObjectAttributes);
    if (concealed)
    {
        status = STATUS_OBJECT_NAME_NOT_FOUND;
        BkntkiRecordSanitizerHit(BkDiagSanitizerFileBlackbird);
        BkntkiWriteIoStatusSafe(IoStatusBlock, status, 0);
    }
    else
    {
        status =
            g_OriginalNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize,
                                   FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
        observedFile = BkntkiReadHandleSafe(FileHandle);
    }

    if (!BkntkiShouldLog(&callerPid))
    {
        goto Exit;
    }
    logAcquired = TRUE;
    BkntkiLog("NtCreateFile", callerPid, (UINT64)(ULONG_PTR)observedFile, (UINT64)DesiredAccess,
              (UINT64)CreateDisposition, (UINT64)CreateOptions, (UINT64)ShareAccess, (UINT64)concealed,
              (UINT64)(ULONG_PTR)ObjectAttributes, 0, execFlags, status);

Exit:
    if (logAcquired)
    {
        ExReleaseRundownProtection(&g_NtApiRundown);
    }
    BkntkiHookExit();
    return status;
}

NTSTATUS NTAPI BkntkiNtOpenFileHook(_Out_ PHANDLE FileHandle, _In_ ACCESS_MASK DesiredAccess,
                                    _In_ POBJECT_ATTRIBUTES ObjectAttributes, _Out_ PIO_STATUS_BLOCK IoStatusBlock,
                                    _In_ ULONG ShareAccess, _In_ ULONG OpenOptions)
{
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE callerPid = NULL;
    HANDLE observedFile = NULL;
    BOOLEAN concealed = FALSE;
    UINT32 execFlags = BkntkiBuildExecFlags(NULL, 0u);
    BOOLEAN logAcquired = FALSE;

    BkntkiHookEnter();
    if (g_OriginalNtOpenFile == NULL)
    {
        BK_NTAPI_LOG(DPFLTR_ERROR_LEVEL, "BK: ntapi hook original null api=NtOpenFile.\n");
        status = STATUS_INVALID_DEVICE_STATE;
        goto Exit;
    }
    concealed =
        BkntkiShouldConcealCurrentFilesystemCaller() && BkntkiObjectAttributesNameShouldBeConcealed(ObjectAttributes);
    if (concealed)
    {
        status = STATUS_OBJECT_NAME_NOT_FOUND;
        BkntkiRecordSanitizerHit(BkDiagSanitizerFileBlackbird);
        BkntkiWriteIoStatusSafe(IoStatusBlock, status, 0);
    }
    else
    {
        status =
            g_OriginalNtOpenFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, OpenOptions);
        observedFile = BkntkiReadHandleSafe(FileHandle);
    }

    if (!BkntkiShouldLog(&callerPid))
    {
        goto Exit;
    }
    logAcquired = TRUE;
    BkntkiLog("NtOpenFile", callerPid, (UINT64)(ULONG_PTR)observedFile, (UINT64)DesiredAccess, (UINT64)OpenOptions,
              (UINT64)ShareAccess, (UINT64)concealed, (UINT64)(ULONG_PTR)ObjectAttributes, 0, 0, execFlags, status);

Exit:
    if (logAcquired)
    {
        ExReleaseRundownProtection(&g_NtApiRundown);
    }
    BkntkiHookExit();
    return status;
}

NTSTATUS NTAPI BkntkiNtDeviceIoControlFileHook(_In_ HANDLE FileHandle, _In_opt_ HANDLE Event,
                                               _In_opt_ PIO_APC_ROUTINE ApcRoutine, _In_opt_ PVOID ApcContext,
                                               _Out_ PIO_STATUS_BLOCK IoStatusBlock, _In_ ULONG IoControlCode,
                                               _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
                                               _In_ ULONG InputBufferLength,
                                               _Out_writes_bytes_opt_(OutputBufferLength) PVOID OutputBuffer,
                                               _In_ ULONG OutputBufferLength)
{
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE callerPid = NULL;
    BOOLEAN concealed = FALSE;
    UINT32 execFlags = BkntkiBuildExecFlags(NULL, 0u);
    BOOLEAN logAcquired = FALSE;

    BkntkiHookEnter();
    if (g_OriginalNtDeviceIoControlFile == NULL)
    {
        BK_NTAPI_LOG(DPFLTR_ERROR_LEVEL, "BK: ntapi hook original null api=NtDeviceIoControlFile.\n");
        status = STATUS_INVALID_DEVICE_STATE;
        goto Exit;
    }
    concealed = BkntkiShouldConcealCurrentFilesystemCaller() && BkntkiHandleValueIsProtectedIpc(FileHandle);
    if (concealed)
    {
        status = STATUS_INVALID_DEVICE_REQUEST;
        BkntkiRecordSanitizerHit(BkDiagSanitizerIpcHandle);
        BkntkiWriteIoStatusSafe(IoStatusBlock, status, 0);
    }
    else
    {
        status =
            g_OriginalNtDeviceIoControlFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, IoControlCode,
                                            InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength);
    }

    if (!BkntkiShouldLog(&callerPid))
    {
        goto Exit;
    }
    logAcquired = TRUE;
    BkntkiLog("NtDeviceIoControlFile", callerPid, (UINT64)(ULONG_PTR)FileHandle, (UINT64)IoControlCode,
              (UINT64)InputBufferLength, (UINT64)OutputBufferLength, (UINT64)concealed,
              (UINT64)BkntkiReadIoStatusInformationSafe(IoStatusBlock), 0, 0, execFlags, status);

Exit:
    if (logAcquired)
    {
        ExReleaseRundownProtection(&g_NtApiRundown);
    }
    BkntkiHookExit();
    return status;
}

NTSTATUS NTAPI BkntkiNtFsControlFileHook(_In_ HANDLE FileHandle, _In_opt_ HANDLE Event,
                                         _In_opt_ PIO_APC_ROUTINE ApcRoutine, _In_opt_ PVOID ApcContext,
                                         _Out_ PIO_STATUS_BLOCK IoStatusBlock, _In_ ULONG FsControlCode,
                                         _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
                                         _In_ ULONG InputBufferLength,
                                         _Out_writes_bytes_opt_(OutputBufferLength) PVOID OutputBuffer,
                                         _In_ ULONG OutputBufferLength)
{
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE callerPid = NULL;
    UINT32 execFlags = BkntkiBuildExecFlags(NULL, 0u);
    BOOLEAN logAcquired = FALSE;

    BkntkiHookEnter();
    if (g_OriginalNtFsControlFile == NULL)
    {
        BK_NTAPI_LOG(DPFLTR_ERROR_LEVEL, "BK: ntapi hook original null api=NtFsControlFile.\n");
        status = STATUS_INVALID_DEVICE_STATE;
        goto Exit;
    }
    status = g_OriginalNtFsControlFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FsControlCode,
                                       InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength);

    if (!BkntkiShouldLog(&callerPid))
    {
        goto Exit;
    }
    logAcquired = TRUE;
    BkntkiLog("NtFsControlFile", callerPid, (UINT64)(ULONG_PTR)FileHandle, (UINT64)FsControlCode,
              (UINT64)InputBufferLength, (UINT64)OutputBufferLength,
              (UINT64)BkntkiReadIoStatusInformationSafe(IoStatusBlock), 0, 0, 0, execFlags, status);

Exit:
    if (logAcquired)
    {
        ExReleaseRundownProtection(&g_NtApiRundown);
    }
    BkntkiHookExit();
    return status;
}

NTSTATUS NTAPI BkntkiNtQueryDirectoryFileHook(_In_ HANDLE FileHandle, _In_opt_ HANDLE Event,
                                              _In_opt_ PIO_APC_ROUTINE ApcRoutine, _In_opt_ PVOID ApcContext,
                                              _Out_ PIO_STATUS_BLOCK IoStatusBlock,
                                              _Out_writes_bytes_(Length) PVOID FileInformation, _In_ ULONG Length,
                                              _In_ FILE_INFORMATION_CLASS FileInformationClass,
                                              _In_ BOOLEAN ReturnSingleEntry, _In_opt_ PUNICODE_STRING FileName,
                                              _In_ BOOLEAN RestartScan)
{
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE callerPid = NULL;
    UINT32 execFlags = BkntkiBuildExecFlags(NULL, 0u);
    BOOLEAN logAcquired = FALSE;

    BkntkiHookEnter();
    if (g_OriginalNtQueryDirectoryFile == NULL)
    {
        BK_NTAPI_LOG(DPFLTR_ERROR_LEVEL, "BK: ntapi hook original null api=NtQueryDirectoryFile.\n");
        status = STATUS_INVALID_DEVICE_STATE;
        goto Exit;
    }
    status = g_OriginalNtQueryDirectoryFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FileInformation,
                                            Length, FileInformationClass, ReturnSingleEntry, FileName, RestartScan);
    status = BkntkiScrubDirectoryInformation(FileInformation, Length, FileInformationClass, status);
    if (status == STATUS_NO_MORE_FILES)
    {
        BkntkiWriteIoStatusSafe(IoStatusBlock, status, 0);
    }

    if (!BkntkiShouldLog(&callerPid))
    {
        goto Exit;
    }
    logAcquired = TRUE;
    BkntkiLog("NtQueryDirectoryFile", callerPid, (UINT64)(ULONG_PTR)FileHandle, (UINT64)FileInformationClass,
              (UINT64)Length, (UINT64)ReturnSingleEntry, (UINT64)RestartScan,
              (UINT64)BkntkiReadIoStatusInformationSafe(IoStatusBlock), 0, 0, execFlags, status);

Exit:
    if (logAcquired)
    {
        ExReleaseRundownProtection(&g_NtApiRundown);
    }
    BkntkiHookExit();
    return status;
}

NTSTATUS NTAPI BkntkiNtQueryDirectoryFileExHook(_In_ HANDLE FileHandle, _In_opt_ HANDLE Event,
                                                _In_opt_ PIO_APC_ROUTINE ApcRoutine, _In_opt_ PVOID ApcContext,
                                                _Out_ PIO_STATUS_BLOCK IoStatusBlock,
                                                _Out_writes_bytes_(Length) PVOID FileInformation, _In_ ULONG Length,
                                                _In_ FILE_INFORMATION_CLASS FileInformationClass, _In_ ULONG QueryFlags,
                                                _In_opt_ PUNICODE_STRING FileName)
{
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE callerPid = NULL;
    UINT32 execFlags = BkntkiBuildExecFlags(NULL, 0u);
    BOOLEAN logAcquired = FALSE;

    BkntkiHookEnter();
    if (g_OriginalNtQueryDirectoryFileEx == NULL)
    {
        BK_NTAPI_LOG(DPFLTR_ERROR_LEVEL, "BK: ntapi hook original null api=NtQueryDirectoryFileEx.\n");
        status = STATUS_INVALID_DEVICE_STATE;
        goto Exit;
    }
    status = g_OriginalNtQueryDirectoryFileEx(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FileInformation,
                                              Length, FileInformationClass, QueryFlags, FileName);
    status = BkntkiScrubDirectoryInformation(FileInformation, Length, FileInformationClass, status);
    if (status == STATUS_NO_MORE_FILES)
    {
        BkntkiWriteIoStatusSafe(IoStatusBlock, status, 0);
    }

    if (!BkntkiShouldLog(&callerPid))
    {
        goto Exit;
    }
    logAcquired = TRUE;
    BkntkiLog("NtQueryDirectoryFileEx", callerPid, (UINT64)(ULONG_PTR)FileHandle, (UINT64)FileInformationClass,
              (UINT64)Length, (UINT64)QueryFlags, (UINT64)BkntkiReadIoStatusInformationSafe(IoStatusBlock), 0, 0, 0,
              execFlags, status);

Exit:
    if (logAcquired)
    {
        ExReleaseRundownProtection(&g_NtApiRundown);
    }
    BkntkiHookExit();
    return status;
}

NTSTATUS NTAPI BkntkiNtAlpcConnectPortHook(_Out_ PHANDLE PortHandle, _In_ PUNICODE_STRING PortName,
                                           _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes, _In_opt_ PVOID PortAttributes,
                                           _In_ ULONG Flags, _In_opt_ PSID RequiredServerSid,
                                           _Inout_updates_bytes_to_opt_(*BufferLength, *BufferLength)
                                               PVOID ConnectionMessage,
                                           _Inout_opt_ PULONG BufferLength, _Inout_opt_ PVOID OutMessageAttributes,
                                           _Inout_opt_ PVOID InMessageAttributes, _In_opt_ PLARGE_INTEGER Timeout)
{
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE callerPid = NULL;
    HANDLE observedPort = NULL;
    BOOLEAN concealed = FALSE;
    UINT32 execFlags = BkntkiBuildExecFlags(NULL, 0u);
    BOOLEAN logAcquired = FALSE;

    BkntkiHookEnter();
    if (g_OriginalNtAlpcConnectPort == NULL)
    {
        BK_NTAPI_LOG(DPFLTR_ERROR_LEVEL, "BK: ntapi hook original null api=NtAlpcConnectPort.\n");
        status = STATUS_INVALID_DEVICE_STATE;
        goto Exit;
    }
    concealed = BkntkiShouldConcealCurrentFilesystemCaller() && BkntkiUnicodeContainsBlackbirdArtifact(PortName);
    if (concealed)
    {
        status = STATUS_OBJECT_NAME_NOT_FOUND;
        BkntkiRecordSanitizerHit(BkDiagSanitizerPortBlackbird);
    }
    else
    {
        status = g_OriginalNtAlpcConnectPort(PortHandle, PortName, ObjectAttributes, PortAttributes, Flags,
                                             RequiredServerSid, ConnectionMessage, BufferLength, OutMessageAttributes,
                                             InMessageAttributes, Timeout);
        observedPort = BkntkiReadHandleSafe(PortHandle);
    }

    if (!BkntkiShouldLog(&callerPid))
    {
        goto Exit;
    }
    logAcquired = TRUE;
    BkntkiLog("NtAlpcConnectPort", callerPid, (UINT64)(ULONG_PTR)observedPort, (UINT64)Flags, (UINT64)concealed,
              (UINT64)(ULONG_PTR)PortName, (UINT64)(ULONG_PTR)BufferLength, 0, 0, 0, execFlags, status);

Exit:
    if (logAcquired)
    {
        ExReleaseRundownProtection(&g_NtApiRundown);
    }
    BkntkiHookExit();
    return status;
}

NTSTATUS NTAPI BkntkiNtAlpcSendWaitReceivePortHook(
    _In_ HANDLE PortHandle, _In_ ULONG Flags, _In_reads_bytes_opt_(0) PVOID SendMessage,
    _Inout_opt_ PVOID SendMessageAttributes, _Out_writes_bytes_opt_(0) PVOID ReceiveMessage,
    _Inout_opt_ PULONG BufferLength, _Inout_opt_ PVOID ReceiveMessageAttributes, _In_opt_ PLARGE_INTEGER Timeout)
{
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE callerPid = NULL;
    BOOLEAN concealed = FALSE;
    UINT32 execFlags = BkntkiBuildExecFlags(NULL, 0u);
    BOOLEAN logAcquired = FALSE;

    BkntkiHookEnter();
    if (g_OriginalNtAlpcSendWaitReceivePort == NULL)
    {
        BK_NTAPI_LOG(DPFLTR_ERROR_LEVEL, "BK: ntapi hook original null api=NtAlpcSendWaitReceivePort.\n");
        status = STATUS_INVALID_DEVICE_STATE;
        goto Exit;
    }
    concealed = BkntkiShouldConcealCurrentFilesystemCaller() && BkntkiHandleValueIsProtectedIpc(PortHandle);
    if (concealed)
    {
        status = STATUS_PORT_DISCONNECTED;
        BkntkiRecordSanitizerHit(BkDiagSanitizerIpcHandle);
    }
    else
    {
        status = g_OriginalNtAlpcSendWaitReceivePort(PortHandle, Flags, SendMessage, SendMessageAttributes,
                                                     ReceiveMessage, BufferLength, ReceiveMessageAttributes, Timeout);
    }

    if (!BkntkiShouldLog(&callerPid))
    {
        goto Exit;
    }
    logAcquired = TRUE;
    BkntkiLog("NtAlpcSendWaitReceivePort", callerPid, (UINT64)(ULONG_PTR)PortHandle, (UINT64)Flags, (UINT64)concealed,
              (UINT64)(ULONG_PTR)BufferLength, 0, 0, 0, 0, execFlags, status);

Exit:
    if (logAcquired)
    {
        ExReleaseRundownProtection(&g_NtApiRundown);
    }
    BkntkiHookExit();
    return status;
}

NTSTATUS NTAPI BkntkiNtConnectPortHook(_Out_ PHANDLE PortHandle, _In_ PUNICODE_STRING PortName,
                                       _In_ PSECURITY_QUALITY_OF_SERVICE SecurityQos, _Inout_opt_ PVOID ClientView,
                                       _Out_opt_ PVOID ServerView, _Out_opt_ PULONG MaxMessageLength,
                                       _Inout_updates_bytes_to_opt_(*ConnectionInformationLength,
                                                                    *ConnectionInformationLength)
                                           PVOID ConnectionInformation,
                                       _Inout_opt_ PULONG ConnectionInformationLength)
{
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE callerPid = NULL;
    HANDLE observedPort = NULL;
    BOOLEAN concealed = FALSE;
    UINT32 execFlags = BkntkiBuildExecFlags(NULL, 0u);
    BOOLEAN logAcquired = FALSE;

    BkntkiHookEnter();
    if (g_OriginalNtConnectPort == NULL)
    {
        BK_NTAPI_LOG(DPFLTR_ERROR_LEVEL, "BK: ntapi hook original null api=NtConnectPort.\n");
        status = STATUS_INVALID_DEVICE_STATE;
        goto Exit;
    }
    concealed = BkntkiShouldConcealCurrentFilesystemCaller() && BkntkiUnicodeContainsBlackbirdArtifact(PortName);
    if (concealed)
    {
        status = STATUS_OBJECT_NAME_NOT_FOUND;
        BkntkiRecordSanitizerHit(BkDiagSanitizerPortBlackbird);
    }
    else
    {
        status = g_OriginalNtConnectPort(PortHandle, PortName, SecurityQos, ClientView, ServerView, MaxMessageLength,
                                         ConnectionInformation, ConnectionInformationLength);
        observedPort = BkntkiReadHandleSafe(PortHandle);
    }

    if (!BkntkiShouldLog(&callerPid))
    {
        goto Exit;
    }
    logAcquired = TRUE;
    BkntkiLog("NtConnectPort", callerPid, (UINT64)(ULONG_PTR)observedPort, (UINT64)concealed,
              (UINT64)(ULONG_PTR)PortName, (UINT64)(ULONG_PTR)MaxMessageLength,
              (UINT64)(ULONG_PTR)ConnectionInformationLength, 0, 0, 0, execFlags, status);

Exit:
    if (logAcquired)
    {
        ExReleaseRundownProtection(&g_NtApiRundown);
    }
    BkntkiHookExit();
    return status;
}

NTSTATUS NTAPI BkntkiNtOpenProcessHook(_Out_ PHANDLE ProcessHandle, _In_ ACCESS_MASK DesiredAccess,
                                       _In_ POBJECT_ATTRIBUTES ObjectAttributes, _In_opt_ PCLIENT_ID ClientId)
{
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE callerPid = NULL;
    HANDLE observedProcess = NULL;
    UINT64 requestedPid = 0;
    UINT32 execFlags = BkntkiBuildExecFlags(NULL, 0u);
    BOOLEAN logAcquired = FALSE;

    UNREFERENCED_PARAMETER(ObjectAttributes);

    BkntkiHookEnter();
    if (g_OriginalNtOpenProcess == NULL)
    {
        BK_NTAPI_LOG(DPFLTR_ERROR_LEVEL, "BK: ntapi hook original null api=NtOpenProcess.\n");
        status = STATUS_INVALID_DEVICE_STATE;
        goto Exit;
    }
    __try
    {
        if (ClientId != NULL)
        {
            requestedPid = (UINT64)(ULONG_PTR)ClientId->UniqueProcess;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        requestedPid = 0;
    }
    status = g_OriginalNtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
    observedProcess = BkntkiReadHandleSafe(ProcessHandle);

    if (!BkntkiShouldLog(&callerPid))
    {
        goto Exit;
    }
    logAcquired = TRUE;
    BkntkiLog("NtOpenProcess", callerPid, (UINT64)(ULONG_PTR)observedProcess, (UINT64)DesiredAccess, requestedPid, 0, 0,
              0, 0, 0, execFlags, status);

Exit:
    if (logAcquired)
    {
        ExReleaseRundownProtection(&g_NtApiRundown);
    }
    BkntkiHookExit();
    return status;
}

NTSTATUS NTAPI BkntkiNtOpenThreadHook(_Out_ PHANDLE ThreadHandle, _In_ ACCESS_MASK DesiredAccess,
                                      _In_ POBJECT_ATTRIBUTES ObjectAttributes, _In_opt_ PCLIENT_ID ClientId)
{
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE callerPid = NULL;
    HANDLE observedThread = NULL;
    UINT64 requestedPid = 0;
    UINT64 requestedTid = 0;
    UINT32 execFlags = BkntkiBuildExecFlags(NULL, 0u);
    BOOLEAN logAcquired = FALSE;

    UNREFERENCED_PARAMETER(ObjectAttributes);

    BkntkiHookEnter();
    if (g_OriginalNtOpenThread == NULL)
    {
        BK_NTAPI_LOG(DPFLTR_ERROR_LEVEL, "BK: ntapi hook original null api=NtOpenThread.\n");
        status = STATUS_INVALID_DEVICE_STATE;
        goto Exit;
    }
    __try
    {
        if (ClientId != NULL)
        {
            requestedPid = (UINT64)(ULONG_PTR)ClientId->UniqueProcess;
            requestedTid = (UINT64)(ULONG_PTR)ClientId->UniqueThread;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        requestedPid = 0;
        requestedTid = 0;
    }
    status = g_OriginalNtOpenThread(ThreadHandle, DesiredAccess, ObjectAttributes, ClientId);
    observedThread = BkntkiReadHandleSafe(ThreadHandle);

    if (!BkntkiShouldLog(&callerPid))
    {
        goto Exit;
    }
    logAcquired = TRUE;
    BkntkiLog("NtOpenThread", callerPid, (UINT64)(ULONG_PTR)observedThread, (UINT64)DesiredAccess, requestedPid,
              requestedTid, 0, 0, 0, 0, execFlags, status);

Exit:
    if (logAcquired)
    {
        ExReleaseRundownProtection(&g_NtApiRundown);
    }
    BkntkiHookExit();
    return status;
}

NTSTATUS NTAPI BkntkiNtDuplicateObjectHook(_In_ HANDLE SourceProcessHandle, _In_ HANDLE SourceHandle,
                                           _In_opt_ HANDLE TargetProcessHandle, _Out_opt_ PHANDLE TargetHandle,
                                           _In_ ACCESS_MASK DesiredAccess, _In_ ULONG HandleAttributes,
                                           _In_ ULONG Options)
{
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE callerPid = NULL;
    HANDLE observedHandle = NULL;
    UINT32 sourcePid = 0;
    UINT32 targetPid = 0;
    UINT32 execFlags = BkntkiBuildExecFlags(TargetProcessHandle, 0u);
    BOOLEAN logAcquired = FALSE;

    BkntkiHookEnter();
    if (g_OriginalNtDuplicateObject == NULL)
    {
        BK_NTAPI_LOG(DPFLTR_ERROR_LEVEL, "BK: ntapi hook original null api=NtDuplicateObject.\n");
        status = STATUS_INVALID_DEVICE_STATE;
        goto Exit;
    }
    (void)BkntkiResolveProcessHandleToPid(SourceProcessHandle, &sourcePid);
    (void)BkntkiResolveProcessHandleToPid(TargetProcessHandle, &targetPid);
    status = g_OriginalNtDuplicateObject(SourceProcessHandle, SourceHandle, TargetProcessHandle, TargetHandle,
                                         DesiredAccess, HandleAttributes, Options);
    observedHandle = BkntkiReadHandleSafe(TargetHandle);

    if (!BkntkiShouldLog(&callerPid))
    {
        goto Exit;
    }
    logAcquired = TRUE;
    BkntkiLog("NtDuplicateObject", callerPid, (UINT64)(ULONG_PTR)SourceProcessHandle, (UINT64)(ULONG_PTR)SourceHandle,
              (UINT64)(ULONG_PTR)TargetProcessHandle, (UINT64)(ULONG_PTR)observedHandle, (UINT64)DesiredAccess,
              (UINT64)Options, (UINT64)sourcePid, (UINT64)targetPid, execFlags, status);

Exit:
    if (logAcquired)
    {
        ExReleaseRundownProtection(&g_NtApiRundown);
    }
    BkntkiHookExit();
    return status;
}

NTSTATUS NTAPI BkntkiNtQueryKeyHook(_In_ HANDLE KeyHandle, _In_ KEY_INFORMATION_CLASS KeyInformationClass,
                                    _Out_writes_bytes_opt_(Length) PVOID KeyInformation, _In_ ULONG Length,
                                    _Out_ PULONG ResultLength)
{
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE callerPid = NULL;
    UINT32 execFlags = BkntkiBuildExecFlags(NULL, 0u);
    BOOLEAN logAcquired = FALSE;

    BkntkiHookEnter();
    if (g_OriginalNtQueryKey == NULL)
    {
        BK_NTAPI_LOG(DPFLTR_ERROR_LEVEL, "BK: ntapi hook original null api=NtQueryKey.\n");
        status = STATUS_INVALID_DEVICE_STATE;
        goto Exit;
    }
    status = g_OriginalNtQueryKey(KeyHandle, KeyInformationClass, KeyInformation, Length, ResultLength);
    if (!BkntkiShouldLog(&callerPid))
    {
        goto Exit;
    }
    logAcquired = TRUE;
    BkntkiLog("NtQueryKey", callerPid, (UINT64)(ULONG_PTR)KeyHandle, (UINT64)KeyInformationClass, (UINT64)Length,
              (UINT64)BkntkiReadUlongSafe(ResultLength), 0, 0, 0, 0, execFlags, status);
Exit:
    if (logAcquired)
    {
        ExReleaseRundownProtection(&g_NtApiRundown);
    }
    BkntkiHookExit();
    return status;
}

NTSTATUS NTAPI BkntkiNtEnumerateKeyHook(_In_ HANDLE KeyHandle, _In_ ULONG Index,
                                        _In_ KEY_INFORMATION_CLASS KeyInformationClass,
                                        _Out_writes_bytes_opt_(Length) PVOID KeyInformation, _In_ ULONG Length,
                                        _Out_ PULONG ResultLength)
{
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE callerPid = NULL;
    UINT32 execFlags = BkntkiBuildExecFlags(NULL, 0u);
    BOOLEAN logAcquired = FALSE;

    BkntkiHookEnter();
    if (g_OriginalNtEnumerateKey == NULL)
    {
        BK_NTAPI_LOG(DPFLTR_ERROR_LEVEL, "BK: ntapi hook original null api=NtEnumerateKey.\n");
        status = STATUS_INVALID_DEVICE_STATE;
        goto Exit;
    }
    status = g_OriginalNtEnumerateKey(KeyHandle, Index, KeyInformationClass, KeyInformation, Length, ResultLength);
    if (!BkntkiShouldLog(&callerPid))
    {
        goto Exit;
    }
    logAcquired = TRUE;
    BkntkiLog("NtEnumerateKey", callerPid, (UINT64)(ULONG_PTR)KeyHandle, (UINT64)Index, (UINT64)KeyInformationClass,
              (UINT64)Length, (UINT64)BkntkiReadUlongSafe(ResultLength), 0, 0, 0, execFlags, status);
Exit:
    if (logAcquired)
    {
        ExReleaseRundownProtection(&g_NtApiRundown);
    }
    BkntkiHookExit();
    return status;
}

NTSTATUS NTAPI BkntkiNtQueryValueKeyHook(_In_ HANDLE KeyHandle, _In_ PUNICODE_STRING ValueName,
                                         _In_ KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
                                         _Out_writes_bytes_opt_(Length) PVOID KeyValueInformation, _In_ ULONG Length,
                                         _Out_ PULONG ResultLength)
{
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE callerPid = NULL;
    UINT32 execFlags = BkntkiBuildExecFlags(NULL, 0u);
    BOOLEAN logAcquired = FALSE;

    BkntkiHookEnter();
    if (g_OriginalNtQueryValueKey == NULL)
    {
        BK_NTAPI_LOG(DPFLTR_ERROR_LEVEL, "BK: ntapi hook original null api=NtQueryValueKey.\n");
        status = STATUS_INVALID_DEVICE_STATE;
        goto Exit;
    }
    status = g_OriginalNtQueryValueKey(KeyHandle, ValueName, KeyValueInformationClass, KeyValueInformation, Length,
                                       ResultLength);
    if (!BkntkiShouldLog(&callerPid))
    {
        goto Exit;
    }
    logAcquired = TRUE;
    BkntkiLog("NtQueryValueKey", callerPid, (UINT64)(ULONG_PTR)KeyHandle, (UINT64)KeyValueInformationClass,
              (UINT64)Length, (UINT64)BkntkiReadUlongSafe(ResultLength), (UINT64)(ULONG_PTR)ValueName, 0, 0, 0,
              execFlags, status);
Exit:
    if (logAcquired)
    {
        ExReleaseRundownProtection(&g_NtApiRundown);
    }
    BkntkiHookExit();
    return status;
}

NTSTATUS NTAPI BkntkiNtEnumerateValueKeyHook(_In_ HANDLE KeyHandle, _In_ ULONG Index,
                                             _In_ KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
                                             _Out_writes_bytes_opt_(Length) PVOID KeyValueInformation,
                                             _In_ ULONG Length, _Out_ PULONG ResultLength)
{
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE callerPid = NULL;
    UINT32 execFlags = BkntkiBuildExecFlags(NULL, 0u);
    BOOLEAN logAcquired = FALSE;

    BkntkiHookEnter();
    if (g_OriginalNtEnumerateValueKey == NULL)
    {
        BK_NTAPI_LOG(DPFLTR_ERROR_LEVEL, "BK: ntapi hook original null api=NtEnumerateValueKey.\n");
        status = STATUS_INVALID_DEVICE_STATE;
        goto Exit;
    }
    status = g_OriginalNtEnumerateValueKey(KeyHandle, Index, KeyValueInformationClass, KeyValueInformation, Length,
                                           ResultLength);
    if (!BkntkiShouldLog(&callerPid))
    {
        goto Exit;
    }
    logAcquired = TRUE;
    BkntkiLog("NtEnumerateValueKey", callerPid, (UINT64)(ULONG_PTR)KeyHandle, (UINT64)Index,
              (UINT64)KeyValueInformationClass, (UINT64)Length, (UINT64)BkntkiReadUlongSafe(ResultLength), 0, 0, 0,
              execFlags, status);
Exit:
    if (logAcquired)
    {
        ExReleaseRundownProtection(&g_NtApiRundown);
    }
    BkntkiHookExit();
    return status;
}
#endif /* _AMD64_ */
