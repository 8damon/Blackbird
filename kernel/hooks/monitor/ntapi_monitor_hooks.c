#include "ntapi_monitor_private.h"

#if defined(_AMD64_)

NTSTATUS NTAPI BLACKBIRDNtQuerySystemInformationHook(_In_ ULONG SystemInformationClass,
                                                     _Out_writes_bytes_opt_(SystemInformationLength)
                                                             PVOID SystemInformation,
                                                     _In_ ULONG SystemInformationLength,
                                                     _Out_opt_ PULONG ReturnLength)
{
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE callerPid = NULL;
    ULONG observedReturnLength;
    BOOLEAN logAcquired = FALSE;

    BLACKBIRDNtApiHookEnter();

    if (g_OriginalNtQuerySystemInformation == NULL)
    {
        BLACKBIRD_NTAPI_LOG(DPFLTR_ERROR_LEVEL, "BLACKBIRD: ntapi hook original null api=NtQuerySystemInformation.\n");
        status = STATUS_INVALID_DEVICE_STATE;
        goto Exit;
    }
    status = g_OriginalNtQuerySystemInformation(
            SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
    BLACKBIRDNtApiSanitizeKernelDebuggerInformation(
            SystemInformationClass, SystemInformation, SystemInformationLength, status);

    if (!BLACKBIRDNtApiShouldLog(&callerPid))
    {
        goto Exit;
    }
    logAcquired = TRUE;

    observedReturnLength = BLACKBIRDNtApiReadUlongSafe(ReturnLength);
    BLACKBIRDEtwLogSystemInfoEvent(callerPid,
                                   PsGetCurrentThreadId(),
                                   SystemInformationClass,
                                   SystemInformationLength,
                                   observedReturnLength,
                                   status);
    BLACKBIRDNtApiLog("NtQuerySystemInformation",
                      callerPid,
                      (UINT64) SystemInformationClass,
                      (UINT64) SystemInformationLength,
                      (UINT64) observedReturnLength,
                      0,
                      0,
                      0,
                      0,
                      0,
                      status);

Exit:
    if (logAcquired)
    {
        ExReleaseRundownProtection(&g_NtApiRundown);
    }
    BLACKBIRDNtApiHookExit();
    return status;
}

NTSTATUS NTAPI BLACKBIRDNtQueryInformationProcessHook(_In_ HANDLE ProcessHandle,
                                                      _In_ ULONG ProcessInformationClass,
                                                      _Out_writes_bytes_opt_(ProcessInformationLength)
                                                              PVOID ProcessInformation,
                                                      _In_ ULONG ProcessInformationLength,
                                                      _Out_opt_ PULONG ReturnLength)
{
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE callerPid = NULL;
    ULONG observedReturnLength;
    BOOLEAN logAcquired = FALSE;

    BLACKBIRDNtApiHookEnter();

    if (g_OriginalNtQueryInformationProcess == NULL)
    {
        BLACKBIRD_NTAPI_LOG(DPFLTR_ERROR_LEVEL, "BLACKBIRD: ntapi hook original null api=NtQueryInformationProcess.\n");
        status = STATUS_INVALID_DEVICE_STATE;
        goto Exit;
    }
    status = g_OriginalNtQueryInformationProcess(
            ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);

    if (!BLACKBIRDNtApiShouldLog(&callerPid))
    {
        goto Exit;
    }
    logAcquired = TRUE;

    observedReturnLength = BLACKBIRDNtApiReadUlongSafe(ReturnLength);
    BLACKBIRDNtApiLog("NtQueryInformationProcess",
                      callerPid,
                      (UINT64) (ULONG_PTR) ProcessHandle,
                      (UINT64) ProcessInformationClass,
                      (UINT64) (ULONG_PTR) ProcessInformation,
                      (UINT64) ProcessInformationLength,
                      (UINT64) observedReturnLength,
                      0,
                      0,
                      0,
                      status);

Exit:
    if (logAcquired)
    {
        ExReleaseRundownProtection(&g_NtApiRundown);
    }
    BLACKBIRDNtApiHookExit();
    return status;
}

NTSTATUS NTAPI BLACKBIRDNtWriteVirtualMemoryHook(_In_ HANDLE ProcessHandle,
                                                 _In_ PVOID BaseAddress,
                                                 _In_reads_bytes_(BufferSize) PVOID Buffer,
                                                 _In_ SIZE_T BufferSize,
                                                 _Out_opt_ PSIZE_T NumberOfBytesWritten)
{
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE callerPid = NULL;
    SIZE_T observedWritten;
    BOOLEAN logAcquired = FALSE;

    BLACKBIRDNtApiHookEnter();

    if (g_OriginalNtWriteVirtualMemory == NULL)
    {
        BLACKBIRD_NTAPI_LOG(DPFLTR_ERROR_LEVEL, "BLACKBIRD: ntapi hook original null api=NtWriteVirtualMemory.\n");
        status = STATUS_INVALID_DEVICE_STATE;
        goto Exit;
    }
    status = g_OriginalNtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesWritten);

    if (!BLACKBIRDNtApiShouldLog(&callerPid))
    {
        goto Exit;
    }
    logAcquired = TRUE;

    observedWritten = BLACKBIRDNtApiReadSizeTSafe(NumberOfBytesWritten);
    BLACKBIRDNtApiLog("NtWriteVirtualMemory",
                      callerPid,
                      (UINT64) (ULONG_PTR) ProcessHandle,
                      (UINT64) (ULONG_PTR) BaseAddress,
                      (UINT64) (ULONG_PTR) Buffer,
                      (UINT64) BufferSize,
                      (UINT64) observedWritten,
                      0,
                      0,
                      0,
                      status);

Exit:
    if (logAcquired)
    {
        ExReleaseRundownProtection(&g_NtApiRundown);
    }
    BLACKBIRDNtApiHookExit();
    return status;
}

NTSTATUS NTAPI BLACKBIRDNtProtectVirtualMemoryHook(_In_ HANDLE ProcessHandle,
                                                   _Inout_ PVOID *BaseAddress,
                                                   _Inout_ PSIZE_T RegionSize,
                                                   _In_ ULONG NewProtect,
                                                   _Out_ PULONG OldProtect)
{
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE callerPid = NULL;
    PVOID observedBase;
    SIZE_T observedSize;
    ULONG observedOldProtect;
    BOOLEAN logAcquired = FALSE;

    BLACKBIRDNtApiHookEnter();

    if (g_OriginalNtProtectVirtualMemory == NULL)
    {
        BLACKBIRD_NTAPI_LOG(DPFLTR_ERROR_LEVEL, "BLACKBIRD: ntapi hook original null api=NtProtectVirtualMemory.\n");
        status = STATUS_INVALID_DEVICE_STATE;
        goto Exit;
    }
    status = g_OriginalNtProtectVirtualMemory(ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);

    if (!BLACKBIRDNtApiShouldLog(&callerPid))
    {
        goto Exit;
    }
    logAcquired = TRUE;

    observedBase = BLACKBIRDNtApiReadPointerSafe(BaseAddress);
    observedSize = BLACKBIRDNtApiReadSizeTSafe(RegionSize);
    observedOldProtect = BLACKBIRDNtApiReadUlongSafe(OldProtect);
    BLACKBIRDNtApiLog("NtProtectVirtualMemory",
                      callerPid,
                      (UINT64) (ULONG_PTR) ProcessHandle,
                      (UINT64) (ULONG_PTR) observedBase,
                      (UINT64) observedSize,
                      (UINT64) NewProtect,
                      (UINT64) observedOldProtect,
                      0,
                      0,
                      0,
                      status);

Exit:
    if (logAcquired)
    {
        ExReleaseRundownProtection(&g_NtApiRundown);
    }
    BLACKBIRDNtApiHookExit();
    return status;
}

NTSTATUS NTAPI BLACKBIRDNtCreateSectionHook(_Out_ PHANDLE SectionHandle,
                                            _In_ ACCESS_MASK DesiredAccess,
                                            _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
                                            _In_opt_ PLARGE_INTEGER MaximumSize,
                                            _In_ ULONG SectionPageProtection,
                                            _In_ ULONG AllocationAttributes,
                                            _In_opt_ HANDLE FileHandle)
{
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE callerPid = NULL;
    HANDLE observedSectionHandle;
    ULONGLONG observedMaximumSize;
    BOOLEAN logAcquired = FALSE;

    BLACKBIRDNtApiHookEnter();

    if (g_OriginalNtCreateSection == NULL)
    {
        BLACKBIRD_NTAPI_LOG(DPFLTR_ERROR_LEVEL, "BLACKBIRD: ntapi hook original null api=NtCreateSection.\n");
        status = STATUS_INVALID_DEVICE_STATE;
        goto Exit;
    }
    status = g_OriginalNtCreateSection(SectionHandle,
                                       DesiredAccess,
                                       ObjectAttributes,
                                       MaximumSize,
                                       SectionPageProtection,
                                       AllocationAttributes,
                                       FileHandle);

    if (!BLACKBIRDNtApiShouldLog(&callerPid))
    {
        goto Exit;
    }
    logAcquired = TRUE;

    observedSectionHandle = BLACKBIRDNtApiReadHandleSafe(SectionHandle);
    observedMaximumSize = BLACKBIRDNtApiReadLargeIntegerSafe(MaximumSize);
    BLACKBIRDNtApiLog("NtCreateSection",
                      callerPid,
                      (UINT64) (ULONG_PTR) observedSectionHandle,
                      (UINT64) DesiredAccess,
                      observedMaximumSize,
                      (UINT64) SectionPageProtection,
                      (UINT64) AllocationAttributes,
                      (UINT64) (ULONG_PTR) FileHandle,
                      (UINT64) (ULONG_PTR) ObjectAttributes,
                      0,
                      status);

Exit:
    if (logAcquired)
    {
        ExReleaseRundownProtection(&g_NtApiRundown);
    }
    BLACKBIRDNtApiHookExit();
    return status;
}

NTSTATUS NTAPI BLACKBIRDNtMapViewOfSectionHook(_In_ HANDLE SectionHandle,
                                               _In_ HANDLE ProcessHandle,
                                               _Inout_ PVOID *BaseAddress,
                                               _In_ ULONG_PTR ZeroBits,
                                               _In_ SIZE_T CommitSize,
                                               _Inout_opt_ PLARGE_INTEGER SectionOffset,
                                               _Inout_ PSIZE_T ViewSize,
                                               _In_ ULONG InheritDisposition,
                                               _In_ ULONG AllocationType,
                                               _In_ ULONG Win32Protect)
{
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE callerPid = NULL;
    PVOID observedBase;
    SIZE_T observedViewSize;
    ULONGLONG observedOffset;
    BOOLEAN logAcquired = FALSE;

    BLACKBIRDNtApiHookEnter();

    if (g_OriginalNtMapViewOfSection == NULL)
    {
        BLACKBIRD_NTAPI_LOG(DPFLTR_ERROR_LEVEL, "BLACKBIRD: ntapi hook original null api=NtMapViewOfSection.\n");
        status = STATUS_INVALID_DEVICE_STATE;
        goto Exit;
    }
    status = g_OriginalNtMapViewOfSection(SectionHandle,
                                          ProcessHandle,
                                          BaseAddress,
                                          ZeroBits,
                                          CommitSize,
                                          SectionOffset,
                                          ViewSize,
                                          InheritDisposition,
                                          AllocationType,
                                          Win32Protect);

    if (!BLACKBIRDNtApiShouldLog(&callerPid))
    {
        goto Exit;
    }
    logAcquired = TRUE;

    observedBase = BLACKBIRDNtApiReadPointerSafe(BaseAddress);
    observedViewSize = BLACKBIRDNtApiReadSizeTSafe(ViewSize);
    observedOffset = BLACKBIRDNtApiReadLargeIntegerSafe(SectionOffset);
    BLACKBIRDNtApiLog("NtMapViewOfSection",
                      callerPid,
                      (UINT64) (ULONG_PTR) SectionHandle,
                      (UINT64) (ULONG_PTR) ProcessHandle,
                      (UINT64) (ULONG_PTR) observedBase,
                      (UINT64) observedViewSize,
                      (UINT64) InheritDisposition,
                      (UINT64) AllocationType,
                      (UINT64) Win32Protect,
                      observedOffset,
                      status);

Exit:
    if (logAcquired)
    {
        ExReleaseRundownProtection(&g_NtApiRundown);
    }
    BLACKBIRDNtApiHookExit();
    return status;
}

NTSTATUS NTAPI BLACKBIRDNtQuerySystemInformationExHook(_In_ ULONG SystemInformationClass,
                                                       _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
                                                       _In_ ULONG InputBufferLength,
                                                       _Out_writes_bytes_opt_(SystemInformationLength)
                                                               PVOID SystemInformation,
                                                       _In_ ULONG SystemInformationLength,
                                                       _Out_opt_ PULONG ReturnLength)
{
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE callerPid = NULL;
    ULONG observedReturnLength;
    BOOLEAN logAcquired = FALSE;

    BLACKBIRDNtApiHookEnter();

    if (g_OriginalNtQuerySystemInformationEx == NULL)
    {
        BLACKBIRD_NTAPI_LOG(DPFLTR_ERROR_LEVEL,
                            "BLACKBIRD: ntapi hook original null api=NtQuerySystemInformationEx.\n");
        status = STATUS_INVALID_DEVICE_STATE;
        goto Exit;
    }
    status = g_OriginalNtQuerySystemInformationEx(SystemInformationClass,
                                                  InputBuffer,
                                                  InputBufferLength,
                                                  SystemInformation,
                                                  SystemInformationLength,
                                                  ReturnLength);
    BLACKBIRDNtApiSanitizeKernelDebuggerInformation(
            SystemInformationClass, SystemInformation, SystemInformationLength, status);
    BLACKBIRDNtApiSanitizeFirmwareTableInformation(
            SystemInformationClass, SystemInformation, SystemInformationLength, status);

    if (!BLACKBIRDNtApiShouldLog(&callerPid))
    {
        goto Exit;
    }
    logAcquired = TRUE;

    observedReturnLength = BLACKBIRDNtApiReadUlongSafe(ReturnLength);
    BLACKBIRDEtwLogSystemInfoEvent(callerPid,
                                   PsGetCurrentThreadId(),
                                   SystemInformationClass,
                                   SystemInformationLength,
                                   observedReturnLength,
                                   status);
    BLACKBIRDNtApiLog("NtQuerySystemInformationEx",
                      callerPid,
                      (UINT64) SystemInformationClass,
                      (UINT64) (ULONG_PTR) InputBuffer,
                      (UINT64) InputBufferLength,
                      (UINT64) (ULONG_PTR) SystemInformation,
                      (UINT64) SystemInformationLength,
                      (UINT64) observedReturnLength,
                      0,
                      0,
                      status);

Exit:
    if (logAcquired)
    {
        ExReleaseRundownProtection(&g_NtApiRundown);
    }
    BLACKBIRDNtApiHookExit();
    return status;
}

NTSTATUS NTAPI BLACKBIRDNtAllocateVirtualMemoryPreLog(_In_ HANDLE ProcessHandle,
                                                      _Inout_ PVOID *BaseAddress,
                                                      _In_ ULONG_PTR ZeroBits,
                                                      _Inout_ PSIZE_T RegionSize,
                                                      _In_ ULONG AllocationType,
                                                      _In_ ULONG Protect)
{
    HANDLE callerPid = NULL;
    PVOID observedBase;
    SIZE_T observedRegionSize;
    LONG remainingBudget;
    BOOLEAN logAcquired = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    BLACKBIRDNtApiHookEnter();

    remainingBudget = InterlockedDecrement(&g_NtApiAllocatePreLogBudget);
    if (remainingBudget >= 0)
    {
        BLACKBIRD_NTAPI_LOG(DPFLTR_INFO_LEVEL,
                            "BLACKBIRD: ntapi allocate prelog original=%p process=%p basePtr=%p zeroBits=0x%p "
                            "regionPtr=%p allocType=0x%08X protect=0x%08X.\n",
                            g_OriginalNtAllocateVirtualMemory,
                            ProcessHandle,
                            BaseAddress,
                            (PVOID) ZeroBits,
                            RegionSize,
                            AllocationType,
                            Protect);
    }
    if (!BLACKBIRDNtApiShouldLog(&callerPid))
    {
        return status;
    }
    logAcquired = TRUE;

    observedBase = BLACKBIRDNtApiReadPointerSafe(BaseAddress);
    observedRegionSize = BLACKBIRDNtApiReadSizeTSafe(RegionSize);
    BLACKBIRDNtApiLog("NtAllocateVirtualMemory",
                      callerPid,
                      (UINT64) (ULONG_PTR) ProcessHandle,
                      (UINT64) (ULONG_PTR) observedBase,
                      (UINT64) observedRegionSize,
                      (UINT64) ZeroBits,
                      (UINT64) AllocationType,
                      (UINT64) Protect,
                      0,
                      0,
                      STATUS_SUCCESS);

    if (logAcquired)
    {
        ExReleaseRundownProtection(&g_NtApiRundown);
    }
    return status;
}

#endif
