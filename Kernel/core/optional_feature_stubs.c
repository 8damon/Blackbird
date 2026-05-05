#include "optional_features.h"
#include "crashdump.h"

#if !BK_ENABLE_CRASHDUMP_CALLBACK

NTSTATUS BkcrashInitialize(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    return STATUS_SUCCESS;
}

VOID BkcrashUninitialize(VOID)
{
}

VOID BkcrashSetDriverState(_In_ LONG DriverState)
{
    UNREFERENCED_PARAMETER(DriverState);
}

VOID BkcrashSetInitFlags(_In_ LONG InitFlags)
{
    UNREFERENCED_PARAMETER(InitFlags);
}

VOID BkcrashRecordCheckpoint(_In_ UINT32 SubsystemId, _In_ UINT32 EventType, _In_ NTSTATUS Status,
                             _In_ UINT32 ComponentId)
{
    UNREFERENCED_PARAMETER(SubsystemId);
    UNREFERENCED_PARAMETER(EventType);
    UNREFERENCED_PARAMETER(Status);
    UNREFERENCED_PARAMETER(ComponentId);
}

#endif

#if !BK_ENABLE_WFP_ENDPOINT_GUARD

NTSTATUS BkwfpEndpointGuardInitialize(VOID)
{
    return STATUS_NOT_SUPPORTED;
}

VOID BkwfpEndpointGuardUninitialize(VOID)
{
}

BOOLEAN BkwfpEndpointGuardSelfCheck(VOID)
{
    return FALSE;
}

BOOLEAN BkwfpEndpointGuardRuntimeActive(VOID)
{
    return FALSE;
}

NTSTATUS BkwfpEndpointGuardConfigure(_In_ const BK_ENDPOINT_GUARD_REQUEST *Request, _In_ UINT32 RequesterPid)
{
    UNREFERENCED_PARAMETER(Request);
    UNREFERENCED_PARAMETER(RequesterPid);

    return STATUS_NOT_SUPPORTED;
}

VOID BkwfpEndpointGuardDisarmProcess(_In_ UINT32 ProcessId)
{
    UNREFERENCED_PARAMETER(ProcessId);
}

#endif

#if !BK_ENABLE_BUGCHECK_MONITOR

NTSTATUS BkbugInitialize(VOID)
{
    return STATUS_NOT_SUPPORTED;
}

VOID BkbugUninitialize(VOID)
{
}

BOOLEAN BkbugSelfCheck(VOID)
{
    return FALSE;
}

VOID BkbugQueryState(_Out_opt_ UINT64 *KeBugCheckExRoutine, _Out_opt_ UINT64 *KeBugCheck2Routine)
{
    if (KeBugCheckExRoutine != NULL)
    {
        *KeBugCheckExRoutine = 0;
    }
    if (KeBugCheck2Routine != NULL)
    {
        *KeBugCheck2Routine = 0;
    }
}

#endif
