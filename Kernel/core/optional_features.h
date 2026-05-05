#ifndef BK_OPTIONAL_FEATURES_H
#define BK_OPTIONAL_FEATURES_H

#include <ntddk.h>
#include "..\..\ABI\blackbird_ioctl.h"

#ifndef BK_ENABLE_WFP_ENDPOINT_GUARD
#define BK_ENABLE_WFP_ENDPOINT_GUARD 0
#endif

#ifndef BK_ENABLE_BUGCHECK_MONITOR
#define BK_ENABLE_BUGCHECK_MONITOR 0
#endif

NTSTATUS BkwfpEndpointGuardInitialize(VOID);
VOID BkwfpEndpointGuardUninitialize(VOID);
BOOLEAN BkwfpEndpointGuardSelfCheck(VOID);
BOOLEAN BkwfpEndpointGuardRuntimeActive(VOID);
NTSTATUS BkwfpEndpointGuardConfigure(_In_ const BK_ENDPOINT_GUARD_REQUEST *Request, _In_ UINT32 RequesterPid);
VOID BkwfpEndpointGuardDisarmProcess(_In_ UINT32 ProcessId);

NTSTATUS BkbugInitialize(VOID);
VOID BkbugUninitialize(VOID);
BOOLEAN BkbugSelfCheck(VOID);
VOID BkbugQueryState(_Out_opt_ UINT64 *KeBugCheckExRoutine, _Out_opt_ UINT64 *KeBugCheck2Routine);

static __inline BOOLEAN BkoptBugCheckMonitorIsRequired(VOID)
{
#if BK_ENABLE_BUGCHECK_MONITOR
    return TRUE;
#else
    return FALSE;
#endif
}

static __inline BOOLEAN BkoptEndpointGuardIsCompiled(VOID)
{
#if BK_ENABLE_WFP_ENDPOINT_GUARD
    return TRUE;
#else
    return FALSE;
#endif
}

#endif
