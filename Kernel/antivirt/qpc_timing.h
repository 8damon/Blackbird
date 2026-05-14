#ifndef BK_QPC_TIMING_H
#define BK_QPC_TIMING_H

#include <ntddk.h>
#include "..\..\abi\blackbird_ioctl.h"

typedef struct _BK_QPC_TIMING_APPLY_INFO
{
    UINT64 RawDeltaTicks;
    UINT64 VirtualDeltaTicks;
    INT64 CorrectionTicks;
    UINT32 SourceFlags;
    INT64 AutoBiasTicks;
} BK_QPC_TIMING_APPLY_INFO, *PBK_QPC_TIMING_APPLY_INFO;

NTSTATUS BkqpcInitialize(VOID);
VOID BkqpcUninitialize(VOID);

NTSTATUS BkqpcSetConfig(_In_ const BK_QPC_TIMING_CONFIG *Config);
VOID BkqpcQueryState(_Out_ BK_QPC_TIMING_STATE *State);

BOOLEAN BkqpcApplyTimingAdjustment(_In_ UINT32 ProcessId, _In_ UINT32 ThreadId, _In_ LARGE_INTEGER RawCounter,
                                   _In_ LARGE_INTEGER Frequency, _Out_ LARGE_INTEGER *VirtualCounter,
                                   _Out_opt_ BK_QPC_TIMING_APPLY_INFO *Info);

VOID BkqpcRecordPostQueryOverhead(_In_ UINT32 ProcessId, _In_ UINT32 ThreadId, _In_ INT64 OverheadTicks);
VOID BkqpcNotifyProcessExecutionControl(_In_ UINT32 ProcessId, _In_ BOOLEAN Suspend);

#endif
