#ifndef STINGER_CONTROL_H
#define STINGER_CONTROL_H

#include <ntddk.h>
#include <wdf.h>
#include "..\..\abi\stinger_ioctl.h"

NTSTATUS
STINGERControlInitialize(
    _In_ WDFDRIVER Driver
);

VOID
STINGERControlUninitialize(
    VOID
);

VOID
STINGERControlPublishHandleEvent(
    _In_ UINT64 CallerPid,
    _In_ UINT64 TargetPid,
    _In_ UINT32 DesiredAccess,
    _In_ UINT32 ClassId,
    _In_ UINT64 OriginAddress,
    _In_ UINT32 OriginProtect,
    _In_ UINT32 Flags,
    _In_opt_z_ PCWSTR OriginPath,
    _In_ UINT32 FrameCount,
    _In_reads_opt_(FrameCount) PVOID const* Frames,
    _In_ INT32 StatusOpenProcess,
    _In_ INT32 StatusBasicInfo,
    _In_ INT32 StatusSectionName
);

VOID
STINGERControlPublishThreadEvent(
    _In_ UINT64 ProcessId,
    _In_ UINT64 ThreadId,
    _In_ UINT64 CreatorPid,
    _In_ UINT64 StartAddress,
    _In_ UINT64 ImageBase,
    _In_ UINT64 ImageSize,
    _In_ UINT32 Flags,
    _In_ UINT32 FrameCount,
    _In_reads_opt_(FrameCount) PVOID const* Frames
);

BOOLEAN
STINGERControlSelfCheck(
    VOID
);

#endif
