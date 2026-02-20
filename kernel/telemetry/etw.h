#ifndef STINGER_ETW_H
#define STINGER_ETW_H

#include <ntdef.h>

NTSTATUS
STINGEREtwInitialize(
    VOID
);

VOID
STINGEREtwUninitialize(
    VOID
);

VOID
STINGEREtwLogHandleEvent(
    _In_z_ PCSTR EventClass,
    _In_ HANDLE CallerPid,
    _In_ HANDLE TargetPid,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ PVOID OriginAddress,
    _In_ ULONG OriginProtect,
    _In_ BOOLEAN ExecProtect,
    _In_ BOOLEAN FromNtdll,
    _In_ BOOLEAN FromExe,
    _In_opt_z_ PCWSTR OriginPath,
    _In_ ULONG FrameCount,
    _In_reads_opt_(FrameCount) PVOID const* Frames,
    _In_ NTSTATUS OpenProcessStatus,
    _In_ NTSTATUS BasicInfoStatus,
    _In_ NTSTATUS SectionNameStatus
);

VOID
STINGEREtwLogThreadEvent(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _In_ HANDLE CreatorPid,
    _In_ PVOID StartAddress,
    _In_ PVOID ImageBase,
    _In_ SIZE_T ImageSize,
    _In_ BOOLEAN GotStart,
    _In_ BOOLEAN GotRange,
    _In_ BOOLEAN IsRemoteCreator,
    _In_ BOOLEAN OutsideMainImage,
    _In_ ULONG WorkerFrameCount,
    _In_reads_opt_(WorkerFrameCount) PVOID const* WorkerFrames
);

#endif
