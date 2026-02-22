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
    _In_ UINT32 CorrelationFlags,
    _In_ UINT32 CorrelationAccessMask,
    _In_ UINT32 CorrelationAgeMs,
    _In_ ULONG StartRegionProtect,
    _In_ ULONG StartRegionState,
    _In_ ULONG StartRegionType,
    _In_ NTSTATUS StartRegionStatus,
    _In_ ULONG WorkerFrameCount,
    _In_reads_opt_(WorkerFrameCount) PVOID const* WorkerFrames
);

VOID
STINGEREtwLogProcessEvent(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ParentProcessId,
    _In_ HANDLE CreatorProcessId,
    _In_ HANDLE CreatorThreadId,
    _In_ ULONGLONG ProcessStartKey,
    _In_ ULONG SessionId,
    _In_ BOOLEAN IsCreate,
    _In_ NTSTATUS CreateStatus,
    _In_opt_z_ PCWSTR ImagePath,
    _In_opt_z_ PCWSTR CommandLine
);

VOID
STINGEREtwLogImageLoadEvent(
    _In_ HANDLE ProcessId,
    _In_ PVOID ImageBase,
    _In_ SIZE_T ImageSize,
    _In_ BOOLEAN IsSystemModeImage,
    _In_ BOOLEAN IsSignatureLevelKnown,
    _In_ UCHAR SignatureLevel,
    _In_ UCHAR SignatureType,
    _In_opt_z_ PCWSTR ImagePath
);

VOID
STINGEREtwLogRegistryEvent(
    _In_z_ PCSTR Operation,
    _In_ HANDLE ProcessId,
    _In_ ULONG SessionId,
    _In_ ULONG NotifyClass,
    _In_ ULONG DataType,
    _In_ ULONG DataSize,
    _In_ BOOLEAN IsHighValuePath,
    _In_opt_z_ PCWSTR KeyPath,
    _In_opt_z_ PCWSTR ValueName
);

VOID
STINGEREtwLogDetectionEvent(
    _In_z_ PCSTR DetectionName,
    _In_ ULONG Severity,
    _In_ HANDLE ProcessId,
    _In_ HANDLE TargetPid,
    _In_ UINT32 CorrelationFlags,
    _In_ UINT32 CorrelationAccessMask,
    _In_ UINT32 CorrelationAgeMs,
    _In_opt_z_ PCWSTR Reason
);

#endif
