#ifndef SLEEPWALKER_CONTROL_H
#define SLEEPWALKER_CONTROL_H

#include <ntddk.h>
#include <wdf.h>
#include "..\..\abi\sleepwalker_ioctl.h"

NTSTATUS
SLEEPWALKERControlInitialize(_In_ WDFDRIVER Driver);

VOID SLEEPWALKERControlUninitialize(VOID);

VOID SLEEPWALKERControlBeginShutdown(VOID);

VOID SLEEPWALKERControlPublishHandleEvent(_In_ UINT64 CallerPid, _In_ UINT64 TargetPid, _In_ UINT32 DesiredAccess,
                                          _In_ UINT32 ClassId, _In_ UINT64 OriginAddress, _In_ UINT32 OriginProtect,
                                          _In_ UINT32 Flags, _In_opt_z_ PCWSTR OriginPath, _In_ UINT32 FrameCount,
                                          _In_reads_opt_(FrameCount) PVOID const *Frames, _In_ INT32 StatusOpenProcess,
                                          _In_ INT32 StatusBasicInfo, _In_ INT32 StatusSectionName,
                                          _In_ UINT64 DeepAllocationBase, _In_ UINT64 DeepRegionSize,
                                          _In_ UINT32 DeepRegionProtect, _In_ UINT32 DeepRegionState,
                                          _In_ UINT32 DeepRegionType, _In_ UINT32 DeepSampleSize,
                                          _In_reads_bytes_opt_(DeepSampleSize) const UCHAR *DeepSample);

VOID SLEEPWALKERControlPublishThreadEvent(_In_ UINT64 ProcessId, _In_ UINT64 ThreadId, _In_ UINT64 CreatorPid,
                                          _In_ UINT64 StartAddress, _In_ UINT64 ImageBase, _In_ UINT64 ImageSize,
                                          _In_ UINT32 Flags, _In_ UINT32 FrameCount,
                                          _In_reads_opt_(FrameCount) PVOID const *Frames);

BOOLEAN
SLEEPWALKERControlSelfCheck(VOID);

#endif
