#ifndef SLEEPWALKER_CONTROL_H
#define SLEEPWALKER_CONTROL_H

#include <ntddk.h>
#include <wdf.h>
#include "..\..\abi\sleepwalker_ioctl.h"

NTSTATUS
SLEEPWALKERControlInitialize(_In_ WDFDRIVER Driver);

VOID SLEEPWALKERControlUninitialize(VOID);

VOID SLEEPWALKERControlBeginShutdown(VOID);

VOID SLEEPWALKERControlPublishHandleEvent(_In_ const SLEEPWALKER_HANDLE_EVENT *HandleEvent);

VOID SLEEPWALKERControlPublishThreadEvent(_In_ UINT64 ProcessId, _In_ UINT64 ThreadId, _In_ UINT64 CreatorPid,
                                          _In_ UINT64 StartAddress, _In_ UINT64 ImageBase, _In_ UINT64 ImageSize,
                                          _In_ UINT32 Flags, _In_ UINT32 FrameCount,
                                          _In_reads_opt_(FrameCount) PVOID const *Frames);

VOID SLEEPWALKERControlPublishFileEvent(_In_ const SLEEPWALKER_FILE_EVENT *FileEvent);

BOOLEAN
SLEEPWALKERControlSelfCheck(VOID);

BOOLEAN
SLEEPWALKERControlHasClientsFast(VOID);

BOOLEAN
SLEEPWALKERControlHasPidInterest(_In_ UINT32 PrimaryProcessId, _In_ UINT32 SecondaryProcessId, _In_ UINT32 StreamMask);

#endif
