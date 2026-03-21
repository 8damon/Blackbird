#ifndef BLACKBIRD_CONTROL_H
#define BLACKBIRD_CONTROL_H

#include <ntddk.h>
#include <wdf.h>
#include "..\..\abi\blackbird_ioctl.h"

NTSTATUS
BLACKBIRDControlInitialize(_In_ WDFDRIVER Driver);

VOID BLACKBIRDControlUninitialize(VOID);

VOID BLACKBIRDControlBeginShutdown(VOID);

VOID BLACKBIRDControlPublishHandleEvent(_In_ const BLACKBIRD_HANDLE_EVENT *HandleEvent);

VOID BLACKBIRDControlPublishThreadEvent(_In_ UINT64 ProcessId, _In_ UINT64 ThreadId, _In_ UINT64 CreatorPid,
                                        _In_ UINT64 StartAddress, _In_ UINT64 ImageBase, _In_ UINT64 ImageSize,
                                        _In_ UINT32 Flags, _In_ UINT32 FrameCount,
                                        _In_reads_opt_(FrameCount) PVOID const *Frames);

VOID BLACKBIRDControlPublishFileEvent(_In_ const BLACKBIRD_FILE_EVENT *FileEvent);

BOOLEAN
BLACKBIRDControlBindPendingLaunchProcess(_In_ UINT32 ProcessId, _In_opt_ PCUNICODE_STRING ImagePath);

BOOLEAN
BLACKBIRDControlSelfCheck(VOID);

BOOLEAN
BLACKBIRDControlHasClientsFast(VOID);

BOOLEAN
BLACKBIRDControlIsArmedFast(VOID);

BOOLEAN
BLACKBIRDControlHasPidInterest(_In_ UINT32 PrimaryProcessId, _In_ UINT32 SecondaryProcessId, _In_ UINT32 StreamMask);

#endif
