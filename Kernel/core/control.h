#ifndef BK_CONTROL_H
#define BK_CONTROL_H

#include <ntddk.h>
#include <wdf.h>
#include "..\..\abi\blackbird_ioctl.h"

NTSTATUS
BkctlInitialize(_In_ WDFDRIVER Driver);

VOID BkctlUninitialize(VOID);

VOID BkctlBeginShutdown(VOID);

VOID BkctlPublishHandleEvent(_In_ const BK_HANDLE_EVENT *HandleEvent);

VOID BkctlPublishThreadEvent(_In_ UINT64 ProcessId, _In_ UINT64 ThreadId, _In_ UINT64 CreatorPid,
                             _In_ UINT64 StartAddress, _In_ UINT64 ImageBase, _In_ UINT64 ImageSize, _In_ UINT32 Flags,
                             _In_ UINT32 FrameCount, _In_reads_opt_(FrameCount) PVOID const *Frames);

VOID BkctlPublishFileEvent(_In_ const BK_FILE_EVENT *FileEvent);

VOID BkctlPublishRegistryEvent(_In_ const BK_REGISTRY_EVENT *RegistryEvent);

VOID BkctlPublishEnterpriseEvent(_In_ const BK_ENTERPRISE_EVENT *EnterpriseEvent);

BOOLEAN
BkctlBindPendingLaunchProcess(_In_ UINT32 ProcessId, _In_opt_ PCUNICODE_STRING ImagePath);

BOOLEAN
BkctlMarkAnalysisSubjectImageLoad(_In_ UINT32 ProcessId, _In_opt_ PCUNICODE_STRING ImagePath, _In_ UINT64 ImageBase,
                                  _In_ UINT64 ImageSize);

BOOLEAN
BkctlSelfCheck(VOID);

PDEVICE_OBJECT
BkctlGetWdmDeviceObject(VOID);

BOOLEAN
BkctlHasClientsFast(VOID);

BOOLEAN
BkctlIsArmedFast(VOID);

BOOLEAN
BkctlHasPidInterest(_In_ UINT32 PrimaryProcessId, _In_ UINT32 SecondaryProcessId, _In_ UINT32 StreamMask);

UINT32
BkctlQueryPidInterest(_In_ UINT32 PrimaryProcessId, _In_ UINT32 SecondaryProcessId, _In_ UINT32 StreamMask);

#endif
