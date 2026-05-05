#ifndef BK_NTAPI_MONITOR_H
#define BK_NTAPI_MONITOR_H

#include <ntdef.h>
#include "..\..\..\abi\blackbird_ioctl.h"

NTSTATUS
BkntkiMonitorInitialize(VOID);

NTSTATUS
BkntkiMonitorArmHooks(VOID);

VOID BkntkiMonitorDisarmHooks(VOID);

VOID BkntkiMonitorSetArmedState(_In_ BOOLEAN Armed);

VOID BkntkiMonitorUninitialize(VOID);

BOOLEAN
BkntkiMonitorSelfCheck(VOID);

NTSTATUS
BkntkiRegisterInstrumentationRange(_In_ UINT32 ProcessId, _In_ UINT64 BaseAddress, _In_ UINT64 RegionSize,
                                   _In_ UINT32 Flags, _In_opt_z_ PCSTR Tag);

NTSTATUS
BkntkiRegisterHookPatch(_In_ UINT32 ProcessId, _In_ UINT64 PatchAddress, _In_ UINT32 PatchSize,
                        _In_reads_bytes_(OriginalSize) const UINT8 *OriginalBytes, _In_ UINT32 OriginalSize,
                        _In_ UINT32 Flags, _In_opt_z_ PCSTR Tag);

BOOLEAN
BkntkiReadTouchesInstrumentationRange(_In_ HANDLE ProcessHandle, _In_ PVOID BaseAddress, _In_ SIZE_T Size,
                                      _Out_opt_ UINT32 *TargetProcessId);

BOOLEAN
BkntkiOverlayHookPatchBytesForPid(_In_ UINT32 ProcessId, _In_ UINT64 BaseAddress, _In_ SIZE_T Size,
                                  _Inout_updates_bytes_(Size) PVOID Buffer);

BOOLEAN
BkntkiOverlayHookPatchBytesForHandle(_In_ HANDLE ProcessHandle, _In_ PVOID BaseAddress, _In_ SIZE_T Size,
                                     _Inout_updates_bytes_(Size) PVOID Buffer, _Out_opt_ UINT32 *TargetProcessId);

NTSTATUS
BkntkiMirrorHookPatchesIntoImage(_In_ UINT32 ProcessId, _In_ UINT64 SourceImageBase, _In_ UINT64 MirrorImageBase,
                                 _In_ UINT64 MirrorImageSize);

NTSTATUS
BkntkiMirrorHookPatchesIntoDataView(_In_ UINT32 ProcessId, _In_ UINT64 SourceImageBase, _In_ UINT64 MirrorViewBase,
                                    _In_ UINT64 MirrorViewSize);

VOID BkntkiQueryDiagnostics(_Out_opt_ UINT32 *InstrumentationRangeCount, _Out_opt_ UINT32 *HookPatchCount,
                            _Out_opt_ UINT64 *HookPatchOverlayCount, _Out_opt_ UINT64 *InstrumentationReadDenyCount,
                            _Out_opt_ UINT64 *DuplicateNtdllMirrorCount,
                            _Out_opt_ UINT64 *DuplicateNtdllMirrorFailureCount);

VOID BkntkiQueryHookDiagnostics(_Out_writes_(Capacity) PBK_DIAGNOSTIC_NTAPI_HOOK_STATE States, _In_ UINT32 Capacity,
                                _Out_ UINT32 *Count);

VOID BkntkiQuerySanitizerDiagnostics(_Out_writes_(Capacity) PBK_DIAGNOSTIC_SANITIZER_STATE States, _In_ UINT32 Capacity,
                                     _Out_ UINT32 *Count);

VOID BkntkiRecordSanitizerHit(_In_ UINT32 SanitizerId);

#endif
