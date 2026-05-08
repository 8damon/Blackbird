#pragma once

#include "../controller_private.h"

VOID ControllerClientClearPendingLaunchLocked(_Inout_ BK_CONTROLLER_CLIENT *Client);
VOID ControllerClientArmPendingLaunchLocked(_Inout_ BK_CONTROLLER_CLIENT *Client, _In_opt_z_ PCWSTR ImagePath,
                                            _In_ DWORD AnalysisSubjectKind, _In_opt_z_ PCWSTR AnalysisSubjectPath);
VOID ControllerClientPrimePendingLaunchPidLocked(_Inout_ BK_CONTROLLER_CLIENT *Client, _In_ DWORD ProcessId);
BOOL ControllerBuildPendingLaunchRequest(_In_z_ PCWSTR ImagePath, _In_ DWORD AnalysisSubjectKind,
                                         _In_opt_z_ PCWSTR AnalysisSubjectPath, _In_ DWORD StreamMask,
                                         _Out_ BK_ARM_PENDING_LAUNCH_REQUEST *Request);
DWORD ControllerEnsureCaptureReadyForLaunch(VOID);
BOOL ControllerClientIsPrivileged(_In_ const BK_CONTROLLER_CLIENT *Client, _Out_ BOOL *IsPrivileged);
DWORD ControllerClientOpenSharedRing(_Inout_ BK_CONTROLLER_CLIENT *Client,
                                     _In_ const BKIPC_OPEN_SHARED_RING_REQUEST *Request,
                                     _Out_ BKIPC_OPEN_SHARED_RING_RESPONSE *Response);
BOOL ControllerProxyQueryProcessImage(_In_ DWORD ProcessId, _Out_ BK_QUERY_PROCESS_IMAGE_RESPONSE *Response);
BOOL ControllerProxySetShutdownMode(VOID);
BOOL ControllerProxyControlProcessExecution(_In_ DWORD ProcessId, _In_ BOOL Suspend);
BOOL ControllerProxySetRuntimeConfig(_In_ DWORD Flags, _In_ DWORD Mask);
BOOL ControllerProxyGetRuntimeConfig(_Out_ BK_RUNTIME_CONFIG_RESPONSE *Response);
BOOL ControllerProxyArmPendingLaunch(_In_ const BK_ARM_PENDING_LAUNCH_REQUEST *Request);
BOOL ControllerProxyDriverConnected(VOID);
BOOL ControllerProxySetQpcTimingConfig(_In_ const BK_QPC_TIMING_CONFIG *Config);
BOOL ControllerProxyGetQpcTimingState(_Out_ BK_QPC_TIMING_STATE *State);
BOOL ControllerProxyGetHealth(_Out_ BK_HEALTH_RESPONSE *Response);
BOOL ControllerProxyGetDiagnostics(_Out_ BK_DIAGNOSTICS_RESPONSE *Response);
BOOL ControllerProxyRegisterInstrumentationRange(_In_ DWORD ProcessId, _In_ UINT64 BaseAddress, _In_ UINT64 RegionSize,
                                                 _In_ UINT32 Flags, _In_opt_z_ PCSTR Tag);
BOOL ControllerProxyRegisterHookPatch(_In_ DWORD ProcessId, _In_ UINT64 PatchAddress, _In_ UINT32 PatchSize,
                                      _In_reads_bytes_(OriginalSize) const UINT8 *OriginalBytes,
                                      _In_ UINT32 OriginalSize, _In_ UINT32 Flags, _In_opt_z_ PCSTR Tag);
BOOL ControllerProxyRegisterProcessInstrumentationCallback(_In_ DWORD ProcessId, _In_ UINT64 CallbackAddress,
                                                          _In_ UINT64 CallbackSize, _In_ UINT32 Flags);
BOOL ControllerProxyReadProcessMemory(_In_ DWORD ProcessId, _In_ UINT64 BaseAddress, _In_ DWORD RequestedSize,
                                      _In_ HANDLE ClientProcessHandle, _Out_ HANDLE *OutDupSectionHandle,
                                      _Out_ DWORD *OutBytesRead);
DWORD ControllerClientGetStats(_Inout_ BK_CONTROLLER_CLIENT *Client, _Out_ BK_STATS_RESPONSE *Stats);
VOID ControllerSanitizeAnsiLabel(_In_opt_z_ PCSTR Input, _Out_writes_z_(OutputChars) PSTR Output,
                                 _In_ size_t OutputChars);
PCSTR ControllerHookEventKindName(_In_ UINT32 Kind);
PCSTR ControllerMemoryProtectName(_In_ UINT32 Protect);
PCSTR ControllerMemoryAllocTypeName(_In_ UINT32 AllocationType);
UINT16 ControllerHookByteSwap16(_In_ UINT16 Value);
BOOL ControllerHookIsInterestingProcessAccess(_In_ ULONG DesiredAccess);
BOOL ControllerHookIsInterestingThreadAccess(_In_ ULONG DesiredAccess);
UINT32 ControllerHookSeverityForProcessAccess(_In_ ULONG DesiredAccess);
UINT32 ControllerHookSeverityForThreadAccess(_In_ ULONG DesiredAccess);
UINT32 ControllerCallerOriginSeverityBoost(_In_ UINT32 CallerFlags);
BOOL ControllerHookDecodeSockaddr(_In_reads_bytes_(SampleSize) const UINT8 *Sample, _In_ UINT32 SampleSize,
                                  _Out_ UINT16 *FamilyOut, _Out_ UINT16 *PortOut,
                                  _Out_writes_opt_z_(IpBufChars) PSTR IpBuf, _In_ size_t IpBufChars);
VOID ControllerHookCopyWideSampleToReason(_Out_writes_z_(ReasonChars) PWSTR Reason, _In_ size_t ReasonChars,
                                          _In_reads_bytes_(SampleSize) const UINT8 *Sample, _In_ UINT32 SampleSize);
VOID ControllerHookCopyAnsiSampleToReason(_Out_writes_z_(ReasonChars) PWSTR Reason, _In_ size_t ReasonChars,
                                          _In_reads_bytes_(SampleSize) const UINT8 *Sample, _In_ UINT32 SampleSize);
BOOL ControllerHookWidePathContainsI(_In_opt_z_ PCWSTR Haystack, _In_z_ PCWSTR Needle);
double ControllerComputeSampleEntropy(_In_reads_(SampleSize) const UINT8 *Sample, _In_ UINT32 SampleSize);
VOID ControllerHookAppendArgsToReason(_Inout_updates_(ReasonChars) PWSTR Reason, _In_ size_t ReasonChars,
                                      _In_reads_(ArgCount) const UINT64 *Args, _In_ UINT32 ArgCount);
VOID ControllerHookCopyArgs(_Out_writes_(BKIPC_MAX_HOOK_ARGS) UINT64 *Destination, _Out_opt_ UINT32 *DestinationCount,
                            _In_reads_(SourceCount) const UINT64 *Source, _In_ UINT32 SourceCount);
VOID ControllerPrimeHookArgumentSymbols(_In_ DWORD ProcessId, _In_z_ PCSTR ApiName,
                                        _In_reads_(ArgCount) const UINT64 *Args, _In_ UINT32 ArgCount);
