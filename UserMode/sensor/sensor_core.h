#ifndef BK_SENSOR_CORE_H
#define BK_SENSOR_CORE_H

#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <winioctl.h>
#include "..\..\abi\blackbird_ioctl.h"
#include "..\..\abi\blackbird_ipc.h"

#ifdef BKSC_EXPORTS
#define BKSC_API __declspec(dllexport)
#else
#define BKSC_API __declspec(dllimport)
#endif

#ifdef __cplusplus
extern "C"
{
#endif

    typedef struct _BKSC_ETW_PROVIDER_CONFIG
    {
        GUID ProviderId;
        UCHAR Level;
        ULONGLONG MatchAnyKeyword;
        ULONGLONG MatchAllKeyword;
    } BKSC_ETW_PROVIDER_CONFIG, *PBKSC_ETW_PROVIDER_CONFIG;

    typedef VOID(WINAPI *BKSC_ETW_EVENT_CALLBACK)(_In_ PEVENT_RECORD Record, _In_opt_z_ PCWSTR EventName,
                                                  _In_opt_ PVOID Context);

    typedef struct _BKSC_ETW_SESSION_CONFIG
    {
        _In_z_ PCWSTR SessionName;
        _In_reads_(ProviderCount) const BKSC_ETW_PROVIDER_CONFIG *Providers;
        ULONG ProviderCount;
        BKSC_ETW_EVENT_CALLBACK Callback;
        PVOID CallbackContext;
    } BKSC_ETW_SESSION_CONFIG, *PBKSC_ETW_SESSION_CONFIG;

    typedef struct _BKSC_ETW_SESSION BKSC_ETW_SESSION;

    typedef struct _BKSC_DETECTION_EVENT
    {
        WCHAR DetectionName[128];
        WCHAR Reason[512];
        ULONG Severity;
        ULONGLONG ProcessId;
        ULONGLONG TargetPid;
        ULONG CorrelationFlags;
        ULONG CorrelationAccessMask;
        ULONG CorrelationAgeMs;
        ULONG EtwProcessId;
        ULONG EtwThreadId;
        ULONGLONG TimestampQpc;
    } BKSC_DETECTION_EVENT, *PBKSC_DETECTION_EVENT;

    typedef VOID(WINAPI *BKSC_DETECTION_CALLBACK)(_In_ const BKSC_DETECTION_EVENT *Event, _In_opt_ PVOID Context);

    typedef enum _BKSC_PROTOCOL_MODE
    {
        BKSC_PROTOCOL_SERVICE = 0,
        BKSC_PROTOCOL_CLIENT = 1
    } BKSC_PROTOCOL_MODE;

    extern BKSC_API const GUID BKSC_PROVIDER_GUID_BLACKBIRD;
    extern BKSC_API const GUID BKSC_PROVIDER_GUID_TI;
    extern BKSC_API const GUID BKSC_PROVIDER_GUID_KERNEL_NETWORK;

    BKSC_API VOID BkscUseServiceProtocol(VOID);
    BKSC_API BOOL BkscUseClientProtocol(_In_opt_z_ PCWSTR PipeName, _In_ DWORD ConnectTimeoutMs);
    BKSC_API BKSC_PROTOCOL_MODE BkscGetProtocolMode(VOID);

    BKSC_API HANDLE BkscOpenControlDevice(VOID);
    BKSC_API BOOL BkscCloseControlDevice(_In_opt_ HANDLE Device);
    BKSC_API BOOL BkscGetBrokerInfo(_Out_opt_ UINT32 *Capabilities, _Out_opt_ BOOL *ThreatIntelEnabled);
    BKSC_API BOOL BkscHasSharedChannel(_In_ HANDLE Device, _Out_opt_ BOOL *HasIoctlChannel,
                                       _Out_opt_ BOOL *HasEtwChannel);
    BKSC_API DWORD BkscGetLastSharedRingError(VOID);
    BKSC_API DWORD BkscGetLastThreatIntelEnableError(VOID);
    BKSC_API BOOL BkscSubscribe(_In_ HANDLE Device, _In_ DWORD ProcessId, _In_ DWORD StreamMask);
    BKSC_API BOOL BkscUnsubscribe(_In_ HANDLE Device, _In_ DWORD ProcessId);
    BKSC_API BOOL BkscSetPids(_In_ HANDLE Device, _In_reads_(ProcessCount) const DWORD *ProcessIds,
                              _In_ DWORD ProcessCount, _In_ DWORD StreamMask);
    BKSC_API BOOL BkscArmPendingLaunch(_In_ HANDLE Device, _In_ const BK_ARM_PENDING_LAUNCH_REQUEST *Request);
    BKSC_API BOOL BkscGetEvent(_In_ HANDLE Device, _Out_ BK_EVENT_RECORD *Record, _Out_opt_ DWORD *BytesReturned);
    BKSC_API BOOL BkscGetEventWait(_In_ HANDLE Device, _Out_ BK_EVENT_RECORD *Record, _Out_opt_ DWORD *BytesReturned,
                                   _In_ DWORD TimeoutMs);
    BKSC_API BOOL BkscGetStats(_In_ HANDLE Device, _Out_ BK_STATS_RESPONSE *Stats, _Out_opt_ DWORD *BytesReturned);
    BKSC_API BOOL BkscGetHealth(_In_ HANDLE Device, _Out_ BK_HEALTH_RESPONSE *Health, _Out_opt_ DWORD *BytesReturned);
    BKSC_API BOOL BkscGetDiagnostics(_In_ HANDLE Device, _Out_ BK_DIAGNOSTICS_RESPONSE *Diagnostics,
                                     _Out_opt_ DWORD *BytesReturned);
    BKSC_API BOOL BkscQueryProcessImagePath(_In_ HANDLE Device, _In_ DWORD ProcessId,
                                            _Out_writes_z_(OutputChars) PWSTR Output, _In_ DWORD OutputChars);
    BKSC_API BOOL BkscSetRuntimeConfig(_In_ HANDLE Device, _In_ DWORD Flags, _In_ DWORD Mask);
    BKSC_API BOOL BkscGetRuntimeConfig(_In_ HANDLE Device, _Out_ BK_RUNTIME_CONFIG_RESPONSE *Response);
    BKSC_API BOOL BkscSetQpcTimingConfig(_In_ HANDLE Device, _In_ const BK_QPC_TIMING_CONFIG *Config);
    BKSC_API BOOL BkscGetQpcTimingState(_In_ HANDLE Device, _Out_ BK_QPC_TIMING_STATE *State);
    BKSC_API BOOL BkscMarkControllerReady(_In_ HANDLE Device, _In_ DWORD ProcessId);
    BKSC_API BOOL BkscRegisterInstrumentationRange(_In_ HANDLE Device,
                                                   _In_ const BK_REGISTER_INSTRUMENTATION_RANGE_REQUEST *Request);
    BKSC_API BOOL BkscRegisterHookPatch(_In_ HANDLE Device, _In_ const BK_REGISTER_HOOK_PATCH_REQUEST *Request);
    BKSC_API BOOL BkscSetEndpointGuard(_In_ HANDLE Device, _In_ const BK_ENDPOINT_GUARD_REQUEST *Request);
    BKSC_API BOOL BkscSetUserHookTarget(_In_ HANDLE Device, _In_ DWORD Mode, _In_ DWORD ProcessId, _In_ DWORD Flags,
                                        _In_opt_z_ PCWSTR ImagePath, _In_ DWORD AnalysisSubjectKind,
                                        _In_opt_z_ PCWSTR AnalysisSubjectPath, _In_opt_z_ PCWSTR HookDllPath,
                                        _In_opt_z_ PCWSTR WorkingDirectory, _In_opt_z_ PCWSTR EnvironmentOverrides,
                                        _In_opt_z_ PCWSTR CommandLineArguments, _In_ DWORD ParentProcessId,
                                        _In_ DWORD PriorityClass, _In_ UINT64 AffinityMask, _In_ BOOL InheritHandles,
                                        _In_ DWORD IntegrityLevel,
                                        _Out_opt_ BKIPC_SET_USER_HOOK_TARGET_RESPONSE *Response);
    BKSC_API BOOL BkscSetShutdownMode(_In_ HANDLE Device);
    BKSC_API BOOL BkscControlProcessExecution(_In_ HANDLE Device, _In_ DWORD ProcessId, _In_ BOOL Suspend);
    BKSC_API BOOL BkscQueryProcessMemory(_In_ HANDLE Device, _In_ DWORD ProcessId, _In_ UINT64 BaseAddress,
                                         _In_ DWORD RequestedSize, _Out_writes_bytes_(*BytesRead) PVOID Buffer,
                                         _In_ DWORD BufferSize, _Out_ DWORD *BytesRead);
    BKSC_API BOOL BkscGetEtwEvent(_In_ HANDLE Device, _Out_ BKIPC_ETW_EVENT *Event, _In_ DWORD TimeoutMs);
    BKSC_API DWORD BkscParseStreamMaskA(_In_z_ const char *Text);

    BKSC_API ULONG BkscStopSessionByName(_In_z_ PCWSTR SessionName);
    BKSC_API BOOL BkscStartEtwSession(_In_ const BKSC_ETW_SESSION_CONFIG *Config, _Outptr_ BKSC_ETW_SESSION **Session);
    BKSC_API BOOL BkscStartBlackbirdEtwSession(_In_z_ PCWSTR SessionName, _In_ BOOL EnableThreatIntelProvider,
                                               _In_ BKSC_ETW_EVENT_CALLBACK Callback, _In_opt_ PVOID CallbackContext,
                                               _Outptr_ BKSC_ETW_SESSION **Session, _Out_opt_ BOOL *ThreatIntelEnabled);
    BKSC_API BOOL BkscStartDetectionEtwSession(_In_z_ PCWSTR SessionName, _In_ BOOL EnableThreatIntelProvider,
                                               _In_ BKSC_DETECTION_CALLBACK Callback, _In_opt_ PVOID CallbackContext,
                                               _Outptr_ BKSC_ETW_SESSION **Session, _Out_opt_ BOOL *ThreatIntelEnabled);
    BKSC_API ULONG BkscRunEtwSession(_In_ BKSC_ETW_SESSION *Session);
    BKSC_API VOID BkscStopEtwSession(_In_opt_ BKSC_ETW_SESSION *Session);

#ifdef __cplusplus
}
#endif

#endif
