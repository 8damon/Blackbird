#ifndef BLACKBIRD_SENSOR_CORE_H
#define BLACKBIRD_SENSOR_CORE_H

#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <winioctl.h>
#include "..\..\abi\blackbird_ioctl.h"
#include "..\..\abi\blackbird_ipc.h"

#ifdef BLACKBIRDSC_EXPORTS
#define BLACKBIRDSC_API __declspec(dllexport)
#else
#define BLACKBIRDSC_API __declspec(dllimport)
#endif

#ifdef __cplusplus
extern "C"
{
#endif

    typedef struct _BLACKBIRDSC_ETW_PROVIDER_CONFIG
    {
        GUID ProviderId;
        UCHAR Level;
        ULONGLONG MatchAnyKeyword;
        ULONGLONG MatchAllKeyword;
    } BLACKBIRDSC_ETW_PROVIDER_CONFIG, *PBLACKBIRDSC_ETW_PROVIDER_CONFIG;

    typedef VOID(WINAPI *BLACKBIRDSC_ETW_EVENT_CALLBACK)(_In_ PEVENT_RECORD Record, _In_opt_z_ PCWSTR EventName,
                                                         _In_opt_ PVOID Context);

    typedef struct _BLACKBIRDSC_ETW_SESSION_CONFIG
    {
        _In_z_ PCWSTR SessionName;
        _In_reads_(ProviderCount) const BLACKBIRDSC_ETW_PROVIDER_CONFIG *Providers;
        ULONG ProviderCount;
        BLACKBIRDSC_ETW_EVENT_CALLBACK Callback;
        PVOID CallbackContext;
    } BLACKBIRDSC_ETW_SESSION_CONFIG, *PBLACKBIRDSC_ETW_SESSION_CONFIG;

    typedef struct _BLACKBIRDSC_ETW_SESSION BLACKBIRDSC_ETW_SESSION;

    typedef struct _BLACKBIRDSC_DETECTION_EVENT
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
    } BLACKBIRDSC_DETECTION_EVENT, *PBLACKBIRDSC_DETECTION_EVENT;

    typedef VOID(WINAPI *BLACKBIRDSC_DETECTION_CALLBACK)(_In_ const BLACKBIRDSC_DETECTION_EVENT *Event,
                                                         _In_opt_ PVOID Context);

    typedef enum _BLACKBIRDSC_PROTOCOL_MODE
    {
        BLACKBIRDSC_PROTOCOL_SERVICE = 0,
        BLACKBIRDSC_PROTOCOL_CLIENT = 1
    } BLACKBIRDSC_PROTOCOL_MODE;

    extern BLACKBIRDSC_API const GUID BLACKBIRDSC_PROVIDER_GUID_BLACKBIRD;
    extern BLACKBIRDSC_API const GUID BLACKBIRDSC_PROVIDER_GUID_TI;
    extern BLACKBIRDSC_API const GUID BLACKBIRDSC_PROVIDER_GUID_KERNEL_NETWORK;

    BLACKBIRDSC_API VOID BLACKBIRDSCUseServiceProtocol(VOID);
    BLACKBIRDSC_API BOOL BLACKBIRDSCUseClientProtocol(_In_opt_z_ PCWSTR PipeName, _In_ DWORD ConnectTimeoutMs);
    BLACKBIRDSC_API BLACKBIRDSC_PROTOCOL_MODE BLACKBIRDSCGetProtocolMode(VOID);

    BLACKBIRDSC_API HANDLE BLACKBIRDSCOpenControlDevice(VOID);
    BLACKBIRDSC_API BOOL BLACKBIRDSCCloseControlDevice(_In_opt_ HANDLE Device);
    BLACKBIRDSC_API BOOL BLACKBIRDSCGetBrokerInfo(_Out_opt_ UINT32 *Capabilities, _Out_opt_ BOOL *ThreatIntelEnabled);
    BLACKBIRDSC_API BOOL BLACKBIRDSCHasSharedChannel(_In_ HANDLE Device, _Out_opt_ BOOL *HasIoctlChannel,
                                                     _Out_opt_ BOOL *HasEtwChannel);
    BLACKBIRDSC_API DWORD BLACKBIRDSCGetLastSharedRingError(VOID);
    BLACKBIRDSC_API DWORD BLACKBIRDSCGetLastThreatIntelEnableError(VOID);
    BLACKBIRDSC_API BOOL BLACKBIRDSCSubscribe(_In_ HANDLE Device, _In_ DWORD ProcessId, _In_ DWORD StreamMask);
    BLACKBIRDSC_API BOOL BLACKBIRDSCUnsubscribe(_In_ HANDLE Device, _In_ DWORD ProcessId);
    BLACKBIRDSC_API BOOL BLACKBIRDSCSetPids(_In_ HANDLE Device, _In_reads_(ProcessCount) const DWORD *ProcessIds,
                                            _In_ DWORD ProcessCount, _In_ DWORD StreamMask);
    BLACKBIRDSC_API BOOL BLACKBIRDSCArmPendingLaunch(_In_ HANDLE Device,
                                                     _In_ const BLACKBIRD_ARM_PENDING_LAUNCH_REQUEST *Request);
    BLACKBIRDSC_API BOOL BLACKBIRDSCGetEvent(_In_ HANDLE Device, _Out_ BLACKBIRD_EVENT_RECORD *Record,
                                             _Out_opt_ DWORD *BytesReturned);
    BLACKBIRDSC_API BOOL BLACKBIRDSCGetEventWait(_In_ HANDLE Device, _Out_ BLACKBIRD_EVENT_RECORD *Record,
                                                 _Out_opt_ DWORD *BytesReturned, _In_ DWORD TimeoutMs);
    BLACKBIRDSC_API BOOL BLACKBIRDSCGetStats(_In_ HANDLE Device, _Out_ BLACKBIRD_STATS_RESPONSE *Stats,
                                             _Out_opt_ DWORD *BytesReturned);
    BLACKBIRDSC_API BOOL BLACKBIRDSCQueryProcessImagePath(_In_ HANDLE Device, _In_ DWORD ProcessId,
                                                          _Out_writes_z_(OutputChars) PWSTR Output,
                                                          _In_ DWORD OutputChars);
    BLACKBIRDSC_API BOOL BLACKBIRDSCSetRuntimeConfig(_In_ HANDLE Device, _In_ DWORD Flags, _In_ DWORD Mask);
    BLACKBIRDSC_API BOOL BLACKBIRDSCGetRuntimeConfig(_In_ HANDLE Device,
                                                     _Out_ BLACKBIRD_RUNTIME_CONFIG_RESPONSE *Response);
    BLACKBIRDSC_API BOOL BLACKBIRDSCMarkInterfaceReady(_In_ HANDLE Device, _In_ DWORD ProcessId);
    BLACKBIRDSC_API BOOL BLACKBIRDSCMarkControllerReady(_In_ HANDLE Device, _In_ DWORD ProcessId);
    BLACKBIRDSC_API BOOL BLACKBIRDSCSetUserHookTarget(_In_ HANDLE Device, _In_ DWORD Mode, _In_ DWORD ProcessId,
                                                      _In_ DWORD Flags, _In_opt_z_ PCWSTR ImagePath,
                                                      _In_opt_z_ PCWSTR HookDllPath, _In_opt_z_ PCWSTR WorkingDirectory,
                                                      _In_opt_z_ PCWSTR EnvironmentOverrides,
                                                      _In_ DWORD ParentProcessId, _In_ DWORD PriorityClass,
                                                      _In_ UINT64 AffinityMask, _In_ BOOL InheritHandles,
                                                      _Out_opt_ BLACKBIRD_IPC_SET_USER_HOOK_TARGET_RESPONSE *Response);
    BLACKBIRDSC_API BOOL BLACKBIRDSCSetShutdownMode(_In_ HANDLE Device);
    BLACKBIRDSC_API BOOL BLACKBIRDSCControlProcessExecution(_In_ HANDLE Device, _In_ DWORD ProcessId,
                                                            _In_ BOOL Suspend);
    BLACKBIRDSC_API BOOL BLACKBIRDSCGetEtwEvent(_In_ HANDLE Device, _Out_ BLACKBIRD_IPC_ETW_EVENT *Event,
                                                _In_ DWORD TimeoutMs);
    BLACKBIRDSC_API DWORD BLACKBIRDSCParseStreamMaskA(_In_z_ const char *Text);

    BLACKBIRDSC_API ULONG BLACKBIRDSCStopSessionByName(_In_z_ PCWSTR SessionName);
    BLACKBIRDSC_API BOOL BLACKBIRDSCStartEtwSession(_In_ const BLACKBIRDSC_ETW_SESSION_CONFIG *Config,
                                                    _Outptr_ BLACKBIRDSC_ETW_SESSION **Session);
    BLACKBIRDSC_API BOOL BLACKBIRDSCStartBlackbirdEtwSession(
        _In_z_ PCWSTR SessionName, _In_ BOOL EnableThreatIntelProvider, _In_ BLACKBIRDSC_ETW_EVENT_CALLBACK Callback,
        _In_opt_ PVOID CallbackContext, _Outptr_ BLACKBIRDSC_ETW_SESSION **Session, _Out_opt_ BOOL *ThreatIntelEnabled);
    BLACKBIRDSC_API BOOL BLACKBIRDSCStartDetectionEtwSession(
        _In_z_ PCWSTR SessionName, _In_ BOOL EnableThreatIntelProvider, _In_ BLACKBIRDSC_DETECTION_CALLBACK Callback,
        _In_opt_ PVOID CallbackContext, _Outptr_ BLACKBIRDSC_ETW_SESSION **Session,
        _Out_opt_ BOOL *ThreatIntelEnabled);
    BLACKBIRDSC_API ULONG BLACKBIRDSCRunEtwSession(_In_ BLACKBIRDSC_ETW_SESSION *Session);
    BLACKBIRDSC_API VOID BLACKBIRDSCStopEtwSession(_In_opt_ BLACKBIRDSC_ETW_SESSION *Session);

#ifdef __cplusplus
}
#endif

#endif
