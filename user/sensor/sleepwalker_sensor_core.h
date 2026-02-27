#ifndef SLEEPWALKER_SENSOR_CORE_H
#define SLEEPWALKER_SENSOR_CORE_H

#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <winioctl.h>
#include "..\..\abi\sleepwalker_ioctl.h"

#ifdef SLEEPWALKERSC_EXPORTS
#define SLEEPWALKERSC_API __declspec(dllexport)
#else
#define SLEEPWALKERSC_API __declspec(dllimport)
#endif

#ifdef __cplusplus
extern "C"
{
#endif

    typedef struct _SLEEPWALKERSC_ETW_PROVIDER_CONFIG
    {
        GUID ProviderId;
        UCHAR Level;
        ULONGLONG MatchAnyKeyword;
        ULONGLONG MatchAllKeyword;
    } SLEEPWALKERSC_ETW_PROVIDER_CONFIG, *PSLEEPWALKERSC_ETW_PROVIDER_CONFIG;

    typedef VOID(WINAPI *SLEEPWALKERSC_ETW_EVENT_CALLBACK)(_In_ PEVENT_RECORD Record, _In_opt_z_ PCWSTR EventName,
                                                           _In_opt_ PVOID Context);

    typedef struct _SLEEPWALKERSC_ETW_SESSION_CONFIG
    {
        _In_z_ PCWSTR SessionName;
        _In_reads_(ProviderCount) const SLEEPWALKERSC_ETW_PROVIDER_CONFIG *Providers;
        ULONG ProviderCount;
        SLEEPWALKERSC_ETW_EVENT_CALLBACK Callback;
        PVOID CallbackContext;
    } SLEEPWALKERSC_ETW_SESSION_CONFIG, *PSLEEPWALKERSC_ETW_SESSION_CONFIG;

    typedef struct _SLEEPWALKERSC_ETW_SESSION SLEEPWALKERSC_ETW_SESSION;

    typedef struct _StgDetectionEvent
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
    } SwkDetectionEvent, *PStgDetectionEvent;

    typedef VOID(WINAPI *SwkDetectionCallback)(_In_ const SwkDetectionEvent *Event, _In_opt_ PVOID Context);

    extern SLEEPWALKERSC_API const GUID SLEEPWALKERSC_PROVIDER_GUID_SLEEPWALKER;
    extern SLEEPWALKERSC_API const GUID SLEEPWALKERSC_PROVIDER_GUID_TI;

    SLEEPWALKERSC_API HANDLE SLEEPWALKERSCOpenControlDevice(VOID);
    SLEEPWALKERSC_API BOOL SLEEPWALKERSCSubscribe(_In_ HANDLE Device, _In_ DWORD ProcessId, _In_ DWORD StreamMask);
    SLEEPWALKERSC_API BOOL SLEEPWALKERSCUnsubscribe(_In_ HANDLE Device, _In_ DWORD ProcessId);
    SLEEPWALKERSC_API BOOL SLEEPWALKERSCSetPids(_In_ HANDLE Device, _In_reads_(ProcessCount) const DWORD *ProcessIds,
                                                _In_ DWORD ProcessCount, _In_ DWORD StreamMask);
    SLEEPWALKERSC_API BOOL SLEEPWALKERSCGetEvent(_In_ HANDLE Device, _Out_ SLEEPWALKER_EVENT_RECORD *Record,
                                                 _Out_opt_ DWORD *BytesReturned);
    SLEEPWALKERSC_API BOOL SLEEPWALKERSCGetStats(_In_ HANDLE Device, _Out_ SLEEPWALKER_STATS_RESPONSE *Stats,
                                                 _Out_opt_ DWORD *BytesReturned);
    SLEEPWALKERSC_API BOOL SLEEPWALKERSCQueryProcessImagePath(_In_ HANDLE Device, _In_ DWORD ProcessId,
                                                              _Out_writes_z_(OutputChars) PWSTR Output,
                                                              _In_ DWORD OutputChars);
    SLEEPWALKERSC_API BOOL SLEEPWALKERSCSetShutdownMode(_In_ HANDLE Device);
    SLEEPWALKERSC_API DWORD SLEEPWALKERSCParseStreamMaskA(_In_z_ const char *Text);

    SLEEPWALKERSC_API ULONG SLEEPWALKERSCStopSessionByName(_In_z_ PCWSTR SessionName);
    SLEEPWALKERSC_API BOOL SLEEPWALKERSCStartEtwSession(_In_ const SLEEPWALKERSC_ETW_SESSION_CONFIG *Config,
                                                        _Outptr_ SLEEPWALKERSC_ETW_SESSION **Session);
    SLEEPWALKERSC_API BOOL SLEEPWALKERSCStartSleepwalkerEtwSession(_In_z_ PCWSTR SessionName,
                                                                   _In_ BOOL EnableThreatIntelProvider,
                                                                   _In_ SLEEPWALKERSC_ETW_EVENT_CALLBACK Callback,
                                                                   _In_opt_ PVOID CallbackContext,
                                                                   _Outptr_ SLEEPWALKERSC_ETW_SESSION **Session,
                                                                   _Out_opt_ BOOL *ThreatIntelEnabled);
    SLEEPWALKERSC_API BOOL SwkStartDetectionEtwSession(_In_z_ PCWSTR SessionName, _In_ BOOL EnableThreatIntelProvider,
                                                       _In_ SwkDetectionCallback Callback,
                                                       _In_opt_ PVOID CallbackContext,
                                                       _Outptr_ SLEEPWALKERSC_ETW_SESSION **Session,
                                                       _Out_opt_ BOOL *ThreatIntelEnabled);
    SLEEPWALKERSC_API ULONG SLEEPWALKERSCRunEtwSession(_In_ SLEEPWALKERSC_ETW_SESSION *Session);
    SLEEPWALKERSC_API VOID SLEEPWALKERSCStopEtwSession(_In_opt_ SLEEPWALKERSC_ETW_SESSION *Session);

#ifdef __cplusplus
}
#endif

#endif
