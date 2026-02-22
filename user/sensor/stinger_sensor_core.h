#ifndef STINGER_SENSOR_CORE_H
#define STINGER_SENSOR_CORE_H

#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <winioctl.h>
#include "..\..\abi\stinger_ioctl.h"

#ifdef STINGERSC_EXPORTS
#define STINGERSC_API __declspec(dllexport)
#else
#define STINGERSC_API __declspec(dllimport)
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _STINGERSC_ETW_PROVIDER_CONFIG {
    GUID ProviderId;
    UCHAR Level;
    ULONGLONG MatchAnyKeyword;
    ULONGLONG MatchAllKeyword;
} STINGERSC_ETW_PROVIDER_CONFIG, *PSTINGERSC_ETW_PROVIDER_CONFIG;

typedef VOID(WINAPI* STINGERSC_ETW_EVENT_CALLBACK)(
    _In_ PEVENT_RECORD Record,
    _In_opt_z_ PCWSTR EventName,
    _In_opt_ PVOID Context
);

typedef struct _STINGERSC_ETW_SESSION_CONFIG {
    _In_z_ PCWSTR SessionName;
    _In_reads_(ProviderCount) const STINGERSC_ETW_PROVIDER_CONFIG* Providers;
    ULONG ProviderCount;
    STINGERSC_ETW_EVENT_CALLBACK Callback;
    PVOID CallbackContext;
} STINGERSC_ETW_SESSION_CONFIG, *PSTINGERSC_ETW_SESSION_CONFIG;

typedef struct _STINGERSC_ETW_SESSION STINGERSC_ETW_SESSION;

STINGERSC_API HANDLE STINGERSCOpenControlDevice(VOID);
STINGERSC_API BOOL STINGERSCSubscribe(_In_ HANDLE Device, _In_ DWORD ProcessId, _In_ DWORD StreamMask);
STINGERSC_API BOOL STINGERSCUnsubscribe(_In_ HANDLE Device, _In_ DWORD ProcessId);
STINGERSC_API BOOL STINGERSCGetEvent(
    _In_ HANDLE Device,
    _Out_ STINGER_EVENT_RECORD* Record,
    _Out_opt_ DWORD* BytesReturned
);
STINGERSC_API BOOL STINGERSCGetStats(
    _In_ HANDLE Device,
    _Out_ STINGER_STATS_RESPONSE* Stats,
    _Out_opt_ DWORD* BytesReturned
);
STINGERSC_API DWORD STINGERSCParseStreamMaskA(_In_z_ const char* Text);

STINGERSC_API ULONG STINGERSCStopSessionByName(_In_z_ PCWSTR SessionName);
STINGERSC_API BOOL STINGERSCStartEtwSession(
    _In_ const STINGERSC_ETW_SESSION_CONFIG* Config,
    _Outptr_ STINGERSC_ETW_SESSION** Session
);
STINGERSC_API ULONG STINGERSCRunEtwSession(_In_ STINGERSC_ETW_SESSION* Session);
STINGERSC_API VOID STINGERSCStopEtwSession(_In_opt_ STINGERSC_ETW_SESSION* Session);

#ifdef __cplusplus
}
#endif

#endif
