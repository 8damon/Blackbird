#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>
#include <strsafe.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sleepwalker_sensor_core.h"
#include "sleepwalker_etw_props.h"

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "tdh.lib")

SLEEPWALKERSC_API const GUID SLEEPWALKERSC_PROVIDER_GUID_SLEEPWALKER = {
    0xd6c73f8a, 0x6ad8, 0x4f4b, {0xa3, 0x63, 0x3d, 0x2f, 0xa3, 0x1c, 0xd0, 0xe2}};
SLEEPWALKERSC_API const GUID SLEEPWALKERSC_PROVIDER_GUID_TI = {
    0xf4e1897c, 0xbb5d, 0x5668, {0xf1, 0xd8, 0x04, 0x0f, 0x4d, 0x8d, 0xd3, 0x44}};

typedef struct _SLEEPWALKERSC_ETW_SESSION
{
    WCHAR SessionName[128];
    TRACEHANDLE SessionHandle;
    TRACEHANDLE TraceHandle;
    SLEEPWALKERSC_ETW_EVENT_CALLBACK Callback;
    PVOID CallbackContext;
    PVOID OwnedCallbackContext;
    volatile LONG ActiveRuns;
    HANDLE RunStoppedEvent;
} SLEEPWALKERSC_ETW_SESSION_INTERNAL;

typedef struct _SLEEPWALKERSC_STG_DETECTION_BRIDGE
{
    SwkDetectionCallback Callback;
    PVOID CallbackContext;
} SLEEPWALKERSC_STG_DETECTION_BRIDGE;

static VOID WINAPI SLEEPWALKERSCInternalRecordCallback(_In_ PEVENT_RECORD Record)
{
    SLEEPWALKERSC_ETW_SESSION_INTERNAL *session;
    PTRACE_EVENT_INFO info = NULL;
    ULONG size = 0;
    TDHSTATUS status;
    PCWSTR eventName = NULL;

    if (Record == NULL)
    {
        return;
    }

    session = (SLEEPWALKERSC_ETW_SESSION_INTERNAL *)Record->UserContext;
    if (session == NULL || session->Callback == NULL)
    {
        return;
    }

    status = TdhGetEventInformation(Record, 0, NULL, NULL, &size);
    if (status == ERROR_INSUFFICIENT_BUFFER && size != 0)
    {
        info = (PTRACE_EVENT_INFO)malloc(size);
        if (info != NULL)
        {
            status = TdhGetEventInformation(Record, 0, NULL, info, &size);
            if (status == ERROR_SUCCESS && info->EventNameOffset != 0)
            {
                eventName = (PCWSTR)(((PBYTE)info) + info->EventNameOffset);
            }
        }
    }

    session->Callback(Record, eventName, session->CallbackContext);

    if (info != NULL)
    {
        free(info);
    }
}

static VOID SLEEPWALKERSCCopyAnsiToWide(_In_z_ const char *Source, _Out_writes_z_(OutputChars) PWSTR Output,
                                        _In_ size_t OutputChars)
{
    int converted;

    if (Output == NULL || OutputChars == 0)
    {
        return;
    }
    Output[0] = L'\0';

    if (Source == NULL || Source[0] == '\0')
    {
        return;
    }

    converted = MultiByteToWideChar(CP_UTF8, 0, Source, -1, Output, (int)OutputChars);
    if (converted <= 0)
    {
        converted = MultiByteToWideChar(CP_ACP, 0, Source, -1, Output, (int)OutputChars);
    }
    if (converted <= 0)
    {
        Output[0] = L'\0';
    }
}

static VOID WINAPI SLEEPWALKERSCStgDetectionBridgeCallback(_In_ PEVENT_RECORD Record, _In_opt_z_ PCWSTR EventName,
                                                           _In_opt_ PVOID Context)
{
    SLEEPWALKERSC_STG_DETECTION_BRIDGE *bridge = (SLEEPWALKERSC_STG_DETECTION_BRIDGE *)Context;
    SwkDetectionEvent event;
    char detectionNameAnsi[128];

    if (Record == NULL || bridge == NULL || bridge->Callback == NULL)
    {
        return;
    }

    if (!IsEqualGUID(&Record->EventHeader.ProviderId, &SLEEPWALKERSC_PROVIDER_GUID_SLEEPWALKER))
    {
        return;
    }

    if (EventName == NULL || wcscmp(EventName, L"DetectionTelemetry") != 0)
    {
        return;
    }

    ZeroMemory(&event, sizeof(event));
    ZeroMemory(detectionNameAnsi, sizeof(detectionNameAnsi));

    event.EtwProcessId = Record->EventHeader.ProcessId;
    event.EtwThreadId = Record->EventHeader.ThreadId;
    event.TimestampQpc = (ULONGLONG)Record->EventHeader.TimeStamp.QuadPart;

    (void)SLEEPWALKERGetU32Property(Record, L"severity", &event.Severity);
    (void)SLEEPWALKERGetU64Property(Record, L"processId", &event.ProcessId);
    (void)SLEEPWALKERGetU64Property(Record, L"targetPid", &event.TargetPid);
    (void)SLEEPWALKERGetU32Property(Record, L"correlationFlags", &event.CorrelationFlags);
    (void)SLEEPWALKERGetU32Property(Record, L"correlationAccessMask", &event.CorrelationAccessMask);
    (void)SLEEPWALKERGetU32Property(Record, L"correlationAgeMs", &event.CorrelationAgeMs);
    (void)SLEEPWALKERGetWideProperty(Record, L"reason", event.Reason, RTL_NUMBER_OF(event.Reason));

    if (SLEEPWALKERGetAnsiProperty(Record, L"detectionName", detectionNameAnsi, RTL_NUMBER_OF(detectionNameAnsi)))
    {
        SLEEPWALKERSCCopyAnsiToWide(detectionNameAnsi, event.DetectionName, RTL_NUMBER_OF(event.DetectionName));
    }
    if (event.DetectionName[0] == L'\0')
    {
        (void)StringCchCopyW(event.DetectionName, RTL_NUMBER_OF(event.DetectionName), L"UNKNOWN");
    }

    bridge->Callback(&event, bridge->CallbackContext);
}

HANDLE
SLEEPWALKERSCOpenControlDevice(VOID)
{
    HANDLE h = CreateFileW(L"\\\\.\\Global\\SleepwalkerCtl", GENERIC_READ | GENERIC_WRITE,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE)
    {
        h = CreateFileW(L"\\\\.\\SleepwalkerCtl", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    }
    return h;
}

BOOL SLEEPWALKERSCSubscribe(_In_ HANDLE Device, _In_ DWORD ProcessId, _In_ DWORD StreamMask)
{
    SLEEPWALKER_SUBSCRIBE_REQUEST req;
    DWORD bytes = 0;

    ZeroMemory(&req, sizeof(req));
    req.ProcessId = ProcessId;
    req.StreamMask = StreamMask;

    return DeviceIoControl(Device, (DWORD)IOCTL_SLEEPWALKER_SUBSCRIBE, &req, sizeof(req), NULL, 0, &bytes, NULL);
}

BOOL SLEEPWALKERSCUnsubscribe(_In_ HANDLE Device, _In_ DWORD ProcessId)
{
    SLEEPWALKER_UNSUBSCRIBE_REQUEST req;
    DWORD bytes = 0;

    ZeroMemory(&req, sizeof(req));
    req.ProcessId = ProcessId;

    return DeviceIoControl(Device, (DWORD)IOCTL_SLEEPWALKER_UNSUBSCRIBE, &req, sizeof(req), NULL, 0, &bytes, NULL);
}

BOOL SLEEPWALKERSCSetPids(_In_ HANDLE Device, _In_reads_(ProcessCount) const DWORD *ProcessIds, _In_ DWORD ProcessCount,
                          _In_ DWORD StreamMask)
{
    SLEEPWALKER_SET_PIDS_REQUEST req;
    DWORD bytes = 0;
    DWORD i;

    if (ProcessIds == NULL || ProcessCount == 0 || ProcessCount > SLEEPWALKER_MAX_PID_LIST)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    ZeroMemory(&req, sizeof(req));
    req.StreamMask = StreamMask;
    req.ProcessCount = ProcessCount;

    for (i = 0; i < ProcessCount; ++i)
    {
        req.ProcessIds[i] = ProcessIds[i];
    }

    return DeviceIoControl(Device, (DWORD)IOCTL_SLEEPWALKER_SET_PIDS, &req, sizeof(req), NULL, 0, &bytes, NULL);
}

BOOL SLEEPWALKERSCGetEvent(_In_ HANDLE Device, _Out_ SLEEPWALKER_EVENT_RECORD *Record, _Out_opt_ DWORD *BytesReturned)
{
    DWORD bytes = 0;
    BOOL ok;

    if (Record == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    ZeroMemory(Record, sizeof(*Record));
    ok = DeviceIoControl(Device, (DWORD)IOCTL_SLEEPWALKER_GET_EVENT, NULL, 0, Record, sizeof(*Record), &bytes, NULL);

    if (BytesReturned != NULL)
    {
        *BytesReturned = bytes;
    }
    return ok;
}

BOOL SLEEPWALKERSCGetStats(_In_ HANDLE Device, _Out_ SLEEPWALKER_STATS_RESPONSE *Stats, _Out_opt_ DWORD *BytesReturned)
{
    DWORD bytes = 0;
    BOOL ok;

    if (Stats == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    ZeroMemory(Stats, sizeof(*Stats));
    ok = DeviceIoControl(Device, (DWORD)IOCTL_SLEEPWALKER_GET_STATS, NULL, 0, Stats, sizeof(*Stats), &bytes, NULL);

    if (BytesReturned != NULL)
    {
        *BytesReturned = bytes;
    }
    return ok;
}

BOOL SLEEPWALKERSCQueryProcessImagePath(_In_ HANDLE Device, _In_ DWORD ProcessId,
                                        _Out_writes_z_(OutputChars) PWSTR Output, _In_ DWORD OutputChars)
{
    SLEEPWALKER_QUERY_PROCESS_IMAGE_REQUEST req;
    SLEEPWALKER_QUERY_PROCESS_IMAGE_RESPONSE resp;
    DWORD bytes = 0;
    BOOL ok;

    if (Output == NULL || OutputChars == 0 || ProcessId == 0)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    Output[0] = L'\0';

    ZeroMemory(&req, sizeof(req));
    ZeroMemory(&resp, sizeof(resp));
    req.ProcessId = ProcessId;

    ok = DeviceIoControl(Device, (DWORD)IOCTL_SLEEPWALKER_QUERY_PROCESS_IMAGE, &req, sizeof(req), &resp, sizeof(resp),
                         &bytes, NULL);
    if (!ok)
    {
        return FALSE;
    }
    if (bytes < sizeof(resp.ProcessId) + sizeof(resp.Status))
    {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }
    if (!NT_SUCCESS(resp.Status) || resp.ImagePath[0] == L'\0')
    {
        SetLastError(ERROR_NOT_FOUND);
        return FALSE;
    }
    if (FAILED(StringCchCopyW(Output, OutputChars, resp.ImagePath)))
    {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }
    return TRUE;
}

BOOL SLEEPWALKERSCSetShutdownMode(_In_ HANDLE Device)
{
    DWORD bytes = 0;

    return DeviceIoControl(Device, (DWORD)IOCTL_SLEEPWALKER_SET_SHUTDOWN_MODE, NULL, 0, NULL, 0, &bytes, NULL);
}

DWORD
SLEEPWALKERSCParseStreamMaskA(_In_z_ const char *Text)
{
    DWORD mask = 0;
    char *copy;
    char *tok;
    char *ctx = NULL;

    if (Text == NULL)
    {
        return 0;
    }

    copy = _strdup(Text);
    if (copy == NULL)
    {
        return 0;
    }

    for (tok = strtok_s(copy, ",", &ctx); tok != NULL; tok = strtok_s(NULL, ",", &ctx))
    {
        if (_stricmp(tok, "handle") == 0)
        {
            mask |= SLEEPWALKER_STREAM_HANDLE;
        }
        else if (_stricmp(tok, "memory") == 0)
        {
            mask |= SLEEPWALKER_STREAM_MEMORY;
        }
        else if (_stricmp(tok, "thread") == 0)
        {
            mask |= SLEEPWALKER_STREAM_THREAD;
        }
    }

    free(copy);
    return mask;
}

ULONG
SLEEPWALKERSCStopSessionByName(_In_z_ PCWSTR SessionName)
{
    ULONG status;
    const ULONG propsBytes = sizeof(EVENT_TRACE_PROPERTIES) + (1024 * sizeof(WCHAR));
    PEVENT_TRACE_PROPERTIES props = (PEVENT_TRACE_PROPERTIES)calloc(1, propsBytes);
    PWSTR loggerName;

    if (SessionName == NULL)
    {
        return ERROR_INVALID_PARAMETER;
    }
    if (props == NULL)
    {
        return ERROR_OUTOFMEMORY;
    }

    props->Wnode.BufferSize = propsBytes;
    props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    loggerName = (PWSTR)((PBYTE)props + props->LoggerNameOffset);
    (void)StringCchCopyW(loggerName, 512, SessionName);

    status = ControlTraceW(0, SessionName, props, EVENT_TRACE_CONTROL_STOP);
    free(props);

    if (status == ERROR_WMI_INSTANCE_NOT_FOUND)
    {
        return ERROR_SUCCESS;
    }
    return status;
}

BOOL SLEEPWALKERSCStartEtwSession(_In_ const SLEEPWALKERSC_ETW_SESSION_CONFIG *Config,
                                  _Outptr_ SLEEPWALKERSC_ETW_SESSION **Session)
{
    SLEEPWALKERSC_ETW_SESSION_INTERNAL *internal = NULL;
    EVENT_TRACE_LOGFILEW log;
    PEVENT_TRACE_PROPERTIES props = NULL;
    PWSTR loggerName;
    ULONG propsBytes;
    ULONG status;
    ULONG i;
    ULONG startAttempt;

    if (Session != NULL)
    {
        *Session = NULL;
    }
    if (Config == NULL || Session == NULL || Config->SessionName == NULL || Config->Providers == NULL ||
        Config->ProviderCount == 0 || Config->Callback == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    internal = (SLEEPWALKERSC_ETW_SESSION_INTERNAL *)calloc(1, sizeof(*internal));
    if (internal == NULL)
    {
        SetLastError(ERROR_OUTOFMEMORY);
        return FALSE;
    }

    (void)StringCchCopyW(internal->SessionName, RTL_NUMBER_OF(internal->SessionName), Config->SessionName);
    internal->Callback = Config->Callback;
    internal->CallbackContext = Config->CallbackContext;
    internal->RunStoppedEvent = CreateEventW(NULL, TRUE, TRUE, NULL);
    if (internal->RunStoppedEvent == NULL)
    {
        free(internal);
        return FALSE;
    }

    (void)SLEEPWALKERSCStopSessionByName(internal->SessionName);
    Sleep(80);

    propsBytes = sizeof(EVENT_TRACE_PROPERTIES) + (1024 * sizeof(WCHAR));
    props = (PEVENT_TRACE_PROPERTIES)calloc(1, propsBytes);
    if (props == NULL)
    {
        CloseHandle(internal->RunStoppedEvent);
        free(internal);
        SetLastError(ERROR_OUTOFMEMORY);
        return FALSE;
    }

    props->Wnode.BufferSize = propsBytes;
    props->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    props->Wnode.ClientContext = 1;
    props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    loggerName = (PWSTR)((PBYTE)props + props->LoggerNameOffset);
    (void)StringCchCopyW(loggerName, 512, internal->SessionName);

    status = ERROR_GEN_FAILURE;
    for (startAttempt = 0; startAttempt < 6; ++startAttempt)
    {
        status = StartTraceW(&internal->SessionHandle, internal->SessionName, props);
        if (status == ERROR_SUCCESS)
        {
            break;
        }
        if (status == ERROR_ALREADY_EXISTS)
        {
            (void)SLEEPWALKERSCStopSessionByName(internal->SessionName);
            Sleep(120);
            continue;
        }
        break;
    }

    if (status != ERROR_SUCCESS)
    {
        free(props);
        CloseHandle(internal->RunStoppedEvent);
        free(internal);
        SetLastError(status);
        return FALSE;
    }

    for (i = 0; i < Config->ProviderCount; ++i)
    {
        status = EnableTraceEx2(internal->SessionHandle, &Config->Providers[i].ProviderId,
                                EVENT_CONTROL_CODE_ENABLE_PROVIDER, Config->Providers[i].Level,
                                Config->Providers[i].MatchAnyKeyword, Config->Providers[i].MatchAllKeyword, 0, NULL);
        if (status != ERROR_SUCCESS)
        {
            (void)SLEEPWALKERSCStopSessionByName(internal->SessionName);
            free(props);
            CloseHandle(internal->RunStoppedEvent);
            free(internal);
            SetLastError(status);
            return FALSE;
        }
    }

    ZeroMemory(&log, sizeof(log));
    log.LoggerName = internal->SessionName;
    log.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    log.EventRecordCallback = SLEEPWALKERSCInternalRecordCallback;
    log.Context = internal;

    internal->TraceHandle = OpenTraceW(&log);
    if (internal->TraceHandle == INVALID_PROCESSTRACE_HANDLE)
    {
        status = GetLastError();
        (void)SLEEPWALKERSCStopSessionByName(internal->SessionName);
        free(props);
        CloseHandle(internal->RunStoppedEvent);
        free(internal);
        SetLastError(status);
        return FALSE;
    }

    free(props);
    *Session = (SLEEPWALKERSC_ETW_SESSION *)internal;
    return TRUE;
}

BOOL SLEEPWALKERSCStartSleepwalkerEtwSession(_In_z_ PCWSTR SessionName, _In_ BOOL EnableThreatIntelProvider,
                                             _In_ SLEEPWALKERSC_ETW_EVENT_CALLBACK Callback,
                                             _In_opt_ PVOID CallbackContext,
                                             _Outptr_ SLEEPWALKERSC_ETW_SESSION **Session,
                                             _Out_opt_ BOOL *ThreatIntelEnabled)
{
    SLEEPWALKERSC_ETW_PROVIDER_CONFIG providers[2];
    SLEEPWALKERSC_ETW_PROVIDER_CONFIG sleepwalkerOnlyProvider;
    SLEEPWALKERSC_ETW_SESSION_CONFIG config;
    BOOL started = FALSE;
    BOOL startedWithTi = FALSE;
    DWORD err = ERROR_SUCCESS;

    if (ThreatIntelEnabled != NULL)
    {
        *ThreatIntelEnabled = FALSE;
    }
    if (Session != NULL)
    {
        *Session = NULL;
    }

    if (SessionName == NULL || Callback == NULL || Session == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    ZeroMemory(&providers, sizeof(providers));
    providers[0].ProviderId = SLEEPWALKERSC_PROVIDER_GUID_SLEEPWALKER;
    providers[0].Level = TRACE_LEVEL_INFORMATION;
    providers[0].MatchAnyKeyword = 0;
    providers[0].MatchAllKeyword = 0;
    providers[1].ProviderId = SLEEPWALKERSC_PROVIDER_GUID_TI;
    providers[1].Level = TRACE_LEVEL_INFORMATION;
    providers[1].MatchAnyKeyword = ~0ULL;
    providers[1].MatchAllKeyword = 0;

    ZeroMemory(&config, sizeof(config));
    config.SessionName = SessionName;
    config.Providers = EnableThreatIntelProvider ? providers : &providers[0];
    config.ProviderCount = EnableThreatIntelProvider ? 2 : 1;
    config.Callback = Callback;
    config.CallbackContext = CallbackContext;

    (void)SLEEPWALKERSCStopSessionByName(SessionName);
    Sleep(80);

    if (SLEEPWALKERSCStartEtwSession(&config, Session))
    {
        started = TRUE;
        startedWithTi = EnableThreatIntelProvider ? TRUE : FALSE;
    }
    else
    {
        err = GetLastError();
    }

    if (!started && EnableThreatIntelProvider && err == ERROR_ACCESS_DENIED)
    {
        sleepwalkerOnlyProvider = providers[0];
        config.Providers = &sleepwalkerOnlyProvider;
        config.ProviderCount = 1;
        if (SLEEPWALKERSCStartEtwSession(&config, Session))
        {
            started = TRUE;
            startedWithTi = FALSE;
        }
        else
        {
            err = GetLastError();
        }
    }

    if (!started)
    {
        SetLastError(err);
        return FALSE;
    }

    if (ThreatIntelEnabled != NULL)
    {
        *ThreatIntelEnabled = startedWithTi;
    }
    return TRUE;
}

BOOL SwkStartDetectionEtwSession(_In_z_ PCWSTR SessionName, _In_ BOOL EnableThreatIntelProvider,
                                 _In_ SwkDetectionCallback Callback, _In_opt_ PVOID CallbackContext,
                                 _Outptr_ SLEEPWALKERSC_ETW_SESSION **Session, _Out_opt_ BOOL *ThreatIntelEnabled)
{
    SLEEPWALKERSC_STG_DETECTION_BRIDGE *bridge;
    SLEEPWALKERSC_ETW_SESSION_INTERNAL *internal;
    DWORD err;

    if (ThreatIntelEnabled != NULL)
    {
        *ThreatIntelEnabled = FALSE;
    }
    if (Session != NULL)
    {
        *Session = NULL;
    }

    if (SessionName == NULL || Callback == NULL || Session == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    bridge = (SLEEPWALKERSC_STG_DETECTION_BRIDGE *)calloc(1, sizeof(*bridge));
    if (bridge == NULL)
    {
        SetLastError(ERROR_OUTOFMEMORY);
        return FALSE;
    }

    bridge->Callback = Callback;
    bridge->CallbackContext = CallbackContext;

    if (!SLEEPWALKERSCStartSleepwalkerEtwSession(SessionName, EnableThreatIntelProvider,
                                                 SLEEPWALKERSCStgDetectionBridgeCallback, bridge, Session,
                                                 ThreatIntelEnabled))
    {
        err = GetLastError();
        free(bridge);
        SetLastError(err);
        return FALSE;
    }

    internal = (SLEEPWALKERSC_ETW_SESSION_INTERNAL *)(*Session);
    if (internal == NULL)
    {
        free(bridge);
        SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }
    internal->OwnedCallbackContext = bridge;
    return TRUE;
}

ULONG
SLEEPWALKERSCRunEtwSession(_In_ SLEEPWALKERSC_ETW_SESSION *Session)
{
    SLEEPWALKERSC_ETW_SESSION_INTERNAL *internal = (SLEEPWALKERSC_ETW_SESSION_INTERNAL *)Session;

    if (internal == NULL || internal->TraceHandle == 0 || internal->TraceHandle == INVALID_PROCESSTRACE_HANDLE)
    {
        return ERROR_INVALID_PARAMETER;
    }

    InterlockedIncrement(&internal->ActiveRuns);
    (void)ResetEvent(internal->RunStoppedEvent);

    {
        ULONG status = ProcessTrace(&internal->TraceHandle, 1, NULL, NULL);
        if (InterlockedDecrement(&internal->ActiveRuns) == 0)
        {
            (void)SetEvent(internal->RunStoppedEvent);
        }
        return status;
    }
}

VOID SLEEPWALKERSCStopEtwSession(_In_opt_ SLEEPWALKERSC_ETW_SESSION *Session)
{
    SLEEPWALKERSC_ETW_SESSION_INTERNAL *internal = (SLEEPWALKERSC_ETW_SESSION_INTERNAL *)Session;

    if (internal == NULL)
    {
        return;
    }

    if (internal->TraceHandle != 0 && internal->TraceHandle != INVALID_PROCESSTRACE_HANDLE)
    {
        CloseTrace(internal->TraceHandle);
        internal->TraceHandle = 0;
    }

    if (internal->SessionHandle != 0)
    {
        (void)SLEEPWALKERSCStopSessionByName(internal->SessionName);
        internal->SessionHandle = 0;
    }

    if (internal->RunStoppedEvent != NULL && InterlockedCompareExchange(&internal->ActiveRuns, 0, 0) > 0)
    {
        (void)WaitForSingleObject(internal->RunStoppedEvent, 10000);
    }

    if (internal->RunStoppedEvent != NULL)
    {
        CloseHandle(internal->RunStoppedEvent);
        internal->RunStoppedEvent = NULL;
    }

    if (internal->OwnedCallbackContext != NULL)
    {
        free(internal->OwnedCallbackContext);
        internal->OwnedCallbackContext = NULL;
    }

    free(internal);
}
