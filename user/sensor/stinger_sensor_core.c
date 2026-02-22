#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>
#include <strsafe.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "stinger_sensor_core.h"

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "tdh.lib")

typedef struct _STINGERSC_ETW_SESSION {
    WCHAR SessionName[128];
    TRACEHANDLE SessionHandle;
    TRACEHANDLE TraceHandle;
    STINGERSC_ETW_EVENT_CALLBACK Callback;
    PVOID CallbackContext;
    volatile LONG ActiveRuns;
    HANDLE RunStoppedEvent;
} STINGERSC_ETW_SESSION_INTERNAL;

static
VOID WINAPI
STINGERSCInternalRecordCallback(_In_ PEVENT_RECORD Record)
{
    STINGERSC_ETW_SESSION_INTERNAL* session;
    PTRACE_EVENT_INFO info = NULL;
    ULONG size = 0;
    TDHSTATUS status;
    PCWSTR eventName = NULL;

    if (Record == NULL) {
        return;
    }

    session = (STINGERSC_ETW_SESSION_INTERNAL*)Record->UserContext;
    if (session == NULL || session->Callback == NULL) {
        return;
    }

    status = TdhGetEventInformation(Record, 0, NULL, NULL, &size);
    if (status == ERROR_INSUFFICIENT_BUFFER && size != 0) {
        info = (PTRACE_EVENT_INFO)malloc(size);
        if (info != NULL) {
            status = TdhGetEventInformation(Record, 0, NULL, info, &size);
            if (status == ERROR_SUCCESS && info->EventNameOffset != 0) {
                eventName = (PCWSTR)(((PBYTE)info) + info->EventNameOffset);
            }
        }
    }

    session->Callback(Record, eventName, session->CallbackContext);

    if (info != NULL) {
        free(info);
    }
}

HANDLE
STINGERSCOpenControlDevice(
    VOID
)
{
    HANDLE h = CreateFileW(
        L"\\\\.\\Global\\StingerCtl",
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    if (h == INVALID_HANDLE_VALUE) {
        h = CreateFileW(
            L"\\\\.\\StingerCtl",
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL
        );
    }
    return h;
}

BOOL
STINGERSCSubscribe(
    _In_ HANDLE Device,
    _In_ DWORD ProcessId,
    _In_ DWORD StreamMask
)
{
    STINGER_SUBSCRIBE_REQUEST req;
    DWORD bytes = 0;

    ZeroMemory(&req, sizeof(req));
    req.ProcessId = ProcessId;
    req.StreamMask = StreamMask;

    return DeviceIoControl(
        Device,
        (DWORD)IOCTL_STINGER_SUBSCRIBE,
        &req,
        sizeof(req),
        NULL,
        0,
        &bytes,
        NULL
    );
}

BOOL
STINGERSCUnsubscribe(
    _In_ HANDLE Device,
    _In_ DWORD ProcessId
)
{
    STINGER_UNSUBSCRIBE_REQUEST req;
    DWORD bytes = 0;

    ZeroMemory(&req, sizeof(req));
    req.ProcessId = ProcessId;

    return DeviceIoControl(
        Device,
        (DWORD)IOCTL_STINGER_UNSUBSCRIBE,
        &req,
        sizeof(req),
        NULL,
        0,
        &bytes,
        NULL
    );
}

BOOL
STINGERSCGetEvent(
    _In_ HANDLE Device,
    _Out_ STINGER_EVENT_RECORD* Record,
    _Out_opt_ DWORD* BytesReturned
)
{
    DWORD bytes = 0;
    BOOL ok;

    if (Record == NULL) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    ZeroMemory(Record, sizeof(*Record));
    ok = DeviceIoControl(
        Device,
        (DWORD)IOCTL_STINGER_GET_EVENT,
        NULL,
        0,
        Record,
        sizeof(*Record),
        &bytes,
        NULL
    );

    if (BytesReturned != NULL) {
        *BytesReturned = bytes;
    }
    return ok;
}

BOOL
STINGERSCGetStats(
    _In_ HANDLE Device,
    _Out_ STINGER_STATS_RESPONSE* Stats,
    _Out_opt_ DWORD* BytesReturned
)
{
    DWORD bytes = 0;
    BOOL ok;

    if (Stats == NULL) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    ZeroMemory(Stats, sizeof(*Stats));
    ok = DeviceIoControl(
        Device,
        (DWORD)IOCTL_STINGER_GET_STATS,
        NULL,
        0,
        Stats,
        sizeof(*Stats),
        &bytes,
        NULL
    );

    if (BytesReturned != NULL) {
        *BytesReturned = bytes;
    }
    return ok;
}

DWORD
STINGERSCParseStreamMaskA(
    _In_z_ const char* Text
)
{
    DWORD mask = 0;
    char* copy;
    char* tok;
    char* ctx = NULL;

    if (Text == NULL) {
        return 0;
    }

    copy = _strdup(Text);
    if (copy == NULL) {
        return 0;
    }

    for (tok = strtok_s(copy, ",", &ctx); tok != NULL; tok = strtok_s(NULL, ",", &ctx)) {
        if (_stricmp(tok, "handle") == 0) {
            mask |= STINGER_STREAM_HANDLE;
        } else if (_stricmp(tok, "memory") == 0) {
            mask |= STINGER_STREAM_MEMORY;
        } else if (_stricmp(tok, "thread") == 0) {
            mask |= STINGER_STREAM_THREAD;
        }
    }

    free(copy);
    return mask;
}

ULONG
STINGERSCStopSessionByName(
    _In_z_ PCWSTR SessionName
)
{
    ULONG status;
    const ULONG propsBytes = sizeof(EVENT_TRACE_PROPERTIES) + (1024 * sizeof(WCHAR));
    PEVENT_TRACE_PROPERTIES props = (PEVENT_TRACE_PROPERTIES)calloc(1, propsBytes);
    PWSTR loggerName;

    if (SessionName == NULL) {
        return ERROR_INVALID_PARAMETER;
    }
    if (props == NULL) {
        return ERROR_OUTOFMEMORY;
    }

    props->Wnode.BufferSize = propsBytes;
    props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    loggerName = (PWSTR)((PBYTE)props + props->LoggerNameOffset);
    (void)StringCchCopyW(loggerName, 512, SessionName);

    status = ControlTraceW(0, SessionName, props, EVENT_TRACE_CONTROL_STOP);
    free(props);

    if (status == ERROR_WMI_INSTANCE_NOT_FOUND) {
        return ERROR_SUCCESS;
    }
    return status;
}

BOOL
STINGERSCStartEtwSession(
    _In_ const STINGERSC_ETW_SESSION_CONFIG* Config,
    _Outptr_ STINGERSC_ETW_SESSION** Session
)
{
    STINGERSC_ETW_SESSION_INTERNAL* internal = NULL;
    EVENT_TRACE_LOGFILEW log;
    PEVENT_TRACE_PROPERTIES props = NULL;
    PWSTR loggerName;
    ULONG propsBytes;
    ULONG status;
    ULONG i;
    ULONG startAttempt;

    if (Session != NULL) {
        *Session = NULL;
    }
    if (Config == NULL || Session == NULL || Config->SessionName == NULL ||
        Config->Providers == NULL || Config->ProviderCount == 0 || Config->Callback == NULL) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    internal = (STINGERSC_ETW_SESSION_INTERNAL*)calloc(1, sizeof(*internal));
    if (internal == NULL) {
        SetLastError(ERROR_OUTOFMEMORY);
        return FALSE;
    }

    (void)StringCchCopyW(internal->SessionName, RTL_NUMBER_OF(internal->SessionName), Config->SessionName);
    internal->Callback = Config->Callback;
    internal->CallbackContext = Config->CallbackContext;
    internal->RunStoppedEvent = CreateEventW(NULL, TRUE, TRUE, NULL);
    if (internal->RunStoppedEvent == NULL) {
        free(internal);
        return FALSE;
    }

    (void)STINGERSCStopSessionByName(internal->SessionName);
    Sleep(80);

    propsBytes = sizeof(EVENT_TRACE_PROPERTIES) + (1024 * sizeof(WCHAR));
    props = (PEVENT_TRACE_PROPERTIES)calloc(1, propsBytes);
    if (props == NULL) {
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
    for (startAttempt = 0; startAttempt < 6; ++startAttempt) {
        status = StartTraceW(&internal->SessionHandle, internal->SessionName, props);
        if (status == ERROR_SUCCESS) {
            break;
        }
        if (status == ERROR_ALREADY_EXISTS) {
            (void)STINGERSCStopSessionByName(internal->SessionName);
            Sleep(120);
            continue;
        }
        break;
    }

    if (status != ERROR_SUCCESS) {
        free(props);
        CloseHandle(internal->RunStoppedEvent);
        free(internal);
        SetLastError(status);
        return FALSE;
    }

    for (i = 0; i < Config->ProviderCount; ++i) {
        status = EnableTraceEx2(
            internal->SessionHandle,
            &Config->Providers[i].ProviderId,
            EVENT_CONTROL_CODE_ENABLE_PROVIDER,
            Config->Providers[i].Level,
            Config->Providers[i].MatchAnyKeyword,
            Config->Providers[i].MatchAllKeyword,
            0,
            NULL
        );
        if (status != ERROR_SUCCESS) {
            (void)STINGERSCStopSessionByName(internal->SessionName);
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
    log.EventRecordCallback = STINGERSCInternalRecordCallback;
    log.Context = internal;

    internal->TraceHandle = OpenTraceW(&log);
    if (internal->TraceHandle == INVALID_PROCESSTRACE_HANDLE) {
        status = GetLastError();
        (void)STINGERSCStopSessionByName(internal->SessionName);
        free(props);
        CloseHandle(internal->RunStoppedEvent);
        free(internal);
        SetLastError(status);
        return FALSE;
    }

    free(props);
    *Session = (STINGERSC_ETW_SESSION*)internal;
    return TRUE;
}

ULONG
STINGERSCRunEtwSession(
    _In_ STINGERSC_ETW_SESSION* Session
)
{
    STINGERSC_ETW_SESSION_INTERNAL* internal = (STINGERSC_ETW_SESSION_INTERNAL*)Session;

    if (internal == NULL || internal->TraceHandle == 0 || internal->TraceHandle == INVALID_PROCESSTRACE_HANDLE) {
        return ERROR_INVALID_PARAMETER;
    }

    InterlockedIncrement(&internal->ActiveRuns);
    (void)ResetEvent(internal->RunStoppedEvent);

    {
        ULONG status = ProcessTrace(&internal->TraceHandle, 1, NULL, NULL);
        if (InterlockedDecrement(&internal->ActiveRuns) == 0) {
            (void)SetEvent(internal->RunStoppedEvent);
        }
        return status;
    }
}

VOID
STINGERSCStopEtwSession(
    _In_opt_ STINGERSC_ETW_SESSION* Session
)
{
    STINGERSC_ETW_SESSION_INTERNAL* internal = (STINGERSC_ETW_SESSION_INTERNAL*)Session;

    if (internal == NULL) {
        return;
    }

    if (internal->TraceHandle != 0 && internal->TraceHandle != INVALID_PROCESSTRACE_HANDLE) {
        CloseTrace(internal->TraceHandle);
        internal->TraceHandle = 0;
    }

    if (internal->SessionHandle != 0) {
        (void)STINGERSCStopSessionByName(internal->SessionName);
        internal->SessionHandle = 0;
    }

    if (internal->RunStoppedEvent != NULL && InterlockedCompareExchange(&internal->ActiveRuns, 0, 0) > 0) {
        (void)WaitForSingleObject(internal->RunStoppedEvent, 10000);
    }

    if (internal->RunStoppedEvent != NULL) {
        CloseHandle(internal->RunStoppedEvent);
        internal->RunStoppedEvent = NULL;
    }

    free(internal);
}
