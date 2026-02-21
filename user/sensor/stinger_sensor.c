#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <evntrace.h>
#include <tdh.h>
#include <strsafe.h>
#include <stdio.h>
#include <stdlib.h>
#include "stinger_etw_printer.h"
#include "stinger_etw_symbols.h"

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "tdh.lib")

// {D6C73F8A-6AD8-4F4B-A363-3D2FA31CD0E2}
static const GUID STINGER_PROVIDER_GUID =
{ 0xd6c73f8a, 0x6ad8, 0x4f4b, { 0xa3, 0x63, 0x3d, 0x2f, 0xa3, 0x1c, 0xd0, 0xe2 } };

static const WCHAR* STINGER_SESSION_NAME = L"StingerSensorSession";
static TRACEHANDLE g_SessionHandle = 0;
static TRACEHANDLE g_TraceHandle = 0;
static volatile LONG g_StopRequested = 0;

static ULONG
StopSessionByName(void)
{
    ULONG status;
    const ULONG propsBytes = sizeof(EVENT_TRACE_PROPERTIES) + (1024 * sizeof(WCHAR));
    PEVENT_TRACE_PROPERTIES props = (PEVENT_TRACE_PROPERTIES)calloc(1, propsBytes);
    PWSTR loggerName;

    if (props == NULL) {
        return ERROR_OUTOFMEMORY;
    }

    props->Wnode.BufferSize = propsBytes;
    props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    loggerName = (PWSTR)((PBYTE)props + props->LoggerNameOffset);
    (void)StringCchCopyW(loggerName, 512, STINGER_SESSION_NAME);

    status = ControlTraceW(0, STINGER_SESSION_NAME, props, EVENT_TRACE_CONTROL_STOP);
    free(props);
    return status;
}

static VOID WINAPI
EventRecordCallback(_In_ PEVENT_RECORD Record)
{
    PTRACE_EVENT_INFO info = NULL;
    ULONG size = 0;
    TDHSTATUS status;
    PWSTR eventName;

    if (Record == NULL) {
        return;
    }

    if (Record->EventHeader.ProviderId.Data1 != STINGER_PROVIDER_GUID.Data1 ||
        Record->EventHeader.ProviderId.Data2 != STINGER_PROVIDER_GUID.Data2 ||
        Record->EventHeader.ProviderId.Data3 != STINGER_PROVIDER_GUID.Data3 ||
        memcmp(Record->EventHeader.ProviderId.Data4, STINGER_PROVIDER_GUID.Data4, sizeof(STINGER_PROVIDER_GUID.Data4)) != 0) {
        return;
    }

    status = TdhGetEventInformation(Record, 0, NULL, NULL, &size);
    if (status != ERROR_INSUFFICIENT_BUFFER || size == 0) {
        return;
    }

    info = (PTRACE_EVENT_INFO)malloc(size);
    if (info == NULL) {
        return;
    }

    status = TdhGetEventInformation(Record, 0, NULL, info, &size);
    if (status == ERROR_SUCCESS && info->EventNameOffset != 0) {
        eventName = (PWSTR)(((PBYTE)info) + info->EventNameOffset);
        STINGERPrintEtwRecord(Record, eventName);
    }

    free(info);
}

static BOOL WINAPI
ConsoleHandler(_In_ DWORD CtrlType)
{
    if (CtrlType == CTRL_C_EVENT || CtrlType == CTRL_BREAK_EVENT || CtrlType == CTRL_CLOSE_EVENT) {
        InterlockedExchange(&g_StopRequested, 1);
        if (g_TraceHandle != 0 && g_TraceHandle != INVALID_PROCESSTRACE_HANDLE) {
            CloseTrace(g_TraceHandle);
            g_TraceHandle = 0;
        }
        if (g_SessionHandle != 0) {
            (void)StopSessionByName();
            g_SessionHandle = 0;
        }
        return TRUE;
    }
    return FALSE;
}

static ULONG
StartSession(void)
{
    ULONG status;
    const ULONG propsBytes = sizeof(EVENT_TRACE_PROPERTIES) + (1024 * sizeof(WCHAR));
    PEVENT_TRACE_PROPERTIES props = (PEVENT_TRACE_PROPERTIES)calloc(1, propsBytes);
    PWSTR loggerName;
    EVENT_TRACE_LOGFILEW log;

    if (props == NULL) {
        return ERROR_OUTOFMEMORY;
    }

    props->Wnode.BufferSize = propsBytes;
    props->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    props->Wnode.ClientContext = 1; // QPC timestamping for stable deltas.
    props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    loggerName = (PWSTR)((PBYTE)props + props->LoggerNameOffset);
    (void)StringCchCopyW(loggerName, 512, STINGER_SESSION_NAME);

    status = StartTraceW(&g_SessionHandle, STINGER_SESSION_NAME, props);
    if (status == ERROR_ALREADY_EXISTS) {
        (void)StopSessionByName();
        status = StartTraceW(&g_SessionHandle, STINGER_SESSION_NAME, props);
    }
    if (status != ERROR_SUCCESS) {
        free(props);
        return status;
    }

    status = EnableTraceEx2(
        g_SessionHandle,
        &STINGER_PROVIDER_GUID,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_INFORMATION,
        0,
        0,
        0,
        NULL
    );
    if (status != ERROR_SUCCESS) {
        (void)StopSessionByName();
        g_SessionHandle = 0;
        free(props);
        return status;
    }

    RtlZeroMemory(&log, sizeof(log));
    log.LoggerName = (LPWSTR)STINGER_SESSION_NAME;
    log.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    log.EventRecordCallback = EventRecordCallback;

    g_TraceHandle = OpenTraceW(&log);
    if (g_TraceHandle == INVALID_PROCESSTRACE_HANDLE) {
        ULONG openErr = GetLastError();
        (void)StopSessionByName();
        g_SessionHandle = 0;
        free(props);
        return openErr;
    }

    free(props);
    return ERROR_SUCCESS;
}

int __cdecl
wmain(void)
{
    ULONG status;

    if (!SetConsoleCtrlHandler(ConsoleHandler, TRUE)) {
        wprintf(L"failed to install control handler\n");
        return 1;
    }

    STINGEREtwSymbolsInitialize();

    status = StartSession();
    if (status != ERROR_SUCCESS) {
        wprintf(L"failed to start ETW session: %lu\n", status);
        STINGEREtwSymbolsCleanup();
        return 1;
    }

    wprintf(L"stinger sensor running, press Ctrl+C to stop\n");
    status = ProcessTrace(&g_TraceHandle, 1, NULL, NULL);

    if (g_TraceHandle != 0 && g_TraceHandle != INVALID_PROCESSTRACE_HANDLE) {
        CloseTrace(g_TraceHandle);
        g_TraceHandle = 0;
    }
    if (g_SessionHandle != 0) {
        (void)StopSessionByName();
        g_SessionHandle = 0;
    }

    STINGEREtwSymbolsCleanup();

    if (status != ERROR_SUCCESS && InterlockedCompareExchange(&g_StopRequested, 0, 0) == 0) {
        wprintf(L"ProcessTrace failed: %lu\n", status);
        return 1;
    }

    return 0;
}
