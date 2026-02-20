#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <evntrace.h>
#include <tdh.h>
#include <dbghelp.h>
#include <strsafe.h>
#include <stdio.h>
#include <stdlib.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "dbghelp.lib")

// {D6C73F8A-6AD8-4F4B-A363-3D2FA31CD0E2}
static const GUID STINGER_PROVIDER_GUID =
{ 0xd6c73f8a, 0x6ad8, 0x4f4b, { 0xa3, 0x63, 0x3d, 0x2f, 0xa3, 0x1c, 0xd0, 0xe2 } };

static const WCHAR* STINGER_SESSION_NAME = L"StingerSensorSession";
static TRACEHANDLE g_SessionHandle = 0;
static TRACEHANDLE g_TraceHandle = 0;
static volatile LONG g_StopRequested = 0;

static ULONG
StopSessionByName(
    VOID
)
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

static BOOL
GetPropertyRaw(
    _In_ PEVENT_RECORD Record,
    _In_z_ PCWSTR Name,
    _Outptr_result_bytebuffer_(*OutSize) PBYTE* OutBuffer,
    _Out_ ULONG* OutSize
)
{
    TDHSTATUS status;
    PROPERTY_DATA_DESCRIPTOR descriptor;

    *OutBuffer = NULL;
    *OutSize = 0;

    RtlZeroMemory(&descriptor, sizeof(descriptor));
    descriptor.PropertyName = (ULONGLONG)(ULONG_PTR)Name;
    descriptor.ArrayIndex = ULONG_MAX;

    status = TdhGetPropertySize(Record, 0, NULL, 1, &descriptor, OutSize);
    if (status != ERROR_SUCCESS || *OutSize == 0) {
        return FALSE;
    }

    *OutBuffer = (PBYTE)malloc(*OutSize + sizeof(WCHAR));
    if (*OutBuffer == NULL) {
        *OutSize = 0;
        return FALSE;
    }
    RtlZeroMemory(*OutBuffer, *OutSize + sizeof(WCHAR));

    status = TdhGetProperty(Record, 0, NULL, 1, &descriptor, *OutSize, *OutBuffer);
    if (status != ERROR_SUCCESS) {
        free(*OutBuffer);
        *OutBuffer = NULL;
        *OutSize = 0;
        return FALSE;
    }

    return TRUE;
}

static BOOL
GetU32Property(
    _In_ PEVENT_RECORD Record,
    _In_z_ PCWSTR Name,
    _Out_ ULONG* Value
)
{
    PBYTE raw = NULL;
    ULONG size = 0;

    *Value = 0;
    if (!GetPropertyRaw(Record, Name, &raw, &size)) {
        return FALSE;
    }
    if (size >= sizeof(ULONG)) {
        *Value = *(ULONG*)raw;
        free(raw);
        return TRUE;
    }
    free(raw);
    return FALSE;
}

static BOOL
GetU64Property(
    _In_ PEVENT_RECORD Record,
    _In_z_ PCWSTR Name,
    _Out_ ULONGLONG* Value
)
{
    PBYTE raw = NULL;
    ULONG size = 0;

    *Value = 0;
    if (!GetPropertyRaw(Record, Name, &raw, &size)) {
        return FALSE;
    }
    if (size >= sizeof(ULONGLONG)) {
        *Value = *(ULONGLONG*)raw;
        free(raw);
        return TRUE;
    }
    free(raw);
    return FALSE;
}

static BOOL
GetBoolProperty(
    _In_ PEVENT_RECORD Record,
    _In_z_ PCWSTR Name,
    _Out_ BOOL* Value
)
{
    PBYTE raw = NULL;
    ULONG size = 0;
    ULONG u = 0;

    *Value = FALSE;
    if (!GetPropertyRaw(Record, Name, &raw, &size)) {
        return FALSE;
    }

    if (size >= sizeof(BOOLEAN)) {
        u = (size >= sizeof(ULONG)) ? *(ULONG*)raw : (ULONG)(*(BOOLEAN*)raw);
        *Value = (u != 0) ? TRUE : FALSE;
        free(raw);
        return TRUE;
    }

    free(raw);
    return FALSE;
}

static BOOL
GetWideProperty(
    _In_ PEVENT_RECORD Record,
    _In_z_ PCWSTR Name,
    _Out_writes_z_(OutputChars) PWSTR Output,
    _In_ size_t OutputChars
)
{
    PBYTE raw = NULL;
    ULONG size = 0;

    if (OutputChars == 0) {
        return FALSE;
    }
    Output[0] = L'\0';

    if (!GetPropertyRaw(Record, Name, &raw, &size)) {
        return FALSE;
    }

    if (size >= sizeof(WCHAR)) {
        WCHAR* ws = (WCHAR*)raw;
        (void)StringCchCopyW(Output, OutputChars, ws);
        free(raw);
        return TRUE;
    }

    free(raw);
    return FALSE;
}

static BOOL
GetAnsiProperty(
    _In_ PEVENT_RECORD Record,
    _In_z_ PCWSTR Name,
    _Out_writes_z_(OutputChars) PSTR Output,
    _In_ size_t OutputChars
)
{
    PBYTE raw = NULL;
    ULONG size = 0;

    if (OutputChars == 0) {
        return FALSE;
    }
    Output[0] = '\0';

    if (!GetPropertyRaw(Record, Name, &raw, &size)) {
        return FALSE;
    }

    if (size > 0) {
        (void)StringCchCopyA(Output, OutputChars, (PCSTR)raw);
        free(raw);
        return TRUE;
    }

    free(raw);
    return FALSE;
}

static void
ResolveSymbol(
    _In_ ULONGLONG Address,
    _Out_writes_z_(OutputChars) PWSTR Output,
    _In_ size_t OutputChars
)
{
    BYTE buffer[sizeof(SYMBOL_INFOW) + (MAX_SYM_NAME * sizeof(WCHAR))];
    PSYMBOL_INFOW symbol;
    DWORD64 displacement = 0;

    if (OutputChars == 0) {
        return;
    }
    if (Address == 0) {
        (void)StringCchCopyW(Output, OutputChars, L"<null>");
        return;
    }

    RtlZeroMemory(buffer, sizeof(buffer));
    symbol = (PSYMBOL_INFOW)buffer;
    symbol->SizeOfStruct = sizeof(SYMBOL_INFOW);
    symbol->MaxNameLen = MAX_SYM_NAME;

    if (SymFromAddrW(GetCurrentProcess(), Address, &displacement, symbol)) {
        (void)StringCchPrintfW(Output, OutputChars, L"%s+0x%llX", symbol->Name, displacement);
    } else {
        (void)StringCchPrintfW(Output, OutputChars, L"0x%llX", Address);
    }
}

static void
PrintStack(
    _In_ PEVENT_RECORD Record,
    _In_ ULONG Count,
    _In_z_ PCWSTR Prefix
)
{
    ULONG i;
    WCHAR name[16];

    for (i = 0; i < Count && i < 8; ++i) {
        ULONGLONG addr = 0;
        WCHAR sym[256];
        (void)StringCchPrintfW(name, RTL_NUMBER_OF(name), L"stack%lu", i);
        if (!GetU64Property(Record, name, &addr)) {
            continue;
        }
        ResolveSymbol(addr, sym, RTL_NUMBER_OF(sym));
        wprintf(L"%ls[%lu]=0x%016llX (%ls)\n", Prefix, i, addr, sym);
    }
}

static void
HandleEventRecord(
    _In_ PEVENT_RECORD Record,
    _In_z_ PCWSTR EventName
)
{
    if (wcscmp(EventName, L"HandleTelemetry") == 0) {
        CHAR eventClass[64];
        ULONGLONG callerPid = 0;
        ULONGLONG targetPid = 0;
        ULONG desiredAccess = 0;
        ULONGLONG originAddress = 0;
        ULONG originProtect = 0;
        BOOL execProtect = FALSE;
        BOOL fromNtdll = FALSE;
        BOOL fromExe = FALSE;
        WCHAR path[1024];
        ULONG frameCount = 0;

        (void)GetAnsiProperty(Record, L"class", eventClass, RTL_NUMBER_OF(eventClass));
        (void)GetU64Property(Record, L"callerPid", &callerPid);
        (void)GetU64Property(Record, L"targetPid", &targetPid);
        (void)GetU32Property(Record, L"desiredAccess", &desiredAccess);
        (void)GetU64Property(Record, L"originAddress", &originAddress);
        (void)GetU32Property(Record, L"originProtect", &originProtect);
        (void)GetBoolProperty(Record, L"execProtect", &execProtect);
        (void)GetBoolProperty(Record, L"fromNtdll", &fromNtdll);
        (void)GetBoolProperty(Record, L"fromExe", &fromExe);
        (void)GetWideProperty(Record, L"originPath", path, RTL_NUMBER_OF(path));
        (void)GetU32Property(Record, L"frameCount", &frameCount);

        wprintf(L"===== [STINGER][HANDLE] =====\n");
        wprintf(
            L"class=%S callerPid=%016llX targetPid=%016llX access=0x%08lX\n",
            eventClass,
            callerPid,
            targetPid,
            desiredAccess
        );
        wprintf(
            L"origin=%016llX protect=0x%08lX exec=%u fromNtdll=%u fromExe=%u path=%ls\n",
            originAddress,
            originProtect,
            execProtect,
            fromNtdll,
            fromExe,
            path[0] ? path : L"<unknown>"
        );
        PrintStack(Record, frameCount, L"stack");
        wprintf(L"==============================\n");
        return;
    }

    if (wcscmp(EventName, L"ThreadTelemetry") == 0) {
        ULONGLONG processId = 0;
        ULONGLONG threadId = 0;
        ULONGLONG creatorPid = 0;
        ULONGLONG startAddress = 0;
        ULONGLONG imageBase = 0;
        ULONGLONG imageSize = 0;
        BOOL gotStart = FALSE;
        BOOL gotRange = FALSE;
        BOOL isRemote = FALSE;
        BOOL outsideImage = FALSE;
        ULONG frameCount = 0;

        (void)GetU64Property(Record, L"processId", &processId);
        (void)GetU64Property(Record, L"threadId", &threadId);
        (void)GetU64Property(Record, L"creatorPid", &creatorPid);
        (void)GetU64Property(Record, L"startAddress", &startAddress);
        (void)GetU64Property(Record, L"imageBase", &imageBase);
        (void)GetU64Property(Record, L"imageSize", &imageSize);
        (void)GetBoolProperty(Record, L"gotStart", &gotStart);
        (void)GetBoolProperty(Record, L"gotRange", &gotRange);
        (void)GetBoolProperty(Record, L"isRemoteCreator", &isRemote);
        (void)GetBoolProperty(Record, L"outsideMainImage", &outsideImage);
        (void)GetU32Property(Record, L"workerFrameCount", &frameCount);

        wprintf(L"===== [STINGER][THREAD] =====\n");
        wprintf(
            L"pid=%016llX tid=%016llX creatorPid=%016llX remote=%u outsideMainImage=%u\n",
            processId,
            threadId,
            creatorPid,
            isRemote,
            outsideImage
        );
        wprintf(
            L"start=%016llX imageBase=%016llX imageSize=0x%llX gotStart=%u gotRange=%u\n",
            startAddress,
            imageBase,
            imageSize,
            gotStart,
            gotRange
        );
        PrintStack(Record, frameCount, L"stack");
        wprintf(L"==============================\n");
    }
}

static VOID WINAPI
EventRecordCallback(
    _In_ PEVENT_RECORD Record
)
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
    if (status != ERROR_SUCCESS) {
        free(info);
        return;
    }

    if (info->EventNameOffset == 0) {
        free(info);
        return;
    }

    eventName = (PWSTR)(((PBYTE)info) + info->EventNameOffset);
    HandleEventRecord(Record, eventName);

    free(info);
}

static BOOL WINAPI
ConsoleHandler(
    _In_ DWORD CtrlType
)
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
StartSession(
    VOID
)
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

    SymSetOptions(SYMOPT_DEFERRED_LOADS | SYMOPT_UNDNAME | SYMOPT_LOAD_LINES);
    if (!SymInitialize(GetCurrentProcess(), NULL, TRUE)) {
        wprintf(L"warning: symbol engine init failed, address-only output will be used\n");
    }

    status = StartSession();
    if (status != ERROR_SUCCESS) {
        wprintf(L"failed to start ETW session: %lu\n", status);
        SymCleanup(GetCurrentProcess());
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

    SymCleanup(GetCurrentProcess());

    if (status != ERROR_SUCCESS && InterlockedCompareExchange(&g_StopRequested, 0, 0) == 0) {
        wprintf(L"ProcessTrace failed: %lu\n", status);
        return 1;
    }

    return 0;
}
