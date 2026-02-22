#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>
#include <strsafe.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "..\..\abi\stinger_ioctl.h"
#include "stinger_event_printer.h"
#include "stinger_symbol_resolver.h"

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "tdh.lib")

// {D6C73F8A-6AD8-4F4B-A363-3D2FA31CD0E2}
static const GUID STINGER_PROVIDER_GUID =
{ 0xd6c73f8a, 0x6ad8, 0x4f4b, { 0xa3, 0x63, 0x3d, 0x2f, 0xa3, 0x1c, 0xd0, 0xe2 } };

typedef struct _TEST_STATE {
    BOOL SawHandle;
    BOOL SawThread;
    DWORD Polls;
    DWORD HandleEvents;
    DWORD ThreadEvents;
    DWORD HandleFlagUnion;
    DWORD ThreadFlagUnion;
} TEST_STATE;

typedef struct _TEST_EXPECTED {
    BOOL RequireHandleEvent;
    BOOL RequireThreadEvent;
    DWORD RequiredHandleFlags;
    DWORD RequiredThreadFlags;
} TEST_EXPECTED;

typedef struct _CHILD_CTX {
    PROCESS_INFORMATION Pi;
    BOOL Started;
} CHILD_CTX;

typedef struct _ETW_CAPTURE {
    WCHAR SessionName[64];
    TRACEHANDLE SessionHandle;
    TRACEHANDLE TraceHandle;
    HANDLE TraceThread;
    volatile LONG HandleEvents;
    volatile LONG ThreadEvents;
    volatile LONG ProcessEvents;
    volatile LONG ImageEvents;
    volatile LONG RegistryEvents;
    volatile LONG DetectionEvents;
    volatile LONG UnknownEvents;
    volatile LONG ProcessTraceStatus;
} ETW_CAPTURE;

typedef struct _SUITE_RESULTS {
    INT Total;
    INT Passed;
} SUITE_RESULTS;

#define STINGER_CHILD_ARG "--idle-child"
#define STINGER_CHILD_ARGW L"--idle-child"
#define STINGER_SUITE_ETW_SESSION L"StingerTestSuiteSession"
#define STINGER_MULTI_CLIENT_COUNT 3
#define STINGER_MULTI_CLIENT_TIMEOUT_MS 8000

static ETW_CAPTURE* g_ActiveEtwCapture = NULL;

typedef struct _STINGER_MULTI_CLIENT_WORKER {
    HANDLE Device;
    DWORD MaxMs;
    BOOL SawHandle;
    BOOL SawThread;
    DWORD Polls;
    DWORD UnexpectedError;
} STINGER_MULTI_CLIENT_WORKER;

static BOOL GenerateMemoryHandleIntent(DWORD pid);
static BOOL GenerateRemoteThreadLoadLibraryIntent(DWORD pid);

static
VOID
RecordResult(
    _Inout_ SUITE_RESULTS* Results,
    _In_ BOOL Passed,
    _In_z_ const char* PassText,
    _In_z_ const char* FailText
)
{
    Results->Total += 1;
    if (Passed) {
        Results->Passed += 1;
        printf("[PASS] %s\n", PassText);
    } else {
        printf("[FAIL] %s\n", FailText);
    }
}

static BOOL
Subscribe(HANDLE h, DWORD pid, DWORD mask)
{
    STINGER_SUBSCRIBE_REQUEST req;
    DWORD bytes = 0;

    ZeroMemory(&req, sizeof(req));
    req.ProcessId = pid;
    req.StreamMask = mask;

    return DeviceIoControl(
        h,
        (DWORD)IOCTL_STINGER_SUBSCRIBE,
        &req,
        sizeof(req),
        NULL,
        0,
        &bytes,
        NULL
    );
}

static BOOL
Unsubscribe(HANDLE h, DWORD pid)
{
    STINGER_UNSUBSCRIBE_REQUEST req;
    DWORD bytes = 0;

    ZeroMemory(&req, sizeof(req));
    req.ProcessId = pid;

    return DeviceIoControl(
        h,
        (DWORD)IOCTL_STINGER_UNSUBSCRIBE,
        &req,
        sizeof(req),
        NULL,
        0,
        &bytes,
        NULL
    );
}

static HANDLE
OpenControlDeviceHandle(void)
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

static
DWORD WINAPI
MultiClientWorkerThreadProc(_In_ LPVOID Context)
{
    STINGER_MULTI_CLIENT_WORKER* worker = (STINGER_MULTI_CLIENT_WORKER*)Context;
    ULONGLONG start = GetTickCount64();

    while ((GetTickCount64() - start) < worker->MaxMs) {
        STINGER_EVENT_RECORD rec;
        DWORD bytes = 0;
        BOOL ok;

        ZeroMemory(&rec, sizeof(rec));
        ok = DeviceIoControl(
            worker->Device,
            (DWORD)IOCTL_STINGER_GET_EVENT,
            NULL,
            0,
            &rec,
            sizeof(rec),
            &bytes,
            NULL
        );

        worker->Polls += 1;
        if (!ok) {
            DWORD err = GetLastError();
            if (err == ERROR_NO_MORE_ITEMS) {
                Sleep(20);
                continue;
            }
            worker->UnexpectedError = err;
            return 1;
        }

        if (rec.Header.Type == StingerEventTypeHandle) {
            worker->SawHandle = TRUE;
        } else if (rec.Header.Type == StingerEventTypeThread) {
            worker->SawThread = TRUE;
        }

        if (worker->SawHandle && worker->SawThread) {
            return 0;
        }
    }

    return (worker->SawHandle && worker->SawThread) ? 0 : 2;
}

static BOOL
RunMultiClientParallelIoctlTest(
    _In_ DWORD CallerPid,
    _In_ DWORD TargetPid,
    _Out_opt_ DWORD* TotalPolls
)
{
    HANDLE clients[STINGER_MULTI_CLIENT_COUNT];
    HANDLE threads[STINGER_MULTI_CLIENT_COUNT];
    STINGER_MULTI_CLIENT_WORKER workers[STINGER_MULTI_CLIENT_COUNT];
    DWORD i;
    BOOL ok = FALSE;
    DWORD pollSum = 0;
    BOOL generatedHandle;
    BOOL generatedThread;

    for (i = 0; i < STINGER_MULTI_CLIENT_COUNT; ++i) {
        clients[i] = INVALID_HANDLE_VALUE;
        threads[i] = NULL;
        ZeroMemory(&workers[i], sizeof(workers[i]));
    }

    for (i = 0; i < STINGER_MULTI_CLIENT_COUNT; ++i) {
        clients[i] = OpenControlDeviceHandle();
        if (clients[i] == INVALID_HANDLE_VALUE) {
            goto Cleanup;
        }

        if (!Subscribe(clients[i], CallerPid, STINGER_STREAM_HANDLE | STINGER_STREAM_MEMORY | STINGER_STREAM_THREAD)) {
            goto Cleanup;
        }
        if (!Subscribe(clients[i], TargetPid, STINGER_STREAM_HANDLE | STINGER_STREAM_MEMORY | STINGER_STREAM_THREAD)) {
            goto Cleanup;
        }

        workers[i].Device = clients[i];
        workers[i].MaxMs = STINGER_MULTI_CLIENT_TIMEOUT_MS;
        threads[i] = CreateThread(NULL, 0, MultiClientWorkerThreadProc, &workers[i], 0, NULL);
        if (threads[i] == NULL) {
            goto Cleanup;
        }
    }

    generatedHandle = GenerateMemoryHandleIntent(TargetPid);
    generatedThread = GenerateRemoteThreadLoadLibraryIntent(TargetPid);
    if (!generatedHandle || !generatedThread) {
        goto Cleanup;
    }

    for (i = 0; i < STINGER_MULTI_CLIENT_COUNT; ++i) {
        DWORD waitResult;
        DWORD exitCode = 1;

        waitResult = WaitForSingleObject(threads[i], STINGER_MULTI_CLIENT_TIMEOUT_MS + 2000);
        if (waitResult != WAIT_OBJECT_0) {
            goto Cleanup;
        }
        if (!GetExitCodeThread(threads[i], &exitCode) || exitCode != 0) {
            goto Cleanup;
        }
        if (workers[i].UnexpectedError != 0 || !workers[i].SawHandle || !workers[i].SawThread) {
            goto Cleanup;
        }
    }

    ok = TRUE;

Cleanup:
    for (i = 0; i < STINGER_MULTI_CLIENT_COUNT; ++i) {
        if (threads[i] != NULL) {
            (void)WaitForSingleObject(threads[i], 1000);
            CloseHandle(threads[i]);
            threads[i] = NULL;
        }
    }

    for (i = 0; i < STINGER_MULTI_CLIENT_COUNT; ++i) {
        pollSum += workers[i].Polls;
        if (clients[i] != INVALID_HANDLE_VALUE) {
            (void)Unsubscribe(clients[i], CallerPid);
            (void)Unsubscribe(clients[i], TargetPid);
            CloseHandle(clients[i]);
            clients[i] = INVALID_HANDLE_VALUE;
        }
    }

    if (TotalPolls != NULL) {
        *TotalPolls = pollSum;
    }
    return ok;
}

static BOOL
RequirementsMet(
    const TEST_STATE* state,
    const TEST_EXPECTED* expected
)
{
    if (expected->RequireHandleEvent && !state->SawHandle) {
        return FALSE;
    }
    if (expected->RequireThreadEvent && !state->SawThread) {
        return FALSE;
    }
    if ((state->HandleFlagUnion & expected->RequiredHandleFlags) != expected->RequiredHandleFlags) {
        return FALSE;
    }
    if ((state->ThreadFlagUnion & expected->RequiredThreadFlags) != expected->RequiredThreadFlags) {
        return FALSE;
    }
    return TRUE;
}

static void
PumpIoctlEvents(
    HANDLE h,
    TEST_STATE* state,
    const TEST_EXPECTED* expected,
    DWORD maxMs
)
{
    ULONGLONG start = GetTickCount64();

    while ((GetTickCount64() - start) < maxMs) {
        STINGER_EVENT_RECORD rec;
        DWORD bytes = 0;
        BOOL ok;

        ZeroMemory(&rec, sizeof(rec));
        ok = DeviceIoControl(
            h,
            (DWORD)IOCTL_STINGER_GET_EVENT,
            NULL,
            0,
            &rec,
            sizeof(rec),
            &bytes,
            NULL
        );

        state->Polls += 1;
        if (!ok) {
            DWORD err = GetLastError();
            if (err == ERROR_NO_MORE_ITEMS) {
                Sleep(40);
                continue;
            }
            printf("[FAIL] IOCTL_STINGER_GET_EVENT err=%lu\n", err);
            return;
        }

        STINGEREventPrinterPrintRecord(&rec);

        if (rec.Header.Type == StingerEventTypeHandle) {
            state->SawHandle = TRUE;
            state->HandleEvents += 1;
            state->HandleFlagUnion |= rec.Data.Handle.Flags;
        } else if (rec.Header.Type == StingerEventTypeThread) {
            state->SawThread = TRUE;
            state->ThreadEvents += 1;
            state->ThreadFlagUnion |= rec.Data.Thread.Flags;
        }

        if (RequirementsMet(state, expected)) {
            return;
        }
    }
}

static void
GenerateLocalThreadEvent(void)
{
    HANDLE t = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Sleep, (LPVOID)(ULONG_PTR)15, 0, NULL);
    if (t != NULL) {
        WaitForSingleObject(t, 2000);
        CloseHandle(t);
    }
}

static BOOL
StartIdleChild(CHILD_CTX* child)
{
    WCHAR imagePath[MAX_PATH];
    WCHAR cmdLine[MAX_PATH + 64];
    STARTUPINFOW si;
    DWORD len;

    ZeroMemory(child, sizeof(*child));
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);

    len = GetModuleFileNameW(NULL, imagePath, (DWORD)RTL_NUMBER_OF(imagePath));
    if (len == 0 || len >= RTL_NUMBER_OF(imagePath)) {
        return FALSE;
    }

    if (swprintf_s(cmdLine, RTL_NUMBER_OF(cmdLine), L"\"%ls\" %ls", imagePath, STINGER_CHILD_ARGW) < 0) {
        return FALSE;
    }

    if (!CreateProcessW(
            imagePath,
            cmdLine,
            NULL,
            NULL,
            FALSE,
            CREATE_NO_WINDOW,
            NULL,
            NULL,
            &si,
            &child->Pi)) {
        return FALSE;
    }

    child->Started = TRUE;
    return TRUE;
}

static void
StopIdleChild(CHILD_CTX* child)
{
    DWORD waitResult;

    if (!child->Started) {
        return;
    }

    waitResult = WaitForSingleObject(child->Pi.hProcess, 500);
    if (waitResult == WAIT_TIMEOUT) {
        (void)TerminateProcess(child->Pi.hProcess, 0);
        (void)WaitForSingleObject(child->Pi.hProcess, 2000);
    }

    CloseHandle(child->Pi.hThread);
    CloseHandle(child->Pi.hProcess);
    ZeroMemory(child, sizeof(*child));
}

static BOOL
GenerateMemoryHandleIntent(DWORD pid)
{
    HANDLE p = OpenProcess(
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION,
        FALSE,
        pid
    );
    if (p == NULL) {
        return FALSE;
    }
    CloseHandle(p);
    return TRUE;
}

static BOOL
GenerateThreadContextHandleIntent(DWORD tid)
{
    HANDLE t = OpenThread(
        THREAD_SET_CONTEXT | THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_LIMITED_INFORMATION,
        FALSE,
        tid
    );
    if (t == NULL) {
        return FALSE;
    }
    CloseHandle(t);
    return TRUE;
}

static BOOL
GenerateDuplicateHandleIntent(DWORD pid)
{
    HANDLE src = NULL;
    HANDLE dup = NULL;
    BOOL ok;

    src = OpenProcess(
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION,
        FALSE,
        pid
    );
    if (src == NULL) {
        return FALSE;
    }

    ok = DuplicateHandle(
        GetCurrentProcess(),
        src,
        GetCurrentProcess(),
        &dup,
        PROCESS_VM_WRITE | PROCESS_VM_READ,
        FALSE,
        0
    );

    if (dup != NULL) {
        CloseHandle(dup);
    }
    CloseHandle(src);
    return ok;
}

static BOOL
FindRemoteModuleBase(
    DWORD pid,
    PCWSTR moduleName,
    ULONGLONG* baseOut
)
{
    HANDLE snap;
    MODULEENTRY32W me;

    *baseOut = 0;
    snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    ZeroMemory(&me, sizeof(me));
    me.dwSize = sizeof(me);

    if (!Module32FirstW(snap, &me)) {
        CloseHandle(snap);
        return FALSE;
    }

    do {
        if (_wcsicmp(me.szModule, moduleName) == 0) {
            *baseOut = (ULONGLONG)(ULONG_PTR)me.modBaseAddr;
            CloseHandle(snap);
            return TRUE;
        }
    } while (Module32NextW(snap, &me));

    CloseHandle(snap);
    return FALSE;
}

static BOOL
GenerateRemoteThreadLoadLibraryIntent(DWORD pid)
{
    HANDLE process = NULL;
    HANDLE thread = NULL;
    HMODULE localKernel32;
    FARPROC localLoadLibraryW;
    ULONGLONG remoteKernel32 = 0;
    ULONGLONG remoteStartAddress;
    SIZE_T dllBytes;
    LPVOID remoteBuffer = NULL;
    WCHAR dllName[] = L"kernel32.dll";
    BOOL ok = FALSE;
    SIZE_T written = 0;
    DWORD waitResult;

    localKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (localKernel32 == NULL) {
        return FALSE;
    }

    localLoadLibraryW = GetProcAddress(localKernel32, "LoadLibraryW");
    if (localLoadLibraryW == NULL) {
        return FALSE;
    }

    if (!FindRemoteModuleBase(pid, L"KERNEL32.DLL", &remoteKernel32)) {
        return FALSE;
    }

    remoteStartAddress =
        remoteKernel32 +
        ((ULONGLONG)(ULONG_PTR)localLoadLibraryW - (ULONGLONG)(ULONG_PTR)localKernel32);

    process = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
        FALSE,
        pid
    );
    if (process == NULL) {
        return FALSE;
    }

    dllBytes = (wcslen(dllName) + 1) * sizeof(WCHAR);
    remoteBuffer = VirtualAllocEx(process, NULL, dllBytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (remoteBuffer == NULL) {
        goto Exit;
    }

    if (!WriteProcessMemory(process, remoteBuffer, dllName, dllBytes, &written) || written != dllBytes) {
        goto Exit;
    }

    thread = CreateRemoteThread(
        process,
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)(ULONG_PTR)remoteStartAddress,
        remoteBuffer,
        0,
        NULL
    );
    if (thread == NULL) {
        goto Exit;
    }

    waitResult = WaitForSingleObject(thread, 5000);
    if (waitResult != WAIT_OBJECT_0 && waitResult != WAIT_TIMEOUT) {
        goto Exit;
    }

    ok = TRUE;

Exit:
    if (thread != NULL) {
        CloseHandle(thread);
    }
    if (remoteBuffer != NULL) {
        (void)VirtualFreeEx(process, remoteBuffer, 0, MEM_RELEASE);
    }
    if (process != NULL) {
        CloseHandle(process);
    }
    return ok;
}

static BOOL
GenerateRegistryHighValueActivity(void)
{
    HKEY key = NULL;
    DWORD disposition = 0;
    LONG status;
    WCHAR valueName[] = L"StingerTestSuite";
    WCHAR valueData[] = L"cmd.exe /c exit";

    status = RegCreateKeyExW(
        HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        0,
        NULL,
        REG_OPTION_NON_VOLATILE,
        KEY_SET_VALUE | KEY_QUERY_VALUE,
        NULL,
        &key,
        &disposition
    );
    if (status != ERROR_SUCCESS) {
        return FALSE;
    }
    UNREFERENCED_PARAMETER(disposition);

    status = RegSetValueExW(
        key,
        valueName,
        0,
        REG_SZ,
        (const BYTE*)valueData,
        (DWORD)((wcslen(valueData) + 1) * sizeof(WCHAR))
    );

    (void)RegDeleteValueW(key, valueName);
    RegCloseKey(key);

    return (status == ERROR_SUCCESS);
}

static
ULONG
StopSessionByName(_In_z_ PCWSTR SessionName)
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
    (void)StringCchCopyW(loggerName, 512, SessionName);

    status = ControlTraceW(0, SessionName, props, EVENT_TRACE_CONTROL_STOP);
    free(props);

    if (status == ERROR_WMI_INSTANCE_NOT_FOUND) {
        return ERROR_SUCCESS;
    }
    return status;
}

static
VOID WINAPI
StingerEtwRecordCallback(_In_ PEVENT_RECORD Record)
{
    ETW_CAPTURE* cap = g_ActiveEtwCapture;
    PTRACE_EVENT_INFO info = NULL;
    ULONG size = 0;
    TDHSTATUS status;
    PCWSTR eventName = NULL;

    if (cap == NULL || Record == NULL) {
        return;
    }

    if (!IsEqualGUID(&Record->EventHeader.ProviderId, &STINGER_PROVIDER_GUID)) {
        return;
    }

    status = TdhGetEventInformation(Record, 0, NULL, NULL, &size);
    if (status != ERROR_INSUFFICIENT_BUFFER || size == 0) {
        InterlockedIncrement(&cap->UnknownEvents);
        return;
    }

    info = (PTRACE_EVENT_INFO)malloc(size);
    if (info == NULL) {
        InterlockedIncrement(&cap->UnknownEvents);
        return;
    }

    status = TdhGetEventInformation(Record, 0, NULL, info, &size);
    if (status == ERROR_SUCCESS && info->EventNameOffset != 0) {
        eventName = (PCWSTR)(((PBYTE)info) + info->EventNameOffset);

        if (wcscmp(eventName, L"HandleTelemetry") == 0) {
            InterlockedIncrement(&cap->HandleEvents);
        } else if (wcscmp(eventName, L"ThreadTelemetry") == 0) {
            InterlockedIncrement(&cap->ThreadEvents);
        } else if (wcscmp(eventName, L"ProcessTelemetry") == 0) {
            InterlockedIncrement(&cap->ProcessEvents);
        } else if (wcscmp(eventName, L"ImageTelemetry") == 0) {
            InterlockedIncrement(&cap->ImageEvents);
        } else if (wcscmp(eventName, L"RegistryTelemetry") == 0) {
            InterlockedIncrement(&cap->RegistryEvents);
        } else if (wcscmp(eventName, L"DetectionTelemetry") == 0) {
            InterlockedIncrement(&cap->DetectionEvents);
        } else {
            InterlockedIncrement(&cap->UnknownEvents);
        }
    } else {
        InterlockedIncrement(&cap->UnknownEvents);
    }

    free(info);
}

static
DWORD WINAPI
EtwConsumerThreadProc(_In_ LPVOID Context)
{
    ETW_CAPTURE* cap = (ETW_CAPTURE*)Context;
    ULONG status;

    status = ProcessTrace(&cap->TraceHandle, 1, NULL, NULL);
    InterlockedExchange(&cap->ProcessTraceStatus, (LONG)status);
    return status;
}

static
BOOL
StartEtwCapture(_Out_ ETW_CAPTURE* cap)
{
    ULONG status;
    const ULONG propsBytes = sizeof(EVENT_TRACE_PROPERTIES) + (1024 * sizeof(WCHAR));
    PEVENT_TRACE_PROPERTIES props = (PEVENT_TRACE_PROPERTIES)calloc(1, propsBytes);
    PWSTR loggerName;
    EVENT_TRACE_LOGFILEW log;

    if (cap == NULL || props == NULL) {
        free(props);
        return FALSE;
    }

    ZeroMemory(cap, sizeof(*cap));
    cap->SessionHandle = 0;
    cap->TraceHandle = 0;
    cap->ProcessTraceStatus = ERROR_SUCCESS;
    (void)StringCchCopyW(cap->SessionName, RTL_NUMBER_OF(cap->SessionName), STINGER_SUITE_ETW_SESSION);

    (void)StopSessionByName(cap->SessionName);

    props->Wnode.BufferSize = propsBytes;
    props->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    props->Wnode.ClientContext = 1;
    props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    loggerName = (PWSTR)((PBYTE)props + props->LoggerNameOffset);
    (void)StringCchCopyW(loggerName, 512, cap->SessionName);

    status = StartTraceW(&cap->SessionHandle, cap->SessionName, props);
    if (status != ERROR_SUCCESS) {
        free(props);
        return FALSE;
    }

    status = EnableTraceEx2(
        cap->SessionHandle,
        &STINGER_PROVIDER_GUID,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_INFORMATION,
        0,
        0,
        0,
        NULL
    );
    if (status != ERROR_SUCCESS) {
        (void)StopSessionByName(cap->SessionName);
        cap->SessionHandle = 0;
        free(props);
        return FALSE;
    }

    ZeroMemory(&log, sizeof(log));
    log.LoggerName = cap->SessionName;
    log.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    log.EventRecordCallback = StingerEtwRecordCallback;

    cap->TraceHandle = OpenTraceW(&log);
    if (cap->TraceHandle == INVALID_PROCESSTRACE_HANDLE) {
        (void)StopSessionByName(cap->SessionName);
        cap->SessionHandle = 0;
        free(props);
        return FALSE;
    }

    g_ActiveEtwCapture = cap;
    cap->TraceThread = CreateThread(NULL, 0, EtwConsumerThreadProc, cap, 0, NULL);
    if (cap->TraceThread == NULL) {
        CloseTrace(cap->TraceHandle);
        cap->TraceHandle = 0;
        (void)StopSessionByName(cap->SessionName);
        cap->SessionHandle = 0;
        g_ActiveEtwCapture = NULL;
        free(props);
        return FALSE;
    }

    free(props);
    Sleep(150);
    return TRUE;
}

static
VOID
StopEtwCapture(_Inout_ ETW_CAPTURE* cap)
{
    if (cap == NULL) {
        return;
    }

    if (cap->TraceHandle != 0 && cap->TraceHandle != INVALID_PROCESSTRACE_HANDLE) {
        CloseTrace(cap->TraceHandle);
        cap->TraceHandle = 0;
    }

    if (cap->SessionHandle != 0) {
        (void)StopSessionByName(cap->SessionName);
        cap->SessionHandle = 0;
    }

    if (cap->TraceThread != NULL) {
        (void)WaitForSingleObject(cap->TraceThread, 5000);
        CloseHandle(cap->TraceThread);
        cap->TraceThread = NULL;
    }

    g_ActiveEtwCapture = NULL;
}

static
BOOL
WaitForEtwEventCoverage(
    _In_ ETW_CAPTURE* cap,
    _In_ DWORD maxMs
)
{
    ULONGLONG start = GetTickCount64();

    while ((GetTickCount64() - start) < maxMs) {
        if (InterlockedCompareExchange(&cap->HandleEvents, 0, 0) > 0 &&
            InterlockedCompareExchange(&cap->ThreadEvents, 0, 0) > 0 &&
            InterlockedCompareExchange(&cap->ProcessEvents, 0, 0) > 0 &&
            InterlockedCompareExchange(&cap->ImageEvents, 0, 0) > 0 &&
            InterlockedCompareExchange(&cap->RegistryEvents, 0, 0) > 0 &&
            InterlockedCompareExchange(&cap->DetectionEvents, 0, 0) > 0) {
            return TRUE;
        }
        Sleep(100);
    }
    return FALSE;
}

int __cdecl
main(int argc, char** argv)
{
    HANDLE h = INVALID_HANDLE_VALUE;
    STINGER_STATS_RESPONSE stats;
    DWORD bytes = 0;
    BOOL ok;
    DWORD selfPid = GetCurrentProcessId();
    TEST_STATE state;
    TEST_EXPECTED expected;
    STINGER_SUBSCRIBE_REQUEST badReq;
    BOOL subscribedSelf = FALSE;
    BOOL subscribedChild = FALSE;
    CHILD_CTX child;
    BOOL generatedMemoryIntent = FALSE;
    BOOL generatedThreadIntent = FALSE;
    BOOL generatedDuplicateIntent = FALSE;
    BOOL generatedRemoteAfterMemory = FALSE;
    BOOL generatedRemoteAfterThread = FALSE;
    BOOL generatedRemoteAfterDup = FALSE;
    BOOL generatedRegistry = FALSE;
    BOOL multiClientParallelOk = FALSE;
    DWORD multiClientPolls = 0;
    ETW_CAPTURE etw;
    BOOL etwStarted = FALSE;
    BOOL etwCoverageMet = FALSE;
    SUITE_RESULTS results;

    if (argc > 1 && strcmp(argv[1], STINGER_CHILD_ARG) == 0) {
        Sleep(15000);
        return 0;
    }

    STINGERSymbolResolverInitialize();
    ZeroMemory(&state, sizeof(state));
    ZeroMemory(&expected, sizeof(expected));
    ZeroMemory(&child, sizeof(child));
    ZeroMemory(&etw, sizeof(etw));
    ZeroMemory(&results, sizeof(results));

    h = OpenControlDeviceHandle();
    RecordResult(
        &results,
        (h != INVALID_HANDLE_VALUE),
        "opened control device",
        "failed to open control device \\\\.\\Global\\StingerCtl/\\\\.\\StingerCtl"
    );
    if (h == INVALID_HANDLE_VALUE) {
        goto Cleanup;
    }

    etwStarted = StartEtwCapture(&etw);
    RecordResult(
        &results,
        etwStarted,
        "started ETW capture session",
        "failed to start ETW capture session"
    );

    ZeroMemory(&badReq, sizeof(badReq));
    badReq.ProcessId = selfPid;
    badReq.StreamMask = 0;
    ok = DeviceIoControl(
        h,
        (DWORD)IOCTL_STINGER_SUBSCRIBE,
        &badReq,
        sizeof(badReq),
        NULL,
        0,
        &bytes,
        NULL
    );
    RecordResult(
        &results,
        (!ok && GetLastError() == ERROR_INVALID_PARAMETER),
        "invalid subscribe stream mask rejected",
        "invalid subscribe stream mask was not rejected"
    );

    ok = Subscribe(h, selfPid, STINGER_STREAM_HANDLE | STINGER_STREAM_MEMORY | STINGER_STREAM_THREAD);
    subscribedSelf = ok;
    RecordResult(
        &results,
        ok,
        "subscribed self",
        "subscribe self failed"
    );
    if (!ok) {
        goto Cleanup;
    }
    printf("[INFO] subscribed self pid=%lu\n", selfPid);

    ZeroMemory(&stats, sizeof(stats));
    ok = DeviceIoControl(h, (DWORD)IOCTL_STINGER_GET_STATS, NULL, 0, &stats, sizeof(stats), &bytes, NULL);
    RecordResult(
        &results,
        ok,
        "queried IOCTL stats",
        "get stats failed"
    );
    if (ok) {
        printf("[INFO] stats subscriptionCount=%u queueDepth=%u dropped=%u\n",
            stats.SubscriptionCount, stats.QueueDepth, stats.DroppedEvents);
    }

    ok = StartIdleChild(&child);
    RecordResult(
        &results,
        ok,
        "launched child process",
        "failed to launch child process"
    );
    if (!ok) {
        goto Cleanup;
    }
    printf("[INFO] child pid=%lu tid=%lu\n", child.Pi.dwProcessId, child.Pi.dwThreadId);

    ok = Subscribe(h, child.Pi.dwProcessId, STINGER_STREAM_HANDLE | STINGER_STREAM_MEMORY | STINGER_STREAM_THREAD);
    subscribedChild = ok;
    RecordResult(
        &results,
        ok,
        "subscribed child",
        "subscribe child failed"
    );
    if (!ok) {
        goto Cleanup;
    }

    GenerateLocalThreadEvent();

    generatedMemoryIntent = GenerateMemoryHandleIntent(child.Pi.dwProcessId);
    RecordResult(
        &results,
        generatedMemoryIntent,
        "generated memory-handle intent",
        "failed to generate memory-handle intent"
    );

    generatedThreadIntent = GenerateThreadContextHandleIntent(child.Pi.dwThreadId);
    RecordResult(
        &results,
        generatedThreadIntent,
        "generated thread-context-handle intent",
        "failed to generate thread-context-handle intent"
    );

    generatedDuplicateIntent = GenerateDuplicateHandleIntent(child.Pi.dwProcessId);
    RecordResult(
        &results,
        generatedDuplicateIntent,
        "generated duplicate-handle intent",
        "failed to generate duplicate-handle intent"
    );

    if (generatedMemoryIntent) {
        generatedRemoteAfterMemory = GenerateRemoteThreadLoadLibraryIntent(child.Pi.dwProcessId);
        RecordResult(
            &results,
            generatedRemoteAfterMemory,
            "generated remote thread after memory intent",
            "failed to generate remote thread after memory intent"
        );
    }

    if (generatedThreadIntent) {
        generatedRemoteAfterThread = GenerateRemoteThreadLoadLibraryIntent(child.Pi.dwProcessId);
        RecordResult(
            &results,
            generatedRemoteAfterThread,
            "generated remote thread after thread-context intent",
            "failed to generate remote thread after thread-context intent"
        );
    }

    if (generatedDuplicateIntent) {
        generatedRemoteAfterDup = GenerateRemoteThreadLoadLibraryIntent(child.Pi.dwProcessId);
        RecordResult(
            &results,
            generatedRemoteAfterDup,
            "generated remote thread after duplicate intent",
            "failed to generate remote thread after duplicate intent"
        );
    }

    generatedRegistry = GenerateRegistryHighValueActivity();
    RecordResult(
        &results,
        generatedRegistry,
        "generated high-value registry activity",
        "failed to generate high-value registry activity"
    );

    expected.RequireThreadEvent = TRUE;
    expected.RequireHandleEvent = generatedMemoryIntent || generatedThreadIntent || generatedDuplicateIntent;
    if (generatedMemoryIntent) {
        expected.RequiredHandleFlags |= STINGER_HANDLE_FLAG_MEMORY_RELATED;
    }
    if (generatedThreadIntent) {
        expected.RequiredHandleFlags |= STINGER_HANDLE_FLAG_THREAD_OBJECT;
    }
    if (generatedDuplicateIntent) {
        expected.RequiredHandleFlags |= STINGER_HANDLE_FLAG_DUPLICATE_OPERATION;
    }
    if (generatedRemoteAfterMemory) {
        expected.RequiredThreadFlags |= STINGER_THREAD_FLAG_CORRELATED_INTENT | STINGER_THREAD_FLAG_CORR_MEMORY;
    }
    if (generatedRemoteAfterThread) {
        expected.RequiredThreadFlags |= STINGER_THREAD_FLAG_CORRELATED_INTENT | STINGER_THREAD_FLAG_CORR_THREAD_CTX;
    }
    if (generatedRemoteAfterDup) {
        expected.RequiredThreadFlags |= STINGER_THREAD_FLAG_CORRELATED_INTENT | STINGER_THREAD_FLAG_CORR_DUP_HANDLE;
    }

    PumpIoctlEvents(h, &state, &expected, 14000);

    RecordResult(
        &results,
        state.SawThread,
        "received thread telemetry via IOCTL",
        "missing thread telemetry via IOCTL"
    );

    if (expected.RequireHandleEvent) {
        RecordResult(
            &results,
            state.SawHandle,
            "received handle telemetry via IOCTL",
            "missing handle telemetry via IOCTL"
        );
    }

    if (generatedMemoryIntent) {
        RecordResult(
            &results,
            ((state.HandleFlagUnion & STINGER_HANDLE_FLAG_MEMORY_RELATED) != 0),
            "observed IOCTL handle flag MemoryRelated",
            "missing IOCTL handle flag MemoryRelated"
        );
    }

    if (generatedThreadIntent) {
        RecordResult(
            &results,
            ((state.HandleFlagUnion & STINGER_HANDLE_FLAG_THREAD_OBJECT) != 0),
            "observed IOCTL handle flag ThreadObject",
            "missing IOCTL handle flag ThreadObject"
        );
    }

    if (generatedDuplicateIntent) {
        RecordResult(
            &results,
            ((state.HandleFlagUnion & STINGER_HANDLE_FLAG_DUPLICATE_OPERATION) != 0),
            "observed IOCTL handle flag DuplicateOperation",
            "missing IOCTL handle flag DuplicateOperation"
        );
    }

    if (generatedRemoteAfterMemory) {
        RecordResult(
            &results,
            ((state.ThreadFlagUnion & STINGER_THREAD_FLAG_CORR_MEMORY) != 0),
            "observed IOCTL thread flag CorrelatedMemory",
            "missing IOCTL thread flag CorrelatedMemory"
        );
    }

    if (generatedRemoteAfterThread) {
        RecordResult(
            &results,
            ((state.ThreadFlagUnion & STINGER_THREAD_FLAG_CORR_THREAD_CTX) != 0),
            "observed IOCTL thread flag CorrelatedThreadContext",
            "missing IOCTL thread flag CorrelatedThreadContext"
        );
    }

    if (generatedRemoteAfterDup) {
        RecordResult(
            &results,
            ((state.ThreadFlagUnion & STINGER_THREAD_FLAG_CORR_DUP_HANDLE) != 0),
            "observed IOCTL thread flag CorrelatedDuplicateHandle",
            "missing IOCTL thread flag CorrelatedDuplicateHandle"
        );
    }

    if (expected.RequiredThreadFlags != 0) {
        RecordResult(
            &results,
            ((state.ThreadFlagUnion & STINGER_THREAD_FLAG_CORRELATED_INTENT) != 0),
            "observed IOCTL thread flag CorrelatedIntent",
            "missing IOCTL thread flag CorrelatedIntent"
        );
    }

    multiClientParallelOk = RunMultiClientParallelIoctlTest(selfPid, child.Pi.dwProcessId, &multiClientPolls);
    RecordResult(
        &results,
        multiClientParallelOk,
        "multi-client parallel IOCTL fanout verified",
        "multi-client parallel IOCTL fanout failed"
    );
    printf("[INFO] multi-client parallel polls=%lu clients=%u\n", multiClientPolls, STINGER_MULTI_CLIENT_COUNT);

    if (etwStarted) {
        etwCoverageMet = WaitForEtwEventCoverage(&etw, 10000);
        RecordResult(
            &results,
            etwCoverageMet,
            "ETW received all core event families",
            "ETW missing one or more core event families"
        );

        RecordResult(
            &results,
            (InterlockedCompareExchange(&etw.HandleEvents, 0, 0) > 0),
            "ETW HandleTelemetry observed",
            "ETW HandleTelemetry missing"
        );
        RecordResult(
            &results,
            (InterlockedCompareExchange(&etw.ThreadEvents, 0, 0) > 0),
            "ETW ThreadTelemetry observed",
            "ETW ThreadTelemetry missing"
        );
        RecordResult(
            &results,
            (InterlockedCompareExchange(&etw.ProcessEvents, 0, 0) > 0),
            "ETW ProcessTelemetry observed",
            "ETW ProcessTelemetry missing"
        );
        RecordResult(
            &results,
            (InterlockedCompareExchange(&etw.ImageEvents, 0, 0) > 0),
            "ETW ImageTelemetry observed",
            "ETW ImageTelemetry missing"
        );
        RecordResult(
            &results,
            (InterlockedCompareExchange(&etw.RegistryEvents, 0, 0) > 0),
            "ETW RegistryTelemetry observed",
            "ETW RegistryTelemetry missing"
        );
        RecordResult(
            &results,
            (InterlockedCompareExchange(&etw.DetectionEvents, 0, 0) > 0),
            "ETW DetectionTelemetry observed",
            "ETW DetectionTelemetry missing"
        );

        printf(
            "[INFO] ETW counts handle=%ld thread=%ld process=%ld image=%ld registry=%ld detection=%ld unknown=%ld\n",
            InterlockedCompareExchange(&etw.HandleEvents, 0, 0),
            InterlockedCompareExchange(&etw.ThreadEvents, 0, 0),
            InterlockedCompareExchange(&etw.ProcessEvents, 0, 0),
            InterlockedCompareExchange(&etw.ImageEvents, 0, 0),
            InterlockedCompareExchange(&etw.RegistryEvents, 0, 0),
            InterlockedCompareExchange(&etw.DetectionEvents, 0, 0),
            InterlockedCompareExchange(&etw.UnknownEvents, 0, 0)
        );
    }

Cleanup:
    if (subscribedChild) {
        ok = Unsubscribe(h, child.Pi.dwProcessId);
        RecordResult(
            &results,
            ok,
            "unsubscribed child",
            "unsubscribe child failed"
        );
    }

    if (subscribedSelf) {
        ok = Unsubscribe(h, selfPid);
        RecordResult(
            &results,
            ok,
            "unsubscribed self",
            "unsubscribe self failed"
        );
    }

    StopIdleChild(&child);

    if (etwStarted) {
        StopEtwCapture(&etw);
    }

    if (h != INVALID_HANDLE_VALUE) {
        CloseHandle(h);
    }

    STINGERSymbolResolverCleanup();

    if (results.Passed == results.Total) {
        printf("[OK] StingerTestSuite complete. tests-passed=%d/%d polls=%lu\n", results.Passed, results.Total, state.Polls);
        return 0;
    }

    printf("[FAIL] StingerTestSuite complete. tests-passed=%d/%d polls=%lu\n", results.Passed, results.Total, state.Polls);
    return 1;
}
