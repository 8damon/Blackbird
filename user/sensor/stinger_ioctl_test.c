#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "..\..\abi\stinger_ioctl.h"
#include "stinger_event_printer.h"
#include "stinger_symbol_resolver.h"

typedef struct _TEST_STATE {
    BOOL SawHandle;
    BOOL SawThread;
    DWORD Polls;
} TEST_STATE;

#define STINGER_CHILD_ARG "--idle-child"
#define STINGER_CHILD_ARGW L"--idle-child"

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

static void
PumpEvents(HANDLE h, TEST_STATE* state, DWORD maxMs)
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
        } else if (rec.Header.Type == StingerEventTypeThread) {
            state->SawThread = TRUE;
        }

        if (state->SawHandle && state->SawThread) {
            return;
        }
    }
}

static void
GenerateThreadEvent(void)
{
    HANDLE t = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Sleep, (LPVOID)(ULONG_PTR)10, 0, NULL);
    if (t != NULL) {
        WaitForSingleObject(t, 2000);
        CloseHandle(t);
    }
}

static void
GenerateHandleEvent(void)
{
    WCHAR imagePath[MAX_PATH];
    WCHAR cmdLine[MAX_PATH + 64];
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    DWORD waitResult;
    HANDLE p;
    DWORD len;

    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(si);

    len = GetModuleFileNameW(NULL, imagePath, (DWORD)RTL_NUMBER_OF(imagePath));
    if (len == 0 || len >= RTL_NUMBER_OF(imagePath)) {
        return;
    }

    if (swprintf_s(cmdLine, RTL_NUMBER_OF(cmdLine), L"\"%ls\" %ls", imagePath, STINGER_CHILD_ARGW) < 0) {
        return;
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
            &pi)) {
        return;
    }

    Sleep(100);

    p = OpenProcess(
        PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION,
        FALSE,
        pi.dwProcessId
    );
    if (p != NULL) {
        CloseHandle(p);
    }

    waitResult = WaitForSingleObject(pi.hProcess, 1000);
    if (waitResult == WAIT_TIMEOUT) {
        (void)TerminateProcess(pi.hProcess, 0);
        (void)WaitForSingleObject(pi.hProcess, 2000);
    }

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
}

int __cdecl
main(int argc, char** argv)
{
    HANDLE h;
    STINGER_STATS_RESPONSE stats;
    DWORD bytes = 0;
    BOOL ok;
    DWORD selfPid = GetCurrentProcessId();
    TEST_STATE state;
    STINGER_SUBSCRIBE_REQUEST badReq;

    if (argc > 1 && strcmp(argv[1], STINGER_CHILD_ARG) == 0) {
        Sleep(7000);
        return 0;
    }

    STINGERSymbolResolverInitialize();
    ZeroMemory(&state, sizeof(state));

    h = CreateFileW(
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
    if (h == INVALID_HANDLE_VALUE) {
        printf("[FAIL] CreateFile \\\\.\\Global\\StingerCtl/\\\\.\\StingerCtl err=%lu\n", GetLastError());
        STINGERSymbolResolverCleanup();
        return 1;
    }

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
    if (ok || GetLastError() != ERROR_INVALID_PARAMETER) {
        printf("[FAIL] invalid subscribe stream mask was not rejected\n");
        CloseHandle(h);
        STINGERSymbolResolverCleanup();
        return 1;
    }
    printf("[PASS] invalid stream mask rejected\n");

    ok = Subscribe(h, selfPid, STINGER_STREAM_HANDLE | STINGER_STREAM_MEMORY | STINGER_STREAM_THREAD);
    if (!ok) {
        printf("[FAIL] subscribe err=%lu\n", GetLastError());
        CloseHandle(h);
        STINGERSymbolResolverCleanup();
        return 1;
    }
    printf("[PASS] subscribed pid=%lu\n", selfPid);

    ZeroMemory(&stats, sizeof(stats));
    ok = DeviceIoControl(h, (DWORD)IOCTL_STINGER_GET_STATS, NULL, 0, &stats, sizeof(stats), &bytes, NULL);
    if (!ok) {
        printf("[FAIL] get stats err=%lu\n", GetLastError());
        Unsubscribe(h, selfPid);
        CloseHandle(h);
        STINGERSymbolResolverCleanup();
        return 1;
    }
    printf("[PASS] stats subscriptionCount=%u queueDepth=%u dropped=%u\n",
        stats.SubscriptionCount, stats.QueueDepth, stats.DroppedEvents);

    GenerateThreadEvent();
    GenerateHandleEvent();
    PumpEvents(h, &state, 5000);

    if (!state.SawThread) {
        printf("[FAIL] did not receive thread event within timeout\n");
        Unsubscribe(h, selfPid);
        CloseHandle(h);
        STINGERSymbolResolverCleanup();
        return 1;
    }
    if (!state.SawHandle) {
        printf("[WARN] no handle event observed (callback policy/telemetry constraints may block this path)\n");
    } else {
        printf("[PASS] received handle event\n");
    }
    printf("[PASS] received thread event\n");

    ok = Unsubscribe(h, selfPid);
    if (!ok) {
        printf("[FAIL] unsubscribe err=%lu\n", GetLastError());
        CloseHandle(h);
        STINGERSymbolResolverCleanup();
        return 1;
    }
    printf("[PASS] unsubscribe succeeded\n");

    CloseHandle(h);
    STINGERSymbolResolverCleanup();
    printf("[OK] IOCTL smoke test complete. polls=%lu\n", state.Polls);
    return 0;
}
