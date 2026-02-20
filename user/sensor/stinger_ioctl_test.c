#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include "..\..\abi\stinger_ioctl.h"

typedef struct _TEST_STATE {
    BOOL SawHandle;
    BOOL SawThread;
    DWORD Polls;
} TEST_STATE;

static DWORD
FindOtherProcessId(void)
{
    HANDLE snap;
    PROCESSENTRY32W pe;
    DWORD self = GetCurrentProcessId();

    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        return 0;
    }

    ZeroMemory(&pe, sizeof(pe));
    pe.dwSize = sizeof(pe);

    if (!Process32FirstW(snap, &pe)) {
        CloseHandle(snap);
        return 0;
    }

    do {
        if (pe.th32ProcessID != 0 && pe.th32ProcessID != self) {
            CloseHandle(snap);
            return pe.th32ProcessID;
        }
    } while (Process32NextW(snap, &pe));

    CloseHandle(snap);
    return 0;
}

static BOOL
Subscribe(HANDLE h, DWORD pid, DWORD mask)
{
    STINGER_SUBSCRIBE_REQUEST req;
    DWORD bytes = 0;
    BOOL ok;

    ZeroMemory(&req, sizeof(req));
    req.ProcessId = pid;
    req.StreamMask = mask;

    ok = DeviceIoControl(
        h,
        IOCTL_STINGER_SUBSCRIBE,
        &req,
        sizeof(req),
        NULL,
        0,
        &bytes,
        NULL
    );
    return ok;
}

static BOOL
Unsubscribe(HANDLE h, DWORD pid)
{
    STINGER_UNSUBSCRIBE_REQUEST req;
    DWORD bytes = 0;
    BOOL ok;

    ZeroMemory(&req, sizeof(req));
    req.ProcessId = pid;

    ok = DeviceIoControl(
        h,
        IOCTL_STINGER_UNSUBSCRIBE,
        &req,
        sizeof(req),
        NULL,
        0,
        &bytes,
        NULL
    );
    return ok;
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
            IOCTL_STINGER_GET_EVENT,
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
    DWORD pid = FindOtherProcessId();
    HANDLE p;

    if (pid == 0) {
        return;
    }

    p = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (p != NULL) {
        CloseHandle(p);
    }
}

int __cdecl
main(void)
{
    HANDLE h;
    STINGER_STATS_RESPONSE stats;
    DWORD bytes = 0;
    BOOL ok;
    DWORD selfPid = GetCurrentProcessId();
    TEST_STATE state;
    STINGER_SUBSCRIBE_REQUEST badReq;

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
        return 1;
    }

    ZeroMemory(&badReq, sizeof(badReq));
    badReq.ProcessId = selfPid;
    badReq.StreamMask = 0;
    ok = DeviceIoControl(
        h,
        IOCTL_STINGER_SUBSCRIBE,
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
        return 1;
    }
    printf("[PASS] invalid stream mask rejected\n");

    ok = Subscribe(h, selfPid, STINGER_STREAM_HANDLE | STINGER_STREAM_MEMORY | STINGER_STREAM_THREAD);
    if (!ok) {
        printf("[FAIL] subscribe err=%lu\n", GetLastError());
        CloseHandle(h);
        return 1;
    }
    printf("[PASS] subscribed pid=%lu\n", selfPid);

    ZeroMemory(&stats, sizeof(stats));
    ok = DeviceIoControl(h, IOCTL_STINGER_GET_STATS, NULL, 0, &stats, sizeof(stats), &bytes, NULL);
    if (!ok) {
        printf("[FAIL] get stats err=%lu\n", GetLastError());
        Unsubscribe(h, selfPid);
        CloseHandle(h);
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
        return 1;
    }
    if (!state.SawHandle) {
        printf("[WARN] no handle event observed (target access constraints may block this in hardened VMs)\n");
    } else {
        printf("[PASS] received handle event\n");
    }
    printf("[PASS] received thread event\n");

    ok = Unsubscribe(h, selfPid);
    if (!ok) {
        printf("[FAIL] unsubscribe err=%lu\n", GetLastError());
        CloseHandle(h);
        return 1;
    }
    printf("[PASS] unsubscribe succeeded\n");

    CloseHandle(h);
    printf("[OK] IOCTL smoke test complete. polls=%lu\n", state.Polls);
    return 0;
}
