#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <strsafe.h>
#include <winioctl.h>
#include "..\..\abi\stinger_ioctl.h"

static void
PrintUsage(void)
{
    printf("Usage: stinger_client.exe <pid> <streams>\n");
    printf("streams: handle,memory,thread (comma-separated)\n");
    printf("example: stinger_client.exe 4242 handle,memory,thread\n");
}

static DWORD
ParseStreams(_In_z_ const char* text)
{
    DWORD mask = 0;
    char* copy;
    char* ctx = NULL;
    char* tok;

    copy = _strdup(text);
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

static const char*
HandleClassToString(DWORD classId)
{
    switch (classId) {
    case StingerHandleClassLegitimateSyscall:
        return "LEGITIMATE-SYSCALL";
    case StingerHandleClassDirectSyscallSuspect:
        return "DIRECT-SYSCALL-SUSPECT";
    default:
        return "UNKNOWN-ORIGIN";
    }
}

static void
PrintHandleEvent(_In_ const STINGER_HANDLE_EVENT* h, _In_ DWORD sequence)
{
    DWORD i;

    printf("===== [STINGER][HANDLE] seq=%lu =====\n", sequence);
    printf("class=%s callerPid=%016llX targetPid=%016llX access=0x%08X\n",
        HandleClassToString(h->ClassId),
        (unsigned long long)h->CallerPid,
        (unsigned long long)h->TargetPid,
        h->DesiredAccess);
    printf("origin=%016llX protect=0x%08X flags=0x%08X path=%ws\n",
        (unsigned long long)h->OriginAddress,
        h->OriginProtect,
        h->Flags,
        h->OriginPath[0] ? h->OriginPath : L"<unknown>");
    printf("status(open=0x%08X basic=0x%08X section=0x%08X) frames=%u\n",
        (unsigned int)h->StatusOpenProcess,
        (unsigned int)h->StatusBasicInfo,
        (unsigned int)h->StatusSectionName,
        h->FrameCount);
    for (i = 0; i < h->FrameCount && i < STINGER_MAX_EVENT_FRAMES; ++i) {
        printf("stack[%lu]=%016llX\n", i, (unsigned long long)h->Frames[i]);
    }
    printf("=====================================\n");
}

static void
PrintThreadEvent(_In_ const STINGER_THREAD_EVENT* t, _In_ DWORD sequence)
{
    DWORD i;

    printf("===== [STINGER][THREAD] seq=%lu =====\n", sequence);
    printf("pid=%016llX tid=%016llX creatorPid=%016llX flags=0x%08X\n",
        (unsigned long long)t->ProcessId,
        (unsigned long long)t->ThreadId,
        (unsigned long long)t->CreatorPid,
        t->Flags);
    printf("start=%016llX imageBase=%016llX imageSize=0x%llX frames=%u\n",
        (unsigned long long)t->StartAddress,
        (unsigned long long)t->ImageBase,
        (unsigned long long)t->ImageSize,
        t->FrameCount);
    for (i = 0; i < t->FrameCount && i < STINGER_MAX_EVENT_FRAMES; ++i) {
        printf("stack[%lu]=%016llX\n", i, (unsigned long long)t->Frames[i]);
    }
    printf("=====================================\n");
}

int __cdecl
main(int argc, char** argv)
{
    HANDLE h = INVALID_HANDLE_VALUE;
    STINGER_SUBSCRIBE_REQUEST sub;
    STINGER_UNSUBSCRIBE_REQUEST unsub;
    STINGER_EVENT_RECORD record;
    DWORD bytes;
    DWORD pid;
    DWORD streams;
    BOOL ok;

    if (argc != 3) {
        PrintUsage();
        return 1;
    }

    pid = strtoul(argv[1], NULL, 10);
    streams = ParseStreams(argv[2]);
    if (pid == 0 || streams == 0) {
        PrintUsage();
        return 1;
    }

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
        printf("CreateFile failed (\\\\.\\Global\\StingerCtl / \\\\.\\StingerCtl): %lu\n", GetLastError());
        return 1;
    }

    ZeroMemory(&sub, sizeof(sub));
    sub.ProcessId = pid;
    sub.StreamMask = streams;
    ok = DeviceIoControl(
        h,
        IOCTL_STINGER_SUBSCRIBE,
        &sub,
        sizeof(sub),
        NULL,
        0,
        &bytes,
        NULL
    );
    if (!ok) {
        printf("subscribe failed: %lu\n", GetLastError());
        CloseHandle(h);
        return 1;
    }

    printf("subscribed pid=%lu streams=0x%08lX. Ctrl+C to stop.\n", pid, streams);

    for (;;) {
        ZeroMemory(&record, sizeof(record));
        ok = DeviceIoControl(
            h,
            IOCTL_STINGER_GET_EVENT,
            NULL,
            0,
            &record,
            sizeof(record),
            &bytes,
            NULL
        );
        if (!ok) {
            DWORD err = GetLastError();
            if (err == ERROR_NO_MORE_ITEMS) {
                Sleep(80);
                continue;
            }
            printf("get event failed: %lu\n", err);
            break;
        }

        if (record.Header.Type == StingerEventTypeHandle) {
            PrintHandleEvent(&record.Data.Handle, record.Header.Sequence);
        } else if (record.Header.Type == StingerEventTypeThread) {
            PrintThreadEvent(&record.Data.Thread, record.Header.Sequence);
        }
    }

    ZeroMemory(&unsub, sizeof(unsub));
    unsub.ProcessId = pid;
    (void)DeviceIoControl(
        h,
        IOCTL_STINGER_UNSUBSCRIBE,
        &unsub,
        sizeof(unsub),
        NULL,
        0,
        &bytes,
        NULL
    );

    CloseHandle(h);
    return 0;
}
