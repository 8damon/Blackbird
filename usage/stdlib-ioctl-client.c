#include <windows.h>
#include <stdio.h>
#include "..\user\sensor\sleepwalker_sensor_core.h"

int __cdecl main(int argc, char **argv)
{
    HANDLE h;
    DWORD pid;
    DWORD mask;

    if (argc < 3)
    {
        printf("usage: stdlib-ioctl-client.exe <pid> handle,memory,thread\n");
        return 1;
    }

    pid = strtoul(argv[1], NULL, 10);
    mask = SLEEPWALKERSCParseStreamMaskA(argv[2]);
    if (pid == 0 || mask == 0)
    {
        printf("invalid pid or stream mask\n");
        return 1;
    }

    h = SLEEPWALKERSCOpenControlDevice();
    if (h == INVALID_HANDLE_VALUE)
    {
        printf("failed to open control device: %lu\n", GetLastError());
        return 1;
    }

    if (!SLEEPWALKERSCSubscribe(h, pid, mask))
    {
        printf("subscribe failed: %lu\n", GetLastError());
        CloseHandle(h);
        return 1;
    }

    printf("subscribed pid=%lu mask=0x%08lX\n", pid, mask);

    for (;;)
    {
        SLEEPWALKER_EVENT_RECORD rec;
        DWORD bytes = 0;

        if (!SLEEPWALKERSCGetEvent(h, &rec, &bytes))
        {
            DWORD err = GetLastError();
            if (err == ERROR_NO_MORE_ITEMS)
            {
                Sleep(25);
                continue;
            }
            printf("get-event failed: %lu\n", err);
            break;
        }

        if (rec.Header.Type == SleepwalkerEventTypeHandle)
        {
            printf("handle event: caller=%lu target=%lu access=0x%08lX\n", rec.Payload.Handle.CallerPid,
                   rec.Payload.Handle.TargetPid, rec.Payload.Handle.DesiredAccess);
        }
        else if (rec.Header.Type == SleepwalkerEventTypeThread)
        {
            printf("thread event: pid=%lu tid=%lu start=0x%p\n", rec.Payload.Thread.ProcessId,
                   rec.Payload.Thread.ThreadId, rec.Payload.Thread.StartAddress);
        }
    }

    (void)SLEEPWALKERSCUnsubscribe(h, pid);
    CloseHandle(h);
    return 0;
}
