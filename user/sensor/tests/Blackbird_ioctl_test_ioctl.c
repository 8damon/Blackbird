#include "blackbird_ioctl_test_internal.h"
BOOL Subscribe(HANDLE h, DWORD pid, DWORD mask)
{
    return BLACKBIRDSCSubscribe(h, pid, mask);
}
BOOL SetPids(HANDLE h, const DWORD *pids, DWORD count, DWORD mask)
{
    return BLACKBIRDSCSetPids(h, pids, count, mask);
}
BOOL Unsubscribe(HANDLE h, DWORD pid)
{
    return BLACKBIRDSCUnsubscribe(h, pid);
}
HANDLE OpenControlDeviceHandle(void)
{
    const char *brokerPipe = getenv("BLACKBIRD_TEST_BROKER_PIPE");
    WCHAR brokerPipeWide[MAX_PATH];
    HANDLE device;

    ZeroMemory(brokerPipeWide, sizeof(brokerPipeWide));
    if (brokerPipe != NULL && brokerPipe[0] != '\0')
    {
        if (MultiByteToWideChar(CP_UTF8, 0, brokerPipe, -1, brokerPipeWide, RTL_NUMBER_OF(brokerPipeWide)) <= 0
            && MultiByteToWideChar(CP_ACP, 0, brokerPipe, -1, brokerPipeWide, RTL_NUMBER_OF(brokerPipeWide)) <= 0)
        {
            SetLastError(ERROR_INVALID_PARAMETER);
            return INVALID_HANDLE_VALUE;
        }
    }

    if (!BLACKBIRDSCUseClientProtocol((brokerPipe != NULL && brokerPipe[0] != '\0') ? brokerPipeWide : NULL, 1500))
    {
        return INVALID_HANDLE_VALUE;
    }

    device = BLACKBIRDSCOpenControlDevice();
    if (device == INVALID_HANDLE_VALUE)
    {
        return INVALID_HANDLE_VALUE;
    }
    return device;
}

static DWORD WINAPI MultiClientWorkerThreadProc(_In_ LPVOID Context)
{
    BLACKBIRD_MULTI_CLIENT_WORKER *worker = (BLACKBIRD_MULTI_CLIENT_WORKER *) Context;
    ULONGLONG start = GetTickCount64();

    while ((GetTickCount64() - start) < worker->MaxMs)
    {
        BLACKBIRD_EVENT_RECORD rec;
        DWORD bytes = 0;
        BOOL ok;

        ok = BLACKBIRDSCGetEvent(worker->Device, &rec, &bytes);

        worker->Polls += 1;
        if (!ok)
        {
            DWORD err = GetLastError();
            if (err == ERROR_NO_MORE_ITEMS)
            {
                Sleep(20);
                continue;
            }
            worker->UnexpectedError = err;
            return 1;
        }

        if (rec.Header.Type == BlackbirdEventTypeHandle)
        {
            worker->SawHandle = TRUE;
        }
        else if (rec.Header.Type == BlackbirdEventTypeThread)
        {
            worker->SawThread = TRUE;
        }

        if (worker->SawHandle && worker->SawThread)
        {
            return 0;
        }
    }

    return (worker->SawHandle && worker->SawThread) ? 0 : 2;
}
BOOL RunMultiClientParallelIoctlTest(_In_ DWORD CallerPid, _In_ DWORD TargetPid, _Out_opt_ DWORD *TotalPolls)
{
    HANDLE clients[BLACKBIRD_MULTI_CLIENT_COUNT];
    HANDLE threads[BLACKBIRD_MULTI_CLIENT_COUNT];
    BLACKBIRD_MULTI_CLIENT_WORKER workers[BLACKBIRD_MULTI_CLIENT_COUNT];
    DWORD i;
    BOOL ok = FALSE;
    DWORD pollSum = 0;
    BOOL generatedHandle;
    BOOL generatedThread;

    for (i = 0; i < BLACKBIRD_MULTI_CLIENT_COUNT; ++i)
    {
        clients[i] = INVALID_HANDLE_VALUE;
        threads[i] = NULL;
        ZeroMemory(&workers[i], sizeof(workers[i]));
    }

    for (i = 0; i < BLACKBIRD_MULTI_CLIENT_COUNT; ++i)
    {
        clients[i] = OpenControlDeviceHandle();
        if (clients[i] == INVALID_HANDLE_VALUE)
        {
            goto Cleanup;
        }

        if (!Subscribe(
                    clients[i], CallerPid, BLACKBIRD_STREAM_HANDLE | BLACKBIRD_STREAM_MEMORY | BLACKBIRD_STREAM_THREAD))
        {
            goto Cleanup;
        }
        if (!Subscribe(
                    clients[i], TargetPid, BLACKBIRD_STREAM_HANDLE | BLACKBIRD_STREAM_MEMORY | BLACKBIRD_STREAM_THREAD))
        {
            goto Cleanup;
        }

        workers[i].Device = clients[i];
        workers[i].MaxMs = BLACKBIRD_MULTI_CLIENT_TIMEOUT_MS;
        threads[i] = CreateThread(NULL, 0, MultiClientWorkerThreadProc, &workers[i], 0, NULL);
        if (threads[i] == NULL)
        {
            goto Cleanup;
        }
    }

    generatedHandle = GenerateMemoryHandleIntent(TargetPid);
    generatedThread = GenerateRemoteThreadLoadLibraryIntent(TargetPid);
    if (!generatedHandle || !generatedThread)
    {
        goto Cleanup;
    }

    for (i = 0; i < BLACKBIRD_MULTI_CLIENT_COUNT; ++i)
    {
        DWORD waitResult;
        DWORD exitCode = 1;

        waitResult = WaitForSingleObject(threads[i], BLACKBIRD_MULTI_CLIENT_TIMEOUT_MS + 2000);
        if (waitResult != WAIT_OBJECT_0)
        {
            goto Cleanup;
        }
        if (!GetExitCodeThread(threads[i], &exitCode) || exitCode != 0)
        {
            goto Cleanup;
        }
        if (workers[i].UnexpectedError != 0 || !workers[i].SawHandle || !workers[i].SawThread)
        {
            goto Cleanup;
        }
    }

    ok = TRUE;

Cleanup:
    for (i = 0; i < BLACKBIRD_MULTI_CLIENT_COUNT; ++i)
    {
        if (threads[i] != NULL)
        {
            (void) WaitForSingleObject(threads[i], 1000);
            CloseHandle(threads[i]);
            threads[i] = NULL;
        }
    }

    for (i = 0; i < BLACKBIRD_MULTI_CLIENT_COUNT; ++i)
    {
        pollSum += workers[i].Polls;
        if (clients[i] != INVALID_HANDLE_VALUE)
        {
            (void) Unsubscribe(clients[i], CallerPid);
            (void) Unsubscribe(clients[i], TargetPid);
            CloseHandle(clients[i]);
            clients[i] = INVALID_HANDLE_VALUE;
        }
    }

    if (TotalPolls != NULL)
    {
        *TotalPolls = pollSum;
    }
    return ok;
}

static BOOL RequirementsMet(const TEST_STATE *state, const TEST_EXPECTED *expected)
{
    if (expected->RequireHandleEvent && !state->SawHandle)
    {
        return FALSE;
    }
    if (expected->RequireThreadEvent && !state->SawThread)
    {
        return FALSE;
    }
    if ((state->HandleFlagUnion & expected->RequiredHandleFlags) != expected->RequiredHandleFlags)
    {
        return FALSE;
    }
    if ((state->ThreadFlagUnion & expected->RequiredThreadFlags) != expected->RequiredThreadFlags)
    {
        return FALSE;
    }
    return TRUE;
}
void PumpIoctlEvents(HANDLE h, TEST_STATE *state, const TEST_EXPECTED *expected, DWORD maxMs)
{
    ULONGLONG start = GetTickCount64();

    while ((GetTickCount64() - start) < maxMs)
    {
        BLACKBIRD_EVENT_RECORD rec;
        DWORD bytes = 0;
        BOOL ok;

        ok = BLACKBIRDSCGetEvent(h, &rec, &bytes);

        state->Polls += 1;
        if (!ok)
        {
            DWORD err = GetLastError();
            if (err == ERROR_NO_MORE_ITEMS)
            {
                Sleep(40);
                continue;
            }
            printf("[FAIL] IOCTL_BLACKBIRD_GET_EVENT err=%lu\n", err);
            return;
        }

        BLACKBIRDEventPrinterPrintRecord(&rec);

        if (rec.Header.Type == BlackbirdEventTypeHandle)
        {
            state->SawHandle = TRUE;
            state->HandleEvents += 1;
            state->HandleFlagUnion |= rec.Data.Handle.Flags;
        }
        else if (rec.Header.Type == BlackbirdEventTypeThread)
        {
            state->SawThread = TRUE;
            state->ThreadEvents += 1;
            state->ThreadFlagUnion |= rec.Data.Thread.Flags;
        }

        if (RequirementsMet(state, expected))
        {
            return;
        }
    }
}
void GenerateLocalThreadEvent(void)
{
    HANDLE t = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE) Sleep, (LPVOID) (ULONG_PTR) 15, 0, NULL);
    if (t != NULL)
    {
        WaitForSingleObject(t, 2000);
        CloseHandle(t);
    }
}
