static DWORD WINAPI ControllerServerThreadProc(_In_ LPVOID Context)
{
    SECURITY_ATTRIBUTES sa;
    PSECURITY_DESCRIPTOR sd = NULL;
    DWORD pipeCreateFailures = 0;

    UNREFERENCED_PARAMETER(Context);

    if (!ControllerCreatePipeSecurity(&sa, &sd))
    {
        ControllerLog("[-] SleepwlkrController: failed to create pipe security (%lu)\n", GetLastError());
        return 1;
    }

    while (!ControllerShouldStop())
    {
        HANDLE pipe;
        BOOL connected;
        DWORD mode = PIPE_READMODE_MESSAGE;
        SLEEPWALKER_CONTROLLER_CLIENT *client;
        HANDLE thread;

        pipe = CreateNamedPipeW(SLEEPWALKER_IPC_PIPE_NAME,
                                PIPE_ACCESS_DUPLEX,
                                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                                PIPE_UNLIMITED_INSTANCES,
                                sizeof(SLEEPWALKER_IPC_PACKET),
                                sizeof(SLEEPWALKER_IPC_PACKET),
                                3000,
                                &sa);
        if (pipe == INVALID_HANDLE_VALUE)
        {
            pipeCreateFailures += 1;
            if (pipeCreateFailures == 1 || (pipeCreateFailures % 50) == 0)
            {
                ControllerLog("[WARN] SleepwlkrController: CreateNamedPipe failed (%lu), retries=%lu\n", GetLastError(),
                              pipeCreateFailures);
            }
            Sleep(250);
            continue;
        }
        pipeCreateFailures = 0;

        connected = ConnectNamedPipe(pipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
        if (!connected)
        {
            ControllerLog("[WARN] SleepwlkrController: ConnectNamedPipe failed (%lu)\n", GetLastError());
            CloseHandle(pipe);
            continue;
        }

        (void)SetNamedPipeHandleState(pipe, &mode, NULL, NULL);

        client = (SLEEPWALKER_CONTROLLER_CLIENT *)calloc(1, sizeof(*client));
        if (client == NULL)
        {
            CloseHandle(pipe);
            continue;
        }

        client->Pipe = pipe;
        client->QueueHead = NULL;
        client->QueueTail = NULL;
        client->QueueDepth = 0;
        client->DroppedEvents = 0;
        client->SubscriptionCount = 0;
        InitializeCriticalSection(&client->Lock);
        if (!GetNamedPipeClientProcessId(pipe, &client->ProcessId))
        {
            client->ProcessId = 0;
        }
        if (!ProcessIdToSessionId(client->ProcessId, &client->SessionId))
        {
            client->SessionId = 0;
        }

        ControllerLog("[IPC] client connected pid=%lu session=%lu\n", client->ProcessId, client->SessionId);

        EnterCriticalSection(&g_ClientListLock);
        if (g_ClientCount >= SLEEPWALKER_CONTROLLER_MAX_CLIENTS)
        {
            LeaveCriticalSection(&g_ClientListLock);
            DeleteCriticalSection(&client->Lock);
            CloseHandle(pipe);
            free(client);
            continue;
        }
        client->Next = g_ClientList;
        g_ClientList = client;
        g_ClientCount += 1;
        ControllerLog("[IPC] active clients=%lu\n", g_ClientCount);
        LeaveCriticalSection(&g_ClientListLock);

        thread = CreateThread(NULL, 0, ControllerClientThreadProc, client, 0, NULL);
        if (thread == NULL)
        {
            ControllerLog("[WARN] SleepwlkrController: failed to spawn client thread for pid=%lu (%lu)\n",
                          client->ProcessId, GetLastError());
            ControllerDetachClient(client);
            DeleteCriticalSection(&client->Lock);
            CloseHandle(pipe);
            free(client);
            continue;
        }
        CloseHandle(thread);
    }

    if (sd != NULL)
    {
        LocalFree(sd);
    }
    return 0;
}

static DWORD WINAPI ControllerDriverPumpThreadProc(_In_ LPVOID Context)
{
    UNREFERENCED_PARAMETER(Context);
    DWORD driverOpenFailures = 0;

    while (!ControllerShouldStop())
    {
        SLEEPWALKER_EVENT_RECORD record;
        DWORD bytes = 0;
        BOOL ok;

        EnterCriticalSection(&g_DriverLock);
        if (g_DriverHandle == INVALID_HANDLE_VALUE)
        {
            g_DriverHandle = SLEEPWALKERSCOpenControlDevice();
            LeaveCriticalSection(&g_DriverLock);
            if (g_DriverHandle != INVALID_HANDLE_VALUE)
            {
                SLEEPWALKER_STATS_RESPONSE stats;
                DWORD statsBytes = 0;
                (void)ControllerApplyDriverSubscriptions();
                driverOpenFailures = 0;
                ZeroMemory(&stats, sizeof(stats));
                if (SLEEPWALKERSCGetStats(g_DriverHandle, &stats, &statsBytes))
                {
                    ControllerLog("[DRIVER] connected and verified. subscriptions=%lu queueDepth=%lu dropped=%lu\n",
                                  stats.SubscriptionCount, stats.QueueDepth, stats.DroppedEvents);
                }
                else
                {
                    ControllerLog("[DRIVER][WARN] connected, but stats query failed (%lu)\n", GetLastError());
                }
            }
            else
            {
                driverOpenFailures += 1;
                if (driverOpenFailures == 1 || (driverOpenFailures % 40) == 0)
                {
                    ControllerLog("[DRIVER][WARN] open failed (%lu), retries=%lu\n", GetLastError(),
                                  driverOpenFailures);
                }
            }
            Sleep(250);
            continue;
        }

        ok = SLEEPWALKERSCGetEvent(g_DriverHandle, &record, &bytes);
        if (!ok)
        {
            DWORD err = GetLastError();
            if (err == ERROR_NO_MORE_ITEMS)
            {
                LeaveCriticalSection(&g_DriverLock);
                Sleep(20);
                continue;
            }

            ControllerLog("[DRIVER][WARN] event read failed (%lu), reconnecting\n", err);
            CloseHandle(g_DriverHandle);
            g_DriverHandle = INVALID_HANDLE_VALUE;
            LeaveCriticalSection(&g_DriverLock);
            Sleep(200);
            continue;
        }
        LeaveCriticalSection(&g_DriverLock);

        if (bytes >= sizeof(record))
        {
            ControllerDispatchDriverRecord(&record);
        }
    }

    return 0;
}
static VOID WINAPI ControllerEtwCallback(_In_ PEVENT_RECORD Record, _In_opt_z_ PCWSTR EventName, _In_opt_ PVOID Context)
{
    SLEEPWALKER_IPC_ETW_EVENT event;
    ULONGLONG processId = 0;
    ULONGLONG callerPid = 0;
    ULONGLONG targetPid = 0;
    ULONG severity = 0;

    UNREFERENCED_PARAMETER(Context);

    if (Record == NULL)
    {
        return;
    }

    ZeroMemory(&event, sizeof(event));
    event.EventId = Record->EventHeader.EventDescriptor.Id;
    event.Opcode = Record->EventHeader.EventDescriptor.Opcode;
    event.Task = Record->EventHeader.EventDescriptor.Task;
    event.EventProcessId = Record->EventHeader.ProcessId;
    event.EventThreadId = Record->EventHeader.ThreadId;
    if (EventName != NULL && EventName[0] != L'\0')
    {
        (void)StringCchCopyW(event.EventName, RTL_NUMBER_OF(event.EventName), EventName);
    }

    if (IsEqualGUID(&Record->EventHeader.ProviderId, &SLEEPWALKERSC_PROVIDER_GUID_TI))
    {
        event.Source = SleepwalkerIpcEtwSourceThreatIntel;
        (void)InterlockedIncrement(&g_EtwTiEvents);
    }
    else if (IsEqualGUID(&Record->EventHeader.ProviderId, &SLEEPWALKERSC_PROVIDER_GUID_SLEEPWALKER))
    {
        event.Source = SleepwalkerIpcEtwSourceSleepwalker;
    }
    else
    {
        return;
    }

    if (EventName != NULL && wcscmp(EventName, L"DetectionTelemetry") == 0)
    {
        (void)InterlockedIncrement(&g_EtwDetectionEvents);
        (void)ControllerEtwGetAnsiProperty(Record, L"detectionName", event.DetectionName,
                                           RTL_NUMBER_OF(event.DetectionName));
        if (event.DetectionName[0] == '\0')
        {
            (void)StringCchCopyA(event.DetectionName, RTL_NUMBER_OF(event.DetectionName), "UNKNOWN");
        }
        (void)ControllerEtwGetU32Property(Record, L"severity", &severity);
        event.Severity = severity;
    }

    (void)ControllerEtwGetU64Property(Record, L"processId", &processId);
    (void)ControllerEtwGetU64Property(Record, L"callerPid", &callerPid);
    (void)ControllerEtwGetU64Property(Record, L"targetPid", &targetPid);
    if (processId == 0)
    {
        processId = callerPid;
    }
    if (processId == 0)
    {
        processId = Record->EventHeader.ProcessId;
    }

    event.PrimaryPid = processId;
    event.SecondaryPid = targetPid;
    ControllerDispatchEtwEvent(&event);
}

static DWORD WINAPI ControllerEtwThreadProc(_In_ LPVOID Context)
{
    DWORD status;

    UNREFERENCED_PARAMETER(Context);

    if (g_EtwSession == NULL)
    {
        return 1;
    }

    status = SLEEPWALKERSCRunEtwSession(g_EtwSession);
    ControllerLog("[ETW] run loop exited status=%lu tiEvents=%ld detectionEvents=%ld\n", status,
                  InterlockedCompareExchange(&g_EtwTiEvents, 0, 0),
                  InterlockedCompareExchange(&g_EtwDetectionEvents, 0, 0));
    return status;
}

static BOOL ControllerStartEtwSession(VOID)
{
    ControllerCleanupStaleEtwSessions();
    (void)InterlockedExchange(&g_EtwTiEvents, 0);
    (void)InterlockedExchange(&g_EtwDetectionEvents, 0);
    g_ThreatIntelEnabled = FALSE;
    if (!SLEEPWALKERSCStartSleepwalkerEtwSession(SLEEPWALKER_CONTROLLER_ETW_SESSION_NAMEW, TRUE, ControllerEtwCallback,
                                                 NULL, &g_EtwSession, &g_ThreatIntelEnabled))
    {
        DWORD err = GetLastError();
        ControllerLog("[WARN] SleepwlkrController: failed to start ETW TI session name=%ws (%lu)\n",
                      SLEEPWALKER_CONTROLLER_ETW_SESSION_NAMEW, err);
        g_EtwSession = NULL;
        g_ThreatIntelEnabled = FALSE;
        return FALSE;
    }

    g_EtwThread = CreateThread(NULL, 0, ControllerEtwThreadProc, NULL, 0, NULL);
    if (g_EtwThread == NULL)
    {
        ControllerLog("[WARN] SleepwlkrController: failed to start ETW thread (%lu)\n", GetLastError());
        SLEEPWALKERSCStopEtwSession(g_EtwSession);
        g_EtwSession = NULL;
        g_ThreatIntelEnabled = FALSE;
        return FALSE;
    }

    ControllerLog("[*] SleepwlkrController: ETW session started. threat-intel=%s\n",
                  g_ThreatIntelEnabled ? "enabled" : "fallback-disabled");
    return TRUE;
}

static VOID ControllerStopEtwSession(VOID)
{
    if (g_EtwSession != NULL)
    {
        SLEEPWALKERSCStopEtwSession(g_EtwSession);
        g_EtwSession = NULL;
    }

    if (g_EtwThread != NULL)
    {
        (void)WaitForSingleObject(g_EtwThread, 3000);
        CloseHandle(g_EtwThread);
        g_EtwThread = NULL;
    }

    ControllerStopEtwSessionByNameBestEffort(SLEEPWALKER_CONTROLLER_ETW_SESSION_NAMEW, "service-stop");
    ControllerLog("[ETW] session stopped tiEvents=%ld detectionEvents=%ld\n",
                  InterlockedCompareExchange(&g_EtwTiEvents, 0, 0),
                  InterlockedCompareExchange(&g_EtwDetectionEvents, 0, 0));
}

static BOOL ControllerStartCore(VOID)
{
    if (g_LocksInitialized)
    {
        return TRUE;
    }

    InitializeCriticalSection(&g_ClientListLock);
    InitializeCriticalSection(&g_DriverLock);
    InitializeCriticalSection(&g_DriverConfigLock);
    g_LocksInitialized = TRUE;

    ControllerLog("[*] SleepwlkrController: core start requested\n");

    g_StopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (g_StopEvent == NULL)
    {
        ControllerLog("[-] SleepwlkrController: failed to create stop event (%lu)\n", GetLastError());
        return FALSE;
    }

    SLEEPWALKERSCUseServiceProtocol();
    g_DriverHandle = SLEEPWALKERSCOpenControlDevice();
    if (g_DriverHandle == INVALID_HANDLE_VALUE)
    {
        ControllerLog("[WARN] SleepwlkrController: initial driver open failed (%lu). retrying in background.\n",
                      GetLastError());
    }
    else
    {
        ControllerLog("[DRIVER] initial open succeeded\n");
    }

    (void)ControllerStartEtwSession();

    g_DriverPumpThread = CreateThread(NULL, 0, ControllerDriverPumpThreadProc, NULL, 0, NULL);
    if (g_DriverPumpThread == NULL)
    {
        ControllerLog("[-] SleepwlkrController: failed to start driver pump thread (%lu)\n", GetLastError());
        return FALSE;
    }

    g_ServerThread = CreateThread(NULL, 0, ControllerServerThreadProc, NULL, 0, NULL);
    if (g_ServerThread == NULL)
    {
        ControllerLog("[-] SleepwlkrController: failed to start server thread (%lu)\n", GetLastError());
        return FALSE;
    }

    ControllerLog("[*] SleepwlkrController: IPC endpoint online at %ls\n", SLEEPWALKER_IPC_PIPE_NAME);
    return TRUE;
}

static VOID ControllerWakeServerPipe(VOID)
{
    HANDLE pipe =
        CreateFileW(SLEEPWALKER_IPC_PIPE_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (pipe != INVALID_HANDLE_VALUE)
    {
        CloseHandle(pipe);
    }
}

static VOID ControllerStopCore(VOID)
{
    DWORD waitMs = 0;

    ControllerLog("[*] SleepwlkrController: stop requested\n");

    if (g_StopEvent != NULL)
    {
        (void)SetEvent(g_StopEvent);
    }

    ControllerWakeServerPipe();

    if (g_ServerThread != NULL)
    {
        (void)WaitForSingleObject(g_ServerThread, 3000);
        CloseHandle(g_ServerThread);
        g_ServerThread = NULL;
    }

    if (g_DriverPumpThread != NULL)
    {
        (void)WaitForSingleObject(g_DriverPumpThread, 3000);
        CloseHandle(g_DriverPumpThread);
        g_DriverPumpThread = NULL;
    }

    EnterCriticalSection(&g_ClientListLock);
    {
        PSLEEPWALKER_CONTROLLER_CLIENT client;
        for (client = g_ClientList; client != NULL; client = client->Next)
        {
            if (client->Pipe != INVALID_HANDLE_VALUE)
            {
                (void)CancelIoEx(client->Pipe, NULL);
                (void)DisconnectNamedPipe(client->Pipe);
            }
        }
    }
    LeaveCriticalSection(&g_ClientListLock);

    while (waitMs < 2000)
    {
        DWORD remaining;
        EnterCriticalSection(&g_ClientListLock);
        remaining = g_ClientCount;
        LeaveCriticalSection(&g_ClientListLock);
        if (remaining == 0)
        {
            break;
        }
        Sleep(50);
        waitMs += 50;
    }

    ControllerStopEtwSession();

    EnterCriticalSection(&g_DriverLock);
    if (g_DriverHandle != INVALID_HANDLE_VALUE)
    {
        CloseHandle(g_DriverHandle);
        g_DriverHandle = INVALID_HANDLE_VALUE;
    }
    LeaveCriticalSection(&g_DriverLock);

    if (g_StopEvent != NULL)
    {
        CloseHandle(g_StopEvent);
        g_StopEvent = NULL;
    }

    ControllerLog("[*] SleepwlkrController: core stopped\n");

}

static DWORD WINAPI ControllerServiceControlHandlerEx(_In_ DWORD ControlCode, _In_ DWORD EventType, _In_ LPVOID EventData,
                                                      _In_ LPVOID Context)
{
    UNREFERENCED_PARAMETER(EventType);
    UNREFERENCED_PARAMETER(EventData);
    UNREFERENCED_PARAMETER(Context);

    if (ControlCode == SERVICE_CONTROL_STOP || ControlCode == SERVICE_CONTROL_SHUTDOWN)
    {
        ControllerLog("[*] SleepwlkrController: service control received code=%lu\n", ControlCode);
        ControllerUpdateServiceStatus(SERVICE_STOP_PENDING, NO_ERROR, 3000);
        if (g_StopEvent != NULL)
        {
            (void)SetEvent(g_StopEvent);
        }
        return NO_ERROR;
    }

    return ERROR_CALL_NOT_IMPLEMENTED;
}

static VOID WINAPI ControllerServiceMain(_In_ DWORD Argc, _In_reads_(Argc) LPWSTR *Argv)
{
    UNREFERENCED_PARAMETER(Argc);
    UNREFERENCED_PARAMETER(Argv);

    ZeroMemory(&g_ServiceStatus, sizeof(g_ServiceStatus));
    g_ServiceStatusHandle = RegisterServiceCtrlHandlerExW(SLEEPWALKER_CONTROLLER_SERVICE_NAMEW,
                                                          ControllerServiceControlHandlerEx, NULL);
    if (g_ServiceStatusHandle == NULL)
    {
        return;
    }
    ControllerLog("[*] SleepwlkrController: service main entered\n");

    ControllerUpdateServiceStatus(SERVICE_START_PENDING, NO_ERROR, 6000);
    if (!ControllerStartCore())
    {
        ControllerUpdateServiceStatus(SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR, 0);
        ControllerStopCore();
        return;
    }

    ControllerUpdateServiceStatus(SERVICE_RUNNING, NO_ERROR, 0);
    ControllerLog("[*] SleepwlkrController: service running\n");
    (void)WaitForSingleObject(g_StopEvent, INFINITE);

    ControllerUpdateServiceStatus(SERVICE_STOP_PENDING, NO_ERROR, 3000);
    ControllerStopCore();
    ControllerUpdateServiceStatus(SERVICE_STOPPED, NO_ERROR, 0);
}

int __cdecl wmain(_In_ int argc, _In_reads_(argc) wchar_t **argv)
{
    SERVICE_TABLE_ENTRYW table[] = {{(LPWSTR)SLEEPWALKER_CONTROLLER_SERVICE_NAMEW, ControllerServiceMain},
                                    {NULL, NULL}};
    BOOL runAsConsole = FALSE;
    int i;

    for (i = 1; i < argc; ++i)
    {
        if (_wcsicmp(argv[i], L"--console") == 0)
        {
            runAsConsole = TRUE;
            break;
        }
    }

    if (runAsConsole)
    {
        ControllerLog("[*] SleepwlkrController: running in console mode.\n");
        if (!ControllerStartCore())
        {
            ControllerStopCore();
            return 1;
        }

        ControllerLog("[*] SleepwlkrController: running. Press Enter to stop.\n");
        (void)getchar();
        ControllerStopCore();
        return 0;
    }

    if (!StartServiceCtrlDispatcherW(table))
    {
        ControllerLog("[-] SleepwlkrController: StartServiceCtrlDispatcherW failed (%lu)\n", GetLastError());
        return 1;
    }

    return 0;
}
