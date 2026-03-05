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
        DWORD slotIndex;

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
        client->SlotIndex = SLEEPWALKER_CONTROLLER_INVALID_SLOT;
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
        slotIndex = ControllerAllocateClientSlotLocked();
        if (slotIndex == SLEEPWALKER_CONTROLLER_INVALID_SLOT)
        {
            LeaveCriticalSection(&g_ClientListLock);
            DeleteCriticalSection(&client->Lock);
            CloseHandle(pipe);
            free(client);
            continue;
        }
        client->SlotIndex = slotIndex;
        g_ClientSlots[slotIndex] = client;
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
                ControllerMarkDriverSubscriptionsDirty();
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
        LeaveCriticalSection(&g_DriverLock);

        (void)ControllerApplyDriverSubscriptionsIfDirty();

        EnterCriticalSection(&g_DriverLock);
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

#ifndef SLEEPWALKER_INTENT_PROCESS_MEMORY
#define SLEEPWALKER_INTENT_PROCESS_MEMORY 0x00000001u
#endif

#ifndef SLEEPWALKER_INTENT_THREAD_CONTEXT
#define SLEEPWALKER_INTENT_THREAD_CONTEXT 0x00000002u
#endif

#ifndef SLEEPWALKER_INTENT_DUP_HANDLE
#define SLEEPWALKER_INTENT_DUP_HANDLE 0x00000004u
#endif

static BOOL ControllerIsInterestingHandleAccessMask(_In_ ULONG DesiredAccess)
{
    return ((DesiredAccess & PROCESS_VM_OPERATION) != 0) ||
           ((DesiredAccess & PROCESS_VM_WRITE) != 0) ||
           ((DesiredAccess & PROCESS_CREATE_THREAD) != 0) ||
           ((DesiredAccess & PROCESS_ALL_ACCESS) != 0) ||
           ((DesiredAccess & THREAD_SET_CONTEXT) != 0) ||
           ((DesiredAccess & THREAD_SUSPEND_RESUME) != 0) ||
           ((DesiredAccess & THREAD_ALL_ACCESS) != 0);
}

static BOOL ControllerAnsiContainsInsensitive(_In_opt_z_ const CHAR *Haystack, _In_z_ const CHAR *Needle)
{
    size_t hayLen;
    size_t needleLen;
    size_t i;

    if (Haystack == NULL || Needle == NULL || Needle[0] == '\0')
    {
        return FALSE;
    }

    hayLen = strlen(Haystack);
    needleLen = strlen(Needle);
    if (needleLen == 0 || hayLen < needleLen)
    {
        return FALSE;
    }

    for (i = 0; i <= (hayLen - needleLen); ++i)
    {
        if (_strnicmp(Haystack + i, Needle, needleLen) == 0)
        {
            return TRUE;
        }
    }

    return FALSE;
}

static BOOL ControllerShouldForwardEtwRecord(_In_ PEVENT_RECORD Record, _In_opt_z_ PCWSTR EventName,
                                             _In_ const SLEEPWALKER_IPC_ETW_EVENT *Event)
{
    ULONG desiredAccess = 0;
    ULONG correlationFlags = 0;
    ULONG severity = 0;
    ULONGLONG processId = 0;
    ULONGLONG creatorPid = 0;
    ULONGLONG targetPid = 0;
    CHAR className[64];
    CHAR detectionName[RTL_NUMBER_OF(Event->DetectionName)];
    BOOL selfTarget = FALSE;
    BOOL handleNoiseDetection = FALSE;
    BOOL lowSignalDetection = FALSE;
    BOOL strongDetection = FALSE;

    if (Record == NULL || Event == NULL)
    {
        return FALSE;
    }
    if (EventName == NULL || EventName[0] == L'\0')
    {
        return FALSE;
    }

    if (wcscmp(EventName, L"DetectionTelemetry") == 0)
    {
        ZeroMemory(detectionName, sizeof(detectionName));
        (void)ControllerEtwGetAnsiProperty(Record, L"detectionName", detectionName, RTL_NUMBER_OF(detectionName));
        (void)ControllerEtwGetU32Property(Record, L"severity", &severity);
        (void)ControllerEtwGetU64Property(Record, L"processId", &processId);
        (void)ControllerEtwGetU64Property(Record, L"targetPid", &targetPid);
        if (targetPid == 0)
        {
            targetPid = Event->SecondaryPid;
        }
        if (processId == 0)
        {
            processId = Event->PrimaryPid;
        }
        selfTarget = (processId != 0 && targetPid != 0 && processId == targetPid);

        (void)ControllerEtwGetU32Property(Record, L"correlationFlags", &correlationFlags);

        handleNoiseDetection =
            ControllerAnsiContainsInsensitive(detectionName, "DIRECT_SYSCALL_SUSPECT_HANDLE_OPERATION") ||
            ControllerAnsiContainsInsensitive(detectionName, "STACK_INTEGRITY_ANOMALY_ON_HANDLE_OP") ||
            ControllerAnsiContainsInsensitive(detectionName, "SUSPECT_HANDLE_OPERATION") ||
            ControllerAnsiContainsInsensitive(detectionName, "ANOMALY_ON_HANDLE_OP");

        if (!handleNoiseDetection &&
            (ControllerAnsiContainsInsensitive(detectionName, "USPECT_HANDLE_OPERATION") ||
             ControllerAnsiContainsInsensitive(detectionName, "NOMALY_ON_HANDLE_OP")))
        {
            handleNoiseDetection = TRUE;
        }

        lowSignalDetection =
            ControllerAnsiContainsInsensitive(detectionName, "REMOTE_THREAD_WITH_RECENT_HANDLE_INTENT") ||
            ControllerAnsiContainsInsensitive(detectionName, "THREAD_ACTIVITY_WITH_THREAD_CONTEXT_INTENT") ||
            ControllerAnsiContainsInsensitive(detectionName, "REMOTE_THREAD_OUTSIDE_MAIN_IMAGE");

        strongDetection =
            ControllerAnsiContainsInsensitive(detectionName, "PROCESS_HOLLOWING") ||
            ControllerAnsiContainsInsensitive(detectionName, "INJECTION") ||
            ControllerAnsiContainsInsensitive(detectionName, "THREAD_HIJACK") ||
            ControllerAnsiContainsInsensitive(detectionName, "REMOTE_APC") ||
            ControllerAnsiContainsInsensitive(detectionName, "NON_IMAGE_EXECUTABLE_REGION");

        if (handleNoiseDetection)
        {
            if (selfTarget)
            {
                return FALSE;
            }
            if (severity < 7)
            {
                return FALSE;
            }
            if ((correlationFlags & (SLEEPWALKER_INTENT_PROCESS_MEMORY | SLEEPWALKER_INTENT_THREAD_CONTEXT |
                                     SLEEPWALKER_INTENT_DUP_HANDLE)) == 0)
            {
                return FALSE;
            }

            return TRUE;
        }

        if (lowSignalDetection)
        {
            return FALSE;
        }

        if (strongDetection)
        {
            return (severity >= 5);
        }

        return (severity >= 6);
    }

    if (Event->Source == SleepwalkerIpcEtwSourceThreatIntel)
    {
        return (Event->Task == 1 || Event->Task == 2 || Event->Task == 7);
    }

    if (wcscmp(EventName, L"HandleTelemetry") == 0)
    {
        ZeroMemory(className, sizeof(className));
        (void)ControllerEtwGetAnsiProperty(Record, L"class", className, RTL_NUMBER_OF(className));
        (void)ControllerEtwGetU32Property(Record, L"desiredAccess", &desiredAccess);

        if (_stricmp(className, "DIRECT-SYSCALL-SUSPECT") == 0 || _stricmp(className, "UNKNOWN-ORIGIN") == 0)
        {
            return TRUE;
        }
        return ControllerIsInterestingHandleAccessMask(desiredAccess);
    }

    if (wcscmp(EventName, L"ApcTelemetry") == 0)
    {
        (void)ControllerEtwGetU32Property(Record, L"desiredAccess", &desiredAccess);
        return ((desiredAccess & (THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME)) != 0);
    }

    if (wcscmp(EventName, L"ThreadTelemetry") == 0)
    {
        (void)ControllerEtwGetU32Property(Record, L"correlationFlags", &correlationFlags);
        (void)ControllerEtwGetU64Property(Record, L"processId", &processId);
        (void)ControllerEtwGetU64Property(Record, L"creatorPid", &creatorPid);

        if ((correlationFlags & (SLEEPWALKER_INTENT_PROCESS_MEMORY | SLEEPWALKER_INTENT_THREAD_CONTEXT |
                                 SLEEPWALKER_INTENT_DUP_HANDLE)) != 0)
        {
            return TRUE;
        }

        if (processId != 0 && creatorPid != 0 && processId != creatorPid)
        {
            return TRUE;
        }
        return FALSE;
    }

    if (wcscmp(EventName, L"ProcessTelemetry") == 0)
    {
        return FALSE;
    }
    if (wcscmp(EventName, L"ImageTelemetry") == 0)
    {
        return FALSE;
    }
    if (wcscmp(EventName, L"RegistryTelemetry") == 0)
    {
        return FALSE;
    }

    return FALSE;
}

static VOID WINAPI ControllerEtwCallback(_In_ PEVENT_RECORD Record, _In_opt_z_ PCWSTR EventName, _In_opt_ PVOID Context)
{
    SLEEPWALKER_IPC_ETW_EVENT event;
    ULONGLONG processId = 0;
    ULONGLONG callerPid = 0;
    ULONGLONG targetPid = 0;
    ULONGLONG parentProcessId = 0;
    ULONGLONG creatorProcessId = 0;
    ULONG severity = 0;
    ULONG correlationFlags = 0;
    ULONG correlationAccessMask = 0;
    ULONG correlationAgeMs = 0;

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
        (void)ControllerEtwGetU32Property(Record, L"correlationFlags", &correlationFlags);
        (void)ControllerEtwGetU32Property(Record, L"correlationAccessMask", &correlationAccessMask);
        (void)ControllerEtwGetU32Property(Record, L"correlationAgeMs", &correlationAgeMs);
        event.CorrelationFlags = (UINT32)correlationFlags;
        event.CorrelationAccessMask = (UINT32)correlationAccessMask;
        event.CorrelationAgeMs = (UINT32)correlationAgeMs;
        (void)ControllerEtwGetWideProperty(Record, L"reason", event.Reason, RTL_NUMBER_OF(event.Reason));
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
    ControllerProcessHollowingEtwRecord(Record, EventName, &event);

    if (EventName != NULL && wcscmp(EventName, L"ProcessTelemetry") == 0)
    {
        DWORD sourcePid32 = 0;
        DWORD childPid32 = 0;

        (void)ControllerEtwGetU64Property(Record, L"parentProcessId", &parentProcessId);
        (void)ControllerEtwGetU64Property(Record, L"creatorProcessId", &creatorProcessId);
        if (processId != 0 && processId <= 0xFFFFFFFFull)
        {
            childPid32 = (DWORD)processId;
            if (creatorProcessId != 0 && creatorProcessId <= 0xFFFFFFFFull)
            {
                sourcePid32 = (DWORD)creatorProcessId;
            }
            else if (parentProcessId != 0 && parentProcessId <= 0xFFFFFFFFull)
            {
                sourcePid32 = (DWORD)parentProcessId;
            }
        }

        if (sourcePid32 != 0 && childPid32 != 0 && sourcePid32 != childPid32)
        {
            ControllerExpandMonitoringGraph(sourcePid32, childPid32, SLEEPWALKER_CONTROLLER_DRIVER_STREAM_MASK);
        }
    }

    if (!ControllerShouldForwardEtwRecord(Record, EventName, &event))
    {
        return;
    }

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

static BOOL ControllerIsThreatIntelRetryableError(_In_ DWORD ErrorCode)
{
    if (ErrorCode == ERROR_SUCCESS)
    {
        return FALSE;
    }
    if (ErrorCode == ERROR_ACCESS_DENIED || ErrorCode == ERROR_PRIVILEGE_NOT_HELD ||
        ErrorCode == ERROR_NOT_SUPPORTED)
    {
        return FALSE;
    }
    return TRUE;
}

static VOID WINAPI ControllerEtwWarmupCallback(_In_ PEVENT_RECORD Record, _In_opt_z_ PCWSTR EventName, _In_opt_ PVOID Context)
{
    UNREFERENCED_PARAMETER(Record);
    UNREFERENCED_PARAMETER(EventName);
    UNREFERENCED_PARAMETER(Context);
}

static BOOL ControllerWarmupThreatIntelProvider(_Out_opt_ DWORD *ErrorCode)
{
    WCHAR warmupSessionName[96];
    SLEEPWALKERSC_ETW_PROVIDER_CONFIG provider;
    SLEEPWALKERSC_ETW_SESSION_CONFIG config;
    SLEEPWALKERSC_ETW_SESSION *warmupSession = NULL;
    BOOL ok;
    DWORD err = ERROR_SUCCESS;

    ZeroMemory(&provider, sizeof(provider));
    provider.ProviderId = SLEEPWALKERSC_PROVIDER_GUID_TI;
    provider.Level = TRACE_LEVEL_INFORMATION;
    provider.MatchAnyKeyword = ~0ULL;
    provider.MatchAllKeyword = 0;

    ZeroMemory(&config, sizeof(config));
    (void)StringCchPrintfW(warmupSessionName, RTL_NUMBER_OF(warmupSessionName), L"%ws-TiWarmup",
                           SLEEPWALKER_CONTROLLER_ETW_SESSION_NAMEW);
    config.SessionName = warmupSessionName;
    config.Providers = &provider;
    config.ProviderCount = 1;
    config.Callback = ControllerEtwWarmupCallback;
    config.CallbackContext = NULL;

    ok = SLEEPWALKERSCStartEtwSession(&config, &warmupSession);
    if (ok)
    {
        // Brief hold gives the TI provider a chance to fully activate.
        Sleep(120);
        SLEEPWALKERSCStopEtwSession(warmupSession);
        warmupSession = NULL;
        err = ERROR_SUCCESS;
    }
    else
    {
        err = GetLastError();
    }

    if (ErrorCode != NULL)
    {
        *ErrorCode = err;
    }
    return ok;
}

static VOID ControllerTryRecoverThreatIntelSession(_In_ DWORD InitialTiError)
{
    const DWORD maxAttempts = 3;
    DWORD attempt;
    DWORD tiErr = InitialTiError;

    if (g_EtwSession == NULL || g_ThreatIntelEnabled || !ControllerIsThreatIntelRetryableError(InitialTiError))
    {
        return;
    }

    for (attempt = 1; attempt <= maxAttempts && !ControllerShouldStop(); ++attempt)
    {
        DWORD warmErr = ERROR_SUCCESS;
        BOOL warmOk;

        ControllerLog("[ETW][WARN] TI inactive after subscribe (err=%lu). warmup+restart attempt %lu/%lu\n",
                      tiErr, attempt, maxAttempts);

        warmOk = ControllerWarmupThreatIntelProvider(&warmErr);
        if (!warmOk)
        {
            ControllerLog("[ETW][WARN] TI warmup failed attempt=%lu err=%lu\n", attempt, warmErr);
        }

        SLEEPWALKERSCStopEtwSession(g_EtwSession);
        g_EtwSession = NULL;
        g_ThreatIntelEnabled = FALSE;

        if (!SLEEPWALKERSCStartSleepwalkerEtwSession(SLEEPWALKER_CONTROLLER_ETW_SESSION_NAMEW, TRUE, ControllerEtwCallback,
                                                     NULL, &g_EtwSession, &g_ThreatIntelEnabled))
        {
            DWORD restartErr = GetLastError();
            tiErr = SLEEPWALKERSCGetLastThreatIntelEnableError();
            ControllerLog("[ETW][WARN] restart after TI warmup failed attempt=%lu startErr=%lu tiErr=%lu\n",
                          attempt, restartErr, tiErr);
            if (attempt < maxAttempts)
            {
                Sleep(180 * attempt);
            }
            continue;
        }

        tiErr = SLEEPWALKERSCGetLastThreatIntelEnableError();
        g_ThreatIntelEnableError = tiErr;
        if (g_ThreatIntelEnabled)
        {
            ControllerLog("[ETW] TI provider enabled after warmup attempt %lu (tiEnableErr=%lu)\n", attempt, tiErr);
            return;
        }

        ControllerLog("[ETW][WARN] TI still inactive after restart attempt=%lu tiEnableErr=%lu\n", attempt, tiErr);
        if (!ControllerIsThreatIntelRetryableError(tiErr))
        {
            return;
        }

        if (attempt < maxAttempts)
        {
            Sleep(180 * attempt);
        }
    }

    UNREFERENCED_PARAMETER(tiErr);
}

static BOOL ControllerStartEtwSession(VOID)
{
    DWORD tiErr = ERROR_SUCCESS;

    ControllerCleanupStaleEtwSessions();
    (void)InterlockedExchange(&g_EtwTiEvents, 0);
    (void)InterlockedExchange(&g_EtwDetectionEvents, 0);
    g_ThreatIntelEnabled = FALSE;
    g_ThreatIntelEnableError = ERROR_SUCCESS;
    if (!SLEEPWALKERSCStartSleepwalkerEtwSession(SLEEPWALKER_CONTROLLER_ETW_SESSION_NAMEW, TRUE, ControllerEtwCallback,
                                                 NULL, &g_EtwSession, &g_ThreatIntelEnabled))
    {
        DWORD err = GetLastError();
        g_ThreatIntelEnableError = err;
        ControllerLog("[WARN] SleepwlkrController: failed to start ETW TI session name=%ws (%lu)\n",
                      SLEEPWALKER_CONTROLLER_ETW_SESSION_NAMEW, err);
        g_EtwSession = NULL;
        g_ThreatIntelEnabled = FALSE;
        return FALSE;
    }

    tiErr = SLEEPWALKERSCGetLastThreatIntelEnableError();
    g_ThreatIntelEnableError = tiErr;
    if (!g_ThreatIntelEnabled)
    {
        ControllerTryRecoverThreatIntelSession(tiErr);
        tiErr = SLEEPWALKERSCGetLastThreatIntelEnableError();
        g_ThreatIntelEnableError = tiErr;
    }
    if (g_EtwSession == NULL)
    {
        ControllerLog("[WARN] SleepwlkrController: ETW session unavailable after TI recovery attempts\n");
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

    ControllerLog("[*] SleepwlkrController: ETW session started. threat-intel=%s tiEnableErr=%lu\n",
                  g_ThreatIntelEnabled ? "enabled" : "disabled", tiErr);
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
    g_ClientList = NULL;
    g_ClientCount = 0;
    g_PidIndexCount = 0;
    ZeroMemory(g_ClientSlots, sizeof(g_ClientSlots));
    ZeroMemory(g_PidIndex, sizeof(g_PidIndex));

    ControllerLog("[*] SleepwlkrController: core start requested\n");
    ControllerResetHollowingState();

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

    ControllerResetHollowingState();

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
