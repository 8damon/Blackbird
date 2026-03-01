static BOOL WaitForPathLaunchViaEtw(_In_ const SLEEPWALKER_TARGET_SPEC *Spec, _Out_ DWORD *Pid)
{
    SLEEPWALKER_PATH_WATCH_CONTEXT watch;
    SLEEPWALKER_ETW_RUN_CONTEXT run;
    SLEEPWALKERSC_ETW_SESSION *session = NULL;
    HANDLE etwThread = NULL;
    WCHAR sessionName[64];

    if (Spec == NULL || Spec->Kind != SleepwalkerTargetPath || Pid == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    *Pid = 0;
    ZeroMemory(&watch, sizeof(watch));
    ZeroMemory(&run, sizeof(run));
    (void)StringCchCopyW(watch.TargetNormDos, RTL_NUMBER_OF(watch.TargetNormDos), Spec->PathNormDos);
    (void)StringCchCopyW(watch.TargetNormNt, RTL_NUMBER_OF(watch.TargetNormNt), Spec->PathNormNt);
    (void)StringCchCopyW(watch.TargetTail, RTL_NUMBER_OF(watch.TargetTail), Spec->PathTail);

    (void)StringCchPrintfW(sessionName, RTL_NUMBER_OF(sessionName), L"SleepwalkerClientWatch-%lu-%lu",
                           GetCurrentProcessId(), GetTickCount());

    if (!SLEEPWALKERSCStartSleepwalkerEtwSession(sessionName, FALSE, PathWatchEtwCallback, &watch, &session, NULL))
    {
        return FALSE;
    }

    run.Session = session;
    run.Watch = &watch;
    etwThread = CreateThread(NULL, 0, EtwRunThreadProc, &run, 0, NULL);
    if (etwThread == NULL)
    {
        SLEEPWALKERSCStopEtwSession(session);
        return FALSE;
    }

    for (;;)
    {
        if (InterlockedCompareExchange(&watch.Matched, 0, 0) != 0)
        {
            *Pid = watch.MatchedPid;
            break;
        }
        if (InterlockedCompareExchange(&watch.SessionEnded, 0, 0) != 0)
        {
            break;
        }
        if (InterlockedCompareExchange(&g_StopRequested, 0, 0) != 0)
        {
            SetLastError(ERROR_CANCELLED);
            break;
        }
        Sleep(80);
    }

    SLEEPWALKERSCStopEtwSession(session);
    (void)WaitForSingleObject(etwThread, 3000);
    CloseHandle(etwThread);

    return (*Pid != 0);
}

static DWORD WINAPI LiveEtwRunThreadProc(_In_ LPVOID Context)
{
    SLEEPWALKER_LIVE_ETW_CONTEXT *live = (SLEEPWALKER_LIVE_ETW_CONTEXT *)Context;

    if (live == NULL || live->Session == NULL)
    {
        return 1;
    }

    (void)SLEEPWALKERSCRunEtwSession(live->Session);
    InterlockedExchange(&live->SessionEnded, 1);
    return 0;
}

static BOOL StartLiveEtw(_Inout_ SLEEPWALKER_LIVE_ETW_CONTEXT *Live, _Out_ HANDLE *ThreadHandle)
{
    WCHAR sessionName[64];
    BOOL tiEnabled = FALSE;

    if (Live == NULL || ThreadHandle == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    *ThreadHandle = NULL;
    Live->Session = NULL;
    Live->SessionEnded = 0;

    (void)StringCchPrintfW(sessionName, RTL_NUMBER_OF(sessionName), L"SleepwalkerClientLive-%lu-%lu",
                           GetCurrentProcessId(), GetTickCount());

    if (!SLEEPWALKERSCStartSleepwalkerEtwSession(sessionName, TRUE, LiveEtwCallback, Live, &Live->Session, &tiEnabled))
    {
        return FALSE;
    }

    if (!tiEnabled)
    {
        DWORD tiErr = SLEEPWALKERSCGetLastThreatIntelEnableError();
        printf("[*] ETW TI provider unavailable (tiEnableErr=%lu); continuing with Sleepwalker provider only.\n",
               tiErr);
    }

    *ThreadHandle = CreateThread(NULL, 0, LiveEtwRunThreadProc, Live, 0, NULL);
    if (*ThreadHandle == NULL)
    {
        SLEEPWALKERSCStopEtwSession(Live->Session);
        Live->Session = NULL;
        return FALSE;
    }

    g_StopSession = Live->Session;
    return TRUE;
}

static DWORD WINAPI BrokerEtwRunThreadProc(_In_ LPVOID Context)
{
    SLEEPWALKER_BROKER_ETW_CONTEXT *broker = (SLEEPWALKER_BROKER_ETW_CONTEXT *)Context;

    if (broker == NULL || broker->Device == NULL || broker->Device == INVALID_HANDLE_VALUE)
    {
        return 1;
    }

    while (InterlockedCompareExchange(&g_StopRequested, 0, 0) == 0)
    {
        SLEEPWALKER_IPC_ETW_EVENT event;
        BOOL ok;
        DWORD err;

        ok = SLEEPWALKERSCGetEtwEvent(broker->Device, &event, 500);
        if (ok)
        {
            if (!BrokerEtwEventMatchesTargetPid(&event, broker->TargetPid, broker->Scope))
            {
                continue;
            }
            LoggerEmitBrokerEtwEvent(&event);
            continue;
        }

        err = GetLastError();
        if (err == ERROR_NO_MORE_ITEMS)
        {
            continue;
        }
        if (err == ERROR_OPERATION_ABORTED || err == ERROR_NOT_READY || err == ERROR_DEVICE_NOT_CONNECTED ||
            err == ERROR_BROKEN_PIPE)
        {
            break;
        }
        if (err == ERROR_NOT_SUPPORTED || err == ERROR_INVALID_FUNCTION)
        {
            printf("[WARN] broker ETW uplink unsupported by service build.\n");
            break;
        }

        printf("[WARN] broker ETW uplink read failed: %lu\n", err);
        Sleep(100);
    }

    InterlockedExchange(&broker->SessionEnded, 1);
    return 0;
}

static BOOL StartBrokerEtw(_Inout_ SLEEPWALKER_BROKER_ETW_CONTEXT *Broker, _Out_ HANDLE *ThreadHandle,
                           _In_ DWORD SeedPid, _In_ DWORD StreamMask, _In_ SLEEPWALKER_TARGET_SCOPE Scope)
{
    UINT32 capabilities = 0;
    BOOL tiEnabled = FALSE;

    if (Broker == NULL || ThreadHandle == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    *ThreadHandle = NULL;
    ZeroMemory(Broker, sizeof(*Broker));

    if (!SLEEPWALKERSCGetBrokerInfo(&capabilities, &tiEnabled))
    {
        return FALSE;
    }
    if ((capabilities & SLEEPWALKER_IPC_CAP_ETW_TI_UPLINK) == 0)
    {
        SetLastError(ERROR_NOT_SUPPORTED);
        return FALSE;
    }

    Broker->Device = SLEEPWALKERSCOpenControlDevice();
    if (Broker->Device == INVALID_HANDLE_VALUE)
    {
        return FALSE;
    }

    if (SeedPid != 0)
    {
        if (!SLEEPWALKERSCSetPids(Broker->Device, &SeedPid, 1, StreamMask))
        {
            CloseHandle(Broker->Device);
            Broker->Device = INVALID_HANDLE_VALUE;
            return FALSE;
        }
    }

    Broker->ThreatIntelEnabled = tiEnabled;
    Broker->TiEnableError = SLEEPWALKERSCGetBrokerThreatIntelEnableError();
    Broker->TargetPid = SeedPid;
    Broker->Scope = Scope;
    Broker->SessionEnded = 0;

    *ThreadHandle = CreateThread(NULL, 0, BrokerEtwRunThreadProc, Broker, 0, NULL);
    if (*ThreadHandle == NULL)
    {
        CloseHandle(Broker->Device);
        Broker->Device = INVALID_HANDLE_VALUE;
        return FALSE;
    }

    return TRUE;
}

