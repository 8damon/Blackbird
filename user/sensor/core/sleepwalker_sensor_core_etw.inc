static BOOL SLEEPWALKERSCTryEnablePrivilege(_In_z_ PCWSTR PrivilegeName)
{
    HANDLE token = NULL;
    TOKEN_PRIVILEGES tp;
    LUID luid;
    BOOL ok = FALSE;

    if (PrivilegeName == NULL || PrivilegeName[0] == L'\0')
    {
        return FALSE;
    }

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
    {
        return FALSE;
    }

    if (!LookupPrivilegeValueW(NULL, PrivilegeName, &luid))
    {
        CloseHandle(token);
        return FALSE;
    }

    ZeroMemory(&tp, sizeof(tp));
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    SetLastError(ERROR_SUCCESS);
    ok = AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), NULL, NULL);
    if (!ok || GetLastError() == ERROR_NOT_ALL_ASSIGNED)
    {
        CloseHandle(token);
        return FALSE;
    }

    CloseHandle(token);
    return TRUE;
}

static VOID SLEEPWALKERSCTryEnableEtwPrivileges(VOID)
{
    (void)SLEEPWALKERSCTryEnablePrivilege(L"SeSystemProfilePrivilege");
    (void)SLEEPWALKERSCTryEnablePrivilege(L"SeDebugPrivilege");
    (void)SLEEPWALKERSCTryEnablePrivilege(L"SeSecurityPrivilege");
}

ULONG SLEEPWALKERSCStopSessionByName(_In_z_ PCWSTR SessionName)
{
    ULONG status;
    const ULONG propsBytes = sizeof(EVENT_TRACE_PROPERTIES) + (1024 * sizeof(WCHAR));
    PEVENT_TRACE_PROPERTIES props = (PEVENT_TRACE_PROPERTIES)calloc(1, propsBytes);
    PWSTR loggerName;

    if (SessionName == NULL)
    {
        return ERROR_INVALID_PARAMETER;
    }
    if (props == NULL)
    {
        return ERROR_OUTOFMEMORY;
    }

    props->Wnode.BufferSize = propsBytes;
    props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    loggerName = (PWSTR)((PBYTE)props + props->LoggerNameOffset);
    (void)StringCchCopyW(loggerName, 512, SessionName);

    status = ControlTraceW(0, SessionName, props, EVENT_TRACE_CONTROL_STOP);
    free(props);

    if (status == ERROR_WMI_INSTANCE_NOT_FOUND)
    {
        return ERROR_SUCCESS;
    }
    return status;
}

BOOL SLEEPWALKERSCStartEtwSession(_In_ const SLEEPWALKERSC_ETW_SESSION_CONFIG *Config,
                                  _Outptr_ SLEEPWALKERSC_ETW_SESSION **Session)
{
    SLEEPWALKERSC_ETW_SESSION_INTERNAL *internal = NULL;
    EVENT_TRACE_LOGFILEW log;
    PEVENT_TRACE_PROPERTIES props = NULL;
    PWSTR loggerName;
    ULONG propsBytes;
    ULONG status;
    ULONG i;
    ULONG startAttempt;

    if (Session != NULL)
    {
        *Session = NULL;
    }
    if (Config == NULL || Session == NULL || Config->SessionName == NULL || Config->Providers == NULL ||
        Config->ProviderCount == 0 || Config->Callback == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    internal = (SLEEPWALKERSC_ETW_SESSION_INTERNAL *)calloc(1, sizeof(*internal));
    if (internal == NULL)
    {
        SetLastError(ERROR_OUTOFMEMORY);
        return FALSE;
    }

    (void)StringCchCopyW(internal->SessionName, RTL_NUMBER_OF(internal->SessionName), Config->SessionName);
    internal->Callback = Config->Callback;
    internal->CallbackContext = Config->CallbackContext;
    internal->RunStoppedEvent = CreateEventW(NULL, TRUE, TRUE, NULL);
    if (internal->RunStoppedEvent == NULL)
    {
        free(internal);
        return FALSE;
    }

    SLEEPWALKERSCTryEnableEtwPrivileges();

    (void)SLEEPWALKERSCStopSessionByName(internal->SessionName);
    Sleep(80);

    propsBytes = sizeof(EVENT_TRACE_PROPERTIES) + (1024 * sizeof(WCHAR));
    props = (PEVENT_TRACE_PROPERTIES)calloc(1, propsBytes);
    if (props == NULL)
    {
        CloseHandle(internal->RunStoppedEvent);
        free(internal);
        SetLastError(ERROR_OUTOFMEMORY);
        return FALSE;
    }

    props->Wnode.BufferSize = propsBytes;
    props->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    props->Wnode.ClientContext = 1;
    /*
     * Use secure real-time sessions so protected providers (for example TI on
     * hardened builds) can be enabled when the caller token is otherwise valid.
     */
    props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_SECURE_MODE;
    props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    loggerName = (PWSTR)((PBYTE)props + props->LoggerNameOffset);
    (void)StringCchCopyW(loggerName, 512, internal->SessionName);

    status = ERROR_GEN_FAILURE;
    for (startAttempt = 0; startAttempt < 6; ++startAttempt)
    {
        status = StartTraceW(&internal->SessionHandle, internal->SessionName, props);
        if (status == ERROR_SUCCESS)
        {
            break;
        }
        if (status == ERROR_ALREADY_EXISTS)
        {
            (void)SLEEPWALKERSCStopSessionByName(internal->SessionName);
            Sleep(120);
            continue;
        }
        break;
    }

    if (status != ERROR_SUCCESS)
    {
        free(props);
        CloseHandle(internal->RunStoppedEvent);
        free(internal);
        SetLastError(status);
        return FALSE;
    }

    for (i = 0; i < Config->ProviderCount; ++i)
    {
        status = EnableTraceEx2(internal->SessionHandle, &Config->Providers[i].ProviderId,
                                EVENT_CONTROL_CODE_ENABLE_PROVIDER, Config->Providers[i].Level,
                                Config->Providers[i].MatchAnyKeyword, Config->Providers[i].MatchAllKeyword, 0, NULL);
        if (status != ERROR_SUCCESS)
        {
            if (IsEqualGUID(&Config->Providers[i].ProviderId, &SLEEPWALKERSC_PROVIDER_GUID_TI))
            {
                (void)InterlockedExchange(&g_SleepwalkerLastTiEnableError, (LONG)status);
            }
            (void)SLEEPWALKERSCStopSessionByName(internal->SessionName);
            free(props);
            CloseHandle(internal->RunStoppedEvent);
            free(internal);
            SetLastError(status);
            return FALSE;
        }
    }

    ZeroMemory(&log, sizeof(log));
    log.LoggerName = internal->SessionName;
    log.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    log.EventRecordCallback = SLEEPWALKERSCInternalRecordCallback;
    log.Context = internal;

    internal->TraceHandle = OpenTraceW(&log);
    if (internal->TraceHandle == INVALID_PROCESSTRACE_HANDLE)
    {
        status = GetLastError();
        (void)SLEEPWALKERSCStopSessionByName(internal->SessionName);
        free(props);
        CloseHandle(internal->RunStoppedEvent);
        free(internal);
        SetLastError(status);
        return FALSE;
    }

    free(props);
    *Session = (SLEEPWALKERSC_ETW_SESSION *)internal;
    return TRUE;
}

BOOL SLEEPWALKERSCStartSleepwalkerEtwSession(_In_z_ PCWSTR SessionName, _In_ BOOL EnableThreatIntelProvider,
                                             _In_ SLEEPWALKERSC_ETW_EVENT_CALLBACK Callback,
                                             _In_opt_ PVOID CallbackContext,
                                             _Outptr_ SLEEPWALKERSC_ETW_SESSION **Session,
                                             _Out_opt_ BOOL *ThreatIntelEnabled)
{
    SLEEPWALKERSC_ETW_PROVIDER_CONFIG providers[2];
    SLEEPWALKERSC_ETW_PROVIDER_CONFIG sleepwalkerOnlyProvider;
    SLEEPWALKERSC_ETW_SESSION_CONFIG config;
    BOOL started = FALSE;
    BOOL startedWithTi = FALSE;
    DWORD err = ERROR_SUCCESS;
    DWORD tiErr = ERROR_SUCCESS;

    if (ThreatIntelEnabled != NULL)
    {
        *ThreatIntelEnabled = FALSE;
    }
    if (Session != NULL)
    {
        *Session = NULL;
    }

    (void)InterlockedExchange(&g_SleepwalkerLastTiEnableError, ERROR_SUCCESS);

    if (SessionName == NULL || Callback == NULL || Session == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    ZeroMemory(&providers, sizeof(providers));
    providers[0].ProviderId = SLEEPWALKERSC_PROVIDER_GUID_SLEEPWALKER;
    providers[0].Level = TRACE_LEVEL_INFORMATION;
    providers[0].MatchAnyKeyword = 0;
    providers[0].MatchAllKeyword = 0;
    providers[1].ProviderId = SLEEPWALKERSC_PROVIDER_GUID_TI;
    providers[1].Level = TRACE_LEVEL_INFORMATION;
    providers[1].MatchAnyKeyword = ~0ULL;
    providers[1].MatchAllKeyword = 0;

    ZeroMemory(&config, sizeof(config));
    config.SessionName = SessionName;
    config.Providers = EnableThreatIntelProvider ? providers : &providers[0];
    config.ProviderCount = EnableThreatIntelProvider ? 2 : 1;
    config.Callback = Callback;
    config.CallbackContext = CallbackContext;

    (void)SLEEPWALKERSCStopSessionByName(SessionName);
    Sleep(80);

    if (SLEEPWALKERSCStartEtwSession(&config, Session))
    {
        started = TRUE;
        startedWithTi = EnableThreatIntelProvider ? TRUE : FALSE;
    }
    else
    {
        err = GetLastError();
    }
    tiErr = (DWORD)InterlockedCompareExchange(&g_SleepwalkerLastTiEnableError, 0, 0);

    if (!started && EnableThreatIntelProvider &&
        (tiErr != ERROR_SUCCESS || err == ERROR_ACCESS_DENIED || err == ERROR_PRIVILEGE_NOT_HELD ||
         err == ERROR_NOT_FOUND || err == ERROR_INVALID_PARAMETER))
    {
        sleepwalkerOnlyProvider = providers[0];
        config.Providers = &sleepwalkerOnlyProvider;
        config.ProviderCount = 1;
        if (SLEEPWALKERSCStartEtwSession(&config, Session))
        {
            started = TRUE;
            startedWithTi = FALSE;
        }
        else
        {
            err = GetLastError();
        }
        if (tiErr == ERROR_SUCCESS)
        {
            tiErr = err;
        }
    }

    if (!started)
    {
        if (tiErr != ERROR_SUCCESS)
        {
            (void)InterlockedExchange(&g_SleepwalkerLastTiEnableError, (LONG)tiErr);
        }
        SetLastError(err);
        return FALSE;
    }

    if (ThreatIntelEnabled != NULL)
    {
        *ThreatIntelEnabled = startedWithTi;
    }
    if (startedWithTi)
    {
        (void)InterlockedExchange(&g_SleepwalkerLastTiEnableError, ERROR_SUCCESS);
    }
    else if (tiErr != ERROR_SUCCESS)
    {
        (void)InterlockedExchange(&g_SleepwalkerLastTiEnableError, (LONG)tiErr);
    }
    return TRUE;
}

BOOL SwkStartDetectionEtwSession(_In_z_ PCWSTR SessionName, _In_ BOOL EnableThreatIntelProvider,
                                 _In_ SwkDetectionCallback Callback, _In_opt_ PVOID CallbackContext,
                                 _Outptr_ SLEEPWALKERSC_ETW_SESSION **Session, _Out_opt_ BOOL *ThreatIntelEnabled)
{
    SLEEPWALKERSC_STG_DETECTION_BRIDGE *bridge;
    SLEEPWALKERSC_ETW_SESSION_INTERNAL *internal;
    DWORD err;

    if (ThreatIntelEnabled != NULL)
    {
        *ThreatIntelEnabled = FALSE;
    }
    if (Session != NULL)
    {
        *Session = NULL;
    }

    if (SessionName == NULL || Callback == NULL || Session == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    bridge = (SLEEPWALKERSC_STG_DETECTION_BRIDGE *)calloc(1, sizeof(*bridge));
    if (bridge == NULL)
    {
        SetLastError(ERROR_OUTOFMEMORY);
        return FALSE;
    }

    bridge->Callback = Callback;
    bridge->CallbackContext = CallbackContext;

    if (!SLEEPWALKERSCStartSleepwalkerEtwSession(SessionName, EnableThreatIntelProvider,
                                                 SLEEPWALKERSCStgDetectionBridgeCallback, bridge, Session,
                                                 ThreatIntelEnabled))
    {
        err = GetLastError();
        free(bridge);
        SetLastError(err);
        return FALSE;
    }

    internal = (SLEEPWALKERSC_ETW_SESSION_INTERNAL *)(*Session);
    if (internal == NULL)
    {
        free(bridge);
        SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }
    internal->OwnedCallbackContext = bridge;
    return TRUE;
}

ULONG
SLEEPWALKERSCRunEtwSession(_In_ SLEEPWALKERSC_ETW_SESSION *Session)
{
    SLEEPWALKERSC_ETW_SESSION_INTERNAL *internal = (SLEEPWALKERSC_ETW_SESSION_INTERNAL *)Session;

    if (internal == NULL || internal->TraceHandle == 0 || internal->TraceHandle == INVALID_PROCESSTRACE_HANDLE)
    {
        return ERROR_INVALID_PARAMETER;
    }

    InterlockedIncrement(&internal->ActiveRuns);
    (void)ResetEvent(internal->RunStoppedEvent);

    {
        ULONG status = ProcessTrace(&internal->TraceHandle, 1, NULL, NULL);
        if (InterlockedDecrement(&internal->ActiveRuns) == 0)
        {
            (void)SetEvent(internal->RunStoppedEvent);
        }
        return status;
    }
}

VOID SLEEPWALKERSCStopEtwSession(_In_opt_ SLEEPWALKERSC_ETW_SESSION *Session)
{
    SLEEPWALKERSC_ETW_SESSION_INTERNAL *internal = (SLEEPWALKERSC_ETW_SESSION_INTERNAL *)Session;

    if (internal == NULL)
    {
        return;
    }

    if (internal->TraceHandle != 0 && internal->TraceHandle != INVALID_PROCESSTRACE_HANDLE)
    {
        CloseTrace(internal->TraceHandle);
        internal->TraceHandle = 0;
    }

    if (internal->SessionHandle != 0)
    {
        (void)SLEEPWALKERSCStopSessionByName(internal->SessionName);
        internal->SessionHandle = 0;
    }

    if (internal->RunStoppedEvent != NULL && InterlockedCompareExchange(&internal->ActiveRuns, 0, 0) > 0)
    {
        (void)WaitForSingleObject(internal->RunStoppedEvent, 10000);
    }

    if (internal->RunStoppedEvent != NULL)
    {
        CloseHandle(internal->RunStoppedEvent);
        internal->RunStoppedEvent = NULL;
    }

    if (internal->OwnedCallbackContext != NULL)
    {
        free(internal->OwnedCallbackContext);
        internal->OwnedCallbackContext = NULL;
    }

    free(internal);
}
