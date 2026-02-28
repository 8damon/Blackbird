static void LoggerEmitIoctlRecord(_In_ const SLEEPWALKER_EVENT_RECORD *Record)
{
    char msg[2048];
    const SLEEPWALKER_HANDLE_EVENT *h;
    const SLEEPWALKER_THREAD_EVENT *t;

    if (Record == NULL)
    {
        return;
    }

    if (Record->Header.Type == SleepwalkerEventTypeHandle)
    {
        if (!g_Logger.Policy.AllowIoctlHandle)
        {
            return;
        }

        h = &Record->Data.Handle;
        (void)StringCchPrintfA(msg, RTL_NUMBER_OF(msg),
                               "seq=%lu class=%u caller=%llu target=%llu access=0x%08X flags=0x%08X origin=0x%llX",
                               (unsigned long)Record->Header.Sequence, (unsigned)h->ClassId,
                               (unsigned long long)h->CallerPid, (unsigned long long)h->TargetPid, h->DesiredAccess,
                               h->Flags, (unsigned long long)h->OriginAddress);
        LoggerEmitJson((h->ClassId == SleepwalkerHandleClassDirectSyscallSuspect) ? 4u : 2u, "ioctl", "handle",
                       (DWORD)h->CallerPid, (DWORD)h->TargetPid, msg);
        return;
    }

    if (Record->Header.Type == SleepwalkerEventTypeThread)
    {
        if (!g_Logger.Policy.AllowIoctlThread)
        {
            return;
        }

        t = &Record->Data.Thread;
        (void)StringCchPrintfA(msg, RTL_NUMBER_OF(msg),
                               "seq=%lu process=%llu thread=%llu creator=%llu flags=0x%08X start=0x%llX imageBase=0x%llX",
                               (unsigned long)Record->Header.Sequence, (unsigned long long)t->ProcessId,
                               (unsigned long long)t->ThreadId, (unsigned long long)t->CreatorPid, t->Flags,
                               (unsigned long long)t->StartAddress, (unsigned long long)t->ImageBase);
        LoggerEmitJson(((t->Flags & SLEEPWALKER_THREAD_FLAG_CORRELATED_INTENT) != 0) ? 3u : 1u, "ioctl", "thread",
                       (DWORD)t->CreatorPid, (DWORD)t->ProcessId, msg);
        return;
    }
}

static void LoggerEmitEtwRecord(_In_ PEVENT_RECORD Record, _In_opt_z_ PCWSTR EventName)
{
    ULONGLONG processId = 0;
    ULONGLONG callerPid = 0;
    ULONGLONG targetPid = 0;
    ULONGLONG severity = 0;
    WCHAR reasonW[384];
    char detectionName[192];
    char reason[512];
    char eventNameUtf8[128];
    char provider[32];
    char message[2048];
    DWORD actorPid = 0;
    DWORD target = 0;

    if (Record == NULL)
    {
        return;
    }

    if (IsEqualGUID(&Record->EventHeader.ProviderId, &SLEEPWALKERSC_PROVIDER_GUID_SLEEPWALKER))
    {
        if (!g_Logger.Policy.AllowEtwSleepwalker)
        {
            return;
        }
        (void)StringCchCopyA(provider, RTL_NUMBER_OF(provider), "sleepwalker");
    }
    else if (IsEqualGUID(&Record->EventHeader.ProviderId, &SLEEPWALKERSC_PROVIDER_GUID_TI))
    {
        if (!g_Logger.Policy.AllowEtwTi)
        {
            return;
        }
        (void)StringCchCopyA(provider, RTL_NUMBER_OF(provider), "ti");
    }
    else
    {
        return;
    }

    (void)GetEtwU64Property(Record, L"processId", &processId);
    (void)GetEtwU64Property(Record, L"callerPid", &callerPid);
    (void)GetEtwU64Property(Record, L"targetPid", &targetPid);
    if (processId == 0)
    {
        processId = callerPid;
    }
    if (processId > 0 && processId <= 0xFFFFFFFFull)
    {
        actorPid = (DWORD)processId;
    }
    if (targetPid > 0 && targetPid <= 0xFFFFFFFFull)
    {
        target = (DWORD)targetPid;
    }

    ZeroMemory(eventNameUtf8, sizeof(eventNameUtf8));
    if (EventName != NULL && EventName[0] != L'\0')
    {
        WideToUtf8(EventName, eventNameUtf8, RTL_NUMBER_OF(eventNameUtf8));
    }
    if (eventNameUtf8[0] == '\0')
    {
        (void)StringCchCopyA(eventNameUtf8, RTL_NUMBER_OF(eventNameUtf8), "unknown");
    }

    if (EventName != NULL && wcscmp(EventName, L"DetectionTelemetry") == 0)
    {
        ZeroMemory(reasonW, sizeof(reasonW));
        ZeroMemory(detectionName, sizeof(detectionName));
        ZeroMemory(reason, sizeof(reason));
        (void)GetEtwAnsiProperty(Record, L"detectionName", detectionName, RTL_NUMBER_OF(detectionName));
        (void)GetEtwWideProperty(Record, L"reason", reasonW, RTL_NUMBER_OF(reasonW));
        (void)GetEtwU64Property(Record, L"severity", &severity);
        WideToUtf8(reasonW, reason, RTL_NUMBER_OF(reason));
        if (detectionName[0] == '\0')
        {
            (void)StringCchCopyA(detectionName, RTL_NUMBER_OF(detectionName), "UNKNOWN");
        }
        (void)StringCchPrintfA(message, RTL_NUMBER_OF(message), "event=%s detection=%s reason=%s", eventNameUtf8,
                               detectionName, (reason[0] != '\0') ? reason : "<none>");
        LoggerEmitJson((severity != 0 && severity <= 10) ? (DWORD)severity : 4u, provider, "detection", actorPid,
                       target, message);
        return;
    }

    (void)StringCchPrintfA(message, RTL_NUMBER_OF(message), "event=%s", eventNameUtf8);
    LoggerEmitJson(1u, provider, "event", actorPid, target, message);
}

static void LoggerEmitBrokerEtwEvent(_In_ const SLEEPWALKER_IPC_ETW_EVENT *Event)
{
    char provider[32];
    char eventNameUtf8[160];
    char message[2048];
    DWORD actorPid = 0;
    DWORD targetPid = 0;
    DWORD severity = 1;
    const char *kind = "event";

    if (Event == NULL)
    {
        return;
    }

    if (Event->Source == SleepwalkerIpcEtwSourceSleepwalker)
    {
        if (!g_Logger.Policy.AllowEtwSleepwalker)
        {
            return;
        }
        (void)StringCchCopyA(provider, RTL_NUMBER_OF(provider), "sleepwalker-broker");
    }
    else if (Event->Source == SleepwalkerIpcEtwSourceThreatIntel)
    {
        if (!g_Logger.Policy.AllowEtwTi)
        {
            return;
        }
        (void)StringCchCopyA(provider, RTL_NUMBER_OF(provider), "ti-broker");
    }
    else
    {
        return;
    }

    if (Event->PrimaryPid != 0 && Event->PrimaryPid <= 0xFFFFFFFFull)
    {
        actorPid = (DWORD)Event->PrimaryPid;
    }
    else
    {
        actorPid = Event->EventProcessId;
    }
    if (Event->SecondaryPid != 0 && Event->SecondaryPid <= 0xFFFFFFFFull)
    {
        targetPid = (DWORD)Event->SecondaryPid;
    }

    eventNameUtf8[0] = '\0';
    if (Event->EventName[0] != L'\0')
    {
        WideToUtf8(Event->EventName, eventNameUtf8, RTL_NUMBER_OF(eventNameUtf8));
    }
    if (eventNameUtf8[0] == '\0')
    {
        (void)StringCchCopyA(eventNameUtf8, RTL_NUMBER_OF(eventNameUtf8), "unknown");
    }

    if (Event->DetectionName[0] != '\0')
    {
        severity = (Event->Severity >= 1 && Event->Severity <= 10) ? Event->Severity : 4;
        kind = "detection";
        (void)StringCchPrintfA(message, RTL_NUMBER_OF(message), "event=%s detection=%s", eventNameUtf8,
                               Event->DetectionName);
        printf("\n[ETW-BROKER] detection=%s severity=%u event=%s actor=%lu target=%lu\n", Event->DetectionName,
               (unsigned)severity, eventNameUtf8, (unsigned long)actorPid, (unsigned long)targetPid);
    }
    else
    {
        (void)StringCchPrintfA(message, RTL_NUMBER_OF(message), "event=%s task=%u opcode=%u", eventNameUtf8,
                               (unsigned)Event->Task, (unsigned)Event->Opcode);
        if (Event->Source == SleepwalkerIpcEtwSourceThreatIntel)
        {
            printf("\n[ETW-BROKER][TI] event=%s task=%u actor=%lu target=%lu\n", eventNameUtf8, (unsigned)Event->Task,
                   (unsigned long)actorPid, (unsigned long)targetPid);
        }
    }

    LoggerEmitJson(severity, provider, kind, actorPid, targetPid, message);
}

int __cdecl main(int argc, char **argv)
{
    HANDLE h;
    HANDLE liveEtwThread = NULL;
    HANDLE brokerEtwThread = NULL;
    SLEEPWALKER_EVENT_RECORD record;
    SLEEPWALKER_TARGET_SPEC targetSpec;
    SLEEPWALKER_ATTACH_CONTEXT attach;
    SLEEPWALKER_LIVE_ETW_CONTEXT liveEtw;
    SLEEPWALKER_BROKER_ETW_CONTEXT brokerEtw;
    SLEEPWALKER_LAUNCH_TARGET launchTarget;
    UINT32 brokerCaps = 0;
    BOOL brokerThreatIntel = FALSE;
    BOOL brokerHasEtwUplink = FALSE;
    DWORD bytes;
    DWORD targetPid;
    DWORD streams;
    DWORD err;
    SLEEPWALKER_TARGET_SCOPE scope = SleepwalkerScopeLocal;
    BOOL ok;
    BOOL symbolsInitialized = FALSE;
    BOOL ioctlVerbose = TRUE;
    BOOL rc = FALSE;
    SLEEPWALKER_CLIENT_POLICY policy;
    const char *configPath = NULL;
    const char *targetArg = NULL;
    const char *streamsArg = NULL;
    const char *scopeArg = NULL;
    const char *brokerPipeArg = NULL;
    const char *positional[3];
    int positionalCount = 0;
    int i;
    BOOL forceDirectIo = FALSE;
    BOOL usingBroker = FALSE;

    (void)SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE);
    ZeroMemory(&attach, sizeof(attach));
    ZeroMemory(&liveEtw, sizeof(liveEtw));
    ZeroMemory(&brokerEtw, sizeof(brokerEtw));
    ZeroMemory(&launchTarget, sizeof(launchTarget));
    PolicyDefaults(&policy);
    for (i = 0; i < (int)RTL_NUMBER_OF(positional); ++i)
    {
        positional[i] = NULL;
    }

    for (i = 1; i < argc; ++i)
    {
        const char *arg = argv[i];
        if (_stricmp(arg, "--config") == 0)
        {
            if (i + 1 >= argc)
            {
                PrintUsage();
                return 1;
            }
            configPath = argv[++i];
        }
    }

    if (configPath != NULL)
    {
        if (!LoadPolicyFile(configPath, &policy))
        {
            printf("[-] failed to load config '%s' (%lu)\n", configPath, GetLastError());
            return 1;
        }
        printf("[*] loaded config: %s\n", configPath);
    }

    positionalCount = 0;
    for (i = 0; i < (int)RTL_NUMBER_OF(positional); ++i)
    {
        positional[i] = NULL;
    }
    for (i = 1; i < argc; ++i)
    {
        const char *arg = argv[i];
        if (_stricmp(arg, "--config") == 0)
        {
            i += 1;
            continue;
        }
        if (_stricmp(arg, "--direct") == 0)
        {
            forceDirectIo = TRUE;
            continue;
        }
        if (_stricmp(arg, "--broker-pipe") == 0)
        {
            if (i + 1 >= argc)
            {
                PrintUsage();
                return 1;
            }
            brokerPipeArg = argv[++i];
            continue;
        }
        if (_stricmp(arg, "--log-format") == 0)
        {
            if (i + 1 >= argc || !PolicySetKeyValue(&policy, "log.format", argv[++i]))
            {
                PrintUsage();
                return 1;
            }
            continue;
        }
        if (_stricmp(arg, "--log-file") == 0)
        {
            if (i + 1 >= argc || !PolicySetKeyValue(&policy, "log.file", argv[++i]))
            {
                PrintUsage();
                return 1;
            }
            continue;
        }
        if (_stricmp(arg, "--high-priority-file") == 0)
        {
            if (i + 1 >= argc || !PolicySetKeyValue(&policy, "log.high_priority_file", argv[++i]))
            {
                PrintUsage();
                return 1;
            }
            continue;
        }
        if (_stricmp(arg, "--high-priority-min-severity") == 0)
        {
            if (i + 1 >= argc || !PolicySetKeyValue(&policy, "log.high_priority_min_severity", argv[++i]))
            {
                PrintUsage();
                return 1;
            }
            continue;
        }
        if (_stricmp(arg, "--ioctl-verbose") == 0)
        {
            if (i + 1 >= argc || !PolicySetKeyValue(&policy, "output.ioctl_verbose", argv[++i]))
            {
                PrintUsage();
                return 1;
            }
            continue;
        }

        if (positionalCount >= 3)
        {
            PrintUsage();
            return 1;
        }
        positional[positionalCount++] = arg;
    }

    if (positionalCount == 1 && _stricmp(positional[0], "shutdown") == 0)
    {
        h = OpenControlDeviceWithBrokerFallback(forceDirectIo, brokerPipeArg, &usingBroker);
        if (h == INVALID_HANDLE_VALUE)
        {
            printf("[-] CreateFile failed (\\\\.\\Global\\SleepwalkerCtl / \\\\.\\SleepwalkerCtl): %lu\n",
                   GetLastError());
            return 1;
        }

        if (!SLEEPWALKERSCSetShutdownMode(h))
        {
            printf("[-] failed to enable shutdown mode via IOCTL_SLEEPWALKER_SET_SHUTDOWN_MODE: %lu\n", GetLastError());
            CloseHandle(h);
            return 1;
        }

        printf("[*] Driver shutdown mode enabled. Active clients should exit shortly.\n");
        CloseHandle(h);
        return 0;
    }

    targetArg = (positionalCount > 0) ? positional[0] : NULL;
    streamsArg = (positionalCount > 1) ? positional[1] : NULL;
    scopeArg = (positionalCount > 2) ? positional[2] : NULL;

    if (targetArg == NULL && policy.HasTarget)
    {
        targetArg = policy.TargetArg;
    }
    if (streamsArg == NULL && policy.HasStreams)
    {
        streamsArg = policy.StreamsArg;
    }
    if (scopeArg == NULL && policy.HasScope)
    {
        scopeArg = policy.ScopeArg;
    }

    if (targetArg == NULL || streamsArg == NULL)
    {
        PrintUsage();
        return 1;
    }

    streams = SLEEPWALKERSCParseStreamMaskA(streamsArg);
    if (streams == 0)
    {
        PrintUsage();
        return 1;
    }
    if (scopeArg != NULL && !ParseScopeArg(scopeArg, &scope))
    {
        PrintUsage();
        return 1;
    }

    if (!ResolveTargetSpec(targetArg, &targetSpec))
    {
        printf("[-] Invalid target '%s'.\n", targetArg);
        return 1;
    }

    if (!ResolveTargetPid(&targetSpec, &targetPid, &launchTarget))
    {
        err = GetLastError();
        if (err == ERROR_CANCELLED)
        {
            printf("[*] Cancelled.\n");
        }
        else
        {
            printf("[-] Could not resolve target '%s': %lu\n", targetArg, err);
        }
        return 1;
    }

    h = OpenControlDeviceWithBrokerFallback(forceDirectIo, brokerPipeArg, &usingBroker);
    if (h == INVALID_HANDLE_VALUE)
    {
        printf("[-] CreateFile failed (\\\\.\\Global\\SleepwalkerCtl / \\\\.\\SleepwalkerCtl): %lu\n", GetLastError());
        return 1;
    }
    printf("[*] Driver channel: %s\n", usingBroker ? "service-broker" : "direct");

    attach.Device = h;
    attach.StreamMask = streams;
    attach.TargetPid = targetPid;
    attach.Scope = scope;
    if (policy.IoctlVerboseOverrideSet)
    {
        ioctlVerbose = policy.IoctlVerboseOverride;
    }

    (void)LoggerInitialize(&policy, targetPid);

    if (!AttachProgramTargetPid(&attach))
    {
        printf("[-] attach failed via IOCTL_SLEEPWALKER_SET_PIDS: %lu\n", GetLastError());
        goto Cleanup;
    }
    printf("[*] Attached target=%lu streams=0x%08lX scope=%s (strict target mode). Ctrl+C to stop.\n", targetPid,
           streams, ScopeToString(scope));
    PrimeTargetImageHint(h, &targetSpec, targetPid);

    if (launchTarget.Active && !launchTarget.Resumed)
    {
        DWORD resumeResult = ResumeThread(launchTarget.ProcessInfo.hThread);
        if (resumeResult == (DWORD)-1)
        {
            printf("[-] ResumeThread failed for launched target pid=%lu: %lu\n", targetPid, GetLastError());
            goto Cleanup;
        }
        launchTarget.Resumed = TRUE;
        printf("[*] Launched target resumed pid=%lu\n", targetPid);
    }

    liveEtw.Attach = &attach;
    SLEEPWALKEREtwSymbolsInitialize();
    symbolsInitialized = TRUE;

    if (usingBroker)
    {
        if (SLEEPWALKERSCGetBrokerInfo(&brokerCaps, &brokerThreatIntel))
        {
            brokerHasEtwUplink = ((brokerCaps & SLEEPWALKER_IPC_CAP_ETW_TI_UPLINK) != 0);
        }
        if (brokerHasEtwUplink && StartBrokerEtw(&brokerEtw, &brokerEtwThread))
        {
            printf("[*] Broker mode active; ETW uplink enabled (service TI=%s).\n",
                   brokerEtw.ThreatIntelEnabled ? "on" : "off");
            printf("[*] Suppressing duplicate IOCTL event dump while broker ETW uplink is active.\n");
            ioctlVerbose = FALSE;
        }
        else
        {
            printf("[WARN] Broker mode active, but ETW uplink unavailable (%lu). Falling back to local ETW session.\n",
                   GetLastError());
            if (!StartLiveEtw(&liveEtw, &liveEtwThread))
            {
                printf("[WARN] live ETW stream unavailable: %lu (continuing with IOCTL stream only)\n", GetLastError());
            }
            else
            {
                printf("[*] Live ETW stream started locally (Sleepwalker provider + TI if available).\n");
                printf("[*] Suppressing duplicate IOCTL event dump while ETW formatter is active.\n");
                ioctlVerbose = FALSE;
            }
        }
    }
    else if (!StartLiveEtw(&liveEtw, &liveEtwThread))
    {
        printf("[WARN] live ETW stream unavailable: %lu (continuing with IOCTL stream only)\n", GetLastError());
    }
    else
    {
        printf("[*] Live ETW stream started (Sleepwalker provider + TI if available).\n");
        printf("[*] Suppressing duplicate IOCTL event dump while ETW formatter is active.\n");
        ioctlVerbose = FALSE;
    }

    while (InterlockedCompareExchange(&g_StopRequested, 0, 0) == 0)
    {
        ok = SLEEPWALKERSCGetEvent(h, &record, &bytes);
        if (!ok)
        {
            err = GetLastError();
            if (err == ERROR_NO_MORE_ITEMS)
            {
                Sleep(80);
                continue;
            }
            if (err == ERROR_NOT_READY || err == ERROR_OPERATION_ABORTED || err == ERROR_DEVICE_NOT_CONNECTED)
            {
                printf("[*] Driver shutdown mode is active; stopping client loop.\n");
                break;
            }
            printf("[-] GetEvent failed: %lu\n", err);
            break;
        }

        if (!IoctlRecordMatchesTargetPid(&record, targetPid, scope))
        {
            continue;
        }

        LoggerEmitIoctlRecord(&record);

        if (!ioctlVerbose)
        {
            continue;
        }

        if (record.Header.Type == SleepwalkerEventTypeHandle)
        {
            PrintHandleEvent(&record.Data.Handle, record.Header.Sequence);
        }
        else if (record.Header.Type == SleepwalkerEventTypeThread)
        {
            PrintThreadEvent(&record.Data.Thread, record.Header.Sequence);
        }
    }

    rc = TRUE;

Cleanup:
    InterlockedExchange(&g_StopRequested, 1);
    if (brokerEtwThread != NULL)
    {
        (void)WaitForSingleObject(brokerEtwThread, 3000);
        CloseHandle(brokerEtwThread);
        brokerEtwThread = NULL;
    }
    if (brokerEtw.Device != NULL && brokerEtw.Device != INVALID_HANDLE_VALUE)
    {
        CloseHandle(brokerEtw.Device);
        brokerEtw.Device = INVALID_HANDLE_VALUE;
    }
    if (liveEtw.Session != NULL)
    {
        SLEEPWALKERSCStopEtwSession(liveEtw.Session);
        g_StopSession = NULL;
    }
    if (liveEtwThread != NULL)
    {
        (void)WaitForSingleObject(liveEtwThread, 3000);
        CloseHandle(liveEtwThread);
        liveEtwThread = NULL;
    }
    SLEEPWALKERFlushEtwPrinterState();
    if (symbolsInitialized)
    {
        SLEEPWALKEREtwSymbolsCleanup();
    }

    if (launchTarget.Active)
    {
        if (!launchTarget.Resumed && launchTarget.ProcessInfo.hProcess != NULL)
        {
            (void)TerminateProcess(launchTarget.ProcessInfo.hProcess, ERROR_CANCELLED);
        }
        if (launchTarget.ProcessInfo.hThread != NULL)
        {
            CloseHandle(launchTarget.ProcessInfo.hThread);
            launchTarget.ProcessInfo.hThread = NULL;
        }
        if (launchTarget.ProcessInfo.hProcess != NULL)
        {
            CloseHandle(launchTarget.ProcessInfo.hProcess);
            launchTarget.ProcessInfo.hProcess = NULL;
        }
        launchTarget.Active = FALSE;
    }

    LoggerShutdown();
    CloseHandle(h);
    return rc ? 0 : 1;
}
