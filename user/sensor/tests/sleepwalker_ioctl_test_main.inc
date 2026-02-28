int __cdecl main(int argc, char **argv)
{
    HANDLE h = INVALID_HANDLE_VALUE;
    SLEEPWALKER_STATS_RESPONSE stats;
    DWORD bytes = 0;
    BOOL ok;
    DWORD selfPid = GetCurrentProcessId();
    TEST_STATE state;
    TEST_EXPECTED expected;
    SLEEPWALKER_SUBSCRIBE_REQUEST badReq;
    BOOL subscribedSelf = FALSE;
    BOOL subscribedChild = FALSE;
    CHILD_CTX child;
    BOOL generatedMemoryIntent = FALSE;
    BOOL generatedThreadIntent = FALSE;
    BOOL generatedDuplicateIntent = FALSE;
    BOOL generatedRemoteAfterMemory = FALSE;
    BOOL generatedRemoteAfterThread = FALSE;
    BOOL generatedRemoteAfterDup = FALSE;
    BOOL generatedRegistry = FALSE;
    BOOL generatedVmApiCalls = FALSE;
    BOOL multiClientParallelOk = FALSE;
    BOOL setPidsApplied = FALSE;
    DWORD multiClientPolls = 0;
    ETW_CAPTURE etw;
    BROKER_ETW_CAPTURE brokerEtw;
    BOOL etwStarted = FALSE;
    BOOL etwCoverageMet = FALSE;
    BOOL brokerMode = FALSE;
    BOOL brokerEtwStarted = FALSE;
    BOOL brokerEtwCoverageMet = FALSE;
    BOOL requireKernelCorrelationSignals = FALSE;
    BOOL requireApcTelemetry = FALSE;
    SUITE_RESULTS results;
    BOOL reportReady;

    if (argc > 1 && strcmp(argv[1], SLEEPWALKER_CHILD_ARG) == 0)
    {
        Sleep(15000);
        return 0;
    }

    SLEEPWALKERSymbolResolverInitialize();
    ZeroMemory(&state, sizeof(state));
    ZeroMemory(&expected, sizeof(expected));
    ZeroMemory(&child, sizeof(child));
    ZeroMemory(&etw, sizeof(etw));
    ZeroMemory(&brokerEtw, sizeof(brokerEtw));
    ZeroMemory(&results, sizeof(results));
    reportReady = SuiteInitReport(&results);
    if (!reportReady)
    {
        printf("reportStatus=unavailable\n");
    }
    requireKernelCorrelationSignals = EnvFlagEnabled("SLEEPWALKER_TEST_REQUIRE_KERNEL_CORRELATION", FALSE);
    requireApcTelemetry = EnvFlagEnabled("SLEEPWALKER_TEST_REQUIRE_APC", FALSE);
    printf("[INFO] suite knobs requireKernelCorrelation=%u requireApcTelemetry=%u\n",
           requireKernelCorrelationSignals ? 1u : 0u, requireApcTelemetry ? 1u : 0u);
    LogEnvironmentBaseline(&results);

    h = OpenControlDeviceHandle();
    RecordResult(&results, (h != INVALID_HANDLE_VALUE), "opened control device",
                 "failed to open control device \\\\.\\Global\\SleepwalkerCtl/\\\\.\\SleepwalkerCtl");
    if (h == INVALID_HANDLE_VALUE)
    {
        goto Cleanup;
    }
    brokerMode = (SLEEPWALKERSCGetProtocolMode() == SLEEPWALKERSC_PROTOCOL_CLIENT);
    printf("[INFO] transport mode=%s\n", brokerMode ? "service-broker" : "direct");

    RunIoctlContractTests(h, selfPid, &results);

    etwStarted = StartEtwCapture(&etw);
    RecordResult(&results, etwStarted, "started ETW capture session", "failed to start ETW capture session");
    if (brokerMode)
    {
        brokerEtwStarted = StartBrokerEtwCapture(&brokerEtw);
        RecordResult(&results, brokerEtwStarted, "started broker ETW/TI uplink capture",
                     "failed to start broker ETW/TI uplink capture");
        if (brokerEtwStarted && !brokerEtw.TiProviderEnabled)
        {
            printf("[INFO] broker ETW started without TI provider (service fallback or unavailable)\n");
        }
    }

    ZeroMemory(&badReq, sizeof(badReq));
    badReq.ProcessId = selfPid;
    badReq.StreamMask = 0;
    ok = SLEEPWALKERSCSubscribe(h, badReq.ProcessId, badReq.StreamMask);
    RecordResult(&results, (!ok && GetLastError() == ERROR_INVALID_PARAMETER), "invalid subscribe stream mask rejected",
                 "invalid subscribe stream mask was not rejected");

    ok = Subscribe(h, selfPid, SLEEPWALKER_STREAM_HANDLE | SLEEPWALKER_STREAM_MEMORY | SLEEPWALKER_STREAM_THREAD);
    subscribedSelf = ok;
    RecordResult(&results, ok, "subscribed self", "subscribe self failed");
    if (!ok)
    {
        goto Cleanup;
    }
    printf("[INFO] subscribed self pid=%lu\n", selfPid);

    ZeroMemory(&stats, sizeof(stats));
    ok = SLEEPWALKERSCGetStats(h, &stats, &bytes);
    RecordResult(&results, ok, "queried IOCTL stats", "get stats failed");
    if (ok)
    {
        printf("[INFO] stats subscriptionCount=%u queueDepth=%u dropped=%u\n", stats.SubscriptionCount,
               stats.QueueDepth, stats.DroppedEvents);
        RecordResult(&results, (bytes == sizeof(stats)), "GET_STATS returned expected byte count",
                     "GET_STATS returned unexpected byte count");
    }

    ok = StartIdleChild(&child);
    RecordResult(&results, ok, "launched child process", "failed to launch child process");
    if (!ok)
    {
        goto Cleanup;
    }
    printf("[INFO] child pid=%lu tid=%lu\n", child.Pi.dwProcessId, child.Pi.dwThreadId);

    ok = Subscribe(h, child.Pi.dwProcessId,
                   SLEEPWALKER_STREAM_HANDLE | SLEEPWALKER_STREAM_MEMORY | SLEEPWALKER_STREAM_THREAD);
    subscribedChild = ok;
    RecordResult(&results, ok, "subscribed child", "subscribe child failed");
    if (!ok)
    {
        goto Cleanup;
    }

    {
        DWORD pidList[2];
        pidList[0] = selfPid;
        pidList[1] = child.Pi.dwProcessId;

        setPidsApplied = SetPids(h, pidList, RTL_NUMBER_OF(pidList),
                                 SLEEPWALKER_STREAM_HANDLE | SLEEPWALKER_STREAM_MEMORY | SLEEPWALKER_STREAM_THREAD);
        RecordResult(&results, setPidsApplied, "applied PID list subscription via IOCTL_SLEEPWALKER_SET_PIDS",
                     "failed to apply PID list subscription via IOCTL_SLEEPWALKER_SET_PIDS");
        if (setPidsApplied)
        {
            ZeroMemory(&stats, sizeof(stats));
            ok = SLEEPWALKERSCGetStats(h, &stats, &bytes);
            RecordResult(&results, (ok && stats.SubscriptionCount == 2),
                         "SET_PIDS applied expected subscription cardinality",
                         "SET_PIDS did not apply expected subscription cardinality");
        }
    }

    GenerateLocalThreadEvent();

    generatedMemoryIntent = GenerateMemoryHandleIntent(child.Pi.dwProcessId);
    RecordResult(&results, generatedMemoryIntent, "generated memory-handle intent",
                 "failed to generate memory-handle intent");

    generatedThreadIntent = GenerateThreadContextHandleIntent(child.Pi.dwThreadId);
    RecordResult(&results, generatedThreadIntent, "generated thread-context-handle intent",
                 "failed to generate thread-context-handle intent");

    generatedDuplicateIntent = GenerateDuplicateHandleIntent(child.Pi.dwProcessId);
    RecordResult(&results, generatedDuplicateIntent, "generated duplicate-handle intent",
                 "failed to generate duplicate-handle intent");

    if (generatedMemoryIntent)
    {
        generatedRemoteAfterMemory = GenerateRemoteThreadLoadLibraryIntent(child.Pi.dwProcessId);
        RecordResult(&results, generatedRemoteAfterMemory, "generated remote thread after memory intent",
                     "failed to generate remote thread after memory intent");
    }

    if (generatedThreadIntent)
    {
        generatedRemoteAfterThread = GenerateRemoteThreadLoadLibraryIntent(child.Pi.dwProcessId);
        RecordResult(&results, generatedRemoteAfterThread, "generated remote thread after thread-context intent",
                     "failed to generate remote thread after thread-context intent");
    }

    if (generatedDuplicateIntent)
    {
        generatedRemoteAfterDup = GenerateRemoteThreadLoadLibraryIntent(child.Pi.dwProcessId);
        RecordResult(&results, generatedRemoteAfterDup, "generated remote thread after duplicate intent",
                     "failed to generate remote thread after duplicate intent");
    }

    generatedRegistry = GenerateRegistryHighValueActivity();
    RecordResult(&results, generatedRegistry, "generated high-value registry activity",
                 "failed to generate high-value registry activity");

    generatedVmApiCalls = GenerateVmApiCallSurface(child.Pi.dwProcessId);
    RecordResult(&results, generatedVmApiCalls, "generated VM API-call surface (alloc/write/protect)",
                 "failed to generate VM API-call surface (alloc/write/protect)");

    expected.RequireThreadEvent = TRUE;
    expected.RequireHandleEvent = generatedMemoryIntent || generatedThreadIntent || generatedDuplicateIntent;
    if (generatedMemoryIntent)
    {
        expected.RequiredHandleFlags |= SLEEPWALKER_HANDLE_FLAG_MEMORY_RELATED;
    }
    if (generatedThreadIntent)
    {
        expected.RequiredHandleFlags |= SLEEPWALKER_HANDLE_FLAG_THREAD_OBJECT;
    }
    if (generatedDuplicateIntent)
    {
        expected.RequiredHandleFlags |= SLEEPWALKER_HANDLE_FLAG_DUPLICATE_OPERATION;
    }
    if (requireKernelCorrelationSignals && generatedRemoteAfterMemory)
    {
        expected.RequiredThreadFlags |= SLEEPWALKER_THREAD_FLAG_CORRELATED_INTENT | SLEEPWALKER_THREAD_FLAG_CORR_MEMORY;
    }
    if (requireKernelCorrelationSignals && generatedRemoteAfterThread)
    {
        expected.RequiredThreadFlags |=
            SLEEPWALKER_THREAD_FLAG_CORRELATED_INTENT | SLEEPWALKER_THREAD_FLAG_CORR_THREAD_CTX;
    }
    if (requireKernelCorrelationSignals && generatedRemoteAfterDup)
    {
        expected.RequiredThreadFlags |=
            SLEEPWALKER_THREAD_FLAG_CORRELATED_INTENT | SLEEPWALKER_THREAD_FLAG_CORR_DUP_HANDLE;
    }

    PumpIoctlEvents(h, &state, &expected, 14000);

    RecordResult(&results, state.SawThread, "received thread telemetry via IOCTL",
                 "missing thread telemetry via IOCTL");

    if (expected.RequireHandleEvent)
    {
        RecordResult(&results, state.SawHandle, "received handle telemetry via IOCTL",
                     "missing handle telemetry via IOCTL");
    }

    if (generatedMemoryIntent)
    {
        RecordResult(&results, ((state.HandleFlagUnion & SLEEPWALKER_HANDLE_FLAG_MEMORY_RELATED) != 0),
                     "observed IOCTL handle flag MemoryRelated", "missing IOCTL handle flag MemoryRelated");
    }

    if (generatedThreadIntent)
    {
        RecordResult(&results, ((state.HandleFlagUnion & SLEEPWALKER_HANDLE_FLAG_THREAD_OBJECT) != 0),
                     "observed IOCTL handle flag ThreadObject", "missing IOCTL handle flag ThreadObject");
    }

    if (generatedDuplicateIntent)
    {
        RecordResult(&results, ((state.HandleFlagUnion & SLEEPWALKER_HANDLE_FLAG_DUPLICATE_OPERATION) != 0),
                     "observed IOCTL handle flag DuplicateOperation", "missing IOCTL handle flag DuplicateOperation");
    }

    if (generatedRemoteAfterMemory)
    {
        if (requireKernelCorrelationSignals)
        {
            RecordResult(&results, ((state.ThreadFlagUnion & SLEEPWALKER_THREAD_FLAG_CORR_MEMORY) != 0),
                         "observed IOCTL thread flag CorrelatedMemory", "missing IOCTL thread flag CorrelatedMemory");
        }
        else
        {
            RecordSkip(
                &results,
                "IOCTL thread flag CorrelatedMemory check skipped (kernel correlation disabled by architecture)");
        }
    }

    if (generatedRemoteAfterThread)
    {
        if (requireKernelCorrelationSignals)
        {
            RecordResult(&results, ((state.ThreadFlagUnion & SLEEPWALKER_THREAD_FLAG_CORR_THREAD_CTX) != 0),
                         "observed IOCTL thread flag CorrelatedThreadContext",
                         "missing IOCTL thread flag CorrelatedThreadContext");
        }
        else
        {
            RecordSkip(&results, "IOCTL thread flag CorrelatedThreadContext check skipped (kernel correlation disabled "
                                 "by architecture)");
        }
    }

    if (generatedRemoteAfterDup)
    {
        if (requireKernelCorrelationSignals)
        {
            RecordResult(&results, ((state.ThreadFlagUnion & SLEEPWALKER_THREAD_FLAG_CORR_DUP_HANDLE) != 0),
                         "observed IOCTL thread flag CorrelatedDuplicateHandle",
                         "missing IOCTL thread flag CorrelatedDuplicateHandle");
        }
        else
        {
            RecordSkip(&results, "IOCTL thread flag CorrelatedDuplicateHandle check skipped (kernel correlation "
                                 "disabled by architecture)");
        }
    }

    if (expected.RequiredThreadFlags != 0)
    {
        RecordResult(&results, ((state.ThreadFlagUnion & SLEEPWALKER_THREAD_FLAG_CORRELATED_INTENT) != 0),
                     "observed IOCTL thread flag CorrelatedIntent", "missing IOCTL thread flag CorrelatedIntent");
    }
    else if (generatedRemoteAfterMemory || generatedRemoteAfterThread || generatedRemoteAfterDup)
    {
        RecordSkip(&results,
                   "IOCTL thread flag CorrelatedIntent check skipped (kernel correlation disabled by architecture)");
    }

    multiClientParallelOk = RunMultiClientParallelIoctlTest(selfPid, child.Pi.dwProcessId, &multiClientPolls);
    RecordResult(&results, multiClientParallelOk, "multi-client parallel IOCTL fanout verified",
                 "multi-client parallel IOCTL fanout failed");
    printf("[INFO] multi-client parallel polls=%lu clients=%u\n", multiClientPolls, SLEEPWALKER_MULTI_CLIENT_COUNT);

    if (etwStarted)
    {
        etwCoverageMet = WaitForEtwEventCoverage(&etw, 10000, requireApcTelemetry);
        RecordResult(&results, etwCoverageMet,
                     requireApcTelemetry ? "ETW received all core event families (including APC)"
                                         : "ETW received all core event families (APC optional)",
                     requireApcTelemetry ? "ETW missing one or more core event families (including APC)"
                                         : "ETW missing one or more core event families (APC optional)");

        RecordResult(&results, (InterlockedCompareExchange(&etw.HandleEvents, 0, 0) > 0),
                     "ETW HandleTelemetry observed", "ETW HandleTelemetry missing");
        RecordResult(&results, (InterlockedCompareExchange(&etw.ThreadEvents, 0, 0) > 0),
                     "ETW ThreadTelemetry observed", "ETW ThreadTelemetry missing");
        RecordResult(&results, (InterlockedCompareExchange(&etw.ProcessEvents, 0, 0) > 0),
                     "ETW ProcessTelemetry observed", "ETW ProcessTelemetry missing");
        RecordResult(&results, (InterlockedCompareExchange(&etw.ImageEvents, 0, 0) > 0), "ETW ImageTelemetry observed",
                     "ETW ImageTelemetry missing");
        RecordResult(&results, (InterlockedCompareExchange(&etw.RegistryEvents, 0, 0) > 0),
                     "ETW RegistryTelemetry observed", "ETW RegistryTelemetry missing");
        if (requireApcTelemetry)
        {
            RecordResult(&results, (InterlockedCompareExchange(&etw.ApcEvents, 0, 0) > 0), "ETW ApcTelemetry observed",
                         "ETW ApcTelemetry missing");
        }
        else if (InterlockedCompareExchange(&etw.ApcEvents, 0, 0) > 0)
        {
            RecordResult(&results, TRUE, "ETW ApcTelemetry observed", "ETW ApcTelemetry missing");
        }
        else
        {
            RecordSkip(&results, "ETW ApcTelemetry check skipped (APC optional in current run)");
        }
        RecordResult(&results, (InterlockedCompareExchange(&etw.DetectionEvents, 0, 0) > 0),
                     "ETW DetectionTelemetry observed", "ETW DetectionTelemetry missing");

        if (generatedVmApiCalls)
        {
            if (etw.TiProviderEnabled)
            {
                RecordResult(&results, (InterlockedCompareExchange(&etw.TiAllocVmEvents, 0, 0) > 0),
                             "ETW TI AllocVM API-call observed", "ETW TI AllocVM API-call missing");
                RecordResult(&results, (InterlockedCompareExchange(&etw.TiWriteVmEvents, 0, 0) > 0),
                             "ETW TI WriteVM API-call observed", "ETW TI WriteVM API-call missing");
                RecordResult(&results, (InterlockedCompareExchange(&etw.TiProtectVmEvents, 0, 0) > 0),
                             "ETW TI ProtectVM API-call observed", "ETW TI ProtectVM API-call missing");
            }
            else
            {
                RecordSkip(&results, "ETW TI AllocVM API-call check skipped (provider unavailable)");
                RecordSkip(&results, "ETW TI WriteVM API-call check skipped (provider unavailable)");
                RecordSkip(&results, "ETW TI ProtectVM API-call check skipped (provider unavailable)");
            }
        }

        if (generatedRegistry)
        {
            RecordResult(&results, (InterlockedCompareExchange(&etw.DetectRegistryHighValue, 0, 0) > 0),
                         "ETW detection HIGH_VALUE_REGISTRY_ACTIVITY observed",
                         "ETW detection HIGH_VALUE_REGISTRY_ACTIVITY missing");
        }

        if (generatedRemoteAfterMemory || generatedRemoteAfterThread || generatedRemoteAfterDup)
        {
            if (requireKernelCorrelationSignals)
            {
                RecordResult(&results, (InterlockedCompareExchange(&etw.DetectRemoteThreadWithIntent, 0, 0) > 0),
                             "ETW detection REMOTE_THREAD_WITH_RECENT_HANDLE_INTENT observed",
                             "ETW detection REMOTE_THREAD_WITH_RECENT_HANDLE_INTENT missing");
            }
            else
            {
                RecordSkip(&results, "ETW detection REMOTE_THREAD_WITH_RECENT_HANDLE_INTENT check skipped (kernel "
                                     "correlation disabled by architecture)");
            }
        }

        if (generatedMemoryIntent && generatedThreadIntent)
        {
            if (requireKernelCorrelationSignals)
            {
                RecordResult(&results, (InterlockedCompareExchange(&etw.DetectRemoteApcCreationSuspect, 0, 0) > 0),
                             "ETW detection REMOTE_APC_CREATION_SUSPECT observed",
                             "ETW detection REMOTE_APC_CREATION_SUSPECT missing");
            }
            else
            {
                RecordSkip(&results, "ETW detection REMOTE_APC_CREATION_SUSPECT check skipped (kernel correlation "
                                     "disabled by architecture)");
            }
        }

        if (generatedThreadIntent)
        {
            if (requireKernelCorrelationSignals)
            {
                RecordResult(&results, (InterlockedCompareExchange(&etw.DetectThreadHijackIntent, 0, 0) > 0),
                             "ETW detection THREAD_HIJACK_INTENT observed",
                             "ETW detection THREAD_HIJACK_INTENT missing");
            }
            else
            {
                RecordSkip(
                    &results,
                    "ETW detection THREAD_HIJACK_INTENT check skipped (kernel correlation disabled by architecture)");
            }
        }

        if (generatedRemoteAfterThread)
        {
            if (requireKernelCorrelationSignals)
            {
                LONG ctxIntent = InterlockedCompareExchange(&etw.DetectThreadContextIntent, 0, 0);
                LONG remoteIntent = InterlockedCompareExchange(&etw.DetectRemoteThreadWithIntent, 0, 0);
                LONG manualMapLike = InterlockedCompareExchange(&etw.DetectManualMapOrHollowingExec, 0, 0);

                if (ctxIntent > 0)
                {
                    RecordResult(&results, TRUE, "ETW detection THREAD_ACTIVITY_WITH_THREAD_CONTEXT_INTENT observed",
                                 "ETW detection THREAD_ACTIVITY_WITH_THREAD_CONTEXT_INTENT missing");
                }
                else if (remoteIntent > 0 || manualMapLike > 0)
                {
                    RecordSkip(&results, "ETW THREAD_ACTIVITY_WITH_THREAD_CONTEXT_INTENT check skipped "
                                         "(higher-priority thread detection emitted)");
                }
                else
                {
                    RecordResult(&results, FALSE, "ETW detection THREAD_ACTIVITY_WITH_THREAD_CONTEXT_INTENT observed",
                                 "ETW detection THREAD_ACTIVITY_WITH_THREAD_CONTEXT_INTENT missing");
                }
            }
            else
            {
                RecordSkip(&results, "ETW detection THREAD_ACTIVITY_WITH_THREAD_CONTEXT_INTENT check skipped (kernel "
                                     "correlation disabled by architecture)");
            }
        }

        if (generatedMemoryIntent && generatedThreadIntent)
        {
            if (requireKernelCorrelationSignals)
            {
                RecordResult(&results, (InterlockedCompareExchange(&etw.DetectIntentChain, 0, 0) > 0),
                             "ETW detection POSSIBLE_PROCESS_HOLLOWING_OR_INJECTION_INTENT_CHAIN observed",
                             "ETW detection POSSIBLE_PROCESS_HOLLOWING_OR_INJECTION_INTENT_CHAIN missing");
            }
            else
            {
                RecordSkip(&results, "ETW detection POSSIBLE_PROCESS_HOLLOWING_OR_INJECTION_INTENT_CHAIN check skipped "
                                     "(kernel correlation disabled by architecture)");
            }
        }

        RecordResult(&results, (InterlockedCompareExchange(&etw.DetectTamper, 0, 0) == 0),
                     "no anti-tamper dispatch/object drift observed during baseline run",
                     "unexpected anti-tamper dispatch/object drift detected during baseline run");

        printf("[INFO] ETW counts handle=%ld thread=%ld process=%ld image=%ld registry=%ld apc=%ld detection=%ld "
               "ti=%ld unknown=%ld det{remoteIntent=%ld remoteApc=%ld hijack=%ld threadCtx=%ld regHigh=%ld chain=%ld "
               "directSys=%ld manualMap=%ld ntdllPath=%ld ntdllMulti=%ld tamper=%ld tamperClear=%ld} tiTask{alloc=%ld "
               "protect=%ld write=%ld syscallUsage=%ld tiUnknown=%ld}\n",
               InterlockedCompareExchange(&etw.HandleEvents, 0, 0), InterlockedCompareExchange(&etw.ThreadEvents, 0, 0),
               InterlockedCompareExchange(&etw.ProcessEvents, 0, 0), InterlockedCompareExchange(&etw.ImageEvents, 0, 0),
               InterlockedCompareExchange(&etw.RegistryEvents, 0, 0), InterlockedCompareExchange(&etw.ApcEvents, 0, 0),
               InterlockedCompareExchange(&etw.DetectionEvents, 0, 0), InterlockedCompareExchange(&etw.TiEvents, 0, 0),
               InterlockedCompareExchange(&etw.UnknownEvents, 0, 0),
               InterlockedCompareExchange(&etw.DetectRemoteThreadWithIntent, 0, 0),
               InterlockedCompareExchange(&etw.DetectRemoteApcCreationSuspect, 0, 0),
               InterlockedCompareExchange(&etw.DetectThreadHijackIntent, 0, 0),
               InterlockedCompareExchange(&etw.DetectThreadContextIntent, 0, 0),
               InterlockedCompareExchange(&etw.DetectRegistryHighValue, 0, 0),
               InterlockedCompareExchange(&etw.DetectIntentChain, 0, 0),
               InterlockedCompareExchange(&etw.DetectDirectSyscallSuspect, 0, 0),
               InterlockedCompareExchange(&etw.DetectManualMapOrHollowingExec, 0, 0),
               InterlockedCompareExchange(&etw.DetectSuspiciousNtdllPath, 0, 0),
               InterlockedCompareExchange(&etw.DetectMultipleNtdllMappings, 0, 0),
               InterlockedCompareExchange(&etw.DetectTamper, 0, 0),
               InterlockedCompareExchange(&etw.DetectTamperCleared, 0, 0),
               InterlockedCompareExchange(&etw.TiAllocVmEvents, 0, 0),
               InterlockedCompareExchange(&etw.TiProtectVmEvents, 0, 0),
               InterlockedCompareExchange(&etw.TiWriteVmEvents, 0, 0),
               InterlockedCompareExchange(&etw.TiSyscallUsageEvents, 0, 0),
               InterlockedCompareExchange(&etw.TiUnknownTaskEvents, 0, 0));
    }

    if (brokerEtwStarted)
    {
        brokerEtwCoverageMet = WaitForBrokerEtwEventCoverage(&brokerEtw, 10000, requireApcTelemetry);
        RecordResult(&results, brokerEtwCoverageMet,
                     requireApcTelemetry ? "broker ETW uplink received all core event families (including APC)"
                                         : "broker ETW uplink received all core event families (APC optional)",
                     requireApcTelemetry ? "broker ETW uplink missing one or more core event families (including APC)"
                                         : "broker ETW uplink missing one or more core event families (APC optional)");

        RecordResult(&results, (InterlockedCompareExchange(&brokerEtw.DetectionEvents, 0, 0) > 0),
                     "broker ETW uplink DetectionTelemetry observed",
                     "broker ETW uplink DetectionTelemetry missing");

        if (generatedVmApiCalls)
        {
            if (brokerEtw.TiProviderEnabled)
            {
                RecordResult(&results, (InterlockedCompareExchange(&brokerEtw.TiAllocVmEvents, 0, 0) > 0),
                             "broker TI AllocVM API-call observed", "broker TI AllocVM API-call missing");
                RecordResult(&results, (InterlockedCompareExchange(&brokerEtw.TiWriteVmEvents, 0, 0) > 0),
                             "broker TI WriteVM API-call observed", "broker TI WriteVM API-call missing");
                RecordResult(&results, (InterlockedCompareExchange(&brokerEtw.TiProtectVmEvents, 0, 0) > 0),
                             "broker TI ProtectVM API-call observed", "broker TI ProtectVM API-call missing");
            }
            else
            {
                RecordSkip(&results, "broker TI AllocVM API-call check skipped (provider unavailable)");
                RecordSkip(&results, "broker TI WriteVM API-call check skipped (provider unavailable)");
                RecordSkip(&results, "broker TI ProtectVM API-call check skipped (provider unavailable)");
            }
        }

        printf("[INFO] broker ETW counts handle=%ld thread=%ld process=%ld image=%ld registry=%ld apc=%ld detection=%ld "
               "ti=%ld unknown=%ld tiTask{alloc=%ld protect=%ld write=%ld syscallUsage=%ld tiUnknown=%ld}\n",
               InterlockedCompareExchange(&brokerEtw.HandleEvents, 0, 0),
               InterlockedCompareExchange(&brokerEtw.ThreadEvents, 0, 0),
               InterlockedCompareExchange(&brokerEtw.ProcessEvents, 0, 0),
               InterlockedCompareExchange(&brokerEtw.ImageEvents, 0, 0),
               InterlockedCompareExchange(&brokerEtw.RegistryEvents, 0, 0),
               InterlockedCompareExchange(&brokerEtw.ApcEvents, 0, 0),
               InterlockedCompareExchange(&brokerEtw.DetectionEvents, 0, 0),
               InterlockedCompareExchange(&brokerEtw.TiEvents, 0, 0),
               InterlockedCompareExchange(&brokerEtw.UnknownEvents, 0, 0),
               InterlockedCompareExchange(&brokerEtw.TiAllocVmEvents, 0, 0),
               InterlockedCompareExchange(&brokerEtw.TiProtectVmEvents, 0, 0),
               InterlockedCompareExchange(&brokerEtw.TiWriteVmEvents, 0, 0),
               InterlockedCompareExchange(&brokerEtw.TiSyscallUsageEvents, 0, 0),
               InterlockedCompareExchange(&brokerEtw.TiUnknownTaskEvents, 0, 0));
    }

Cleanup:
    if (subscribedChild)
    {
        ok = Unsubscribe(h, child.Pi.dwProcessId);
        RecordResult(&results, ok, "unsubscribed child", "unsubscribe child failed");
    }

    if (subscribedSelf)
    {
        ok = Unsubscribe(h, selfPid);
        RecordResult(&results, ok, "unsubscribed self", "unsubscribe self failed");
    }

    StopIdleChild(&child);

    if (etwStarted)
    {
        StopEtwCapture(&etw);
    }
    if (brokerEtwStarted)
    {
        StopBrokerEtwCapture(&brokerEtw);
    }

    if (h != INVALID_HANDLE_VALUE)
    {
        CloseHandle(h);
    }

    SLEEPWALKERSymbolResolverCleanup();
    if (results.Passed == results.Total)
    {
        SuiteCloseReport(&results, state.Polls);
        return 0;
    }

    SuiteCloseReport(&results, state.Polls);
    return 1;
}
