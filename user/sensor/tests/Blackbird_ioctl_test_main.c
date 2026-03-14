#include "blackbird_ioctl_test_internal.h"

int __cdecl main(int argc, char **argv)
{
    HANDLE h = INVALID_HANDLE_VALUE;
    BLACKBIRD_STATS_RESPONSE stats;
    DWORD bytes = 0;
    BOOL ok;
    DWORD selfPid = GetCurrentProcessId();
    TEST_STATE state;
    TEST_EXPECTED expected;
    BLACKBIRD_SUBSCRIBE_REQUEST badReq;
    BOOL subscribedSelf = FALSE;
    CHILD_CTX child;
    BOOL generatedMemoryIntent = FALSE;
    BOOL generatedThreadIntent = FALSE;
    BOOL generatedDuplicateIntent = FALSE;
    BOOL generatedRemoteAfterMemory = FALSE;
    BOOL generatedRemoteAfterThread = FALSE;
    BOOL generatedRemoteAfterDup = FALSE;
    BOOL generatedRegistry = FALSE;
    BOOL generatedVmApiCalls = FALSE;
    BOOL generatedSuspendedChain = FALSE;
    BOOL multiClientParallelOk = FALSE;
    BOOL setPidsApplied = FALSE;
    BOOL brokerDynamicGraphExpanded = FALSE;
    BOOL brokerDynamicDepth2Expanded = FALSE;
    BOOL brokerDynamicCleanupWorked = FALSE;
    DWORD multiClientPolls = 0;
    BROKER_ETW_CAPTURE brokerEtw;
    BOOL brokerMode = FALSE;
    BOOL brokerEtwStarted = FALSE;
    BOOL brokerEtwCoverageMet = FALSE;
    BOOL requireKernelCorrelationSignals = FALSE;
    BOOL requireApcTelemetry = FALSE;
    CHILD_CTX graphActor;
    SUITE_RESULTS results;
    BOOL reportReady;

    if (argc > 1 && strcmp(argv[1], BLACKBIRD_CHILD_ARG) == 0)
    {
        Sleep(15000);
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], BLACKBIRD_CHILD_SPAWN_AND_TOUCH_ARG) == 0)
    {
        CHILD_CTX nested;
        BOOL started = StartIdleChild(&nested);
        if (started)
        {
            ULONGLONG start = GetTickCount64();
            while ((GetTickCount64() - start) < 2500ull)
            {
                (void) GenerateMemoryHandleIntent(nested.Pi.dwProcessId);
                Sleep(40);
            }
            StopIdleChild(&nested);
            return 0;
        }

        return 1;
    }

    BLACKBIRDSymbolResolverInitialize();
    ZeroMemory(&state, sizeof(state));
    ZeroMemory(&expected, sizeof(expected));
    ZeroMemory(&child, sizeof(child));
    ZeroMemory(&graphActor, sizeof(graphActor));
    ZeroMemory(&brokerEtw, sizeof(brokerEtw));
    ZeroMemory(&results, sizeof(results));
    reportReady = SuiteInitReport(&results);
    if (!reportReady)
    {
        printf("reportStatus=unavailable\n");
    }
    requireKernelCorrelationSignals = EnvFlagEnabled("BLACKBIRD_TEST_REQUIRE_KERNEL_CORRELATION", FALSE);
    requireApcTelemetry = EnvFlagEnabled("BLACKBIRD_TEST_REQUIRE_APC", FALSE);
    printf("[INFO] suite knobs requireKernelCorrelation=%u requireApcTelemetry=%u\n",
           requireKernelCorrelationSignals ? 1u : 0u,
           requireApcTelemetry ? 1u : 0u);
    LogEnvironmentBaseline(&results);

    h = OpenControlDeviceHandle();
    RecordResult(&results,
                 (h != INVALID_HANDLE_VALUE),
                 "opened control device",
                 "failed to open broker or direct control transport");
    if (h == INVALID_HANDLE_VALUE)
    {
        DWORD openErr = GetLastError();
        printf("[INFO] control open failed err=%lu (broker IPC to BlackbirdController is required)\n", openErr);
        goto Cleanup;
    }
    brokerMode = (BLACKBIRDSCGetProtocolMode() == BLACKBIRDSC_PROTOCOL_CLIENT);
    printf("[INFO] transport mode=%s\n", brokerMode ? "service-broker" : "direct");
    RecordResult(&results, brokerMode, "transport mode is service-broker", "transport mode is not service-broker");
    if (!brokerMode)
    {
        goto Cleanup;
    }

    if (brokerMode)
    {
        DWORD brokerSeedPid = selfPid;
        brokerEtwStarted =
                StartBrokerEtwCapture(&brokerEtw,
                                      &brokerSeedPid,
                                      1,
                                      BLACKBIRD_STREAM_HANDLE | BLACKBIRD_STREAM_MEMORY | BLACKBIRD_STREAM_THREAD);
        RecordResult(&results,
                     brokerEtwStarted,
                     "started broker ETW/TI uplink capture",
                     "failed to start broker ETW/TI uplink capture");
        if (brokerEtwStarted && !brokerEtw.TiProviderEnabled)
        {
            printf("[INFO] broker ETW started without TI provider (tiEnableErr=%lu)\n", brokerEtw.TiEnableError);
        }
    }

    ZeroMemory(&badReq, sizeof(badReq));
    badReq.ProcessId = selfPid;
    badReq.StreamMask = 0;
    ok = BLACKBIRDSCSubscribe(h, badReq.ProcessId, badReq.StreamMask);
    RecordResult(&results,
                 (!ok && GetLastError() == ERROR_INVALID_PARAMETER),
                 "invalid subscribe stream mask rejected",
                 "invalid subscribe stream mask was not rejected");

    ok = Subscribe(h, selfPid, BLACKBIRD_STREAM_HANDLE | BLACKBIRD_STREAM_MEMORY | BLACKBIRD_STREAM_THREAD);
    subscribedSelf = ok;
    RecordResult(&results, ok, "subscribed self", "subscribe self failed");
    if (!ok)
    {
        goto Cleanup;
    }
    printf("[INFO] subscribed self pid=%lu\n", selfPid);

    ZeroMemory(&stats, sizeof(stats));
    ok = BLACKBIRDSCGetStats(h, &stats, &bytes);
    RecordResult(&results, ok, "queried IOCTL stats", "get stats failed");
    if (ok)
    {
        printf("[INFO] stats subscriptionCount=%u queueDepth=%u dropped=%u\n",
               stats.SubscriptionCount,
               stats.QueueDepth,
               stats.DroppedEvents);
        RecordResult(&results,
                     (bytes == sizeof(stats)),
                     "GET_STATS returned expected byte count",
                     "GET_STATS returned unexpected byte count");
    }

    ok = StartIdleChild(&child);
    RecordResult(&results, ok, "launched child process", "failed to launch child process");
    if (!ok)
    {
        goto Cleanup;
    }
    printf("[INFO] child pid=%lu tid=%lu\n", child.Pi.dwProcessId, child.Pi.dwThreadId);

    {
        DWORD pidList[1];
        DWORD pidCount = 1u;
        pidList[0] = selfPid;

        setPidsApplied = SetPids(
                h, pidList, pidCount, BLACKBIRD_STREAM_HANDLE | BLACKBIRD_STREAM_MEMORY | BLACKBIRD_STREAM_THREAD);
        RecordResult(&results,
                     setPidsApplied,
                     "applied PID list subscription via IOCTL_BLACKBIRD_SET_PIDS",
                     "failed to apply PID list subscription via IOCTL_BLACKBIRD_SET_PIDS");
        if (setPidsApplied)
        {
            ZeroMemory(&stats, sizeof(stats));
            ok = BLACKBIRDSCGetStats(h, &stats, &bytes);
            RecordResult(&results,
                         (ok && stats.SubscriptionCount == pidCount),
                         "SET_PIDS applied expected subscription cardinality",
                         "SET_PIDS did not apply expected subscription cardinality");
        }
    }

    GenerateLocalThreadEvent();

    generatedMemoryIntent = GenerateMemoryHandleIntent(child.Pi.dwProcessId);
    RecordResult(&results,
                 generatedMemoryIntent,
                 "generated memory-handle intent",
                 "failed to generate memory-handle intent");

    generatedThreadIntent = GenerateThreadContextHandleIntent(child.Pi.dwThreadId);
    RecordResult(&results,
                 generatedThreadIntent,
                 "generated thread-context-handle intent",
                 "failed to generate thread-context-handle intent");

    generatedDuplicateIntent = GenerateDuplicateHandleIntent(child.Pi.dwProcessId);
    RecordResult(&results,
                 generatedDuplicateIntent,
                 "generated duplicate-handle intent",
                 "failed to generate duplicate-handle intent");

    if (generatedMemoryIntent)
    {
        generatedRemoteAfterMemory = GenerateRemoteThreadLoadLibraryIntent(child.Pi.dwProcessId);
        RecordResult(&results,
                     generatedRemoteAfterMemory,
                     "generated remote thread after memory intent",
                     "failed to generate remote thread after memory intent");
    }

    if (generatedThreadIntent)
    {
        generatedRemoteAfterThread = GenerateRemoteThreadLoadLibraryIntent(child.Pi.dwProcessId);
        RecordResult(&results,
                     generatedRemoteAfterThread,
                     "generated remote thread after thread-context intent",
                     "failed to generate remote thread after thread-context intent");
    }

    if (generatedDuplicateIntent)
    {
        generatedRemoteAfterDup = GenerateRemoteThreadLoadLibraryIntent(child.Pi.dwProcessId);
        RecordResult(&results,
                     generatedRemoteAfterDup,
                     "generated remote thread after duplicate intent",
                     "failed to generate remote thread after duplicate intent");
    }

    generatedRegistry = GenerateRegistryHighValueActivity();
    RecordResult(&results,
                 generatedRegistry,
                 "generated high-value registry activity",
                 "failed to generate high-value registry activity");

    generatedVmApiCalls = GenerateVmApiCallSurface(child.Pi.dwProcessId);
    RecordResult(&results,
                 generatedVmApiCalls,
                 "generated VM API-call surface (alloc/write/protect)",
                 "failed to generate VM API-call surface (alloc/write/protect)");

    generatedSuspendedChain = GenerateSuspendedHollowingLikeChain();
    RecordResult(&results,
                 generatedSuspendedChain,
                 "generated suspended hollowing-like chain",
                 "failed to generate suspended hollowing-like chain");

    if (brokerMode)
    {
        ULONGLONG startTick = GetTickCount64();
        while ((GetTickCount64() - startTick) < 4000ull)
        {
            ZeroMemory(&stats, sizeof(stats));
            if (BLACKBIRDSCGetStats(h, &stats, &bytes) && stats.SubscriptionCount >= 2)
            {
                brokerDynamicGraphExpanded = TRUE;
                break;
            }
            Sleep(60);
        }

        RecordResult(&results,
                     brokerDynamicGraphExpanded,
                     "broker dynamic PID expansion observed from self seed to related child",
                     "broker dynamic PID expansion not observed from self seed to related child");

        if (StartSpawnAndTouchChild(&graphActor))
        {
            startTick = GetTickCount64();
            while ((GetTickCount64() - startTick) < 5000ull)
            {
                ZeroMemory(&stats, sizeof(stats));
                if (BLACKBIRDSCGetStats(h, &stats, &bytes) && stats.SubscriptionCount >= 4)
                {
                    brokerDynamicDepth2Expanded = TRUE;
                    break;
                }
                Sleep(60);
            }
            StopIdleChild(&graphActor);
            RecordResult(&results,
                         brokerDynamicDepth2Expanded,
                         "broker dynamic PID expansion reached second hop (child -> spawned child)",
                         "broker dynamic PID expansion did not reach second hop (child -> spawned child)");
        }
        else
        {
            RecordResult(&results,
                         FALSE,
                         "started broker graph actor child for second-hop test",
                         "failed to start broker graph actor child for second-hop test");
        }

        ok = Unsubscribe(h, selfPid);
        RecordResult(&results,
                     ok,
                     "broker unsubscribe root PID for dynamic cleanup",
                     "broker unsubscribe root PID for dynamic cleanup failed");
        if (ok)
        {
            subscribedSelf = FALSE;
            startTick = GetTickCount64();
            while ((GetTickCount64() - startTick) < 3000ull)
            {
                ZeroMemory(&stats, sizeof(stats));
                if (BLACKBIRDSCGetStats(h, &stats, &bytes) && stats.SubscriptionCount == 0)
                {
                    brokerDynamicCleanupWorked = TRUE;
                    break;
                }
                Sleep(60);
            }
        }
        RecordResult(&results,
                     brokerDynamicCleanupWorked,
                     "broker dynamic descendant cleanup observed after root unsubscribe",
                     "broker dynamic descendant cleanup missing after root unsubscribe");

        if (!subscribedSelf)
        {
            ok = Subscribe(h, selfPid, BLACKBIRD_STREAM_HANDLE | BLACKBIRD_STREAM_MEMORY | BLACKBIRD_STREAM_THREAD);
            subscribedSelf = ok;
            RecordResult(&results,
                         ok,
                         "broker re-subscribed self after dynamic cleanup test",
                         "broker failed to re-subscribe self after dynamic cleanup test");
        }
    }
    else
    {
        RecordResult(&results,
                     FALSE,
                     "broker dynamic PID expansion observed from self seed to related child",
                     "broker mode expected but not active");
    }

    expected.RequireThreadEvent = TRUE;
    expected.RequireHandleEvent = generatedMemoryIntent || generatedThreadIntent || generatedDuplicateIntent;
    if (generatedMemoryIntent)
    {
        expected.RequiredHandleFlags |= BLACKBIRD_HANDLE_FLAG_MEMORY_RELATED;
    }
    if (generatedThreadIntent)
    {
        expected.RequiredHandleFlags |= BLACKBIRD_HANDLE_FLAG_THREAD_OBJECT;
    }
    if (generatedDuplicateIntent)
    {
        expected.RequiredHandleFlags |= BLACKBIRD_HANDLE_FLAG_DUPLICATE_OPERATION;
    }
    if (requireKernelCorrelationSignals && generatedRemoteAfterMemory)
    {
        expected.RequiredThreadFlags |= BLACKBIRD_THREAD_FLAG_CORRELATED_INTENT | BLACKBIRD_THREAD_FLAG_CORR_MEMORY;
    }
    if (requireKernelCorrelationSignals && generatedRemoteAfterThread)
    {
        expected.RequiredThreadFlags |= BLACKBIRD_THREAD_FLAG_CORRELATED_INTENT | BLACKBIRD_THREAD_FLAG_CORR_THREAD_CTX;
    }
    if (requireKernelCorrelationSignals && generatedRemoteAfterDup)
    {
        expected.RequiredThreadFlags |= BLACKBIRD_THREAD_FLAG_CORRELATED_INTENT | BLACKBIRD_THREAD_FLAG_CORR_DUP_HANDLE;
    }

    PumpIoctlEvents(h, &state, &expected, 14000);

    RecordResult(
            &results, state.SawThread, "received thread telemetry via IOCTL", "missing thread telemetry via IOCTL");

    if (expected.RequireHandleEvent)
    {
        RecordResult(
                &results, state.SawHandle, "received handle telemetry via IOCTL", "missing handle telemetry via IOCTL");
    }

    if (generatedMemoryIntent)
    {
        RecordResult(&results,
                     ((state.HandleFlagUnion & BLACKBIRD_HANDLE_FLAG_MEMORY_RELATED) != 0),
                     "observed IOCTL handle flag MemoryRelated",
                     "missing IOCTL handle flag MemoryRelated");
    }

    if (generatedThreadIntent)
    {
        RecordResult(&results,
                     ((state.HandleFlagUnion & BLACKBIRD_HANDLE_FLAG_THREAD_OBJECT) != 0),
                     "observed IOCTL handle flag ThreadObject",
                     "missing IOCTL handle flag ThreadObject");
    }

    if (generatedDuplicateIntent)
    {
        RecordResult(&results,
                     ((state.HandleFlagUnion & BLACKBIRD_HANDLE_FLAG_DUPLICATE_OPERATION) != 0),
                     "observed IOCTL handle flag DuplicateOperation",
                     "missing IOCTL handle flag DuplicateOperation");
    }

    if (generatedRemoteAfterMemory)
    {
        if (requireKernelCorrelationSignals)
        {
            RecordResult(&results,
                         ((state.ThreadFlagUnion & BLACKBIRD_THREAD_FLAG_CORR_MEMORY) != 0),
                         "observed IOCTL thread flag CorrelatedMemory",
                         "missing IOCTL thread flag CorrelatedMemory");
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
            RecordResult(&results,
                         ((state.ThreadFlagUnion & BLACKBIRD_THREAD_FLAG_CORR_THREAD_CTX) != 0),
                         "observed IOCTL thread flag CorrelatedThreadContext",
                         "missing IOCTL thread flag CorrelatedThreadContext");
        }
        else
        {
            RecordSkip(&results,
                       "IOCTL thread flag CorrelatedThreadContext check skipped (kernel correlation disabled "
                       "by architecture)");
        }
    }

    if (generatedRemoteAfterDup)
    {
        if (requireKernelCorrelationSignals)
        {
            RecordResult(&results,
                         ((state.ThreadFlagUnion & BLACKBIRD_THREAD_FLAG_CORR_DUP_HANDLE) != 0),
                         "observed IOCTL thread flag CorrelatedDuplicateHandle",
                         "missing IOCTL thread flag CorrelatedDuplicateHandle");
        }
        else
        {
            RecordSkip(&results,
                       "IOCTL thread flag CorrelatedDuplicateHandle check skipped (kernel correlation "
                       "disabled by architecture)");
        }
    }

    if (expected.RequiredThreadFlags != 0)
    {
        RecordResult(&results,
                     ((state.ThreadFlagUnion & BLACKBIRD_THREAD_FLAG_CORRELATED_INTENT) != 0),
                     "observed IOCTL thread flag CorrelatedIntent",
                     "missing IOCTL thread flag CorrelatedIntent");
    }
    else if (generatedRemoteAfterMemory || generatedRemoteAfterThread || generatedRemoteAfterDup)
    {
        RecordSkip(&results,
                   "IOCTL thread flag CorrelatedIntent check skipped (kernel correlation disabled by architecture)");
    }

    multiClientParallelOk = RunMultiClientParallelIoctlTest(selfPid, child.Pi.dwProcessId, &multiClientPolls);
    RecordResult(&results,
                 multiClientParallelOk,
                 "multi-client parallel IOCTL fanout verified",
                 "multi-client parallel IOCTL fanout failed");
    printf("[INFO] multi-client parallel polls=%lu clients=%u\n", multiClientPolls, BLACKBIRD_MULTI_CLIENT_COUNT);

    if (brokerEtwStarted)
    {
        brokerEtwCoverageMet = WaitForBrokerEtwEventCoverage(&brokerEtw, 10000, requireApcTelemetry);
        RecordResult(&results,
                     brokerEtwCoverageMet,
                     requireApcTelemetry ? "broker ETW uplink received all core event families (including APC)"
                                         : "broker ETW uplink received all core event families (APC optional)",
                     requireApcTelemetry ? "broker ETW uplink missing one or more core event families (including APC)"
                                         : "broker ETW uplink missing one or more core event families (APC optional)");

        RecordResult(&results,
                     (InterlockedCompareExchange(&brokerEtw.DetectionEvents, 0, 0) > 0),
                     "broker ETW uplink DetectionTelemetry observed",
                     "broker ETW uplink DetectionTelemetry missing");

        if (generatedVmApiCalls)
        {
            if (brokerEtw.TiProviderEnabled)
            {
                RecordResult(&results,
                             (InterlockedCompareExchange(&brokerEtw.TiAllocVmEvents, 0, 0) > 0),
                             "broker TI AllocVM API-call observed",
                             "broker TI AllocVM API-call missing");
                RecordResult(&results,
                             (InterlockedCompareExchange(&brokerEtw.TiWriteVmEvents, 0, 0) > 0),
                             "broker TI WriteVM API-call observed",
                             "broker TI WriteVM API-call missing");
                RecordResult(&results,
                             (InterlockedCompareExchange(&brokerEtw.TiProtectVmEvents, 0, 0) > 0),
                             "broker TI ProtectVM API-call observed",
                             "broker TI ProtectVM API-call missing");
            }
            else
            {
                RecordSkip(&results, "broker TI AllocVM API-call check skipped (provider unavailable)");
                RecordSkip(&results, "broker TI WriteVM API-call check skipped (provider unavailable)");
                RecordSkip(&results, "broker TI ProtectVM API-call check skipped (provider unavailable)");
            }
        }

        if (generatedSuspendedChain)
        {
            if (brokerEtw.TiProviderEnabled)
            {
                LONG hollowMedium = InterlockedCompareExchange(&brokerEtw.DetectHollowingMarkMedium, 0, 0);
                LONG hollowStrong = InterlockedCompareExchange(&brokerEtw.DetectHollowingMarkStrong, 0, 0);
                RecordResult(&results,
                             (hollowMedium > 0 || hollowStrong > 0),
                             "broker detection PROCESS_HOLLOWING_MARK_CHAIN_(MEDIUM|STRONG) observed",
                             "broker detection PROCESS_HOLLOWING_MARK_CHAIN_(MEDIUM|STRONG) missing");
            }
            else
            {
                RecordSkip(&results, "broker hollowing mark-chain detection check skipped (TI provider unavailable)");
            }
        }

        printf("[INFO] broker ETW counts handle=%ld thread=%ld process=%ld image=%ld registry=%ld apc=%ld "
               "detection=%ld "
               "ti=%ld unknown=%ld det{hollowMedium=%ld hollowStrong=%ld hollowTxf=%ld} tiTask{alloc=%ld protect=%ld "
               "write=%ld "
               "syscallUsage=%ld tiUnknown=%ld}\n",
               InterlockedCompareExchange(&brokerEtw.HandleEvents, 0, 0),
               InterlockedCompareExchange(&brokerEtw.ThreadEvents, 0, 0),
               InterlockedCompareExchange(&brokerEtw.ProcessEvents, 0, 0),
               InterlockedCompareExchange(&brokerEtw.ImageEvents, 0, 0),
               InterlockedCompareExchange(&brokerEtw.RegistryEvents, 0, 0),
               InterlockedCompareExchange(&brokerEtw.ApcEvents, 0, 0),
               InterlockedCompareExchange(&brokerEtw.DetectionEvents, 0, 0),
               InterlockedCompareExchange(&brokerEtw.TiEvents, 0, 0),
               InterlockedCompareExchange(&brokerEtw.UnknownEvents, 0, 0),
               InterlockedCompareExchange(&brokerEtw.DetectHollowingMarkMedium, 0, 0),
               InterlockedCompareExchange(&brokerEtw.DetectHollowingMarkStrong, 0, 0),
               InterlockedCompareExchange(&brokerEtw.DetectHollowingTxfChain, 0, 0),
               InterlockedCompareExchange(&brokerEtw.TiAllocVmEvents, 0, 0),
               InterlockedCompareExchange(&brokerEtw.TiProtectVmEvents, 0, 0),
               InterlockedCompareExchange(&brokerEtw.TiWriteVmEvents, 0, 0),
               InterlockedCompareExchange(&brokerEtw.TiSyscallUsageEvents, 0, 0),
               InterlockedCompareExchange(&brokerEtw.TiUnknownTaskEvents, 0, 0));
    }

Cleanup:
    if (subscribedSelf)
    {
        ok = Unsubscribe(h, selfPid);
        RecordResult(&results, ok, "unsubscribed self", "unsubscribe self failed");
    }

    StopIdleChild(&child);

    if (brokerEtwStarted)
    {
        StopBrokerEtwCapture(&brokerEtw);
    }

    if (h != INVALID_HANDLE_VALUE)
    {
        (void) BLACKBIRDSCCloseControlDevice(h);
    }

    BLACKBIRDSymbolResolverCleanup();
    if (results.Passed == results.Total)
    {
        SuiteCloseReport(&results, state.Polls);
        return 0;
    }

    SuiteCloseReport(&results, state.Polls);
    return 1;
}
