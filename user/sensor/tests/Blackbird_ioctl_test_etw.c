#include "blackbird_ioctl_test_internal.h"

static VOID WINAPI BlackbirdEtwRecordCallback(_In_ PEVENT_RECORD Record, _In_opt_z_ PCWSTR EventName,
                                                _In_opt_ PVOID Context)
{
    ETW_CAPTURE *cap = (ETW_CAPTURE *)Context;
    CHAR detectionName[128];

    if (cap == NULL || Record == NULL)
    {
        return;
    }

    if (IsEqualGUID(&Record->EventHeader.ProviderId, &BLACKBIRDSC_PROVIDER_GUID_TI))
    {
        USHORT task = Record->EventHeader.EventDescriptor.Task;

        InterlockedIncrement(&cap->TiEvents);
        switch (task)
        {
        case 1:
            InterlockedIncrement(&cap->TiAllocVmEvents);
            break;
        case 2:
            InterlockedIncrement(&cap->TiProtectVmEvents);
            break;
        case 7:
            InterlockedIncrement(&cap->TiWriteVmEvents);
            break;
        case 13:
            InterlockedIncrement(&cap->TiSyscallUsageEvents);
            break;
        default:
            InterlockedIncrement(&cap->TiUnknownTaskEvents);
            break;
        }
        return;
    }

    if (!IsEqualGUID(&Record->EventHeader.ProviderId, &BLACKBIRDSC_PROVIDER_GUID_BLACKBIRD) || EventName == NULL ||
        EventName[0] == L'\0')
    {
        InterlockedIncrement(&cap->UnknownEvents);
        return;
    }

    if (wcscmp(EventName, L"HandleTelemetry") == 0)
    {
        InterlockedIncrement(&cap->HandleEvents);
    }
    else if (wcscmp(EventName, L"ThreadTelemetry") == 0)
    {
        InterlockedIncrement(&cap->ThreadEvents);
    }
    else if (wcscmp(EventName, L"ProcessTelemetry") == 0)
    {
        InterlockedIncrement(&cap->ProcessEvents);
    }
    else if (wcscmp(EventName, L"ImageTelemetry") == 0)
    {
        InterlockedIncrement(&cap->ImageEvents);
    }
    else if (wcscmp(EventName, L"RegistryTelemetry") == 0)
    {
        InterlockedIncrement(&cap->RegistryEvents);
    }
    else if (wcscmp(EventName, L"ApcTelemetry") == 0)
    {
        InterlockedIncrement(&cap->ApcEvents);
    }
    else if (wcscmp(EventName, L"DetectionTelemetry") == 0)
    {
        InterlockedIncrement(&cap->DetectionEvents);
        detectionName[0] = '\0';
        if (GetEtwAnsiProperty(Record, L"detectionName", detectionName, RTL_NUMBER_OF(detectionName)))
        {
            if (strcmp(detectionName, "REMOTE_THREAD_WITH_RECENT_HANDLE_INTENT") == 0)
            {
                InterlockedIncrement(&cap->DetectRemoteThreadWithIntent);
            }
            else if (strcmp(detectionName, "HIGH_VALUE_REGISTRY_ACTIVITY") == 0)
            {
                InterlockedIncrement(&cap->DetectRegistryHighValue);
            }
            else if (strcmp(detectionName, "POSSIBLE_PROCESS_HOLLOWING_OR_INJECTION_INTENT_CHAIN") == 0)
            {
                InterlockedIncrement(&cap->DetectIntentChain);
            }
            else if (strcmp(detectionName, "DIRECT_SYSCALL_SUSPECT_HANDLE_OPERATION") == 0)
            {
                InterlockedIncrement(&cap->DetectDirectSyscallSuspect);
            }
            else if (strcmp(detectionName, "POSSIBLE_MANUAL_MAP_OR_HOLLOWING_EXECUTION") == 0 ||
                     strcmp(detectionName, "REMOTE_THREAD_START_IN_NON_IMAGE_EXECUTABLE_REGION") == 0)
            {
                InterlockedIncrement(&cap->DetectManualMapOrHollowingExec);
            }
            else if (strcmp(detectionName, "KERNEL_PROCESS_HOLLOWING_MARK_CHAIN_MEDIUM") == 0)
            {
                InterlockedIncrement(&cap->DetectKernelHollowingMarkMedium);
            }
            else if (strcmp(detectionName, "KERNEL_PROCESS_HOLLOWING_MARK_CHAIN_STRONG") == 0)
            {
                InterlockedIncrement(&cap->DetectKernelHollowingMarkStrong);
            }
            else if (strcmp(detectionName, "SUSPICIOUS_NTDLL_IMAGE_PATH") == 0)
            {
                InterlockedIncrement(&cap->DetectSuspiciousNtdllPath);
            }
            else if (strcmp(detectionName, "MULTIPLE_NTDLL_IMAGE_MAPPINGS") == 0)
            {
                InterlockedIncrement(&cap->DetectMultipleNtdllMappings);
            }
            else if (strcmp(detectionName, "REMOTE_APC_CREATION_SUSPECT") == 0)
            {
                InterlockedIncrement(&cap->DetectRemoteApcCreationSuspect);
            }
            else if (strcmp(detectionName, "THREAD_HIJACK_INTENT") == 0)
            {
                InterlockedIncrement(&cap->DetectThreadHijackIntent);
            }
            else if (strcmp(detectionName, "THREAD_ACTIVITY_WITH_THREAD_CONTEXT_INTENT") == 0)
            {
                InterlockedIncrement(&cap->DetectThreadContextIntent);
            }
            else if (strcmp(detectionName, "DRIVER_DISPATCH_OR_OBJECT_TAMPER") == 0)
            {
                InterlockedIncrement(&cap->DetectTamper);
            }
            else if (strcmp(detectionName, "DRIVER_DISPATCH_OR_OBJECT_TAMPER_CLEARED") == 0)
            {
                InterlockedIncrement(&cap->DetectTamperCleared);
            }
        }
    }
    else
    {
        InterlockedIncrement(&cap->UnknownEvents);
    }
}

static DWORD WINAPI EtwConsumerThreadProc(_In_ LPVOID Context)
{
    ETW_CAPTURE *cap = (ETW_CAPTURE *)Context;
    ULONG status;

    status = BLACKBIRDSCRunEtwSession(cap->Session);
    InterlockedExchange(&cap->ProcessTraceStatus, (LONG)status);
    return status;
}

static BOOL StartEtwCapture(_Out_ ETW_CAPTURE *cap)
{
    WCHAR fallbackName[64];
    DWORD err = ERROR_SUCCESS;

    if (cap == NULL)
    {
        return FALSE;
    }

    ZeroMemory(cap, sizeof(*cap));
    cap->Session = NULL;
    cap->ProcessTraceStatus = ERROR_SUCCESS;
    cap->TiProviderEnabled = FALSE;
    (void)StringCchCopyW(cap->SessionName, RTL_NUMBER_OF(cap->SessionName), BLACKBIRD_SUITE_ETW_SESSION);

    (void)BLACKBIRDSCStopSessionByName(BLACKBIRD_SUITE_ETW_SESSION);
    (void)BLACKBIRDSCStopSessionByName(L"BlackbirdSensorSession");
    Sleep(80);

    if (!BLACKBIRDSCStartBlackbirdEtwSession(cap->SessionName, TRUE, BlackbirdEtwRecordCallback, cap,
                                                 &cap->Session, &cap->TiProviderEnabled))
    {
        err = GetLastError();
        printf("[INFO] ETW start failed err=%lu session=%ws\n", err, cap->SessionName);
        if (err == ERROR_ACCESS_DENIED || err == ERROR_ALREADY_EXISTS)
        {
            if (swprintf_s(fallbackName, RTL_NUMBER_OF(fallbackName), L"%ls-%lu", BLACKBIRD_SUITE_ETW_SESSION,
                           GetCurrentProcessId()) > 0)
            {
                (void)StringCchCopyW(cap->SessionName, RTL_NUMBER_OF(cap->SessionName), fallbackName);
                if (!BLACKBIRDSCStartBlackbirdEtwSession(cap->SessionName, TRUE, BlackbirdEtwRecordCallback, cap,
                                                             &cap->Session, &cap->TiProviderEnabled))
                {
                    err = GetLastError();
                    printf("[INFO] ETW fallback start failed err=%lu session=%ws\n", err, cap->SessionName);
                    return FALSE;
                }
                printf("[INFO] ETW started with fallback session name %ws\n", cap->SessionName);
            }
            else
            {
                return FALSE;
            }
        }
        else
        {
            return FALSE;
        }
    }

    if (!cap->TiProviderEnabled)
    {
        printf("[INFO] ETW started without TI provider (tiEnableErr=%lu)\n",
               BLACKBIRDSCGetLastThreatIntelEnableError());
    }

    g_ActiveEtwCapture = cap;
    cap->TraceThread = CreateThread(NULL, 0, EtwConsumerThreadProc, cap, 0, NULL);
    if (cap->TraceThread == NULL)
    {
        BLACKBIRDSCStopEtwSession(cap->Session);
        cap->Session = NULL;
        g_ActiveEtwCapture = NULL;
        return FALSE;
    }

    Sleep(150);
    return TRUE;
}

static VOID StopEtwCapture(_Inout_ ETW_CAPTURE *cap)
{
    if (cap == NULL)
    {
        return;
    }

    if (cap->Session != NULL)
    {
        BLACKBIRDSCStopEtwSession(cap->Session);
        cap->Session = NULL;
    }

    if (cap->TraceThread != NULL)
    {
        (void)WaitForSingleObject(cap->TraceThread, 5000);
        CloseHandle(cap->TraceThread);
        cap->TraceThread = NULL;
    }

    g_ActiveEtwCapture = NULL;
}

static VOID BrokerCaptureCountEvent(_Inout_ BROKER_ETW_CAPTURE *cap, _In_ const BLACKBIRD_IPC_ETW_EVENT *event)
{
    if (cap == NULL || event == NULL)
    {
        return;
    }

    if (event->Source == BlackbirdIpcEtwSourceThreatIntel)
    {
        InterlockedIncrement(&cap->TiEvents);
        switch (event->Task)
        {
        case 1:
            InterlockedIncrement(&cap->TiAllocVmEvents);
            break;
        case 2:
            InterlockedIncrement(&cap->TiProtectVmEvents);
            break;
        case 7:
            InterlockedIncrement(&cap->TiWriteVmEvents);
            break;
        case 13:
            InterlockedIncrement(&cap->TiSyscallUsageEvents);
            break;
        default:
            InterlockedIncrement(&cap->TiUnknownTaskEvents);
            break;
        }
        return;
    }

    if (event->Source != BlackbirdIpcEtwSourceBlackbird || event->EventName[0] == L'\0')
    {
        InterlockedIncrement(&cap->UnknownEvents);
        return;
    }

    if (wcscmp(event->EventName, L"HandleTelemetry") == 0)
    {
        InterlockedIncrement(&cap->HandleEvents);
    }
    else if (wcscmp(event->EventName, L"ThreadTelemetry") == 0)
    {
        InterlockedIncrement(&cap->ThreadEvents);
    }
    else if (wcscmp(event->EventName, L"ProcessTelemetry") == 0)
    {
        InterlockedIncrement(&cap->ProcessEvents);
    }
    else if (wcscmp(event->EventName, L"ImageTelemetry") == 0)
    {
        InterlockedIncrement(&cap->ImageEvents);
    }
    else if (wcscmp(event->EventName, L"RegistryTelemetry") == 0)
    {
        InterlockedIncrement(&cap->RegistryEvents);
    }
    else if (wcscmp(event->EventName, L"ApcTelemetry") == 0)
    {
        InterlockedIncrement(&cap->ApcEvents);
    }
    else if (wcscmp(event->EventName, L"DetectionTelemetry") == 0)
    {
        InterlockedIncrement(&cap->DetectionEvents);
        if (strcmp(event->DetectionName, "PROCESS_HOLLOWING_MARK_CHAIN_MEDIUM") == 0)
        {
            InterlockedIncrement(&cap->DetectHollowingMarkMedium);
        }
        else if (strcmp(event->DetectionName, "PROCESS_HOLLOWING_MARK_CHAIN_STRONG") == 0)
        {
            InterlockedIncrement(&cap->DetectHollowingMarkStrong);
        }
        else if (strcmp(event->DetectionName, "PROCESS_HOLLOWING_TXF_SUSPECT_CHAIN") == 0)
        {
            InterlockedIncrement(&cap->DetectHollowingTxfChain);
        }
    }
    else
    {
        InterlockedIncrement(&cap->UnknownEvents);
    }
}

static DWORD WINAPI BrokerEtwConsumerThreadProc(_In_ LPVOID Context)
{
    BROKER_ETW_CAPTURE *cap = (BROKER_ETW_CAPTURE *)Context;

    if (cap == NULL || cap->Device == NULL || cap->Device == INVALID_HANDLE_VALUE)
    {
        return 1;
    }

    while (InterlockedCompareExchange(&cap->StopRequested, 0, 0) == 0)
    {
        BLACKBIRD_IPC_ETW_EVENT event;
        BOOL ok = BLACKBIRDSCGetEtwEvent(cap->Device, &event, 500);
        if (!ok)
        {
            DWORD err = GetLastError();
            if (err == ERROR_NO_MORE_ITEMS)
            {
                continue;
            }
            if (err == ERROR_NOT_READY || err == ERROR_OPERATION_ABORTED || err == ERROR_DEVICE_NOT_CONNECTED ||
                err == ERROR_BROKEN_PIPE)
            {
                break;
            }
            if (err == ERROR_NOT_SUPPORTED || err == ERROR_INVALID_FUNCTION)
            {
                break;
            }
            Sleep(60);
            continue;
        }

        BrokerCaptureCountEvent(cap, &event);
    }

    return 0;
}
BOOL StartBrokerEtwCapture(_Out_ BROKER_ETW_CAPTURE *cap, _In_reads_opt_(SeedCount) const DWORD *SeedPids,
                                  _In_ DWORD SeedCount, _In_ DWORD StreamMask)
{
    UINT32 capabilities = 0;
    BOOL tiEnabled = FALSE;

    if (cap == NULL)
    {
        return FALSE;
    }

    ZeroMemory(cap, sizeof(*cap));
    cap->Device = INVALID_HANDLE_VALUE;

    if (!BLACKBIRDSCGetBrokerInfo(&capabilities, &tiEnabled))
    {
        return FALSE;
    }
    if ((capabilities & BLACKBIRD_IPC_CAP_ETW_TI_UPLINK) == 0)
    {
        SetLastError(ERROR_NOT_SUPPORTED);
        return FALSE;
    }

    cap->Device = BLACKBIRDSCOpenControlDevice();
    if (cap->Device == INVALID_HANDLE_VALUE)
    {
        return FALSE;
    }

    if (SeedPids != NULL && SeedCount > 0)
    {
        if (!BLACKBIRDSCSetPids(cap->Device, SeedPids, SeedCount, StreamMask))
        {
            (void)BLACKBIRDSCCloseControlDevice(cap->Device);
            cap->Device = INVALID_HANDLE_VALUE;
            return FALSE;
        }
    }

    cap->TiProviderEnabled = tiEnabled;
    cap->TiEnableError = BLACKBIRDSCGetBrokerThreatIntelEnableError();
    cap->StopRequested = 0;
    cap->TraceThread = CreateThread(NULL, 0, BrokerEtwConsumerThreadProc, cap, 0, NULL);
    if (cap->TraceThread == NULL)
    {
        (void)BLACKBIRDSCCloseControlDevice(cap->Device);
        cap->Device = INVALID_HANDLE_VALUE;
        return FALSE;
    }

    Sleep(150);
    return TRUE;
}
VOID StopBrokerEtwCapture(_Inout_ BROKER_ETW_CAPTURE *cap)
{
    if (cap == NULL)
    {
        return;
    }

    InterlockedExchange(&cap->StopRequested, 1);
    if (cap->TraceThread != NULL)
    {
        (void)WaitForSingleObject(cap->TraceThread, 5000);
        CloseHandle(cap->TraceThread);
        cap->TraceThread = NULL;
    }

    if (cap->Device != NULL && cap->Device != INVALID_HANDLE_VALUE)
    {
        (void)BLACKBIRDSCCloseControlDevice(cap->Device);
        cap->Device = INVALID_HANDLE_VALUE;
    }
}
BOOL WaitForBrokerEtwEventCoverage(_In_ BROKER_ETW_CAPTURE *cap, _In_ DWORD maxMs, _In_ BOOL requireApcTelemetry)
{
    ULONGLONG start = GetTickCount64();

    while ((GetTickCount64() - start) < maxMs)
    {
        if (InterlockedCompareExchange(&cap->HandleEvents, 0, 0) > 0 &&
            InterlockedCompareExchange(&cap->ThreadEvents, 0, 0) > 0 &&
            InterlockedCompareExchange(&cap->ProcessEvents, 0, 0) > 0 &&
            InterlockedCompareExchange(&cap->ImageEvents, 0, 0) > 0 &&
            InterlockedCompareExchange(&cap->RegistryEvents, 0, 0) > 0 &&
            (!requireApcTelemetry || InterlockedCompareExchange(&cap->ApcEvents, 0, 0) > 0) &&
            InterlockedCompareExchange(&cap->DetectionEvents, 0, 0) > 0)
        {
            return TRUE;
        }
        Sleep(100);
    }
    return FALSE;
}

static BOOL WaitForEtwEventCoverage(_In_ ETW_CAPTURE *cap, _In_ DWORD maxMs, _In_ BOOL requireApcTelemetry)
{
    ULONGLONG start = GetTickCount64();

    while ((GetTickCount64() - start) < maxMs)
    {
        if (InterlockedCompareExchange(&cap->HandleEvents, 0, 0) > 0 &&
            InterlockedCompareExchange(&cap->ThreadEvents, 0, 0) > 0 &&
            InterlockedCompareExchange(&cap->ProcessEvents, 0, 0) > 0 &&
            InterlockedCompareExchange(&cap->ImageEvents, 0, 0) > 0 &&
            InterlockedCompareExchange(&cap->RegistryEvents, 0, 0) > 0 &&
            (!requireApcTelemetry || InterlockedCompareExchange(&cap->ApcEvents, 0, 0) > 0) &&
            InterlockedCompareExchange(&cap->DetectionEvents, 0, 0) > 0)
        {
            return TRUE;
        }
        Sleep(100);
    }
    return FALSE;
}




