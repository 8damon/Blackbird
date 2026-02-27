#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>
#include <strsafe.h>
#include <stdio.h>
#include "..\\user\\sensor\\sleepwalker_sensor_core.h"

// {D6C73F8A-6AD8-4F4B-A363-3D2FA31CD0E2}
static const GUID SLEEPWALKER_PROVIDER_GUID = {
    0xd6c73f8a, 0x6ad8, 0x4f4b, {0xa3, 0x63, 0x3d, 0x2f, 0xa3, 0x1c, 0xd0, 0xe2}};

static BOOL GetEtwAnsiProperty(_In_ PEVENT_RECORD Record, _In_z_ PCWSTR Name, _Out_writes_z_(OutputChars) PSTR Output,
                               _In_ size_t OutputChars)
{
    PROPERTY_DATA_DESCRIPTOR descriptor;
    ULONG size = 0;
    PBYTE data = NULL;
    TDHSTATUS status;
    BOOL ok = FALSE;

    if (Record == NULL || Name == NULL || Output == NULL || OutputChars == 0)
    {
        return FALSE;
    }

    Output[0] = '\0';
    ZeroMemory(&descriptor, sizeof(descriptor));
    descriptor.PropertyName = (ULONGLONG)(ULONG_PTR)Name;
    descriptor.ArrayIndex = ULONG_MAX;

    status = TdhGetPropertySize(Record, 0, NULL, 1, &descriptor, &size);
    if (status != ERROR_SUCCESS || size == 0)
    {
        return FALSE;
    }

    data = (PBYTE)malloc(size + 1);
    if (data == NULL)
    {
        return FALSE;
    }
    ZeroMemory(data, size + 1);

    status = TdhGetProperty(Record, 0, NULL, 1, &descriptor, size, data);
    if (status == ERROR_SUCCESS)
    {
        (void)StringCchCopyA(Output, OutputChars, (PCSTR)data);
        ok = TRUE;
    }

    free(data);
    return ok;
}

static BOOL GetEtwUInt32Property(_In_ PEVENT_RECORD Record, _In_z_ PCWSTR Name, _Out_ UINT32 *Value)
{
    PROPERTY_DATA_DESCRIPTOR descriptor;
    ULONG size = 0;
    TDHSTATUS status;
    UINT32 value = 0;

    if (Record == NULL || Name == NULL || Value == NULL)
    {
        return FALSE;
    }

    *Value = 0;
    ZeroMemory(&descriptor, sizeof(descriptor));
    descriptor.PropertyName = (ULONGLONG)(ULONG_PTR)Name;
    descriptor.ArrayIndex = ULONG_MAX;

    status = TdhGetPropertySize(Record, 0, NULL, 1, &descriptor, &size);
    if (status != ERROR_SUCCESS || size < sizeof(UINT32))
    {
        return FALSE;
    }

    status = TdhGetProperty(Record, 0, NULL, 1, &descriptor, sizeof(value), (PBYTE)&value);
    if (status != ERROR_SUCCESS)
    {
        return FALSE;
    }

    *Value = value;
    return TRUE;
}

static VOID WINAPI OnEvent(_In_ PEVENT_RECORD Record, _In_opt_z_ PCWSTR EventName, _In_opt_ PVOID Context)
{
    CHAR detectionName[128];
    UINT32 severity = 0;

    UNREFERENCED_PARAMETER(Context);

    if (Record == NULL || EventName == NULL || EventName[0] == L'\0')
    {
        return;
    }

    if (!IsEqualGUID(&Record->EventHeader.ProviderId, &SLEEPWALKER_PROVIDER_GUID))
    {
        return;
    }

    if (wcscmp(EventName, L"DetectionTelemetry") != 0)
    {
        return;
    }

    detectionName[0] = '\0';
    if (!GetEtwAnsiProperty(Record, L"detectionName", detectionName, RTL_NUMBER_OF(detectionName)))
    {
        return;
    }

    (void)GetEtwUInt32Property(Record, L"severity", &severity);

    if (strcmp(detectionName, "POSSIBLE_PROCESS_HOLLOWING_OR_INJECTION_INTENT_CHAIN") == 0 ||
        strcmp(detectionName, "DIRECT_SYSCALL_SUSPECT_HANDLE_OPERATION") == 0 ||
        strcmp(detectionName, "SUSPICIOUS_NTDLL_IMAGE_PATH") == 0 ||
        strcmp(detectionName, "MULTIPLE_NTDLL_IMAGE_MAPPINGS") == 0)
    {
        printf("[ALERT] injection intent signal: %s (severity=%u)\n", detectionName, severity);
    }
}

int __cdecl wmain(void)
{
    SLEEPWALKERSC_ETW_PROVIDER_CONFIG provider;
    SLEEPWALKERSC_ETW_SESSION_CONFIG config;
    SLEEPWALKERSC_ETW_SESSION *session = NULL;

    ZeroMemory(&provider, sizeof(provider));
    provider.ProviderId = SLEEPWALKER_PROVIDER_GUID;
    provider.Level = TRACE_LEVEL_INFORMATION;
    provider.MatchAnyKeyword = 0;
    provider.MatchAllKeyword = 0;

    ZeroMemory(&config, sizeof(config));
    config.SessionName = L"SleepwalkerIntentChainExample";
    config.Providers = &provider;
    config.ProviderCount = 1;
    config.Callback = OnEvent;
    config.CallbackContext = NULL;

    if (!SLEEPWALKERSCStartEtwSession(&config, &session))
    {
        wprintf(L"failed to start ETW session: %lu\n", GetLastError());
        return 1;
    }

    wprintf(L"ETW session running, press Ctrl+C to stop\n");
    (void)SLEEPWALKERSCRunEtwSession(session);

    SLEEPWALKERSCStopEtwSession(session);
    return 0;
}
