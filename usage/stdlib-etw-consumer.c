#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <stdio.h>
#include "..\user\sensor\sleepwalker_sensor_core.h"

// {D6C73F8A-6AD8-4F4B-A363-3D2FA31CD0E2}
static const GUID SLEEPWALKER_PROVIDER_GUID = {
    0xd6c73f8a, 0x6ad8, 0x4f4b, {0xa3, 0x63, 0x3d, 0x2f, 0xa3, 0x1c, 0xd0, 0xe2}};

static VOID WINAPI OnEvent(_In_ PEVENT_RECORD Record, _In_opt_z_ PCWSTR EventName, _In_opt_ PVOID Context)
{
    UNREFERENCED_PARAMETER(Context);

    if (Record == NULL || EventName == NULL)
    {
        return;
    }

    if (Record->EventHeader.ProviderId.Data1 != SLEEPWALKER_PROVIDER_GUID.Data1)
    {
        return;
    }

    wprintf(L"%ls\n", EventName);
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
    config.SessionName = L"SleepwalkerUsageSession";
    config.Providers = &provider;
    config.ProviderCount = 1;
    config.Callback = OnEvent;
    config.CallbackContext = NULL;

    if (!SLEEPWALKERSCStartEtwSession(&config, &session))
    {
        wprintf(L"failed to start ETW session: %lu\n", GetLastError());
        return 1;
    }

    wprintf(L"sleepwalker ETW session running, press Ctrl+C to stop\n");
    (void)SLEEPWALKERSCRunEtwSession(session);

    SLEEPWALKERSCStopEtwSession(session);
    return 0;
}
