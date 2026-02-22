#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <stdio.h>
#include <string.h>
#include "stinger_etw_printer.h"
#include "stinger_etw_symbols.h"
#include "stinger_sensor_core.h"

// {D6C73F8A-6AD8-4F4B-A363-3D2FA31CD0E2}
static const GUID STINGER_PROVIDER_GUID =
{ 0xd6c73f8a, 0x6ad8, 0x4f4b, { 0xa3, 0x63, 0x3d, 0x2f, 0xa3, 0x1c, 0xd0, 0xe2 } };
// {F4E1897C-BB5D-5668-F1D8-040F4D8DD344}
static const GUID STINGER_TI_PROVIDER_GUID =
{ 0xf4e1897c, 0xbb5d, 0x5668, { 0xf1, 0xd8, 0x04, 0x0f, 0x4d, 0x8d, 0xd3, 0x44 } };

static const WCHAR* STINGER_SESSION_NAME = L"StingerSensorSession";
static STINGERSC_ETW_SESSION* g_Session = NULL;
static volatile LONG g_StopRequested = 0;

static
VOID WINAPI
StingerSensorCallback(
    _In_ PEVENT_RECORD Record,
    _In_opt_z_ PCWSTR EventName,
    _In_opt_ PVOID Context
)
{
    UNREFERENCED_PARAMETER(Context);

    if (Record == NULL) {
        return;
    }
    if (IsEqualGUID(&Record->EventHeader.ProviderId, &STINGER_PROVIDER_GUID)) {
        if (EventName != NULL && EventName[0] != L'\0') {
            STINGERPrintEtwRecord(Record, EventName);
        }
    }
}

static BOOL WINAPI
ConsoleHandler(_In_ DWORD CtrlType)
{
    if (CtrlType == CTRL_C_EVENT || CtrlType == CTRL_BREAK_EVENT || CtrlType == CTRL_CLOSE_EVENT) {
        InterlockedExchange(&g_StopRequested, 1);
        if (g_Session != NULL) {
            STINGERSCStopEtwSession(g_Session);
            g_Session = NULL;
        }
        return TRUE;
    }
    return FALSE;
}

int __cdecl
wmain(void)
{
    ULONG status;
    STINGERSC_ETW_PROVIDER_CONFIG providers[2];
    STINGERSC_ETW_SESSION_CONFIG config;

    if (!SetConsoleCtrlHandler(ConsoleHandler, TRUE)) {
        wprintf(L"failed to install control handler\n");
        return 1;
    }

    STINGEREtwSymbolsInitialize();

    ZeroMemory(&providers, sizeof(providers));
    providers[0].ProviderId = STINGER_PROVIDER_GUID;
    providers[0].Level = TRACE_LEVEL_INFORMATION;
    providers[0].MatchAnyKeyword = 0;
    providers[0].MatchAllKeyword = 0;
    providers[1].ProviderId = STINGER_TI_PROVIDER_GUID;
    providers[1].Level = TRACE_LEVEL_INFORMATION;
    providers[1].MatchAnyKeyword = ~0ULL;
    providers[1].MatchAllKeyword = 0;

    ZeroMemory(&config, sizeof(config));
    config.SessionName = STINGER_SESSION_NAME;
    config.Providers = providers;
    config.ProviderCount = RTL_NUMBER_OF(providers);
    config.Callback = StingerSensorCallback;
    config.CallbackContext = NULL;

    if (!STINGERSCStartEtwSession(&config, &g_Session)) {
        wprintf(L"failed to start ETW session: %lu\n", GetLastError());
        STINGEREtwSymbolsCleanup();
        return 1;
    }

    wprintf(L"stinger sensor running, press Ctrl+C to stop\n");
    status = STINGERSCRunEtwSession(g_Session);

    if (g_Session != NULL) {
        STINGERSCStopEtwSession(g_Session);
        g_Session = NULL;
    }

    STINGEREtwSymbolsCleanup();

    if (status != ERROR_SUCCESS && InterlockedCompareExchange(&g_StopRequested, 0, 0) == 0) {
        wprintf(L"ProcessTrace failed: %lu\n", status);
        return 1;
    }

    return 0;
}
