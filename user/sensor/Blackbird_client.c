#include "client/blackbird_client_internal.h"

#pragma comment(lib, "tdh.lib")

volatile LONG g_StopRequested = 0;
BLACKBIRDSC_ETW_SESSION *g_StopSession = NULL;
BLACKBIRD_LOGGER g_Logger;

BOOL WINAPI ConsoleCtrlHandler(_In_ DWORD CtrlType)
{
    UNREFERENCED_PARAMETER(CtrlType);
    InterlockedExchange(&g_StopRequested, 1);
    if (g_StopSession != NULL)
    {
        BLACKBIRDSCStopEtwSession(g_StopSession);
    }
    return TRUE;
}

