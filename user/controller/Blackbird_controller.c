#include "core/blackbird_controller_private.h"

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "tdh.lib")

SERVICE_STATUS_HANDLE g_ServiceStatusHandle = NULL;
SERVICE_STATUS g_ServiceStatus;
HANDLE g_StopEvent = NULL;
HANDLE g_ServerThread = NULL;
HANDLE g_DriverPumpThread = NULL;
HANDLE g_EtwThread = NULL;
HANDLE g_DriverHandle = INVALID_HANDLE_VALUE;
BLACKBIRDSC_ETW_SESSION *g_EtwSession = NULL;
BOOL g_ThreatIntelEnabled = FALSE;
DWORD g_ThreatIntelEnableError = ERROR_SUCCESS;
volatile LONG g_EtwDetectionEvents = 0;
volatile LONG g_EtwTiEvents = 0;
CRITICAL_SECTION g_ClientListLock;
CRITICAL_SECTION g_DriverLock;
CRITICAL_SECTION g_DriverConfigLock;
BOOL g_LocksInitialized = FALSE;
volatile LONG g_DriverSubscriptionsDirty = 0;
PBLACKBIRD_CONTROLLER_CLIENT g_ClientList = NULL;
PBLACKBIRD_CONTROLLER_CLIENT g_ClientSlots[BLACKBIRD_CONTROLLER_MAX_CLIENTS];
DWORD g_ClientCount = 0;
DWORD g_ProgrammedPids[BLACKBIRD_MAX_PID_LIST];
DWORD g_ProgrammedPidCount = 0;
BLACKBIRD_CONTROLLER_PID_INDEX_ENTRY g_PidIndex[BLACKBIRD_MAX_PID_LIST];
DWORD g_PidIndexCount = 0;
SRWLOCK g_HollowLock = SRWLOCK_INIT;
BLACKBIRD_CONTROLLER_HOLLOW_ENTRY g_HollowEntries[BLACKBIRD_CONTROLLER_HOLLOW_MAX_ENTRIES];

VOID ControllerLog(_In_z_ _Printf_format_string_ PCSTR Format, ...)
{
    char message[1024];
    va_list args;

    va_start(args, Format);
    (void) StringCchVPrintfA(message, RTL_NUMBER_OF(message), Format, args);
    va_end(args);

    (void) OutputDebugStringA(message);
    (void) printf("%s", message);
}

VOID ControllerUpdateServiceStatus(_In_ DWORD CurrentState, _In_ DWORD Win32ExitCode, _In_ DWORD WaitHint)
{
    static DWORD checkpoint = 1;

    if (g_ServiceStatusHandle == NULL)
    {
        return;
    }

    g_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_ServiceStatus.dwCurrentState = CurrentState;
    g_ServiceStatus.dwWin32ExitCode = Win32ExitCode;
    g_ServiceStatus.dwWaitHint = WaitHint;
    g_ServiceStatus.dwControlsAccepted = 0;
    g_ServiceStatus.dwCheckPoint = 0;

    if (CurrentState == SERVICE_START_PENDING || CurrentState == SERVICE_STOP_PENDING)
    {
        g_ServiceStatus.dwCheckPoint = checkpoint++;
    }

    if (CurrentState == SERVICE_RUNNING)
    {
        g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    }

    (void) SetServiceStatus(g_ServiceStatusHandle, &g_ServiceStatus);
}

BOOL ControllerShouldStop(VOID)
{
    return (g_StopEvent != NULL && WaitForSingleObject(g_StopEvent, 0) == WAIT_OBJECT_0);
}

VOID ControllerStopEtwSessionByNameBestEffort(_In_z_ PCWSTR SessionName, _In_z_ PCSTR Reason)
{
    ULONG status;

    if (SessionName == NULL || SessionName[0] == L'\0')
    {
        return;
    }

    status = BLACKBIRDSCStopSessionByName(SessionName);
    if (status == ERROR_SUCCESS)
    {
        ControllerLog("[ETW] stopped session reason=%s name=%ws\n", Reason, SessionName);
    }
    else
    {
        ControllerLog("[ETW][WARN] stop-by-name failed reason=%s name=%ws status=%lu\n", Reason, SessionName, status);
    }
}

VOID ControllerCleanupStaleEtwSessions(VOID)
{
    ControllerStopEtwSessionByNameBestEffort(BLACKBIRD_CONTROLLER_ETW_SESSION_NAMEW, "pre-start");
}
