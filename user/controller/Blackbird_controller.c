#include "core/blackbird_controller_private.h"

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "tdh.lib")

SERVICE_STATUS_HANDLE g_ServiceStatusHandle = NULL;
SERVICE_STATUS g_ServiceStatus;
HANDLE g_StopEvent = NULL;

static HANDLE g_LogFile = INVALID_HANDLE_VALUE;
static CRITICAL_SECTION g_LogLock;
static BOOL g_LogLockInitialized = FALSE;
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

VOID ControllerLogInit(VOID)
{
    CHAR logDir[MAX_PATH];
    CHAR logPath[MAX_PATH];
    CHAR rotatePath[MAX_PATH];
    CHAR intermediate[MAX_PATH];
    DWORD expanded;
    LARGE_INTEGER fileSize;
    HANDLE probe;

    if (!g_LogLockInitialized)
    {
        InitializeCriticalSection(&g_LogLock);
        g_LogLockInitialized = TRUE;
    }

    EnterCriticalSection(&g_LogLock);
    __try
    {
        if (g_LogFile != INVALID_HANDLE_VALUE)
        {
            __leave;
        }

        // Build the log directory path: %ProgramData%\Blackbird\Node\logs
        expanded = ExpandEnvironmentStringsA("%ProgramData%\\Blackbird", intermediate, RTL_NUMBER_OF(intermediate));
        if (expanded > 0 && expanded <= RTL_NUMBER_OF(intermediate))
        {
            CreateDirectoryA(intermediate, NULL);
        }
        expanded =
            ExpandEnvironmentStringsA("%ProgramData%\\Blackbird\\Node", intermediate, RTL_NUMBER_OF(intermediate));
        if (expanded > 0 && expanded <= RTL_NUMBER_OF(intermediate))
        {
            CreateDirectoryA(intermediate, NULL);
        }
        expanded = ExpandEnvironmentStringsA("%ProgramData%\\Blackbird\\Node\\logs", logDir, RTL_NUMBER_OF(logDir));
        if (expanded == 0 || expanded > RTL_NUMBER_OF(logDir))
        {
            __leave;
        }
        CreateDirectoryA(logDir, NULL);

        (void)StringCchPrintfA(logPath, RTL_NUMBER_OF(logPath), "%s\\controller.log", logDir);
        (void)StringCchPrintfA(rotatePath, RTL_NUMBER_OF(rotatePath), "%s\\controller.log.1", logDir);

        // Rotate if existing log exceeds 4 MB so the file stays small enough for the UI to tail.
        probe = CreateFileA(logPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                            OPEN_EXISTING, 0, NULL);
        if (probe != INVALID_HANDLE_VALUE)
        {
            if (GetFileSizeEx(probe, &fileSize) && fileSize.QuadPart > (4LL * 1024 * 1024))
            {
                CloseHandle(probe);
                probe = INVALID_HANDLE_VALUE;
                (void)MoveFileExA(logPath, rotatePath, MOVEFILE_REPLACE_EXISTING);
            }
            else
            {
                CloseHandle(probe);
                probe = INVALID_HANDLE_VALUE;
            }
        }

        // Open with FILE_APPEND_DATA and share-read so the interface can tail it concurrently.
        g_LogFile = CreateFileA(logPath, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS,
                                FILE_ATTRIBUTE_NORMAL, NULL);
    }
    __finally
    {
        LeaveCriticalSection(&g_LogLock);
    }
}

VOID ControllerLogClose(VOID)
{
    if (!g_LogLockInitialized)
    {
        return;
    }
    EnterCriticalSection(&g_LogLock);
    if (g_LogFile != INVALID_HANDLE_VALUE)
    {
        FlushFileBuffers(g_LogFile);
        CloseHandle(g_LogFile);
        g_LogFile = INVALID_HANDLE_VALUE;
    }
    LeaveCriticalSection(&g_LogLock);
}

VOID ControllerLog(_In_z_ _Printf_format_string_ PCSTR Format, ...)
{
    char message[1024];
    char stamped[1080];
    SYSTEMTIME st;
    va_list args;
    DWORD written;

    va_start(args, Format);
    (void)StringCchVPrintfA(message, RTL_NUMBER_OF(message), Format, args);
    va_end(args);

    (void)OutputDebugStringA(message);
    (void)printf("%s", message);

    if (g_LogLockInitialized && g_LogFile != INVALID_HANDLE_VALUE)
    {
        GetLocalTime(&st);
        // Strip trailing newline from message before adding our own; keeps the log tidy.
        SIZE_T msgLen = strlen(message);
        while (msgLen > 0 && (message[msgLen - 1] == '\n' || message[msgLen - 1] == '\r'))
        {
            message[--msgLen] = '\0';
        }
        (void)StringCchPrintfA(stamped, RTL_NUMBER_OF(stamped), "[%04u-%02u-%02u %02u:%02u:%02u] %s\r\n", st.wYear,
                               st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, message);
        EnterCriticalSection(&g_LogLock);
        if (g_LogFile != INVALID_HANDLE_VALUE)
        {
            (void)WriteFile(g_LogFile, stamped, (DWORD)strlen(stamped), &written, NULL);
        }
        LeaveCriticalSection(&g_LogLock);
    }
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

    (void)SetServiceStatus(g_ServiceStatusHandle, &g_ServiceStatus);
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
