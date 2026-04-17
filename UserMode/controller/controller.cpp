#include "core/blackbird_controller_private.h"

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "tdh.lib")

SERVICE_STATUS_HANDLE g_ServiceStatusHandle = NULL;
SERVICE_STATUS g_ServiceStatus;
HANDLE g_StopEvent = NULL;

class ControllerLogger
{
  public:
    ControllerLogger() noexcept = default;
    ~ControllerLogger() noexcept
    {
        Close();
    }

    ControllerLogger(const ControllerLogger &) = delete;
    ControllerLogger &operator=(const ControllerLogger &) = delete;

    void Init() noexcept
    {
        CHAR logDir[MAX_PATH];
        CHAR logPath[MAX_PATH];
        CHAR rotatePath[MAX_PATH];
        CHAR intermediate[MAX_PATH];
        DWORD expanded;
        LARGE_INTEGER fileSize;

        ScopedCriticalSection guard(m_lock);

        if (m_file != INVALID_HANDLE_VALUE)
        {
            return;
        }

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
            return;
        }
        CreateDirectoryA(logDir, NULL);

        (void)StringCchPrintfA(logPath, RTL_NUMBER_OF(logPath), "%s\\controller.log", logDir);
        (void)StringCchPrintfA(rotatePath, RTL_NUMBER_OF(rotatePath), "%s\\controller.log.1", logDir);

        HANDLE probe = CreateFileA(logPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                                   OPEN_EXISTING, 0, NULL);
        if (probe != INVALID_HANDLE_VALUE)
        {
            if (GetFileSizeEx(probe, &fileSize) && fileSize.QuadPart > (4LL * 1024 * 1024))
            {
                CloseHandle(probe);
                (void)MoveFileExA(logPath, rotatePath, MOVEFILE_REPLACE_EXISTING);
            }
            else
            {
                CloseHandle(probe);
            }
        }

        m_file = CreateFileA(logPath, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS,
                             FILE_ATTRIBUTE_NORMAL, NULL);
    }

    void Close() noexcept
    {
        ScopedCriticalSection guard(m_lock);
        if (m_file != INVALID_HANDLE_VALUE)
        {
            FlushFileBuffers(m_file);
            CloseHandle(m_file);
            m_file = INVALID_HANDLE_VALUE;
        }
    }

    void Log(_In_z_ _Printf_format_string_ PCSTR fmt, va_list args) noexcept
    {
        char message[1024];
        char stamped[1080];
        SYSTEMTIME st;
        DWORD written;

        (void)StringCchVPrintfA(message, RTL_NUMBER_OF(message), fmt, args);

        (void)OutputDebugStringA(message);
        (void)printf("%s", message);

        if (m_file == INVALID_HANDLE_VALUE)
        {
            return;
        }

        GetLocalTime(&st);
        SIZE_T msgLen = strlen(message);
        while (msgLen > 0 && (message[msgLen - 1] == '\n' || message[msgLen - 1] == '\r'))
        {
            message[--msgLen] = '\0';
        }
        (void)StringCchPrintfA(stamped, RTL_NUMBER_OF(stamped), "[%04u-%02u-%02u %02u:%02u:%02u] %s\r\n", st.wYear,
                               st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, message);

        ScopedCriticalSection guard(m_lock);
        if (m_file != INVALID_HANDLE_VALUE)
        {
            (void)WriteFile(m_file, stamped, (DWORD)strlen(stamped), &written, NULL);
        }
    }

  private:
    OwnedCriticalSection m_lock;
    HANDLE m_file = INVALID_HANDLE_VALUE;
};

static ControllerLogger g_Log;

HANDLE g_ServerThread = NULL;
HANDLE g_DriverPumpThread = NULL;
HANDLE g_EtwThread = NULL;
HANDLE g_DriverHandle = INVALID_HANDLE_VALUE;
BLACKBIRDSC_ETW_SESSION *g_EtwSession = NULL;
BOOL g_ThreatIntelEnabled = FALSE;
DWORD g_ThreatIntelEnableError = ERROR_SUCCESS;
volatile LONG g_EtwDetectionEvents = 0;
volatile LONG g_EtwTiEvents = 0;
OwnedCriticalSection g_ClientListLock;
OwnedCriticalSection g_DriverLock;
OwnedCriticalSection g_DriverConfigLock;
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
    g_Log.Init();
}

VOID ControllerLogClose(VOID)
{
    g_Log.Close();
}

VOID ControllerLog(_In_z_ _Printf_format_string_ PCSTR Format, ...)
{
    va_list args;
    va_start(args, Format);
    g_Log.Log(Format, args);
    va_end(args);
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
