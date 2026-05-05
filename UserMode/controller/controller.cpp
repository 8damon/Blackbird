#include "core/controller_private.h"

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
        ApplyLogDirectoryAcl(logDir);

        (void)StringCchPrintfA(logPath, RTL_NUMBER_OF(logPath), "%s\\controller.log", logDir);
        (void)StringCchPrintfA(rotatePath, RTL_NUMBER_OF(rotatePath), "%s\\controller.log.1", logDir);

        HANDLE probe = CreateFileA(logPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                                   OPEN_EXISTING, 0, NULL);
        if (probe != INVALID_HANDLE_VALUE)
        {
            CloseHandle(probe);
            (void)MoveFileExA(logPath, rotatePath, MOVEFILE_REPLACE_EXISTING);
        }

        m_file = CreateFileA(logPath, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                             CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (m_file != INVALID_HANDLE_VALUE)
        {
            LARGE_INTEGER end = {};
            (void)SetFilePointerEx(m_file, end, NULL, FILE_END);
        }
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

    static bool TagEquals(_In_reads_(tagLen) PCSTR tag, _In_ SIZE_T tagLen, _In_z_ PCSTR expected) noexcept
    {
        SIZE_T expectedLen = strlen(expected);
        return tagLen == expectedLen && _strnicmp(tag, expected, expectedLen) == 0;
    }

    static bool IsSeverityTag(_In_reads_(tagLen) PCSTR tag, _In_ SIZE_T tagLen) noexcept
    {
        return TagEquals(tag, tagLen, "WARN") || TagEquals(tag, tagLen, "ERR") || TagEquals(tag, tagLen, "ERROR") ||
               TagEquals(tag, tagLen, "INFO") || TagEquals(tag, tagLen, "DIAG") || TagEquals(tag, tagLen, "PANIC");
    }

    static PCSTR ComponentForTag(_In_reads_(tagLen) PCSTR tag, _In_ SIZE_T tagLen) noexcept
    {
        if (TagEquals(tag, tagLen, "DRIVER"))
        {
            return "blackbird.sys";
        }
        if (TagEquals(tag, tagLen, "NETSVC") || TagEquals(tag, tagLen, "NODE"))
        {
            return "BlackbirdNetSvc.exe";
        }
        if (TagEquals(tag, tagLen, "INJ") || TagEquals(tag, tagLen, "HOOK"))
        {
            return "SR71.dll";
        }
        if (TagEquals(tag, tagLen, "IPC") || TagEquals(tag, tagLen, "ETW") || TagEquals(tag, tagLen, "MON") ||
            TagEquals(tag, tagLen, "MITIGATION") || TagEquals(tag, tagLen, "WARN") || TagEquals(tag, tagLen, "ERR") ||
            TagEquals(tag, tagLen, "ERROR") || TagEquals(tag, tagLen, "INFO") || TagEquals(tag, tagLen, "*") ||
            TagEquals(tag, tagLen, "-"))
        {
            return "BlackbirdController.exe";
        }

        return NULL;
    }

    static void ApplyLogDirectoryAcl(_In_z_ PCSTR logDir) noexcept
    {
        PSECURITY_DESCRIPTOR securityDescriptor = NULL;

        if (logDir == NULL || logDir[0] == '\0')
        {
            return;
        }

        if (ConvertStringSecurityDescriptorToSecurityDescriptorA(
                "D:P(A;OICI;GA;;;SY)(A;OICI;GA;;;BA)(A;OICI;GRGW;;;BU)", SDDL_REVISION_1, &securityDescriptor,
                NULL) &&
            securityDescriptor != NULL)
        {
            (void)SetFileSecurityA(logDir, DACL_SECURITY_INFORMATION, securityDescriptor);
            LocalFree(securityDescriptor);
        }
    }

    static void NormalizeComponentPrefix(_In_z_ PCSTR message, _Out_writes_z_(normalizedChars) PSTR normalized,
                                         _In_ SIZE_T normalizedChars) noexcept
    {
        PCSTR close;
        PCSTR component;
        PCSTR tail;
        SIZE_T tagLen;

        if (normalized == NULL || normalizedChars == 0)
        {
            return;
        }
        normalized[0] = '\0';

        if (message == NULL || message[0] != '[')
        {
            (void)StringCchCopyA(normalized, normalizedChars, message != NULL ? message : "");
            return;
        }

        close = strchr(message + 1, ']');
        if (close == NULL || close == message + 1)
        {
            (void)StringCchCopyA(normalized, normalizedChars, message);
            return;
        }

        tagLen = (SIZE_T)(close - (message + 1));
        component = ComponentForTag(message + 1, tagLen);
        if (component == NULL)
        {
            (void)StringCchCopyA(normalized, normalizedChars, message);
            return;
        }
        tail = close + 1;
        if (_stricmp(component, "BlackbirdController.exe") == 0 && _strnicmp(tail, " BlackbirdController:", 21) == 0)
        {
            tail += 21;
        }

        if (IsSeverityTag(message + 1, tagLen))
        {
            (void)StringCchPrintfA(normalized, normalizedChars, "[%s][%.*s]%s", component, (int)tagLen, message + 1,
                                   tail);
        }
        else
        {
            (void)StringCchPrintfA(normalized, normalizedChars, "[%s]%s", component, tail);
        }
    }

    void Log(_In_z_ _Printf_format_string_ PCSTR fmt, va_list args) noexcept
    {
        char message[2048];
        char normalized[2048];
        char stamped[2200];
        SYSTEMTIME st;
        DWORD written;

        (void)StringCchVPrintfA(message, RTL_NUMBER_OF(message), fmt, args);
        NormalizeComponentPrefix(message, normalized, RTL_NUMBER_OF(normalized));

        (void)OutputDebugStringA(normalized);
        (void)printf("%s", normalized);

        if (m_file == INVALID_HANDLE_VALUE)
        {
            return;
        }

        GetLocalTime(&st);
        SIZE_T msgLen = strlen(normalized);
        while (msgLen > 0 && (normalized[msgLen - 1] == '\n' || normalized[msgLen - 1] == '\r'))
        {
            normalized[--msgLen] = '\0';
        }
        (void)StringCchPrintfA(stamped, RTL_NUMBER_OF(stamped),
                               "[%04u-%02u-%02u %02u:%02u:%02u pid=%lu tid=%lu] %s\r\n", st.wYear, st.wMonth, st.wDay,
                               st.wHour, st.wMinute, st.wSecond, GetCurrentProcessId(), GetCurrentThreadId(),
                               normalized);

        ScopedCriticalSection guard(m_lock);
        if (m_file != INVALID_HANDLE_VALUE)
        {
            (void)WriteFile(m_file, stamped, (DWORD)strlen(stamped), &written, NULL);
            (void)FlushFileBuffers(m_file);
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
BKSC_ETW_SESSION *g_EtwSession = NULL;
BOOL g_ThreatIntelEnabled = FALSE;
DWORD g_ThreatIntelEnableError = ERROR_SUCCESS;
volatile LONG g_EtwDetectionEvents = 0;
volatile LONG g_EtwTiEvents = 0;
OwnedCriticalSection g_ClientListLock;
OwnedCriticalSection g_DriverLock;
OwnedCriticalSection g_DriverConfigLock;
volatile LONG g_DriverSubscriptionsDirty = 0;
PBK_CONTROLLER_CLIENT g_ClientList = NULL;
PBK_CONTROLLER_CLIENT g_ClientSlots[BK_CONTROLLER_MAX_CLIENTS];
DWORD g_ClientCount = 0;
DWORD g_ProgrammedPids[BK_MAX_PID_LIST];
DWORD g_ProgrammedPidCount = 0;
BK_CONTROLLER_PID_INDEX_ENTRY g_PidIndex[BK_MAX_PID_LIST];
DWORD g_PidIndexCount = 0;
SRWLOCK g_HollowLock = SRWLOCK_INIT;
BK_CONTROLLER_HOLLOW_ENTRY g_HollowEntries[BK_CONTROLLER_HOLLOW_MAX_ENTRIES];

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

VOID ControllerApplyProcessMitigations(VOID)
{
    PROCESS_MITIGATION_DYNAMIC_CODE_POLICY dynamicCode = {};
    PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY extensionPoints = {};
    PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY strictHandles = {};
    PROCESS_MITIGATION_IMAGE_LOAD_POLICY imageLoad = {};

    SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32);

    dynamicCode.ProhibitDynamicCode = 1;
    dynamicCode.AllowThreadOptOut = 0;
    dynamicCode.AllowRemoteDowngrade = 0;
    if (!SetProcessMitigationPolicy(ProcessDynamicCodePolicy, &dynamicCode, sizeof(dynamicCode)))
    {
        ControllerLog("[MITIGATION][WARN] dynamic-code mitigation failed err=%lu\n", GetLastError());
    }

    extensionPoints.DisableExtensionPoints = 1;
    if (!SetProcessMitigationPolicy(ProcessExtensionPointDisablePolicy, &extensionPoints, sizeof(extensionPoints)))
    {
        ControllerLog("[MITIGATION][WARN] extension-point mitigation failed err=%lu\n", GetLastError());
    }

    strictHandles.RaiseExceptionOnInvalidHandleReference = 1;
    strictHandles.HandleExceptionsPermanentlyEnabled = 1;
    if (!SetProcessMitigationPolicy(ProcessStrictHandleCheckPolicy, &strictHandles, sizeof(strictHandles)))
    {
        ControllerLog("[MITIGATION][WARN] strict-handle mitigation failed err=%lu\n", GetLastError());
    }

    imageLoad.NoRemoteImages = 1;
    imageLoad.NoLowMandatoryLabelImages = 1;
    imageLoad.PreferSystem32Images = 1;
    if (!SetProcessMitigationPolicy(ProcessImageLoadPolicy, &imageLoad, sizeof(imageLoad)))
    {
        ControllerLog("[MITIGATION][WARN] image-load mitigation failed err=%lu\n", GetLastError());
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

    status = BkscStopSessionByName(SessionName);
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
    ControllerStopEtwSessionByNameBestEffort(BK_CONTROLLER_ETW_SESSION_NAMEW, "pre-start");
}
