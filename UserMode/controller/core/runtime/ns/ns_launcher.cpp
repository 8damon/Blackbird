#include "ns_launcher.h"
#include <iphlpapi.h>

static HANDLE g_NetSvcProcess = NULL;
static HANDLE g_NetSvcStopEvent = NULL;
static HANDLE g_NetSvcDriverHandle = NULL;
static HANDLE g_NetSvcJob = NULL;
static DWORD g_NetSvcPid = 0;
static BOOL g_NetSvcEndpointGuardArmed = FALSE;
static WCHAR g_NetSvcStopEventName[128] = {0};

#define BK_NETSVC_DISCOVERY_PORT 49371u
#define BK_NETSVC_STATUS_PORT 49372u
#define BK_NETSVC_COMMAND_PORT 49373u

static BOOL ControllerBuildSiblingPath(_In_z_ PCWSTR ImageName, _Out_writes_z_(PathChars) PWSTR Path,
                                       _In_ size_t PathChars)
{
    WCHAR modulePath[MAX_PATH];
    PWSTR slash;

    if (ImageName == NULL || ImageName[0] == L'\0' || Path == NULL || PathChars == 0)
    {
        return FALSE;
    }
    if (GetModuleFileNameW(NULL, modulePath, RTL_NUMBER_OF(modulePath)) == 0)
    {
        return FALSE;
    }
    slash = wcsrchr(modulePath, L'\\');
    if (slash == NULL)
    {
        return FALSE;
    }
    slash[1] = L'\0';
    return SUCCEEDED(StringCchPrintfW(Path, PathChars, L"%s%s", modulePath, ImageName));
}

static BOOL ControllerQueryProcessImagePath(_In_ HANDLE Process, _Out_writes_z_(PathChars) PWSTR Path,
                                            _In_ DWORD PathChars)
{
    DWORD chars = PathChars;

    if (Process == NULL || Process == INVALID_HANDLE_VALUE || Path == NULL || PathChars == 0)
    {
        return FALSE;
    }
    Path[0] = L'\0';
    return QueryFullProcessImageNameW(Process, 0, Path, &chars);
}

static VOID ControllerFormatWin32Error(_In_ DWORD Error, _Out_writes_z_(BufferChars) PSTR Buffer,
                                       _In_ size_t BufferChars)
{
    DWORD written;

    if (Buffer == NULL || BufferChars == 0)
    {
        return;
    }
    Buffer[0] = '\0';

    written = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, Error, 0, Buffer,
                             (DWORD)BufferChars, NULL);
    if (written == 0)
    {
        (void)StringCchPrintfA(Buffer, BufferChars, "Win32 error %lu", Error);
        return;
    }

    while (written > 0 && (Buffer[written - 1] == '\r' || Buffer[written - 1] == '\n' || Buffer[written - 1] == '.' ||
                           Buffer[written - 1] == ' '))
    {
        Buffer[--written] = '\0';
    }
}

static PCSTR ControllerSensorProtocolModeName(_In_ BKSC_PROTOCOL_MODE Mode)
{
    switch (Mode)
    {
    case BKSC_PROTOCOL_SERVICE:
        return "service";
    case BKSC_PROTOCOL_CLIENT:
        return "client";
    default:
        return "unknown";
    }
}

static PCSTR ControllerServiceStateName(_In_ DWORD State)
{
    switch (State)
    {
    case SERVICE_STOPPED:
        return "stopped";
    case SERVICE_START_PENDING:
        return "start-pending";
    case SERVICE_STOP_PENDING:
        return "stop-pending";
    case SERVICE_RUNNING:
        return "running";
    case SERVICE_CONTINUE_PENDING:
        return "continue-pending";
    case SERVICE_PAUSE_PENDING:
        return "pause-pending";
    case SERVICE_PAUSED:
        return "paused";
    default:
        return "unknown";
    }
}

static BOOL ControllerCreateNetSvcLifecycleJob(_In_ HANDLE Process, _In_ DWORD ProcessId)
{
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits;
    HANDLE job;
    DWORD err;

    if (Process == NULL || Process == INVALID_HANDLE_VALUE)
    {
        SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    if (g_NetSvcJob != NULL)
    {
        CloseHandle(g_NetSvcJob);
        g_NetSvcJob = NULL;
    }

    job = CreateJobObjectW(NULL, NULL);
    if (job == NULL)
    {
        err = GetLastError();
        ControllerLog("[NETSVC][WARN] lifecycle job create failed pid=%lu err=%lu\n", ProcessId, err);
        SetLastError(err);
        return FALSE;
    }

    ZeroMemory(&limits, sizeof(limits));
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_BREAKAWAY_OK;
    if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits)))
    {
        err = GetLastError();
        ControllerLog("[NETSVC][WARN] lifecycle job configure failed pid=%lu err=%lu\n", ProcessId, err);
        CloseHandle(job);
        SetLastError(err);
        return FALSE;
    }

    if (!AssignProcessToJobObject(job, Process))
    {
        err = GetLastError();
        ControllerLog("[NETSVC][WARN] lifecycle job assignment failed pid=%lu err=%lu\n", ProcessId, err);
        CloseHandle(job);
        SetLastError(err);
        return FALSE;
    }

    g_NetSvcJob = job;
    ControllerLog("[NETSVC] lifecycle job assigned pid=%lu killOnClose=1 breakawayOk=1\n", ProcessId);
    return TRUE;
}

static UINT16 ControllerNetworkPortToHost(_In_ DWORD Port)
{
    UINT16 value = (UINT16)Port;
    return (UINT16)(((value & 0x00FFu) << 8) | ((value & 0xFF00u) >> 8));
}

static BOOL ControllerTcpListenOwnedByPid(_In_ DWORD ProcessId, _In_ UINT16 Port)
{
    DWORD size = 0;
    DWORD status;

    status = GetExtendedTcpTable(NULL, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_LISTENER, 0);
    if (status != ERROR_INSUFFICIENT_BUFFER || size == 0)
    {
        SetLastError(status == NO_ERROR ? ERROR_NOT_FOUND : status);
        return FALSE;
    }

    std::vector<BYTE> storage(size);
    PMIB_TCPTABLE_OWNER_PID table = reinterpret_cast<PMIB_TCPTABLE_OWNER_PID>(storage.data());
    status = GetExtendedTcpTable(table, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_LISTENER, 0);
    if (status != NO_ERROR)
    {
        SetLastError(status);
        return FALSE;
    }

    for (DWORD i = 0; i < table->dwNumEntries; ++i)
    {
        const MIB_TCPROW_OWNER_PID &row = table->table[i];
        if (row.dwOwningPid == ProcessId && ControllerNetworkPortToHost(row.dwLocalPort) == Port)
        {
            return TRUE;
        }
    }

    SetLastError(ERROR_NOT_FOUND);
    return FALSE;
}

static BOOL ControllerUdpEndpointOwnedByPid(_In_ DWORD ProcessId, _In_ UINT16 Port)
{
    DWORD size = 0;
    DWORD status;

    status = GetExtendedUdpTable(NULL, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    if (status != ERROR_INSUFFICIENT_BUFFER || size == 0)
    {
        SetLastError(status == NO_ERROR ? ERROR_NOT_FOUND : status);
        return FALSE;
    }

    std::vector<BYTE> storage(size);
    PMIB_UDPTABLE_OWNER_PID table = reinterpret_cast<PMIB_UDPTABLE_OWNER_PID>(storage.data());
    status = GetExtendedUdpTable(table, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    if (status != NO_ERROR)
    {
        SetLastError(status);
        return FALSE;
    }

    for (DWORD i = 0; i < table->dwNumEntries; ++i)
    {
        const MIB_UDPROW_OWNER_PID &row = table->table[i];
        if (row.dwOwningPid == ProcessId && ControllerNetworkPortToHost(row.dwLocalPort) == Port)
        {
            return TRUE;
        }
    }

    SetLastError(ERROR_NOT_FOUND);
    return FALSE;
}

static BOOL ControllerWaitNetSvcEndpointsOnline(_In_ HANDLE Process, _In_ DWORD ProcessId, _In_ DWORD TimeoutMs)
{
    ULONGLONG start = GetTickCount64();
    ULONGLONG deadline = start + TimeoutMs;
    BOOL discoveryReady = FALSE;
    BOOL statusReady = FALSE;
    BOOL commandReady = FALSE;

    if (Process == NULL || Process == INVALID_HANDLE_VALUE || ProcessId == 0)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    do
    {
        DWORD wait = WaitForSingleObject(Process, 0);
        if (wait == WAIT_OBJECT_0)
        {
            DWORD exitCode = 0;
            (void)GetExitCodeProcess(Process, &exitCode);
            ControllerLog("[NETSVC][WARN] process exited before network lanes were ready pid=%lu exit=%lu\n", ProcessId,
                          exitCode);
            SetLastError(ERROR_PROCESS_ABORTED);
            return FALSE;
        }

        discoveryReady = ControllerUdpEndpointOwnedByPid(ProcessId, (UINT16)BK_NETSVC_DISCOVERY_PORT);
        statusReady = ControllerTcpListenOwnedByPid(ProcessId, (UINT16)BK_NETSVC_STATUS_PORT);
        commandReady = ControllerTcpListenOwnedByPid(ProcessId, (UINT16)BK_NETSVC_COMMAND_PORT);
        if (discoveryReady && statusReady && commandReady)
        {
            ControllerLog("[NETSVC] network endpoints online pid=%lu waitMs=%llu discovery=%u status=%u command=%u\n",
                          ProcessId, GetTickCount64() - start, discoveryReady ? 1u : 0u, statusReady ? 1u : 0u,
                          commandReady ? 1u : 0u);
            return TRUE;
        }

        Sleep(100);
    } while (GetTickCount64() < deadline);

    ControllerLog(
        "[NETSVC][WARN] network endpoint readiness timed out pid=%lu waitMs=%lu discovery=%u status=%u command=%u\n",
        ProcessId, TimeoutMs, discoveryReady ? 1u : 0u, statusReady ? 1u : 0u, commandReady ? 1u : 0u);
    SetLastError(ERROR_TIMEOUT);
    return FALSE;
}

static BOOL ControllerQueryServiceProcessStatus(_In_ SC_HANDLE Service, _Out_ SERVICE_STATUS_PROCESS *Status)
{
    DWORD bytesNeeded = 0;

    if (Service == NULL || Status == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    ZeroMemory(Status, sizeof(*Status));
    return QueryServiceStatusEx(Service, SC_STATUS_PROCESS_INFO, (LPBYTE)Status, sizeof(*Status), &bytesNeeded);
}

static BOOL ControllerEnsureBaseFilteringEngineReady(_In_z_ PCSTR Reason)
{
    SC_HANDLE scm;
    SC_HANDLE service;
    SERVICE_STATUS_PROCESS status;
    DWORD lastError;

    scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (scm == NULL)
    {
        lastError = GetLastError();
        ControllerLog("[NETSVC][WARN] BFE dependency probe failed reason=%s step=open-scm err=%lu\n", Reason,
                      lastError);
        SetLastError(lastError);
        return FALSE;
    }

    service = OpenServiceW(scm, L"BFE", SERVICE_QUERY_STATUS | SERVICE_START);
    if (service == NULL)
    {
        lastError = GetLastError();
        ControllerLog("[NETSVC][WARN] BFE dependency probe failed reason=%s step=open-service err=%lu\n", Reason,
                      lastError);
        CloseServiceHandle(scm);
        SetLastError(lastError);
        return FALSE;
    }

    if (!ControllerQueryServiceProcessStatus(service, &status))
    {
        lastError = GetLastError();
        ControllerLog("[NETSVC][WARN] BFE dependency status query failed reason=%s err=%lu\n", Reason, lastError);
        CloseServiceHandle(service);
        CloseServiceHandle(scm);
        SetLastError(lastError);
        return FALSE;
    }

    ControllerLog("[NETSVC] BFE dependency state=%lu(%s) pid=%lu reason=%s\n", status.dwCurrentState,
                  ControllerServiceStateName(status.dwCurrentState), status.dwProcessId, Reason);
    if (status.dwCurrentState == SERVICE_RUNNING)
    {
        CloseServiceHandle(service);
        CloseServiceHandle(scm);
        return TRUE;
    }

    if (status.dwCurrentState == SERVICE_STOPPED || status.dwCurrentState == SERVICE_PAUSED)
    {
        if (!StartServiceW(service, 0, NULL))
        {
            lastError = GetLastError();
            if (lastError != ERROR_SERVICE_ALREADY_RUNNING)
            {
                ControllerLog("[NETSVC][WARN] BFE dependency start failed reason=%s err=%lu\n", Reason, lastError);
                CloseServiceHandle(service);
                CloseServiceHandle(scm);
                SetLastError(lastError);
                return FALSE;
            }
        }
        ControllerLog("[NETSVC] BFE dependency start requested reason=%s\n", Reason);
    }

    for (DWORD attempt = 0; attempt < 40; ++attempt)
    {
        Sleep(250);
        if (!ControllerQueryServiceProcessStatus(service, &status))
        {
            lastError = GetLastError();
            ControllerLog("[NETSVC][WARN] BFE dependency wait query failed reason=%s attempt=%lu err=%lu\n", Reason,
                          attempt + 1, lastError);
            CloseServiceHandle(service);
            CloseServiceHandle(scm);
            SetLastError(lastError);
            return FALSE;
        }
        if (status.dwCurrentState == SERVICE_RUNNING)
        {
            ControllerLog("[NETSVC] BFE dependency ready pid=%lu waitMs=%lu reason=%s\n", status.dwProcessId,
                          (attempt + 1) * 250, Reason);
            CloseServiceHandle(service);
            CloseServiceHandle(scm);
            return TRUE;
        }
        if (status.dwCurrentState == SERVICE_STOPPED)
        {
            break;
        }
    }

    lastError = ERROR_SERVICE_NOT_ACTIVE;
    ControllerLog("[NETSVC][WARN] BFE dependency not ready reason=%s state=%lu(%s)\n", Reason, status.dwCurrentState,
                  ControllerServiceStateName(status.dwCurrentState));
    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    SetLastError(lastError);
    return FALSE;
}

static PCSTR ControllerDiagnosticEventName(_In_ UINT32 EventType)
{
    switch (EventType)
    {
    case BkDiagEventInitBegin:
        return "init-begin";
    case BkDiagEventInitOk:
        return "init-ok";
    case BkDiagEventInitFailed:
        return "init-failed";
    case BkDiagEventOnline:
        return "online";
    case BkDiagEventConfirmedOnline:
        return "confirmed-online";
    case BkDiagEventDisabledByPolicy:
        return "disabled-by-policy";
    case BkDiagEventOptionalMissingContinuing:
        return "optional-missing-continuing";
    case BkDiagEventDisarmed:
        return "disarmed";
    case BkDiagEventArmed:
        return "armed";
    case BkDiagEventShutdownBegin:
        return "shutdown-begin";
    case BkDiagEventShutdownOk:
        return "shutdown-ok";
    case BkDiagEventSelfCheckFailed:
        return "self-check-failed";
    case BkDiagEventDegradedContinuing:
        return "degraded-continuing";
    default:
        return "unknown";
    }
}

static PCSTR ControllerDiagnosticComponentName(_In_ UINT32 ComponentId)
{
    switch (ComponentId)
    {
    case BK_DIAG_COMPONENT_CONTROL:
        return "control";
    case BK_DIAG_COMPONENT_WFP_ENDPOINT_GUARD:
        return "wfp-endpoint-guard";
    case BK_DIAG_COMPONENT_WFP_ENDPOINT:
        return "wfp-endpoint";
    case BK_DIAG_COMPONENT_ENTERPRISE_MONITOR:
        return "enterprise-monitor";
    case BK_DIAG_COMPONENT_BUGCHECK_MONITOR:
        return "bugcheck-monitor";
    default:
        return "other";
    }
}

static PCSTR ControllerEndpointGuardProtocolName(_In_ UINT32 Protocol)
{
    switch (Protocol)
    {
    case BK_ENDPOINT_GUARD_PROTOCOL_TCP:
        return "tcp";
    case BK_ENDPOINT_GUARD_PROTOCOL_UDP:
        return "udp";
    default:
        return "unknown";
    }
}

static PCSTR ControllerEndpointGuardStageName(_In_ UINT32 Stage)
{
    switch (Stage)
    {
    case 0x01u:
        return "filter-listen";
    case 0x02u:
        return "filter-recv-accept";
    case 0x04u:
        return "filter-connect";
    case 0x08u:
        return "filter-resource-assignment";
    case 0xA1u:
        return "authorize";
    case 0xA2u:
        return "validate";
    case 0xA3u:
        return "runtime";
    case 0xA4u:
        return "slot";
    case 0xA5u:
        return "required-filter";
    case 0xA6u:
        return "arm-begin";
    case 0xA7u:
        return "disarm-begin";
    case 0xE1u:
        return "runtime-engine-open";
    case 0xE2u:
        return "runtime-register-listen";
    case 0xE3u:
        return "runtime-register-recv-accept";
    case 0xE4u:
        return "runtime-register-connect";
    case 0xE5u:
        return "runtime-register-resource-assignment";
    case 0xE6u:
        return "runtime-add-listen";
    case 0xE7u:
        return "runtime-add-recv-accept";
    case 0xE8u:
        return "runtime-add-connect";
    case 0xE9u:
        return "runtime-add-resource-assignment";
    case 0xEAu:
        return "runtime-add-sublayer";
    case 0xEBu:
        return "runtime-engine-open-static";
    case 0xECu:
        return "runtime-bfe-state";
    case 0xEDu:
        return "runtime-engine-open-dynamic-default";
    case 0xEEu:
        return "runtime-engine-open-null-winnt";
    case 0xEFu:
        return "runtime-engine-open-null-default";
    default:
        return "unknown";
    }
}

static PCSTR ControllerEndpointGuardBfeStateName(_In_ UINT32 State)
{
    switch (State)
    {
    case 0u:
        return "stopped";
    case 1u:
        return "start-pending";
    case 2u:
        return "stop-pending";
    case 3u:
        return "running";
    default:
        return "unknown";
    }
}

static PCSTR ControllerEndpointGuardActionName(_In_ UINT32 Action)
{
    switch (Action)
    {
    case BK_ENDPOINT_GUARD_ACTION_ARM:
        return "arm";
    case BK_ENDPOINT_GUARD_ACTION_DISARM:
        return "disarm";
    default:
        return "unknown";
    }
}

static VOID ControllerDescribeEndpointGuardDetail(_In_ const BK_DIAGNOSTIC_EVENT *Event,
                                                  _Out_writes_z_(BufferChars) PSTR Buffer, _In_ size_t BufferChars)
{
    UINT32 detail;
    UINT32 stage;
    UINT32 protocol;
    UINT32 port;

    if (Buffer == NULL || BufferChars == 0)
    {
        return;
    }
    Buffer[0] = '\0';
    if (Event == NULL)
    {
        return;
    }

    detail = Event->DetailCode;
    stage = (detail >> 24) & 0xFFu;
    protocol = (detail >> 16) & 0xFFu;
    port = detail & 0xFFFFu;

    if (stage == 0x01u || stage == 0x02u || stage == 0x04u || stage == 0x08u || (stage >= 0xA1u && stage <= 0xA7u))
    {
        (void)StringCchPrintfA(Buffer, BufferChars, "stage=%s protocol=%s port=%lu",
                               ControllerEndpointGuardStageName(stage), ControllerEndpointGuardProtocolName(protocol),
                               port);
        return;
    }
    if (stage >= 0xE1u && stage <= 0xEAu)
    {
        (void)StringCchPrintfA(Buffer, BufferChars, "stage=%s", ControllerEndpointGuardStageName(stage));
        return;
    }
    if (stage == 0xEBu)
    {
        (void)StringCchCopyA(Buffer, BufferChars, "stage=runtime-engine-open-static");
        return;
    }
    if (stage == 0xECu)
    {
        (void)StringCchPrintfA(Buffer, BufferChars, "stage=runtime-bfe-state state=%lu(%s)", port,
                               ControllerEndpointGuardBfeStateName(port));
        return;
    }
    if (stage >= 0xEDu && stage <= 0xEFu)
    {
        (void)StringCchPrintfA(Buffer, BufferChars, "stage=%s", ControllerEndpointGuardStageName(stage));
        return;
    }

    {
        UINT32 action = (detail >> 28) & 0x0Fu;
        UINT32 direction = (detail >> 24) & 0x0Fu;
        if ((action == BK_ENDPOINT_GUARD_ACTION_ARM || action == BK_ENDPOINT_GUARD_ACTION_DISARM) &&
            (direction & ~(BK_ENDPOINT_GUARD_DIRECTION_INBOUND | BK_ENDPOINT_GUARD_DIRECTION_OUTBOUND)) == 0)
        {
            (void)StringCchPrintfA(Buffer, BufferChars, "request=%s direction=0x%lX protocol=%s port=%lu",
                                   ControllerEndpointGuardActionName(action), direction,
                                   ControllerEndpointGuardProtocolName(protocol), port);
            return;
        }
    }

    (void)StringCchCopyA(Buffer, BufferChars, "detail=unclassified");
}

static BOOL ControllerDiagnosticIsEndpointGuardRelevant(_In_ const BK_DIAGNOSTIC_EVENT *Event)
{
    if (Event == NULL)
    {
        return FALSE;
    }
    return Event->ComponentId == BK_DIAG_COMPONENT_WFP_ENDPOINT_GUARD ||
           Event->ComponentId == BK_DIAG_COMPONENT_WFP_ENDPOINT || Event->ComponentId == BK_DIAG_COMPONENT_CONTROL;
}

static VOID ControllerDumpEndpointGuardDiagnostics(_In_ HANDLE DriverHandle, _In_z_ PCSTR Reason)
{
    BK_DIAGNOSTICS_RESPONSE diagnostics;
    DWORD bytes = 0;
    UINT32 shown = 0;
    BKSC_PROTOCOL_MODE mode = BkscGetProtocolMode();

    if (mode != BKSC_PROTOCOL_SERVICE)
    {
        ControllerLog(
            "[NETSVC][DIAG] endpoint guard kernel diagnostics skipped reason=%s protocolMode=%lu(%s); request path is broker/client, not direct driver IOCTL\n",
            Reason, (DWORD)mode, ControllerSensorProtocolModeName(mode));
        return;
    }
    if (DriverHandle == NULL || DriverHandle == INVALID_HANDLE_VALUE)
    {
        ControllerLog(
            "[NETSVC][DIAG] endpoint guard diagnostics unavailable reason=%s driver=%p protocolMode=%lu(%s)\n", Reason,
            DriverHandle, (DWORD)mode, ControllerSensorProtocolModeName(mode));
        return;
    }

    ZeroMemory(&diagnostics, sizeof(diagnostics));
    if (!BkscGetDiagnostics(DriverHandle, &diagnostics, &bytes))
    {
        DWORD err = GetLastError();
        CHAR message[256];
        ControllerFormatWin32Error(err, message, RTL_NUMBER_OF(message));
        ControllerLog(
            "[NETSVC][DIAG] endpoint guard diagnostics query failed reason=%s err=%lu (%s) protocolMode=%lu(%s)\n",
            Reason, err, message, (DWORD)mode, ControllerSensorProtocolModeName(mode));
        return;
    }

    for (LONG i = (LONG)diagnostics.EventCount - 1; i >= 0 && shown < 8; --i)
    {
        const BK_DIAGNOSTIC_EVENT *event = &diagnostics.Events[i];
        if (!ControllerDiagnosticIsEndpointGuardRelevant(event))
        {
            continue;
        }

        CHAR detailText[160];
        ControllerDescribeEndpointGuardDetail(event, detailText, RTL_NUMBER_OF(detailText));
        ControllerLog(
            "[NETSVC][DIAG] endpoint guard seq=%llu component=%s event=%s status=0x%08lX flags=0x%08lX detail=0x%08lX decoded=\"%s\" elapsedQpc=%llu reason=%s\n",
            event->Sequence, ControllerDiagnosticComponentName(event->ComponentId),
            ControllerDiagnosticEventName(event->EventType), (DWORD)event->Status, event->Flags, event->DetailCode,
            detailText, event->ElapsedQpc, Reason);
        ++shown;
    }

    if (shown == 0)
    {
        ControllerLog(
            "[NETSVC][DIAG] no endpoint guard kernel diagnostics found reason=%s events=%lu nextSeq=%llu dropped=%lu protocolMode=%lu(%s)\n",
            Reason, diagnostics.EventCount, diagnostics.NextSequence, diagnostics.DroppedCount, (DWORD)mode,
            ControllerSensorProtocolModeName(mode));
    }
}

static BOOL ControllerQueryThreadImpersonationLevel(_Out_ SECURITY_IMPERSONATION_LEVEL *Level)
{
    HANDLE threadToken = NULL;
    DWORD bytesReturned = 0;
    BOOL ok;

    if (Level != NULL)
    {
        *Level = SecurityAnonymous;
    }

    if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &threadToken))
    {
        return FALSE;
    }

    ok = GetTokenInformation(threadToken, TokenImpersonationLevel, Level, sizeof(*Level), &bytesReturned);
    CloseHandle(threadToken);
    return ok;
}

static BOOL ControllerRevertImpersonationForProcessCreate(_In_z_ PCSTR Context)
{
    SECURITY_IMPERSONATION_LEVEL level = SecurityAnonymous;
    BOOL wasImpersonating = ControllerQueryThreadImpersonationLevel(&level);

    if (!RevertToSelf())
    {
        DWORD err = GetLastError();
        CHAR message[256];
        ControllerFormatWin32Error(err, message, RTL_NUMBER_OF(message));
        ControllerLog("[NETSVC][ERR] RevertToSelf failed context=%s wasImpersonating=%u level=%lu err=%lu (%s)\n",
                      Context, wasImpersonating ? 1u : 0u, wasImpersonating ? (DWORD)level : 0xFFFFFFFFu, err, message);
        SetLastError(err);
        return FALSE;
    }

    if (wasImpersonating)
    {
        ControllerLog("[NETSVC] reverted thread impersonation before %s level=%lu\n", Context, (DWORD)level);
    }
    return TRUE;
}

static BOOL ControllerGetDirectoryFromPath(_In_z_ PCWSTR Path, _Out_writes_z_(DirectoryChars) PWSTR Directory,
                                           _In_ size_t DirectoryChars)
{
    PCWSTR slash;
    size_t chars;

    if (Path == NULL || Directory == NULL || DirectoryChars == 0)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    Directory[0] = L'\0';

    slash = wcsrchr(Path, L'\\');
    if (slash == NULL || slash == Path)
    {
        SetLastError(ERROR_INVALID_NAME);
        return FALSE;
    }

    chars = (size_t)(slash - Path);
    if (chars + 1 > DirectoryChars)
    {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }

    (void)StringCchCopyNW(Directory, DirectoryChars, Path, chars);
    Directory[chars] = L'\0';
    return TRUE;
}

static BOOL ControllerBuildNetSvcCommandLine(_In_z_ PCWSTR ImagePath, _In_z_ PCWSTR StopEventName,
                                             _Out_writes_z_(CommandLineChars) PWSTR CommandLine,
                                             _In_ size_t CommandLineChars)
{
    if (ImagePath == NULL || StopEventName == NULL || CommandLine == NULL || CommandLineChars == 0)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    if (FAILED(StringCchPrintfW(CommandLine, CommandLineChars, L"\"%s\" --controller-child --stop-event-name \"%s\"",
                                ImagePath, StopEventName)))
    {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }

    return TRUE;
}

static VOID ControllerReleaseNetSvcStartupAttributes(_Inout_ STARTUPINFOEXW *StartupInfo,
                                                     _Inout_ PVOID *AttributeBuffer, _Inout_ DWORD *CreationFlags)
{
    if (StartupInfo != NULL && StartupInfo->lpAttributeList != NULL)
    {
        DeleteProcThreadAttributeList(StartupInfo->lpAttributeList);
        StartupInfo->lpAttributeList = NULL;
    }
    if (AttributeBuffer != NULL && *AttributeBuffer != NULL)
    {
        HeapFree(GetProcessHeap(), 0, *AttributeBuffer);
        *AttributeBuffer = NULL;
    }
    if (CreationFlags != NULL)
    {
        *CreationFlags &= ~EXTENDED_STARTUPINFO_PRESENT;
    }
}

static HANDLE ControllerOpenNetSvcNullInputForChild(VOID)
{
    SECURITY_ATTRIBUTES sa;
    HANDLE handle;

    ZeroMemory(&sa, sizeof(sa));
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    handle = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, &sa,
                         OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (handle == INVALID_HANDLE_VALUE)
    {
        ControllerLog("[NETSVC][WARN] stdin NUL open failed err=%lu\n", GetLastError());
    }
    return handle;
}

static VOID ControllerApplyReadableLogDirectorySecurity(_In_z_ PCWSTR LogDir)
{
    PSECURITY_DESCRIPTOR securityDescriptor = NULL;

    if (LogDir == NULL || LogDir[0] == L'\0')
    {
        return;
    }

    if (ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;OICI;GA;;;SY)(A;OICI;GA;;;BA)(A;OICI;GRGW;;;BU)",
                                                             SDDL_REVISION_1, &securityDescriptor, NULL) &&
        securityDescriptor != NULL)
    {
        (void)SetFileSecurityW(LogDir, DACL_SECURITY_INFORMATION, securityDescriptor);
        LocalFree(securityDescriptor);
    }
}

static HANDLE ControllerOpenNetSvcLogForChild(VOID)
{
    WCHAR programData[MAX_PATH];
    WCHAR blackbirdDir[MAX_PATH];
    WCHAR nodeDir[MAX_PATH];
    WCHAR logDir[MAX_PATH];
    WCHAR logPath[MAX_PATH];
    DWORD chars;
    SECURITY_ATTRIBUTES sa;
    HANDLE logHandle;

    ZeroMemory(programData, sizeof(programData));
    chars = GetEnvironmentVariableW(L"ProgramData", programData, RTL_NUMBER_OF(programData));
    if (chars == 0 || chars >= RTL_NUMBER_OF(programData))
    {
        (void)StringCchCopyW(programData, RTL_NUMBER_OF(programData), L"C:\\ProgramData");
    }

    if (FAILED(StringCchPrintfW(blackbirdDir, RTL_NUMBER_OF(blackbirdDir), L"%s\\Blackbird", programData)) ||
        FAILED(StringCchPrintfW(nodeDir, RTL_NUMBER_OF(nodeDir), L"%s\\Node", blackbirdDir)) ||
        FAILED(StringCchPrintfW(logDir, RTL_NUMBER_OF(logDir), L"%s\\logs", nodeDir)) ||
        FAILED(StringCchPrintfW(logPath, RTL_NUMBER_OF(logPath), L"%s\\netsvc.log", logDir)))
    {
        return INVALID_HANDLE_VALUE;
    }

    (void)CreateDirectoryW(blackbirdDir, NULL);
    (void)CreateDirectoryW(nodeDir, NULL);
    (void)CreateDirectoryW(logDir, NULL);
    ControllerApplyReadableLogDirectorySecurity(logDir);

    ZeroMemory(&sa, sizeof(sa));
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    logHandle = CreateFileW(logPath, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, &sa,
                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (logHandle == INVALID_HANDLE_VALUE)
    {
        ControllerLog("[NETSVC][WARN] stdout log open failed path=%ws err=%lu\n", logPath, GetLastError());
        return INVALID_HANDLE_VALUE;
    }

    ControllerLog("[NETSVC] stdout/stderr redirected path=%ws\n", logPath);
    return logHandle;
}

static DWORD64 ControllerBuildNetSvcCreationMitigationPolicy(VOID)
{
    DWORD64 policy = 0;

    policy |= PROCESS_CREATION_MITIGATION_POLICY_DEP_ENABLE;
    policy |= PROCESS_CREATION_MITIGATION_POLICY_SEHOP_ENABLE;
    policy |= PROCESS_CREATION_MITIGATION_POLICY_HEAP_TERMINATE_ALWAYS_ON;
    policy |= PROCESS_CREATION_MITIGATION_POLICY_BOTTOM_UP_ASLR_ALWAYS_ON;
#ifdef _WIN64
    policy |= PROCESS_CREATION_MITIGATION_POLICY_HIGH_ENTROPY_ASLR_ALWAYS_ON;
#endif
    policy |= PROCESS_CREATION_MITIGATION_POLICY_STRICT_HANDLE_CHECKS_ALWAYS_ON;
    policy |= PROCESS_CREATION_MITIGATION_POLICY_EXTENSION_POINT_DISABLE_ALWAYS_ON;
    policy |= PROCESS_CREATION_MITIGATION_POLICY_PROHIBIT_DYNAMIC_CODE_ALWAYS_ON;
    policy |= PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_REMOTE_ALWAYS_ON;
    policy |= PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_LOW_LABEL_ALWAYS_ON;
    policy |= PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_PREFER_SYSTEM32_ALWAYS_ON;
    return policy;
}

static BOOL ControllerInitializeNetSvcStartupInfo(_Out_ STARTUPINFOEXW *StartupInfo,
                                                  _Outptr_result_maybenull_ PVOID *AttributeBuffer,
                                                  _Out_ DWORD *CreationFlags)
{
    SIZE_T attributeListSize = 0;
    DWORD64 mitigationPolicy = ControllerBuildNetSvcCreationMitigationPolicy();
    DWORD firstErr;

    if (StartupInfo == NULL || AttributeBuffer == NULL || CreationFlags == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    ZeroMemory(StartupInfo, sizeof(*StartupInfo));
    StartupInfo->StartupInfo.cb = sizeof(*StartupInfo);
    StartupInfo->StartupInfo.dwFlags = STARTF_USESHOWWINDOW;
    StartupInfo->StartupInfo.wShowWindow = SW_HIDE;
    *AttributeBuffer = NULL;
    *CreationFlags = CREATE_SUSPENDED | CREATE_NO_WINDOW;

    (void)InitializeProcThreadAttributeList(NULL, 1, 0, &attributeListSize);
    firstErr = GetLastError();
    if (attributeListSize == 0)
    {
        CHAR message[256];
        ControllerFormatWin32Error(firstErr, message, RTL_NUMBER_OF(message));
        ControllerLog(
            "[NETSVC][WARN] mitigation attribute sizing unavailable err=%lu (%s); child will self-apply mitigations after resume\n",
            firstErr, message);
        return TRUE;
    }

    *AttributeBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, attributeListSize);
    if (*AttributeBuffer == NULL)
    {
        SetLastError(ERROR_OUTOFMEMORY);
        return FALSE;
    }

    StartupInfo->lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)*AttributeBuffer;
    if (!InitializeProcThreadAttributeList(StartupInfo->lpAttributeList, 1, 0, &attributeListSize))
    {
        DWORD err = GetLastError();
        CHAR message[256];
        ControllerFormatWin32Error(err, message, RTL_NUMBER_OF(message));
        ControllerLog(
            "[NETSVC][WARN] mitigation attribute init failed err=%lu (%s); child will self-apply mitigations after resume\n",
            err, message);
        HeapFree(GetProcessHeap(), 0, *AttributeBuffer);
        *AttributeBuffer = NULL;
        StartupInfo->lpAttributeList = NULL;
        return TRUE;
    }

    if (!UpdateProcThreadAttribute(StartupInfo->lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
                                   &mitigationPolicy, sizeof(mitigationPolicy), NULL, NULL))
    {
        DWORD err = GetLastError();
        CHAR message[256];
        ControllerFormatWin32Error(err, message, RTL_NUMBER_OF(message));
        ControllerLog(
            "[NETSVC][WARN] mitigation attribute update failed policy=0x%016I64X err=%lu (%s); child will self-apply mitigations after resume\n",
            mitigationPolicy, err, message);
        DeleteProcThreadAttributeList(StartupInfo->lpAttributeList);
        HeapFree(GetProcessHeap(), 0, *AttributeBuffer);
        *AttributeBuffer = NULL;
        StartupInfo->lpAttributeList = NULL;
        return TRUE;
    }

    *CreationFlags |= EXTENDED_STARTUPINFO_PRESENT;
    ControllerLog("[NETSVC] creation mitigation policy=0x%016I64X\n", mitigationPolicy);
    return TRUE;
}

static BOOL ControllerSetControllerProtectionRuntime(_In_ HANDLE DriverHandle, _In_ BOOL Enable, _In_z_ PCSTR Reason)
{
    DWORD flags = Enable ? BK_RUNTIME_FLAG_CONTROLLER_PROTECTED_ACCESS : 0;
    DWORD mask = BK_RUNTIME_FLAG_CONTROLLER_PROTECTED_ACCESS;

    if (DriverHandle == NULL || DriverHandle == INVALID_HANDLE_VALUE)
    {
        SetLastError(ERROR_DEVICE_NOT_CONNECTED);
        return FALSE;
    }

    if (!BkscSetRuntimeConfig(DriverHandle, flags, mask))
    {
        DWORD err = GetLastError();
        ControllerLog("[DRIVER][WARN] controller protected-access %s failed reason=%s err=%lu\n",
                      Enable ? "enable" : "disable", Reason, err);
        SetLastError(err);
        return FALSE;
    }

    ControllerLog("[DRIVER] controller protected-access %s reason=%s\n", Enable ? "enabled" : "disabled", Reason);
    return TRUE;
}

static BOOL ControllerIsEndpointGuardUnsupportedError(_In_ DWORD ErrorCode)
{
    return ErrorCode == ERROR_NOT_SUPPORTED || ErrorCode == ERROR_INVALID_FUNCTION;
}

static BOOL ControllerQueryEndpointGuardReady(_In_ HANDLE DriverHandle, _Out_ BOOL *Ready)
{
    BK_HEALTH_RESPONSE health;
    DWORD bytes = 0;
    BKSC_PROTOCOL_MODE protocolMode = BkscGetProtocolMode();

    if (Ready == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    *Ready = FALSE;
    if (DriverHandle == NULL || DriverHandle == INVALID_HANDLE_VALUE)
    {
        SetLastError(ERROR_DEVICE_NOT_CONNECTED);
        return FALSE;
    }

    ZeroMemory(&health, sizeof(health));
    if (!BkscGetHealth(DriverHandle, &health, &bytes))
    {
        DWORD err = GetLastError();
        CHAR message[256];
        ControllerFormatWin32Error(err, message, RTL_NUMBER_OF(message));
        ControllerLog("[NETSVC][WARN] endpoint guard health query failed err=%lu (%s) protocolMode=%lu(%s) driver=%p\n",
                      err, message, (DWORD)protocolMode, ControllerSensorProtocolModeName(protocolMode), DriverHandle);
        ControllerDumpEndpointGuardDiagnostics(DriverHandle, "health-query-failed");
        SetLastError(err);
        return FALSE;
    }

    *Ready = ((health.HealthMask & BK_HEALTH_ENDPOINT_GUARD_READY) != 0);
    ControllerLog(
        "[NETSVC] endpoint guard health probe ready=%u healthMask=0x%08lX bytes=%lu buildMagic=0x%08lX featureMask=0x%08lX protocolMode=%lu(%s) driver=%p\n",
        *Ready ? 1u : 0u, health.HealthMask, bytes, health.Reserved0, health.Reserved1, (DWORD)protocolMode,
        ControllerSensorProtocolModeName(protocolMode), DriverHandle);
    if (*Ready && (health.Reserved0 != BK_HEALTH_BUILD_MAGIC ||
                   (health.Reserved1 & BK_HEALTH_FEATURE_ENDPOINT_GUARD_FILTER_DIAG) == 0))
    {
        ControllerLog(
            "[NETSVC][WARN] loaded driver does not advertise endpoint guard filter diagnostics buildMagic=0x%08lX featureMask=0x%08lX; reinstall/restart blackbird.sys from the current build\n",
            health.Reserved0, health.Reserved1);
    }
    if (!*Ready)
    {
        ControllerLog(
            "[NETSVC][WARN] endpoint guard not advertised by driver healthMask=0x%08lX protocolMode=%lu(%s)\n",
            health.HealthMask, (DWORD)protocolMode, ControllerSensorProtocolModeName(protocolMode));
        ControllerDumpEndpointGuardDiagnostics(DriverHandle, "health-bit-missing");
        SetLastError(ERROR_NOT_SUPPORTED);
        return FALSE;
    }

    return TRUE;
}

static BOOL ControllerSetNetSvcEndpointGuard(_In_ HANDLE DriverHandle, _In_ DWORD ProcessId, _In_ BOOL Enable,
                                             _In_z_ PCSTR Reason, _Out_opt_ BOOL *Unsupported)
{
    static const struct
    {
        UINT32 Protocol;
        UINT16 Port;
        PCSTR Name;
    } kEndpoints[] = {{BK_ENDPOINT_GUARD_PROTOCOL_TCP, (UINT16)BK_NETSVC_STATUS_PORT, "status"},
                      {BK_ENDPOINT_GUARD_PROTOCOL_TCP, (UINT16)BK_NETSVC_COMMAND_PORT, "command"},
                      {BK_ENDPOINT_GUARD_PROTOCOL_UDP, (UINT16)BK_NETSVC_DISCOVERY_PORT, "discovery"}};
    BOOL allOk = TRUE;
    BOOL armedAny = FALSE;
    BOOL softUnsupported = FALSE;
    BOOL hardFailure = FALSE;
    DWORD firstError = ERROR_SUCCESS;
    BKSC_PROTOCOL_MODE protocolMode = BkscGetProtocolMode();

    if (Unsupported != NULL)
    {
        *Unsupported = FALSE;
    }
    if (DriverHandle == NULL || DriverHandle == INVALID_HANDLE_VALUE || ProcessId == 0)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    for (UINT32 i = 0; i < RTL_NUMBER_OF(kEndpoints); ++i)
    {
        BK_ENDPOINT_GUARD_REQUEST request;
        ZeroMemory(&request, sizeof(request));
        request.Action = Enable ? BK_ENDPOINT_GUARD_ACTION_ARM : BK_ENDPOINT_GUARD_ACTION_DISARM;
        request.ProcessId = ProcessId;
        request.Protocol = kEndpoints[i].Protocol;
        request.Direction = BK_ENDPOINT_GUARD_DIRECTION_INBOUND | BK_ENDPOINT_GUARD_DIRECTION_OUTBOUND;
        request.LocalPort = kEndpoints[i].Port;
        request.RemotePort = kEndpoints[i].Port;

        if (!BkscSetEndpointGuard(DriverHandle, &request))
        {
            DWORD err = GetLastError();
            CHAR message[256];
            ControllerFormatWin32Error(err, message, RTL_NUMBER_OF(message));
            ControllerLog(
                "[NETSVC][WARN] endpoint guard %s failed pid=%lu endpoint=%s port=%hu protocol=%lu direction=0x%08lX action=%lu reason=%s err=%lu (%s) protocolMode=%lu(%s) driver=%p\n",
                Enable ? "arm" : "disarm", ProcessId, kEndpoints[i].Name, kEndpoints[i].Port, kEndpoints[i].Protocol,
                request.Direction, request.Action, Reason, err, message, (DWORD)protocolMode,
                ControllerSensorProtocolModeName(protocolMode), DriverHandle);
            if (protocolMode == BKSC_PROTOCOL_CLIENT && ControllerIsEndpointGuardUnsupportedError(err))
            {
                ControllerLog(
                    "[NETSVC][WARN] endpoint guard request did not reach driver; J58 is in client/broker protocol mode\n");
            }
            else if (protocolMode == BKSC_PROTOCOL_SERVICE && ControllerIsEndpointGuardUnsupportedError(err))
            {
                ControllerLog(
                    "[NETSVC][WARN] endpoint guard request reached the service/direct path but returned unsupported; check driver IOCTL dispatch and WFP endpoint guard health\n");
            }
            ControllerDumpEndpointGuardDiagnostics(DriverHandle, Enable ? "arm-failed" : "disarm-failed");
            SetLastError(err);
            if (firstError == ERROR_SUCCESS)
            {
                firstError = err;
            }
            if (Enable && ControllerIsEndpointGuardUnsupportedError(err))
            {
                if (Unsupported != NULL)
                {
                    *Unsupported = TRUE;
                }
                softUnsupported = TRUE;
            }
            else
            {
                hardFailure = TRUE;
                allOk = FALSE;
            }
            if (Enable && hardFailure)
            {
                break;
            }
        }
        else
        {
            if (Enable)
            {
                armedAny = TRUE;
            }
            ControllerLog("[NETSVC] endpoint guard %s pid=%lu endpoint=%s port=%hu protocol=%lu reason=%s\n",
                          Enable ? "armed" : "disarmed", ProcessId, kEndpoints[i].Name, kEndpoints[i].Port,
                          kEndpoints[i].Protocol, Reason);
        }
    }

    if (Enable && hardFailure && armedAny)
    {
        DWORD rollbackError = GetLastError();
        ControllerLog("[NETSVC][WARN] endpoint guard partial arm; rolling back pid=%lu reason=%s\n", ProcessId, Reason);
        (void)ControllerSetNetSvcEndpointGuard(DriverHandle, ProcessId, FALSE, "netsvc-arm-rollback", NULL);
        SetLastError(firstError != ERROR_SUCCESS ? firstError : rollbackError);
        return FALSE;
    }

    if (Enable && softUnsupported)
    {
        if (armedAny)
        {
            ControllerLog("[NETSVC][WARN] endpoint guard partially armed pid=%lu reason=%s unsupportedErr=%lu\n",
                          ProcessId, Reason, firstError);
            return TRUE;
        }
        allOk = FALSE;
    }

    return allOk;
}

static VOID ControllerDisarmNetSvcEndpointGuard(_In_z_ PCSTR Reason)
{
    HANDLE driverHandle = g_NetSvcDriverHandle;
    DWORD processId = g_NetSvcPid;

    if (driverHandle == NULL || driverHandle == INVALID_HANDLE_VALUE || processId == 0)
    {
        return;
    }
    if (!g_NetSvcEndpointGuardArmed)
    {
        return;
    }

    (void)ControllerSetNetSvcEndpointGuard(driverHandle, processId, FALSE, Reason, NULL);
    g_NetSvcEndpointGuardArmed = FALSE;
    g_NetSvcDriverHandle = NULL;
}

VOID ControllerStopNetService(VOID)
{
    DWORD pid = g_NetSvcPid;

    ControllerDisarmNetSvcEndpointGuard("netsvc-stop");
    if (g_NetSvcStopEvent != NULL)
    {
        BOOL signaled = SetEvent(g_NetSvcStopEvent);
        ControllerLog("[NETSVC] stop event signal pid=%lu event=%ws result=%u err=%lu\n", pid,
                      g_NetSvcStopEventName[0] != L'\0' ? g_NetSvcStopEventName : L"(unnamed)", signaled ? 1u : 0u,
                      signaled ? ERROR_SUCCESS : GetLastError());
    }
    else if (pid != 0)
    {
        ControllerLog("[NETSVC][WARN] stop event absent pid=%lu\n", pid);
    }
    if (g_NetSvcProcess != NULL)
    {
        DWORD wait = WaitForSingleObject(g_NetSvcProcess, 5000);
        DWORD exitCode = STILL_ACTIVE;
        if (wait == WAIT_OBJECT_0)
        {
            (void)GetExitCodeProcess(g_NetSvcProcess, &exitCode);
            ControllerLog("[NETSVC] graceful stop completed pid=%lu exitCode=%lu\n", pid, exitCode);
        }
        else
        {
            DWORD waitErr = (wait == WAIT_FAILED) ? GetLastError() : ERROR_TIMEOUT;
            BOOL terminated;
            DWORD terminateErr;
            DWORD terminateWait;

            ControllerLog("[NETSVC][WARN] graceful stop wait failed pid=%lu wait=0x%08lX err=%lu; terminating\n", pid,
                          wait, waitErr);
            terminated = TerminateProcess(g_NetSvcProcess, 1);
            terminateErr = terminated ? ERROR_SUCCESS : GetLastError();
            terminateWait = WaitForSingleObject(g_NetSvcProcess, 2000);
            (void)GetExitCodeProcess(g_NetSvcProcess, &exitCode);
            ControllerLog(
                "[NETSVC][WARN] terminate result pid=%lu terminate=%u terminateErr=%lu wait=0x%08lX exitCode=%lu\n",
                pid, terminated ? 1u : 0u, terminateErr, terminateWait, exitCode);
        }
        CloseHandle(g_NetSvcProcess);
        g_NetSvcProcess = NULL;
    }
    if (g_NetSvcJob != NULL)
    {
        CloseHandle(g_NetSvcJob);
        g_NetSvcJob = NULL;
    }
    if (g_NetSvcStopEvent != NULL)
    {
        CloseHandle(g_NetSvcStopEvent);
        g_NetSvcStopEvent = NULL;
    }
    g_NetSvcPid = 0;
    g_NetSvcDriverHandle = NULL;
    g_NetSvcEndpointGuardArmed = FALSE;
    g_NetSvcStopEventName[0] = L'\0';
}

VOID ControllerRefreshNetSvcDriverHandle(_In_ HANDLE DriverHandle, _In_z_ PCSTR Reason)
{
    DWORD processId = g_NetSvcPid;
    BOOL wasArmed = g_NetSvcEndpointGuardArmed;

    if (DriverHandle == NULL || DriverHandle == INVALID_HANDLE_VALUE || processId == 0)
    {
        return;
    }

    g_NetSvcDriverHandle = DriverHandle;
    if (!wasArmed)
    {
        return;
    }

    if (ControllerSetNetSvcEndpointGuard(DriverHandle, processId, TRUE, Reason, NULL))
    {
        ControllerLog("[NETSVC] endpoint guard driver handle refreshed pid=%lu reason=%s driver=%p\n", processId,
                      Reason, DriverHandle);
        return;
    }

    ControllerLog("[NETSVC][WARN] endpoint guard refresh failed pid=%lu reason=%s err=%lu driver=%p\n", processId,
                  Reason, GetLastError(), DriverHandle);
}

BOOL ControllerStartNetService(_In_ HANDLE DriverHandle)
{
    WCHAR imagePath[MAX_PATH];
    WCHAR imageDirectory[MAX_PATH];
    WCHAR observedPath[MAX_PATH];
    WCHAR commandLine[MAX_PATH * 2];
    WCHAR stopEventName[128];
    STARTUPINFOEXW startupInfo = {0};
    PROCESS_INFORMATION processInfo = {0};
    PVOID attributeBuffer = NULL;
    HANDLE childLogHandle = INVALID_HANDLE_VALUE;
    HANDLE childInputHandle = INVALID_HANDLE_VALUE;
    DWORD attributes;
    DWORD creationFlags = 0;
    DWORD controllerSession = 0xFFFFFFFFu;
    DWORD activeConsoleSession = WTSGetActiveConsoleSessionId();
    BOOL protectionTemporarilyDisabled = FALSE;
    BOOL inheritHandles = FALSE;
    BOOL stdioRedirected = FALSE;
    BOOL endpointGuardReady = FALSE;
    BOOL endpointGuardUnsupported = FALSE;
    BOOL endpointGuardArmed = FALSE;

    if (DriverHandle == NULL || DriverHandle == INVALID_HANDLE_VALUE)
    {
        ControllerLog("[NETSVC][WARN] driver unavailable; refusing to start unprotected NetSvc\n");
        return FALSE;
    }
    if (!ControllerBuildSiblingPath(BK_NET_SERVICE_IMAGE_NAMEW, imagePath, RTL_NUMBER_OF(imagePath)))
    {
        ControllerLog("[NETSVC][WARN] failed to build NetSvc path err=%lu\n", GetLastError());
        return FALSE;
    }
    attributes = GetFileAttributesW(imagePath);
    if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
    {
        ControllerLog(
            "[NETSVC][INFO] optional NetSvc image absent; discovery/status/secure node sockets disabled path=%ws\n",
            imagePath);
        return FALSE;
    }
    if (!ControllerGetDirectoryFromPath(imagePath, imageDirectory, RTL_NUMBER_OF(imageDirectory)))
    {
        ControllerLog("[NETSVC][WARN] failed to derive working directory path=%ws err=%lu\n", imagePath,
                      GetLastError());
        return FALSE;
    }
    if (!ControllerRevertImpersonationForProcessCreate("NetSvc launch"))
    {
        return FALSE;
    }
    (void)ProcessIdToSessionId(GetCurrentProcessId(), &controllerSession);
    {
        BKSC_PROTOCOL_MODE protocolMode = BkscGetProtocolMode();
        ControllerLog(
            "[NETSVC] launch requested controllerPid=%lu controllerSession=%lu activeConsoleSession=%lu sensorProtocolMode=%lu(%s) image=%ws\n",
            GetCurrentProcessId(), controllerSession, activeConsoleSession, (DWORD)protocolMode,
            ControllerSensorProtocolModeName(protocolMode), imagePath);
    }

    /* The controller is a service-session parent for NetSvc. If controller protected-access was
       already forced by registry/runtime config, disable it until CreateProcessW finishes; otherwise
       the driver handle callbacks can strip access needed by the process manager and surface as
       ERROR_BAD_IMPERSONATION_LEVEL from CreateProcessW. NetSvc is still created suspended and is
       marked protected before it is resumed. */
    if (ControllerSetControllerProtectionRuntime(DriverHandle, FALSE, "netsvc-launch"))
    {
        protectionTemporarilyDisabled = TRUE;
    }

    if (FAILED(StringCchPrintfW(stopEventName, RTL_NUMBER_OF(stopEventName), L"Local\\BlackbirdNetSvcStop-%lu",
                                GetCurrentProcessId())))
    {
        if (protectionTemporarilyDisabled)
        {
            (void)ControllerSetControllerProtectionRuntime(DriverHandle, TRUE, "netsvc-launch-abort");
        }
        return FALSE;
    }
    g_NetSvcStopEvent = CreateEventW(NULL, TRUE, FALSE, stopEventName);
    if (g_NetSvcStopEvent == NULL)
    {
        ControllerLog("[NETSVC][WARN] stop event create failed err=%lu\n", GetLastError());
        if (protectionTemporarilyDisabled)
        {
            (void)ControllerSetControllerProtectionRuntime(DriverHandle, TRUE, "netsvc-launch-abort");
        }
        return FALSE;
    }
    (void)StringCchCopyW(g_NetSvcStopEventName, RTL_NUMBER_OF(g_NetSvcStopEventName), stopEventName);
    if (!ControllerBuildNetSvcCommandLine(imagePath, stopEventName, commandLine, RTL_NUMBER_OF(commandLine)))
    {
        if (protectionTemporarilyDisabled)
        {
            (void)ControllerSetControllerProtectionRuntime(DriverHandle, TRUE, "netsvc-launch-abort");
        }
        ControllerStopNetService();
        return FALSE;
    }

    if (!ControllerInitializeNetSvcStartupInfo(&startupInfo, &attributeBuffer, &creationFlags))
    {
        DWORD err = GetLastError();
        ControllerLog("[NETSVC][WARN] startup attribute setup failed err=%lu\n", err);
        if (protectionTemporarilyDisabled)
        {
            (void)ControllerSetControllerProtectionRuntime(DriverHandle, TRUE, "netsvc-launch-abort");
        }
        ControllerStopNetService();
        SetLastError(err);
        return FALSE;
    }

    childLogHandle = ControllerOpenNetSvcLogForChild();
    if (childLogHandle != INVALID_HANDLE_VALUE)
    {
        childInputHandle = ControllerOpenNetSvcNullInputForChild();
        startupInfo.StartupInfo.dwFlags |= STARTF_USESTDHANDLES;
        startupInfo.StartupInfo.hStdOutput = childLogHandle;
        startupInfo.StartupInfo.hStdError = childLogHandle;
        startupInfo.StartupInfo.hStdInput = (childInputHandle != INVALID_HANDLE_VALUE) ? childInputHandle : NULL;
        inheritHandles = TRUE;
        stdioRedirected = TRUE;
    }

    if (!CreateProcessW(imagePath, commandLine, NULL, NULL, inheritHandles, creationFlags, NULL, imageDirectory,
                        &startupInfo.StartupInfo, &processInfo))
    {
        DWORD err = GetLastError();
        CHAR message[256];
        ControllerFormatWin32Error(err, message, RTL_NUMBER_OF(message));
        ControllerLog(
            "[NETSVC][WARN] CreateProcessW failed path=%ws cwd=%ws flags=0x%08lX session=%lu inheritHandles=%u stdio=%u attrList=%u err=%lu (%s)\n",
            imagePath, imageDirectory, creationFlags, controllerSession, inheritHandles ? 1u : 0u,
            stdioRedirected ? 1u : 0u, startupInfo.lpAttributeList != NULL ? 1u : 0u, err, message);

        if (err == ERROR_INVALID_PARAMETER && startupInfo.lpAttributeList != NULL)
        {
            ControllerLog("[NETSVC][WARN] retrying CreateProcessW without creation mitigation attributes\n");
            ControllerReleaseNetSvcStartupAttributes(&startupInfo, &attributeBuffer, &creationFlags);
            if (!ControllerBuildNetSvcCommandLine(imagePath, stopEventName, commandLine, RTL_NUMBER_OF(commandLine)))
            {
                err = GetLastError();
            }
            else if (CreateProcessW(imagePath, commandLine, NULL, NULL, inheritHandles, creationFlags, NULL,
                                    imageDirectory, &startupInfo.StartupInfo, &processInfo))
            {
                err = ERROR_SUCCESS;
                ControllerLog(
                    "[NETSVC] CreateProcessW fallback succeeded without creation mitigation attributes flags=0x%08lX\n",
                    creationFlags);
            }
            else
            {
                err = GetLastError();
                ControllerFormatWin32Error(err, message, RTL_NUMBER_OF(message));
                ControllerLog(
                    "[NETSVC][WARN] CreateProcessW fallback without creation mitigation attributes failed flags=0x%08lX err=%lu (%s)\n",
                    creationFlags, err, message);
            }
        }

        if (err == ERROR_INVALID_PARAMETER && stdioRedirected)
        {
            ControllerLog("[NETSVC][WARN] retrying CreateProcessW without inherited stdio handles\n");
            startupInfo.StartupInfo.dwFlags &= ~STARTF_USESTDHANDLES;
            startupInfo.StartupInfo.hStdInput = NULL;
            startupInfo.StartupInfo.hStdOutput = NULL;
            startupInfo.StartupInfo.hStdError = NULL;
            inheritHandles = FALSE;
            stdioRedirected = FALSE;
            if (!ControllerBuildNetSvcCommandLine(imagePath, stopEventName, commandLine, RTL_NUMBER_OF(commandLine)))
            {
                err = GetLastError();
            }
            else if (CreateProcessW(imagePath, commandLine, NULL, NULL, inheritHandles, creationFlags, NULL,
                                    imageDirectory, &startupInfo.StartupInfo, &processInfo))
            {
                err = ERROR_SUCCESS;
                ControllerLog("[NETSVC] CreateProcessW fallback succeeded without stdio inheritance flags=0x%08lX\n",
                              creationFlags);
            }
            else
            {
                err = GetLastError();
                ControllerFormatWin32Error(err, message, RTL_NUMBER_OF(message));
                ControllerLog(
                    "[NETSVC][WARN] CreateProcessW fallback without stdio inheritance failed flags=0x%08lX err=%lu (%s)\n",
                    creationFlags, err, message);
            }
        }

        if (err != ERROR_SUCCESS)
        {
            ControllerReleaseNetSvcStartupAttributes(&startupInfo, &attributeBuffer, &creationFlags);
            if (childInputHandle != INVALID_HANDLE_VALUE)
            {
                CloseHandle(childInputHandle);
            }
            if (childLogHandle != INVALID_HANDLE_VALUE)
            {
                CloseHandle(childLogHandle);
            }
            ControllerStopNetService();
            if (protectionTemporarilyDisabled)
            {
                (void)ControllerSetControllerProtectionRuntime(DriverHandle, TRUE, "netsvc-launch-abort");
            }
            SetLastError(err);
            return FALSE;
        }

        if (childInputHandle != INVALID_HANDLE_VALUE)
        {
            CloseHandle(childInputHandle);
            childInputHandle = INVALID_HANDLE_VALUE;
        }
        if (childLogHandle != INVALID_HANDLE_VALUE)
        {
            CloseHandle(childLogHandle);
            childLogHandle = INVALID_HANDLE_VALUE;
        }
    }
    ControllerReleaseNetSvcStartupAttributes(&startupInfo, &attributeBuffer, &creationFlags);
    if (childInputHandle != INVALID_HANDLE_VALUE)
    {
        CloseHandle(childInputHandle);
        childInputHandle = INVALID_HANDLE_VALUE;
    }
    if (childLogHandle != INVALID_HANDLE_VALUE)
    {
        CloseHandle(childLogHandle);
        childLogHandle = INVALID_HANDLE_VALUE;
    }

    if (!ControllerQueryProcessImagePath(processInfo.hProcess, observedPath, RTL_NUMBER_OF(observedPath)) ||
        _wcsicmp(observedPath, imagePath) != 0)
    {
        ControllerLog("[NETSVC][WARN] image verification failed expected=%ws observed=%ws err=%lu\n", imagePath,
                      observedPath, GetLastError());
        TerminateProcess(processInfo.hProcess, 1);
        CloseHandle(processInfo.hThread);
        CloseHandle(processInfo.hProcess);
        ControllerStopNetService();
        if (protectionTemporarilyDisabled)
        {
            (void)ControllerSetControllerProtectionRuntime(DriverHandle, TRUE, "netsvc-launch-abort");
        }
        return FALSE;
    }
    {
        DWORD childSession = 0xFFFFFFFFu;
        if (!ProcessIdToSessionId(processInfo.dwProcessId, &childSession))
        {
            childSession = 0xFFFFFFFFu;
        }
        ControllerLog(
            "[NETSVC] created suspended pid=%lu childSession=%lu controllerSession=%lu inheritedHandles=%u cwd=%ws\n",
            processInfo.dwProcessId, childSession, controllerSession, inheritHandles ? 1u : 0u, imageDirectory);
        if (childSession != controllerSession)
        {
            ControllerLog("[NETSVC][WARN] child session mismatch pid=%lu childSession=%lu controllerSession=%lu\n",
                          processInfo.dwProcessId, childSession, controllerSession);
        }
    }

    if (!ControllerCreateNetSvcLifecycleJob(processInfo.hProcess, processInfo.dwProcessId))
    {
        DWORD err = GetLastError();
        TerminateProcess(processInfo.hProcess, 1);
        CloseHandle(processInfo.hThread);
        CloseHandle(processInfo.hProcess);
        ControllerStopNetService();
        if (protectionTemporarilyDisabled)
        {
            (void)ControllerSetControllerProtectionRuntime(DriverHandle, TRUE, "netsvc-launch-abort");
        }
        SetLastError(err);
        return FALSE;
    }

    if (!BkscMarkControllerReady(DriverHandle, processInfo.dwProcessId))
    {
        ControllerLog("[NETSVC][WARN] driver protection mark failed pid=%lu err=%lu\n", processInfo.dwProcessId,
                      GetLastError());
        TerminateProcess(processInfo.hProcess, 1);
        CloseHandle(processInfo.hThread);
        CloseHandle(processInfo.hProcess);
        ControllerStopNetService();
        if (protectionTemporarilyDisabled)
        {
            (void)ControllerSetControllerProtectionRuntime(DriverHandle, TRUE, "netsvc-launch-abort");
        }
        return FALSE;
    }

    if (protectionTemporarilyDisabled)
    {
        (void)ControllerSetControllerProtectionRuntime(DriverHandle, TRUE, "netsvc-launch-complete");
    }

    if (!ControllerEnsureBaseFilteringEngineReady("netsvc-launch"))
    {
        DWORD err = GetLastError();
        ControllerLog(
            "[NETSVC][WARN] endpoint guard dependency unavailable; WFP engine open may fail pid=%lu err=%lu\n",
            processInfo.dwProcessId, err);
    }

    if (!ControllerQueryEndpointGuardReady(DriverHandle, &endpointGuardReady) || !endpointGuardReady)
    {
        DWORD err = GetLastError();
        ControllerLog(
            "[NETSVC][WARN] endpoint guard unavailable before launch; continuing without ALE guard pid=%lu err=%lu\n",
            processInfo.dwProcessId, err);
    }

    if (ResumeThread(processInfo.hThread) == (DWORD)-1)
    {
        ControllerLog("[NETSVC][WARN] resume failed pid=%lu err=%lu\n", processInfo.dwProcessId, GetLastError());
        if (endpointGuardArmed)
        {
            (void)ControllerSetNetSvcEndpointGuard(DriverHandle, processInfo.dwProcessId, FALSE, "netsvc-resume-failed",
                                                   NULL);
        }
        TerminateProcess(processInfo.hProcess, 1);
        CloseHandle(processInfo.hThread);
        CloseHandle(processInfo.hProcess);
        ControllerStopNetService();
        return FALSE;
    }

    if (!ControllerWaitNetSvcEndpointsOnline(processInfo.hProcess, processInfo.dwProcessId, 15000))
    {
        DWORD err = GetLastError();
        ControllerLog("[NETSVC][WARN] network endpoints did not become ready pid=%lu err=%lu\n",
                      processInfo.dwProcessId, err);
        TerminateProcess(processInfo.hProcess, 1);
        CloseHandle(processInfo.hThread);
        CloseHandle(processInfo.hProcess);
        ControllerStopNetService();
        return FALSE;
    }

    if (endpointGuardReady && !ControllerSetNetSvcEndpointGuard(DriverHandle, processInfo.dwProcessId, TRUE,
                                                                "netsvc-listeners-online", &endpointGuardUnsupported))
    {
        DWORD err = GetLastError();
        if (endpointGuardUnsupported || ControllerIsEndpointGuardUnsupportedError(err))
        {
            ControllerLog(
                "[NETSVC][WARN] endpoint guard unsupported on current control path; continuing without ALE guard pid=%lu err=%lu\n",
                processInfo.dwProcessId, err);
        }
        else
        {
            ControllerLog("[NETSVC][WARN] endpoint guard arm failed after listeners online pid=%lu err=%lu\n",
                          processInfo.dwProcessId, err);
            TerminateProcess(processInfo.hProcess, 1);
            CloseHandle(processInfo.hThread);
            CloseHandle(processInfo.hProcess);
            ControllerStopNetService();
            return FALSE;
        }
    }
    else if (endpointGuardReady)
    {
        endpointGuardArmed = TRUE;
    }

    g_NetSvcProcess = processInfo.hProcess;
    g_NetSvcDriverHandle = DriverHandle;
    g_NetSvcPid = processInfo.dwProcessId;
    g_NetSvcEndpointGuardArmed = endpointGuardArmed;
    CloseHandle(processInfo.hThread);
    ControllerLog("[NETSVC] launched verified protected pid=%lu image=%ws\n", g_NetSvcPid, imagePath);
    return TRUE;
}
