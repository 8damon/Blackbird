#include "internal.h"

BOOL ControllerInjectionAcquirePrimaryTokenFromProcess(_In_ DWORD ProcessId, _Out_ HANDLE *TokenOut)
{
    HANDLE processHandle = NULL;
    HANDLE token = NULL;
    HANDLE primaryToken = NULL;

    if (TokenOut == NULL || ProcessId == 0)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    *TokenOut = NULL;
    processHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, ProcessId);
    if (processHandle == NULL)
    {
        return FALSE;
    }

    if (!OpenProcessToken(processHandle,
                          TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT |
                              TOKEN_ADJUST_SESSIONID,
                          &token))
    {
        DWORD err = GetLastError();
        CloseHandle(processHandle);
        SetLastError(err);
        return FALSE;
    }

    if (!DuplicateTokenEx(
            token, TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID,
            NULL, SecurityImpersonation, TokenPrimary, &primaryToken))
    {
        DWORD err = GetLastError();
        CloseHandle(token);
        CloseHandle(processHandle);
        SetLastError(err);
        return FALSE;
    }

    CloseHandle(token);
    CloseHandle(processHandle);
    *TokenOut = primaryToken;
    return TRUE;
}

static BOOL ControllerInjectionDuplicateWtsUserToken(_In_ DWORD SessionId, _Out_ HANDLE *TokenOut)
{
    HANDLE userToken = NULL;
    HANDLE primaryToken = NULL;

    if (TokenOut == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    *TokenOut = NULL;
    if (SessionId == 0 || SessionId == 0xFFFFFFFFu)
    {
        SetLastError(ERROR_NO_TOKEN);
        return FALSE;
    }

    if (!WTSQueryUserToken(SessionId, &userToken))
    {
        return FALSE;
    }

    if (!DuplicateTokenEx(userToken,
                          TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT |
                              TOKEN_ADJUST_SESSIONID,
                          NULL, SecurityImpersonation, TokenPrimary, &primaryToken))
    {
        DWORD err = GetLastError();
        CloseHandle(userToken);
        SetLastError(err);
        return FALSE;
    }

    CloseHandle(userToken);
    *TokenOut = primaryToken;
    return TRUE;
}

BOOL ControllerInjectionAcquireActiveInteractiveUserToken(_Out_ HANDLE *TokenOut, _Out_opt_ DWORD *SessionIdOut)
{
    DWORD consoleSessionId = WTSGetActiveConsoleSessionId();
    WTS_SESSION_INFOW *sessions = NULL;
    DWORD sessionCount = 0;
    DWORD lastErr = ERROR_NO_TOKEN;

    if (TokenOut == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    *TokenOut = NULL;
    if (SessionIdOut != NULL)
    {
        *SessionIdOut = 0;
    }

    if (consoleSessionId != 0 && consoleSessionId != 0xFFFFFFFFu)
    {
        if (ControllerInjectionDuplicateWtsUserToken(consoleSessionId, TokenOut))
        {
            if (SessionIdOut != NULL)
            {
                *SessionIdOut = consoleSessionId;
            }
            return TRUE;
        }
        lastErr = GetLastError();
    }

    if (!WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &sessions, &sessionCount))
    {
        DWORD err = GetLastError();
        SetLastError(err == ERROR_SUCCESS ? lastErr : err);
        return FALSE;
    }

    for (DWORD i = 0; i < sessionCount; ++i)
    {
        DWORD sessionId = sessions[i].SessionId;
        if (sessions[i].State != WTSActive || sessionId == 0 || sessionId == consoleSessionId)
        {
            continue;
        }

        if (ControllerInjectionDuplicateWtsUserToken(sessionId, TokenOut))
        {
            if (SessionIdOut != NULL)
            {
                *SessionIdOut = sessionId;
            }
            WTSFreeMemory(sessions);
            return TRUE;
        }
        lastErr = GetLastError();
    }

    WTSFreeMemory(sessions);
    SetLastError(lastErr == ERROR_SUCCESS ? ERROR_NO_TOKEN : lastErr);
    return FALSE;
}

static DWORD ControllerInjectionIntegrityRid(_In_ UINT32 IntegrityLevel)
{
    switch (IntegrityLevel)
    {
    case BK_LAUNCH_INTEGRITY_UNTRUSTED:
        return SECURITY_MANDATORY_UNTRUSTED_RID;
    case BK_LAUNCH_INTEGRITY_LOW:
        return SECURITY_MANDATORY_LOW_RID;
    case BK_LAUNCH_INTEGRITY_MEDIUM:
        return SECURITY_MANDATORY_MEDIUM_RID;
    case BK_LAUNCH_INTEGRITY_HIGH:
        return SECURITY_MANDATORY_HIGH_RID;
    case BK_LAUNCH_INTEGRITY_SYSTEM:
        return SECURITY_MANDATORY_SYSTEM_RID;
    default:
        return 0;
    }
}

BOOL ControllerInjectionApplyRequestedIntegrity(_In_ HANDLE TokenHandle, _In_ UINT32 IntegrityLevel)
{
    SID_IDENTIFIER_AUTHORITY authority = SECURITY_MANDATORY_LABEL_AUTHORITY;
    PSID integritySid = NULL;
    TOKEN_MANDATORY_LABEL label;
    DWORD integrityRid = ControllerInjectionIntegrityRid(IntegrityLevel);
    BOOL success;

    if (IntegrityLevel == BK_LAUNCH_INTEGRITY_DEFAULT)
    {
        return TRUE;
    }
    if (TokenHandle == NULL || TokenHandle == INVALID_HANDLE_VALUE || integrityRid == 0)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    if (!AllocateAndInitializeSid(&authority, 1, integrityRid, 0, 0, 0, 0, 0, 0, 0, &integritySid))
    {
        return FALSE;
    }

    ZeroMemory(&label, sizeof(label));
    label.Label.Attributes = SE_GROUP_INTEGRITY;
    label.Label.Sid = integritySid;
    success = SetTokenInformation(TokenHandle, TokenIntegrityLevel, &label, sizeof(label) + GetLengthSid(integritySid));
    if (!success)
    {
        DWORD err = GetLastError();
        FreeSid(integritySid);
        SetLastError(err);
        return FALSE;
    }

    FreeSid(integritySid);
    return TRUE;
}

BOOL ControllerInjectionEnablePrivilege(_In_z_ PCWSTR PrivilegeName)
{
    HANDLE token = NULL;
    TOKEN_PRIVILEGES privileges;
    LUID luid;
    DWORD err;

    if (PrivilegeName == NULL || PrivilegeName[0] == L'\0')
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
    {
        return FALSE;
    }

    if (!LookupPrivilegeValueW(NULL, PrivilegeName, &luid))
    {
        err = GetLastError();
        CloseHandle(token);
        SetLastError(err);
        return FALSE;
    }

    ZeroMemory(&privileges, sizeof(privileges));
    privileges.PrivilegeCount = 1;
    privileges.Privileges[0].Luid = luid;
    privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(token, FALSE, &privileges, sizeof(privileges), NULL, NULL))
    {
        err = GetLastError();
        CloseHandle(token);
        SetLastError(err);
        return FALSE;
    }

    err = GetLastError();
    CloseHandle(token);
    if (err == ERROR_NOT_ALL_ASSIGNED)
    {
        SetLastError(err);
        return FALSE;
    }

    SetLastError(ERROR_SUCCESS);
    return TRUE;
}

BOOL ControllerInjectionQueryPipeClientSession(_In_ HANDLE PipeHandle, _Out_opt_ DWORD *ClientProcessIdOut,
                                               _Out_ DWORD *SessionIdOut)
{
    DWORD clientPid = 0;
    DWORD sessionId = 0;

    if (SessionIdOut == NULL || PipeHandle == NULL || PipeHandle == INVALID_HANDLE_VALUE)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    *SessionIdOut = 0;
    if (ClientProcessIdOut != NULL)
    {
        *ClientProcessIdOut = 0;
    }

    if (!GetNamedPipeClientSessionId(PipeHandle, &sessionId))
    {
        return FALSE;
    }

    if (ClientProcessIdOut != NULL)
    {
        if (GetNamedPipeClientProcessId(PipeHandle, &clientPid))
        {
            *ClientProcessIdOut = clientPid;
        }
    }
    *SessionIdOut = sessionId;
    return TRUE;
}

static BOOL ControllerInjectionQueryTokenSession(_In_ HANDLE TokenHandle, _Out_ DWORD *SessionIdOut)
{
    DWORD sessionId = 0;
    DWORD bytesReturned = 0;

    if (TokenHandle == NULL || TokenHandle == INVALID_HANDLE_VALUE || SessionIdOut == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    if (!GetTokenInformation(TokenHandle, TokenSessionId, &sessionId, sizeof(sessionId), &bytesReturned))
    {
        return FALSE;
    }

    *SessionIdOut = sessionId;
    return TRUE;
}

BOOL ControllerInjectionEnsureTokenSession(_In_ HANDLE TokenHandle, _In_ DWORD DesiredSessionId,
                                           _Out_opt_ DWORD *OriginalSessionIdOut, _Out_opt_ DWORD *TokenSessionIdOut)
{
    DWORD tokenSessionId = 0;

    if (OriginalSessionIdOut != NULL)
    {
        *OriginalSessionIdOut = 0;
    }
    if (TokenSessionIdOut != NULL)
    {
        *TokenSessionIdOut = 0;
    }
    if (!ControllerInjectionQueryTokenSession(TokenHandle, &tokenSessionId))
    {
        return FALSE;
    }
    if (OriginalSessionIdOut != NULL)
    {
        *OriginalSessionIdOut = tokenSessionId;
    }

    if (tokenSessionId != DesiredSessionId)
    {
        DWORD desired = DesiredSessionId;
        if (!SetTokenInformation(TokenHandle, TokenSessionId, &desired, sizeof(desired)))
        {
            return FALSE;
        }
        tokenSessionId = desired;
    }

    if (TokenSessionIdOut != NULL)
    {
        *TokenSessionIdOut = tokenSessionId;
    }
    return TRUE;
}
