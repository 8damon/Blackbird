#include "../controller_private.h"
#include "ipc_internal.h"

static DWORD ControllerClampSharedRingCapacity(_In_ DWORD Desired, _In_ DWORD DefaultValue, _In_ DWORD MaxValue)
{
    if (Desired == 0)
    {
        return DefaultValue;
    }
    if (Desired > MaxValue)
    {
        return MaxValue;
    }
    if (Desired < 64)
    {
        return 64;
    }
    return Desired;
}

_Success_(return) static BOOL ControllerCreateSharedRing(_In_ DWORD Capacity, _In_ DWORD RecordSize,
                                                         _Out_ HANDLE *MappingHandle, _Out_ HANDLE *DataReadyEvent,
                                                         _Out_ PBKIPC_SHARED_RING_HEADER *Header, _Out_ PBYTE *Records)
{
    SIZE_T totalBytes;
    HANDLE mapping;
    PBYTE view;
    HANDLE ready;
    PBKIPC_SHARED_RING_HEADER hdr;

    if (MappingHandle != NULL)
    {
        *MappingHandle = NULL;
    }
    if (DataReadyEvent != NULL)
    {
        *DataReadyEvent = NULL;
    }
    if (Header != NULL)
    {
        *Header = NULL;
    }
    if (Records != NULL)
    {
        *Records = NULL;
    }

    if (MappingHandle == NULL || DataReadyEvent == NULL || Header == NULL || Records == NULL || Capacity == 0 ||
        RecordSize == 0)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    totalBytes = sizeof(*hdr) + ((SIZE_T)Capacity * (SIZE_T)RecordSize);
    mapping = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, (DWORD)((ULONGLONG)totalBytes >> 32),
                                 (DWORD)(totalBytes & 0xFFFFFFFFu), NULL);
    if (mapping == NULL)
    {
        return FALSE;
    }

    view = (PBYTE)MapViewOfFile(mapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, totalBytes);
    if (view == NULL)
    {
        DWORD err = GetLastError();
        (void)CloseHandle(mapping);
        SetLastError(err);
        return FALSE;
    }

    ready = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (ready == NULL)
    {
        DWORD err = GetLastError();
        (void)UnmapViewOfFile(view);
        (void)CloseHandle(mapping);
        SetLastError(err);
        return FALSE;
    }

    hdr = (PBKIPC_SHARED_RING_HEADER)view;
    ZeroMemory(hdr, sizeof(*hdr));
    hdr->Capacity = Capacity;
    hdr->RecordSize = RecordSize;

    *MappingHandle = mapping;
    *DataReadyEvent = ready;
    *Header = hdr;
    *Records = view + sizeof(*hdr);
    return TRUE;
}

static DWORD ControllerClientEnsureSharedRingsLocked(_Inout_ BK_CONTROLLER_CLIENT *Client,
                                                     _In_ DWORD DesiredIoctlCapacity, _In_ DWORD DesiredEtwCapacity)
{
    DWORD ioctlCap;
    DWORD etwCap;

    if (Client == NULL)
    {
        return ERROR_INVALID_PARAMETER;
    }

    if (Client->IoctlSharedHeader != NULL && Client->EtwSharedHeader != NULL && Client->IoctlSharedDataEvent != NULL &&
        Client->EtwSharedDataEvent != NULL)
    {
        return ERROR_SUCCESS;
    }

    ioctlCap =
        ControllerClampSharedRingCapacity(DesiredIoctlCapacity, BK_CONTROLLER_SHARED_IOCTL_RING_CAPACITY, 1048576);
    etwCap = ControllerClampSharedRingCapacity(DesiredEtwCapacity, BK_CONTROLLER_SHARED_ETW_RING_CAPACITY, 262144);

    if (!ControllerCreateSharedRing(ioctlCap, sizeof(BK_EVENT_RECORD), &Client->IoctlSharedMapping,
                                    &Client->IoctlSharedDataEvent, &Client->IoctlSharedHeader,
                                    &Client->IoctlSharedRecords))
    {
        return GetLastError();
    }

    if (!ControllerCreateSharedRing(etwCap, sizeof(BKIPC_ETW_EVENT), &Client->EtwSharedMapping,
                                    &Client->EtwSharedDataEvent, &Client->EtwSharedHeader, &Client->EtwSharedRecords))
    {
        DWORD err = GetLastError();
        ControllerClientDestroySharedRingsLocked(Client);
        return err;
    }

    return ERROR_SUCCESS;
}

static VOID ControllerCloseRemoteHandle(_In_ HANDLE ClientProcess, _Inout_ HANDLE *RemoteHandle)
{
    HANDLE localHandle = NULL;

    if (ClientProcess == NULL || ClientProcess == INVALID_HANDLE_VALUE || RemoteHandle == NULL ||
        *RemoteHandle == NULL || *RemoteHandle == INVALID_HANDLE_VALUE)
    {
        return;
    }

    if (DuplicateHandle(ClientProcess, *RemoteHandle, GetCurrentProcess(), &localHandle, 0, FALSE,
                        DUPLICATE_SAME_ACCESS | DUPLICATE_CLOSE_SOURCE))
    {
        if (localHandle != NULL && localHandle != INVALID_HANDLE_VALUE)
        {
            (void)CloseHandle(localHandle);
        }
    }

    *RemoteHandle = NULL;
}

DWORD ControllerClientOpenSharedRing(_Inout_ BK_CONTROLLER_CLIENT *Client,
                                     _In_ const BKIPC_OPEN_SHARED_RING_REQUEST *Request,
                                     _Out_ BKIPC_OPEN_SHARED_RING_RESPONSE *Response)
{
    DWORD err;
    HANDLE clientProcess = NULL;
    HANDLE ioctlMapDup = NULL;
    HANDLE ioctlEventDup = NULL;
    HANDLE etwMapDup = NULL;
    HANDLE etwEventDup = NULL;

    if (Client == NULL || Request == NULL || Response == NULL || Client->ProcessId == 0)
    {
        return ERROR_INVALID_PARAMETER;
    }

    ZeroMemory(Response, sizeof(*Response));
    EnterCriticalSection(&Client->Lock);
    err = ControllerClientEnsureSharedRingsLocked(Client, Request->DesiredIoctlCapacity, Request->DesiredEtwCapacity);
    if (err != ERROR_SUCCESS)
    {
        LeaveCriticalSection(&Client->Lock);
        return err;
    }

    clientProcess = OpenProcess(PROCESS_DUP_HANDLE, FALSE, Client->ProcessId);
    if (clientProcess == NULL)
    {
        err = GetLastError();
        LeaveCriticalSection(&Client->Lock);
        return err;
    }

    if (!DuplicateHandle(GetCurrentProcess(), Client->IoctlSharedMapping, clientProcess, &ioctlMapDup, 0, FALSE,
                         DUPLICATE_SAME_ACCESS) ||
        !DuplicateHandle(GetCurrentProcess(), Client->IoctlSharedDataEvent, clientProcess, &ioctlEventDup, 0, FALSE,
                         DUPLICATE_SAME_ACCESS) ||
        !DuplicateHandle(GetCurrentProcess(), Client->EtwSharedMapping, clientProcess, &etwMapDup, 0, FALSE,
                         DUPLICATE_SAME_ACCESS) ||
        !DuplicateHandle(GetCurrentProcess(), Client->EtwSharedDataEvent, clientProcess, &etwEventDup, 0, FALSE,
                         DUPLICATE_SAME_ACCESS))
    {
        err = GetLastError();
        ControllerCloseRemoteHandle(clientProcess, &ioctlMapDup);
        ControllerCloseRemoteHandle(clientProcess, &ioctlEventDup);
        ControllerCloseRemoteHandle(clientProcess, &etwMapDup);
        ControllerCloseRemoteHandle(clientProcess, &etwEventDup);
        LeaveCriticalSection(&Client->Lock);
        (void)CloseHandle(clientProcess);
        return err;
    }

    ZeroMemory(Response, sizeof(*Response));
    Response->IoctlMappingHandle = (UINT64)(ULONG_PTR)ioctlMapDup;
    Response->IoctlDataReadyEventHandle = (UINT64)(ULONG_PTR)ioctlEventDup;
    Response->IoctlCapacity = Client->IoctlSharedHeader->Capacity;
    Response->IoctlRecordSize = Client->IoctlSharedHeader->RecordSize;
    Response->EtwMappingHandle = (UINT64)(ULONG_PTR)etwMapDup;
    Response->EtwDataReadyEventHandle = (UINT64)(ULONG_PTR)etwEventDup;
    Response->EtwCapacity = Client->EtwSharedHeader->Capacity;
    Response->EtwRecordSize = Client->EtwSharedHeader->RecordSize;
    Client->SharedRingEnabled = TRUE;
    LeaveCriticalSection(&Client->Lock);

    (void)CloseHandle(clientProcess);
    return ERROR_SUCCESS;
}

_Success_(return) static BOOL ControllerCheckTokenMembershipRid(_In_ HANDLE Token, _In_ DWORD Rid, _Out_ BOOL *IsMember)
{
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    PSID sid = NULL;
    BOOL isMember = FALSE;

    if (Token == NULL || Token == INVALID_HANDLE_VALUE || IsMember == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    *IsMember = FALSE;
    if (!AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, Rid, 0, 0, 0, 0, 0, 0, &sid))
    {
        return FALSE;
    }

    if (!CheckTokenMembership(Token, sid, &isMember))
    {
        DWORD err = GetLastError();
        FreeSid(sid);
        SetLastError(err);
        return FALSE;
    }

    FreeSid(sid);
    *IsMember = isMember;
    return TRUE;
}

_Success_(return) static BOOL ControllerCheckTokenIsLocalSystem(_In_ HANDLE Token, _Out_ BOOL *IsSystem)
{
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    PSID systemSid = NULL;
    BOOL isSystem = FALSE;

    if (Token == NULL || Token == INVALID_HANDLE_VALUE || IsSystem == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    *IsSystem = FALSE;
    if (!AllocateAndInitializeSid(&ntAuthority, 1, SECURITY_LOCAL_SYSTEM_RID, 0, 0, 0, 0, 0, 0, 0, &systemSid))
    {
        return FALSE;
    }

    if (!CheckTokenMembership(Token, systemSid, &isSystem))
    {
        DWORD err = GetLastError();
        FreeSid(systemSid);
        SetLastError(err);
        return FALSE;
    }

    FreeSid(systemSid);
    *IsSystem = isSystem;
    return TRUE;
}

BOOL ControllerClientIsPrivileged(_In_ const BK_CONTROLLER_CLIENT *Client, _Out_ BOOL *IsPrivileged)
{
    HANDLE process = NULL;
    HANDLE token = NULL;
    BOOL isAdmin = FALSE;
    BOOL isSystem = FALSE;

    if (Client == NULL || IsPrivileged == NULL || Client->ProcessId == 0)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    *IsPrivileged = FALSE;
    process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, Client->ProcessId);
    if (process == NULL)
    {
        return FALSE;
    }

    if (!OpenProcessToken(process, TOKEN_QUERY | TOKEN_DUPLICATE, &token))
    {
        DWORD err = GetLastError();
        CloseHandle(process);
        SetLastError(err);
        return FALSE;
    }

    if (!ControllerCheckTokenMembershipRid(token, DOMAIN_ALIAS_RID_ADMINS, &isAdmin))
    {
        DWORD err = GetLastError();
        CloseHandle(token);
        CloseHandle(process);
        SetLastError(err);
        return FALSE;
    }

    if (!ControllerCheckTokenIsLocalSystem(token, &isSystem))
    {
        DWORD err = GetLastError();
        CloseHandle(token);
        CloseHandle(process);
        SetLastError(err);
        return FALSE;
    }

    CloseHandle(token);
    CloseHandle(process);
    *IsPrivileged = (isAdmin || isSystem);
    return TRUE;
}
