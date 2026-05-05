#include "../controller_private.h"
#include "ipc_internal.h"

#include <wctype.h>

VOID ControllerClientClearPendingLaunchLocked(_Inout_ BK_CONTROLLER_CLIENT *Client)
{
    if (Client == NULL)
    {
        return;
    }

    Client->PendingLaunchArmed = FALSE;
    Client->PendingLaunchPid = 0;
    Client->PendingAnalysisSubjectKind = BlackbirdAnalysisSubjectProcess;
    Client->PendingLaunchArmedTick = 0;
    Client->PendingLaunchImagePath[0] = L'\0';
    Client->PendingAnalysisSubjectPath[0] = L'\0';
}

VOID ControllerClientArmPendingLaunchLocked(_Inout_ BK_CONTROLLER_CLIENT *Client, _In_opt_z_ PCWSTR ImagePath,
                                            _In_ DWORD AnalysisSubjectKind, _In_opt_z_ PCWSTR AnalysisSubjectPath)
{
    if (Client == NULL)
    {
        return;
    }

    ControllerClientClearPendingLaunchLocked(Client);
    if (ImagePath == NULL || ImagePath[0] == L'\0')
    {
        return;
    }

    (void)StringCchCopyW(Client->PendingLaunchImagePath, RTL_NUMBER_OF(Client->PendingLaunchImagePath), ImagePath);
    Client->PendingAnalysisSubjectKind = AnalysisSubjectKind;
    if (AnalysisSubjectKind == BlackbirdAnalysisSubjectDll && AnalysisSubjectPath != NULL &&
        AnalysisSubjectPath[0] != L'\0')
    {
        (void)StringCchCopyW(Client->PendingAnalysisSubjectPath, RTL_NUMBER_OF(Client->PendingAnalysisSubjectPath),
                             AnalysisSubjectPath);
    }
    Client->PendingLaunchArmed = TRUE;
    Client->PendingLaunchArmedTick = GetTickCount64();
}

VOID ControllerClientPrimePendingLaunchPidLocked(_Inout_ BK_CONTROLLER_CLIENT *Client, _In_ DWORD ProcessId)
{
    DWORD i;

    if (Client == NULL || ProcessId == 0)
    {
        return;
    }

    Client->PendingLaunchPid = ProcessId;
    Client->PendingLaunchArmed = FALSE;
    Client->PendingLaunchArmedTick = 0;

    for (i = 0; i < Client->SubscriptionCount; ++i)
    {
        if (Client->Subscriptions[i].ProcessId == ProcessId)
        {
            Client->Subscriptions[i].StreamMask |= BK_CONTROLLER_DRIVER_STREAM_MASK;
            if (Client->Subscriptions[i].Dynamic)
            {
                Client->Subscriptions[i].Dynamic = FALSE;
                Client->Subscriptions[i].Depth = 0;
                Client->Subscriptions[i].SourceProcessId = 0;
                Client->Subscriptions[i].LastSeenTick = 0;
            }
            ControllerMarkDriverSubscriptionsDirty();
            return;
        }
    }

    if (Client->SubscriptionCount >= BK_CONTROLLER_MAX_CLIENT_SUBSCRIPTIONS)
    {
        return;
    }

    Client->Subscriptions[Client->SubscriptionCount].ProcessId = ProcessId;
    Client->Subscriptions[Client->SubscriptionCount].StreamMask = BK_CONTROLLER_DRIVER_STREAM_MASK;
    Client->Subscriptions[Client->SubscriptionCount].Dynamic = FALSE;
    Client->Subscriptions[Client->SubscriptionCount].SourceProcessId = 0;
    Client->Subscriptions[Client->SubscriptionCount].Depth = 0;
    Client->Subscriptions[Client->SubscriptionCount].LastSeenTick = 0;
    Client->SubscriptionCount += 1;
    ControllerMarkDriverSubscriptionsDirty();
}

static VOID ControllerNormalizePathForCompare(_In_z_ const WCHAR *Input, _Out_writes_z_(OutputChars) WCHAR *Output,
                                              _In_ size_t OutputChars)
{
    size_t i;
    size_t j = 0;

    if (Output == NULL || OutputChars == 0)
    {
        return;
    }
    Output[0] = L'\0';

    if (Input == NULL)
    {
        return;
    }

    for (i = 0; Input[i] != L'\0' && (j + 1) < OutputChars; ++i)
    {
        WCHAR ch = Input[i];
        if (ch == L'/')
        {
            ch = L'\\';
        }
        Output[j++] = (WCHAR)towlower(ch);
    }
    Output[j] = L'\0';
}

static BOOL ControllerIsDrivePathW(_In_z_ const WCHAR *Path)
{
    if (Path == NULL)
    {
        return FALSE;
    }
    return (Path[0] != L'\0' && Path[1] == L':');
}

static VOID ControllerBuildTailFromDosPath(_In_z_ const WCHAR *DosPath, _Out_writes_z_(TailChars) WCHAR *Tail,
                                           _In_ size_t TailChars)
{
    WCHAR normalized[BK_MAX_IMAGE_PATH_CHARS];

    if (Tail == NULL || TailChars == 0)
    {
        return;
    }
    Tail[0] = L'\0';

    if (DosPath == NULL || !ControllerIsDrivePathW(DosPath) || DosPath[2] == L'\0')
    {
        return;
    }

    ControllerNormalizePathForCompare(DosPath + 2, normalized, RTL_NUMBER_OF(normalized));
    (void)StringCchCopyW(Tail, TailChars, normalized);
}

static BOOL ControllerBuildNtPathFromDosPath(_In_z_ const WCHAR *DosPath, _Out_writes_z_(NtChars) WCHAR *NtPath,
                                             _In_ size_t NtChars)
{
    WCHAR drive[3];
    WCHAR devicePrefix[BK_MAX_IMAGE_PATH_CHARS];

    if (NtPath != NULL && NtChars != 0)
    {
        NtPath[0] = L'\0';
    }

    if (DosPath == NULL || NtPath == NULL || NtChars == 0 || !ControllerIsDrivePathW(DosPath))
    {
        return FALSE;
    }

    drive[0] = (WCHAR)towupper(DosPath[0]);
    drive[1] = L':';
    drive[2] = L'\0';

    if (!QueryDosDeviceW(drive, devicePrefix, RTL_NUMBER_OF(devicePrefix)))
    {
        NtPath[0] = L'\0';
        return FALSE;
    }

    if (FAILED(StringCchPrintfW(NtPath, NtChars, L"%ls%ls", devicePrefix, DosPath + 2)))
    {
        NtPath[0] = L'\0';
        return FALSE;
    }

    return TRUE;
}

static VOID ControllerStripPathPrefixes(_Inout_updates_z_(BufferChars) WCHAR *Buffer, _In_ size_t BufferChars)
{
    size_t len;

    if (Buffer == NULL || BufferChars == 0)
    {
        return;
    }

    if (_wcsnicmp(Buffer, L"\\\\?\\", 4) == 0 || _wcsnicmp(Buffer, L"\\??\\", 4) == 0)
    {
        len = wcslen(Buffer);
        if (len > 4)
        {
            MoveMemory(Buffer, Buffer + 4, (len - 3) * sizeof(WCHAR));
        }
        else
        {
            Buffer[0] = L'\0';
        }
    }
}

BOOL ControllerBuildPendingLaunchRequest(_In_z_ PCWSTR ImagePath, _In_ DWORD AnalysisSubjectKind,
                                         _In_opt_z_ PCWSTR AnalysisSubjectPath, _In_ DWORD StreamMask,
                                         _Out_ BK_ARM_PENDING_LAUNCH_REQUEST *Request)
{
    WCHAR canonical[BK_MAX_IMAGE_PATH_CHARS];
    WCHAR ntPath[BK_MAX_IMAGE_PATH_CHARS];
    WCHAR effective[BK_MAX_IMAGE_PATH_CHARS];
    DWORD fullLen;

    if (ImagePath == NULL || ImagePath[0] == L'\0' || Request == NULL)
    {
        return FALSE;
    }

    ZeroMemory(Request, sizeof(*Request));
    ZeroMemory(canonical, sizeof(canonical));
    ZeroMemory(ntPath, sizeof(ntPath));
    ZeroMemory(effective, sizeof(effective));

    (void)StringCchCopyW(effective, RTL_NUMBER_OF(effective), ImagePath);
    ControllerStripPathPrefixes(effective, RTL_NUMBER_OF(effective));
    if (ControllerIsDrivePathW(effective))
    {
        fullLen = GetFullPathNameW(effective, RTL_NUMBER_OF(canonical), canonical, NULL);
        if (fullLen != 0 && fullLen < RTL_NUMBER_OF(canonical))
        {
            (void)StringCchCopyW(effective, RTL_NUMBER_OF(effective), canonical);
        }
    }

    Request->StreamMask = StreamMask;
    Request->AnalysisSubjectKind = AnalysisSubjectKind;
    ControllerNormalizePathForCompare(effective, Request->ImagePathNormDos, RTL_NUMBER_OF(Request->ImagePathNormDos));

    if (ControllerIsDrivePathW(effective))
    {
        ControllerBuildTailFromDosPath(effective, Request->ImagePathTail, RTL_NUMBER_OF(Request->ImagePathTail));
        if (ControllerBuildNtPathFromDosPath(effective, ntPath, RTL_NUMBER_OF(ntPath)))
        {
            ControllerNormalizePathForCompare(ntPath, Request->ImagePathNormNt,
                                              RTL_NUMBER_OF(Request->ImagePathNormNt));
        }
    }
    else if (_wcsnicmp(effective, L"\\device\\", 8) == 0 || _wcsnicmp(effective, L"\\systemroot\\", 12) == 0)
    {
        ControllerNormalizePathForCompare(effective, Request->ImagePathNormNt, RTL_NUMBER_OF(Request->ImagePathNormNt));
    }

    if (AnalysisSubjectKind == BlackbirdAnalysisSubjectDll && AnalysisSubjectPath != NULL &&
        AnalysisSubjectPath[0] != L'\0')
    {
        ZeroMemory(canonical, sizeof(canonical));
        ZeroMemory(ntPath, sizeof(ntPath));
        ZeroMemory(effective, sizeof(effective));
        (void)StringCchCopyW(effective, RTL_NUMBER_OF(effective), AnalysisSubjectPath);
        ControllerStripPathPrefixes(effective, RTL_NUMBER_OF(effective));
        if (ControllerIsDrivePathW(effective))
        {
            fullLen = GetFullPathNameW(effective, RTL_NUMBER_OF(canonical), canonical, NULL);
            if (fullLen != 0 && fullLen < RTL_NUMBER_OF(canonical))
            {
                (void)StringCchCopyW(effective, RTL_NUMBER_OF(effective), canonical);
            }
        }

        ControllerNormalizePathForCompare(effective, Request->AnalysisSubjectNormDos,
                                          RTL_NUMBER_OF(Request->AnalysisSubjectNormDos));
        if (ControllerIsDrivePathW(effective))
        {
            ControllerBuildTailFromDosPath(effective, Request->AnalysisSubjectTail,
                                           RTL_NUMBER_OF(Request->AnalysisSubjectTail));
            if (ControllerBuildNtPathFromDosPath(effective, ntPath, RTL_NUMBER_OF(ntPath)))
            {
                ControllerNormalizePathForCompare(ntPath, Request->AnalysisSubjectNormNt,
                                                  RTL_NUMBER_OF(Request->AnalysisSubjectNormNt));
            }
        }
        else if (_wcsnicmp(effective, L"\\device\\", 8) == 0 || _wcsnicmp(effective, L"\\systemroot\\", 12) == 0)
        {
            ControllerNormalizePathForCompare(effective, Request->AnalysisSubjectNormNt,
                                              RTL_NUMBER_OF(Request->AnalysisSubjectNormNt));
        }
    }

    return (Request->ImagePathNormDos[0] != L'\0' || Request->ImagePathNormNt[0] != L'\0' ||
            Request->ImagePathTail[0] != L'\0');
}

static DWORD ControllerQueryHookReadyMaskForProcess(_In_ DWORD ProcessId)
{
    PBK_CONTROLLER_CLIENT current;
    DWORD observedMask = 0;

    if (ProcessId == 0)
    {
        return 0;
    }

    EnterCriticalSection(g_ClientListLock.get());
    current = g_ClientList;
    while (current != NULL)
    {
        if (current->ProcessId == ProcessId)
        {
            observedMask |= (DWORD)InterlockedCompareExchange(&current->HookReadyMask, 0, 0);
        }
        current = current->Next;
    }
    LeaveCriticalSection(g_ClientListLock.get());

    return observedMask;
}

DWORD ControllerWaitForHookReady(_In_ DWORD ProcessId)
{
    static const DWORD kPollIntervalMs = 5u;
    static const ULONGLONG kLogPeriodMs = 1000ull;
    static const ULONGLONG kTimeoutMs = (ULONGLONG)BK_CONTROLLER_HOOK_READY_TIMEOUT_MS;
    static const DWORD kRequiredMask = BK_CONTROLLER_HOOK_LAUNCH_REQUIRED_MASK;
    HANDLE processHandle = NULL;
    DWORD readyMask = 0;
    ULONGLONG startTick;
    ULONGLONG lastLogTick;
    ULONGLONG now;

    if (ProcessId == 0)
    {
        return ERROR_INVALID_PARAMETER;
    }

    processHandle = OpenProcess(SYNCHRONIZE, FALSE, ProcessId);
    startTick = GetTickCount64();
    lastLogTick = startTick;

    for (;;)
    {
        readyMask = ControllerQueryHookReadyMaskForProcess(ProcessId);
        if ((readyMask & kRequiredMask) == kRequiredMask)
        {
            ULONGLONG elapsed = GetTickCount64() - startTick;
            ControllerLog("[IPC] hook-ready confirmed pid=%lu mask=0x%08lX elapsedMs=%llu\n", ProcessId, readyMask,
                          elapsed);
            if (processHandle != NULL)
            {
                CloseHandle(processHandle);
            }
            return ERROR_SUCCESS;
        }

        now = GetTickCount64();
        if (now - startTick >= kTimeoutMs)
        {
            ControllerLog("[IPC][WARN] hook-ready timed out pid=%lu mask=0x%08lX required=0x%08X elapsedMs=%llu\n",
                          ProcessId, readyMask, kRequiredMask, now - startTick);
            if (processHandle != NULL)
            {
                CloseHandle(processHandle);
            }
            return ERROR_TIMEOUT;
        }

        if (now - lastLogTick >= kLogPeriodMs)
        {
            ControllerLog("[IPC] waiting hook-ready pid=%lu mask=0x%08lX required=0x%08X elapsedMs=%llu\n", ProcessId,
                          readyMask, kRequiredMask, now - startTick);
            lastLogTick = now;
        }

        if (processHandle != NULL)
        {
            DWORD waitResult = WaitForSingleObject(processHandle, kPollIntervalMs);
            if (waitResult == WAIT_OBJECT_0)
            {
                DWORD exitCode = 0;
                (void)GetExitCodeProcess(processHandle, &exitCode);
                ControllerLog(
                    "[IPC][WARN] hook-ready aborted pid=%lu process exited before ready mask=0x%08lX exitCode=0x%08lX\n",
                    ProcessId, readyMask, exitCode);
                CloseHandle(processHandle);
                return ERROR_DLL_INIT_FAILED;
            }
        }
        else
        {
            Sleep(kPollIntervalMs);
        }
    }
}

DWORD ControllerEnsureCaptureReadyForLaunch(VOID)
{
    DWORD openErr = ERROR_SUCCESS;
    HANDLE localHandle = INVALID_HANDLE_VALUE;

    if (ControllerShouldStop())
    {
        return ERROR_SHUTDOWN_IN_PROGRESS;
    }
    if (g_EtwSession == NULL || g_EtwThread == NULL)
    {
        return ERROR_SERVICE_NOT_ACTIVE;
    }

    EnterCriticalSection(g_DriverLock.get());
    if (g_DriverHandle == INVALID_HANDLE_VALUE)
    {
        g_DriverHandle = BkscOpenControlDevice();
        if (g_DriverHandle == INVALID_HANDLE_VALUE)
        {
            openErr = GetLastError();
        }
    }
    localHandle = g_DriverHandle;
    LeaveCriticalSection(g_DriverLock.get());
    if (openErr != ERROR_SUCCESS)
    {
        return (openErr == ERROR_SUCCESS) ? ERROR_DEVICE_NOT_CONNECTED : openErr;
    }

    ControllerTryMarkProtectedReady(localHandle, TRUE);
    ControllerMarkDriverSubscriptionsDirty();
    return ERROR_SUCCESS;
}
