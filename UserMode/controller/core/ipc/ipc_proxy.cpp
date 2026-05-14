#include "../controller_private.h"
#include "ipc_internal.h"

static BOOL ControllerOpenDriverProxyHandle(_Out_ HANDLE *OutHandle, _In_z_ PCSTR Operation)
{
    HANDLE localHandle = INVALID_HANDLE_VALUE;
    DWORD err = ERROR_SUCCESS;
    BOOL lockHeld = FALSE;

    if (OutHandle == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    *OutHandle = INVALID_HANDLE_VALUE;

    if (TryEnterCriticalSection(g_DriverLock.get()))
    {
        lockHeld = TRUE;
        if (g_DriverHandle != INVALID_HANDLE_VALUE)
        {
            HANDLE currentProcess = GetCurrentProcess();
            if (!DuplicateHandle(currentProcess, g_DriverHandle, currentProcess, &localHandle, 0, FALSE,
                                 DUPLICATE_SAME_ACCESS))
            {
                err = GetLastError();
                localHandle = INVALID_HANDLE_VALUE;
            }
        }
    }
    else
    {
        err = ERROR_BUSY;
        ControllerLog("[DRIVER][WARN] driver handle lock busy op=%s; opening transient handle\n", Operation);
    }

    if (lockHeld)
    {
        LeaveCriticalSection(g_DriverLock.get());
    }

    if (localHandle == INVALID_HANDLE_VALUE)
    {
        HANDLE transient = BkscOpenControlDevice();
        if (transient != INVALID_HANDLE_VALUE)
        {
            localHandle = transient;
            err = ERROR_SUCCESS;
            ControllerLog("[DRIVER] transient driver handle opened op=%s\n", Operation);
        }
        else if (err == ERROR_SUCCESS)
        {
            err = GetLastError();
            if (err == ERROR_SUCCESS)
            {
                err = ERROR_DEVICE_NOT_CONNECTED;
            }
        }
    }

    if (localHandle == INVALID_HANDLE_VALUE)
    {
        SetLastError(err == ERROR_SUCCESS ? ERROR_DEVICE_NOT_CONNECTED : err);
        return FALSE;
    }

    *OutHandle = localHandle;
    return TRUE;
}

static VOID ControllerCloseDriverProxyHandle(_In_ HANDLE Handle)
{
    if (Handle != NULL && Handle != INVALID_HANDLE_VALUE)
    {
        CloseHandle(Handle);
    }
}

BOOL ControllerProxyDriverConnected(VOID)
{
    HANDLE handle = INVALID_HANDLE_VALUE;
    BOOL ok = ControllerOpenDriverProxyHandle(&handle, "driver-connected");
    ControllerCloseDriverProxyHandle(handle);
    return ok;
}

BOOL ControllerProxyQueryProcessImage(_In_ DWORD ProcessId, _Out_ BK_QUERY_PROCESS_IMAGE_RESPONSE *Response)
{
    WCHAR imagePath[BK_MAX_IMAGE_PATH_CHARS];
    HANDLE handle = INVALID_HANDLE_VALUE;
    BOOL ok;
    DWORD err;

    if (Response == NULL || ProcessId == 0)
    {
        return FALSE;
    }

    ZeroMemory(Response, sizeof(*Response));
    Response->ProcessId = ProcessId;
    imagePath[0] = L'\0';

    ok = ControllerOpenDriverProxyHandle(&handle, "query-process-image") &&
         BkscQueryProcessImagePath(handle, ProcessId, imagePath, RTL_NUMBER_OF(imagePath));
    err = ok ? ERROR_SUCCESS : GetLastError();
    ControllerCloseDriverProxyHandle(handle);

    if (!ok)
    {
        Response->Status = (INT32)HRESULT_FROM_WIN32(err);
        SetLastError(err);
        return FALSE;
    }

    Response->Status = 0;
    (void)StringCchCopyW(Response->ImagePath, RTL_NUMBER_OF(Response->ImagePath), imagePath);
    return TRUE;
}

BOOL ControllerProxySetShutdownMode(VOID)
{
    HANDLE handle = INVALID_HANDLE_VALUE;
    BOOL ok;
    DWORD err;

    ok = ControllerOpenDriverProxyHandle(&handle, "set-shutdown-mode") && BkscSetShutdownMode(handle);
    err = ok ? ERROR_SUCCESS : GetLastError();
    ControllerCloseDriverProxyHandle(handle);
    if (!ok)
    {
        SetLastError(err);
    }
    return ok;
}

BOOL ControllerProxyControlProcessExecution(_In_ DWORD ProcessId, _In_ BOOL Suspend)
{
    HANDLE handle = INVALID_HANDLE_VALUE;
    BOOL ok;
    DWORD err;

    ok = ControllerOpenDriverProxyHandle(&handle, "control-process-execution") &&
         BkscControlProcessExecution(handle, ProcessId, Suspend);
    err = ok ? ERROR_SUCCESS : GetLastError();
    ControllerCloseDriverProxyHandle(handle);

    if (!ok)
    {
        SetLastError(err);
        return FALSE;
    }

    return ok;
}

BOOL ControllerProxySetRuntimeConfig(_In_ DWORD Flags, _In_ DWORD Mask)
{
    HANDLE handle = INVALID_HANDLE_VALUE;
    BOOL ok;
    DWORD err;
    ULONGLONG startTick = GetTickCount64();

    ok = ControllerOpenDriverProxyHandle(&handle, "set-runtime-config") && BkscSetRuntimeConfig(handle, Flags, Mask);
    err = ok ? ERROR_SUCCESS : GetLastError();
    ControllerCloseDriverProxyHandle(handle);
    if (!ok || (GetTickCount64() - startTick) >= 500)
    {
        ControllerLog("[DRIVER]%s set-runtime-config flags=0x%08lX mask=0x%08lX elapsedMs=%llu err=%lu\n",
                      ok ? "" : "[WARN]", Flags, Mask, (unsigned long long)(GetTickCount64() - startTick), err);
    }
    if (!ok)
    {
        SetLastError(err);
    }
    return ok;
}

BOOL ControllerProxyGetRuntimeConfig(_Out_ BK_RUNTIME_CONFIG_RESPONSE *Response)
{
    HANDLE handle = INVALID_HANDLE_VALUE;
    BOOL ok;
    DWORD err;

    if (Response == NULL)
    {
        return FALSE;
    }

    ZeroMemory(Response, sizeof(*Response));
    ok = ControllerOpenDriverProxyHandle(&handle, "get-runtime-config") && BkscGetRuntimeConfig(handle, Response);
    err = ok ? ERROR_SUCCESS : GetLastError();
    ControllerCloseDriverProxyHandle(handle);
    if (!ok)
    {
        SetLastError(err);
    }
    return ok;
}

BOOL ControllerProxyArmPendingLaunch(_In_ const BK_ARM_PENDING_LAUNCH_REQUEST *Request)
{
    HANDLE handle = INVALID_HANDLE_VALUE;
    BOOL ok;
    DWORD err;

    if (Request == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    ok = ControllerOpenDriverProxyHandle(&handle, "arm-pending-launch") && BkscArmPendingLaunch(handle, Request);
    err = ok ? ERROR_SUCCESS : GetLastError();
    ControllerCloseDriverProxyHandle(handle);
    if (!ok)
    {
        SetLastError(err);
    }
    return ok;
}

BOOL ControllerProxySetQpcTimingConfig(_In_ const BK_QPC_TIMING_CONFIG *Config)
{
    HANDLE handle = INVALID_HANDLE_VALUE;
    BOOL ok;
    DWORD err;

    if (Config == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    ok = ControllerOpenDriverProxyHandle(&handle, "set-qpc-timing-config") && BkscSetQpcTimingConfig(handle, Config);
    err = ok ? ERROR_SUCCESS : GetLastError();
    ControllerCloseDriverProxyHandle(handle);
    if (!ok)
    {
        SetLastError(err);
    }
    return ok;
}

BOOL ControllerProxyGetQpcTimingState(_Out_ BK_QPC_TIMING_STATE *State)
{
    HANDLE handle = INVALID_HANDLE_VALUE;
    BOOL ok;
    DWORD err;

    if (State == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    ZeroMemory(State, sizeof(*State));
    ok = ControllerOpenDriverProxyHandle(&handle, "get-qpc-timing-state") && BkscGetQpcTimingState(handle, State);
    err = ok ? ERROR_SUCCESS : GetLastError();
    ControllerCloseDriverProxyHandle(handle);
    if (!ok)
    {
        SetLastError(err);
    }
    return ok;
}

BOOL ControllerProxyGetHealth(_Out_ BK_HEALTH_RESPONSE *Response)
{
    HANDLE handle = INVALID_HANDLE_VALUE;
    BOOL ok;
    DWORD bytes = 0;
    DWORD err;

    if (Response == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    ZeroMemory(Response, sizeof(*Response));
    ok = ControllerOpenDriverProxyHandle(&handle, "get-health") && BkscGetHealth(handle, Response, &bytes);
    err = ok ? ERROR_SUCCESS : GetLastError();
    ControllerCloseDriverProxyHandle(handle);
    if (!ok)
    {
        SetLastError(err);
    }
    return ok;
}

BOOL ControllerProxyGetDiagnostics(_Out_ BK_DIAGNOSTICS_RESPONSE *Response)
{
    HANDLE handle = INVALID_HANDLE_VALUE;
    BOOL ok;
    DWORD bytes = 0;
    DWORD err;

    if (Response == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    ZeroMemory(Response, sizeof(*Response));
    ok = ControllerOpenDriverProxyHandle(&handle, "get-diagnostics") && BkscGetDiagnostics(handle, Response, &bytes);
    err = ok ? ERROR_SUCCESS : GetLastError();
    ControllerCloseDriverProxyHandle(handle);
    if (!ok)
    {
        SetLastError(err);
    }
    return ok;
}

BOOL ControllerProxyRegisterInstrumentationRange(_In_ DWORD ProcessId, _In_ UINT64 BaseAddress, _In_ UINT64 RegionSize,
                                                 _In_ UINT32 Flags, _In_opt_z_ PCSTR Tag)
{
    BK_REGISTER_INSTRUMENTATION_RANGE_REQUEST req;
    HANDLE handle = INVALID_HANDLE_VALUE;
    BOOL ok;
    DWORD err;

    if (ProcessId == 0 || BaseAddress == 0 || RegionSize == 0)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    ZeroMemory(&req, sizeof(req));
    req.ProcessId = ProcessId;
    req.BaseAddress = BaseAddress;
    req.RegionSize = RegionSize;
    req.Flags = Flags;
    if (Tag != NULL)
    {
        (void)StringCchCopyA(req.Tag, RTL_NUMBER_OF(req.Tag), Tag);
    }

    ok = ControllerOpenDriverProxyHandle(&handle, "register-instrumentation-range") &&
         BkscRegisterInstrumentationRange(handle, &req);
    err = ok ? ERROR_SUCCESS : GetLastError();
    ControllerCloseDriverProxyHandle(handle);
    if (!ok)
    {
        SetLastError(err);
    }
    return ok;
}

BOOL ControllerProxyRegisterHookPatch(_In_ DWORD ProcessId, _In_ UINT64 PatchAddress, _In_ UINT32 PatchSize,
                                      _In_reads_bytes_(OriginalSize) const UINT8 *OriginalBytes,
                                      _In_ UINT32 OriginalSize, _In_ UINT32 Flags, _In_opt_z_ PCSTR Tag)
{
    BK_REGISTER_HOOK_PATCH_REQUEST req;
    HANDLE handle = INVALID_HANDLE_VALUE;
    BOOL ok;
    DWORD err;

    if (ProcessId == 0 || PatchAddress == 0 || PatchSize == 0 || OriginalSize == 0 ||
        PatchSize > BK_MAX_HOOK_PATCH_BYTES || OriginalSize > BK_MAX_HOOK_PATCH_BYTES || OriginalBytes == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    ZeroMemory(&req, sizeof(req));
    req.ProcessId = ProcessId;
    req.PatchAddress = PatchAddress;
    req.PatchSize = PatchSize;
    req.OriginalSize = OriginalSize;
    req.Flags = Flags;
    CopyMemory(req.OriginalBytes, OriginalBytes, OriginalSize);
    if (Tag != NULL)
    {
        (void)StringCchCopyA(req.Tag, RTL_NUMBER_OF(req.Tag), Tag);
    }

    ok = ControllerOpenDriverProxyHandle(&handle, "register-hook-patch") && BkscRegisterHookPatch(handle, &req);
    err = ok ? ERROR_SUCCESS : GetLastError();
    ControllerCloseDriverProxyHandle(handle);
    if (!ok)
    {
        SetLastError(err);
    }
    return ok;
}

BOOL ControllerProxyRegisterProcessInstrumentationCallback(_In_ DWORD ProcessId, _In_ UINT64 CallbackAddress,
                                                           _In_ UINT64 CallbackSize, _In_ UINT32 Flags)
{
    BK_REGISTER_PROCESS_INSTRUMENTATION_CALLBACK_REQUEST req;
    HANDLE handle = INVALID_HANDLE_VALUE;
    BOOL ok;
    DWORD err;

    if (ProcessId == 0 || CallbackAddress == 0 || CallbackSize == 0)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    ZeroMemory(&req, sizeof(req));
    req.ProcessId = ProcessId;
    req.CallbackAddress = CallbackAddress;
    req.CallbackSize = CallbackSize;
    req.Flags = Flags;

    ok = ControllerOpenDriverProxyHandle(&handle, "register-process-instrumentation-callback") &&
         BkscRegisterProcessInstrumentationCallback(handle, &req);
    err = ok ? ERROR_SUCCESS : GetLastError();
    ControllerCloseDriverProxyHandle(handle);
    if (!ok)
    {
        SetLastError(err);
    }
    return ok;
}
