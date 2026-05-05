#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#ifndef NOMINMAX
#define NOMINMAX
#endif

#ifndef _WINSOCKAPI_
#define _WINSOCKAPI_
#endif

#include <windows.h>

#include "ipc/pipe.h"
#include "hooks/runtime.h"
#include "instrument/unlink.h"

static bool ShouldUnlinkModule() noexcept
{
    char value[8]{};
    DWORD read = GetEnvironmentVariableA("BK_HOOK_UNLINK", value, (DWORD)RTL_NUMBER_OF(value));
    if (read == 0 || read >= RTL_NUMBER_OF(value))
    {
        return false;
    }

    return (value[0] == '1' || value[0] == 'y' || value[0] == 'Y' || value[0] == 't' || value[0] == 'T');
}

static bool ShouldPrepareLaunchGate() noexcept
{
    char value[8]{};
    DWORD read = GetEnvironmentVariableA("BK_HOOK_LAUNCH_GATE", value, (DWORD)RTL_NUMBER_OF(value));
    if (read == 0 || read >= RTL_NUMBER_OF(value))
    {
        return false;
    }

    return (value[0] == '1' || value[0] == 'y' || value[0] == 'Y' || value[0] == 't' || value[0] == 'T');
}

static DWORD WINAPI BkDispatchFlightThread(LPVOID)
{
    BkDbgLog("BkDispatchFlightThread: start unlink=%u", ShouldUnlinkModule() ? 1u : 0u);
    if (ShouldUnlinkModule())
    {
        __try
        {
            UnlinkModulePEB();
            BkDbgLog("BkDispatchFlightThread: unlink complete");
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            BkDbgLog("BkDispatchFlightThread: unlink exception=0x%08lX", (unsigned long)GetExceptionCode());
        }
    }

    __try
    {
        BkDbgLog("BkDispatchFlightThread: entering runtime thread proc");
        return BkRuntimeThreadProc(nullptr);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        BkDbgLog("BkDispatchFlightThread: runtime thread exception=0x%08lX", (unsigned long)GetExceptionCode());
        return 0;
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved)
{
    UNREFERENCED_PARAMETER(hModule);
    UNREFERENCED_PARAMETER(reserved);

    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hModule);

        bool launchGate = ShouldPrepareLaunchGate();
        BkDbgLog("DllMain: PROCESS_ATTACH launchGate=%u reserved=%p", launchGate ? 1u : 0u, reserved);
        if (launchGate)
        {
            if (!BkInitializeSubsystems())
            {
                BkDbgLog("DllMain: launch gate preparation failed");
                BkRuntimeFailClosed(ERROR_DLL_INIT_FAILED);
                return FALSE;
            }

            BkDbgLog("DllMain: launch gate bootstrap deferred to trapped target thread");
            return TRUE;
        }

        HANDLE hThread = BkRuntimeCreateBootstrapThread(BkDispatchFlightThread, nullptr);

        if (hThread)
        {
            BkDbgLog("DllMain: bootstrap thread created handle=%p", hThread);
            BkRuntimeCloseHandle(hThread);
        }
        else if (launchGate)
        {
            BkDbgLog("DllMain: bootstrap thread creation failed");
            BkRuntimeFailClosed(ERROR_DLL_INIT_FAILED);
            return FALSE;
        }
    }
    else if (reason == DLL_PROCESS_DETACH)
    {
        BkDbgLog("DllMain: PROCESS_DETACH reserved=%p", reserved);
        BkRuntimeShutdown();
    }

    return TRUE;
}
