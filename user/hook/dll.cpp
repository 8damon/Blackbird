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
    DWORD read = GetEnvironmentVariableA("BLACKBIRD_HOOK_UNLINK", value, (DWORD)RTL_NUMBER_OF(value));
    if (read == 0 || read >= RTL_NUMBER_OF(value))
    {
        return false;
    }

    return (value[0] == '1' || value[0] == 'y' || value[0] == 'Y' || value[0] == 't' || value[0] == 'T');
}

static DWORD WINAPI BkRuntimeBootstrapThread(LPVOID)
{
    // Keep DllMain minimal. Any expensive/risky work happens here.
    if (ShouldUnlinkModule())
    {
        __try
        {
            UnlinkModule();
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            OutputDebugStringA("[SR71][ERR] UnlinkModule raised an exception during bootstrap.\n");
        }
    }

    __try
    {
        return BkRuntimeThreadProc(nullptr);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        OutputDebugStringA("[SR71][ERR] BkRuntimeThreadProc raised an exception during bootstrap.\n");
        return 0;
    }
}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD   reason,
    LPVOID  reserved)
{
    UNREFERENCED_PARAMETER(hModule);
    UNREFERENCED_PARAMETER(reserved);

    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hModule);

        HANDLE hThread = CreateThread(
            nullptr,
            0,
            BkRuntimeBootstrapThread,
            nullptr,
            0,
            nullptr
        );

        if (hThread)
        {
            CloseHandle(hThread);
        }
    }
    else if (reason == DLL_PROCESS_DETACH)
    {
        BkRuntimeShutdown();
    }

    return TRUE;
}
