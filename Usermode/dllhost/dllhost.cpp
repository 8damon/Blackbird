#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>

#include <cstdio>

#include "dllhost_invoke.h"
#include "dllhost_options.h"

using namespace BK::DllHost;

int wmain(int argc, wchar_t **argv)
{
    Options options{};
    if (!ParseOptions(argc, argv, options))
    {
        PrintUsage();
        return ERROR_INVALID_PARAMETER;
    }

    std::fwprintf(stdout, L"BlackbirdDllHost: loading %ls\n", options.DllPath.c_str());
    HMODULE module = options.LoadFlags == 0 ? LoadLibraryW(options.DllPath.c_str())
                                            : LoadLibraryExW(options.DllPath.c_str(), nullptr, options.LoadFlags);
    if (module == nullptr)
    {
        DWORD err = GetLastError();
        std::fwprintf(stderr, L"BlackbirdDllHost: load failed gle=%lu path=%ls\n", err, options.DllPath.c_str());
        return static_cast<int>(err == ERROR_SUCCESS ? ERROR_MOD_NOT_FOUND : err);
    }

    DWORD result = InvokeConfiguredMode(module, options);
    if (result != ERROR_SUCCESS)
    {
        std::fwprintf(stderr, L"BlackbirdDllHost: invocation failed result=%lu\n", result);
    }

    if (options.WaitMs != 0)
    {
        std::fwprintf(stdout, L"BlackbirdDllHost: holding process for %lu ms\n", options.WaitMs);
        Sleep(options.WaitMs);
    }

    if (options.FreeOnExit)
    {
        FreeLibrary(module);
    }

    std::fwprintf(stdout, L"BlackbirdDllHost: exiting result=%lu\n", result);
    return static_cast<int>(result);
}
