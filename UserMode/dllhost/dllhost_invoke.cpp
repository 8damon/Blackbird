#include "dllhost_invoke.h"

#include <string>

namespace BK::DllHost
{
    namespace
    {
        bool WideToAnsi(const std::wstring &input, std::string &output) noexcept
        {
            output.clear();
            if (input.empty())
            {
                return true;
            }

            int bytes = WideCharToMultiByte(CP_ACP, 0, input.c_str(), -1, nullptr, 0, nullptr, nullptr);
            if (bytes <= 1)
            {
                return false;
            }

            output.resize(static_cast<size_t>(bytes - 1));
            return WideCharToMultiByte(CP_ACP, 0, input.c_str(), -1, output.data(), bytes, nullptr, nullptr) != 0;
        }

        FARPROC ResolveExport(HMODULE module, const Options &options) noexcept
        {
            if (module == nullptr)
            {
                return nullptr;
            }

            if (options.ExportOrdinal != 0)
            {
                return GetProcAddress(module, MAKEINTRESOURCEA(options.ExportOrdinal));
            }

            std::string name;
            if (!WideToAnsi(options.ExportName, name) || name.empty())
            {
                return nullptr;
            }

            return GetProcAddress(module, name.c_str());
        }

        DWORD InvokeSelectedExport(HMODULE module, const Options &options) noexcept
        {
            FARPROC proc = ResolveExport(module, options);
            if (proc == nullptr)
            {
                DWORD err = GetLastError();
                return err == ERROR_SUCCESS ? ERROR_PROC_NOT_FOUND : err;
            }

            using ExportVoidFn = DWORD(WINAPI *)();
            return reinterpret_cast<ExportVoidFn>(proc)();
        }

        DWORD InvokeRundllExport(HMODULE module, const Options &options) noexcept
        {
            FARPROC proc = ResolveExport(module, options);
            if (proc == nullptr)
            {
                DWORD err = GetLastError();
                return err == ERROR_SUCCESS ? ERROR_PROC_NOT_FOUND : err;
            }

            std::string argument;
            if (!WideToAnsi(options.RundllArgument, argument))
            {
                return ERROR_INVALID_PARAMETER;
            }

            using RundllFn = void(CALLBACK *)(HWND, HINSTANCE, LPSTR, int);
            reinterpret_cast<RundllFn>(proc)(nullptr, module,
                                             argument.empty() ? const_cast<char *>("") : argument.data(), SW_HIDE);
            return ERROR_SUCCESS;
        }

        DWORD InvokeNoArgComExport(HMODULE module, const char *name) noexcept
        {
            FARPROC proc = GetProcAddress(module, name);
            if (proc == nullptr)
            {
                DWORD err = GetLastError();
                return err == ERROR_SUCCESS ? ERROR_PROC_NOT_FOUND : err;
            }

            using ComExportFn = HRESULT(STDAPICALLTYPE *)();
            HRESULT hr = reinterpret_cast<ComExportFn>(proc)();
            return SUCCEEDED(hr) ? ERROR_SUCCESS : HRESULT_CODE(hr);
        }

        DWORD InvokeDllInstall(HMODULE module, const Options &options) noexcept
        {
            FARPROC proc = GetProcAddress(module, "DllInstall");
            if (proc == nullptr)
            {
                DWORD err = GetLastError();
                return err == ERROR_SUCCESS ? ERROR_PROC_NOT_FOUND : err;
            }

            using DllInstallFn = HRESULT(STDAPICALLTYPE *)(BOOL, LPCWSTR);
            HRESULT hr = reinterpret_cast<DllInstallFn>(proc)(
                options.InstallEnable, options.InstallArgument.empty() ? nullptr : options.InstallArgument.c_str());
            return SUCCEEDED(hr) ? ERROR_SUCCESS : HRESULT_CODE(hr);
        }
    } // namespace

    DWORD InvokeConfiguredMode(HMODULE module, const Options &options) noexcept
    {
        switch (options.Mode)
        {
        case DllMode::LoadOnly:
            return ERROR_SUCCESS;
        case DllMode::ExportVoid:
            return InvokeSelectedExport(module, options);
        case DllMode::Rundll:
            return InvokeRundllExport(module, options);
        case DllMode::RegisterServer:
            return InvokeNoArgComExport(module, "DllRegisterServer");
        case DllMode::UnregisterServer:
            return InvokeNoArgComExport(module, "DllUnregisterServer");
        case DllMode::Install:
            return InvokeDllInstall(module, options);
        }

        return ERROR_INVALID_PARAMETER;
    }
} // namespace BK::DllHost
