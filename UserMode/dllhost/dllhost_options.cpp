#include "dllhost_options.h"

#include <cstdio>
#include <cwchar>

namespace BK::DllHost
{
    namespace
    {
        bool EqualsInsensitive(const wchar_t *left, const wchar_t *right) noexcept
        {
            return left != nullptr && right != nullptr && _wcsicmp(left, right) == 0;
        }

        bool TryParseDword(const wchar_t *text, DWORD &value) noexcept
        {
            if (text == nullptr || *text == L'\0')
            {
                return false;
            }

            wchar_t *end = nullptr;
            unsigned long base = 10;
            const wchar_t *cursor = text;
            if (cursor[0] == L'0' && (cursor[1] == L'x' || cursor[1] == L'X'))
            {
                cursor += 2;
                base = 16;
            }

            unsigned long parsed = std::wcstoul(cursor, &end, base);
            if (end == cursor || (end != nullptr && *end != L'\0'))
            {
                return false;
            }

            value = static_cast<DWORD>(parsed);
            return true;
        }

        bool TryParseMode(const wchar_t *text, DllMode &mode) noexcept
        {
            if (EqualsInsensitive(text, L"load"))
            {
                mode = DllMode::LoadOnly;
                return true;
            }
            if (EqualsInsensitive(text, L"export") || EqualsInsensitive(text, L"export-void"))
            {
                mode = DllMode::ExportVoid;
                return true;
            }
            if (EqualsInsensitive(text, L"rundll"))
            {
                mode = DllMode::Rundll;
                return true;
            }
            if (EqualsInsensitive(text, L"register") || EqualsInsensitive(text, L"dllregisterserver"))
            {
                mode = DllMode::RegisterServer;
                return true;
            }
            if (EqualsInsensitive(text, L"unregister") || EqualsInsensitive(text, L"dllunregisterserver"))
            {
                mode = DllMode::UnregisterServer;
                return true;
            }
            if (EqualsInsensitive(text, L"install") || EqualsInsensitive(text, L"dllinstall"))
            {
                mode = DllMode::Install;
                return true;
            }
            return false;
        }
    } // namespace

    void PrintUsage() noexcept
    {
        std::fwprintf(
            stderr, L"Usage: BlackbirdDllHost.exe --dll <path> [--mode load|export|rundll|register|unregister|install] "
                    L"[--export <name>] [--ordinal <n>] [--arg <text>] [--load-flags <hex>] [--wait-ms <n>] "
                    L"[--free-on-exit]\n");
    }

    bool ParseOptions(int argc, wchar_t **argv, Options &options) noexcept
    {
        for (int i = 1; i < argc; ++i)
        {
            const wchar_t *arg = argv[i];
            auto requireValue = [&]() -> const wchar_t *
            {
                if ((i + 1) >= argc)
                {
                    return nullptr;
                }
                return argv[++i];
            };

            if (EqualsInsensitive(arg, L"--dll"))
            {
                const wchar_t *value = requireValue();
                if (value == nullptr)
                {
                    return false;
                }
                options.DllPath = value;
            }
            else if (EqualsInsensitive(arg, L"--mode"))
            {
                const wchar_t *value = requireValue();
                if (value == nullptr || !TryParseMode(value, options.Mode))
                {
                    return false;
                }
            }
            else if (EqualsInsensitive(arg, L"--export"))
            {
                const wchar_t *value = requireValue();
                if (value == nullptr)
                {
                    return false;
                }
                options.ExportName = value;
            }
            else if (EqualsInsensitive(arg, L"--ordinal"))
            {
                const wchar_t *value = requireValue();
                if (value == nullptr || !TryParseDword(value, options.ExportOrdinal))
                {
                    return false;
                }
            }
            else if (EqualsInsensitive(arg, L"--arg"))
            {
                const wchar_t *value = requireValue();
                if (value == nullptr)
                {
                    return false;
                }
                options.RundllArgument = value;
                options.InstallArgument = value;
            }
            else if (EqualsInsensitive(arg, L"--install-disable"))
            {
                options.InstallEnable = FALSE;
            }
            else if (EqualsInsensitive(arg, L"--load-flags"))
            {
                const wchar_t *value = requireValue();
                if (value == nullptr || !TryParseDword(value, options.LoadFlags))
                {
                    return false;
                }
            }
            else if (EqualsInsensitive(arg, L"--wait-ms"))
            {
                const wchar_t *value = requireValue();
                if (value == nullptr || !TryParseDword(value, options.WaitMs))
                {
                    return false;
                }
            }
            else if (EqualsInsensitive(arg, L"--free-on-exit"))
            {
                options.FreeOnExit = true;
            }
            else if (EqualsInsensitive(arg, L"--help") || EqualsInsensitive(arg, L"/?"))
            {
                return false;
            }
            else
            {
                return false;
            }
        }

        return !options.DllPath.empty();
    }
} // namespace BK::DllHost
