#include "internal.h"

static bool ControllerInjectionEnvironmentNamesEqual(_In_z_ PCWSTR Left, _In_z_ PCWSTR Right) noexcept
{
    PCWSTR leftEq = wcschr(Left, L'=');
    PCWSTR rightEq = wcschr(Right, L'=');
    size_t leftChars = leftEq ? (size_t)(leftEq - Left) : wcslen(Left);
    size_t rightChars = rightEq ? (size_t)(rightEq - Right) : wcslen(Right);
    return (leftChars == rightChars) && (_wcsnicmp(Left, Right, leftChars) == 0);
}

bool ControllerInjectionEnvironmentHasName(_In_opt_z_ PCWSTR Overrides, _In_z_ PCWSTR Name) noexcept
{
    if (Overrides == NULL || Name == NULL || Name[0] == L'\0')
    {
        return false;
    }

    for (PCWSTR cursor = Overrides; *cursor != L'\0';)
    {
        PCWSTR lineEnd = cursor;
        while (*lineEnd != L'\0' && *lineEnd != L'\r' && *lineEnd != L'\n')
        {
            lineEnd += 1;
        }

        PCWSTR lineStart = cursor;
        while (lineStart < lineEnd && (*lineStart == L' ' || *lineStart == L'\t'))
        {
            lineStart += 1;
        }

        if (lineStart < lineEnd)
        {
            std::wstring line(lineStart, lineEnd);
            if (ControllerInjectionEnvironmentNamesEqual(line.c_str(), Name))
            {
                return true;
            }
        }

        cursor = lineEnd;
        while (*cursor == L'\r' || *cursor == L'\n')
        {
            cursor += 1;
        }
    }

    return false;
}

static ULONGLONG ControllerInjectionRandom64(VOID)
{
    using RtlGenRandomFn = BOOLEAN(WINAPI *)(PVOID RandomBuffer, ULONG RandomBufferLength);

    ULONGLONG value = 0;
    HMODULE advapi = LoadLibraryW(L"advapi32.dll");
    if (advapi != NULL)
    {
        auto rtlGenRandom = reinterpret_cast<RtlGenRandomFn>(GetProcAddress(advapi, "SystemFunction036"));
        if (rtlGenRandom != NULL && rtlGenRandom(&value, sizeof(value)))
        {
            FreeLibrary(advapi);
            return value;
        }
        FreeLibrary(advapi);
    }

    LARGE_INTEGER qpc;
    QueryPerformanceCounter(&qpc);
    value = ((ULONGLONG)GetCurrentProcessId() << 32) ^ (ULONGLONG)GetTickCount64() ^ (ULONGLONG)qpc.QuadPart;
    return value;
}

BOOL ControllerInjectionBuildDeferredLaunchGateEventName(_Out_writes_z_(EventNameChars) PWSTR EventName,
                                                        _In_ size_t EventNameChars)
{
    ULONGLONG nonce0;
    ULONGLONG nonce1;

    if (EventName == NULL || EventNameChars == 0)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    nonce0 = ControllerInjectionRandom64();
    nonce1 = ControllerInjectionRandom64();
    if (FAILED(StringCchPrintfW(EventName, EventNameChars, L"Global\\BlackbirdLaunchGateRelease.%08lX.%016llX.%016llX",
                                (unsigned long)GetCurrentProcessId(), (unsigned long long)nonce0,
                                (unsigned long long)nonce1)))
    {
        EventName[0] = L'\0';
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }

    return TRUE;
}

HANDLE ControllerInjectionCreateDeferredLaunchGateEvent(_In_z_ PCWSTR EventName, _In_ DWORD ProcessId)
{
    PSECURITY_DESCRIPTOR securityDescriptor = NULL;
    SECURITY_ATTRIBUTES securityAttributes;
    HANDLE eventHandle;

    if (EventName == NULL || EventName[0] == L'\0')
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return NULL;
    }

    ZeroMemory(&securityAttributes, sizeof(securityAttributes));
    securityAttributes.nLength = sizeof(securityAttributes);
    if (ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:P(A;;0x00100000;;;WD)(A;;0x001F0003;;;SY)(A;;0x001F0003;;;BA)(A;;0x001F0003;;;OW)",
            SDDL_REVISION_1, &securityDescriptor, NULL))
    {
        securityAttributes.lpSecurityDescriptor = securityDescriptor;
    }

    SetLastError(ERROR_SUCCESS);
    eventHandle = CreateEventExW(securityAttributes.lpSecurityDescriptor != NULL ? &securityAttributes : NULL,
                                 EventName, CREATE_EVENT_MANUAL_RESET, EVENT_MODIFY_STATE | SYNCHRONIZE);
    DWORD createError = GetLastError();
    if (eventHandle == NULL)
    {
        ControllerLog("[INJ] deferred launch gate event create failed pid=%lu name=%ws err=%lu\n",
                      (unsigned long)ProcessId, EventName, createError);
        if (securityDescriptor != NULL)
        {
            LocalFree(securityDescriptor);
        }
        SetLastError(createError == ERROR_SUCCESS ? ERROR_GEN_FAILURE : createError);
        return NULL;
    }

    if (createError == ERROR_ALREADY_EXISTS)
    {
        ControllerLog("[INJ][WARN] deferred launch gate event collision pid=%lu name=%ws\n",
                      (unsigned long)ProcessId, EventName);
        CloseHandle(eventHandle);
        if (securityDescriptor != NULL)
        {
            LocalFree(securityDescriptor);
        }
        SetLastError(ERROR_ALREADY_EXISTS);
        return NULL;
    }

    ControllerLog("[INJ] deferred launch gate event ready pid=%lu name=%ws\n", (unsigned long)ProcessId, EventName);
    if (securityDescriptor != NULL)
    {
        LocalFree(securityDescriptor);
    }
    return eventHandle;
}

BOOL ControllerInjectionBuildEnvironmentBlock(_In_opt_ HANDLE UserToken,
                                              _In_reads_or_z_(OverrideChars) PCWSTR Overrides,
                                              _In_ BOOL EnableLaunchGate, _In_ BOOL DeferLaunchGateRelease,
                                              _In_opt_z_ PCWSTR LaunchGateEventName,
                                              _Outptr_result_nullonfailure_ PWSTR *EnvironmentBlockOut)
{
    HMODULE userEnv = NULL;
    CreateEnvironmentBlockFn createEnvironmentBlock = NULL;
    DestroyEnvironmentBlockFn destroyEnvironmentBlock = NULL;
    LPVOID userEnvironment = NULL;
    LPWCH currentEnvironment = NULL;
    BOOL usingUserEnvironment = FALSE;

    if (EnvironmentBlockOut == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    *EnvironmentBlockOut = NULL;
    if ((Overrides == NULL || Overrides[0] == L'\0') && !EnableLaunchGate && !DeferLaunchGateRelease)
    {
        return TRUE;
    }

    if (UserToken != NULL)
    {
        userEnv = LoadLibraryW(L"userenv.dll");
        if (userEnv != NULL)
        {
            createEnvironmentBlock =
                reinterpret_cast<CreateEnvironmentBlockFn>(GetProcAddress(userEnv, "CreateEnvironmentBlock"));
            destroyEnvironmentBlock =
                reinterpret_cast<DestroyEnvironmentBlockFn>(GetProcAddress(userEnv, "DestroyEnvironmentBlock"));
            if (createEnvironmentBlock != NULL && destroyEnvironmentBlock != NULL &&
                createEnvironmentBlock(&userEnvironment, UserToken, TRUE))
            {
                currentEnvironment = static_cast<LPWCH>(userEnvironment);
                usingUserEnvironment = TRUE;
            }
        }
    }

    if (currentEnvironment == NULL)
    {
        currentEnvironment = GetEnvironmentStringsW();
    }
    if (currentEnvironment == NULL)
    {
        if (userEnv != NULL)
        {
            FreeLibrary(userEnv);
        }
        return FALSE;
    }

    std::vector<std::wstring> entries;

    for (PCWSTR cursor = currentEnvironment; *cursor != L'\0'; cursor += wcslen(cursor) + 1)
    {
        entries.emplace_back(cursor);
    }
    if (usingUserEnvironment)
    {
        destroyEnvironmentBlock(userEnvironment);
    }
    else
    {
        FreeEnvironmentStringsW(currentEnvironment);
    }
    if (userEnv != NULL)
    {
        FreeLibrary(userEnv);
    }

    if (Overrides != NULL)
    {
        for (PCWSTR cursor = Overrides; *cursor != L'\0';)
        {
            PCWSTR lineEnd = cursor;
            while (*lineEnd != L'\0' && *lineEnd != L'\r' && *lineEnd != L'\n')
            {
                lineEnd += 1;
            }

            PCWSTR lineStart = cursor;
            while (lineStart < lineEnd && (*lineStart == L' ' || *lineStart == L'\t'))
            {
                lineStart += 1;
            }
            while (lineEnd > lineStart && (lineEnd[-1] == L' ' || lineEnd[-1] == L'\t'))
            {
                lineEnd -= 1;
            }

            if (lineEnd > lineStart)
            {
                std::wstring line(lineStart, lineEnd);
                const wchar_t *eq = wcschr(line.c_str(), L'=');
                if (eq == NULL || eq == line.c_str())
                {
                    SetLastError(ERROR_INVALID_PARAMETER);
                    return FALSE;
                }

                bool replaced = false;
                for (auto &e : entries)
                {
                    if (ControllerInjectionEnvironmentNamesEqual(e.c_str(), line.c_str()))
                    {
                        e = std::move(line);
                        replaced = true;
                        break;
                    }
                }
                if (!replaced)
                {
                    entries.push_back(std::move(line));
                }
            }

            cursor = lineEnd;
            while (*cursor == L'\r' || *cursor == L'\n')
            {
                cursor += 1;
            }
        }
    }

    if (EnableLaunchGate)
    {
        const wchar_t *launchGate = L"BK_HOOK_LAUNCH_GATE=1";
        const wchar_t *deferLaunchGate = L"BK_HOOK_LAUNCH_GATE_DEFER_OPEN=1";
        bool replaced = false;
        for (auto &e : entries)
        {
            if (ControllerInjectionEnvironmentNamesEqual(e.c_str(), launchGate))
            {
                e = launchGate;
                replaced = true;
                break;
            }
        }
        if (!replaced)
        {
            entries.emplace_back(launchGate);
        }

        if (DeferLaunchGateRelease)
        {
            std::wstring eventNameEntry;

            replaced = false;
            for (auto &e : entries)
            {
                if (ControllerInjectionEnvironmentNamesEqual(e.c_str(), deferLaunchGate))
                {
                    e = deferLaunchGate;
                    replaced = true;
                    break;
                }
            }
            if (!replaced)
            {
                entries.emplace_back(deferLaunchGate);
            }

            if (LaunchGateEventName != NULL && LaunchGateEventName[0] != L'\0')
            {
                eventNameEntry.assign(L"BK_HOOK_LAUNCH_GATE_EVENT=");
                eventNameEntry.append(LaunchGateEventName);

                replaced = false;
                for (auto &e : entries)
                {
                    if (ControllerInjectionEnvironmentNamesEqual(e.c_str(), eventNameEntry.c_str()))
                    {
                        e = eventNameEntry;
                        replaced = true;
                        break;
                    }
                }
                if (!replaced)
                {
                    entries.push_back(std::move(eventNameEntry));
                }
            }
        }
    }

    std::sort(entries.begin(), entries.end(),
              [](const std::wstring &a, const std::wstring &b) { return _wcsicmp(a.c_str(), b.c_str()) < 0; });

    size_t totalChars = 1;
    for (const auto &e : entries)
    {
        totalChars += e.size() + 1;
    }

    PWSTR block = (PWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, totalChars * sizeof(WCHAR));
    if (block == NULL)
    {
        SetLastError(ERROR_OUTOFMEMORY);
        return FALSE;
    }

    PWSTR write = block;
    for (const auto &e : entries)
    {
        CopyMemory(write, e.c_str(), e.size() * sizeof(WCHAR));
        write += e.size() + 1;
    }
    *write = L'\0';
    *EnvironmentBlockOut = block;
    return TRUE;
}

DWORD ControllerInjectionMapPriorityClass(_In_ UINT32 PriorityClass)
{
    switch (PriorityClass)
    {
    case IDLE_PRIORITY_CLASS:
    case BELOW_NORMAL_PRIORITY_CLASS:
    case NORMAL_PRIORITY_CLASS:
    case ABOVE_NORMAL_PRIORITY_CLASS:
    case HIGH_PRIORITY_CLASS:
    case REALTIME_PRIORITY_CLASS:
        return PriorityClass;
    default:
        return 0;
    }
}

BOOL ControllerInjectionBuildLaunchCommandLine(_In_z_ PCWSTR ImagePath, _In_opt_z_ PCWSTR Arguments,
                                               _Out_ std::wstring *CommandLineOut)
{
    static constexpr size_t kMaxCreateProcessCommandLineChars = 32767u;

    if (ImagePath == NULL || ImagePath[0] == L'\0' || CommandLineOut == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    CommandLineOut->clear();
    CommandLineOut->reserve(wcslen(ImagePath) + (Arguments != NULL ? wcslen(Arguments) : 0u) + 4u);
    CommandLineOut->push_back(L'"');
    CommandLineOut->append(ImagePath);
    CommandLineOut->push_back(L'"');
    if (Arguments != NULL && Arguments[0] != L'\0')
    {
        CommandLineOut->push_back(L' ');
        CommandLineOut->append(Arguments);
    }

    if (CommandLineOut->size() >= kMaxCreateProcessCommandLineChars)
    {
        CommandLineOut->clear();
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }

    return TRUE;
}

std::vector<WCHAR> ControllerInjectionMakeMutableCommandLine(_In_ const std::wstring &CommandLine)
{
    std::vector<WCHAR> mutableCommandLine(CommandLine.begin(), CommandLine.end());
    mutableCommandLine.push_back(L'\0');
    return mutableCommandLine;
}
