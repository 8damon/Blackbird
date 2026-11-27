#include "..\common\bkaes_sample.h"

using BkaesWinEventProc = void(CALLBACK *)(HWINEVENTHOOK, DWORD, HWND, LONG, LONG, DWORD, DWORD);

static const wchar_t *BkaesFindArgument(int argc, wchar_t **argv, const wchar_t *name)
{
    for (int index = 1; index + 1 < argc; ++index)
    {
        if (_wcsicmp(argv[index], name) == 0)
        {
            return argv[index + 1];
        }
    }
    return nullptr;
}

static bool BkaesHasWinEventArgument(int argc, wchar_t **argv, const wchar_t *name)
{
    for (int index = 1; index < argc; ++index)
    {
        if (_wcsicmp(argv[index], name) == 0)
        {
            return true;
        }
    }
    return false;
}

int RunSetWinEventHook(int argc, wchar_t **argv)
{
    const wchar_t *pidText = BkaesFindArgument(argc, argv, L"--target-pid");
    const wchar_t *tidText = BkaesFindArgument(argc, argv, L"--target-tid");
    const wchar_t *triggerName = BkaesFindArgument(argc, argv, L"--trigger-event");
    DWORD targetPid = pidText != nullptr ? wcstoul(pidText, nullptr, 10) : 0;
    DWORD targetTid = tidText != nullptr ? wcstoul(tidText, nullptr, 10) : 0;
    bool globalMode = BkaesHasWinEventArgument(argc, argv, L"--global");
    bool remoteMode = globalMode || targetPid != 0 || targetTid != 0 || triggerName != nullptr;

    if (remoteMode && ((!globalMode && (targetPid == 0 || targetTid == 0)) || triggerName == nullptr ||
                       triggerName[0] == L'\0'))
    {
        BkaesPrint("[FAIL] expected --target-pid, --target-tid, and --trigger-event\n");
        return 2;
    }

    std::wstring dllPath = BkaesJoinPath(BkaesSelfDirectory(), L"bb_unsigned_plugin.dll");
    HMODULE plugin = LoadLibraryW(dllPath.c_str());
    if (plugin == nullptr)
    {
        BkaesPrint("[FAIL] LoadLibrary plugin path=%ls err=%lu\n", dllPath.c_str(), GetLastError());
        return 1;
    }

    auto callback = reinterpret_cast<BkaesWinEventProc>(GetProcAddress(plugin, "BkaesNoopWinEventProc"));
    if (callback == nullptr)
    {
        BkaesPrint("[FAIL] missing BkaesNoopWinEventProc err=%lu\n", GetLastError());
        FreeLibrary(plugin);
        return 1;
    }

    if (!remoteMode)
    {
        targetPid = GetCurrentProcessId();
        targetTid = GetCurrentThreadId();
    }
    DWORD flags = remoteMode ? WINEVENT_INCONTEXT : WINEVENT_OUTOFCONTEXT;
    HMODULE callbackModule = remoteMode ? plugin : nullptr;
    HWINEVENTHOOK hook =
        SetWinEventHook(EVENT_OBJECT_SHOW, EVENT_OBJECT_SHOW, callbackModule, callback, targetPid, targetTid, flags);
    DWORD hookError = GetLastError();
    HANDLE trigger = remoteMode ? OpenEventW(EVENT_MODIFY_STATE, FALSE, triggerName) : nullptr;
    BOOL signaled = !remoteMode || (trigger != nullptr && SetEvent(trigger));
    if (trigger != nullptr)
    {
        CloseHandle(trigger);
    }

    if (hook != nullptr && signaled)
    {
        Sleep(1200);
    }
    if (hook != nullptr)
    {
        UnhookWinEvent(hook);
    }

    BkaesSettleTelemetry();
    BkaesPrint("[OK] SetWinEventHook mode=%s targetPid=%lu targetTid=%lu hook=%p signaled=%u error=%lu\n",
               globalMode ? "global" : (remoteMode ? "remote" : "local"), targetPid, targetTid, hook,
               signaled ? 1u : 0u, hookError);
    FreeLibrary(plugin);
    return hook != nullptr && signaled ? 0 : 1;
}
