#include "..\common\bkaes_sample.h"

using BkaesHookProc = LRESULT(CALLBACK*)(int, WPARAM, LPARAM);

static DWORD BkaesParseTargetThreadId(int argc, wchar_t **argv)
{
    for (int index = 1; index + 1 < argc; ++index)
    {
        if (_wcsicmp(argv[index], L"--target-tid") == 0)
        {
            return wcstoul(argv[index + 1], nullptr, 10);
        }
    }
    return 0;
}

static bool BkaesHasSetWindowsHookArgument(int argc, wchar_t **argv, const wchar_t *name)
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

int RunSetWindowsHookEx(int argc, wchar_t **argv)
{
    std::wstring dllPath = BkaesJoinPath(BkaesSelfDirectory(), L"bb_unsigned_plugin.dll");
    HMODULE plugin = LoadLibraryW(dllPath.c_str());
    MSG msg = {};
    DWORD targetThreadId = BkaesParseTargetThreadId(argc, argv);
    bool globalMode = BkaesHasSetWindowsHookArgument(argc, argv, L"--global");
    bool ansiMode = BkaesHasSetWindowsHookArgument(argc, argv, L"--ansi");

    if (plugin == nullptr)
    {
        BkaesPrint("[FAIL] LoadLibrary plugin path=%ls err=%lu\n", dllPath.c_str(), GetLastError());
        return 1;
    }

    auto hookProc = (BkaesHookProc)GetProcAddress(plugin, "BkaesNoopHookProc");
    if (hookProc == nullptr)
    {
        FreeLibrary(plugin);
        return 1;
    }

    if (targetThreadId == 0 && !globalMode)
    {
        targetThreadId = GetCurrentThreadId();
        PeekMessageW(&msg, nullptr, WM_USER, WM_USER, PM_NOREMOVE);
    }
    else if (globalMode)
    {
        PeekMessageW(&msg, nullptr, WM_USER, WM_USER, PM_NOREMOVE);
    }

    HHOOK hook = ansiMode ? SetWindowsHookExA(WH_GETMESSAGE, hookProc, plugin, targetThreadId)
                          : SetWindowsHookExW(WH_GETMESSAGE, hookProc, plugin, targetThreadId);
    if (hook != nullptr)
    {
        DWORD triggerThreadId = globalMode ? GetCurrentThreadId() : targetThreadId;
        PostThreadMessageW(triggerThreadId, WM_USER + 42, 0, 0);
        if (triggerThreadId == GetCurrentThreadId())
        {
            while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE))
            {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
        else
        {
            Sleep(750);
        }
        UnhookWindowsHookEx(hook);
    }

    BkaesSettleTelemetry();
    BkaesPrint("[OK] SetWindowsHookEx%s mode=%s targetTid=%lu dll=%ls hook=%p\n",
               ansiMode ? "A" : "W", globalMode ? "global" : "targeted", targetThreadId, dllPath.c_str(), hook);
    FreeLibrary(plugin);
    return hook != nullptr ? 0 : 1;
}
