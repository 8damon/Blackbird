#include "..\common\bkaes_sample.h"

static const wchar_t *BkaesTargetArgument(int argc, wchar_t **argv, const wchar_t *name)
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

static LRESULT CALLBACK BkaesGuiTargetWindowProc(HWND window, UINT message, WPARAM wParam, LPARAM lParam)
{
    if (message == WM_DESTROY)
    {
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(window, message, wParam, lParam);
}

int RunGuiHookTarget(int argc, wchar_t **argv)
{
    const wchar_t *infoPath = BkaesTargetArgument(argc, argv, L"--info-file");
    const wchar_t *triggerName = BkaesTargetArgument(argc, argv, L"--trigger-event");
    if (infoPath == nullptr || infoPath[0] == L'\0' || triggerName == nullptr || triggerName[0] == L'\0')
    {
        BkaesPrint("[FAIL] expected --info-file and --trigger-event\n");
        return 2;
    }

    HANDLE trigger = CreateEventW(nullptr, TRUE, FALSE, triggerName);
    if (trigger == nullptr)
    {
        BkaesPrint("[FAIL] CreateEvent err=%lu\n", GetLastError());
        return 1;
    }

    HINSTANCE instance = GetModuleHandleW(nullptr);
    const wchar_t *className = L"BkaesGuiHookTargetWindow";
    WNDCLASSW windowClass = {};
    windowClass.lpfnWndProc = BkaesGuiTargetWindowProc;
    windowClass.hInstance = instance;
    windowClass.lpszClassName = className;
    if (RegisterClassW(&windowClass) == 0 && GetLastError() != ERROR_CLASS_ALREADY_EXISTS)
    {
        BkaesPrint("[FAIL] RegisterClass err=%lu\n", GetLastError());
        CloseHandle(trigger);
        return 1;
    }

    HWND window = CreateWindowExW(0, className, L"AES GUI hook target", WS_OVERLAPPEDWINDOW, CW_USEDEFAULT,
                                  CW_USEDEFAULT, 320, 160, nullptr, nullptr, instance, nullptr);
    if (window == nullptr)
    {
        BkaesPrint("[FAIL] CreateWindow err=%lu\n", GetLastError());
        CloseHandle(trigger);
        return 1;
    }

    MSG message = {};
    PeekMessageW(&message, nullptr, 0, 0, PM_NOREMOVE);
    char info[128] = {};
    sprintf_s(info, "pid=%lu\ntid=%lu\n", GetCurrentProcessId(), GetCurrentThreadId());
    if (!BkaesWriteTextFile(infoPath, info))
    {
        BkaesPrint("[FAIL] write info file path=%ls err=%lu\n", infoPath, GetLastError());
        DestroyWindow(window);
        CloseHandle(trigger);
        return 1;
    }

    ULONGLONG deadline = GetTickCount64() + 30000ull;
    bool shown = false;
    bool running = true;
    while (running && GetTickCount64() < deadline)
    {
        HANDLE handles[] = {trigger};
        DWORD wait = MsgWaitForMultipleObjects(1, handles, FALSE, 250, QS_ALLINPUT);
        if (wait == WAIT_OBJECT_0 && !shown)
        {
            shown = true;
            ShowWindow(window, SW_SHOW);
            UpdateWindow(window);
            ResetEvent(trigger);
        }
        while (PeekMessageW(&message, nullptr, 0, 0, PM_REMOVE))
        {
            if (message.message == WM_QUIT)
            {
                running = false;
                break;
            }
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }
    }

    if (IsWindow(window))
    {
        DestroyWindow(window);
    }
    CloseHandle(trigger);
    return 0;
}
