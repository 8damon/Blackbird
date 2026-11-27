#define UNICODE
#define _UNICODE
#include <windows.h>
#include <strsafe.h>
#include <fstream>
#include <string>

static HWND g_result = nullptr;
static HWND g_overlay = nullptr;

static void AppendAudit(const wchar_t* fileName, const char* text)
{
    wchar_t jobDir[MAX_PATH];
    wchar_t path[MAX_PATH];
    DWORD length = GetEnvironmentVariableW(L"BKAES_AUDIT_JOB_DIR", jobDir, ARRAYSIZE(jobDir));
    if (length == 0 || length >= ARRAYSIZE(jobDir) ||
        FAILED(StringCchPrintfW(path, ARRAYSIZE(path), L"%s\\%s", jobDir, fileName))) {
        return;
    }
    HANDLE file = CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                              OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return;
    DWORD written = 0;
    WriteFile(file, text, static_cast<DWORD>(strlen(text)), &written, nullptr);
    CloseHandle(file);
}

static bool ExerciseNormalWorkflow(HWND window)
{
    const int left = 144;
    const int right = 233;
    const int total = left + right;
    wchar_t label[128];
    StringCchPrintfW(label, ARRAYSIZE(label), L"%d + %d = %d   |   18%% tip = %.2f", left, right, total,
                     total * 0.18);
    SetWindowTextW(g_result, label);

    wchar_t temp[MAX_PATH];
    wchar_t filePath[MAX_PATH];
    if (GetTempPathW(ARRAYSIZE(temp), temp) == 0 ||
        FAILED(StringCchPrintfW(filePath, ARRAYSIZE(filePath), L"%sbkaes-ui-%lu.json", temp,
                                GetCurrentProcessId()))) {
        return false;
    }
    {
        std::ofstream settings(filePath, std::ios::binary | std::ios::trunc);
        settings << "{\"theme\":\"dark\",\"lastTotal\":" << total << ",\"overlay\":true}\n";
    }
    std::ifstream input(filePath, std::ios::binary);
    std::string contents((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
    input.close();
    DeleteFileW(filePath);
    SetWindowTextW(window, L"BKAES Normal Calculator - self-check passed");
    return contents.find("lastTotal") != std::string::npos && total == 377;
}

static LRESULT CALLBACK WindowProc(HWND window, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message) {
    case WM_CREATE:
        CreateWindowW(L"STATIC", L"Normal invoice calculator", WS_CHILD | WS_VISIBLE,
                      20, 20, 320, 24, window, nullptr, nullptr, nullptr);
        g_result = CreateWindowW(L"STATIC", L"waiting for self-check...", WS_CHILD | WS_VISIBLE,
                                 20, 58, 420, 24, window, nullptr, nullptr, nullptr);
        CreateWindowW(L"BUTTON", L"Recalculate", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                      20, 98, 130, 30, window, reinterpret_cast<HMENU>(1001), nullptr, nullptr);
        SetTimer(window, 1, 700, nullptr);
        return 0;
    case WM_COMMAND:
        if (LOWORD(wParam) == 1001) {
            ExerciseNormalWorkflow(window);
            return 0;
        }
        break;
    case WM_TIMER:
        if (wParam == 1) {
            KillTimer(window, 1);
            if (!ExerciseNormalWorkflow(window)) {
                AppendAudit(L"bkaes-assertions.txt", "[BKAES_ASSERT_FAIL] cpp_ui workflow mismatch\r\n");
                PostQuitMessage(2);
                return 0;
            }
            AppendAudit(L"bkaes-protection-outcome.txt",
                        "[BKAES_OUTCOME] benign_cpp_ui=passed calculation=377 overlay=created settings=roundtrip\r\n");
            SetTimer(window, 2, 900, nullptr);
            return 0;
        }
        if (wParam == 2) {
            KillTimer(window, 2);
            DestroyWindow(window);
            return 0;
        }
        break;
    case WM_DESTROY:
        if (g_overlay) DestroyWindow(g_overlay);
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(window, message, wParam, lParam);
}

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int show)
{
    WNDCLASSEXW wc = { sizeof(wc) };
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = instance;
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
    wc.lpszClassName = L"BkaesNormalCalculator";
    if (!RegisterClassExW(&wc)) return 1;

    HWND window = CreateWindowExW(0, wc.lpszClassName, L"BKAES Normal Calculator",
        WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 500, 210,
        nullptr, nullptr, instance, nullptr);
    if (!window) {
        AppendAudit(L"bkaes-assertions.txt", "[BKAES_ASSERT_FAIL] cpp_ui main window creation failed\r\n");
        return 1;
    }
    g_overlay = CreateWindowExW(WS_EX_TOPMOST | WS_EX_TOOLWINDOW | WS_EX_LAYERED,
        L"STATIC", L"BKAES normal status overlay", WS_POPUP | SS_CENTER,
        40, 40, 260, 42, nullptr, nullptr, instance, nullptr);
    if (g_overlay) {
        SetLayeredWindowAttributes(g_overlay, 0, 215, LWA_ALPHA);
        ShowWindow(g_overlay, show);
    }
    ShowWindow(window, show);
    UpdateWindow(window);

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return static_cast<int>(msg.wParam);
}
