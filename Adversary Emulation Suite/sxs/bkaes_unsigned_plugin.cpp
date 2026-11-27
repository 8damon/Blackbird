#include "../common/bkaes_common.h"

extern "C" __declspec(dllexport) DWORD BkaesPluginMarker()
{
    return GetCurrentProcessId();
}

extern "C" __declspec(dllexport) LRESULT CALLBACK BkaesNoopHookProc(int code, WPARAM wParam, LPARAM lParam)
{
    return CallNextHookEx(nullptr, code, wParam, lParam);
}

extern "C" __declspec(dllexport) void CALLBACK BkaesNoopWinEventProc(HWINEVENTHOOK hook, DWORD event, HWND window,
                                                                      LONG objectId, LONG childId,
                                                                      DWORD eventThread, DWORD eventTime)
{
    UNREFERENCED_PARAMETER(hook);
    UNREFERENCED_PARAMETER(event);
    UNREFERENCED_PARAMETER(window);
    UNREFERENCED_PARAMETER(objectId);
    UNREFERENCED_PARAMETER(childId);
    UNREFERENCED_PARAMETER(eventThread);
    UNREFERENCED_PARAMETER(eventTime);
}

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID reserved)
{
    UNREFERENCED_PARAMETER(module);
    UNREFERENCED_PARAMETER(reserved);

    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(module);
    }
    return TRUE;
}
