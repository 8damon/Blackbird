#include "..\common\bkaes_sample.h"

int RunOkSystemDllLoads()
{
    wchar_t systemDir[MAX_PATH];
    UINT len = GetSystemDirectoryW(systemDir, ARRAYSIZE(systemDir));
    if (len == 0 || len >= ARRAYSIZE(systemDir))
    {
        return 1;
    }

    const wchar_t* names[] = {
        L"version.dll", L"winhttp.dll", L"crypt32.dll", L"userenv.dll", L"iphlpapi.dll",
    };
    HMODULE loaded[ARRAYSIZE(names)] = {};
    std::wstring base(systemDir, len);
    for (size_t i = 0; i < ARRAYSIZE(names); ++i)
    {
        std::wstring fullPath = BkaesJoinPath(base, names[i]);
        HMODULE module = LoadLibraryW(fullPath.c_str());
        if (module != nullptr)
        {
            loaded[i] = module;
            GetProcAddress(module, "DllGetVersion");
        }
    }

    BkaesSettleTelemetry();
    for (HMODULE module : loaded)
    {
        if (module != nullptr)
        {
            FreeLibrary(module);
        }
    }
    BkaesPrint("[OK] benign system DLL load sample completed\n");
    return 0;
}
