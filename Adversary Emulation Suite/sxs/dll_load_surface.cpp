#include "..\common\bkaes_sample.h"

int RunDllLoadSurface()
{
    std::wstring dir = BkaesSelfDirectory();
    std::wstring plugin = dir + L"\\bb_unsigned_plugin.dll";
    std::wstring version = dir + L"\\version.dll";
    std::wstring invoice = dir + L"\\invoice.pdf.dll";
    HMODULE loaded[4] = {};

    loaded[0] = LoadLibraryW(plugin.c_str());
    loaded[1] = LoadLibraryW(version.c_str());
    loaded[2] = LoadLibraryW(invoice.c_str());
    loaded[3] = LoadLibraryW(L"jscript.dll");

    BkaesPrint("[OK] DLL load surface plugin=%p version=%p invoice=%p jscript=%p\n", loaded[0], loaded[1], loaded[2],
               loaded[3]);
    BkaesSettleTelemetry(4000);
    for (HMODULE module : loaded)
    {
        if (module != nullptr)
        {
            FreeLibrary(module);
        }
    }
    return 0;
}
