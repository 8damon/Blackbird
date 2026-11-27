#include "..\common\bkaes_sample.h"

int RunFuzzModuleLoads()
{
    const wchar_t* names[] = {
        L"kernel32.dll",
        L"user32.dll",
        L"advapi32.dll",
        L"jscript.dll",
        L"scrobj.dll",
        L"definitely_missing_bkaes.dll",
        L"C:\\Temp\\missing.invoice.pdf.dll",
    };
    HMODULE loaded[ARRAYSIZE(names)] = {};
    for (size_t i = 0; i < ARRAYSIZE(names); ++i)
    {
        HMODULE module = LoadLibraryExW(names[i], nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (module != nullptr)
        {
            loaded[i] = module;
        }
    }
    BkaesSettleTelemetry(4000);
    for (HMODULE module : loaded)
    {
        if (module != nullptr)
        {
            FreeLibrary(module);
        }
    }
    BkaesPrint("[OK] module load fuzzer completed\n");
    return 0;
}
