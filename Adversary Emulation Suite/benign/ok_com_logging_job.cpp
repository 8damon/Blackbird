#include "..\common\bkaes_sample.h"

int RunOkComLoggingJob()
{
    GUID provider = {0x34d3a3d9, 0x2450, 0x4d86, {0x8a, 0x1f, 0x31, 0x71, 0x45, 0x67, 0x90, 0x21}};
    GUID shellLink = {0x00021401, 0x0000, 0x0000, {0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}};
    GUID iidUnknown = {0x00000000, 0x0000, 0x0000, {0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}};
    REGHANDLE reg = 0;
    HRESULT co = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);

    if (SUCCEEDED(co))
    {
        IUnknown* unknown = nullptr;
        CoCreateInstance(shellLink, nullptr, CLSCTX_INPROC_SERVER, iidUnknown, (void**)&unknown);
        if (unknown != nullptr)
        {
            unknown->Release();
        }
    }

    if (EventRegister(&provider, nullptr, nullptr, &reg) == ERROR_SUCCESS && reg != 0)
    {
        EventUnregister(reg);
    }

    wchar_t jobName[64];
    if (SUCCEEDED(StringCchPrintfW(jobName, ARRAYSIZE(jobName), L"BKAES_Normal_Job_%lu", GetCurrentProcessId())))
    {
        HANDLE job = CreateJobObjectW(nullptr, jobName);
        if (job != nullptr)
        {
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION info = {};
            SetInformationJobObject(job, JobObjectExtendedLimitInformation, &info, sizeof(info));
            CloseHandle(job);
        }
    }

    BkaesSettleTelemetry();
    if (SUCCEEDED(co))
    {
        CoUninitialize();
    }
    BkaesPrint("[OK] benign COM logging/job sample completed\n");
    return 0;
}
