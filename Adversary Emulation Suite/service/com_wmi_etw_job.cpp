#include "..\common\bkaes_sample.h"

int RunComWmiEtwJob()
{
    GUID provider = {0x2fbc5e65, 0xf48c, 0x45a6, {0xb5, 0x84, 0x13, 0x37, 0x42, 0x10, 0x00, 0x01}};
    REGHANDLE reg = 0;
    TRACEHANDLE trace = 0;
    BYTE propsBuffer[sizeof(EVENT_TRACE_PROPERTIES) + 256] = {};
    auto props = (EVENT_TRACE_PROPERTIES*)propsBuffer;
    wchar_t sessionName[] = L"BKAES_Benchmark_ETW";

    CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    CoInitializeSecurity(nullptr, -1, nullptr, nullptr, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IDENTIFY, nullptr,
                         EOAC_NONE, nullptr);
    IWbemLocator* locator = nullptr;
    CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (void**)&locator);
    if (locator != nullptr)
    {
        locator->Release();
    }

    EventRegister(&provider, nullptr, nullptr, &reg);
    EventUnregister(reg);

    props->Wnode.BufferSize = sizeof(propsBuffer);
    props->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    wcscpy_s((wchar_t*)(propsBuffer + props->LoggerNameOffset), 128, sessionName);
    if (StartTraceW(&trace, sessionName, props) == ERROR_SUCCESS)
    {
        EnableTraceEx2(trace, &provider, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_INFORMATION, 0, 0, 0, nullptr);
        ControlTraceW(trace, sessionName, props, EVENT_TRACE_CONTROL_STOP);
    }
    else
    {
        EnableTraceEx2(0, &provider, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_INFORMATION, 0, 0, 0, nullptr);
    }

    HANDLE job = CreateJobObjectW(nullptr, L"BKAES_Benchmark_Job");
    if (job != nullptr)
    {
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION info = {};
        SetInformationJobObject(job, JobObjectExtendedLimitInformation, &info, sizeof(info));
        CloseHandle(job);
    }
    BkaesSettleTelemetry();
    CoUninitialize();
    BkaesPrint("[OK] COM/WMI/ETW/job-object activity issued\n");
    return 0;
}
