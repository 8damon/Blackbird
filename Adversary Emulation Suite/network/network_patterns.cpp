#include "..\common\bkaes_sample.h"

int RunNetworkPatterns()
{
    WSADATA data;
    if (WSAStartup(MAKEWORD(2, 2), &data) != 0)
    {
        return 1;
    }

    addrinfoW hints = {};
    addrinfoW* result = nullptr;
    hints.ai_family = AF_UNSPEC;
    GetAddrInfoW(L"a8f31c2e74b94d1f9bbca6e071d4bkaes.invalid", nullptr, &hints, &result);
    if (result != nullptr)
    {
        FreeAddrInfoW(result);
    }

    const USHORT ports[] = {4444, 3389, 5985, 445};
    for (USHORT port : ports)
    {
        BkaesTryConnectLoopback(port);
    }
    for (int i = 0; i < 5; ++i)
    {
        BkaesTryConnectLoopback(9);
        Sleep(1000);
    }

    BkaesSettleTelemetry();
    WSACleanup();
    BkaesPrint("[OK] network pattern attempts issued over loopback/reserved names\n");
    return 0;
}
