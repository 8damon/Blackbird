#include "..\common\bkaes_sample.h"

int RunBeaconLoopbackPattern()
{
    WSADATA data;
    if (WSAStartup(MAKEWORD(2, 2), &data) != 0)
    {
        return 1;
    }

    BkaesResolveProbeDomain(L"bkaes-beacon-7f3b2c9d1a.invalid");

    for (int i = 0; i < 8; ++i)
    {
        BkaesTryConnectLoopback(443);
        Sleep(900);
    }

    BkaesSettleTelemetry();
    WSACleanup();
    BkaesPrint("[OK] loopback beacon timing pattern completed\n");
    return 0;
}
