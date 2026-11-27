#include "..\common\bkaes_sample.h"

int RunOkNetworkLoopback()
{
    WSADATA data;
    if (WSAStartup(MAKEWORD(2, 2), &data) != 0)
    {
        return 1;
    }
    BkaesTryConnectLoopback(80);
    WSACleanup();
    BkaesPrint("[OK] benign loopback connect sample completed\n");
    return 0;
}
