#include "..\common\bkaes_sample.h"

static DWORD WINAPI BkaesLoopbackServerThread(void* param)
{
    SOCKET listener = static_cast<SOCKET>(reinterpret_cast<UINT_PTR>(param));
    SOCKET client = accept(listener, nullptr, nullptr);
    if (client != INVALID_SOCKET)
    {
        char request[128];
        recv(client, request, sizeof(request), 0);
        const char response[] = "HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nOK";
        send(client, response, (int)strlen(response), 0);
        closesocket(client);
    }
    return 0;
}

int RunOkLocalhostService()
{
    WSADATA data;
    if (WSAStartup(MAKEWORD(2, 2), &data) != 0)
    {
        return 1;
    }

    SOCKET listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listener == INVALID_SOCKET)
    {
        WSACleanup();
        return 1;
    }

    sockaddr_in server = {};
    server.sin_family = AF_INET;
    server.sin_port = 0;
    InetPtonW(AF_INET, L"127.0.0.1", &server.sin_addr);
    if (bind(listener, (sockaddr*)&server, sizeof(server)) != 0 || listen(listener, 1) != 0)
    {
        closesocket(listener);
        WSACleanup();
        return 1;
    }

    int serverLen = sizeof(server);
    getsockname(listener, (sockaddr*)&server, &serverLen);
    HANDLE thread = CreateThread(nullptr, 0, BkaesLoopbackServerThread,
                                 reinterpret_cast<void*>(static_cast<UINT_PTR>(listener)), 0, nullptr);

    SOCKET client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (client != INVALID_SOCKET)
    {
        if (connect(client, (sockaddr*)&server, sizeof(server)) == 0)
        {
            const char request[] = "GET /health HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n";
            char response[128];
            send(client, request, (int)strlen(request), 0);
            recv(client, response, sizeof(response), 0);
        }
        closesocket(client);
    }

    if (thread != nullptr)
    {
        WaitForSingleObject(thread, 2500);
        CloseHandle(thread);
    }
    closesocket(listener);
    BkaesSettleTelemetry();
    WSACleanup();
    BkaesPrint("[OK] benign localhost client/server sample completed port=%u\n", ntohs(server.sin_port));
    return 0;
}
