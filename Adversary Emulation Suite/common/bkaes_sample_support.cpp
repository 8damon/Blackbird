#include "bkaes_sample.h"

bool BkaesEnvFlagEnabled(const wchar_t* name)
{
    wchar_t value[16];
    DWORD len = GetEnvironmentVariableW(name, value, ARRAYSIZE(value));
    if (len == 0 || len >= ARRAYSIZE(value))
    {
        return false;
    }

    return _wcsicmp(value, L"1") == 0 || _wcsicmp(value, L"true") == 0 || _wcsicmp(value, L"yes") == 0;
}

std::wstring BkaesGetEnvString(const wchar_t* name)
{
    DWORD needed = GetEnvironmentVariableW(name, nullptr, 0);
    if (needed == 0)
    {
        return std::wstring();
    }

    std::vector<wchar_t> buffer(needed + 1);
    DWORD len = GetEnvironmentVariableW(name, buffer.data(), (DWORD)buffer.size());
    if (len == 0 || len >= buffer.size())
    {
        return std::wstring();
    }

    return std::wstring(buffer.data(), len);
}

void BkaesWriteAuditText(const wchar_t* fileName, const char* text)
{
    std::wstring directory = BkaesGetEnvString(L"BKAES_AUDIT_JOB_DIR");
    if (directory.empty() || fileName == nullptr || fileName[0] == L'\0' || text == nullptr)
    {
        return;
    }

    std::wstring path = directory;
    if (!path.empty() && path.back() != L'\\' && path.back() != L'/')
    {
        path += L"\\";
    }
    path += fileName;
    BkaesWriteTextFile(path, text);
}

void BkaesSetStringValue(HKEY root, const wchar_t* subkey, const wchar_t* name, const wchar_t* value)
{
    HKEY key = nullptr;
    DWORD disposition = 0;
    if (RegCreateKeyExW(root, subkey, 0, nullptr, 0, KEY_ALL_ACCESS, nullptr, &key, &disposition) == ERROR_SUCCESS)
    {
        RegSetValueExW(key, name, 0, REG_SZ, (const BYTE*)value, (DWORD)((wcslen(value) + 1) * sizeof(wchar_t)));
        RegCloseKey(key);
    }
}

void BkaesQueryKeyValue(HKEY root, const wchar_t* subkey, const wchar_t* value)
{
    HKEY key = nullptr;
    BYTE buffer[128];
    DWORD size = sizeof(buffer);
    if (RegOpenKeyExW(root, subkey, 0, KEY_READ, &key) == ERROR_SUCCESS)
    {
        RegQueryValueExW(key, value, nullptr, nullptr, buffer, &size);
        RegCloseKey(key);
    }
}

void BkaesResolveProbeDomain(const wchar_t* host)
{
    addrinfoW hints = {};
    addrinfoW* result = nullptr;
    hints.ai_family = AF_UNSPEC;
    GetAddrInfoW(host, nullptr, &hints, &result);
    if (result != nullptr)
    {
        FreeAddrInfoW(result);
    }
}

void BkaesQueryServicePresence(const wchar_t* serviceName)
{
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (scm == nullptr)
    {
        return;
    }

    SC_HANDLE service = OpenServiceW(scm, serviceName, SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG);
    if (service != nullptr)
    {
        SERVICE_STATUS_PROCESS status = {};
        DWORD bytesNeeded = 0;
        QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, (LPBYTE)&status, sizeof(status), &bytesNeeded);

        BYTE configBuffer[4096] = {};
        QueryServiceConfigW(service, (LPQUERY_SERVICE_CONFIGW)configBuffer, sizeof(configBuffer), &bytesNeeded);
        CloseServiceHandle(service);
    }

    CloseServiceHandle(scm);
}

void BkaesTryConnectLoopback(USHORT port)
{
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET)
    {
        return;
    }
    sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    InetPtonW(AF_INET, L"127.0.0.1", &addr.sin_addr);
    connect(s, (sockaddr*)&addr, sizeof(addr));
    closesocket(s);
}

std::wstring BkaesJoinPath(const std::wstring& base, const wchar_t* name)
{
    if (base.empty())
    {
        return std::wstring(name != nullptr ? name : L"");
    }
    std::wstring path = base;
    wchar_t last = path.back();
    if (last != L'\\' && last != L'/')
    {
        path.push_back(L'\\');
    }
    if (name != nullptr)
    {
        path.append(name);
    }
    return path;
}

DWORD BkaesReadFileChecksum(const std::wstring& path)
{
    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                              FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE)
    {
        return 0;
    }

    BYTE buffer[512];
    DWORD read = 0;
    DWORD hash = 2166136261u;
    while (ReadFile(file, buffer, sizeof(buffer), &read, nullptr) && read != 0)
    {
        for (DWORD i = 0; i < read; ++i)
        {
            hash ^= buffer[i];
            hash *= 16777619u;
        }
    }
    CloseHandle(file);
    return hash;
}
