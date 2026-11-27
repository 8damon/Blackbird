// Synthetic entropy-transition fixture. No encryption, traversal, external input
// files, or deletion. Every write is to a handle created with CREATE_NEW here.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <objbase.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>
#pragma comment(lib, "ole32.lib")

int wmain(int argc, wchar_t **argv)
{
    const wchar_t *mode = argc > 1 ? argv[1] : L"burst";
    if (wcscmp(mode, L"burst") && wcscmp(mode, L"low") && wcscmp(mode, L"already-high") &&
        wcscmp(mode, L"single-file") && wcscmp(mode, L"slow") && wcscmp(mode, L"failed-write"))
        return 2;
    wchar_t temp[MAX_PATH], guidText[40], root[MAX_PATH], path[MAX_PATH];
    GUID guid;
    HANDLE files[16];
    unsigned char plain[1024] = {}, pattern[1024], readBack[1024];
    DWORD transferred, allowed = 0, denied = 0, unexpected = 0;
    if (!GetTempPathW(MAX_PATH, temp) || FAILED(CoCreateGuid(&guid)) ||
        !StringFromGUID2(guid, guidText, 40)) return 3;
    if (swprintf_s(root, L"%sAES-ransomware-fixture-%s", temp, guidText) < 0 ||
        !CreateDirectoryW(root, nullptr)) return 4;
    for (unsigned i = 0; i < 1024; ++i) pattern[i] = static_cast<unsigned char>(i);
    const bool alreadyHigh = !wcscmp(mode, L"already-high");
    for (unsigned i = 0; i < 16; ++i)
    {
        swprintf_s(path, L"%s\\fixture-%02u.bin", root, i);
        files[i] = CreateFileW(path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                               CREATE_NEW, FILE_ATTRIBUTE_TEMPORARY, nullptr);
        if (files[i] == INVALID_HANDLE_VALUE ||
            !WriteFile(files[i], alreadyHigh ? pattern : plain, sizeof(plain), &transferred, nullptr) ||
            transferred != sizeof(plain)) return 5;
    }
    wprintf(L"READY pid=%lu mode=%s root=%s files=16 bytesPerFile=1024 startupDelayMs=15000\n",
             GetCurrentProcessId(), mode, root);
    fflush(stdout);
    Sleep(15000); // Bounded interval for preparing observation tools.
    LARGE_INTEGER zero = {};
    LARGE_INTEGER start, stop, frequency;
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&start);
    for (unsigned i = 0; i < 16; ++i)
    {
        HANDLE file = files[!wcscmp(mode, L"single-file") ? 0 : i];
        if (!wcscmp(mode, L"single-file"))
        {
            SetFilePointerEx(file, zero, nullptr, FILE_BEGIN);
            if (!WriteFile(file, plain, sizeof(plain), &transferred, nullptr)) ++unexpected;
        }
        SetFilePointerEx(file, zero, nullptr, FILE_BEGIN);
        if (!ReadFile(file, readBack, sizeof(readBack), &transferred, nullptr) || transferred != sizeof(readBack))
        { ++unexpected; continue; }
        SetFilePointerEx(file, zero, nullptr, FILE_BEGIN);
        BOOL ok;
        if (!wcscmp(mode, L"failed-write"))
        {
            swprintf_s(path, L"%s\\fixture-%02u.bin", root, i);
            HANDLE readOnly = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                           nullptr, OPEN_EXISTING, 0, nullptr);
            if (readOnly == INVALID_HANDLE_VALUE) { ++unexpected; continue; }
            ok = WriteFile(readOnly, pattern, sizeof(pattern), &transferred, nullptr);
            DWORD error = GetLastError();
            CloseHandle(readOnly);
            SetLastError(error);
        }
        else ok = WriteFile(file, !wcscmp(mode, L"low") ? plain : pattern, sizeof(pattern), &transferred, nullptr);
        if (ok && transferred == sizeof(pattern)) ++allowed;
        else if (!ok && GetLastError() == ERROR_ACCESS_DENIED) ++denied;
        else ++unexpected;
        if (!wcscmp(mode, L"slow")) Sleep(1200);
    }
    for (HANDLE file : files) CloseHandle(file);
    QueryPerformanceCounter(&stop);
    wprintf(L"RESULT mode=%s allowed=%lu denied=%lu unexpected=%lu operationsMs=%.3f root=%s\n",
            mode, allowed, denied, unexpected,
            1000.0 * static_cast<double>(stop.QuadPart - start.QuadPart) / static_cast<double>(frequency.QuadPart), root);
    // Inspect these newly created files and remove this exact directory after testing.
    // No recursive cleanup is performed by the sample.
    return unexpected ? 6 : 0;
}
