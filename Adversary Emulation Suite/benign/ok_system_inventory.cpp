#include "..\common\bkaes_sample.h"

int RunOkSystemInventory()
{
    wchar_t computerName[128] = {};
    DWORD computerNameChars = ARRAYSIZE(computerName);
    GetComputerNameW(computerName, &computerNameChars);

    SYSTEM_INFO systemInfo = {};
    MEMORYSTATUSEX memory = {};
    memory.dwLength = sizeof(memory);
    GetNativeSystemInfo(&systemInfo);
    GlobalMemoryStatusEx(&memory);

    wchar_t drives[256] = {};
    DWORD driveChars = GetLogicalDriveStringsW(ARRAYSIZE(drives), drives);
    for (wchar_t* drive = drives; driveChars != 0 && drive < drives + driveChars && *drive != L'\0';
         drive += wcslen(drive) + 1)
    {
        ULARGE_INTEGER freeBytes = {};
        ULARGE_INTEGER totalBytes = {};
        ULARGE_INTEGER totalFreeBytes = {};
        GetDiskFreeSpaceExW(drive, &freeBytes, &totalBytes, &totalFreeBytes);
    }

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    DWORD processCount = 0;
    if (snapshot != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32W entry = {};
        entry.dwSize = sizeof(entry);
        if (Process32FirstW(snapshot, &entry))
        {
            do
            {
                ++processCount;
            } while (processCount < 64 && Process32NextW(snapshot, &entry));
        }
        CloseHandle(snapshot);
    }

    BkaesSettleTelemetry();
    BkaesPrint("[OK] benign system inventory completed computer=%ls processors=%lu memoryLoad=%lu processes=%lu\n",
               computerName, systemInfo.dwNumberOfProcessors, memory.dwMemoryLoad, processCount);
    return 0;
}
