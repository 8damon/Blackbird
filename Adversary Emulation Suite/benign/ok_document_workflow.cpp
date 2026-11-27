#include "..\common\bkaes_sample.h"

int RunOkDocumentWorkflow()
{
    wchar_t dirName[64];
    if (FAILED(StringCchPrintfW(dirName, ARRAYSIZE(dirName), L"bkaes-doc-work-%lu", GetCurrentProcessId())))
    {
        return 1;
    }

    std::wstring dir = BkaesTempPath(dirName);
    std::wstring notes = BkaesJoinPath(dir, L"meeting-notes.txt");
    std::wstring report = BkaesJoinPath(dir, L"daily-report.csv");
    std::wstring reportFinal = BkaesJoinPath(dir, L"daily-report-final.csv");
    std::wstring settings = BkaesJoinPath(dir, L"settings.json");
    std::wstring backup = BkaesJoinPath(dir, L"meeting-notes.bak");

    CreateDirectoryW(dir.c_str(), nullptr);
    BkaesWriteTextFile(notes, "title,owner,status\r\nrelease-notes,analyst,done\r\ntriage,analyst,queued\r\n");
    BkaesWriteTextFile(report, "metric,value\r\nopen_items,4\r\nclosed_items,12\r\n");
    BkaesWriteTextFile(settings, "{\"theme\":\"system\",\"autosave\":true,\"zoom\":100}\r\n");
    CopyFileW(notes.c_str(), backup.c_str(), FALSE);
    MoveFileExW(report.c_str(), reportFinal.c_str(), MOVEFILE_REPLACE_EXISTING);
    SetFileAttributesW(settings.c_str(), FILE_ATTRIBUTE_ARCHIVE);

    DWORD checksum =
        BkaesReadFileChecksum(notes) ^ BkaesReadFileChecksum(reportFinal) ^ BkaesReadFileChecksum(settings);

    BkaesSetStringValue(HKEY_CURRENT_USER, L"Software\\BKAES\\NormalPrograms\\DocumentWorkflow", L"RecentFile",
                        reportFinal.c_str());
    BkaesSetStringValue(HKEY_CURRENT_USER, L"Software\\BKAES\\NormalPrograms\\DocumentWorkflow", L"Theme", L"system");
    BkaesQueryKeyValue(HKEY_CURRENT_USER, L"Software\\BKAES\\NormalPrograms\\DocumentWorkflow", L"RecentFile");
    BkaesQueryKeyValue(HKEY_CURRENT_USER, L"Software\\BKAES\\NormalPrograms\\DocumentWorkflow", L"Theme");

    BkaesSettleTelemetry();
    RegDeleteTreeW(HKEY_CURRENT_USER, L"Software\\BKAES\\NormalPrograms\\DocumentWorkflow");
    DeleteFileW(backup.c_str());
    DeleteFileW(settings.c_str());
    DeleteFileW(reportFinal.c_str());
    DeleteFileW(notes.c_str());
    RemoveDirectoryW(dir.c_str());
    BkaesPrint("[OK] benign document workflow completed checksum=0x%08lX\n", checksum);
    return 0;
}
