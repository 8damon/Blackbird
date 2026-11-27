#include "..\common\bkaes_sample.h"

int RunPowerShellCmdlines()
{
    static const wchar_t* commands[] = {
        L"powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand "
        L"VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIABCAEsAQQBFAFMA DownloadString Net.WebClient IEX Invoke-Expression "
        L"amsiInitFailed AmsiScanBuffer [Ref].Assembly",
        L"powershell.exe -NoProfile -EncodedCommand VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIABCAEsAQQBFAFMA",
        L"powershell.exe -NoProfile -Command \"Write-Output 'DownloadString WebClient IEX Invoke-Expression'\"",
        L"powershell.exe -NoProfile -Command \"Write-Output 'amsiInitFailed AmsiScanBuffer [Ref].Assembly'\"",
    };
    int rc = BkaesRunSuspendedCmdlines(commands, ARRAYSIZE(commands));
    BkaesSettleTelemetry();
    BkaesPrint("[OK] PowerShell command-line benchmark issued\n");
    return rc;
}
