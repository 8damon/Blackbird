#include "..\common\bkaes_sample.h"

int BkaesRunSuspendedCmdlines(const wchar_t* const* commands, size_t count)
{
    int failures = 0;
    for (size_t i = 0; i < count; ++i)
    {
        PROCESS_INFORMATION pi;
        if (BkaesCreateSuspendedProcess(commands[i], &pi))
        {
            BkaesTerminateAfterCreateTelemetry(&pi);
        }
        else
        {
            BkaesPrint("[WARN] failed command %zu err=%lu\n", i, GetLastError());
            failures += 1;
        }
    }
    return failures == (int)count ? 1 : 0;
}
