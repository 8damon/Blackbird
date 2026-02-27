#ifndef SLEEPWALKER_TEST_REPORT_HTML_H
#define SLEEPWALKER_TEST_REPORT_HTML_H

#include <windows.h>

typedef enum _SLEEPWALKER_REPORT_CHECK_STATUS
{
    SleepwalkerReportCheckPass = 0,
    SleepwalkerReportCheckFail = 1,
    SleepwalkerReportCheckSkip = 2
} SLEEPWALKER_REPORT_CHECK_STATUS;

typedef struct _SLEEPWALKER_REPORT_META
{
    const char *Key;
    const char *Value;
} SLEEPWALKER_REPORT_META;

typedef struct _SLEEPWALKER_REPORT_CHECK
{
    UINT32 Id;
    SLEEPWALKER_REPORT_CHECK_STATUS Status;
    const char *Text;
} SLEEPWALKER_REPORT_CHECK;

BOOL SLEEPWALKERWriteHtmlReport(_In_z_ const char *OutputPath, _In_z_ const char *Title,
                                _In_reads_(MetaCount) const SLEEPWALKER_REPORT_META *Metadata, _In_ size_t MetaCount,
                                _In_reads_(CheckCount) const SLEEPWALKER_REPORT_CHECK *Checks, _In_ size_t CheckCount);

#endif
