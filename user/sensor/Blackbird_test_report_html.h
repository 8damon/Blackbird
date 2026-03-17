#ifndef BLACKBIRD_TEST_REPORT_HTML_H
#define BLACKBIRD_TEST_REPORT_HTML_H

#include <windows.h>

typedef enum _BLACKBIRD_REPORT_CHECK_STATUS
{
    BlackbirdReportCheckPass = 0,
    BlackbirdReportCheckFail = 1,
    BlackbirdReportCheckSkip = 2
} BLACKBIRD_REPORT_CHECK_STATUS;

typedef struct _BLACKBIRD_REPORT_META
{
    const char *Key;
    const char *Value;
} BLACKBIRD_REPORT_META;

typedef struct _BLACKBIRD_REPORT_CHECK
{
    UINT32 Id;
    BLACKBIRD_REPORT_CHECK_STATUS Status;
    const char *Text;
} BLACKBIRD_REPORT_CHECK;

BOOL BLACKBIRDWriteHtmlReport(_In_z_ const char *OutputPath, _In_z_ const char *Title,
                                _In_reads_(MetaCount) const BLACKBIRD_REPORT_META *Metadata, _In_ size_t MetaCount,
                                _In_reads_(CheckCount) const BLACKBIRD_REPORT_CHECK *Checks, _In_ size_t CheckCount);

#endif

