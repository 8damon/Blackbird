#ifndef BK_TEST_REPORT_HTML_H
#define BK_TEST_REPORT_HTML_H

#include <windows.h>

typedef enum _BK_REPORT_CHECK_STATUS
{
    BlackbirdReportCheckPass = 0,
    BlackbirdReportCheckFail = 1,
    BlackbirdReportCheckSkip = 2
} BK_REPORT_CHECK_STATUS;

typedef struct _BK_REPORT_META
{
    const char *Key;
    const char *Value;
} BK_REPORT_META;

typedef struct _BK_REPORT_CHECK
{
    UINT32 Id;
    BK_REPORT_CHECK_STATUS Status;
    const char *Text;
} BK_REPORT_CHECK;

BOOL BkhtmlWriteReport(_In_z_ const char *OutputPath, _In_z_ const char *Title,
                       _In_reads_(MetaCount) const BK_REPORT_META *Metadata, _In_ size_t MetaCount,
                       _In_reads_(CheckCount) const BK_REPORT_CHECK *Checks, _In_ size_t CheckCount);

#endif
