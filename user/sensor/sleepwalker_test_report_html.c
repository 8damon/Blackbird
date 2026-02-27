#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include "sleepwalker_test_report_html.h"

static VOID SLEEPWALKERHtmlWriteEscaped(_In_ FILE *File, _In_z_ const char *Text)
{
    const unsigned char *p;

    if (File == NULL || Text == NULL)
    {
        return;
    }

    for (p = (const unsigned char *)Text; *p != '\0'; ++p)
    {
        switch (*p)
        {
        case '&':
            (void)fputs("&amp;", File);
            break;
        case '<':
            (void)fputs("&lt;", File);
            break;
        case '>':
            (void)fputs("&gt;", File);
            break;
        case '"':
            (void)fputs("&quot;", File);
            break;
        case '\'':
            (void)fputs("&#39;", File);
            break;
        default:
            (void)fputc(*p, File);
            break;
        }
    }
}

static const char *SLEEPWALKERHtmlStatusText(_In_ SLEEPWALKER_REPORT_CHECK_STATUS Status)
{
    switch (Status)
    {
    case SleepwalkerReportCheckPass:
        return "PASS";
    case SleepwalkerReportCheckFail:
        return "FAIL";
    case SleepwalkerReportCheckSkip:
        return "SKIP";
    default:
        return "UNKNOWN";
    }
}

static const char *SLEEPWALKERHtmlStatusClass(_In_ SLEEPWALKER_REPORT_CHECK_STATUS Status)
{
    switch (Status)
    {
    case SleepwalkerReportCheckPass:
        return "pass";
    case SleepwalkerReportCheckFail:
        return "fail";
    case SleepwalkerReportCheckSkip:
        return "skip";
    default:
        return "unknown";
    }
}

BOOL SLEEPWALKERWriteHtmlReport(_In_z_ const char *OutputPath, _In_z_ const char *Title,
                                _In_reads_(MetaCount) const SLEEPWALKER_REPORT_META *Metadata, _In_ size_t MetaCount,
                                _In_reads_(CheckCount) const SLEEPWALKER_REPORT_CHECK *Checks, _In_ size_t CheckCount)
{
    FILE *f;
    size_t i;

    if (OutputPath == NULL || Title == NULL)
    {
        return FALSE;
    }

    f = fopen(OutputPath, "w");
    if (f == NULL)
    {
        return FALSE;
    }

    (void)fputs("<!doctype html>\n"
                "<html lang=\"en\">\n"
                "<head>\n"
                "  <meta charset=\"utf-8\" />\n"
                "  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />\n"
                "  <title>",
                f);
    SLEEPWALKERHtmlWriteEscaped(f, Title);
    (void)fputs(
        "</title>\n"
        "  <style>\n"
        "    body { font-family: Segoe UI, Tahoma, sans-serif; margin: 26px; color: #1f2937; background: #f7fafc; }\n"
        "    .card { background: #fff; border: 1px solid #e5e7eb; border-radius: 12px; padding: 18px; }\n"
        "    h1, h2 { margin: 0 0 12px 0; }\n"
        "    table { width: 100%; border-collapse: collapse; }\n"
        "    th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid #e5e7eb; }\n"
        "    .meta th { width: 32%; font-weight: 600; }\n"
        "    .checks thead th { background: #f3f4f6; }\n"
        "    .checks tbody tr.pass { background: #ecfdf3; }\n"
        "    .checks tbody tr.fail { background: #fef2f2; }\n"
        "    .checks tbody tr.skip { background: #fff7ed; }\n"
        "    .checks td.status { font-weight: 700; }\n"
        "    .checks tr.pass td.status { color: #166534; }\n"
        "    .checks tr.fail td.status { color: #991b1b; }\n"
        "    .checks tr.skip td.status { color: #9a3412; }\n"
        "    .mono { font-family: ui-monospace, SFMono-Regular, Consolas, monospace; }\n"
        "  </style>\n"
        "</head>\n"
        "<body>\n"
        "  <div class=\"card\">\n"
        "    <h1>",
        f);
    SLEEPWALKERHtmlWriteEscaped(f, Title);
    (void)fputs("</h1>\n"
                "    <table class=\"meta\">\n"
                "      <tbody>\n",
                f);

    for (i = 0; i < MetaCount; ++i)
    {
        const char *key = (Metadata != NULL && Metadata[i].Key != NULL) ? Metadata[i].Key : "";
        const char *value = (Metadata != NULL && Metadata[i].Value != NULL) ? Metadata[i].Value : "";
        (void)fputs("        <tr><th>", f);
        SLEEPWALKERHtmlWriteEscaped(f, key);
        (void)fputs("</th><td>", f);
        SLEEPWALKERHtmlWriteEscaped(f, value);
        (void)fputs("</td></tr>\n", f);
    }

    (void)fputs("      </tbody>\n"
                "    </table>\n"
                "    <h2>Checks</h2>\n"
                "    <table class=\"checks\">\n"
                "      <thead>\n"
                "        <tr><th>ID</th><th>Status</th><th>Check</th></tr>\n"
                "      </thead>\n"
                "      <tbody>\n",
                f);

    for (i = 0; i < CheckCount; ++i)
    {
        const char *cls = SLEEPWALKERHtmlStatusClass(Checks[i].Status);
        const char *status = SLEEPWALKERHtmlStatusText(Checks[i].Status);
        const char *text = (Checks[i].Text != NULL) ? Checks[i].Text : "";

        fprintf(f, "        <tr class=\"%s\"><td class=\"mono\">T%04lu</td><td class=\"status\">", cls,
                (unsigned long)Checks[i].Id);
        SLEEPWALKERHtmlWriteEscaped(f, status);
        (void)fputs("</td><td>", f);
        SLEEPWALKERHtmlWriteEscaped(f, text);
        (void)fputs("</td></tr>\n", f);
    }

    (void)fputs("      </tbody>\n"
                "    </table>\n"
                "  </div>\n"
                "</body>\n"
                "</html>\n",
                f);

    fclose(f);
    return TRUE;
}
