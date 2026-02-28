static unsigned __int64 SuiteReadCycles(_In_ const SUITE_RESULTS *Results)
{
#if defined(_M_X64) || defined(_M_IX86)
    if (Results != NULL && Results->CycleCounterAvailable)
    {
        return __rdtsc();
    }
#else
    UNREFERENCED_PARAMETER(Results);
#endif
    return 0;
}

typedef struct _SLEEPWALKER_MULTI_CLIENT_WORKER
{
    HANDLE Device;
    DWORD MaxMs;
    BOOL SawHandle;
    BOOL SawThread;
    DWORD Polls;
    DWORD UnexpectedError;
} SLEEPWALKER_MULTI_CLIENT_WORKER;

typedef NTSTATUS(NTAPI *SLEEPWALKER_NT_QUERY_SYSTEM_INFORMATION_FN)(
    _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
    _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation, _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength);

typedef NTSTATUS(NTAPI *SLEEPWALKER_RTL_GET_VERSION_FN)(_Inout_ PRTL_OSVERSIONINFOW VersionInformation);

typedef struct _SLEEPWALKER_SYSTEM_CODEINTEGRITY_INFORMATION
{
    ULONG Length;
    ULONG CodeIntegrityOptions;
} SLEEPWALKER_SYSTEM_CODEINTEGRITY_INFORMATION;

typedef struct _SLEEPWALKER_SYSTEM_KERNEL_DEBUGGER_INFORMATION
{
    BOOLEAN KernelDebuggerEnabled;
    BOOLEAN KernelDebuggerNotPresent;
} SLEEPWALKER_SYSTEM_KERNEL_DEBUGGER_INFORMATION;

static BOOL GenerateMemoryHandleIntent(DWORD pid);
static BOOL GenerateRemoteThreadLoadLibraryIntent(DWORD pid);
static BOOL GenerateVmApiCallSurface(DWORD pid);

static BOOL GetEtwAnsiProperty(_In_ PEVENT_RECORD Record, _In_z_ PCWSTR Name, _Out_writes_z_(OutputChars) PSTR Output,
                               _In_ size_t OutputChars)
{
    TDHSTATUS status;
    PROPERTY_DATA_DESCRIPTOR descriptor;
    ULONG propertySize = 0;
    PBYTE propertyRaw = NULL;
    BOOL ok = FALSE;

    if (Record == NULL || Name == NULL || Output == NULL || OutputChars == 0)
    {
        return FALSE;
    }
    Output[0] = '\0';

    ZeroMemory(&descriptor, sizeof(descriptor));
    descriptor.PropertyName = (ULONGLONG)(ULONG_PTR)Name;
    descriptor.ArrayIndex = ULONG_MAX;

    status = TdhGetPropertySize(Record, 0, NULL, 1, &descriptor, &propertySize);
    if (status != ERROR_SUCCESS || propertySize == 0)
    {
        return FALSE;
    }

    propertyRaw = (PBYTE)malloc(propertySize + 1);
    if (propertyRaw == NULL)
    {
        return FALSE;
    }
    ZeroMemory(propertyRaw, propertySize + 1);

    status = TdhGetProperty(Record, 0, NULL, 1, &descriptor, propertySize, propertyRaw);
    if (status == ERROR_SUCCESS)
    {
        (void)StringCchCopyA(Output, OutputChars, (PCSTR)propertyRaw);
        ok = TRUE;
    }

    free(propertyRaw);
    return ok;
}

static VOID SuiteFreeCollectedData(_Inout_ SUITE_RESULTS *Results)
{
    size_t i;

    if (Results == NULL)
    {
        return;
    }

    if (Results->Meta != NULL)
    {
        for (i = 0; i < Results->MetaCount; ++i)
        {
            if (Results->Meta[i].Key != NULL)
            {
                free((void *)Results->Meta[i].Key);
                Results->Meta[i].Key = NULL;
            }
            if (Results->Meta[i].Value != NULL)
            {
                free((void *)Results->Meta[i].Value);
                Results->Meta[i].Value = NULL;
            }
        }
        free(Results->Meta);
        Results->Meta = NULL;
        Results->MetaCount = 0;
        Results->MetaCapacity = 0;
    }

    if (Results->Checks != NULL)
    {
        for (i = 0; i < Results->CheckCount; ++i)
        {
            if (Results->Checks[i].Text != NULL)
            {
                free((void *)Results->Checks[i].Text);
                Results->Checks[i].Text = NULL;
            }
        }
        free(Results->Checks);
        Results->Checks = NULL;
        Results->CheckCount = 0;
        Results->CheckCapacity = 0;
    }
}

static char *SuiteDupString(_In_z_ const char *Text)
{
    size_t len;
    char *copy;

    if (Text == NULL)
    {
        return NULL;
    }

    len = strlen(Text);
    copy = (char *)malloc(len + 1);
    if (copy == NULL)
    {
        return NULL;
    }
    (void)memcpy(copy, Text, len + 1);
    return copy;
}

static BOOL SuiteEnsureMetaCapacity(_Inout_ SUITE_RESULTS *Results)
{
    SLEEPWALKER_REPORT_META *grown;
    size_t nextCapacity;

    if (Results == NULL)
    {
        return FALSE;
    }

    if (Results->MetaCount < Results->MetaCapacity)
    {
        return TRUE;
    }

    nextCapacity = (Results->MetaCapacity == 0) ? 16 : (Results->MetaCapacity * 2);
    grown = (SLEEPWALKER_REPORT_META *)realloc(Results->Meta, nextCapacity * sizeof(SLEEPWALKER_REPORT_META));
    if (grown == NULL)
    {
        return FALSE;
    }

    ZeroMemory(grown + Results->MetaCapacity, (nextCapacity - Results->MetaCapacity) * sizeof(SLEEPWALKER_REPORT_META));
    Results->Meta = grown;
    Results->MetaCapacity = nextCapacity;
    return TRUE;
}

static BOOL SuiteEnsureCheckCapacity(_Inout_ SUITE_RESULTS *Results)
{
    SLEEPWALKER_REPORT_CHECK *grown;
    size_t nextCapacity;

    if (Results == NULL)
    {
        return FALSE;
    }

    if (Results->CheckCount < Results->CheckCapacity)
    {
        return TRUE;
    }

    nextCapacity = (Results->CheckCapacity == 0) ? 64 : (Results->CheckCapacity * 2);
    grown = (SLEEPWALKER_REPORT_CHECK *)realloc(Results->Checks, nextCapacity * sizeof(SLEEPWALKER_REPORT_CHECK));
    if (grown == NULL)
    {
        return FALSE;
    }

    ZeroMemory(grown + Results->CheckCapacity,
               (nextCapacity - Results->CheckCapacity) * sizeof(SLEEPWALKER_REPORT_CHECK));
    Results->Checks = grown;
    Results->CheckCapacity = nextCapacity;
    return TRUE;
}

static const char *SuiteCheckStatusText(_In_ SLEEPWALKER_REPORT_CHECK_STATUS Status)
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

static INT SuiteCheckSortPriority(_In_ SLEEPWALKER_REPORT_CHECK_STATUS Status)
{
    switch (Status)
    {
    case SleepwalkerReportCheckFail:
        return 0;
    case SleepwalkerReportCheckSkip:
        return 1;
    case SleepwalkerReportCheckPass:
        return 2;
    default:
        return 3;
    }
}

static int __cdecl SuiteCompareChecks(_In_ const VOID *Left, _In_ const VOID *Right)
{
    const SLEEPWALKER_REPORT_CHECK *a = (const SLEEPWALKER_REPORT_CHECK *)Left;
    const SLEEPWALKER_REPORT_CHECK *b = (const SLEEPWALKER_REPORT_CHECK *)Right;
    INT ap;
    INT bp;

    ap = SuiteCheckSortPriority(a->Status);
    bp = SuiteCheckSortPriority(b->Status);
    if (ap != bp)
    {
        return ap - bp;
    }
    if (a->Id < b->Id)
    {
        return -1;
    }
    if (a->Id > b->Id)
    {
        return 1;
    }
    return 0;
}

static BOOL SuiteBuildSortedChecks(_In_ const SUITE_RESULTS *Results,
                                   _Outptr_result_buffer_(*OutCount) SLEEPWALKER_REPORT_CHECK **OutChecks,
                                   _Out_ size_t *OutCount)
{
    SLEEPWALKER_REPORT_CHECK *sorted;

    if (Results == NULL || OutChecks == NULL || OutCount == NULL)
    {
        return FALSE;
    }

    *OutChecks = NULL;
    *OutCount = 0;
    if (Results->CheckCount == 0)
    {
        return TRUE;
    }

    sorted = (SLEEPWALKER_REPORT_CHECK *)malloc(Results->CheckCount * sizeof(SLEEPWALKER_REPORT_CHECK));
    if (sorted == NULL)
    {
        return FALSE;
    }

    (void)memcpy(sorted, Results->Checks, Results->CheckCount * sizeof(SLEEPWALKER_REPORT_CHECK));
    qsort(sorted, Results->CheckCount, sizeof(SLEEPWALKER_REPORT_CHECK), SuiteCompareChecks);

    *OutChecks = sorted;
    *OutCount = Results->CheckCount;
    return TRUE;
}

static VOID SuiteLogMetaLine(_Inout_opt_ SUITE_RESULTS *Results, _In_z_ const char *Key, _In_z_ const char *Value)
{
    char *keyCopy;
    char *valueCopy;

    if (Key == NULL || Value == NULL)
    {
        return;
    }

    printf("%s=%s\n", Key, Value);

    if (Results != NULL && Results->Report != NULL)
    {
        fprintf(Results->Report, "%s=%s\n", Key, Value);
        fflush(Results->Report);
    }

    if (Results == NULL)
    {
        return;
    }

    if (!SuiteEnsureMetaCapacity(Results))
    {
        return;
    }

    keyCopy = SuiteDupString(Key);
    valueCopy = SuiteDupString(Value);
    if (keyCopy == NULL || valueCopy == NULL)
    {
        if (keyCopy != NULL)
        {
            free(keyCopy);
        }
        if (valueCopy != NULL)
        {
            free(valueCopy);
        }
        return;
    }

    Results->Meta[Results->MetaCount].Key = keyCopy;
    Results->Meta[Results->MetaCount].Value = valueCopy;
    Results->MetaCount += 1;
}

static VOID SuiteRecordCheck(_Inout_opt_ SUITE_RESULTS *Results, _In_ SLEEPWALKER_REPORT_CHECK_STATUS Status,
                             _In_z_ const char *Text)
{
    UINT32 id;
    const char *statusText;
    char *textCopy;
    char rendered[768];
    double deltaMs = 0.0;
    double suiteMs = 0.0;
    unsigned __int64 deltaCycles = 0;
    ULONGLONG nowQpc = 0;
    unsigned __int64 nowCycles = 0;

    if (Text == NULL)
    {
        return;
    }

    id = (Results != NULL) ? (++Results->NextCheckId) : 0;
    statusText = SuiteCheckStatusText(Status);

    if (Results != NULL && Results->QpcFrequency.QuadPart > 0)
    {
        LARGE_INTEGER qpcNow;
        QueryPerformanceCounter(&qpcNow);
        nowQpc = (ULONGLONG)qpcNow.QuadPart;
        if (Results->LastCheckQpc != 0 && nowQpc >= Results->LastCheckQpc)
        {
            deltaMs = ((double)(nowQpc - Results->LastCheckQpc) * 1000.0) / (double)Results->QpcFrequency.QuadPart;
        }
        if (Results->SuiteStartQpc != 0 && nowQpc >= Results->SuiteStartQpc)
        {
            suiteMs = ((double)(nowQpc - Results->SuiteStartQpc) * 1000.0) / (double)Results->QpcFrequency.QuadPart;
        }
        Results->LastCheckQpc = nowQpc;
    }

    if (Results != NULL && Results->CycleCounterAvailable)
    {
        nowCycles = SuiteReadCycles(Results);
        if (Results->LastCheckCycles != 0 && nowCycles >= Results->LastCheckCycles)
        {
            deltaCycles = nowCycles - Results->LastCheckCycles;
        }
        Results->LastCheckCycles = nowCycles;
    }

    if (Results != NULL && Results->CycleCounterAvailable)
    {
        (void)sprintf_s(rendered, RTL_NUMBER_OF(rendered), "%s [+%.3fms suite=%.3fms +%llu cyc]", Text, deltaMs,
                        suiteMs, (unsigned long long)deltaCycles);
    }
    else
    {
        (void)sprintf_s(rendered, RTL_NUMBER_OF(rendered), "%s [+%.3fms suite=%.3fms]", Text, deltaMs, suiteMs);
    }

    if (id != 0)
    {
        printf("[%s][T%04lu] %s\n", statusText, (unsigned long)id, rendered);
    }
    else
    {
        printf("[%s] %s\n", statusText, rendered);
    }

    if (Results == NULL)
    {
        return;
    }

    if (!SuiteEnsureCheckCapacity(Results))
    {
        return;
    }

    textCopy = SuiteDupString(rendered);
    if (textCopy == NULL)
    {
        return;
    }

    Results->Checks[Results->CheckCount].Id = id;
    Results->Checks[Results->CheckCount].Status = Status;
    Results->Checks[Results->CheckCount].Text = textCopy;
    Results->CheckCount += 1;
}

static BOOL QueryRegSzA(_In_z_ const char *SubKey, _In_z_ const char *ValueName, _Out_writes_z_(OutChars) char *Out,
                        _In_ size_t OutChars)
{
    DWORD bytes;
    LSTATUS status;

    if (SubKey == NULL || ValueName == NULL || Out == NULL || OutChars == 0)
    {
        return FALSE;
    }

    bytes = (DWORD)OutChars;
    Out[0] = '\0';
    status = RegGetValueA(HKEY_LOCAL_MACHINE, SubKey, ValueName, RRF_RT_REG_SZ, NULL, Out, &bytes);
    return (status == ERROR_SUCCESS);
}

static BOOL QueryRegDword(_In_z_ const char *SubKey, _In_z_ const char *ValueName, _Out_ DWORD *Value)
{
    DWORD bytes;
    LSTATUS status;

    if (SubKey == NULL || ValueName == NULL || Value == NULL)
    {
        return FALSE;
    }

    bytes = sizeof(*Value);
    *Value = 0;
    status = RegGetValueA(HKEY_LOCAL_MACHINE, SubKey, ValueName, RRF_RT_REG_DWORD, NULL, Value, &bytes);
    return (status == ERROR_SUCCESS);
}

static BOOL QueryKernelImageVersion(_Out_ DWORD *Major, _Out_ DWORD *Minor, _Out_ DWORD *Build, _Out_ DWORD *Revision)
{
    WCHAR sysDir[MAX_PATH];
    WCHAR path[MAX_PATH];
    const WCHAR *names[] = {L"ntoskrnl.exe", L"ntkrnlmp.exe"};
    DWORD i;

    if (Major == NULL || Minor == NULL || Build == NULL || Revision == NULL)
    {
        return FALSE;
    }
    *Major = 0;
    *Minor = 0;
    *Build = 0;
    *Revision = 0;

    if (GetSystemDirectoryW(sysDir, RTL_NUMBER_OF(sysDir)) == 0)
    {
        return FALSE;
    }

    for (i = 0; i < RTL_NUMBER_OF(names); ++i)
    {
        DWORD handle = 0;
        DWORD size;
        BYTE *blob;
        VS_FIXEDFILEINFO *ffi = NULL;
        UINT ffiSize = 0;

        if (swprintf_s(path, RTL_NUMBER_OF(path), L"%ls\\%ls", sysDir, names[i]) < 0)
        {
            continue;
        }

        size = GetFileVersionInfoSizeW(path, &handle);
        if (size == 0)
        {
            continue;
        }

        blob = (BYTE *)malloc(size);
        if (blob == NULL)
        {
            return FALSE;
        }

        if (!GetFileVersionInfoW(path, 0, size, blob))
        {
            free(blob);
            continue;
        }
        if (!VerQueryValueW(blob, L"\\", (LPVOID *)&ffi, &ffiSize) || ffi == NULL || ffiSize < sizeof(*ffi))
        {
            free(blob);
            continue;
        }

        *Major = HIWORD(ffi->dwFileVersionMS);
        *Minor = LOWORD(ffi->dwFileVersionMS);
        *Build = HIWORD(ffi->dwFileVersionLS);
        *Revision = LOWORD(ffi->dwFileVersionLS);
        free(blob);
        return TRUE;
    }

    return FALSE;
}

static VOID LogEnvironmentBaseline(_Inout_ SUITE_RESULTS *Results)
{
    OSVERSIONINFOEXW osw;
    SYSTEM_INFO si;
    HMODULE ntdll;
    SLEEPWALKER_RTL_GET_VERSION_FN rtlGetVersion;
    SLEEPWALKER_NT_QUERY_SYSTEM_INFORMATION_FN ntQuerySystemInformation;
    SLEEPWALKER_SYSTEM_CODEINTEGRITY_INFORMATION ci;
    SLEEPWALKER_SYSTEM_KERNEL_DEBUGGER_INFORMATION kdInfo;
    char line[512];
    char arch[32];
    char productName[128];
    char displayVersion[64];
    char currentBuild[32];
    DWORD ubr;
    DWORD kmj, kmn, kbd, krv;
    NTSTATUS status;

    ZeroMemory(&osw, sizeof(osw));
    osw.dwOSVersionInfoSize = sizeof(osw);
    ZeroMemory(&ci, sizeof(ci));
    ci.Length = sizeof(ci);
    ZeroMemory(&kdInfo, sizeof(kdInfo));
    ZeroMemory(productName, sizeof(productName));
    ZeroMemory(displayVersion, sizeof(displayVersion));
    ZeroMemory(currentBuild, sizeof(currentBuild));
    ubr = 0;

    GetNativeSystemInfo(&si);
    switch (si.wProcessorArchitecture)
    {
    case PROCESSOR_ARCHITECTURE_AMD64:
        (void)strcpy_s(arch, RTL_NUMBER_OF(arch), "x64");
        break;
    case PROCESSOR_ARCHITECTURE_ARM64:
        (void)strcpy_s(arch, RTL_NUMBER_OF(arch), "arm64");
        break;
    case PROCESSOR_ARCHITECTURE_INTEL:
        (void)strcpy_s(arch, RTL_NUMBER_OF(arch), "x86");
        break;
    default:
        (void)strcpy_s(arch, RTL_NUMBER_OF(arch), "unknown");
        break;
    }

    ntdll = GetModuleHandleW(L"ntdll.dll");
    rtlGetVersion = (ntdll != NULL) ? (SLEEPWALKER_RTL_GET_VERSION_FN)GetProcAddress(ntdll, "RtlGetVersion") : NULL;
    ntQuerySystemInformation =
        (ntdll != NULL) ? (SLEEPWALKER_NT_QUERY_SYSTEM_INFORMATION_FN)GetProcAddress(ntdll, "NtQuerySystemInformation")
                        : NULL;

    if (rtlGetVersion != NULL && NT_SUCCESS(rtlGetVersion((PRTL_OSVERSIONINFOW)&osw)))
    {
        (void)QueryRegSzA("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "ProductName", productName,
                          RTL_NUMBER_OF(productName));
        (void)QueryRegSzA("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "DisplayVersion", displayVersion,
                          RTL_NUMBER_OF(displayVersion));
        (void)QueryRegSzA("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "CurrentBuildNumber", currentBuild,
                          RTL_NUMBER_OF(currentBuild));
        (void)QueryRegDword("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "UBR", &ubr);

        (void)sprintf_s(line, RTL_NUMBER_OF(line), "%s %lu.%lu.%lu ubr=%lu display=%s build=%s arch=%s",
                        (productName[0] != '\0') ? productName : "Windows", osw.dwMajorVersion, osw.dwMinorVersion,
                        osw.dwBuildNumber, ubr, (displayVersion[0] != '\0') ? displayVersion : "n/a",
                        (currentBuild[0] != '\0') ? currentBuild : "n/a", arch);
        SuiteLogMetaLine(Results, "environmentOs", line);
    }
    else
    {
        SuiteLogMetaLine(Results, "environmentOs", "unavailable");
    }

    if (QueryKernelImageVersion(&kmj, &kmn, &kbd, &krv))
    {
        (void)sprintf_s(line, RTL_NUMBER_OF(line), "%lu.%lu.%lu.%lu", kmj, kmn, kbd, krv);
        SuiteLogMetaLine(Results, "environmentKernelImageVersion", line);
    }
    else
    {
        SuiteLogMetaLine(Results, "environmentKernelImageVersion", "unavailable");
    }

    if (ntQuerySystemInformation != NULL)
    {
        status = ntQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SLEEPWALKER_SYSTEM_CODEINTEGRITY_INFORMATION_CLASS,
                                          &ci, sizeof(ci), NULL);
        if (NT_SUCCESS(status))
        {
            (void)sprintf_s(line, RTL_NUMBER_OF(line),
                            "0x%08lX enabled %s testsigning %s umci %s hvci %s hvciAudit %s hvciStrict %s debug %s "
                            "flighting %s whqlEnforce %s",
                            ci.CodeIntegrityOptions,
                            (ci.CodeIntegrityOptions & SLEEPWALKER_CI_OPTION_ENABLED) ? "yes" : "no",
                            (ci.CodeIntegrityOptions & SLEEPWALKER_CI_OPTION_TESTSIGN) ? "yes" : "no",
                            (ci.CodeIntegrityOptions & SLEEPWALKER_CI_OPTION_UMCI_ENABLED) ? "yes" : "no",
                            (ci.CodeIntegrityOptions & SLEEPWALKER_CI_OPTION_HVCI_KMCI_ENABLED) ? "yes" : "no",
                            (ci.CodeIntegrityOptions & SLEEPWALKER_CI_OPTION_HVCI_KMCI_AUDIT) ? "yes" : "no",
                            (ci.CodeIntegrityOptions & SLEEPWALKER_CI_OPTION_HVCI_KMCI_STRICT) ? "yes" : "no",
                            (ci.CodeIntegrityOptions & SLEEPWALKER_CI_OPTION_DEBUGMODE) ? "yes" : "no",
                            (ci.CodeIntegrityOptions & SLEEPWALKER_CI_OPTION_FLIGHTING) ? "yes" : "no",
                            (ci.CodeIntegrityOptions & SLEEPWALKER_CI_OPTION_WHQL_ENFORCEMENT_ENABLED) ? "yes" : "no");
            SuiteLogMetaLine(Results, "environmentCiOptions", line);
        }
        else
        {
            (void)sprintf_s(line, RTL_NUMBER_OF(line), "unavailable ntstatus=0x%08lX", (ULONG)status);
            SuiteLogMetaLine(Results, "environmentCiOptions", line);
        }

        status =
            ntQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SLEEPWALKER_SYSTEM_KERNEL_DEBUGGER_INFORMATION_CLASS,
                                     &kdInfo, sizeof(kdInfo), NULL);
        if (NT_SUCCESS(status))
        {
            (void)sprintf_s(line, RTL_NUMBER_OF(line), "%s present %s", kdInfo.KernelDebuggerEnabled ? "yes" : "no",
                            kdInfo.KernelDebuggerNotPresent ? "no" : "yes");
            SuiteLogMetaLine(Results, "environmentKernelDebugger", line);
        }
        else
        {
            (void)sprintf_s(line, RTL_NUMBER_OF(line), "unavailable ntstatus=0x%08lX", (ULONG)status);
            SuiteLogMetaLine(Results, "environmentKernelDebugger", line);
        }
    }
    else
    {
        SuiteLogMetaLine(Results, "environmentKernelDebugger", "unavailable");
    }
}

static BOOL SuiteInitReport(_Inout_ SUITE_RESULTS *Results)
{
    SYSTEMTIME stUtc;
    CHAR startedUtc[64];
    CHAR fileName[MAX_PATH];
    CHAR htmlName[MAX_PATH];

    if (Results == NULL)
    {
        return FALSE;
    }

    ZeroMemory(&Results->QpcFrequency, sizeof(Results->QpcFrequency));
    Results->SuiteStartQpc = 0;
    Results->LastCheckQpc = 0;
    Results->SuiteStartCycles = 0;
    Results->LastCheckCycles = 0;
    Results->CycleCounterAvailable = FALSE;

    if (QueryPerformanceFrequency(&Results->QpcFrequency))
    {
        LARGE_INTEGER qpcNow;
        QueryPerformanceCounter(&qpcNow);
        Results->SuiteStartQpc = (ULONGLONG)qpcNow.QuadPart;
        Results->LastCheckQpc = Results->SuiteStartQpc;
    }
#if defined(_M_X64) || defined(_M_IX86)
    Results->CycleCounterAvailable = TRUE;
    Results->SuiteStartCycles = __rdtsc();
    Results->LastCheckCycles = Results->SuiteStartCycles;
#endif

    if (!CreateDirectoryA("test-results", NULL))
    {
        DWORD err = GetLastError();
        if (err != ERROR_ALREADY_EXISTS)
        {
            return FALSE;
        }
    }

    GetSystemTime(&stUtc);
    if (sprintf_s(fileName, RTL_NUMBER_OF(fileName),
                  "test-results\\SleepwalkerTestSuite-%04u%02u%02u-%02u%02u%02uZ.txt", stUtc.wYear, stUtc.wMonth,
                  stUtc.wDay, stUtc.wHour, stUtc.wMinute, stUtc.wSecond) <= 0)
    {
        return FALSE;
    }

    if (sprintf_s(htmlName, RTL_NUMBER_OF(htmlName),
                  "test-results\\SleepwalkerTestSuite-%04u%02u%02u-%02u%02u%02uZ.html", stUtc.wYear, stUtc.wMonth,
                  stUtc.wDay, stUtc.wHour, stUtc.wMinute, stUtc.wSecond) <= 0)
    {
        return FALSE;
    }

    Results->Report = fopen(fileName, "w");
    if (Results->Report == NULL)
    {
        return FALSE;
    }

    (void)strcpy_s(Results->ReportPath, RTL_NUMBER_OF(Results->ReportPath), fileName);
    (void)strcpy_s(Results->HtmlReportPath, RTL_NUMBER_OF(Results->HtmlReportPath), htmlName);

    if (sprintf_s(startedUtc, RTL_NUMBER_OF(startedUtc), "%04u-%02u-%02uT%02u:%02u:%02uZ", stUtc.wYear, stUtc.wMonth,
                  stUtc.wDay, stUtc.wHour, stUtc.wMinute, stUtc.wSecond) <= 0)
    {
        fclose(Results->Report);
        Results->Report = NULL;
        return FALSE;
    }

    fprintf(Results->Report, "SleepwalkerTestSuite report\n");
    SuiteLogMetaLine(Results, "startedUtc", startedUtc);
    SuiteLogMetaLine(Results, "reportTxt", Results->ReportPath);
    SuiteLogMetaLine(Results, "reportHtml", Results->HtmlReportPath);
    if (Results->QpcFrequency.QuadPart > 0)
    {
        CHAR qpcFreq[64];
        (void)sprintf_s(qpcFreq, RTL_NUMBER_OF(qpcFreq), "%lld", Results->QpcFrequency.QuadPart);
        SuiteLogMetaLine(Results, "timingQpcFrequency", qpcFreq);
    }
    SuiteLogMetaLine(Results, "timingCycleCounter", Results->CycleCounterAvailable ? "rdtsc" : "unavailable");
    fprintf(Results->Report, "\n");

    fflush(Results->Report);
    return TRUE;
}

static VOID SuiteCloseReport(_Inout_ SUITE_RESULTS *Results, _In_ DWORD Polls)
{
    SLEEPWALKER_REPORT_CHECK *sortedChecks = NULL;
    size_t sortedCount = 0;
    const SLEEPWALKER_REPORT_CHECK *checksForOutput;
    size_t checksForOutputCount;
    INT failed;
    CHAR summary[256];
    CHAR timingSummary[160];
    BOOL htmlWritten = FALSE;
    size_t i;
    double suiteMs = 0.0;

    if (Results == NULL)
    {
        return;
    }

    if (Results->QpcFrequency.QuadPart > 0 && Results->SuiteStartQpc != 0)
    {
        LARGE_INTEGER qpcNow;
        QueryPerformanceCounter(&qpcNow);
        if ((ULONGLONG)qpcNow.QuadPart >= Results->SuiteStartQpc)
        {
            suiteMs = ((double)((ULONGLONG)qpcNow.QuadPart - Results->SuiteStartQpc) * 1000.0) /
                      (double)Results->QpcFrequency.QuadPart;
        }
    }

    failed = Results->Total - Results->Passed;
    (void)sprintf_s(summary, RTL_NUMBER_OF(summary),
                    "SleepwalkerTestSuite complete. tests-passed=%d/%d tests-failed=%d tests-skipped=%d polls=%lu",
                    Results->Passed, Results->Total, failed, Results->Skipped, Polls);
    (void)sprintf_s(timingSummary, RTL_NUMBER_OF(timingSummary), "suiteTiming elapsedMs=%.3f polls=%lu", suiteMs,
                    Polls);

    if (!SuiteBuildSortedChecks(Results, &sortedChecks, &sortedCount))
    {
        sortedChecks = NULL;
        sortedCount = 0;
    }

    if (sortedChecks != NULL)
    {
        checksForOutput = sortedChecks;
        checksForOutputCount = sortedCount;
    }
    else
    {
        checksForOutput = Results->Checks;
        checksForOutputCount = Results->CheckCount;
    }

    if (Results->Report != NULL)
    {
        fprintf(Results->Report, "Checks\n\n");
        for (i = 0; i < checksForOutputCount; ++i)
        {
            const char *status = SuiteCheckStatusText(checksForOutput[i].Status);
            fprintf(Results->Report, "[%s][T%04lu] %s\n", status, (unsigned long)checksForOutput[i].Id,
                    (checksForOutput[i].Text != NULL) ? checksForOutput[i].Text : "");
        }
        fprintf(Results->Report, "\n[INFO] %s\n", timingSummary);
        fprintf(Results->Report, "\n[%s] %s\n", (failed == 0) ? "OK" : "FAIL", summary);
        fclose(Results->Report);
        Results->Report = NULL;
    }

    printf("[INFO] %s\n", timingSummary);
    printf("[%s] %s\n", (failed == 0) ? "OK" : "FAIL", summary);

    if (Results->HtmlReportPath[0] != '\0')
    {
        htmlWritten = SLEEPWALKERWriteHtmlReport(Results->HtmlReportPath, "SleepwalkerTestSuite Report", Results->Meta,
                                                 Results->MetaCount, checksForOutput, checksForOutputCount);
        if (!htmlWritten)
        {
            printf("reportHtmlStatus=failed\n");
        }
    }

    if (sortedChecks != NULL)
    {
        free(sortedChecks);
    }

    SuiteFreeCollectedData(Results);
}

static VOID RecordResult(_Inout_ SUITE_RESULTS *Results, _In_ BOOL Passed, _In_z_ const char *PassText,
                         _In_z_ const char *FailText)
{
    if (Results == NULL)
    {
        return;
    }

    Results->Total += 1;
    if (Passed)
    {
        Results->Passed += 1;
        SuiteRecordCheck(Results, SleepwalkerReportCheckPass, PassText);
    }
    else
    {
        SuiteRecordCheck(Results, SleepwalkerReportCheckFail, FailText);
    }
}

static VOID RecordSkip(_Inout_ SUITE_RESULTS *Results, _In_z_ const char *SkipText)
{
    if (Results == NULL || SkipText == NULL)
    {
        return;
    }

    Results->Skipped += 1;
    SuiteRecordCheck(Results, SleepwalkerReportCheckSkip, SkipText);
}

static BOOL ErrorInList(_In_ DWORD Actual, _In_reads_(ExpectedCount) const DWORD *Expected, _In_ size_t ExpectedCount)
{
    size_t i;

    if (Expected == NULL || ExpectedCount == 0)
    {
        return FALSE;
    }

    for (i = 0; i < ExpectedCount; ++i)
    {
        if (Actual == Expected[i])
        {
            return TRUE;
        }
    }
    return FALSE;
}

