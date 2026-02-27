#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>
#include <strsafe.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <intrin.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "..\..\abi\sleepwalker_ioctl.h"
#include "sleepwalker_event_printer.h"
#include "sleepwalker_sensor_core.h"
#include "sleepwalker_symbol_resolver.h"
#include "sleepwalker_test_report_html.h"

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "version.lib")

typedef struct _TEST_STATE
{
    BOOL SawHandle;
    BOOL SawThread;
    DWORD Polls;
    DWORD HandleEvents;
    DWORD ThreadEvents;
    DWORD HandleFlagUnion;
    DWORD ThreadFlagUnion;
} TEST_STATE;

typedef struct _TEST_EXPECTED
{
    BOOL RequireHandleEvent;
    BOOL RequireThreadEvent;
    DWORD RequiredHandleFlags;
    DWORD RequiredThreadFlags;
} TEST_EXPECTED;

typedef struct _CHILD_CTX
{
    PROCESS_INFORMATION Pi;
    BOOL Started;
} CHILD_CTX;

typedef struct _ETW_CAPTURE
{
    WCHAR SessionName[64];
    SLEEPWALKERSC_ETW_SESSION *Session;
    TRACEHANDLE SessionHandle;
    TRACEHANDLE TraceHandle;
    HANDLE TraceThread;
    volatile LONG HandleEvents;
    volatile LONG ThreadEvents;
    volatile LONG ProcessEvents;
    volatile LONG ImageEvents;
    volatile LONG RegistryEvents;
    volatile LONG ApcEvents;
    volatile LONG DetectionEvents;
    volatile LONG TiEvents;
    volatile LONG TiAllocVmEvents;
    volatile LONG TiProtectVmEvents;
    volatile LONG TiWriteVmEvents;
    volatile LONG TiSyscallUsageEvents;
    volatile LONG TiUnknownTaskEvents;
    volatile LONG DetectRemoteThreadWithIntent;
    volatile LONG DetectRegistryHighValue;
    volatile LONG DetectIntentChain;
    volatile LONG DetectDirectSyscallSuspect;
    volatile LONG DetectManualMapOrHollowingExec;
    volatile LONG DetectSuspiciousNtdllPath;
    volatile LONG DetectMultipleNtdllMappings;
    volatile LONG DetectRemoteApcCreationSuspect;
    volatile LONG DetectThreadHijackIntent;
    volatile LONG DetectThreadContextIntent;
    volatile LONG DetectTamper;
    volatile LONG DetectTamperCleared;
    volatile LONG UnknownEvents;
    volatile LONG ProcessTraceStatus;
    BOOL TiProviderEnabled;
} ETW_CAPTURE;

typedef struct _SUITE_RESULTS
{
    INT Total;
    INT Passed;
    INT Skipped;
    FILE *Report;
    UINT32 NextCheckId;
    SLEEPWALKER_REPORT_META *Meta;
    size_t MetaCount;
    size_t MetaCapacity;
    SLEEPWALKER_REPORT_CHECK *Checks;
    size_t CheckCount;
    size_t CheckCapacity;
    CHAR ReportPath[MAX_PATH];
    CHAR HtmlReportPath[MAX_PATH];
    LARGE_INTEGER QpcFrequency;
    ULONGLONG SuiteStartQpc;
    ULONGLONG LastCheckQpc;
    unsigned __int64 SuiteStartCycles;
    unsigned __int64 LastCheckCycles;
    BOOL CycleCounterAvailable;
} SUITE_RESULTS;

#define SLEEPWALKER_CHILD_ARG "--idle-child"
#define SLEEPWALKER_CHILD_ARGW L"--idle-child"
#define SLEEPWALKER_SUITE_ETW_SESSION L"SleepwalkerTestSuiteSession"
#define SLEEPWALKER_MULTI_CLIENT_COUNT 3
#define SLEEPWALKER_MULTI_CLIENT_TIMEOUT_MS 8000
#define SLEEPWALKER_SYSTEM_CODEINTEGRITY_INFORMATION_CLASS 103
#define SLEEPWALKER_SYSTEM_KERNEL_DEBUGGER_INFORMATION_CLASS 35

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#define SLEEPWALKER_CI_OPTION_ENABLED 0x0001
#define SLEEPWALKER_CI_OPTION_TESTSIGN 0x0002
#define SLEEPWALKER_CI_OPTION_UMCI_ENABLED 0x0004
#define SLEEPWALKER_CI_OPTION_DEBUGMODE 0x0080
#define SLEEPWALKER_CI_OPTION_FLIGHTING 0x0200
#define SLEEPWALKER_CI_OPTION_HVCI_KMCI_ENABLED 0x0400
#define SLEEPWALKER_CI_OPTION_HVCI_KMCI_AUDIT 0x0800
#define SLEEPWALKER_CI_OPTION_HVCI_KMCI_STRICT 0x1000
#define SLEEPWALKER_CI_OPTION_WHQL_ENFORCEMENT_ENABLED 0x4000

static ETW_CAPTURE *g_ActiveEtwCapture = NULL;

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

static BOOL EnvFlagEnabled(_In_z_ const char *Name, _In_ BOOL DefaultValue)
{
    char value[16];
    size_t i;

    if (Name == NULL)
    {
        return DefaultValue;
    }

    if (GetEnvironmentVariableA(Name, value, (DWORD)RTL_NUMBER_OF(value)) == 0)
    {
        return DefaultValue;
    }

    for (i = 0; i < RTL_NUMBER_OF(value) && value[i] != '\0'; ++i)
    {
        if (value[i] >= 'A' && value[i] <= 'Z')
        {
            value[i] = (char)(value[i] - 'A' + 'a');
        }
    }

    if (strcmp(value, "1") == 0 || strcmp(value, "true") == 0 || strcmp(value, "yes") == 0 || strcmp(value, "on") == 0)
    {
        return TRUE;
    }
    if (strcmp(value, "0") == 0 || strcmp(value, "false") == 0 || strcmp(value, "no") == 0 || strcmp(value, "off") == 0)
    {
        return FALSE;
    }

    return DefaultValue;
}

static BOOL ExpectRawIoctlFailure(_In_ HANDLE Device, _In_ DWORD Ioctl,
                                  _In_reads_bytes_opt_(InSize) const VOID *InBuffer, _In_ DWORD InSize,
                                  _Out_writes_bytes_opt_(OutSize) VOID *OutBuffer, _In_ DWORD OutSize,
                                  _In_reads_(ExpectedErrorCount) const DWORD *ExpectedErrors,
                                  _In_ size_t ExpectedErrorCount)
{
    DWORD bytes = 0;
    BOOL ok;
    DWORD err;

    ok = DeviceIoControl(Device, Ioctl, (LPVOID)InBuffer, InSize, OutBuffer, OutSize, &bytes, NULL);
    if (ok)
    {
        return FALSE;
    }

    err = GetLastError();
    return ErrorInList(err, ExpectedErrors, ExpectedErrorCount);
}

static BOOL ExpectRawIoctlSuccess(_In_ HANDLE Device, _In_ DWORD Ioctl,
                                  _In_reads_bytes_opt_(InSize) const VOID *InBuffer, _In_ DWORD InSize,
                                  _Out_writes_bytes_opt_(OutSize) VOID *OutBuffer, _In_ DWORD OutSize)
{
    DWORD bytes = 0;

    return DeviceIoControl(Device, Ioctl, (LPVOID)InBuffer, InSize, OutBuffer, OutSize, &bytes, NULL);
}

static VOID RunIoctlContractTests(_In_ HANDLE Device, _In_ DWORD SelfPid, _Inout_ SUITE_RESULTS *Results)
{
    static const DWORD expectedInvalidFunction[] = {ERROR_INVALID_FUNCTION, ERROR_NOT_SUPPORTED};
    static const DWORD expectedNoMore[] = {ERROR_NO_MORE_ITEMS};
    static const DWORD expectedBuffer[] = {ERROR_INSUFFICIENT_BUFFER, ERROR_MORE_DATA};
    static const DWORD expectedInvalidParameter[] = {ERROR_INVALID_PARAMETER};
    static const DWORD expectedNotFound[] = {ERROR_NOT_FOUND};
    SLEEPWALKER_EVENT_RECORD eventRecord;
    SLEEPWALKER_SUBSCRIBE_REQUEST subReq;
    SLEEPWALKER_UNSUBSCRIBE_REQUEST unsubReq;
    SLEEPWALKER_SET_PIDS_REQUEST setReq;
    BYTE tinyOut = 0;

    ZeroMemory(&eventRecord, sizeof(eventRecord));
    ZeroMemory(&subReq, sizeof(subReq));
    ZeroMemory(&unsubReq, sizeof(unsubReq));
    ZeroMemory(&setReq, sizeof(setReq));

    subReq.ProcessId = SelfPid;
    subReq.StreamMask = SLEEPWALKER_STREAM_HANDLE;
    unsubReq.ProcessId = SelfPid;

    RecordResult(
        Results,
        ExpectRawIoctlFailure(Device, (DWORD)CTL_CODE(FILE_DEVICE_SLEEPWALKER, 0x8FF, METHOD_BUFFERED, FILE_ANY_ACCESS),
                              NULL, 0, NULL, 0, expectedInvalidFunction, RTL_NUMBER_OF(expectedInvalidFunction)),
        "unknown IOCTL rejected", "unknown IOCTL was not rejected");

    RecordResult(Results,
                 ExpectRawIoctlFailure(Device, (DWORD)IOCTL_SLEEPWALKER_GET_EVENT, NULL, 0, &eventRecord,
                                       sizeof(eventRecord), expectedNoMore, RTL_NUMBER_OF(expectedNoMore)),
                 "empty event queue returns NO_MORE_ITEMS", "empty event queue did not return NO_MORE_ITEMS");

    RecordResult(Results,
                 ExpectRawIoctlFailure(Device, (DWORD)IOCTL_SLEEPWALKER_GET_EVENT, NULL, 0, &tinyOut, sizeof(tinyOut),
                                       expectedBuffer, RTL_NUMBER_OF(expectedBuffer)),
                 "GET_EVENT short output buffer rejected", "GET_EVENT short output buffer was not rejected");

    RecordResult(Results,
                 ExpectRawIoctlFailure(Device, (DWORD)IOCTL_SLEEPWALKER_GET_STATS, NULL, 0, &tinyOut, sizeof(tinyOut),
                                       expectedBuffer, RTL_NUMBER_OF(expectedBuffer)),
                 "GET_STATS short output buffer rejected", "GET_STATS short output buffer was not rejected");

    RecordResult(Results,
                 ExpectRawIoctlFailure(Device, (DWORD)IOCTL_SLEEPWALKER_SUBSCRIBE, &subReq, sizeof(subReq) - 1, NULL, 0,
                                       expectedBuffer, RTL_NUMBER_OF(expectedBuffer)),
                 "SUBSCRIBE short input buffer rejected", "SUBSCRIBE short input buffer was not rejected");

    RecordResult(Results,
                 ExpectRawIoctlFailure(Device, (DWORD)IOCTL_SLEEPWALKER_UNSUBSCRIBE, &unsubReq, sizeof(unsubReq) - 1,
                                       NULL, 0, expectedBuffer, RTL_NUMBER_OF(expectedBuffer)),
                 "UNSUBSCRIBE short input buffer rejected", "UNSUBSCRIBE short input buffer was not rejected");

    setReq.StreamMask = SLEEPWALKER_STREAM_HANDLE;
    setReq.ProcessCount = 1;
    setReq.ProcessIds[0] = SelfPid;
    RecordResult(Results,
                 ExpectRawIoctlFailure(Device, (DWORD)IOCTL_SLEEPWALKER_SET_PIDS, &setReq, sizeof(setReq) - 1, NULL, 0,
                                       expectedBuffer, RTL_NUMBER_OF(expectedBuffer)),
                 "SET_PIDS short input buffer rejected", "SET_PIDS short input buffer was not rejected");

    setReq.StreamMask = SLEEPWALKER_STREAM_HANDLE;
    setReq.ProcessCount = 0;
    RecordResult(Results,
                 ExpectRawIoctlFailure(Device, (DWORD)IOCTL_SLEEPWALKER_SET_PIDS, &setReq, sizeof(setReq), NULL, 0,
                                       expectedInvalidParameter, RTL_NUMBER_OF(expectedInvalidParameter)),
                 "SET_PIDS zero process count rejected", "SET_PIDS zero process count was not rejected");

    setReq.StreamMask = 0;
    setReq.ProcessCount = 1;
    setReq.ProcessIds[0] = SelfPid;
    RecordResult(Results,
                 ExpectRawIoctlFailure(Device, (DWORD)IOCTL_SLEEPWALKER_SET_PIDS, &setReq, sizeof(setReq), NULL, 0,
                                       expectedInvalidParameter, RTL_NUMBER_OF(expectedInvalidParameter)),
                 "SET_PIDS invalid stream mask rejected", "SET_PIDS invalid stream mask was not rejected");

    setReq.StreamMask = SLEEPWALKER_STREAM_HANDLE;
    setReq.ProcessCount = 2;
    setReq.ProcessIds[0] = 0;
    setReq.ProcessIds[1] = 0;
    RecordResult(Results,
                 ExpectRawIoctlFailure(Device, (DWORD)IOCTL_SLEEPWALKER_SET_PIDS, &setReq, sizeof(setReq), NULL, 0,
                                       expectedInvalidParameter, RTL_NUMBER_OF(expectedInvalidParameter)),
                 "SET_PIDS all-zero PID list rejected", "SET_PIDS all-zero PID list was not rejected");

    unsubReq.ProcessId = 0x7FFFFFFF;
    RecordResult(Results,
                 ExpectRawIoctlFailure(Device, (DWORD)IOCTL_SLEEPWALKER_UNSUBSCRIBE, &unsubReq, sizeof(unsubReq), NULL,
                                       0, expectedNotFound, RTL_NUMBER_OF(expectedNotFound)),
                 "UNSUBSCRIBE unknown PID rejected", "UNSUBSCRIBE unknown PID was not rejected");

    subReq.ProcessId = SelfPid;
    subReq.StreamMask = SLEEPWALKER_STREAM_HANDLE;
    RecordResult(Results,
                 ExpectRawIoctlSuccess(Device, (DWORD)IOCTL_SLEEPWALKER_SUBSCRIBE, &subReq, sizeof(subReq), NULL, 0),
                 "SUBSCRIBE accepts valid request", "SUBSCRIBE rejected valid request");

    unsubReq.ProcessId = SelfPid;
    RecordResult(
        Results,
        ExpectRawIoctlSuccess(Device, (DWORD)IOCTL_SLEEPWALKER_UNSUBSCRIBE, &unsubReq, sizeof(unsubReq), NULL, 0),
        "UNSUBSCRIBE accepts valid request", "UNSUBSCRIBE rejected valid request");
}

static BOOL Subscribe(HANDLE h, DWORD pid, DWORD mask)
{
    return SLEEPWALKERSCSubscribe(h, pid, mask);
}

static BOOL SetPids(HANDLE h, const DWORD *pids, DWORD count, DWORD mask)
{
    return SLEEPWALKERSCSetPids(h, pids, count, mask);
}

static BOOL Unsubscribe(HANDLE h, DWORD pid)
{
    return SLEEPWALKERSCUnsubscribe(h, pid);
}

static HANDLE OpenControlDeviceHandle(void)
{
    return SLEEPWALKERSCOpenControlDevice();
}

static DWORD WINAPI MultiClientWorkerThreadProc(_In_ LPVOID Context)
{
    SLEEPWALKER_MULTI_CLIENT_WORKER *worker = (SLEEPWALKER_MULTI_CLIENT_WORKER *)Context;
    ULONGLONG start = GetTickCount64();

    while ((GetTickCount64() - start) < worker->MaxMs)
    {
        SLEEPWALKER_EVENT_RECORD rec;
        DWORD bytes = 0;
        BOOL ok;

        ok = SLEEPWALKERSCGetEvent(worker->Device, &rec, &bytes);

        worker->Polls += 1;
        if (!ok)
        {
            DWORD err = GetLastError();
            if (err == ERROR_NO_MORE_ITEMS)
            {
                Sleep(20);
                continue;
            }
            worker->UnexpectedError = err;
            return 1;
        }

        if (rec.Header.Type == SleepwalkerEventTypeHandle)
        {
            worker->SawHandle = TRUE;
        }
        else if (rec.Header.Type == SleepwalkerEventTypeThread)
        {
            worker->SawThread = TRUE;
        }

        if (worker->SawHandle && worker->SawThread)
        {
            return 0;
        }
    }

    return (worker->SawHandle && worker->SawThread) ? 0 : 2;
}

static BOOL RunMultiClientParallelIoctlTest(_In_ DWORD CallerPid, _In_ DWORD TargetPid, _Out_opt_ DWORD *TotalPolls)
{
    HANDLE clients[SLEEPWALKER_MULTI_CLIENT_COUNT];
    HANDLE threads[SLEEPWALKER_MULTI_CLIENT_COUNT];
    SLEEPWALKER_MULTI_CLIENT_WORKER workers[SLEEPWALKER_MULTI_CLIENT_COUNT];
    DWORD i;
    BOOL ok = FALSE;
    DWORD pollSum = 0;
    BOOL generatedHandle;
    BOOL generatedThread;

    for (i = 0; i < SLEEPWALKER_MULTI_CLIENT_COUNT; ++i)
    {
        clients[i] = INVALID_HANDLE_VALUE;
        threads[i] = NULL;
        ZeroMemory(&workers[i], sizeof(workers[i]));
    }

    for (i = 0; i < SLEEPWALKER_MULTI_CLIENT_COUNT; ++i)
    {
        clients[i] = OpenControlDeviceHandle();
        if (clients[i] == INVALID_HANDLE_VALUE)
        {
            goto Cleanup;
        }

        if (!Subscribe(clients[i], CallerPid,
                       SLEEPWALKER_STREAM_HANDLE | SLEEPWALKER_STREAM_MEMORY | SLEEPWALKER_STREAM_THREAD))
        {
            goto Cleanup;
        }
        if (!Subscribe(clients[i], TargetPid,
                       SLEEPWALKER_STREAM_HANDLE | SLEEPWALKER_STREAM_MEMORY | SLEEPWALKER_STREAM_THREAD))
        {
            goto Cleanup;
        }

        workers[i].Device = clients[i];
        workers[i].MaxMs = SLEEPWALKER_MULTI_CLIENT_TIMEOUT_MS;
        threads[i] = CreateThread(NULL, 0, MultiClientWorkerThreadProc, &workers[i], 0, NULL);
        if (threads[i] == NULL)
        {
            goto Cleanup;
        }
    }

    generatedHandle = GenerateMemoryHandleIntent(TargetPid);
    generatedThread = GenerateRemoteThreadLoadLibraryIntent(TargetPid);
    if (!generatedHandle || !generatedThread)
    {
        goto Cleanup;
    }

    for (i = 0; i < SLEEPWALKER_MULTI_CLIENT_COUNT; ++i)
    {
        DWORD waitResult;
        DWORD exitCode = 1;

        waitResult = WaitForSingleObject(threads[i], SLEEPWALKER_MULTI_CLIENT_TIMEOUT_MS + 2000);
        if (waitResult != WAIT_OBJECT_0)
        {
            goto Cleanup;
        }
        if (!GetExitCodeThread(threads[i], &exitCode) || exitCode != 0)
        {
            goto Cleanup;
        }
        if (workers[i].UnexpectedError != 0 || !workers[i].SawHandle || !workers[i].SawThread)
        {
            goto Cleanup;
        }
    }

    ok = TRUE;

Cleanup:
    for (i = 0; i < SLEEPWALKER_MULTI_CLIENT_COUNT; ++i)
    {
        if (threads[i] != NULL)
        {
            (void)WaitForSingleObject(threads[i], 1000);
            CloseHandle(threads[i]);
            threads[i] = NULL;
        }
    }

    for (i = 0; i < SLEEPWALKER_MULTI_CLIENT_COUNT; ++i)
    {
        pollSum += workers[i].Polls;
        if (clients[i] != INVALID_HANDLE_VALUE)
        {
            (void)Unsubscribe(clients[i], CallerPid);
            (void)Unsubscribe(clients[i], TargetPid);
            CloseHandle(clients[i]);
            clients[i] = INVALID_HANDLE_VALUE;
        }
    }

    if (TotalPolls != NULL)
    {
        *TotalPolls = pollSum;
    }
    return ok;
}

static BOOL RequirementsMet(const TEST_STATE *state, const TEST_EXPECTED *expected)
{
    if (expected->RequireHandleEvent && !state->SawHandle)
    {
        return FALSE;
    }
    if (expected->RequireThreadEvent && !state->SawThread)
    {
        return FALSE;
    }
    if ((state->HandleFlagUnion & expected->RequiredHandleFlags) != expected->RequiredHandleFlags)
    {
        return FALSE;
    }
    if ((state->ThreadFlagUnion & expected->RequiredThreadFlags) != expected->RequiredThreadFlags)
    {
        return FALSE;
    }
    return TRUE;
}

static void PumpIoctlEvents(HANDLE h, TEST_STATE *state, const TEST_EXPECTED *expected, DWORD maxMs)
{
    ULONGLONG start = GetTickCount64();

    while ((GetTickCount64() - start) < maxMs)
    {
        SLEEPWALKER_EVENT_RECORD rec;
        DWORD bytes = 0;
        BOOL ok;

        ok = SLEEPWALKERSCGetEvent(h, &rec, &bytes);

        state->Polls += 1;
        if (!ok)
        {
            DWORD err = GetLastError();
            if (err == ERROR_NO_MORE_ITEMS)
            {
                Sleep(40);
                continue;
            }
            printf("[FAIL] IOCTL_SLEEPWALKER_GET_EVENT err=%lu\n", err);
            return;
        }

        SLEEPWALKEREventPrinterPrintRecord(&rec);

        if (rec.Header.Type == SleepwalkerEventTypeHandle)
        {
            state->SawHandle = TRUE;
            state->HandleEvents += 1;
            state->HandleFlagUnion |= rec.Data.Handle.Flags;
        }
        else if (rec.Header.Type == SleepwalkerEventTypeThread)
        {
            state->SawThread = TRUE;
            state->ThreadEvents += 1;
            state->ThreadFlagUnion |= rec.Data.Thread.Flags;
        }

        if (RequirementsMet(state, expected))
        {
            return;
        }
    }
}

static void GenerateLocalThreadEvent(void)
{
    HANDLE t = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Sleep, (LPVOID)(ULONG_PTR)15, 0, NULL);
    if (t != NULL)
    {
        WaitForSingleObject(t, 2000);
        CloseHandle(t);
    }
}

static BOOL StartIdleChild(CHILD_CTX *child)
{
    WCHAR imagePath[MAX_PATH];
    WCHAR cmdLine[MAX_PATH + 64];
    STARTUPINFOW si;
    DWORD len;

    ZeroMemory(child, sizeof(*child));
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);

    len = GetModuleFileNameW(NULL, imagePath, (DWORD)RTL_NUMBER_OF(imagePath));
    if (len == 0 || len >= RTL_NUMBER_OF(imagePath))
    {
        return FALSE;
    }

    if (swprintf_s(cmdLine, RTL_NUMBER_OF(cmdLine), L"\"%ls\" %ls", imagePath, SLEEPWALKER_CHILD_ARGW) < 0)
    {
        return FALSE;
    }

    if (!CreateProcessW(imagePath, cmdLine, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &child->Pi))
    {
        return FALSE;
    }

    child->Started = TRUE;
    return TRUE;
}

static void StopIdleChild(CHILD_CTX *child)
{
    DWORD waitResult;

    if (!child->Started)
    {
        return;
    }

    waitResult = WaitForSingleObject(child->Pi.hProcess, 500);
    if (waitResult == WAIT_TIMEOUT)
    {
        (void)TerminateProcess(child->Pi.hProcess, 0);
        (void)WaitForSingleObject(child->Pi.hProcess, 2000);
    }

    CloseHandle(child->Pi.hThread);
    CloseHandle(child->Pi.hProcess);
    ZeroMemory(child, sizeof(*child));
}

static BOOL GenerateMemoryHandleIntent(DWORD pid)
{
    HANDLE p = OpenProcess(
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (p == NULL)
    {
        return FALSE;
    }
    CloseHandle(p);
    return TRUE;
}

static BOOL GenerateThreadContextHandleIntent(DWORD tid)
{
    HANDLE t = OpenThread(
        THREAD_SET_CONTEXT | THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_LIMITED_INFORMATION, FALSE, tid);
    if (t == NULL)
    {
        return FALSE;
    }
    CloseHandle(t);
    return TRUE;
}

static BOOL GenerateDuplicateHandleIntent(DWORD pid)
{
    HANDLE src = NULL;
    HANDLE dup = NULL;
    BOOL ok;

    src = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION,
                      FALSE, pid);
    if (src == NULL)
    {
        return FALSE;
    }

    ok = DuplicateHandle(GetCurrentProcess(), src, GetCurrentProcess(), &dup, PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE,
                         0);

    if (dup != NULL)
    {
        CloseHandle(dup);
    }
    CloseHandle(src);
    return ok;
}

static BOOL FindRemoteModuleBase(DWORD pid, PCWSTR moduleName, ULONGLONG *baseOut)
{
    HANDLE snap;
    MODULEENTRY32W me;

    *baseOut = 0;
    snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE)
    {
        return FALSE;
    }

    ZeroMemory(&me, sizeof(me));
    me.dwSize = sizeof(me);

    if (!Module32FirstW(snap, &me))
    {
        CloseHandle(snap);
        return FALSE;
    }

    do
    {
        if (_wcsicmp(me.szModule, moduleName) == 0)
        {
            *baseOut = (ULONGLONG)(ULONG_PTR)me.modBaseAddr;
            CloseHandle(snap);
            return TRUE;
        }
    } while (Module32NextW(snap, &me));

    CloseHandle(snap);
    return FALSE;
}

static BOOL GenerateRemoteThreadLoadLibraryIntent(DWORD pid)
{
    HANDLE process = NULL;
    HANDLE thread = NULL;
    HMODULE localKernel32;
    FARPROC localLoadLibraryW;
    ULONGLONG remoteKernel32 = 0;
    ULONGLONG remoteStartAddress;
    SIZE_T dllBytes;
    LPVOID remoteBuffer = NULL;
    WCHAR dllName[] = L"kernel32.dll";
    BOOL ok = FALSE;
    SIZE_T written = 0;
    DWORD waitResult;

    localKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (localKernel32 == NULL)
    {
        return FALSE;
    }

    localLoadLibraryW = GetProcAddress(localKernel32, "LoadLibraryW");
    if (localLoadLibraryW == NULL)
    {
        return FALSE;
    }

    if (!FindRemoteModuleBase(pid, L"KERNEL32.DLL", &remoteKernel32))
    {
        return FALSE;
    }

    remoteStartAddress =
        remoteKernel32 + ((ULONGLONG)(ULONG_PTR)localLoadLibraryW - (ULONGLONG)(ULONG_PTR)localKernel32);

    process = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE |
                              PROCESS_VM_READ,
                          FALSE, pid);
    if (process == NULL)
    {
        return FALSE;
    }

    dllBytes = (wcslen(dllName) + 1) * sizeof(WCHAR);
    remoteBuffer = VirtualAllocEx(process, NULL, dllBytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (remoteBuffer == NULL)
    {
        goto Exit;
    }

    if (!WriteProcessMemory(process, remoteBuffer, dllName, dllBytes, &written) || written != dllBytes)
    {
        goto Exit;
    }

    thread = CreateRemoteThread(process, NULL, 0, (LPTHREAD_START_ROUTINE)(ULONG_PTR)remoteStartAddress, remoteBuffer,
                                0, NULL);
    if (thread == NULL)
    {
        goto Exit;
    }

    waitResult = WaitForSingleObject(thread, 5000);
    if (waitResult != WAIT_OBJECT_0 && waitResult != WAIT_TIMEOUT)
    {
        goto Exit;
    }

    ok = TRUE;

Exit:
    if (thread != NULL)
    {
        CloseHandle(thread);
    }
    if (remoteBuffer != NULL)
    {
        (void)VirtualFreeEx(process, remoteBuffer, 0, MEM_RELEASE);
    }
    if (process != NULL)
    {
        CloseHandle(process);
    }
    return ok;
}

static BOOL GenerateVmApiCallSurface(DWORD pid)
{
    HANDLE process = NULL;
    LPVOID remote = NULL;
    BYTE payload[64];
    SIZE_T written = 0;
    DWORD oldProtect = 0;
    BOOL ok = FALSE;

    ZeroMemory(payload, sizeof(payload));
    for (DWORD i = 0; i < (DWORD)sizeof(payload); ++i)
    {
        payload[i] = (BYTE)(i ^ 0x5A);
    }

    process = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION,
                          FALSE, pid);
    if (process == NULL)
    {
        return FALSE;
    }

    remote = VirtualAllocEx(process, NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (remote == NULL)
    {
        goto Exit;
    }

    if (!WriteProcessMemory(process, remote, payload, sizeof(payload), &written) || written != sizeof(payload))
    {
        goto Exit;
    }

    if (!VirtualProtectEx(process, remote, 0x1000, PAGE_EXECUTE_READ, &oldProtect))
    {
        goto Exit;
    }

    ok = TRUE;

Exit:
    if (remote != NULL)
    {
        (void)VirtualFreeEx(process, remote, 0, MEM_RELEASE);
    }
    if (process != NULL)
    {
        CloseHandle(process);
    }
    return ok;
}

static BOOL GenerateRegistryHighValueActivity(void)
{
    HKEY key = NULL;
    DWORD disposition = 0;
    LONG status;
    WCHAR valueName[] = L"SleepwalkerTestSuite";
    WCHAR valueData[] = L"cmd.exe /c exit";

    status = RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, NULL,
                             REG_OPTION_NON_VOLATILE, KEY_SET_VALUE | KEY_QUERY_VALUE, NULL, &key, &disposition);
    if (status != ERROR_SUCCESS)
    {
        return FALSE;
    }
    UNREFERENCED_PARAMETER(disposition);

    status = RegSetValueExW(key, valueName, 0, REG_SZ, (const BYTE *)valueData,
                            (DWORD)((wcslen(valueData) + 1) * sizeof(WCHAR)));

    (void)RegDeleteValueW(key, valueName);
    RegCloseKey(key);

    return (status == ERROR_SUCCESS);
}

static VOID WINAPI SleepwalkerEtwRecordCallback(_In_ PEVENT_RECORD Record, _In_opt_z_ PCWSTR EventName,
                                                _In_opt_ PVOID Context)
{
    ETW_CAPTURE *cap = (ETW_CAPTURE *)Context;
    CHAR detectionName[128];

    if (cap == NULL || Record == NULL)
    {
        return;
    }

    if (IsEqualGUID(&Record->EventHeader.ProviderId, &SLEEPWALKERSC_PROVIDER_GUID_TI))
    {
        USHORT task = Record->EventHeader.EventDescriptor.Task;

        InterlockedIncrement(&cap->TiEvents);
        switch (task)
        {
        case 1:
            InterlockedIncrement(&cap->TiAllocVmEvents);
            break;
        case 2:
            InterlockedIncrement(&cap->TiProtectVmEvents);
            break;
        case 7:
            InterlockedIncrement(&cap->TiWriteVmEvents);
            break;
        case 13:
            InterlockedIncrement(&cap->TiSyscallUsageEvents);
            break;
        default:
            InterlockedIncrement(&cap->TiUnknownTaskEvents);
            break;
        }
        return;
    }

    if (!IsEqualGUID(&Record->EventHeader.ProviderId, &SLEEPWALKERSC_PROVIDER_GUID_SLEEPWALKER) || EventName == NULL ||
        EventName[0] == L'\0')
    {
        InterlockedIncrement(&cap->UnknownEvents);
        return;
    }

    if (wcscmp(EventName, L"HandleTelemetry") == 0)
    {
        InterlockedIncrement(&cap->HandleEvents);
    }
    else if (wcscmp(EventName, L"ThreadTelemetry") == 0)
    {
        InterlockedIncrement(&cap->ThreadEvents);
    }
    else if (wcscmp(EventName, L"ProcessTelemetry") == 0)
    {
        InterlockedIncrement(&cap->ProcessEvents);
    }
    else if (wcscmp(EventName, L"ImageTelemetry") == 0)
    {
        InterlockedIncrement(&cap->ImageEvents);
    }
    else if (wcscmp(EventName, L"RegistryTelemetry") == 0)
    {
        InterlockedIncrement(&cap->RegistryEvents);
    }
    else if (wcscmp(EventName, L"ApcTelemetry") == 0)
    {
        InterlockedIncrement(&cap->ApcEvents);
    }
    else if (wcscmp(EventName, L"DetectionTelemetry") == 0)
    {
        InterlockedIncrement(&cap->DetectionEvents);
        detectionName[0] = '\0';
        if (GetEtwAnsiProperty(Record, L"detectionName", detectionName, RTL_NUMBER_OF(detectionName)))
        {
            if (strcmp(detectionName, "REMOTE_THREAD_WITH_RECENT_HANDLE_INTENT") == 0)
            {
                InterlockedIncrement(&cap->DetectRemoteThreadWithIntent);
            }
            else if (strcmp(detectionName, "HIGH_VALUE_REGISTRY_ACTIVITY") == 0)
            {
                InterlockedIncrement(&cap->DetectRegistryHighValue);
            }
            else if (strcmp(detectionName, "POSSIBLE_PROCESS_HOLLOWING_OR_INJECTION_INTENT_CHAIN") == 0)
            {
                InterlockedIncrement(&cap->DetectIntentChain);
            }
            else if (strcmp(detectionName, "DIRECT_SYSCALL_SUSPECT_HANDLE_OPERATION") == 0)
            {
                InterlockedIncrement(&cap->DetectDirectSyscallSuspect);
            }
            else if (strcmp(detectionName, "POSSIBLE_MANUAL_MAP_OR_HOLLOWING_EXECUTION") == 0 ||
                     strcmp(detectionName, "REMOTE_THREAD_START_IN_NON_IMAGE_EXECUTABLE_REGION") == 0)
            {
                InterlockedIncrement(&cap->DetectManualMapOrHollowingExec);
            }
            else if (strcmp(detectionName, "SUSPICIOUS_NTDLL_IMAGE_PATH") == 0)
            {
                InterlockedIncrement(&cap->DetectSuspiciousNtdllPath);
            }
            else if (strcmp(detectionName, "MULTIPLE_NTDLL_IMAGE_MAPPINGS") == 0)
            {
                InterlockedIncrement(&cap->DetectMultipleNtdllMappings);
            }
            else if (strcmp(detectionName, "REMOTE_APC_CREATION_SUSPECT") == 0)
            {
                InterlockedIncrement(&cap->DetectRemoteApcCreationSuspect);
            }
            else if (strcmp(detectionName, "THREAD_HIJACK_INTENT") == 0)
            {
                InterlockedIncrement(&cap->DetectThreadHijackIntent);
            }
            else if (strcmp(detectionName, "THREAD_ACTIVITY_WITH_THREAD_CONTEXT_INTENT") == 0)
            {
                InterlockedIncrement(&cap->DetectThreadContextIntent);
            }
            else if (strcmp(detectionName, "DRIVER_DISPATCH_OR_OBJECT_TAMPER") == 0)
            {
                InterlockedIncrement(&cap->DetectTamper);
            }
            else if (strcmp(detectionName, "DRIVER_DISPATCH_OR_OBJECT_TAMPER_CLEARED") == 0)
            {
                InterlockedIncrement(&cap->DetectTamperCleared);
            }
        }
    }
    else
    {
        InterlockedIncrement(&cap->UnknownEvents);
    }
}

static DWORD WINAPI EtwConsumerThreadProc(_In_ LPVOID Context)
{
    ETW_CAPTURE *cap = (ETW_CAPTURE *)Context;
    ULONG status;

    status = SLEEPWALKERSCRunEtwSession(cap->Session);
    InterlockedExchange(&cap->ProcessTraceStatus, (LONG)status);
    return status;
}

static BOOL StartEtwCapture(_Out_ ETW_CAPTURE *cap)
{
    WCHAR fallbackName[64];
    DWORD err = ERROR_SUCCESS;

    if (cap == NULL)
    {
        return FALSE;
    }

    ZeroMemory(cap, sizeof(*cap));
    cap->Session = NULL;
    cap->ProcessTraceStatus = ERROR_SUCCESS;
    cap->TiProviderEnabled = FALSE;
    (void)StringCchCopyW(cap->SessionName, RTL_NUMBER_OF(cap->SessionName), SLEEPWALKER_SUITE_ETW_SESSION);

    (void)SLEEPWALKERSCStopSessionByName(SLEEPWALKER_SUITE_ETW_SESSION);
    (void)SLEEPWALKERSCStopSessionByName(L"SleepwalkerSensorSession");
    Sleep(80);

    if (!SLEEPWALKERSCStartSleepwalkerEtwSession(cap->SessionName, TRUE, SleepwalkerEtwRecordCallback, cap,
                                                 &cap->Session, &cap->TiProviderEnabled))
    {
        err = GetLastError();
        printf("[INFO] ETW start failed err=%lu session=%ws\n", err, cap->SessionName);
        if (err == ERROR_ACCESS_DENIED || err == ERROR_ALREADY_EXISTS)
        {
            if (swprintf_s(fallbackName, RTL_NUMBER_OF(fallbackName), L"%ls-%lu", SLEEPWALKER_SUITE_ETW_SESSION,
                           GetCurrentProcessId()) > 0)
            {
                (void)StringCchCopyW(cap->SessionName, RTL_NUMBER_OF(cap->SessionName), fallbackName);
                if (!SLEEPWALKERSCStartSleepwalkerEtwSession(cap->SessionName, TRUE, SleepwalkerEtwRecordCallback, cap,
                                                             &cap->Session, &cap->TiProviderEnabled))
                {
                    err = GetLastError();
                    printf("[INFO] ETW fallback start failed err=%lu session=%ws\n", err, cap->SessionName);
                    return FALSE;
                }
                printf("[INFO] ETW started with fallback session name %ws\n", cap->SessionName);
            }
            else
            {
                return FALSE;
            }
        }
        else
        {
            return FALSE;
        }
    }

    if (!cap->TiProviderEnabled)
    {
        printf("[INFO] ETW started without TI provider (access denied or unavailable)\n");
    }

    g_ActiveEtwCapture = cap;
    cap->TraceThread = CreateThread(NULL, 0, EtwConsumerThreadProc, cap, 0, NULL);
    if (cap->TraceThread == NULL)
    {
        SLEEPWALKERSCStopEtwSession(cap->Session);
        cap->Session = NULL;
        g_ActiveEtwCapture = NULL;
        return FALSE;
    }

    Sleep(150);
    return TRUE;
}

static VOID StopEtwCapture(_Inout_ ETW_CAPTURE *cap)
{
    if (cap == NULL)
    {
        return;
    }

    if (cap->Session != NULL)
    {
        SLEEPWALKERSCStopEtwSession(cap->Session);
        cap->Session = NULL;
    }

    if (cap->TraceThread != NULL)
    {
        (void)WaitForSingleObject(cap->TraceThread, 5000);
        CloseHandle(cap->TraceThread);
        cap->TraceThread = NULL;
    }

    g_ActiveEtwCapture = NULL;
}

static BOOL WaitForEtwEventCoverage(_In_ ETW_CAPTURE *cap, _In_ DWORD maxMs, _In_ BOOL requireApcTelemetry)
{
    ULONGLONG start = GetTickCount64();

    while ((GetTickCount64() - start) < maxMs)
    {
        if (InterlockedCompareExchange(&cap->HandleEvents, 0, 0) > 0 &&
            InterlockedCompareExchange(&cap->ThreadEvents, 0, 0) > 0 &&
            InterlockedCompareExchange(&cap->ProcessEvents, 0, 0) > 0 &&
            InterlockedCompareExchange(&cap->ImageEvents, 0, 0) > 0 &&
            InterlockedCompareExchange(&cap->RegistryEvents, 0, 0) > 0 &&
            (!requireApcTelemetry || InterlockedCompareExchange(&cap->ApcEvents, 0, 0) > 0) &&
            InterlockedCompareExchange(&cap->DetectionEvents, 0, 0) > 0)
        {
            return TRUE;
        }
        Sleep(100);
    }
    return FALSE;
}

int __cdecl main(int argc, char **argv)
{
    HANDLE h = INVALID_HANDLE_VALUE;
    SLEEPWALKER_STATS_RESPONSE stats;
    DWORD bytes = 0;
    BOOL ok;
    DWORD selfPid = GetCurrentProcessId();
    TEST_STATE state;
    TEST_EXPECTED expected;
    SLEEPWALKER_SUBSCRIBE_REQUEST badReq;
    BOOL subscribedSelf = FALSE;
    BOOL subscribedChild = FALSE;
    CHILD_CTX child;
    BOOL generatedMemoryIntent = FALSE;
    BOOL generatedThreadIntent = FALSE;
    BOOL generatedDuplicateIntent = FALSE;
    BOOL generatedRemoteAfterMemory = FALSE;
    BOOL generatedRemoteAfterThread = FALSE;
    BOOL generatedRemoteAfterDup = FALSE;
    BOOL generatedRegistry = FALSE;
    BOOL generatedVmApiCalls = FALSE;
    BOOL multiClientParallelOk = FALSE;
    BOOL setPidsApplied = FALSE;
    DWORD multiClientPolls = 0;
    ETW_CAPTURE etw;
    BOOL etwStarted = FALSE;
    BOOL etwCoverageMet = FALSE;
    BOOL requireKernelCorrelationSignals = FALSE;
    BOOL requireApcTelemetry = FALSE;
    SUITE_RESULTS results;
    BOOL reportReady;

    if (argc > 1 && strcmp(argv[1], SLEEPWALKER_CHILD_ARG) == 0)
    {
        Sleep(15000);
        return 0;
    }

    SLEEPWALKERSymbolResolverInitialize();
    ZeroMemory(&state, sizeof(state));
    ZeroMemory(&expected, sizeof(expected));
    ZeroMemory(&child, sizeof(child));
    ZeroMemory(&etw, sizeof(etw));
    ZeroMemory(&results, sizeof(results));
    reportReady = SuiteInitReport(&results);
    if (!reportReady)
    {
        printf("reportStatus=unavailable\n");
    }
    requireKernelCorrelationSignals = EnvFlagEnabled("SLEEPWALKER_TEST_REQUIRE_KERNEL_CORRELATION", FALSE);
    requireApcTelemetry = EnvFlagEnabled("SLEEPWALKER_TEST_REQUIRE_APC", FALSE);
    printf("[INFO] suite knobs requireKernelCorrelation=%u requireApcTelemetry=%u\n",
           requireKernelCorrelationSignals ? 1u : 0u, requireApcTelemetry ? 1u : 0u);
    LogEnvironmentBaseline(&results);

    h = OpenControlDeviceHandle();
    RecordResult(&results, (h != INVALID_HANDLE_VALUE), "opened control device",
                 "failed to open control device \\\\.\\Global\\SleepwalkerCtl/\\\\.\\SleepwalkerCtl");
    if (h == INVALID_HANDLE_VALUE)
    {
        goto Cleanup;
    }

    RunIoctlContractTests(h, selfPid, &results);

    etwStarted = StartEtwCapture(&etw);
    RecordResult(&results, etwStarted, "started ETW capture session", "failed to start ETW capture session");

    ZeroMemory(&badReq, sizeof(badReq));
    badReq.ProcessId = selfPid;
    badReq.StreamMask = 0;
    ok = SLEEPWALKERSCSubscribe(h, badReq.ProcessId, badReq.StreamMask);
    RecordResult(&results, (!ok && GetLastError() == ERROR_INVALID_PARAMETER), "invalid subscribe stream mask rejected",
                 "invalid subscribe stream mask was not rejected");

    ok = Subscribe(h, selfPid, SLEEPWALKER_STREAM_HANDLE | SLEEPWALKER_STREAM_MEMORY | SLEEPWALKER_STREAM_THREAD);
    subscribedSelf = ok;
    RecordResult(&results, ok, "subscribed self", "subscribe self failed");
    if (!ok)
    {
        goto Cleanup;
    }
    printf("[INFO] subscribed self pid=%lu\n", selfPid);

    ZeroMemory(&stats, sizeof(stats));
    ok = SLEEPWALKERSCGetStats(h, &stats, &bytes);
    RecordResult(&results, ok, "queried IOCTL stats", "get stats failed");
    if (ok)
    {
        printf("[INFO] stats subscriptionCount=%u queueDepth=%u dropped=%u\n", stats.SubscriptionCount,
               stats.QueueDepth, stats.DroppedEvents);
        RecordResult(&results, (bytes == sizeof(stats)), "GET_STATS returned expected byte count",
                     "GET_STATS returned unexpected byte count");
    }

    ok = StartIdleChild(&child);
    RecordResult(&results, ok, "launched child process", "failed to launch child process");
    if (!ok)
    {
        goto Cleanup;
    }
    printf("[INFO] child pid=%lu tid=%lu\n", child.Pi.dwProcessId, child.Pi.dwThreadId);

    ok = Subscribe(h, child.Pi.dwProcessId,
                   SLEEPWALKER_STREAM_HANDLE | SLEEPWALKER_STREAM_MEMORY | SLEEPWALKER_STREAM_THREAD);
    subscribedChild = ok;
    RecordResult(&results, ok, "subscribed child", "subscribe child failed");
    if (!ok)
    {
        goto Cleanup;
    }

    {
        DWORD pidList[2];
        pidList[0] = selfPid;
        pidList[1] = child.Pi.dwProcessId;

        setPidsApplied = SetPids(h, pidList, RTL_NUMBER_OF(pidList),
                                 SLEEPWALKER_STREAM_HANDLE | SLEEPWALKER_STREAM_MEMORY | SLEEPWALKER_STREAM_THREAD);
        RecordResult(&results, setPidsApplied, "applied PID list subscription via IOCTL_SLEEPWALKER_SET_PIDS",
                     "failed to apply PID list subscription via IOCTL_SLEEPWALKER_SET_PIDS");
        if (setPidsApplied)
        {
            ZeroMemory(&stats, sizeof(stats));
            ok = SLEEPWALKERSCGetStats(h, &stats, &bytes);
            RecordResult(&results, (ok && stats.SubscriptionCount == 2),
                         "SET_PIDS applied expected subscription cardinality",
                         "SET_PIDS did not apply expected subscription cardinality");
        }
    }

    GenerateLocalThreadEvent();

    generatedMemoryIntent = GenerateMemoryHandleIntent(child.Pi.dwProcessId);
    RecordResult(&results, generatedMemoryIntent, "generated memory-handle intent",
                 "failed to generate memory-handle intent");

    generatedThreadIntent = GenerateThreadContextHandleIntent(child.Pi.dwThreadId);
    RecordResult(&results, generatedThreadIntent, "generated thread-context-handle intent",
                 "failed to generate thread-context-handle intent");

    generatedDuplicateIntent = GenerateDuplicateHandleIntent(child.Pi.dwProcessId);
    RecordResult(&results, generatedDuplicateIntent, "generated duplicate-handle intent",
                 "failed to generate duplicate-handle intent");

    if (generatedMemoryIntent)
    {
        generatedRemoteAfterMemory = GenerateRemoteThreadLoadLibraryIntent(child.Pi.dwProcessId);
        RecordResult(&results, generatedRemoteAfterMemory, "generated remote thread after memory intent",
                     "failed to generate remote thread after memory intent");
    }

    if (generatedThreadIntent)
    {
        generatedRemoteAfterThread = GenerateRemoteThreadLoadLibraryIntent(child.Pi.dwProcessId);
        RecordResult(&results, generatedRemoteAfterThread, "generated remote thread after thread-context intent",
                     "failed to generate remote thread after thread-context intent");
    }

    if (generatedDuplicateIntent)
    {
        generatedRemoteAfterDup = GenerateRemoteThreadLoadLibraryIntent(child.Pi.dwProcessId);
        RecordResult(&results, generatedRemoteAfterDup, "generated remote thread after duplicate intent",
                     "failed to generate remote thread after duplicate intent");
    }

    generatedRegistry = GenerateRegistryHighValueActivity();
    RecordResult(&results, generatedRegistry, "generated high-value registry activity",
                 "failed to generate high-value registry activity");

    generatedVmApiCalls = GenerateVmApiCallSurface(child.Pi.dwProcessId);
    RecordResult(&results, generatedVmApiCalls, "generated VM API-call surface (alloc/write/protect)",
                 "failed to generate VM API-call surface (alloc/write/protect)");

    expected.RequireThreadEvent = TRUE;
    expected.RequireHandleEvent = generatedMemoryIntent || generatedThreadIntent || generatedDuplicateIntent;
    if (generatedMemoryIntent)
    {
        expected.RequiredHandleFlags |= SLEEPWALKER_HANDLE_FLAG_MEMORY_RELATED;
    }
    if (generatedThreadIntent)
    {
        expected.RequiredHandleFlags |= SLEEPWALKER_HANDLE_FLAG_THREAD_OBJECT;
    }
    if (generatedDuplicateIntent)
    {
        expected.RequiredHandleFlags |= SLEEPWALKER_HANDLE_FLAG_DUPLICATE_OPERATION;
    }
    if (requireKernelCorrelationSignals && generatedRemoteAfterMemory)
    {
        expected.RequiredThreadFlags |= SLEEPWALKER_THREAD_FLAG_CORRELATED_INTENT | SLEEPWALKER_THREAD_FLAG_CORR_MEMORY;
    }
    if (requireKernelCorrelationSignals && generatedRemoteAfterThread)
    {
        expected.RequiredThreadFlags |=
            SLEEPWALKER_THREAD_FLAG_CORRELATED_INTENT | SLEEPWALKER_THREAD_FLAG_CORR_THREAD_CTX;
    }
    if (requireKernelCorrelationSignals && generatedRemoteAfterDup)
    {
        expected.RequiredThreadFlags |=
            SLEEPWALKER_THREAD_FLAG_CORRELATED_INTENT | SLEEPWALKER_THREAD_FLAG_CORR_DUP_HANDLE;
    }

    PumpIoctlEvents(h, &state, &expected, 14000);

    RecordResult(&results, state.SawThread, "received thread telemetry via IOCTL",
                 "missing thread telemetry via IOCTL");

    if (expected.RequireHandleEvent)
    {
        RecordResult(&results, state.SawHandle, "received handle telemetry via IOCTL",
                     "missing handle telemetry via IOCTL");
    }

    if (generatedMemoryIntent)
    {
        RecordResult(&results, ((state.HandleFlagUnion & SLEEPWALKER_HANDLE_FLAG_MEMORY_RELATED) != 0),
                     "observed IOCTL handle flag MemoryRelated", "missing IOCTL handle flag MemoryRelated");
    }

    if (generatedThreadIntent)
    {
        RecordResult(&results, ((state.HandleFlagUnion & SLEEPWALKER_HANDLE_FLAG_THREAD_OBJECT) != 0),
                     "observed IOCTL handle flag ThreadObject", "missing IOCTL handle flag ThreadObject");
    }

    if (generatedDuplicateIntent)
    {
        RecordResult(&results, ((state.HandleFlagUnion & SLEEPWALKER_HANDLE_FLAG_DUPLICATE_OPERATION) != 0),
                     "observed IOCTL handle flag DuplicateOperation", "missing IOCTL handle flag DuplicateOperation");
    }

    if (generatedRemoteAfterMemory)
    {
        if (requireKernelCorrelationSignals)
        {
            RecordResult(&results, ((state.ThreadFlagUnion & SLEEPWALKER_THREAD_FLAG_CORR_MEMORY) != 0),
                         "observed IOCTL thread flag CorrelatedMemory", "missing IOCTL thread flag CorrelatedMemory");
        }
        else
        {
            RecordSkip(
                &results,
                "IOCTL thread flag CorrelatedMemory check skipped (kernel correlation disabled by architecture)");
        }
    }

    if (generatedRemoteAfterThread)
    {
        if (requireKernelCorrelationSignals)
        {
            RecordResult(&results, ((state.ThreadFlagUnion & SLEEPWALKER_THREAD_FLAG_CORR_THREAD_CTX) != 0),
                         "observed IOCTL thread flag CorrelatedThreadContext",
                         "missing IOCTL thread flag CorrelatedThreadContext");
        }
        else
        {
            RecordSkip(&results, "IOCTL thread flag CorrelatedThreadContext check skipped (kernel correlation disabled "
                                 "by architecture)");
        }
    }

    if (generatedRemoteAfterDup)
    {
        if (requireKernelCorrelationSignals)
        {
            RecordResult(&results, ((state.ThreadFlagUnion & SLEEPWALKER_THREAD_FLAG_CORR_DUP_HANDLE) != 0),
                         "observed IOCTL thread flag CorrelatedDuplicateHandle",
                         "missing IOCTL thread flag CorrelatedDuplicateHandle");
        }
        else
        {
            RecordSkip(&results, "IOCTL thread flag CorrelatedDuplicateHandle check skipped (kernel correlation "
                                 "disabled by architecture)");
        }
    }

    if (expected.RequiredThreadFlags != 0)
    {
        RecordResult(&results, ((state.ThreadFlagUnion & SLEEPWALKER_THREAD_FLAG_CORRELATED_INTENT) != 0),
                     "observed IOCTL thread flag CorrelatedIntent", "missing IOCTL thread flag CorrelatedIntent");
    }
    else if (generatedRemoteAfterMemory || generatedRemoteAfterThread || generatedRemoteAfterDup)
    {
        RecordSkip(&results,
                   "IOCTL thread flag CorrelatedIntent check skipped (kernel correlation disabled by architecture)");
    }

    multiClientParallelOk = RunMultiClientParallelIoctlTest(selfPid, child.Pi.dwProcessId, &multiClientPolls);
    RecordResult(&results, multiClientParallelOk, "multi-client parallel IOCTL fanout verified",
                 "multi-client parallel IOCTL fanout failed");
    printf("[INFO] multi-client parallel polls=%lu clients=%u\n", multiClientPolls, SLEEPWALKER_MULTI_CLIENT_COUNT);

    if (etwStarted)
    {
        etwCoverageMet = WaitForEtwEventCoverage(&etw, 10000, requireApcTelemetry);
        RecordResult(&results, etwCoverageMet,
                     requireApcTelemetry ? "ETW received all core event families (including APC)"
                                         : "ETW received all core event families (APC optional)",
                     requireApcTelemetry ? "ETW missing one or more core event families (including APC)"
                                         : "ETW missing one or more core event families (APC optional)");

        RecordResult(&results, (InterlockedCompareExchange(&etw.HandleEvents, 0, 0) > 0),
                     "ETW HandleTelemetry observed", "ETW HandleTelemetry missing");
        RecordResult(&results, (InterlockedCompareExchange(&etw.ThreadEvents, 0, 0) > 0),
                     "ETW ThreadTelemetry observed", "ETW ThreadTelemetry missing");
        RecordResult(&results, (InterlockedCompareExchange(&etw.ProcessEvents, 0, 0) > 0),
                     "ETW ProcessTelemetry observed", "ETW ProcessTelemetry missing");
        RecordResult(&results, (InterlockedCompareExchange(&etw.ImageEvents, 0, 0) > 0), "ETW ImageTelemetry observed",
                     "ETW ImageTelemetry missing");
        RecordResult(&results, (InterlockedCompareExchange(&etw.RegistryEvents, 0, 0) > 0),
                     "ETW RegistryTelemetry observed", "ETW RegistryTelemetry missing");
        if (requireApcTelemetry)
        {
            RecordResult(&results, (InterlockedCompareExchange(&etw.ApcEvents, 0, 0) > 0), "ETW ApcTelemetry observed",
                         "ETW ApcTelemetry missing");
        }
        else if (InterlockedCompareExchange(&etw.ApcEvents, 0, 0) > 0)
        {
            RecordResult(&results, TRUE, "ETW ApcTelemetry observed", "ETW ApcTelemetry missing");
        }
        else
        {
            RecordSkip(&results, "ETW ApcTelemetry check skipped (APC optional in current run)");
        }
        RecordResult(&results, (InterlockedCompareExchange(&etw.DetectionEvents, 0, 0) > 0),
                     "ETW DetectionTelemetry observed", "ETW DetectionTelemetry missing");

        if (generatedVmApiCalls)
        {
            if (etw.TiProviderEnabled)
            {
                RecordResult(&results, (InterlockedCompareExchange(&etw.TiAllocVmEvents, 0, 0) > 0),
                             "ETW TI AllocVM API-call observed", "ETW TI AllocVM API-call missing");
                RecordResult(&results, (InterlockedCompareExchange(&etw.TiWriteVmEvents, 0, 0) > 0),
                             "ETW TI WriteVM API-call observed", "ETW TI WriteVM API-call missing");
                RecordResult(&results, (InterlockedCompareExchange(&etw.TiProtectVmEvents, 0, 0) > 0),
                             "ETW TI ProtectVM API-call observed", "ETW TI ProtectVM API-call missing");
            }
            else
            {
                RecordSkip(&results, "ETW TI AllocVM API-call check skipped (provider unavailable)");
                RecordSkip(&results, "ETW TI WriteVM API-call check skipped (provider unavailable)");
                RecordSkip(&results, "ETW TI ProtectVM API-call check skipped (provider unavailable)");
            }
        }

        if (generatedRegistry)
        {
            RecordResult(&results, (InterlockedCompareExchange(&etw.DetectRegistryHighValue, 0, 0) > 0),
                         "ETW detection HIGH_VALUE_REGISTRY_ACTIVITY observed",
                         "ETW detection HIGH_VALUE_REGISTRY_ACTIVITY missing");
        }

        if (generatedRemoteAfterMemory || generatedRemoteAfterThread || generatedRemoteAfterDup)
        {
            if (requireKernelCorrelationSignals)
            {
                RecordResult(&results, (InterlockedCompareExchange(&etw.DetectRemoteThreadWithIntent, 0, 0) > 0),
                             "ETW detection REMOTE_THREAD_WITH_RECENT_HANDLE_INTENT observed",
                             "ETW detection REMOTE_THREAD_WITH_RECENT_HANDLE_INTENT missing");
            }
            else
            {
                RecordSkip(&results, "ETW detection REMOTE_THREAD_WITH_RECENT_HANDLE_INTENT check skipped (kernel "
                                     "correlation disabled by architecture)");
            }
        }

        if (generatedMemoryIntent && generatedThreadIntent)
        {
            if (requireKernelCorrelationSignals)
            {
                RecordResult(&results, (InterlockedCompareExchange(&etw.DetectRemoteApcCreationSuspect, 0, 0) > 0),
                             "ETW detection REMOTE_APC_CREATION_SUSPECT observed",
                             "ETW detection REMOTE_APC_CREATION_SUSPECT missing");
            }
            else
            {
                RecordSkip(&results, "ETW detection REMOTE_APC_CREATION_SUSPECT check skipped (kernel correlation "
                                     "disabled by architecture)");
            }
        }

        if (generatedThreadIntent)
        {
            if (requireKernelCorrelationSignals)
            {
                RecordResult(&results, (InterlockedCompareExchange(&etw.DetectThreadHijackIntent, 0, 0) > 0),
                             "ETW detection THREAD_HIJACK_INTENT observed",
                             "ETW detection THREAD_HIJACK_INTENT missing");
            }
            else
            {
                RecordSkip(
                    &results,
                    "ETW detection THREAD_HIJACK_INTENT check skipped (kernel correlation disabled by architecture)");
            }
        }

        if (generatedRemoteAfterThread)
        {
            if (requireKernelCorrelationSignals)
            {
                LONG ctxIntent = InterlockedCompareExchange(&etw.DetectThreadContextIntent, 0, 0);
                LONG remoteIntent = InterlockedCompareExchange(&etw.DetectRemoteThreadWithIntent, 0, 0);
                LONG manualMapLike = InterlockedCompareExchange(&etw.DetectManualMapOrHollowingExec, 0, 0);

                if (ctxIntent > 0)
                {
                    RecordResult(&results, TRUE, "ETW detection THREAD_ACTIVITY_WITH_THREAD_CONTEXT_INTENT observed",
                                 "ETW detection THREAD_ACTIVITY_WITH_THREAD_CONTEXT_INTENT missing");
                }
                else if (remoteIntent > 0 || manualMapLike > 0)
                {
                    RecordSkip(&results, "ETW THREAD_ACTIVITY_WITH_THREAD_CONTEXT_INTENT check skipped "
                                         "(higher-priority thread detection emitted)");
                }
                else
                {
                    RecordResult(&results, FALSE, "ETW detection THREAD_ACTIVITY_WITH_THREAD_CONTEXT_INTENT observed",
                                 "ETW detection THREAD_ACTIVITY_WITH_THREAD_CONTEXT_INTENT missing");
                }
            }
            else
            {
                RecordSkip(&results, "ETW detection THREAD_ACTIVITY_WITH_THREAD_CONTEXT_INTENT check skipped (kernel "
                                     "correlation disabled by architecture)");
            }
        }

        if (generatedMemoryIntent && generatedThreadIntent)
        {
            if (requireKernelCorrelationSignals)
            {
                RecordResult(&results, (InterlockedCompareExchange(&etw.DetectIntentChain, 0, 0) > 0),
                             "ETW detection POSSIBLE_PROCESS_HOLLOWING_OR_INJECTION_INTENT_CHAIN observed",
                             "ETW detection POSSIBLE_PROCESS_HOLLOWING_OR_INJECTION_INTENT_CHAIN missing");
            }
            else
            {
                RecordSkip(&results, "ETW detection POSSIBLE_PROCESS_HOLLOWING_OR_INJECTION_INTENT_CHAIN check skipped "
                                     "(kernel correlation disabled by architecture)");
            }
        }

        RecordResult(&results, (InterlockedCompareExchange(&etw.DetectTamper, 0, 0) == 0),
                     "no anti-tamper dispatch/object drift observed during baseline run",
                     "unexpected anti-tamper dispatch/object drift detected during baseline run");

        printf("[INFO] ETW counts handle=%ld thread=%ld process=%ld image=%ld registry=%ld apc=%ld detection=%ld "
               "ti=%ld unknown=%ld det{remoteIntent=%ld remoteApc=%ld hijack=%ld threadCtx=%ld regHigh=%ld chain=%ld "
               "directSys=%ld manualMap=%ld ntdllPath=%ld ntdllMulti=%ld tamper=%ld tamperClear=%ld} tiTask{alloc=%ld "
               "protect=%ld write=%ld syscallUsage=%ld tiUnknown=%ld}\n",
               InterlockedCompareExchange(&etw.HandleEvents, 0, 0), InterlockedCompareExchange(&etw.ThreadEvents, 0, 0),
               InterlockedCompareExchange(&etw.ProcessEvents, 0, 0), InterlockedCompareExchange(&etw.ImageEvents, 0, 0),
               InterlockedCompareExchange(&etw.RegistryEvents, 0, 0), InterlockedCompareExchange(&etw.ApcEvents, 0, 0),
               InterlockedCompareExchange(&etw.DetectionEvents, 0, 0), InterlockedCompareExchange(&etw.TiEvents, 0, 0),
               InterlockedCompareExchange(&etw.UnknownEvents, 0, 0),
               InterlockedCompareExchange(&etw.DetectRemoteThreadWithIntent, 0, 0),
               InterlockedCompareExchange(&etw.DetectRemoteApcCreationSuspect, 0, 0),
               InterlockedCompareExchange(&etw.DetectThreadHijackIntent, 0, 0),
               InterlockedCompareExchange(&etw.DetectThreadContextIntent, 0, 0),
               InterlockedCompareExchange(&etw.DetectRegistryHighValue, 0, 0),
               InterlockedCompareExchange(&etw.DetectIntentChain, 0, 0),
               InterlockedCompareExchange(&etw.DetectDirectSyscallSuspect, 0, 0),
               InterlockedCompareExchange(&etw.DetectManualMapOrHollowingExec, 0, 0),
               InterlockedCompareExchange(&etw.DetectSuspiciousNtdllPath, 0, 0),
               InterlockedCompareExchange(&etw.DetectMultipleNtdllMappings, 0, 0),
               InterlockedCompareExchange(&etw.DetectTamper, 0, 0),
               InterlockedCompareExchange(&etw.DetectTamperCleared, 0, 0),
               InterlockedCompareExchange(&etw.TiAllocVmEvents, 0, 0),
               InterlockedCompareExchange(&etw.TiProtectVmEvents, 0, 0),
               InterlockedCompareExchange(&etw.TiWriteVmEvents, 0, 0),
               InterlockedCompareExchange(&etw.TiSyscallUsageEvents, 0, 0),
               InterlockedCompareExchange(&etw.TiUnknownTaskEvents, 0, 0));
    }

Cleanup:
    if (subscribedChild)
    {
        ok = Unsubscribe(h, child.Pi.dwProcessId);
        RecordResult(&results, ok, "unsubscribed child", "unsubscribe child failed");
    }

    if (subscribedSelf)
    {
        ok = Unsubscribe(h, selfPid);
        RecordResult(&results, ok, "unsubscribed self", "unsubscribe self failed");
    }

    StopIdleChild(&child);

    if (etwStarted)
    {
        StopEtwCapture(&etw);
    }

    if (h != INVALID_HANDLE_VALUE)
    {
        CloseHandle(h);
    }

    SLEEPWALKERSymbolResolverCleanup();
    if (results.Passed == results.Total)
    {
        SuiteCloseReport(&results, state.Polls);
        return 0;
    }

    SuiteCloseReport(&results, state.Polls);
    return 1;
}
