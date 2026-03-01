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
    volatile LONG DetectKernelHollowingMarkMedium;
    volatile LONG DetectKernelHollowingMarkStrong;
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

typedef struct _BROKER_ETW_CAPTURE
{
    HANDLE Device;
    HANDLE TraceThread;
    volatile LONG StopRequested;
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
    volatile LONG DetectHollowingMarkMedium;
    volatile LONG DetectHollowingMarkStrong;
    volatile LONG DetectHollowingTxfChain;
    volatile LONG UnknownEvents;
    BOOL TiProviderEnabled;
    DWORD TiEnableError;
} BROKER_ETW_CAPTURE;

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
#define SLEEPWALKER_CHILD_SPAWN_AND_TOUCH_ARG "--spawn-and-touch"
#define SLEEPWALKER_CHILD_SPAWN_AND_TOUCH_ARGW L"--spawn-and-touch"
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

#include "tests/sleepwalker_ioctl_test_report.inc"
#include "tests/sleepwalker_ioctl_test_env.inc"
#include "tests/sleepwalker_ioctl_test_ioctl.inc"
#include "tests/sleepwalker_ioctl_test_intent.inc"
#include "tests/sleepwalker_ioctl_test_etw.inc"
#include "tests/sleepwalker_ioctl_test_main.inc"

