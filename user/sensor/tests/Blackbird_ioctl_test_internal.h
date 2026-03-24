#ifndef BLACKBIRD_IOCTL_TEST_INTERNAL_H
#define BLACKBIRD_IOCTL_TEST_INTERNAL_H

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
#include "..\\..\\..\\abi\\blackbird_ioctl.h"
#include "..\\blackbird_event_printer.h"
#include "..\\blackbird_sensor_core.h"
#include "..\\blackbird_symbol_resolver.h"
#include "..\\blackbird_test_report_html.h"

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
    BLACKBIRDSC_ETW_SESSION *Session;
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
    BLACKBIRD_REPORT_META *Meta;
    size_t MetaCount;
    size_t MetaCapacity;
    BLACKBIRD_REPORT_CHECK *Checks;
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

typedef struct _BLACKBIRD_MULTI_CLIENT_WORKER
{
    HANDLE Device;
    DWORD MaxMs;
    BOOL SawHandle;
    BOOL SawThread;
    DWORD Polls;
    DWORD UnexpectedError;
} BLACKBIRD_MULTI_CLIENT_WORKER;

#define BLACKBIRD_CHILD_ARG "--idle-child"
#define BLACKBIRD_CHILD_ARGW L"--idle-child"
#define BLACKBIRD_CHILD_SPAWN_AND_TOUCH_ARG "--spawn-and-touch"
#define BLACKBIRD_CHILD_SPAWN_AND_TOUCH_ARGW L"--spawn-and-touch"
#define BLACKBIRD_SUITE_ETW_SESSION L"BlackbirdTestSuiteSession"
#define BLACKBIRD_MULTI_CLIENT_COUNT 3
#define BLACKBIRD_MULTI_CLIENT_TIMEOUT_MS 8000
#define BLACKBIRD_SYSTEM_CODEINTEGRITY_INFORMATION_CLASS 103
#define BLACKBIRD_SYSTEM_KERNEL_DEBUGGER_INFORMATION_CLASS 35

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#define BLACKBIRD_CI_OPTION_ENABLED 0x0001
#define BLACKBIRD_CI_OPTION_TESTSIGN 0x0002
#define BLACKBIRD_CI_OPTION_UMCI_ENABLED 0x0004
#define BLACKBIRD_CI_OPTION_DEBUGMODE 0x0080
#define BLACKBIRD_CI_OPTION_FLIGHTING 0x0200
#define BLACKBIRD_CI_OPTION_HVCI_KMCI_ENABLED 0x0400
#define BLACKBIRD_CI_OPTION_HVCI_KMCI_AUDIT 0x0800
#define BLACKBIRD_CI_OPTION_HVCI_KMCI_STRICT 0x1000
#define BLACKBIRD_CI_OPTION_WHQL_ENFORCEMENT_ENABLED 0x4000

extern ETW_CAPTURE *g_ActiveEtwCapture;

BOOL EnvFlagEnabled(_In_z_ const char *Name, _In_ BOOL DefaultValue);
BOOL StartIdleChild(_Out_ CHILD_CTX *child);
BOOL StartSpawnAndTouchChild(_Out_ CHILD_CTX *child);
void StopIdleChild(_Inout_ CHILD_CTX *child);
BOOL GenerateMemoryHandleIntent(DWORD pid);
BOOL GenerateThreadContextHandleIntent(DWORD tid);
BOOL GenerateDuplicateHandleIntent(DWORD pid);
BOOL GenerateRemoteThreadLoadLibraryIntent(DWORD pid);
BOOL GenerateVmApiCallSurface(DWORD pid);
BOOL GenerateSuspendedHollowingLikeChain(VOID);
BOOL GenerateRegistryHighValueActivity(void);

BOOL Subscribe(HANDLE h, DWORD pid, DWORD mask);
BOOL SetPids(HANDLE h, const DWORD *pids, DWORD count, DWORD mask);
BOOL Unsubscribe(HANDLE h, DWORD pid);
HANDLE OpenControlDeviceHandle(void);
BOOL RunMultiClientParallelIoctlTest(_In_ DWORD CallerPid, _In_ DWORD TargetPid, _Out_opt_ DWORD *TotalPolls);
void PumpIoctlEvents(HANDLE h, TEST_STATE *state, const TEST_EXPECTED *expected, DWORD maxMs);
void GenerateLocalThreadEvent(void);

BOOL GetEtwAnsiProperty(_In_ PEVENT_RECORD Record, _In_z_ PCWSTR Name, _Out_writes_z_(OutputChars) PSTR Output,
                        _In_ size_t OutputChars);
BOOL StartBrokerEtwCapture(_Out_ BROKER_ETW_CAPTURE *cap, _In_reads_opt_(SeedCount) const DWORD *SeedPids,
                           _In_ DWORD SeedCount, _In_ DWORD StreamMask);
VOID StopBrokerEtwCapture(_Inout_ BROKER_ETW_CAPTURE *cap);
BOOL WaitForBrokerEtwEventCoverage(_In_ BROKER_ETW_CAPTURE *cap, _In_ DWORD maxMs, _In_ BOOL requireApcTelemetry);

BOOL SuiteInitReport(_Inout_ SUITE_RESULTS *Results);
VOID SuiteCloseReport(_Inout_ SUITE_RESULTS *Results, _In_ DWORD Polls);
VOID RecordResult(_Inout_ SUITE_RESULTS *Results, _In_ BOOL Passed, _In_z_ const char *PassText,
                  _In_opt_z_ const char *FailText);
VOID RecordSkip(_Inout_ SUITE_RESULTS *Results, _In_z_ const char *SkipText);
VOID LogEnvironmentBaseline(_Inout_ SUITE_RESULTS *Results);

#endif
