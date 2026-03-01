#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <tdh.h>
#include <strsafe.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>
#include <wctype.h>
#include <math.h>
#include <stdarg.h>
#include "..\..\abi\sleepwalker_ioctl.h"
#include "sleepwalker_sensor_core.h"
#include "sleepwalker_etw_printer.h"
#include "sleepwalker_etw_symbols.h"

#pragma comment(lib, "tdh.lib")

#define SLEEPWALKER_PATH_CHARS 1024

typedef enum _SLEEPWALKER_TARGET_KIND
{
    SleepwalkerTargetPid = 0,
    SleepwalkerTargetName = 1,
    SleepwalkerTargetPath = 2,
    SleepwalkerTargetLaunch = 3
} SLEEPWALKER_TARGET_KIND;

typedef enum _SLEEPWALKER_TARGET_SCOPE
{
    SleepwalkerScopeLocal = 0,
    SleepwalkerScopeRemote = 1,
    SleepwalkerScopeBoth = 2
} SLEEPWALKER_TARGET_SCOPE;

typedef struct _SLEEPWALKER_TARGET_SPEC
{
    SLEEPWALKER_TARGET_KIND Kind;
    DWORD Pid;
    WCHAR Name[MAX_PATH];
    WCHAR PathRaw[SLEEPWALKER_PATH_CHARS];
    WCHAR PathNormDos[SLEEPWALKER_PATH_CHARS];
    WCHAR PathNormNt[SLEEPWALKER_PATH_CHARS];
    WCHAR PathTail[SLEEPWALKER_PATH_CHARS];
} SLEEPWALKER_TARGET_SPEC;

typedef struct _SLEEPWALKER_PATH_WATCH_CONTEXT
{
    WCHAR TargetNormDos[SLEEPWALKER_PATH_CHARS];
    WCHAR TargetNormNt[SLEEPWALKER_PATH_CHARS];
    WCHAR TargetTail[SLEEPWALKER_PATH_CHARS];
    volatile LONG Matched;
    volatile LONG SessionEnded;
    DWORD MatchedPid;
} SLEEPWALKER_PATH_WATCH_CONTEXT;

typedef struct _SLEEPWALKER_ETW_RUN_CONTEXT
{
    SLEEPWALKERSC_ETW_SESSION *Session;
    SLEEPWALKER_PATH_WATCH_CONTEXT *Watch;
} SLEEPWALKER_ETW_RUN_CONTEXT;

typedef struct _SLEEPWALKER_ATTACH_CONTEXT
{
    HANDLE Device;
    DWORD StreamMask;
    DWORD TargetPid;
    SLEEPWALKER_TARGET_SCOPE Scope;
} SLEEPWALKER_ATTACH_CONTEXT;

typedef struct _SLEEPWALKER_LIVE_ETW_CONTEXT
{
    SLEEPWALKERSC_ETW_SESSION *Session;
    SLEEPWALKER_ATTACH_CONTEXT *Attach;
    volatile LONG SessionEnded;
} SLEEPWALKER_LIVE_ETW_CONTEXT;

typedef struct _SLEEPWALKER_BROKER_ETW_CONTEXT
{
    HANDLE Device;
    BOOL ThreatIntelEnabled;
    DWORD TiEnableError;
    DWORD TargetPid;
    SLEEPWALKER_TARGET_SCOPE Scope;
    volatile LONG SessionEnded;
} SLEEPWALKER_BROKER_ETW_CONTEXT;

typedef struct _SLEEPWALKER_LAUNCH_TARGET
{
    BOOL Active;
    BOOL Resumed;
    PROCESS_INFORMATION ProcessInfo;
} SLEEPWALKER_LAUNCH_TARGET;

typedef enum _SLEEPWALKER_LOG_FORMAT
{
    SleepwalkerLogFormatText = 0,
    SleepwalkerLogFormatJsonl = 1
} SLEEPWALKER_LOG_FORMAT;

typedef struct _SLEEPWALKER_CLIENT_POLICY
{
    BOOL HasTarget;
    BOOL HasStreams;
    BOOL HasScope;
    char TargetArg[512];
    char StreamsArg[128];
    char ScopeArg[32];

    SLEEPWALKER_LOG_FORMAT LogFormat;
    char LogFilePath[MAX_PATH];
    char HighPriorityFilePath[MAX_PATH];
    DWORD HighPriorityMinSeverity;
    BOOL IoctlVerboseOverrideSet;
    BOOL IoctlVerboseOverride;

    BOOL AllowIoctlHandle;
    BOOL AllowIoctlThread;
    BOOL AllowEtwSleepwalker;
    BOOL AllowEtwTi;
} SLEEPWALKER_CLIENT_POLICY;

typedef struct _SLEEPWALKER_LOGGER
{
    SLEEPWALKER_CLIENT_POLICY Policy;
    FILE *LogFile;
    FILE *HighPriorityFile;
    DWORD TargetPid;
} SLEEPWALKER_LOGGER;

static volatile LONG g_StopRequested = 0;
static SLEEPWALKERSC_ETW_SESSION *g_StopSession = NULL;
static SLEEPWALKER_LOGGER g_Logger;
static void LoggerEmitEtwRecord(_In_ PEVENT_RECORD Record, _In_opt_z_ PCWSTR EventName);
static void LoggerEmitBrokerEtwEvent(_In_ const SLEEPWALKER_IPC_ETW_EVENT *Event);

static BOOL WINAPI ConsoleCtrlHandler(_In_ DWORD CtrlType)
{
    UNREFERENCED_PARAMETER(CtrlType);
    InterlockedExchange(&g_StopRequested, 1);
    if (g_StopSession != NULL)
    {
        SLEEPWALKERSCStopEtwSession(g_StopSession);
    }
    return TRUE;
}

#include "client/sleepwalker_client_targets.inc"
#include "client/sleepwalker_client_etw.inc"
#include "client/sleepwalker_client_attach.inc"
#include "client/sleepwalker_client_ui.inc"
#include "client/sleepwalker_client_main.inc"

