#ifndef BLACKBIRD_CLIENT_INTERNAL_H
#define BLACKBIRD_CLIENT_INTERNAL_H

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
#include "..\..\..\abi\blackbird_ioctl.h"
#include "..\blackbird_sensor_core.h"
#include "..\blackbird_etw_printer.h"
#include "..\blackbird_etw_symbols.h"

#define BLACKBIRD_PATH_CHARS 1024

typedef enum _BLACKBIRD_TARGET_KIND
{
    BlackbirdTargetPid = 0,
    BlackbirdTargetName = 1,
    BlackbirdTargetPath = 2,
    BlackbirdTargetLaunch = 3
} BLACKBIRD_TARGET_KIND;

typedef enum _BLACKBIRD_TARGET_SCOPE
{
    BlackbirdScopeLocal = 0,
    BlackbirdScopeRemote = 1,
    BlackbirdScopeBoth = 2
} BLACKBIRD_TARGET_SCOPE;

typedef struct _BLACKBIRD_TARGET_SPEC
{
    BLACKBIRD_TARGET_KIND Kind;
    DWORD Pid;
    WCHAR Name[MAX_PATH];
    WCHAR PathRaw[BLACKBIRD_PATH_CHARS];
    WCHAR PathNormDos[BLACKBIRD_PATH_CHARS];
    WCHAR PathNormNt[BLACKBIRD_PATH_CHARS];
    WCHAR PathTail[BLACKBIRD_PATH_CHARS];
} BLACKBIRD_TARGET_SPEC;

typedef struct _BLACKBIRD_PATH_WATCH_CONTEXT
{
    WCHAR TargetNormDos[BLACKBIRD_PATH_CHARS];
    WCHAR TargetNormNt[BLACKBIRD_PATH_CHARS];
    WCHAR TargetTail[BLACKBIRD_PATH_CHARS];
    volatile LONG Matched;
    volatile LONG SessionEnded;
    DWORD MatchedPid;
} BLACKBIRD_PATH_WATCH_CONTEXT;

typedef struct _BLACKBIRD_ETW_RUN_CONTEXT
{
    BLACKBIRDSC_ETW_SESSION *Session;
    BLACKBIRD_PATH_WATCH_CONTEXT *Watch;
} BLACKBIRD_ETW_RUN_CONTEXT;

typedef struct _BLACKBIRD_ATTACH_CONTEXT
{
    HANDLE Device;
    DWORD StreamMask;
    DWORD TargetPid;
    BLACKBIRD_TARGET_SCOPE Scope;
} BLACKBIRD_ATTACH_CONTEXT;

typedef struct _BLACKBIRD_LIVE_ETW_CONTEXT
{
    BLACKBIRDSC_ETW_SESSION *Session;
    BLACKBIRD_ATTACH_CONTEXT *Attach;
    volatile LONG SessionEnded;
} BLACKBIRD_LIVE_ETW_CONTEXT;

typedef struct _BLACKBIRD_BROKER_ETW_CONTEXT
{
    HANDLE Device;
    BOOL ThreatIntelEnabled;
    DWORD TiEnableError;
    DWORD TargetPid;
    BLACKBIRD_TARGET_SCOPE Scope;
    volatile LONG SessionEnded;
} BLACKBIRD_BROKER_ETW_CONTEXT;

typedef struct _BLACKBIRD_LAUNCH_TARGET
{
    BOOL Active;
    BOOL Resumed;
    PROCESS_INFORMATION ProcessInfo;
} BLACKBIRD_LAUNCH_TARGET;

typedef enum _BLACKBIRD_LOG_FORMAT
{
    BlackbirdLogFormatText = 0,
    BlackbirdLogFormatJsonl = 1
} BLACKBIRD_LOG_FORMAT;

typedef struct _BLACKBIRD_CLIENT_POLICY
{
    BOOL HasTarget;
    BOOL HasStreams;
    BOOL HasScope;
    char TargetArg[512];
    char StreamsArg[128];
    char ScopeArg[32];

    BLACKBIRD_LOG_FORMAT LogFormat;
    char LogFilePath[MAX_PATH];
    char HighPriorityFilePath[MAX_PATH];
    DWORD HighPriorityMinSeverity;
    BOOL IoctlVerboseOverrideSet;
    BOOL IoctlVerboseOverride;

    BOOL AllowIoctlHandle;
    BOOL AllowIoctlThread;
    BOOL AllowIoctlFilesystem;
    BOOL AllowEtwBlackbird;
    BOOL AllowEtwTi;
} BLACKBIRD_CLIENT_POLICY;

typedef struct _BLACKBIRD_LOGGER
{
    BLACKBIRD_CLIENT_POLICY Policy;
    FILE *LogFile;
    FILE *HighPriorityFile;
    DWORD TargetPid;
} BLACKBIRD_LOGGER;

extern volatile LONG g_StopRequested;
extern BLACKBIRDSC_ETW_SESSION *g_StopSession;
extern BLACKBIRD_LOGGER g_Logger;

BOOL WINAPI ConsoleCtrlHandler(_In_ DWORD CtrlType);

DWORD FindProcessIdByNameW(_In_z_ const wchar_t *processName);
DWORD FindProcessIdByPathSpec(_In_ const BLACKBIRD_TARGET_SPEC *Spec);
VOID WINAPI LiveEtwCallback(_In_ PEVENT_RECORD Record, _In_opt_z_ PCWSTR EventName, _In_opt_ PVOID Context);
VOID WINAPI PathWatchEtwCallback(_In_ PEVENT_RECORD Record, _In_opt_z_ PCWSTR EventName, _In_opt_ PVOID Context);
DWORD WINAPI EtwRunThreadProc(_In_ LPVOID Context);

HANDLE OpenControlDeviceByPolicy(_In_opt_z_ const char *BrokerPipeUtf8, _Out_opt_ BOOL *UsingBroker);
BOOL ResolveTargetSpec(_In_z_ const char *TargetArg, _Out_ BLACKBIRD_TARGET_SPEC *Spec);
BOOL ParseScopeArg(_In_opt_z_ const char *Text, _Out_ BLACKBIRD_TARGET_SCOPE *Scope);
const char *ScopeToString(_In_ BLACKBIRD_TARGET_SCOPE Scope);
BOOL ScopeMatches(_In_ BLACKBIRD_TARGET_SCOPE Scope, _In_ BOOL LocalMatch, _In_ BOOL RemoteMatch);

void PolicyDefaults(_Out_ BLACKBIRD_CLIENT_POLICY *Policy);
BOOL PolicySetKeyValue(_Inout_ BLACKBIRD_CLIENT_POLICY *Policy, _In_z_ const char *Key, _In_z_ const char *Value);
BOOL LoadPolicyFile(_In_z_ const char *Path, _Inout_ BLACKBIRD_CLIENT_POLICY *Policy);

BOOL ResolveTargetPid(_In_ const BLACKBIRD_TARGET_SPEC *Spec,
                      _Out_ DWORD *Pid,
                      _Out_opt_ BLACKBIRD_LAUNCH_TARGET *Launch);
VOID PrimeTargetImageHint(_In_ HANDLE Device, _In_ const BLACKBIRD_TARGET_SPEC *Spec, _In_ DWORD TargetPid);
BOOL AttachProgramTargetPid(_Inout_ BLACKBIRD_ATTACH_CONTEXT *Attach);

BOOL WaitForPathLaunchViaEtw(_In_ const BLACKBIRD_TARGET_SPEC *Spec, _Out_ DWORD *Pid);
BOOL BrokerEtwEventMatchesTargetPid(_In_ const BLACKBIRD_IPC_ETW_EVENT *Event,
                                    _In_ DWORD TargetPid,
                                    _In_ BLACKBIRD_TARGET_SCOPE Scope);
BOOL StartBrokerEtw(_Inout_ BLACKBIRD_BROKER_ETW_CONTEXT *Broker,
                    _Out_ HANDLE *ThreadHandle,
                    _In_ DWORD SeedPid,
                    _In_ DWORD StreamMask,
                    _In_ BLACKBIRD_TARGET_SCOPE Scope);

void PrintUsage(void);
BOOL IoctlRecordMatchesTargetPid(_In_ const BLACKBIRD_EVENT_RECORD *Record,
                                 _In_ DWORD TargetPid,
                                 _In_ BLACKBIRD_TARGET_SCOPE Scope);
void PrintHandleEvent(_In_ const BLACKBIRD_HANDLE_EVENT *h, _In_ DWORD sequence);
void PrintThreadEvent(_In_ const BLACKBIRD_THREAD_EVENT *t, _In_ DWORD sequence);
void PrintFileEvent(_In_ const BLACKBIRD_FILE_EVENT *f, _In_ DWORD sequence);

void WideToUtf8(_In_opt_z_ const WCHAR *Wide, _Out_writes_z_(OutputChars) char *Output, _In_ size_t OutputChars);
BOOL GetEtwWideProperty(_In_ PEVENT_RECORD Record,
                        _In_z_ PCWSTR Name,
                        _Out_writes_z_(OutputChars) PWSTR Output,
                        _In_ size_t OutputChars);
BOOL GetEtwAnsiProperty(_In_ PEVENT_RECORD Record,
                        _In_z_ PCWSTR Name,
                        _Out_writes_z_(OutputChars) PSTR Output,
                        _In_ size_t OutputChars);
BOOL GetEtwU64Property(_In_ PEVENT_RECORD Record, _In_z_ PCWSTR Name, _Out_ ULONGLONG *Value);

BOOL LoggerInitialize(_In_ const BLACKBIRD_CLIENT_POLICY *Policy, _In_ DWORD TargetPid);
void LoggerShutdown(void);
void LoggerEmitJson(_In_ DWORD Severity,
                    _In_z_ const char *Category,
                    _In_z_ const char *Kind,
                    _In_ DWORD Pid,
                    _In_ DWORD TargetPid,
                    _In_z_ const char *Message);
void LoggerEmitEtwRecord(_In_ PEVENT_RECORD Record, _In_opt_z_ PCWSTR EventName);
void LoggerEmitBrokerEtwEvent(_In_ const BLACKBIRD_IPC_ETW_EVENT *Event);

#endif
