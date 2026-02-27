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

static DWORD FindProcessIdByNameW(_In_z_ const wchar_t *processName)
{
    PROCESSENTRY32W pe;
    HANDLE snapshot;

    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
    {
        return 0;
    }

    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snapshot, &pe))
    {
        do
        {
            if (_wcsicmp(pe.szExeFile, processName) == 0)
            {
                CloseHandle(snapshot);
                return pe.th32ProcessID;
            }
        } while (Process32NextW(snapshot, &pe));
    }

    CloseHandle(snapshot);
    return 0;
}

static BOOL TryParsePid(_In_z_ const char *text, _Out_ DWORD *pid)
{
    char *end = NULL;
    unsigned long value;

    if (text == NULL || pid == NULL)
    {
        return FALSE;
    }

    value = strtoul(text, &end, 10);
    if (end == text || *end != '\0' || value == 0 || value > 0xFFFFFFFFul)
    {
        return FALSE;
    }

    *pid = (DWORD)value;
    return TRUE;
}

static BOOL ConvertArgToWide(_In_z_ const char *Text, _Out_writes_z_(OutputChars) WCHAR *Output,
                             _In_ size_t OutputChars)
{
    int converted;

    if (Text == NULL || Output == NULL || OutputChars == 0)
    {
        return FALSE;
    }

    Output[0] = L'\0';
    converted = MultiByteToWideChar(CP_UTF8, 0, Text, -1, Output, (int)OutputChars);
    if (converted <= 0)
    {
        converted = MultiByteToWideChar(CP_ACP, 0, Text, -1, Output, (int)OutputChars);
    }
    return (converted > 0);
}

static VOID StripWrappingQuotesInPlace(_Inout_updates_z_(BufferChars) WCHAR *Buffer, _In_ size_t BufferChars)
{
    size_t len;

    if (Buffer == NULL || BufferChars == 0)
    {
        return;
    }

    len = wcslen(Buffer);
    if (len >= 2 && Buffer[0] == L'"' && Buffer[len - 1] == L'"')
    {
        size_t i;
        for (i = 0; i + 1 < len; ++i)
        {
            Buffer[i] = Buffer[i + 1];
        }
        Buffer[len - 2] = L'\0';
    }
}

static VOID NormalizePathForCompare(_In_z_ const WCHAR *Input, _Out_writes_z_(OutputChars) WCHAR *Output,
                                    _In_ size_t OutputChars)
{
    size_t i;
    size_t j = 0;

    if (Output == NULL || OutputChars == 0)
    {
        return;
    }
    Output[0] = L'\0';

    if (Input == NULL)
    {
        return;
    }

    for (i = 0; Input[i] != L'\0' && (j + 1) < OutputChars; ++i)
    {
        WCHAR ch = Input[i];
        if (ch == L'/')
        {
            ch = L'\\';
        }
        Output[j++] = (WCHAR)towlower(ch);
    }
    Output[j] = L'\0';
}

static BOOL IsDrivePathW(_In_z_ const WCHAR *Path)
{
    if (Path == NULL)
    {
        return FALSE;
    }
    return (Path[0] != L'\0' && Path[1] == L':');
}

static VOID BuildTailFromDosPath(_In_z_ const WCHAR *DosPath, _Out_writes_z_(TailChars) WCHAR *Tail,
                                 _In_ size_t TailChars)
{
    WCHAR normalized[SLEEPWALKER_PATH_CHARS];

    if (Tail == NULL || TailChars == 0)
    {
        return;
    }
    Tail[0] = L'\0';

    if (DosPath == NULL || !IsDrivePathW(DosPath) || DosPath[2] == L'\0')
    {
        return;
    }

    NormalizePathForCompare(DosPath + 2, normalized, RTL_NUMBER_OF(normalized));
    (void)StringCchCopyW(Tail, TailChars, normalized);
}

static BOOL BuildNtPathFromDosPath(_In_z_ const WCHAR *DosPath, _Out_writes_z_(NtChars) WCHAR *NtPath,
                                   _In_ size_t NtChars)
{
    WCHAR drive[3];
    WCHAR devicePrefix[SLEEPWALKER_PATH_CHARS];

    if (DosPath == NULL || NtPath == NULL || NtChars == 0 || !IsDrivePathW(DosPath))
    {
        return FALSE;
    }

    drive[0] = (WCHAR)towupper(DosPath[0]);
    drive[1] = L':';
    drive[2] = L'\0';

    if (!QueryDosDeviceW(drive, devicePrefix, RTL_NUMBER_OF(devicePrefix)))
    {
        NtPath[0] = L'\0';
        return FALSE;
    }

    if (FAILED(StringCchPrintfW(NtPath, NtChars, L"%ls%ls", devicePrefix, DosPath + 2)))
    {
        NtPath[0] = L'\0';
        return FALSE;
    }
    return TRUE;
}

static BOOL PathHasTrailingSegment(_In_z_ const WCHAR *Path, _In_z_ const WCHAR *Tail)
{
    size_t pathLen;
    size_t tailLen;
    const WCHAR *end;

    if (Path == NULL || Tail == NULL || Tail[0] == L'\0')
    {
        return FALSE;
    }

    pathLen = wcslen(Path);
    tailLen = wcslen(Tail);
    if (tailLen > pathLen)
    {
        return FALSE;
    }

    end = Path + (pathLen - tailLen);
    if (_wcsicmp(end, Tail) != 0)
    {
        return FALSE;
    }

    if (end == Path)
    {
        return TRUE;
    }
    return (end[-1] == L'\\');
}

static BOOL PathMatchesSpec(_In_ const SLEEPWALKER_TARGET_SPEC *Spec, _In_z_ const WCHAR *CandidatePath)
{
    WCHAR candidateNorm[SLEEPWALKER_PATH_CHARS];

    if (Spec == NULL || CandidatePath == NULL)
    {
        return FALSE;
    }

    NormalizePathForCompare(CandidatePath, candidateNorm, RTL_NUMBER_OF(candidateNorm));
    if (candidateNorm[0] == L'\0')
    {
        return FALSE;
    }

    if (Spec->PathNormDos[0] != L'\0' && _wcsicmp(candidateNorm, Spec->PathNormDos) == 0)
    {
        return TRUE;
    }

    if (Spec->PathNormNt[0] != L'\0' && _wcsicmp(candidateNorm, Spec->PathNormNt) == 0)
    {
        return TRUE;
    }

    if (Spec->PathTail[0] != L'\0' && PathHasTrailingSegment(candidateNorm, Spec->PathTail))
    {
        return TRUE;
    }

    return FALSE;
}

static BOOL ResolvePathSpec(_In_z_ const char *PathText, _Out_ SLEEPWALKER_TARGET_SPEC *Spec)
{
    WCHAR inputWide[SLEEPWALKER_PATH_CHARS];
    WCHAR canonical[SLEEPWALKER_PATH_CHARS];
    WCHAR ntPath[SLEEPWALKER_PATH_CHARS];
    WCHAR *effective;
    DWORD fullLen;

    if (PathText == NULL || Spec == NULL)
    {
        return FALSE;
    }

    ZeroMemory(inputWide, sizeof(inputWide));
    ZeroMemory(canonical, sizeof(canonical));
    ZeroMemory(ntPath, sizeof(ntPath));

    if (!ConvertArgToWide(PathText, inputWide, RTL_NUMBER_OF(inputWide)))
    {
        return FALSE;
    }

    StripWrappingQuotesInPlace(inputWide, RTL_NUMBER_OF(inputWide));

    effective = inputWide;
    if (_wcsnicmp(effective, L"\\\\?\\", 4) == 0)
    {
        effective += 4;
    }
    else if (_wcsnicmp(effective, L"\\??\\", 4) == 0)
    {
        effective += 4;
    }

    if (IsDrivePathW(effective))
    {
        fullLen = GetFullPathNameW(effective, RTL_NUMBER_OF(canonical), canonical, NULL);
        if (fullLen == 0 || fullLen >= RTL_NUMBER_OF(canonical))
        {
            (void)StringCchCopyW(canonical, RTL_NUMBER_OF(canonical), effective);
        }
        effective = canonical;
    }

    if (effective[0] == L'\0')
    {
        return FALSE;
    }

    Spec->Kind = SleepwalkerTargetPath;
    (void)StringCchCopyW(Spec->PathRaw, RTL_NUMBER_OF(Spec->PathRaw), effective);
    NormalizePathForCompare(effective, Spec->PathNormDos, RTL_NUMBER_OF(Spec->PathNormDos));

    if (IsDrivePathW(effective))
    {
        BuildTailFromDosPath(effective, Spec->PathTail, RTL_NUMBER_OF(Spec->PathTail));
        if (BuildNtPathFromDosPath(effective, ntPath, RTL_NUMBER_OF(ntPath)))
        {
            NormalizePathForCompare(ntPath, Spec->PathNormNt, RTL_NUMBER_OF(Spec->PathNormNt));
        }
    }

    return TRUE;
}

static BOOL ResolveTargetSpec(_In_z_ const char *TargetArg, _Out_ SLEEPWALKER_TARGET_SPEC *Spec)
{
    const char *namePart;
    const char *pathPart;
    DWORD pid;

    if (TargetArg == NULL || Spec == NULL)
    {
        return FALSE;
    }

    ZeroMemory(Spec, sizeof(*Spec));

    if (_strnicmp(TargetArg, "pid:", 4) == 0 || _strnicmp(TargetArg, "pid=", 4) == 0)
    {
        if (!TryParsePid(TargetArg + 4, &pid))
        {
            return FALSE;
        }
        Spec->Kind = SleepwalkerTargetPid;
        Spec->Pid = pid;
        return TRUE;
    }

    if (TryParsePid(TargetArg, &pid))
    {
        Spec->Kind = SleepwalkerTargetPid;
        Spec->Pid = pid;
        return TRUE;
    }

    if (_strnicmp(TargetArg, "path:", 5) == 0 || _strnicmp(TargetArg, "path=", 5) == 0)
    {
        pathPart = TargetArg + 5;
        if (pathPart[0] == '\0')
        {
            return FALSE;
        }
        return ResolvePathSpec(pathPart, Spec);
    }

    if (_strnicmp(TargetArg, "launch:", 7) == 0 || _strnicmp(TargetArg, "launch=", 7) == 0)
    {
        pathPart = TargetArg + 7;
        if (pathPart[0] == '\0')
        {
            return FALSE;
        }
        if (!ResolvePathSpec(pathPart, Spec))
        {
            return FALSE;
        }
        Spec->Kind = SleepwalkerTargetLaunch;
        return TRUE;
    }

    if (_strnicmp(TargetArg, "name:", 5) == 0 || _strnicmp(TargetArg, "name=", 5) == 0)
    {
        namePart = TargetArg + 5;
        if (namePart[0] == '\0')
        {
            return FALSE;
        }
        Spec->Kind = SleepwalkerTargetName;
        return ConvertArgToWide(namePart, Spec->Name, RTL_NUMBER_OF(Spec->Name));
    }

    if (strchr(TargetArg, '\\') != NULL || strchr(TargetArg, '/') != NULL)
    {
        return ResolvePathSpec(TargetArg, Spec);
    }

    Spec->Kind = SleepwalkerTargetName;
    return ConvertArgToWide(TargetArg, Spec->Name, RTL_NUMBER_OF(Spec->Name));
}

static DWORD FindProcessIdByPathSpec(_In_ const SLEEPWALKER_TARGET_SPEC *Spec)
{
    PROCESSENTRY32W pe;
    HANDLE snapshot;

    if (Spec == NULL || Spec->Kind != SleepwalkerTargetPath)
    {
        return 0;
    }

    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
    {
        return 0;
    }

    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snapshot, &pe))
    {
        do
        {
            HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
            if (process != NULL)
            {
                WCHAR path[SLEEPWALKER_PATH_CHARS];
                DWORD pathChars = RTL_NUMBER_OF(path);
                if (QueryFullProcessImageNameW(process, 0, path, &pathChars) && PathMatchesSpec(Spec, path))
                {
                    CloseHandle(process);
                    CloseHandle(snapshot);
                    return pe.th32ProcessID;
                }
                CloseHandle(process);
            }
        } while (Process32NextW(snapshot, &pe));
    }

    CloseHandle(snapshot);
    return 0;
}

static BOOL ScopeMatches(_In_ SLEEPWALKER_TARGET_SCOPE Scope, _In_ BOOL LocalMatch, _In_ BOOL RemoteMatch)
{
    if (Scope == SleepwalkerScopeLocal)
    {
        return LocalMatch;
    }
    if (Scope == SleepwalkerScopeRemote)
    {
        return RemoteMatch;
    }
    return (LocalMatch || RemoteMatch);
}

static BOOL ParseScopeArg(_In_opt_z_ const char *Text, _Out_ SLEEPWALKER_TARGET_SCOPE *Scope)
{
    const char *value = Text;

    if (Scope == NULL)
    {
        return FALSE;
    }

    *Scope = SleepwalkerScopeLocal;
    if (Text == NULL || Text[0] == '\0')
    {
        return TRUE;
    }

    if (_strnicmp(value, "scope:", 6) == 0 || _strnicmp(value, "scope=", 6) == 0)
    {
        value += 6;
    }

    if (_stricmp(value, "local") == 0 || _stricmp(value, "actor") == 0 || _stricmp(value, "self") == 0)
    {
        *Scope = SleepwalkerScopeLocal;
        return TRUE;
    }
    if (_stricmp(value, "remote") == 0 || _stricmp(value, "target") == 0)
    {
        *Scope = SleepwalkerScopeRemote;
        return TRUE;
    }
    if (_stricmp(value, "both") == 0 || _stricmp(value, "all") == 0)
    {
        *Scope = SleepwalkerScopeBoth;
        return TRUE;
    }

    return FALSE;
}

static const char *ScopeToString(_In_ SLEEPWALKER_TARGET_SCOPE Scope)
{
    if (Scope == SleepwalkerScopeRemote)
    {
        return "remote";
    }
    if (Scope == SleepwalkerScopeBoth)
    {
        return "both";
    }
    return "local";
}

static void TrimAsciiInPlace(_Inout_updates_z_(BufferChars) char *Text, _In_ size_t BufferChars)
{
    size_t len;
    size_t start = 0;
    size_t end;
    size_t i;

    if (Text == NULL || BufferChars == 0)
    {
        return;
    }

    len = strlen(Text);
    while (start < len && (Text[start] == ' ' || Text[start] == '\t' || Text[start] == '\r' || Text[start] == '\n'))
    {
        start += 1;
    }

    end = len;
    while (end > start &&
           (Text[end - 1] == ' ' || Text[end - 1] == '\t' || Text[end - 1] == '\r' || Text[end - 1] == '\n'))
    {
        end -= 1;
    }

    if (start > 0)
    {
        for (i = 0; (start + i) < end && i + 1 < BufferChars; ++i)
        {
            Text[i] = Text[start + i];
        }
        Text[i] = '\0';
    }
    else
    {
        Text[end] = '\0';
    }
}

static BOOL ParseBoolText(_In_z_ const char *Text, _Out_ BOOL *Value)
{
    if (Text == NULL || Value == NULL)
    {
        return FALSE;
    }
    if (_stricmp(Text, "1") == 0 || _stricmp(Text, "true") == 0 || _stricmp(Text, "yes") == 0 ||
        _stricmp(Text, "on") == 0)
    {
        *Value = TRUE;
        return TRUE;
    }
    if (_stricmp(Text, "0") == 0 || _stricmp(Text, "false") == 0 || _stricmp(Text, "no") == 0 ||
        _stricmp(Text, "off") == 0)
    {
        *Value = FALSE;
        return TRUE;
    }
    return FALSE;
}

static void PolicyDefaults(_Out_ SLEEPWALKER_CLIENT_POLICY *Policy)
{
    if (Policy == NULL)
    {
        return;
    }
    ZeroMemory(Policy, sizeof(*Policy));
    Policy->LogFormat = SleepwalkerLogFormatText;
    Policy->HighPriorityMinSeverity = 4;
    Policy->AllowIoctlHandle = TRUE;
    Policy->AllowIoctlThread = TRUE;
    Policy->AllowEtwSleepwalker = TRUE;
    Policy->AllowEtwTi = TRUE;
}

static BOOL PolicySetKeyValue(_Inout_ SLEEPWALKER_CLIENT_POLICY *Policy, _In_z_ const char *Key, _In_z_ const char *Value)
{
    BOOL b;
    unsigned long n;
    char *end = NULL;

    if (Policy == NULL || Key == NULL || Value == NULL)
    {
        return FALSE;
    }

    if (_stricmp(Key, "target") == 0)
    {
        (void)StringCchCopyA(Policy->TargetArg, RTL_NUMBER_OF(Policy->TargetArg), Value);
        Policy->HasTarget = (Policy->TargetArg[0] != '\0');
        return TRUE;
    }
    if (_stricmp(Key, "streams") == 0)
    {
        (void)StringCchCopyA(Policy->StreamsArg, RTL_NUMBER_OF(Policy->StreamsArg), Value);
        Policy->HasStreams = (Policy->StreamsArg[0] != '\0');
        return TRUE;
    }
    if (_stricmp(Key, "scope") == 0)
    {
        (void)StringCchCopyA(Policy->ScopeArg, RTL_NUMBER_OF(Policy->ScopeArg), Value);
        Policy->HasScope = (Policy->ScopeArg[0] != '\0');
        return TRUE;
    }
    if (_stricmp(Key, "log.format") == 0)
    {
        if (_stricmp(Value, "jsonl") == 0 || _stricmp(Value, "json") == 0)
        {
            Policy->LogFormat = SleepwalkerLogFormatJsonl;
            return TRUE;
        }
        if (_stricmp(Value, "text") == 0 || _stricmp(Value, "console") == 0)
        {
            Policy->LogFormat = SleepwalkerLogFormatText;
            return TRUE;
        }
        return FALSE;
    }
    if (_stricmp(Key, "log.file") == 0)
    {
        (void)StringCchCopyA(Policy->LogFilePath, RTL_NUMBER_OF(Policy->LogFilePath), Value);
        return TRUE;
    }
    if (_stricmp(Key, "log.high_priority_file") == 0 || _stricmp(Key, "high_priority.file") == 0)
    {
        (void)StringCchCopyA(Policy->HighPriorityFilePath, RTL_NUMBER_OF(Policy->HighPriorityFilePath), Value);
        return TRUE;
    }
    if (_stricmp(Key, "log.high_priority_min_severity") == 0 || _stricmp(Key, "high_priority.min_severity") == 0)
    {
        n = strtoul(Value, &end, 10);
        if (end == Value || *end != '\0')
        {
            return FALSE;
        }
        Policy->HighPriorityMinSeverity = (DWORD)n;
        return TRUE;
    }
    if (_stricmp(Key, "output.ioctl_verbose") == 0)
    {
        if (!ParseBoolText(Value, &b))
        {
            return FALSE;
        }
        Policy->IoctlVerboseOverrideSet = TRUE;
        Policy->IoctlVerboseOverride = b;
        return TRUE;
    }
    if (_stricmp(Key, "filter.ioctl.handle") == 0)
    {
        if (!ParseBoolText(Value, &b))
        {
            return FALSE;
        }
        Policy->AllowIoctlHandle = b;
        return TRUE;
    }
    if (_stricmp(Key, "filter.ioctl.thread") == 0)
    {
        if (!ParseBoolText(Value, &b))
        {
            return FALSE;
        }
        Policy->AllowIoctlThread = b;
        return TRUE;
    }
    if (_stricmp(Key, "filter.etw.sleepwalker") == 0)
    {
        if (!ParseBoolText(Value, &b))
        {
            return FALSE;
        }
        Policy->AllowEtwSleepwalker = b;
        return TRUE;
    }
    if (_stricmp(Key, "filter.etw.ti") == 0)
    {
        if (!ParseBoolText(Value, &b))
        {
            return FALSE;
        }
        Policy->AllowEtwTi = b;
        return TRUE;
    }

    return FALSE;
}

static BOOL LoadPolicyFile(_In_z_ const char *Path, _Inout_ SLEEPWALKER_CLIENT_POLICY *Policy)
{
    FILE *f;
    char line[1024];
    DWORD lineNo = 0;

    if (Path == NULL || Path[0] == '\0' || Policy == NULL)
    {
        return FALSE;
    }

    f = fopen(Path, "rb");
    if (f == NULL)
    {
        return FALSE;
    }

    while (fgets(line, (int)sizeof(line), f) != NULL)
    {
        char key[256];
        char value[768];
        const char *sep = NULL;
        size_t keyLen;

        lineNo += 1;
        TrimAsciiInPlace(line, RTL_NUMBER_OF(line));
        if (line[0] == '\0' || line[0] == '#' || line[0] == ';')
        {
            continue;
        }

        sep = strchr(line, ':');
        if (sep == NULL)
        {
            sep = strchr(line, '=');
        }
        if (sep == NULL)
        {
            continue;
        }

        keyLen = (size_t)(sep - line);
        if (keyLen == 0 || keyLen >= RTL_NUMBER_OF(key))
        {
            continue;
        }

        ZeroMemory(key, sizeof(key));
        ZeroMemory(value, sizeof(value));
        memcpy(key, line, keyLen);
        key[keyLen] = '\0';
        (void)StringCchCopyA(value, RTL_NUMBER_OF(value), sep + 1);
        TrimAsciiInPlace(key, RTL_NUMBER_OF(key));
        TrimAsciiInPlace(value, RTL_NUMBER_OF(value));

        if (value[0] != '\0' && value[0] == '"' && value[strlen(value) - 1] == '"')
        {
            memmove(value, value + 1, strlen(value));
            if (value[0] != '\0')
            {
                value[strlen(value) - 1] = '\0';
            }
        }

        if (!PolicySetKeyValue(Policy, key, value))
        {
            printf("[WARN] config ignored key '%s' at %s:%lu\n", key, Path, (unsigned long)lineNo);
        }
    }

    fclose(f);
    return TRUE;
}

static void JsonEscapeA(_In_z_ const char *Input, _Out_writes_z_(OutputChars) char *Output, _In_ size_t OutputChars)
{
    size_t i;
    size_t w = 0;

    if (Output == NULL || OutputChars == 0)
    {
        return;
    }
    Output[0] = '\0';
    if (Input == NULL)
    {
        return;
    }

    for (i = 0; Input[i] != '\0' && w + 2 < OutputChars; ++i)
    {
        char ch = Input[i];
        if (ch == '\\' || ch == '"')
        {
            Output[w++] = '\\';
            Output[w++] = ch;
        }
        else if (ch == '\r')
        {
            Output[w++] = '\\';
            Output[w++] = 'r';
        }
        else if (ch == '\n')
        {
            Output[w++] = '\\';
            Output[w++] = 'n';
        }
        else if (ch == '\t')
        {
            Output[w++] = '\\';
            Output[w++] = 't';
        }
        else if ((unsigned char)ch < 0x20)
        {
            continue;
        }
        else
        {
            Output[w++] = ch;
        }
    }
    Output[w] = '\0';
}

static void WideToUtf8(_In_opt_z_ const WCHAR *Wide, _Out_writes_z_(OutputChars) char *Output, _In_ size_t OutputChars)
{
    int converted;
    if (Output == NULL || OutputChars == 0)
    {
        return;
    }
    Output[0] = '\0';
    if (Wide == NULL || Wide[0] == L'\0')
    {
        return;
    }
    converted = WideCharToMultiByte(CP_UTF8, 0, Wide, -1, Output, (int)OutputChars, NULL, NULL);
    if (converted <= 0)
    {
        Output[0] = '\0';
    }
}

static void GetTimestampUtcIso(_Out_writes_z_(OutputChars) char *Output, _In_ size_t OutputChars)
{
    SYSTEMTIME st;
    if (Output == NULL || OutputChars == 0)
    {
        return;
    }
    GetSystemTime(&st);
    (void)StringCchPrintfA(Output, OutputChars, "%04u-%02u-%02uT%02u:%02u:%02u.%03uZ", st.wYear, st.wMonth, st.wDay,
                           st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
}

static void LoggerWriteLine(_In_opt_ FILE *F, _In_z_ const char *Line)
{
    if (F == NULL || Line == NULL)
    {
        return;
    }
    (void)fputs(Line, F);
    (void)fputc('\n', F);
    (void)fflush(F);
}

static void LoggerEmitJson(_In_ DWORD Severity, _In_z_ const char *Category, _In_z_ const char *Kind, _In_ DWORD Pid,
                           _In_ DWORD TargetPid, _In_z_ const char *Message)
{
    char ts[64];
    char catEsc[128];
    char kindEsc[128];
    char msgEsc[2048];
    char line[2600];

    if (g_Logger.Policy.LogFormat != SleepwalkerLogFormatJsonl || g_Logger.LogFile == NULL)
    {
        return;
    }

    GetTimestampUtcIso(ts, RTL_NUMBER_OF(ts));
    JsonEscapeA(Category, catEsc, RTL_NUMBER_OF(catEsc));
    JsonEscapeA(Kind, kindEsc, RTL_NUMBER_OF(kindEsc));
    JsonEscapeA(Message, msgEsc, RTL_NUMBER_OF(msgEsc));

    (void)StringCchPrintfA(line, RTL_NUMBER_OF(line),
                           "{\"ts\":\"%s\",\"source\":\"sleepwalker-client\",\"category\":\"%s\",\"kind\":\"%s\","
                           "\"severity\":%lu,\"pid\":%lu,\"targetPid\":%lu,\"message\":\"%s\"}",
                           ts, catEsc, kindEsc, (unsigned long)Severity, (unsigned long)Pid, (unsigned long)TargetPid,
                           msgEsc);
    LoggerWriteLine(g_Logger.LogFile, line);

    if (g_Logger.HighPriorityFile != NULL && Severity >= g_Logger.Policy.HighPriorityMinSeverity)
    {
        LoggerWriteLine(g_Logger.HighPriorityFile, line);
    }
}

static BOOL LoggerInitialize(_In_ const SLEEPWALKER_CLIENT_POLICY *Policy, _In_ DWORD TargetPid)
{
    if (Policy == NULL)
    {
        return FALSE;
    }

    ZeroMemory(&g_Logger, sizeof(g_Logger));
    g_Logger.Policy = *Policy;
    g_Logger.TargetPid = TargetPid;

    if (g_Logger.Policy.LogFormat != SleepwalkerLogFormatJsonl)
    {
        return TRUE;
    }

    if (g_Logger.Policy.LogFilePath[0] == '\0')
    {
        (void)StringCchCopyA(g_Logger.Policy.LogFilePath, RTL_NUMBER_OF(g_Logger.Policy.LogFilePath), "events.swk.jsonl");
    }
    if (g_Logger.Policy.HighPriorityFilePath[0] == '\0')
    {
        (void)StringCchCopyA(g_Logger.Policy.HighPriorityFilePath, RTL_NUMBER_OF(g_Logger.Policy.HighPriorityFilePath),
                             "high_priority.swk.jsonl");
    }

    g_Logger.LogFile = fopen(g_Logger.Policy.LogFilePath, "ab");
    if (g_Logger.LogFile == NULL)
    {
        printf("[WARN] failed to open log file '%s'\n", g_Logger.Policy.LogFilePath);
        return FALSE;
    }

    g_Logger.HighPriorityFile = fopen(g_Logger.Policy.HighPriorityFilePath, "ab");
    if (g_Logger.HighPriorityFile == NULL)
    {
        printf("[WARN] failed to open high-priority log file '%s'\n", g_Logger.Policy.HighPriorityFilePath);
    }

    printf("[*] JSONL logging enabled file=%s highPriority=%s minSeverity=%lu\n", g_Logger.Policy.LogFilePath,
           (g_Logger.HighPriorityFile != NULL) ? g_Logger.Policy.HighPriorityFilePath : "<disabled>",
           (unsigned long)g_Logger.Policy.HighPriorityMinSeverity);
    return TRUE;
}

static void LoggerShutdown(void)
{
    if (g_Logger.LogFile != NULL)
    {
        fclose(g_Logger.LogFile);
        g_Logger.LogFile = NULL;
    }
    if (g_Logger.HighPriorityFile != NULL)
    {
        fclose(g_Logger.HighPriorityFile);
        g_Logger.HighPriorityFile = NULL;
    }
}

static BOOL GetEtwWideProperty(_In_ PEVENT_RECORD Record, _In_z_ PCWSTR Name, _Out_writes_z_(OutputChars) PWSTR Output,
                               _In_ size_t OutputChars)
{
    PROPERTY_DATA_DESCRIPTOR descriptor;
    ULONG propertySize = 0;
    TDHSTATUS status;
    BYTE *raw = NULL;
    BOOL ok = FALSE;

    if (Record == NULL || Name == NULL || Output == NULL || OutputChars == 0)
    {
        return FALSE;
    }

    Output[0] = L'\0';
    ZeroMemory(&descriptor, sizeof(descriptor));
    descriptor.PropertyName = (ULONGLONG)(ULONG_PTR)Name;
    descriptor.ArrayIndex = ULONG_MAX;

    status = TdhGetPropertySize(Record, 0, NULL, 1, &descriptor, &propertySize);
    if (status != ERROR_SUCCESS || propertySize < sizeof(WCHAR))
    {
        return FALSE;
    }

    raw = (BYTE *)malloc(propertySize + sizeof(WCHAR));
    if (raw == NULL)
    {
        return FALSE;
    }
    ZeroMemory(raw, propertySize + sizeof(WCHAR));

    status = TdhGetProperty(Record, 0, NULL, 1, &descriptor, propertySize, raw);
    if (status == ERROR_SUCCESS)
    {
        (void)StringCchCopyW(Output, OutputChars, (PCWSTR)raw);
        ok = TRUE;
    }

    free(raw);
    return ok;
}

static BOOL GetEtwAnsiProperty(_In_ PEVENT_RECORD Record, _In_z_ PCWSTR Name, _Out_writes_z_(OutputChars) PSTR Output,
                               _In_ size_t OutputChars)
{
    PROPERTY_DATA_DESCRIPTOR descriptor;
    ULONG propertySize = 0;
    TDHSTATUS status;
    BYTE *raw = NULL;
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

    raw = (BYTE *)malloc(propertySize + 1);
    if (raw == NULL)
    {
        return FALSE;
    }
    ZeroMemory(raw, propertySize + 1);

    status = TdhGetProperty(Record, 0, NULL, 1, &descriptor, propertySize, raw);
    if (status == ERROR_SUCCESS)
    {
        (void)StringCchCopyA(Output, OutputChars, (PCSTR)raw);
        ok = TRUE;
    }

    free(raw);
    return ok;
}

static BOOL GetEtwU64Property(_In_ PEVENT_RECORD Record, _In_z_ PCWSTR Name, _Out_ ULONGLONG *Value)
{
    PROPERTY_DATA_DESCRIPTOR descriptor;
    ULONG propertySize = 0;
    TDHSTATUS status;
    BYTE raw[16];

    if (Record == NULL || Name == NULL || Value == NULL)
    {
        return FALSE;
    }

    *Value = 0;
    ZeroMemory(&descriptor, sizeof(descriptor));
    descriptor.PropertyName = (ULONGLONG)(ULONG_PTR)Name;
    descriptor.ArrayIndex = ULONG_MAX;

    status = TdhGetPropertySize(Record, 0, NULL, 1, &descriptor, &propertySize);
    if (status != ERROR_SUCCESS || propertySize == 0 || propertySize > sizeof(raw))
    {
        return FALSE;
    }

    ZeroMemory(raw, sizeof(raw));
    status = TdhGetProperty(Record, 0, NULL, 1, &descriptor, propertySize, raw);
    if (status != ERROR_SUCCESS)
    {
        return FALSE;
    }

    if (propertySize >= sizeof(ULONGLONG))
    {
        *Value = *(const ULONGLONG *)raw;
    }
    else if (propertySize >= sizeof(ULONG))
    {
        *Value = *(const ULONG *)raw;
    }
    else if (propertySize >= sizeof(USHORT))
    {
        *Value = *(const USHORT *)raw;
    }
    else
    {
        *Value = *raw;
    }

    return TRUE;
}

static BOOL AttachProgramTargetPid(_Inout_ SLEEPWALKER_ATTACH_CONTEXT *Attach)
{
    DWORD pids[1];

    if (Attach == NULL || Attach->Device == INVALID_HANDLE_VALUE || Attach->TargetPid == 0)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    pids[0] = Attach->TargetPid;
    return SLEEPWALKERSCSetPids(Attach->Device, pids, RTL_NUMBER_OF(pids), Attach->StreamMask);
}

static BOOL EtwPropertyMatchesTargetPid(_In_ PEVENT_RECORD Record, _In_z_ PCWSTR PropertyName, _In_ DWORD TargetPid)
{
    ULONGLONG value = 0;

    if (Record == NULL || PropertyName == NULL || TargetPid == 0)
    {
        return FALSE;
    }

    if (!GetEtwU64Property(Record, PropertyName, &value))
    {
        return FALSE;
    }

    if (value == 0 || value > 0xFFFFFFFFull)
    {
        return FALSE;
    }

    return ((DWORD)value == TargetPid);
}

static BOOL EtwAnyPropertyMatchesTargetPid(_In_ PEVENT_RECORD Record, _In_reads_(NameCount) const PCWSTR *Names,
                                           _In_ size_t NameCount, _In_ DWORD TargetPid)
{
    size_t i;

    if (Record == NULL || Names == NULL || NameCount == 0 || TargetPid == 0)
    {
        return FALSE;
    }

    for (i = 0; i < NameCount; ++i)
    {
        if (EtwPropertyMatchesTargetPid(Record, Names[i], TargetPid))
        {
            return TRUE;
        }
    }

    return FALSE;
}

static BOOL EtwRecordMatchesTargetPid(_In_ PEVENT_RECORD Record, _In_opt_z_ PCWSTR EventName, _In_ DWORD TargetPid,
                                      _In_ SLEEPWALKER_TARGET_SCOPE Scope)
{
    static const PCWSTR tiActorNames[] = {L"CallingProcessId", L"CallerProcessId", L"SourceProcessId", L"ProcessId"};
    static const PCWSTR tiTargetNames[] = {L"TargetProcessId", L"NewProcessId", L"DestProcessId"};
    BOOL localMatch = FALSE;
    BOOL remoteMatch = FALSE;

    if (Record == NULL || TargetPid == 0)
    {
        return FALSE;
    }

    if (IsEqualGUID(&Record->EventHeader.ProviderId, &SLEEPWALKERSC_PROVIDER_GUID_SLEEPWALKER))
    {
        if (EventName == NULL)
        {
            return FALSE;
        }

        if (wcscmp(EventName, L"HandleTelemetry") == 0)
        {
            localMatch = EtwPropertyMatchesTargetPid(Record, L"callerPid", TargetPid);
            remoteMatch = EtwPropertyMatchesTargetPid(Record, L"targetPid", TargetPid);
            return ScopeMatches(Scope, localMatch, remoteMatch);
        }

        if (wcscmp(EventName, L"ThreadTelemetry") == 0)
        {
            localMatch = EtwPropertyMatchesTargetPid(Record, L"creatorPid", TargetPid);
            remoteMatch = EtwPropertyMatchesTargetPid(Record, L"processId", TargetPid);
            return ScopeMatches(Scope, localMatch, remoteMatch);
        }

        if (wcscmp(EventName, L"ProcessTelemetry") == 0)
        {
            localMatch = EtwPropertyMatchesTargetPid(Record, L"processId", TargetPid);
            return ScopeMatches(Scope, localMatch, FALSE);
        }

        if (wcscmp(EventName, L"ImageTelemetry") == 0 || wcscmp(EventName, L"RegistryTelemetry") == 0)
        {
            localMatch = EtwPropertyMatchesTargetPid(Record, L"processId", TargetPid);
            return ScopeMatches(Scope, localMatch, FALSE);
        }

        if (wcscmp(EventName, L"DetectionTelemetry") == 0 || wcscmp(EventName, L"ApcTelemetry") == 0)
        {
            localMatch = EtwPropertyMatchesTargetPid(Record, L"processId", TargetPid) ||
                         EtwPropertyMatchesTargetPid(Record, L"callerPid", TargetPid);
            remoteMatch = EtwPropertyMatchesTargetPid(Record, L"targetPid", TargetPid);
            return ScopeMatches(Scope, localMatch, remoteMatch);
        }

        localMatch = EtwPropertyMatchesTargetPid(Record, L"processId", TargetPid) ||
                     EtwPropertyMatchesTargetPid(Record, L"callerPid", TargetPid);
        remoteMatch = EtwPropertyMatchesTargetPid(Record, L"targetPid", TargetPid);
        return ScopeMatches(Scope, localMatch, remoteMatch);
    }

    if (IsEqualGUID(&Record->EventHeader.ProviderId, &SLEEPWALKERSC_PROVIDER_GUID_TI))
    {
        localMatch = EtwAnyPropertyMatchesTargetPid(Record, tiActorNames, RTL_NUMBER_OF(tiActorNames), TargetPid);
        remoteMatch = EtwAnyPropertyMatchesTargetPid(Record, tiTargetNames, RTL_NUMBER_OF(tiTargetNames), TargetPid);
        return ScopeMatches(Scope, localMatch, remoteMatch);
    }

    return FALSE;
}

static VOID WINAPI LiveEtwCallback(_In_ PEVENT_RECORD Record, _In_opt_z_ PCWSTR EventName, _In_opt_ PVOID Context)
{
    SLEEPWALKER_LIVE_ETW_CONTEXT *live = (SLEEPWALKER_LIVE_ETW_CONTEXT *)Context;

    if (Record == NULL || live == NULL || live->Attach == NULL)
    {
        return;
    }

    SLEEPWALKERPrimeProcessImageFromEtw(Record, EventName);

    if (!EtwRecordMatchesTargetPid(Record, EventName, live->Attach->TargetPid, live->Attach->Scope))
    {
        return;
    }

    LoggerEmitEtwRecord(Record, EventName);

    if (IsEqualGUID(&Record->EventHeader.ProviderId, &SLEEPWALKERSC_PROVIDER_GUID_SLEEPWALKER))
    {
        if (EventName != NULL && EventName[0] != L'\0')
        {
            SLEEPWALKERPrintEtwRecord(Record, EventName);
        }
    }
    else if (IsEqualGUID(&Record->EventHeader.ProviderId, &SLEEPWALKERSC_PROVIDER_GUID_TI))
    {
        SLEEPWALKERPrintThreatIntelRecord(Record, EventName);
    }
}

static VOID WINAPI PathWatchEtwCallback(_In_ PEVENT_RECORD Record, _In_opt_z_ PCWSTR EventName, _In_opt_ PVOID Context)
{
    SLEEPWALKER_PATH_WATCH_CONTEXT *watch = (SLEEPWALKER_PATH_WATCH_CONTEXT *)Context;
    WCHAR imagePath[SLEEPWALKER_PATH_CHARS];
    ULONGLONG pidValue = 0;
    SLEEPWALKER_TARGET_SPEC spec;

    if (watch == NULL || EventName == NULL || Record == NULL)
    {
        return;
    }

    if (InterlockedCompareExchange(&watch->Matched, 0, 0) != 0)
    {
        return;
    }

    if (wcscmp(EventName, L"ProcessTelemetry") != 0 && wcscmp(EventName, L"ImageTelemetry") != 0)
    {
        return;
    }

    if (!GetEtwWideProperty(Record, L"imagePath", imagePath, RTL_NUMBER_OF(imagePath)))
    {
        return;
    }

    if (!GetEtwU64Property(Record, L"processId", &pidValue) || pidValue == 0 || pidValue > 0xFFFFFFFFull)
    {
        return;
    }

    ZeroMemory(&spec, sizeof(spec));
    spec.Kind = SleepwalkerTargetPath;
    (void)StringCchCopyW(spec.PathNormDos, RTL_NUMBER_OF(spec.PathNormDos), watch->TargetNormDos);
    (void)StringCchCopyW(spec.PathNormNt, RTL_NUMBER_OF(spec.PathNormNt), watch->TargetNormNt);
    (void)StringCchCopyW(spec.PathTail, RTL_NUMBER_OF(spec.PathTail), watch->TargetTail);
    if (!PathMatchesSpec(&spec, imagePath))
    {
        return;
    }

    watch->MatchedPid = (DWORD)pidValue;
    InterlockedExchange(&watch->Matched, 1);
}

static DWORD WINAPI EtwRunThreadProc(_In_ LPVOID Context)
{
    SLEEPWALKER_ETW_RUN_CONTEXT *run = (SLEEPWALKER_ETW_RUN_CONTEXT *)Context;

    if (run == NULL || run->Session == NULL)
    {
        return 1;
    }

    (void)SLEEPWALKERSCRunEtwSession(run->Session);
    if (run->Watch != NULL)
    {
        InterlockedExchange(&run->Watch->SessionEnded, 1);
    }
    return 0;
}

static BOOL WaitForPathLaunchViaEtw(_In_ const SLEEPWALKER_TARGET_SPEC *Spec, _Out_ DWORD *Pid)
{
    SLEEPWALKER_PATH_WATCH_CONTEXT watch;
    SLEEPWALKER_ETW_RUN_CONTEXT run;
    SLEEPWALKERSC_ETW_SESSION *session = NULL;
    HANDLE etwThread = NULL;
    WCHAR sessionName[64];

    if (Spec == NULL || Spec->Kind != SleepwalkerTargetPath || Pid == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    *Pid = 0;
    ZeroMemory(&watch, sizeof(watch));
    ZeroMemory(&run, sizeof(run));
    (void)StringCchCopyW(watch.TargetNormDos, RTL_NUMBER_OF(watch.TargetNormDos), Spec->PathNormDos);
    (void)StringCchCopyW(watch.TargetNormNt, RTL_NUMBER_OF(watch.TargetNormNt), Spec->PathNormNt);
    (void)StringCchCopyW(watch.TargetTail, RTL_NUMBER_OF(watch.TargetTail), Spec->PathTail);

    (void)StringCchPrintfW(sessionName, RTL_NUMBER_OF(sessionName), L"SleepwalkerClientWatch-%lu-%lu",
                           GetCurrentProcessId(), GetTickCount());

    if (!SLEEPWALKERSCStartSleepwalkerEtwSession(sessionName, FALSE, PathWatchEtwCallback, &watch, &session, NULL))
    {
        return FALSE;
    }

    run.Session = session;
    run.Watch = &watch;
    etwThread = CreateThread(NULL, 0, EtwRunThreadProc, &run, 0, NULL);
    if (etwThread == NULL)
    {
        SLEEPWALKERSCStopEtwSession(session);
        return FALSE;
    }

    for (;;)
    {
        if (InterlockedCompareExchange(&watch.Matched, 0, 0) != 0)
        {
            *Pid = watch.MatchedPid;
            break;
        }
        if (InterlockedCompareExchange(&watch.SessionEnded, 0, 0) != 0)
        {
            break;
        }
        if (InterlockedCompareExchange(&g_StopRequested, 0, 0) != 0)
        {
            SetLastError(ERROR_CANCELLED);
            break;
        }
        Sleep(80);
    }

    SLEEPWALKERSCStopEtwSession(session);
    (void)WaitForSingleObject(etwThread, 3000);
    CloseHandle(etwThread);

    return (*Pid != 0);
}

static DWORD WINAPI LiveEtwRunThreadProc(_In_ LPVOID Context)
{
    SLEEPWALKER_LIVE_ETW_CONTEXT *live = (SLEEPWALKER_LIVE_ETW_CONTEXT *)Context;

    if (live == NULL || live->Session == NULL)
    {
        return 1;
    }

    (void)SLEEPWALKERSCRunEtwSession(live->Session);
    InterlockedExchange(&live->SessionEnded, 1);
    return 0;
}

static BOOL StartLiveEtw(_Inout_ SLEEPWALKER_LIVE_ETW_CONTEXT *Live, _Out_ HANDLE *ThreadHandle)
{
    WCHAR sessionName[64];
    BOOL tiEnabled = FALSE;

    if (Live == NULL || ThreadHandle == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    *ThreadHandle = NULL;
    Live->Session = NULL;
    Live->SessionEnded = 0;

    (void)StringCchPrintfW(sessionName, RTL_NUMBER_OF(sessionName), L"SleepwalkerClientLive-%lu-%lu",
                           GetCurrentProcessId(), GetTickCount());

    if (!SLEEPWALKERSCStartSleepwalkerEtwSession(sessionName, TRUE, LiveEtwCallback, Live, &Live->Session, &tiEnabled))
    {
        return FALSE;
    }

    if (!tiEnabled)
    {
        printf("[*] ETW TI provider unavailable; continuing with Sleepwalker provider only.\n");
    }

    *ThreadHandle = CreateThread(NULL, 0, LiveEtwRunThreadProc, Live, 0, NULL);
    if (*ThreadHandle == NULL)
    {
        SLEEPWALKERSCStopEtwSession(Live->Session);
        Live->Session = NULL;
        return FALSE;
    }

    g_StopSession = Live->Session;
    return TRUE;
}

static BOOL LaunchTargetSuspended(_In_ const SLEEPWALKER_TARGET_SPEC *Spec, _Out_ SLEEPWALKER_LAUNCH_TARGET *Launch,
                                  _Out_ DWORD *Pid)
{
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;

    if (Spec == NULL || Launch == NULL || Pid == NULL || Spec->Kind != SleepwalkerTargetLaunch)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    *Pid = 0;
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(si);

    if (!CreateProcessW(Spec->PathRaw, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi))
    {
        return FALSE;
    }

    Launch->Active = TRUE;
    Launch->Resumed = FALSE;
    Launch->ProcessInfo = pi;
    *Pid = pi.dwProcessId;
    return TRUE;
}

static BOOL ResolveTargetPid(_In_ const SLEEPWALKER_TARGET_SPEC *Spec, _Out_ DWORD *Pid,
                             _Out_opt_ SLEEPWALKER_LAUNCH_TARGET *Launch)
{
    DWORD foundPid;

    if (Spec == NULL || Pid == NULL)
    {
        return FALSE;
    }

    *Pid = 0;
    if (Launch != NULL)
    {
        ZeroMemory(Launch, sizeof(*Launch));
    }

    switch (Spec->Kind)
    {
    case SleepwalkerTargetPid:
        *Pid = Spec->Pid;
        return TRUE;

    case SleepwalkerTargetName:
        foundPid = FindProcessIdByNameW(Spec->Name);
        if (foundPid == 0)
        {
            SetLastError(ERROR_NOT_FOUND);
            return FALSE;
        }
        *Pid = foundPid;
        return TRUE;

    case SleepwalkerTargetPath:
        foundPid = FindProcessIdByPathSpec(Spec);
        if (foundPid != 0)
        {
            *Pid = foundPid;
            return TRUE;
        }

        wprintf(L"[*] Waiting for path match via ProcessTelemetry/ImageTelemetry: %ls\n", Spec->PathRaw);
        if (!WaitForPathLaunchViaEtw(Spec, &foundPid))
        {
            return FALSE;
        }
        *Pid = foundPid;
        return TRUE;

    case SleepwalkerTargetLaunch:
        if (Launch == NULL)
        {
            SetLastError(ERROR_INVALID_PARAMETER);
            return FALSE;
        }
        return LaunchTargetSuspended(Spec, Launch, Pid);
    }

    SetLastError(ERROR_INVALID_PARAMETER);
    return FALSE;
}

static VOID PrimeTargetImageHint(_In_ HANDLE Device, _In_ const SLEEPWALKER_TARGET_SPEC *Spec, _In_ DWORD TargetPid)
{
    WCHAR imagePath[SLEEPWALKER_PATH_CHARS];
    HANDLE process;
    DWORD pathChars;

    if (Spec == NULL || TargetPid == 0)
    {
        return;
    }

    imagePath[0] = L'\0';
    if ((Spec->Kind == SleepwalkerTargetLaunch || Spec->Kind == SleepwalkerTargetPath) && Spec->PathRaw[0] != L'\0')
    {
        (void)StringCchCopyW(imagePath, RTL_NUMBER_OF(imagePath), Spec->PathRaw);
    }
    else
    {
        process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, TargetPid);
        if (process != NULL)
        {
            pathChars = RTL_NUMBER_OF(imagePath);
            if (!QueryFullProcessImageNameW(process, 0, imagePath, &pathChars))
            {
                imagePath[0] = L'\0';
            }
            CloseHandle(process);
        }
    }

    if (imagePath[0] == L'\0' && Device != INVALID_HANDLE_VALUE)
    {
        (void)SLEEPWALKERSCQueryProcessImagePath(Device, TargetPid, imagePath, (DWORD)RTL_NUMBER_OF(imagePath));
    }

    SLEEPWALKERPrimeProcessImagePath((ULONGLONG)TargetPid, imagePath);
}

static void PrintUsage(void)
{
    printf("Usage: sleepwalker_client.exe shutdown\n");
    printf("Usage: sleepwalker_client.exe [--config <file>] [--log-format text|jsonl] [--log-file <path>]\n");
    printf("                             [--high-priority-file <path>] [--high-priority-min-severity <0-10>]\n");
    printf("                             [--ioctl-verbose 0|1] <target> <streams> [scope]\n");
    printf("target: PID | pid:<PID> | pid=<PID> | name:process.exe | name=process.exe | process.exe | path:<full-path> "
           "| path=<full-path> | launch:<full-path>\n");
    printf("streams: handle,memory,thread\n");
    printf("scope: local (default) | remote | both\n");
    printf("config file supports key:value or key=value (YAML-like flat keys)\n");
    printf("keys: target, streams, scope, log.format, log.file, log.high_priority_file,\n");
    printf("      log.high_priority_min_severity, output.ioctl_verbose,\n");
    printf("      filter.ioctl.handle, filter.ioctl.thread, filter.etw.sleepwalker, filter.etw.ti\n");
    printf("example: sleepwalker_client.exe shutdown\n");
    printf("example: sleepwalker_client.exe notepad.exe handle,thread\n");
    printf("example: sleepwalker_client.exe --log-format jsonl --log-file events.swk.jsonl notepad.exe handle,memory,thread\n");
    printf("example: sleepwalker_client.exe path:C:\\Windows\\System32\\notepad.exe handle,memory,thread\n");
    printf("example: sleepwalker_client.exe launch:C:\\Windows\\System32\\notepad.exe handle,memory,thread\n");
    printf("example: sleepwalker_client.exe 4242 handle,memory,thread both\n");
}

static const char *HandleClassToString(DWORD classId)
{
    switch (classId)
    {
    case SleepwalkerHandleClassLegitimateSyscall:
        return "LEGITIMATE-SYSCALL";
    case SleepwalkerHandleClassDirectSyscallSuspect:
        return "DIRECT-SYSCALL-SUSPECT";
    default:
        return "UNKNOWN-ORIGIN";
    }
}

static BOOL WideContainsInsensitive(_In_opt_z_ const WCHAR *Haystack, _In_z_ const WCHAR *Needle)
{
    WCHAR hay[1024];
    WCHAR need[64];
    size_t i;

    if (Haystack == NULL || Needle == NULL)
    {
        return FALSE;
    }

    (void)StringCchCopyW(hay, RTL_NUMBER_OF(hay), Haystack);
    (void)StringCchCopyW(need, RTL_NUMBER_OF(need), Needle);

    for (i = 0; i < RTL_NUMBER_OF(hay); ++i)
    {
        hay[i] = (WCHAR)towlower(hay[i]);
        if (hay[i] == L'\0')
        {
            break;
        }
    }
    for (i = 0; i < RTL_NUMBER_OF(need); ++i)
    {
        need[i] = (WCHAR)towlower(need[i]);
        if (need[i] == L'\0')
        {
            break;
        }
    }

    return (wcsstr(hay, need) != NULL);
}

static const char *ComputeUserModeHandleClass(_In_ const SLEEPWALKER_HANDLE_EVENT *h,
                                              _In_z_ const WCHAR *OriginResolved)
{
    BOOL fromNtdll;
    BOOL execProtect;
    BOOL fromExe;

    if (h == NULL)
    {
        return "UNKNOWN-ORIGIN";
    }

    fromNtdll = ((h->Flags & SLEEPWALKER_HANDLE_FLAG_FROM_NTDLL) != 0) ||
                WideContainsInsensitive(OriginResolved, L"ntdll!") ||
                WideContainsInsensitive(OriginResolved, L"ntdll+");
    execProtect = ((h->Flags & SLEEPWALKER_HANDLE_FLAG_EXEC_PROTECT) != 0);
    fromExe = ((h->Flags & SLEEPWALKER_HANDLE_FLAG_FROM_EXE) != 0);

    if (execProtect && fromNtdll)
    {
        return "LEGITIMATE-SYSCALL";
    }
    if (execProtect && !fromNtdll && (fromExe || h->OriginPath[0] == L'\0'))
    {
        return "DIRECT-SYSCALL-SUSPECT";
    }
    return "UNKNOWN-ORIGIN";
}

static double ComputeShannonEntropy(_In_reads_bytes_(Size) const BYTE *Data, _In_ DWORD Size)
{
    DWORD i;
    UINT32 counts[256];
    double entropy = 0.0;

    if (Data == NULL || Size == 0)
    {
        return 0.0;
    }

    ZeroMemory(counts, sizeof(counts));
    for (i = 0; i < Size; ++i)
    {
        counts[Data[i]] += 1;
    }

    for (i = 0; i < RTL_NUMBER_OF(counts); ++i)
    {
        if (counts[i] != 0)
        {
            double p = ((double)counts[i]) / ((double)Size);
            entropy -= p * (log(p) / log(2.0));
        }
    }
    return entropy;
}

static void FormatOpcodePreviewA(_In_reads_bytes_(Size) const BYTE *Data, _In_ DWORD Size,
                                 _Out_writes_z_(OutputChars) char *Output, _In_ size_t OutputChars)
{
    DWORD i;
    DWORD limit;

    if (Output == NULL || OutputChars == 0)
    {
        return;
    }
    Output[0] = '\0';

    if (Data == NULL || Size == 0)
    {
        (void)StringCchCopyA(Output, OutputChars, "<none>");
        return;
    }

    limit = (Size > 16) ? 16 : Size;
    for (i = 0; i < limit; ++i)
    {
        char chunk[8];
        (void)StringCchPrintfA(chunk, RTL_NUMBER_OF(chunk), (i == 0) ? "%02X" : " %02X", Data[i]);
        (void)StringCchCatA(Output, OutputChars, chunk);
    }
    if (Size > limit)
    {
        (void)StringCchCatA(Output, OutputChars, " ...");
    }
}

static void PrintHandleFlags(_In_ DWORD flags)
{
    printf("flags=");
    if (flags == 0)
    {
        printf("<none>");
    }
    else
    {
        if ((flags & SLEEPWALKER_HANDLE_FLAG_EXEC_PROTECT) != 0)
        {
            printf("ExecProtect ");
        }
        if ((flags & SLEEPWALKER_HANDLE_FLAG_FROM_NTDLL) != 0)
        {
            printf("FromNtdll ");
        }
        if ((flags & SLEEPWALKER_HANDLE_FLAG_FROM_EXE) != 0)
        {
            printf("FromExe ");
        }
        if ((flags & SLEEPWALKER_HANDLE_FLAG_MEMORY_RELATED) != 0)
        {
            printf("MemoryRelated ");
        }
        if ((flags & SLEEPWALKER_HANDLE_FLAG_THREAD_OBJECT) != 0)
        {
            printf("ThreadObject ");
        }
        if ((flags & SLEEPWALKER_HANDLE_FLAG_DUPLICATE_OPERATION) != 0)
        {
            printf("DuplicateOp ");
        }
        if ((flags & SLEEPWALKER_HANDLE_FLAG_DEEP_PATH_CANDIDATE) != 0)
        {
            printf("DeepCandidate ");
        }
        if ((flags & SLEEPWALKER_HANDLE_FLAG_DEEP_PATH_CAPTURED) != 0)
        {
            printf("DeepCaptured ");
        }
        if ((flags & SLEEPWALKER_HANDLE_FLAG_DEEP_PATH_CACHE_HIT) != 0)
        {
            printf("DeepCacheHit ");
        }
    }
    printf("\n");
}

static void PrintThreadFlags(_In_ DWORD flags)
{
    printf("flags=");
    if (flags == 0)
    {
        printf("<none>");
    }
    else
    {
        if ((flags & SLEEPWALKER_THREAD_FLAG_GOT_START) != 0)
        {
            printf("GotStart ");
        }
        if ((flags & SLEEPWALKER_THREAD_FLAG_GOT_RANGE) != 0)
        {
            printf("GotRange ");
        }
        if ((flags & SLEEPWALKER_THREAD_FLAG_REMOTE_CREATOR) != 0)
        {
            printf("RemoteCreator ");
        }
        if ((flags & SLEEPWALKER_THREAD_FLAG_OUTSIDE_MAIN_IMG) != 0)
        {
            printf("OutsideMainImage ");
        }
        if ((flags & SLEEPWALKER_THREAD_FLAG_CORRELATED_INTENT) != 0)
        {
            printf("CorrelatedIntent ");
        }
        if ((flags & SLEEPWALKER_THREAD_FLAG_CORR_MEMORY) != 0)
        {
            printf("IntentProcessMemory ");
        }
        if ((flags & SLEEPWALKER_THREAD_FLAG_CORR_THREAD_CTX) != 0)
        {
            printf("IntentThreadContext ");
        }
        if ((flags & SLEEPWALKER_THREAD_FLAG_CORR_DUP_HANDLE) != 0)
        {
            printf("IntentDupHandle ");
        }
        if ((flags & SLEEPWALKER_THREAD_FLAG_START_REGION_EXEC) != 0)
        {
            printf("StartRegionExec ");
        }
    }
    printf("\n");
}

static void PrintResolvedFrames(_In_ DWORD ProcessId, _In_reads_(FrameCount) const UINT64 *Frames,
                                _In_ DWORD FrameCount)
{
    DWORD i;
    DWORD limit = (FrameCount > SLEEPWALKER_MAX_EVENT_FRAMES) ? SLEEPWALKER_MAX_EVENT_FRAMES : FrameCount;

    printf("stackFrames=%lu\n", limit);
    for (i = 0; i < limit; ++i)
    {
        WCHAR resolved[768];
        SLEEPWALKEREtwSymbolsFormatAddressForProcess(ProcessId, Frames[i], resolved, RTL_NUMBER_OF(resolved));
        wprintf(L"  #%lu 0x%016llX (%ls)\n", i, (unsigned long long)Frames[i], resolved);
    }
}

static BOOL IoctlRecordMatchesTargetPid(_In_ const SLEEPWALKER_EVENT_RECORD *Record, _In_ DWORD TargetPid,
                                        _In_ SLEEPWALKER_TARGET_SCOPE Scope)
{
    BOOL localMatch = FALSE;
    BOOL remoteMatch = FALSE;

    if (Record == NULL || TargetPid == 0)
    {
        return FALSE;
    }

    if (Record->Header.Type == SleepwalkerEventTypeHandle)
    {
        DWORD caller = (DWORD)Record->Data.Handle.CallerPid;
        DWORD target = (DWORD)Record->Data.Handle.TargetPid;
        localMatch = (caller == TargetPid);
        remoteMatch = (target == TargetPid);
        return ScopeMatches(Scope, localMatch, remoteMatch);
    }

    if (Record->Header.Type == SleepwalkerEventTypeThread)
    {
        DWORD process = (DWORD)Record->Data.Thread.ProcessId;
        DWORD creator = (DWORD)Record->Data.Thread.CreatorPid;
        localMatch = (creator == TargetPid);
        remoteMatch = (process == TargetPid);
        return ScopeMatches(Scope, localMatch, remoteMatch);
    }

    return FALSE;
}

static void PrintHandleEvent(_In_ const SLEEPWALKER_HANDLE_EVENT *h, _In_ DWORD sequence)
{
    WCHAR originResolved[768];
    const char *userClass;
    BOOL flagFromNtdll;
    BOOL originResolvedAsNtdll;
    char deepOpcodes[128];
    double deepEntropy = 0.0;

    SLEEPWALKEREtwSymbolsFormatAddressForProcess((DWORD)h->CallerPid, h->OriginAddress, originResolved,
                                                 RTL_NUMBER_OF(originResolved));
    flagFromNtdll = ((h->Flags & SLEEPWALKER_HANDLE_FLAG_FROM_NTDLL) != 0);
    originResolvedAsNtdll =
        WideContainsInsensitive(originResolved, L"ntdll!") || WideContainsInsensitive(originResolved, L"ntdll+");
    userClass = ComputeUserModeHandleClass(h, originResolved);
    deepOpcodes[0] = '\0';
    if (h->DeepSampleSize != 0)
    {
        deepEntropy = ComputeShannonEntropy(h->DeepSample, h->DeepSampleSize);
        FormatOpcodePreviewA(h->DeepSample, h->DeepSampleSize, deepOpcodes, RTL_NUMBER_OF(deepOpcodes));
    }

    printf("===== [SLEEPWALKER][HANDLE] seq=%lu =====\n", sequence);
    printf("class=%s callerPid=%016llX targetPid=%016llX access=0x%08X\n", userClass, (unsigned long long)h->CallerPid,
           (unsigned long long)h->TargetPid, h->DesiredAccess);
    wprintf(L"origin=0x%016llX (%ls)\n", (unsigned long long)h->OriginAddress, originResolved);
    wprintf(L"path=%ls\n", h->OriginPath[0] ? h->OriginPath : L"<unknown>");
    printf("protect=0x%08X\n", h->OriginProtect);
    PrintHandleFlags(h->Flags);
    printf("statusOpen=0x%08X statusBasic=0x%08X statusSection=0x%08X\n", (unsigned int)h->StatusOpenProcess,
           (unsigned int)h->StatusBasicInfo, (unsigned int)h->StatusSectionName);
    if (h->DeepAllocationBase != 0 || h->DeepRegionSize != 0 || h->DeepSampleSize != 0)
    {
        printf("deep allocBase=0x%016llX regionSize=0x%016llX protect=0x%08X state=0x%08X type=0x%08X\n",
               (unsigned long long)h->DeepAllocationBase, (unsigned long long)h->DeepRegionSize, h->DeepRegionProtect,
               h->DeepRegionState, h->DeepRegionType);
        printf("deep sampleSize=%u entropy=%.3f opcodes=%s\n", h->DeepSampleSize, deepEntropy,
               (h->DeepSampleSize != 0) ? deepOpcodes : "<none>");
    }
    PrintResolvedFrames((DWORD)h->CallerPid, h->Frames, h->FrameCount);

    if (flagFromNtdll != originResolvedAsNtdll)
    {
        printf("[WARN] fromNtdll flag mismatch: flag=%u resolvedNtdll=%u\n", flagFromNtdll ? 1u : 0u,
               originResolvedAsNtdll ? 1u : 0u);
    }
    if (_stricmp(userClass, "DIRECT-SYSCALL-SUSPECT") == 0)
    {
        printf("[ALERT] direct-syscall-suspect classification observed\n");
    }
    printf("=====================================\n");
}

static void PrintThreadEvent(_In_ const SLEEPWALKER_THREAD_EVENT *t, _In_ DWORD sequence)
{
    WCHAR startResolved[768];
    WCHAR imageResolved[768];

    SLEEPWALKEREtwSymbolsFormatAddressForProcess((DWORD)t->ProcessId, t->StartAddress, startResolved,
                                                 RTL_NUMBER_OF(startResolved));
    SLEEPWALKEREtwSymbolsFormatAddressForProcess((DWORD)t->ProcessId, t->ImageBase, imageResolved,
                                                 RTL_NUMBER_OF(imageResolved));

    printf("===== [SLEEPWALKER][THREAD] seq=%lu =====\n", sequence);
    printf("pid=%016llX tid=%016llX creatorPid=%016llX flags=0x%08X\n", (unsigned long long)t->ProcessId,
           (unsigned long long)t->ThreadId, (unsigned long long)t->CreatorPid, t->Flags);
    wprintf(L"start=0x%016llX (%ls)\n", (unsigned long long)t->StartAddress, startResolved);
    wprintf(L"imageBase=0x%016llX (%ls) imageSize=0x%llX\n", (unsigned long long)t->ImageBase, imageResolved,
            (unsigned long long)t->ImageSize);
    PrintThreadFlags(t->Flags);
    PrintResolvedFrames((DWORD)t->ProcessId, t->Frames, t->FrameCount);
    printf("=====================================\n");
}

static void LoggerEmitIoctlRecord(_In_ const SLEEPWALKER_EVENT_RECORD *Record)
{
    char msg[2048];
    const SLEEPWALKER_HANDLE_EVENT *h;
    const SLEEPWALKER_THREAD_EVENT *t;

    if (Record == NULL)
    {
        return;
    }

    if (Record->Header.Type == SleepwalkerEventTypeHandle)
    {
        if (!g_Logger.Policy.AllowIoctlHandle)
        {
            return;
        }

        h = &Record->Data.Handle;
        (void)StringCchPrintfA(msg, RTL_NUMBER_OF(msg),
                               "seq=%lu class=%u caller=%llu target=%llu access=0x%08X flags=0x%08X origin=0x%llX",
                               (unsigned long)Record->Header.Sequence, (unsigned)h->ClassId,
                               (unsigned long long)h->CallerPid, (unsigned long long)h->TargetPid, h->DesiredAccess,
                               h->Flags, (unsigned long long)h->OriginAddress);
        LoggerEmitJson((h->ClassId == SleepwalkerHandleClassDirectSyscallSuspect) ? 4u : 2u, "ioctl", "handle",
                       (DWORD)h->CallerPid, (DWORD)h->TargetPid, msg);
        return;
    }

    if (Record->Header.Type == SleepwalkerEventTypeThread)
    {
        if (!g_Logger.Policy.AllowIoctlThread)
        {
            return;
        }

        t = &Record->Data.Thread;
        (void)StringCchPrintfA(msg, RTL_NUMBER_OF(msg),
                               "seq=%lu process=%llu thread=%llu creator=%llu flags=0x%08X start=0x%llX imageBase=0x%llX",
                               (unsigned long)Record->Header.Sequence, (unsigned long long)t->ProcessId,
                               (unsigned long long)t->ThreadId, (unsigned long long)t->CreatorPid, t->Flags,
                               (unsigned long long)t->StartAddress, (unsigned long long)t->ImageBase);
        LoggerEmitJson(((t->Flags & SLEEPWALKER_THREAD_FLAG_CORRELATED_INTENT) != 0) ? 3u : 1u, "ioctl", "thread",
                       (DWORD)t->CreatorPid, (DWORD)t->ProcessId, msg);
        return;
    }
}

static void LoggerEmitEtwRecord(_In_ PEVENT_RECORD Record, _In_opt_z_ PCWSTR EventName)
{
    ULONGLONG processId = 0;
    ULONGLONG callerPid = 0;
    ULONGLONG targetPid = 0;
    ULONGLONG severity = 0;
    WCHAR reasonW[384];
    char detectionName[192];
    char reason[512];
    char eventNameUtf8[128];
    char provider[32];
    char message[2048];
    DWORD actorPid = 0;
    DWORD target = 0;

    if (Record == NULL)
    {
        return;
    }

    if (IsEqualGUID(&Record->EventHeader.ProviderId, &SLEEPWALKERSC_PROVIDER_GUID_SLEEPWALKER))
    {
        if (!g_Logger.Policy.AllowEtwSleepwalker)
        {
            return;
        }
        (void)StringCchCopyA(provider, RTL_NUMBER_OF(provider), "sleepwalker");
    }
    else if (IsEqualGUID(&Record->EventHeader.ProviderId, &SLEEPWALKERSC_PROVIDER_GUID_TI))
    {
        if (!g_Logger.Policy.AllowEtwTi)
        {
            return;
        }
        (void)StringCchCopyA(provider, RTL_NUMBER_OF(provider), "ti");
    }
    else
    {
        return;
    }

    (void)GetEtwU64Property(Record, L"processId", &processId);
    (void)GetEtwU64Property(Record, L"callerPid", &callerPid);
    (void)GetEtwU64Property(Record, L"targetPid", &targetPid);
    if (processId == 0)
    {
        processId = callerPid;
    }
    if (processId > 0 && processId <= 0xFFFFFFFFull)
    {
        actorPid = (DWORD)processId;
    }
    if (targetPid > 0 && targetPid <= 0xFFFFFFFFull)
    {
        target = (DWORD)targetPid;
    }

    ZeroMemory(eventNameUtf8, sizeof(eventNameUtf8));
    if (EventName != NULL && EventName[0] != L'\0')
    {
        WideToUtf8(EventName, eventNameUtf8, RTL_NUMBER_OF(eventNameUtf8));
    }
    if (eventNameUtf8[0] == '\0')
    {
        (void)StringCchCopyA(eventNameUtf8, RTL_NUMBER_OF(eventNameUtf8), "unknown");
    }

    if (EventName != NULL && wcscmp(EventName, L"DetectionTelemetry") == 0)
    {
        ZeroMemory(reasonW, sizeof(reasonW));
        ZeroMemory(detectionName, sizeof(detectionName));
        ZeroMemory(reason, sizeof(reason));
        (void)GetEtwAnsiProperty(Record, L"detectionName", detectionName, RTL_NUMBER_OF(detectionName));
        (void)GetEtwWideProperty(Record, L"reason", reasonW, RTL_NUMBER_OF(reasonW));
        (void)GetEtwU64Property(Record, L"severity", &severity);
        WideToUtf8(reasonW, reason, RTL_NUMBER_OF(reason));
        if (detectionName[0] == '\0')
        {
            (void)StringCchCopyA(detectionName, RTL_NUMBER_OF(detectionName), "UNKNOWN");
        }
        (void)StringCchPrintfA(message, RTL_NUMBER_OF(message), "event=%s detection=%s reason=%s", eventNameUtf8,
                               detectionName, (reason[0] != '\0') ? reason : "<none>");
        LoggerEmitJson((severity != 0 && severity <= 10) ? (DWORD)severity : 4u, provider, "detection", actorPid,
                       target, message);
        return;
    }

    (void)StringCchPrintfA(message, RTL_NUMBER_OF(message), "event=%s", eventNameUtf8);
    LoggerEmitJson(1u, provider, "event", actorPid, target, message);
}

int __cdecl main(int argc, char **argv)
{
    HANDLE h;
    HANDLE liveEtwThread = NULL;
    SLEEPWALKER_EVENT_RECORD record;
    SLEEPWALKER_TARGET_SPEC targetSpec;
    SLEEPWALKER_ATTACH_CONTEXT attach;
    SLEEPWALKER_LIVE_ETW_CONTEXT liveEtw;
    SLEEPWALKER_LAUNCH_TARGET launchTarget;
    DWORD bytes;
    DWORD targetPid;
    DWORD streams;
    DWORD err;
    SLEEPWALKER_TARGET_SCOPE scope = SleepwalkerScopeLocal;
    BOOL ok;
    BOOL symbolsInitialized = FALSE;
    BOOL ioctlVerbose = TRUE;
    BOOL rc = FALSE;
    SLEEPWALKER_CLIENT_POLICY policy;
    const char *configPath = NULL;
    const char *targetArg = NULL;
    const char *streamsArg = NULL;
    const char *scopeArg = NULL;
    const char *positional[3];
    int positionalCount = 0;
    int i;

    (void)SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE);
    ZeroMemory(&attach, sizeof(attach));
    ZeroMemory(&liveEtw, sizeof(liveEtw));
    ZeroMemory(&launchTarget, sizeof(launchTarget));
    PolicyDefaults(&policy);
    for (i = 0; i < (int)RTL_NUMBER_OF(positional); ++i)
    {
        positional[i] = NULL;
    }

    for (i = 1; i < argc; ++i)
    {
        const char *arg = argv[i];
        if (_stricmp(arg, "--config") == 0)
        {
            if (i + 1 >= argc)
            {
                PrintUsage();
                return 1;
            }
            configPath = argv[++i];
        }
    }

    if (configPath != NULL)
    {
        if (!LoadPolicyFile(configPath, &policy))
        {
            printf("[-] failed to load config '%s' (%lu)\n", configPath, GetLastError());
            return 1;
        }
        printf("[*] loaded config: %s\n", configPath);
    }

    positionalCount = 0;
    for (i = 0; i < (int)RTL_NUMBER_OF(positional); ++i)
    {
        positional[i] = NULL;
    }
    for (i = 1; i < argc; ++i)
    {
        const char *arg = argv[i];
        if (_stricmp(arg, "--config") == 0)
        {
            i += 1;
            continue;
        }
        if (_stricmp(arg, "--log-format") == 0)
        {
            if (i + 1 >= argc || !PolicySetKeyValue(&policy, "log.format", argv[++i]))
            {
                PrintUsage();
                return 1;
            }
            continue;
        }
        if (_stricmp(arg, "--log-file") == 0)
        {
            if (i + 1 >= argc || !PolicySetKeyValue(&policy, "log.file", argv[++i]))
            {
                PrintUsage();
                return 1;
            }
            continue;
        }
        if (_stricmp(arg, "--high-priority-file") == 0)
        {
            if (i + 1 >= argc || !PolicySetKeyValue(&policy, "log.high_priority_file", argv[++i]))
            {
                PrintUsage();
                return 1;
            }
            continue;
        }
        if (_stricmp(arg, "--high-priority-min-severity") == 0)
        {
            if (i + 1 >= argc || !PolicySetKeyValue(&policy, "log.high_priority_min_severity", argv[++i]))
            {
                PrintUsage();
                return 1;
            }
            continue;
        }
        if (_stricmp(arg, "--ioctl-verbose") == 0)
        {
            if (i + 1 >= argc || !PolicySetKeyValue(&policy, "output.ioctl_verbose", argv[++i]))
            {
                PrintUsage();
                return 1;
            }
            continue;
        }

        if (positionalCount >= 3)
        {
            PrintUsage();
            return 1;
        }
        positional[positionalCount++] = arg;
    }

    if (positionalCount == 1 && _stricmp(positional[0], "shutdown") == 0)
    {
        h = SLEEPWALKERSCOpenControlDevice();
        if (h == INVALID_HANDLE_VALUE)
        {
            printf("[-] CreateFile failed (\\\\.\\Global\\SleepwalkerCtl / \\\\.\\SleepwalkerCtl): %lu\n",
                   GetLastError());
            return 1;
        }

        if (!SLEEPWALKERSCSetShutdownMode(h))
        {
            printf("[-] failed to enable shutdown mode via IOCTL_SLEEPWALKER_SET_SHUTDOWN_MODE: %lu\n", GetLastError());
            CloseHandle(h);
            return 1;
        }

        printf("[*] Driver shutdown mode enabled. Active clients should exit shortly.\n");
        CloseHandle(h);
        return 0;
    }

    targetArg = (positionalCount > 0) ? positional[0] : NULL;
    streamsArg = (positionalCount > 1) ? positional[1] : NULL;
    scopeArg = (positionalCount > 2) ? positional[2] : NULL;

    if (targetArg == NULL && policy.HasTarget)
    {
        targetArg = policy.TargetArg;
    }
    if (streamsArg == NULL && policy.HasStreams)
    {
        streamsArg = policy.StreamsArg;
    }
    if (scopeArg == NULL && policy.HasScope)
    {
        scopeArg = policy.ScopeArg;
    }

    if (targetArg == NULL || streamsArg == NULL)
    {
        PrintUsage();
        return 1;
    }

    streams = SLEEPWALKERSCParseStreamMaskA(streamsArg);
    if (streams == 0)
    {
        PrintUsage();
        return 1;
    }
    if (scopeArg != NULL && !ParseScopeArg(scopeArg, &scope))
    {
        PrintUsage();
        return 1;
    }

    if (!ResolveTargetSpec(targetArg, &targetSpec))
    {
        printf("[-] Invalid target '%s'.\n", targetArg);
        return 1;
    }

    if (!ResolveTargetPid(&targetSpec, &targetPid, &launchTarget))
    {
        err = GetLastError();
        if (err == ERROR_CANCELLED)
        {
            printf("[*] Cancelled.\n");
        }
        else
        {
            printf("[-] Could not resolve target '%s': %lu\n", targetArg, err);
        }
        return 1;
    }

    h = SLEEPWALKERSCOpenControlDevice();
    if (h == INVALID_HANDLE_VALUE)
    {
        printf("[-] CreateFile failed (\\\\.\\Global\\SleepwalkerCtl / \\\\.\\SleepwalkerCtl): %lu\n", GetLastError());
        return 1;
    }

    attach.Device = h;
    attach.StreamMask = streams;
    attach.TargetPid = targetPid;
    attach.Scope = scope;
    if (policy.IoctlVerboseOverrideSet)
    {
        ioctlVerbose = policy.IoctlVerboseOverride;
    }

    (void)LoggerInitialize(&policy, targetPid);

    if (!AttachProgramTargetPid(&attach))
    {
        printf("[-] attach failed via IOCTL_SLEEPWALKER_SET_PIDS: %lu\n", GetLastError());
        goto Cleanup;
    }
    printf("[*] Attached target=%lu streams=0x%08lX scope=%s (strict target mode). Ctrl+C to stop.\n", targetPid,
           streams, ScopeToString(scope));
    PrimeTargetImageHint(h, &targetSpec, targetPid);

    if (launchTarget.Active && !launchTarget.Resumed)
    {
        DWORD resumeResult = ResumeThread(launchTarget.ProcessInfo.hThread);
        if (resumeResult == (DWORD)-1)
        {
            printf("[-] ResumeThread failed for launched target pid=%lu: %lu\n", targetPid, GetLastError());
            goto Cleanup;
        }
        launchTarget.Resumed = TRUE;
        printf("[*] Launched target resumed pid=%lu\n", targetPid);
    }

    liveEtw.Attach = &attach;
    SLEEPWALKEREtwSymbolsInitialize();
    symbolsInitialized = TRUE;

    if (!StartLiveEtw(&liveEtw, &liveEtwThread))
    {
        printf("[WARN] live ETW stream unavailable: %lu (continuing with IOCTL stream only)\n", GetLastError());
    }
    else
    {
        printf("[*] Live ETW stream started (Sleepwalker provider + TI if available).\n");
        printf("[*] Suppressing duplicate IOCTL event dump while ETW formatter is active.\n");
        ioctlVerbose = FALSE;
    }

    while (InterlockedCompareExchange(&g_StopRequested, 0, 0) == 0)
    {
        ok = SLEEPWALKERSCGetEvent(h, &record, &bytes);
        if (!ok)
        {
            err = GetLastError();
            if (err == ERROR_NO_MORE_ITEMS)
            {
                Sleep(80);
                continue;
            }
            if (err == ERROR_NOT_READY || err == ERROR_OPERATION_ABORTED || err == ERROR_DEVICE_NOT_CONNECTED)
            {
                printf("[*] Driver shutdown mode is active; stopping client loop.\n");
                break;
            }
            printf("[-] GetEvent failed: %lu\n", err);
            break;
        }

        if (!IoctlRecordMatchesTargetPid(&record, targetPid, scope))
        {
            continue;
        }

        LoggerEmitIoctlRecord(&record);

        if (!ioctlVerbose)
        {
            continue;
        }

        if (record.Header.Type == SleepwalkerEventTypeHandle)
        {
            PrintHandleEvent(&record.Data.Handle, record.Header.Sequence);
        }
        else if (record.Header.Type == SleepwalkerEventTypeThread)
        {
            PrintThreadEvent(&record.Data.Thread, record.Header.Sequence);
        }
    }

    rc = TRUE;

Cleanup:
    if (liveEtw.Session != NULL)
    {
        SLEEPWALKERSCStopEtwSession(liveEtw.Session);
        g_StopSession = NULL;
    }
    if (liveEtwThread != NULL)
    {
        (void)WaitForSingleObject(liveEtwThread, 3000);
        CloseHandle(liveEtwThread);
        liveEtwThread = NULL;
    }
    SLEEPWALKERFlushEtwPrinterState();
    if (symbolsInitialized)
    {
        SLEEPWALKEREtwSymbolsCleanup();
    }

    if (launchTarget.Active)
    {
        if (!launchTarget.Resumed && launchTarget.ProcessInfo.hProcess != NULL)
        {
            (void)TerminateProcess(launchTarget.ProcessInfo.hProcess, ERROR_CANCELLED);
        }
        if (launchTarget.ProcessInfo.hThread != NULL)
        {
            CloseHandle(launchTarget.ProcessInfo.hThread);
            launchTarget.ProcessInfo.hThread = NULL;
        }
        if (launchTarget.ProcessInfo.hProcess != NULL)
        {
            CloseHandle(launchTarget.ProcessInfo.hProcess);
            launchTarget.ProcessInfo.hProcess = NULL;
        }
        launchTarget.Active = FALSE;
    }

    LoggerShutdown();
    CloseHandle(h);
    return rc ? 0 : 1;
}
