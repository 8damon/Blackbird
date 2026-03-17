#include "blackbird_client_internal.h"
DWORD FindProcessIdByNameW(_In_z_ const wchar_t *processName)
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

HANDLE OpenControlDeviceByPolicy(_In_opt_z_ const char *BrokerPipeUtf8, _Out_opt_ BOOL *UsingBroker)
{
    HANDLE device;
    WCHAR brokerPipeWide[MAX_PATH];
    PCWSTR pipeName = NULL;

    if (UsingBroker != NULL)
    {
        *UsingBroker = FALSE;
    }

    ZeroMemory(brokerPipeWide, sizeof(brokerPipeWide));
    if (BrokerPipeUtf8 != NULL && BrokerPipeUtf8[0] != '\0')
    {
        if (!ConvertArgToWide(BrokerPipeUtf8, brokerPipeWide, RTL_NUMBER_OF(brokerPipeWide)))
        {
            SetLastError(ERROR_INVALID_PARAMETER);
            return INVALID_HANDLE_VALUE;
        }
        pipeName = brokerPipeWide;
    }

    if (!BLACKBIRDSCUseClientProtocol(pipeName, 1500))
    {
        return INVALID_HANDLE_VALUE;
    }

    device = BLACKBIRDSCOpenControlDevice();
    if (device == INVALID_HANDLE_VALUE)
    {
        return INVALID_HANDLE_VALUE;
    }

    if (UsingBroker != NULL)
    {
        *UsingBroker = TRUE;
    }
    return device;
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
    WCHAR normalized[BLACKBIRD_PATH_CHARS];

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
    WCHAR devicePrefix[BLACKBIRD_PATH_CHARS];

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

static BOOL PathMatchesSpec(_In_ const BLACKBIRD_TARGET_SPEC *Spec, _In_z_ const WCHAR *CandidatePath)
{
    WCHAR candidateNorm[BLACKBIRD_PATH_CHARS];

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

static BOOL ResolvePathSpec(_In_z_ const char *PathText, _Out_ BLACKBIRD_TARGET_SPEC *Spec)
{
    WCHAR inputWide[BLACKBIRD_PATH_CHARS];
    WCHAR canonical[BLACKBIRD_PATH_CHARS];
    WCHAR ntPath[BLACKBIRD_PATH_CHARS];
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

    Spec->Kind = BlackbirdTargetPath;
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

BOOL ResolveTargetSpec(_In_z_ const char *TargetArg, _Out_ BLACKBIRD_TARGET_SPEC *Spec)
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
        Spec->Kind = BlackbirdTargetPid;
        Spec->Pid = pid;
        return TRUE;
    }

    if (TryParsePid(TargetArg, &pid))
    {
        Spec->Kind = BlackbirdTargetPid;
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
        Spec->Kind = BlackbirdTargetLaunch;
        return TRUE;
    }

    if (_strnicmp(TargetArg, "name:", 5) == 0 || _strnicmp(TargetArg, "name=", 5) == 0)
    {
        namePart = TargetArg + 5;
        if (namePart[0] == '\0')
        {
            return FALSE;
        }
        Spec->Kind = BlackbirdTargetName;
        return ConvertArgToWide(namePart, Spec->Name, RTL_NUMBER_OF(Spec->Name));
    }

    if (strchr(TargetArg, '\\') != NULL || strchr(TargetArg, '/') != NULL)
    {
        return ResolvePathSpec(TargetArg, Spec);
    }

    Spec->Kind = BlackbirdTargetName;
    return ConvertArgToWide(TargetArg, Spec->Name, RTL_NUMBER_OF(Spec->Name));
}
DWORD FindProcessIdByPathSpec(_In_ const BLACKBIRD_TARGET_SPEC *Spec)
{
    PROCESSENTRY32W pe;
    HANDLE snapshot;

    if (Spec == NULL || Spec->Kind != BlackbirdTargetPath)
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
                WCHAR path[BLACKBIRD_PATH_CHARS];
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

BOOL ScopeMatches(_In_ BLACKBIRD_TARGET_SCOPE Scope, _In_ BOOL LocalMatch, _In_ BOOL RemoteMatch)
{
    if (Scope == BlackbirdScopeLocal)
    {
        return LocalMatch;
    }
    if (Scope == BlackbirdScopeRemote)
    {
        return RemoteMatch;
    }
    return (LocalMatch || RemoteMatch);
}

BOOL ParseScopeArg(_In_opt_z_ const char *Text, _Out_ BLACKBIRD_TARGET_SCOPE *Scope)
{
    const char *value = Text;

    if (Scope == NULL)
    {
        return FALSE;
    }

    *Scope = BlackbirdScopeLocal;
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
        *Scope = BlackbirdScopeLocal;
        return TRUE;
    }
    if (_stricmp(value, "remote") == 0 || _stricmp(value, "target") == 0)
    {
        *Scope = BlackbirdScopeRemote;
        return TRUE;
    }
    if (_stricmp(value, "both") == 0 || _stricmp(value, "all") == 0)
    {
        *Scope = BlackbirdScopeBoth;
        return TRUE;
    }

    return FALSE;
}

const char *ScopeToString(_In_ BLACKBIRD_TARGET_SCOPE Scope)
{
    if (Scope == BlackbirdScopeRemote)
    {
        return "remote";
    }
    if (Scope == BlackbirdScopeBoth)
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

void PolicyDefaults(_Out_ BLACKBIRD_CLIENT_POLICY *Policy)
{
    if (Policy == NULL)
    {
        return;
    }
    ZeroMemory(Policy, sizeof(*Policy));
    Policy->LogFormat = BlackbirdLogFormatText;
    Policy->HighPriorityMinSeverity = 4;
    Policy->AllowIoctlHandle = TRUE;
    Policy->AllowIoctlThread = TRUE;
    Policy->AllowIoctlFilesystem = TRUE;
    Policy->AllowEtwBlackbird = TRUE;
    Policy->AllowEtwTi = TRUE;
}

BOOL PolicySetKeyValue(_Inout_ BLACKBIRD_CLIENT_POLICY *Policy, _In_z_ const char *Key, _In_z_ const char *Value)
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
            Policy->LogFormat = BlackbirdLogFormatJsonl;
            return TRUE;
        }
        if (_stricmp(Value, "text") == 0 || _stricmp(Value, "console") == 0)
        {
            Policy->LogFormat = BlackbirdLogFormatText;
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
    if (_stricmp(Key, "filter.ioctl.filesystem") == 0 || _stricmp(Key, "filter.ioctl.file") == 0)
    {
        if (!ParseBoolText(Value, &b))
        {
            return FALSE;
        }
        Policy->AllowIoctlFilesystem = b;
        return TRUE;
    }
    if (_stricmp(Key, "filter.etw.blackbird") == 0)
    {
        if (!ParseBoolText(Value, &b))
        {
            return FALSE;
        }
        Policy->AllowEtwBlackbird = b;
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

BOOL LoadPolicyFile(_In_z_ const char *Path, _Inout_ BLACKBIRD_CLIENT_POLICY *Policy)
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

void WideToUtf8(_In_opt_z_ const WCHAR *Wide, _Out_writes_z_(OutputChars) char *Output, _In_ size_t OutputChars)
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

void LoggerEmitJson(_In_ DWORD Severity, _In_z_ const char *Category, _In_z_ const char *Kind, _In_ DWORD Pid,
                    _In_ DWORD TargetPid, _In_z_ const char *Message)
{
    char ts[64];
    char catEsc[128];
    char kindEsc[128];
    char msgEsc[2048];
    char line[2600];

    if (g_Logger.Policy.LogFormat != BlackbirdLogFormatJsonl || g_Logger.LogFile == NULL)
    {
        return;
    }

    GetTimestampUtcIso(ts, RTL_NUMBER_OF(ts));
    JsonEscapeA(Category, catEsc, RTL_NUMBER_OF(catEsc));
    JsonEscapeA(Kind, kindEsc, RTL_NUMBER_OF(kindEsc));
    JsonEscapeA(Message, msgEsc, RTL_NUMBER_OF(msgEsc));

    (void)StringCchPrintfA(line, RTL_NUMBER_OF(line),
                           "{\"ts\":\"%s\",\"source\":\"blackbird-client\",\"category\":\"%s\",\"kind\":\"%s\","
                           "\"severity\":%lu,\"pid\":%lu,\"targetPid\":%lu,\"message\":\"%s\"}",
                           ts, catEsc, kindEsc, (unsigned long)Severity, (unsigned long)Pid, (unsigned long)TargetPid,
                           msgEsc);
    LoggerWriteLine(g_Logger.LogFile, line);

    if (g_Logger.HighPriorityFile != NULL && Severity >= g_Logger.Policy.HighPriorityMinSeverity)
    {
        LoggerWriteLine(g_Logger.HighPriorityFile, line);
    }
}

BOOL LoggerInitialize(_In_ const BLACKBIRD_CLIENT_POLICY *Policy, _In_ DWORD TargetPid)
{
    if (Policy == NULL)
    {
        return FALSE;
    }

    ZeroMemory(&g_Logger, sizeof(g_Logger));
    g_Logger.Policy = *Policy;
    g_Logger.TargetPid = TargetPid;

    if (g_Logger.Policy.LogFormat != BlackbirdLogFormatJsonl)
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

void LoggerShutdown(void)
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

BOOL GetEtwWideProperty(_In_ PEVENT_RECORD Record, _In_z_ PCWSTR Name, _Out_writes_z_(OutputChars) PWSTR Output,
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

BOOL GetEtwAnsiProperty(_In_ PEVENT_RECORD Record, _In_z_ PCWSTR Name, _Out_writes_z_(OutputChars) PSTR Output,
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

BOOL GetEtwU64Property(_In_ PEVENT_RECORD Record, _In_z_ PCWSTR Name, _Out_ ULONGLONG *Value)
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

BOOL AttachProgramTargetPid(_Inout_ BLACKBIRD_ATTACH_CONTEXT *Attach)
{
    DWORD pids[1];

    if (Attach == NULL || Attach->Device == INVALID_HANDLE_VALUE || Attach->TargetPid == 0)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    pids[0] = Attach->TargetPid;
    return BLACKBIRDSCSetPids(Attach->Device, pids, RTL_NUMBER_OF(pids), Attach->StreamMask);
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
                                      _In_ BLACKBIRD_TARGET_SCOPE Scope)
{
    static const PCWSTR tiActorNames[] = {L"CallingProcessId", L"CallerProcessId", L"SourceProcessId", L"ProcessId"};
    static const PCWSTR tiTargetNames[] = {L"TargetProcessId", L"NewProcessId", L"DestProcessId"};
    static const PCWSTR socketActorNames[] = {L"PID", L"ProcessId", L"processId"};
    BOOL localMatch = FALSE;
    BOOL remoteMatch = FALSE;

    if (Record == NULL || TargetPid == 0)
    {
        return FALSE;
    }

    if (IsEqualGUID(&Record->EventHeader.ProviderId, &BLACKBIRDSC_PROVIDER_GUID_BLACKBIRD))
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

    if (IsEqualGUID(&Record->EventHeader.ProviderId, &BLACKBIRDSC_PROVIDER_GUID_TI))
    {
        localMatch = EtwAnyPropertyMatchesTargetPid(Record, tiActorNames, RTL_NUMBER_OF(tiActorNames), TargetPid);
        remoteMatch = EtwAnyPropertyMatchesTargetPid(Record, tiTargetNames, RTL_NUMBER_OF(tiTargetNames), TargetPid);
        return ScopeMatches(Scope, localMatch, remoteMatch);
    }
    if (IsEqualGUID(&Record->EventHeader.ProviderId, &BLACKBIRDSC_PROVIDER_GUID_KERNEL_NETWORK))
    {
        localMatch = (Record->EventHeader.ProcessId == TargetPid) ||
                     EtwAnyPropertyMatchesTargetPid(Record, socketActorNames, RTL_NUMBER_OF(socketActorNames), TargetPid);
        remoteMatch = FALSE;
        return ScopeMatches(Scope, localMatch, remoteMatch);
    }

    return FALSE;
}

BOOL BrokerEtwEventMatchesTargetPid(_In_ const BLACKBIRD_IPC_ETW_EVENT *Event, _In_ DWORD TargetPid,
                                    _In_ BLACKBIRD_TARGET_SCOPE Scope)
{
    DWORD actorPid = 0;
    DWORD remotePid = 0;
    BOOL localMatch;
    BOOL remoteMatch;

    if (Event == NULL || TargetPid == 0)
    {
        return FALSE;
    }

    switch (Event->Family)
    {
    case BlackbirdIpcEtwFamilyHandle:
    case BlackbirdIpcEtwFamilyApc:
        if (Event->CallerPid != 0 && Event->CallerPid <= 0xFFFFFFFFull)
        {
            actorPid = (DWORD)Event->CallerPid;
        }
        else if (Event->ProcessId != 0 && Event->ProcessId <= 0xFFFFFFFFull)
        {
            actorPid = (DWORD)Event->ProcessId;
        }
        if (Event->TargetPid != 0 && Event->TargetPid <= 0xFFFFFFFFull)
        {
            remotePid = (DWORD)Event->TargetPid;
        }
        break;
    case BlackbirdIpcEtwFamilyThread:
        if (Event->CreatorProcessId != 0 && Event->CreatorProcessId <= 0xFFFFFFFFull)
        {
            actorPid = (DWORD)Event->CreatorProcessId;
        }
        else if (Event->ProcessId != 0 && Event->ProcessId <= 0xFFFFFFFFull)
        {
            actorPid = (DWORD)Event->ProcessId;
        }
        if (Event->ProcessId != 0 && Event->ProcessId <= 0xFFFFFFFFull)
        {
            remotePid = (DWORD)Event->ProcessId;
        }
        break;
    case BlackbirdIpcEtwFamilyProcess:
        if (Event->CreatorProcessId != 0 && Event->CreatorProcessId <= 0xFFFFFFFFull)
        {
            actorPid = (DWORD)Event->CreatorProcessId;
        }
        else if (Event->ParentProcessId != 0 && Event->ParentProcessId <= 0xFFFFFFFFull)
        {
            actorPid = (DWORD)Event->ParentProcessId;
        }
        else if (Event->ProcessId != 0 && Event->ProcessId <= 0xFFFFFFFFull)
        {
            actorPid = (DWORD)Event->ProcessId;
        }
        if (Event->ProcessId != 0 && Event->ProcessId <= 0xFFFFFFFFull)
        {
            remotePid = (DWORD)Event->ProcessId;
        }
        break;
    case BlackbirdIpcEtwFamilyDetection:
    case BlackbirdIpcEtwFamilyThreatIntel:
    case BlackbirdIpcEtwFamilySocket:
        if (Event->ProcessId != 0 && Event->ProcessId <= 0xFFFFFFFFull)
        {
            actorPid = (DWORD)Event->ProcessId;
        }
        if (Event->TargetPid != 0 && Event->TargetPid <= 0xFFFFFFFFull)
        {
            remotePid = (DWORD)Event->TargetPid;
        }
        break;
    default:
        if (Event->ProcessId != 0 && Event->ProcessId <= 0xFFFFFFFFull)
        {
            actorPid = (DWORD)Event->ProcessId;
        }
        else if (Event->EventProcessId != 0)
        {
            actorPid = Event->EventProcessId;
        }
        if (Event->TargetPid != 0 && Event->TargetPid <= 0xFFFFFFFFull)
        {
            remotePid = (DWORD)Event->TargetPid;
        }
        break;
    }

    localMatch = (actorPid == TargetPid);
    remoteMatch = (remotePid == TargetPid && actorPid != TargetPid);

    return ScopeMatches(Scope, localMatch, remoteMatch);
}
VOID WINAPI LiveEtwCallback(_In_ PEVENT_RECORD Record, _In_opt_z_ PCWSTR EventName, _In_opt_ PVOID Context)
{
    BLACKBIRD_LIVE_ETW_CONTEXT *live = (BLACKBIRD_LIVE_ETW_CONTEXT *)Context;

    if (Record == NULL || live == NULL || live->Attach == NULL)
    {
        return;
    }

    BLACKBIRDPrimeProcessImageFromEtw(Record, EventName);

    if (!EtwRecordMatchesTargetPid(Record, EventName, live->Attach->TargetPid, live->Attach->Scope))
    {
        return;
    }

    LoggerEmitEtwRecord(Record, EventName);

    if (IsEqualGUID(&Record->EventHeader.ProviderId, &BLACKBIRDSC_PROVIDER_GUID_BLACKBIRD))
    {
        if (EventName != NULL && EventName[0] != L'\0')
        {
            BLACKBIRDPrintEtwRecord(Record, EventName);
        }
    }
    else if (IsEqualGUID(&Record->EventHeader.ProviderId, &BLACKBIRDSC_PROVIDER_GUID_TI))
    {
        BLACKBIRDPrintThreatIntelRecord(Record, EventName);
    }
}
VOID WINAPI PathWatchEtwCallback(_In_ PEVENT_RECORD Record, _In_opt_z_ PCWSTR EventName, _In_opt_ PVOID Context)
{
    BLACKBIRD_PATH_WATCH_CONTEXT *watch = (BLACKBIRD_PATH_WATCH_CONTEXT *)Context;
    WCHAR imagePath[BLACKBIRD_PATH_CHARS];
    ULONGLONG pidValue = 0;
    BLACKBIRD_TARGET_SPEC spec;

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
    spec.Kind = BlackbirdTargetPath;
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

 DWORD WINAPI EtwRunThreadProc(_In_ LPVOID Context)
{
    BLACKBIRD_ETW_RUN_CONTEXT *run = (BLACKBIRD_ETW_RUN_CONTEXT *)Context;

    if (run == NULL || run->Session == NULL)
    {
        return 1;
    }

    (void)BLACKBIRDSCRunEtwSession(run->Session);
    if (run->Watch != NULL)
    {
        InterlockedExchange(&run->Watch->SessionEnded, 1);
    }
    return 0;
}



