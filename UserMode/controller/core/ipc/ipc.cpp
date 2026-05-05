#include "../controller_private.h"
#include "../injection/injection.h"
#include "ipc_internal.h"
#include <tlhelp32.h>

static constexpr UINT64 ControllerSr71WriteBlockedMarker = 0x5352373157424C4Bull;   // SR71WBLK
static constexpr UINT64 ControllerSr71ProtectBlockedMarker = 0x5352373150424C4Bull; // SR71PBLK

enum
{
    ControllerModuleOpLoadLibraryA = 0,
    ControllerModuleOpLoadLibraryW = 1,
    ControllerModuleOpLoadLibraryExA = 2,
    ControllerModuleOpLoadLibraryExW = 3,
    ControllerModuleOpLdrLoadDll = 4,
    ControllerModuleOpRtlAddFunctionTable = 5,
    ControllerModuleOpRtlInstallFunctionTableCallback = 6,
    ControllerModuleOpRtlDeleteFunctionTable = 7,
    ControllerModuleOpCoInitializeEx = 8,
    ControllerModuleOpCoInitializeSecurity = 9,
    ControllerModuleOpCoCreateInstance = 10,
    ControllerModuleOpEventRegister = 11,
    ControllerModuleOpEventUnregister = 12,
    ControllerModuleOpStartTraceW = 13,
    ControllerModuleOpEnableTraceEx2 = 14,
    ControllerModuleOpCreateJobObjectW = 15,
    ControllerModuleOpOpenJobObjectW = 16,
    ControllerModuleOpAssignProcessToJobObject = 17,
    ControllerModuleOpSetInformationJobObject = 18
};

enum CONTROLLER_IMAGE_TAMPER_KIND
{
    ControllerImageTamperNone = 0,
    ControllerImageTamperIat,
    ControllerImageTamperEat,
    ControllerImageTamperNtdll
};

struct CONTROLLER_IMAGE_TAMPER_CLASSIFICATION
{
    CONTROLLER_IMAGE_TAMPER_KIND Kind;
    WCHAR ModulePath[MAX_PATH];
    CHAR ModuleName[MAX_PATH];
    UINT64 ModuleBase;
    UINT32 Rva;
    UINT32 DirectoryRva;
    UINT32 DirectorySize;
};

typedef struct _BK_CONTROLLER_ANALYSIS_TEARDOWN
{
    BOOL HadState;
    BOOL HadAnalysisLease;
    BOOL LaunchOwned;
    BOOL PendingLaunchArmed;
    DWORD RootProcessId;
    DWORD SubscriptionCount;
    DWORD OwnedRangeCount;
    ULONGLONG SessionId;
} BK_CONTROLLER_ANALYSIS_TEARDOWN, *PBK_CONTROLLER_ANALYSIS_TEARDOWN;

static volatile LONG64 g_ControllerAnalysisSessionSequence = 0;

static VOID ControllerClearDriverPendingLaunchBestEffort(_In_z_ PCSTR Reason);

static ULONGLONG ControllerNextAnalysisSessionId(VOID)
{
    LONG64 value = InterlockedIncrement64(&g_ControllerAnalysisSessionSequence);
    return (value > 0) ? (ULONGLONG)value : 1ull;
}

static ULONGLONG ControllerClientBeginAnalysisSessionLocked(_Inout_ BK_CONTROLLER_CLIENT *Client,
                                                            _In_ DWORD RootProcessId, _In_ BOOL LaunchOwned)
{
    BOOL newSession;

    if (Client == NULL || RootProcessId == 0)
    {
        return 0;
    }

    newSession = (!Client->AnalysisActive || Client->AnalysisRootProcessId != RootProcessId ||
                  Client->AnalysisSessionId == 0);
    if (newSession)
    {
        Client->AnalysisSessionId = ControllerNextAnalysisSessionId();
        Client->AnalysisStartedTick = GetTickCount64();
        Client->AnalysisLaunchOwned = FALSE;
    }

    Client->AnalysisRootProcessId = RootProcessId;
    Client->AnalysisActive = TRUE;
    if (LaunchOwned)
    {
        Client->AnalysisLaunchOwned = TRUE;
    }

    return Client->AnalysisSessionId;
}

static BOOL ControllerClientStopAnalysisLocked(_Inout_ BK_CONTROLLER_CLIENT *Client,
                                               _Out_opt_ PBK_CONTROLLER_ANALYSIS_TEARDOWN Teardown)
{
    BK_CONTROLLER_ANALYSIS_TEARDOWN local;

    ZeroMemory(&local, sizeof(local));
    if (Client == NULL)
    {
        if (Teardown != NULL)
        {
            ZeroMemory(Teardown, sizeof(*Teardown));
        }
        return FALSE;
    }

    local.HadAnalysisLease = (Client->AnalysisActive || Client->AnalysisRootProcessId != 0 ||
                              Client->AnalysisSessionId != 0 || Client->AnalysisLaunchOwned ||
                              Client->PendingLaunchArmed || Client->PendingLaunchPid != 0);
    local.HadState = (local.HadAnalysisLease || Client->SubscriptionCount != 0 || Client->OwnedRangeCount != 0);
    local.LaunchOwned = Client->AnalysisLaunchOwned;
    local.PendingLaunchArmed = Client->PendingLaunchArmed;
    local.RootProcessId = (Client->AnalysisRootProcessId != 0) ? Client->AnalysisRootProcessId : Client->PendingLaunchPid;
    local.SubscriptionCount = Client->SubscriptionCount;
    local.OwnedRangeCount = Client->OwnedRangeCount;
    local.SessionId = Client->AnalysisSessionId;

    Client->SubscriptionCount = 0;
    ZeroMemory(Client->Subscriptions, sizeof(Client->Subscriptions));
    ControllerClientClearPendingLaunchLocked(Client);
    Client->AnalysisSessionId = 0;
    Client->AnalysisRootProcessId = 0;
    Client->AnalysisLaunchOwned = FALSE;
    Client->AnalysisActive = FALSE;
    Client->AnalysisStartedTick = 0;
    Client->OwnedRangeCount = 0;
    ZeroMemory(Client->OwnedRanges, sizeof(Client->OwnedRanges));
    InterlockedExchange(&Client->HookReadyMask, 0);
    Client->HookReadyTick = 0;

    if (local.HadAnalysisLease || local.SubscriptionCount != 0)
    {
        ControllerMarkDriverSubscriptionsDirty();
    }
    if (Teardown != NULL)
    {
        *Teardown = local;
    }
    return local.HadState;
}

static VOID ControllerCompleteAnalysisTeardown(_In_ const BK_CONTROLLER_CLIENT *Client,
                                               _In_ const BK_CONTROLLER_ANALYSIS_TEARDOWN *Teardown,
                                               _In_z_ PCSTR Reason)
{
    PCSTR reason = (Reason != NULL && Reason[0] != '\0') ? Reason : "analysis-teardown";

    if (Client == NULL || Teardown == NULL || !Teardown->HadState)
    {
        return;
    }

    if (Teardown->HadAnalysisLease)
    {
        ControllerLog("[IPC] analysis session stopped clientPid=%lu sessionId=%llu rootPid=%lu launchOwned=%u "
                      "subscriptions=%lu ranges=%lu reason=%s\n",
                      Client->ProcessId, (unsigned long long)Teardown->SessionId, Teardown->RootProcessId,
                      Teardown->LaunchOwned ? 1u : 0u, Teardown->SubscriptionCount, Teardown->OwnedRangeCount, reason);
    }
    else if (Teardown->SubscriptionCount != 0 || Teardown->OwnedRangeCount != 0)
    {
        ControllerLog("[IPC] client analysis state cleared clientPid=%lu subscriptions=%lu ranges=%lu reason=%s\n",
                      Client->ProcessId, Teardown->SubscriptionCount, Teardown->OwnedRangeCount, reason);
    }

    if (Teardown->PendingLaunchArmed)
    {
        ControllerClearDriverPendingLaunchBestEffort(reason);
    }
}

static VOID ControllerTerminateLaunchOwnedTeardown(_In_ const BK_CONTROLLER_ANALYSIS_TEARDOWN *Teardown,
                                                   _In_z_ PCSTR Reason)
{
    PCSTR reason = (Reason != NULL && Reason[0] != '\0') ? Reason : "analysis-teardown";

    if (Teardown != NULL && Teardown->HadAnalysisLease && Teardown->LaunchOwned && Teardown->RootProcessId != 0)
    {
        ControllerInjectionTerminateProcessTreeBestEffort(Teardown->RootProcessId, reason);
    }
}

static BOOL ControllerRangeOverlaps32(_In_ UINT32 Start, _In_ UINT32 Size, _In_ UINT32 OtherStart,
                                      _In_ UINT32 OtherSize)
{
    UINT64 end = (UINT64)Start + ((Size == 0u) ? 1u : Size);
    UINT64 otherEnd = (UINT64)OtherStart + ((OtherSize == 0u) ? 1u : OtherSize);
    return Start < otherEnd && OtherStart < end;
}

static PCSTR ControllerImageTamperDetectionName(_In_ CONTROLLER_IMAGE_TAMPER_KIND Kind)
{
    switch (Kind)
    {
    case ControllerImageTamperIat:
        return "IAT_TAMPER_SUSPECT";
    case ControllerImageTamperEat:
        return "EAT_TAMPER_SUSPECT";
    case ControllerImageTamperNtdll:
        return "NTDLL_IMAGE_TAMPER_SUSPECT";
    default:
        return NULL;
    }
}

static PCWSTR ControllerImageTamperKindLabel(_In_ CONTROLLER_IMAGE_TAMPER_KIND Kind)
{
    switch (Kind)
    {
    case ControllerImageTamperIat:
        return L"IAT";
    case ControllerImageTamperEat:
        return L"EAT";
    case ControllerImageTamperNtdll:
        return L"ntdll image";
    default:
        return L"image";
    }
}

static BOOL ControllerProtectAllowsWrite(_In_ UINT32 Protect)
{
    UINT32 baseProtect = Protect & 0xFFu;
    return baseProtect == PAGE_READWRITE || baseProtect == PAGE_WRITECOPY || baseProtect == PAGE_EXECUTE_READWRITE ||
           baseProtect == PAGE_EXECUTE_WRITECOPY;
}

static BOOL ControllerProtectAllowsExecute(_In_ UINT32 Protect)
{
    UINT32 baseProtect = Protect & 0xFFu;
    return baseProtect == PAGE_EXECUTE || baseProtect == PAGE_EXECUTE_READ || baseProtect == PAGE_EXECUTE_READWRITE ||
           baseProtect == PAGE_EXECUTE_WRITECOPY;
}

static PCWSTR ControllerBaseNameW(_In_opt_z_ PCWSTR Path)
{
    PCWSTR slash;
    PCWSTR altSlash;

    if (Path == NULL)
    {
        return L"";
    }

    slash = wcsrchr(Path, L'\\');
    altSlash = wcsrchr(Path, L'/');
    if (altSlash != NULL && (slash == NULL || altSlash > slash))
    {
        slash = altSlash;
    }

    return (slash != NULL) ? slash + 1 : Path;
}

static BOOL ControllerPidImageNameEquals(_In_ DWORD ProcessId, _In_z_ PCWSTR ExpectedImageName)
{
    HANDLE process;
    WCHAR imagePath[MAX_PATH * 2];
    DWORD imageChars;
    HANDLE snapshot;
    PROCESSENTRY32W entry;

    if (ProcessId == 0 || ExpectedImageName == NULL || ExpectedImageName[0] == L'\0')
    {
        return FALSE;
    }

    imageChars = RTL_NUMBER_OF(imagePath);
    imagePath[0] = L'\0';
    process = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, ProcessId);
    if (process != NULL)
    {
        if (QueryFullProcessImageNameW(process, 0, imagePath, &imageChars) &&
            _wcsicmp(ControllerBaseNameW(imagePath), ExpectedImageName) == 0)
        {
            CloseHandle(process);
            return TRUE;
        }
        CloseHandle(process);
    }

    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
    {
        return FALSE;
    }

    ZeroMemory(&entry, sizeof(entry));
    entry.dwSize = sizeof(entry);
    if (!Process32FirstW(snapshot, &entry))
    {
        CloseHandle(snapshot);
        return FALSE;
    }

    do
    {
        if (entry.th32ProcessID == ProcessId && _wcsicmp(entry.szExeFile, ExpectedImageName) == 0)
        {
            CloseHandle(snapshot);
            return TRUE;
        }
    } while (Process32NextW(snapshot, &entry));

    CloseHandle(snapshot);
    return FALSE;
}

static BOOL ControllerQueryProcessMemoryBasic(_In_ DWORD ProcessId, _In_ UINT64 Address,
                                              _Out_ MEMORY_BASIC_INFORMATION *Mbi)
{
    HANDLE process;
    SIZE_T queried;

    if (ProcessId == 0 || Address == 0 || Mbi == NULL)
    {
        return FALSE;
    }

    process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, ProcessId);
    if (process == NULL)
    {
        return FALSE;
    }

    ZeroMemory(Mbi, sizeof(*Mbi));
    queried = VirtualQueryEx(process, (LPCVOID)(ULONG_PTR)Address, Mbi, sizeof(*Mbi));
    CloseHandle(process);
    return queried == sizeof(*Mbi);
}

static BOOL ControllerFunctionTableBaseLooksAbusive(_In_ DWORD ProcessId, _In_ UINT64 BaseAddress,
                                                    _Out_opt_ MEMORY_BASIC_INFORMATION *MbiOut,
                                                    _Out_writes_z_(ReasonChars) PWSTR Reason, _In_ size_t ReasonChars)
{
    MEMORY_BASIC_INFORMATION mbi;
    BOOL queried;
    BOOL executable;
    BOOL writable;

    if (Reason != NULL && ReasonChars != 0)
    {
        Reason[0] = L'\0';
    }
    if (MbiOut != NULL)
    {
        ZeroMemory(MbiOut, sizeof(*MbiOut));
    }

    queried = ControllerQueryProcessMemoryBasic(ProcessId, BaseAddress, &mbi);
    if (!queried)
    {
        if (Reason != NULL && ReasonChars != 0)
        {
            (void)StringCchCopyW(Reason, ReasonChars, L"unmapped function-table base");
        }
        return TRUE;
    }

    if (MbiOut != NULL)
    {
        *MbiOut = mbi;
    }

    executable = ControllerProtectAllowsExecute((UINT32)mbi.Protect);
    writable = ControllerProtectAllowsWrite((UINT32)mbi.Protect);
    if (mbi.State != MEM_COMMIT)
    {
        if (Reason != NULL && ReasonChars != 0)
        {
            (void)StringCchPrintfW(Reason, ReasonChars, L"function-table base is not committed state=0x%lX",
                                   (unsigned long)mbi.State);
        }
        return TRUE;
    }
    if (executable && writable)
    {
        if (Reason != NULL && ReasonChars != 0)
        {
            (void)StringCchPrintfW(Reason, ReasonChars, L"function-table base is writable executable protect=0x%lX",
                                   (unsigned long)mbi.Protect);
        }
        return TRUE;
    }
    if (mbi.Type == MEM_PRIVATE && executable)
    {
        if (Reason != NULL && ReasonChars != 0)
        {
            (void)StringCchPrintfW(Reason, ReasonChars, L"function-table base is private executable protect=0x%lX",
                                   (unsigned long)mbi.Protect);
        }
        return TRUE;
    }

    return FALSE;
}

static BOOL ControllerFindModuleForAddress(_In_ DWORD ProcessId, _In_ UINT64 Address, _Out_ MODULEENTRY32W *Module)
{
    HANDLE snapshot;
    MODULEENTRY32W entry;

    if (ProcessId == 0 || Address == 0 || Module == NULL)
    {
        return FALSE;
    }

    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, ProcessId);
    if (snapshot == INVALID_HANDLE_VALUE)
    {
        return FALSE;
    }

    ZeroMemory(&entry, sizeof(entry));
    entry.dwSize = sizeof(entry);
    if (!Module32FirstW(snapshot, &entry))
    {
        CloseHandle(snapshot);
        return FALSE;
    }

    do
    {
        UINT64 base = (UINT64)(ULONG_PTR)entry.modBaseAddr;
        UINT64 end = base + entry.modBaseSize;
        if (Address >= base && Address < end)
        {
            *Module = entry;
            CloseHandle(snapshot);
            return TRUE;
        }
    } while (Module32NextW(snapshot, &entry));

    CloseHandle(snapshot);
    return FALSE;
}

static BOOL ControllerReadRemoteExact(_In_ HANDLE Process, _In_ UINT64 Address, _Out_writes_bytes_(Size) PVOID Buffer,
                                      _In_ SIZE_T Size)
{
    SIZE_T bytesRead = 0;
    return Process != NULL && Process != INVALID_HANDLE_VALUE && Address != 0 && Buffer != NULL && Size != 0 &&
           ReadProcessMemory(Process, (LPCVOID)(ULONG_PTR)Address, Buffer, Size, &bytesRead) && bytesRead == Size;
}

static BOOL ControllerClassifyImageTamperTarget(_In_ DWORD ProcessId, _In_ UINT64 Address, _In_ UINT64 Size,
                                                _Out_ CONTROLLER_IMAGE_TAMPER_CLASSIFICATION *Out)
{
    HANDLE process;
    MODULEENTRY32W module;
    IMAGE_DOS_HEADER dos;
    DWORD signature = 0;
    IMAGE_FILE_HEADER fileHeader;
    WORD optionalMagic = 0;
    IMAGE_DATA_DIRECTORY directories[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
    UINT64 moduleBase;
    UINT32 rva;
    UINT32 span;
    BOOL isNtdll;

    if (Out == NULL)
    {
        return FALSE;
    }

    ZeroMemory(Out, sizeof(*Out));
    Out->Kind = ControllerImageTamperNone;

    if (ProcessId == 0 || Address == 0 || !ControllerFindModuleForAddress(ProcessId, Address, &module))
    {
        return FALSE;
    }

    moduleBase = (UINT64)(ULONG_PTR)module.modBaseAddr;
    if (Address < moduleBase || Address - moduleBase > 0xFFFFFFFFull)
    {
        return FALSE;
    }

    rva = (UINT32)(Address - moduleBase);
    span = (Size == 0 || Size > 0xFFFFFFFFull) ? 1u : (UINT32)Size;
    isNtdll = (_wcsicmp(module.szModule, L"ntdll.dll") == 0);

    process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, ProcessId);
    if (process == NULL)
    {
        return FALSE;
    }

    ZeroMemory(directories, sizeof(directories));
    if (!ControllerReadRemoteExact(process, moduleBase, &dos, sizeof(dos)) || dos.e_magic != IMAGE_DOS_SIGNATURE ||
        dos.e_lfanew <= 0 || dos.e_lfanew > 0x100000)
    {
        CloseHandle(process);
        return FALSE;
    }

    UINT64 ntBase = moduleBase + (UINT64)dos.e_lfanew;
    if (!ControllerReadRemoteExact(process, ntBase, &signature, sizeof(signature)) || signature != IMAGE_NT_SIGNATURE ||
        !ControllerReadRemoteExact(process, ntBase + sizeof(signature), &fileHeader, sizeof(fileHeader)) ||
        !ControllerReadRemoteExact(process, ntBase + sizeof(signature) + sizeof(fileHeader), &optionalMagic,
                                   sizeof(optionalMagic)))
    {
        CloseHandle(process);
        return FALSE;
    }

    UINT64 optionalBase = ntBase + sizeof(signature) + sizeof(fileHeader);
    if (optionalMagic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        IMAGE_OPTIONAL_HEADER64 optionalHeader;
        if (!ControllerReadRemoteExact(process, optionalBase, &optionalHeader, sizeof(optionalHeader)))
        {
            CloseHandle(process);
            return FALSE;
        }
        CopyMemory(directories, optionalHeader.DataDirectory, sizeof(directories));
    }
    else if (optionalMagic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
    {
        IMAGE_OPTIONAL_HEADER32 optionalHeader;
        if (!ControllerReadRemoteExact(process, optionalBase, &optionalHeader, sizeof(optionalHeader)))
        {
            CloseHandle(process);
            return FALSE;
        }
        CopyMemory(directories, optionalHeader.DataDirectory, sizeof(directories));
    }
    else
    {
        CloseHandle(process);
        return FALSE;
    }

    CloseHandle(process);

    Out->ModuleBase = moduleBase;
    Out->Rva = rva;
    (void)StringCchCopyW(Out->ModulePath, RTL_NUMBER_OF(Out->ModulePath), module.szExePath);
    WideCharToMultiByte(CP_ACP, 0, module.szModule, -1, Out->ModuleName, RTL_NUMBER_OF(Out->ModuleName), NULL, NULL);

    const IMAGE_DATA_DIRECTORY &iat = directories[IMAGE_DIRECTORY_ENTRY_IAT];
    if (iat.VirtualAddress != 0 && iat.Size != 0 && ControllerRangeOverlaps32(rva, span, iat.VirtualAddress, iat.Size))
    {
        Out->Kind = ControllerImageTamperIat;
        Out->DirectoryRva = iat.VirtualAddress;
        Out->DirectorySize = iat.Size;
        return TRUE;
    }

    const IMAGE_DATA_DIRECTORY &exports = directories[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exports.VirtualAddress != 0 && exports.Size != 0 &&
        ControllerRangeOverlaps32(rva, span, exports.VirtualAddress, exports.Size))
    {
        Out->Kind = ControllerImageTamperEat;
        Out->DirectoryRva = exports.VirtualAddress;
        Out->DirectorySize = exports.Size;
        return TRUE;
    }

    if (isNtdll)
    {
        Out->Kind = ControllerImageTamperNtdll;
        return TRUE;
    }

    return FALSE;
}

static BOOL ControllerApplyImageTamperDetection(_Inout_ BKIPC_ETW_EVENT *Mapped,
                                                _In_ const CONTROLLER_IMAGE_TAMPER_CLASSIFICATION *Classification,
                                                _In_z_ PCWSTR Action, _In_ UINT64 Address, _In_ UINT64 Size)
{
    PCSTR detectionName;

    if (Mapped == NULL || Classification == NULL || Classification->Kind == ControllerImageTamperNone)
    {
        return FALSE;
    }

    detectionName = ControllerImageTamperDetectionName(Classification->Kind);
    if (detectionName == NULL)
    {
        return FALSE;
    }

    (void)StringCchCopyA(Mapped->DetectionName, RTL_NUMBER_OF(Mapped->DetectionName), detectionName);
    Mapped->Severity = (Classification->Kind == ControllerImageTamperNtdll) ? 7u : 8u;
    (void)StringCchPrintfW(
        Mapped->Reason, RTL_NUMBER_OF(Mapped->Reason),
        L"%ws tamper action=%ws module=%S base=0x%llX rva=0x%X size=0x%llX dirRva=0x%X dirSize=0x%X path=%ws",
        ControllerImageTamperKindLabel(Classification->Kind), Action,
        Classification->ModuleName[0] != '\0' ? Classification->ModuleName : "<unknown>", (unsigned long long)Address,
        Classification->Rva, (unsigned long long)Size, Classification->DirectoryRva, Classification->DirectorySize,
        Classification->ModulePath[0] != L'\0' ? Classification->ModulePath : L"<unknown>");
    return TRUE;
}

static BOOL ControllerValidatePacket(_In_ const BKIPC_PACKET *Packet, _In_ UINT16 ExpectedType)
{
    if (Packet == NULL)
    {
        return FALSE;
    }

    if (Packet->Magic != BKIPC_MAGIC)
    {
        return FALSE;
    }

    if (Packet->Version != BKIPC_VERSION)
    {
        return FALSE;
    }

    if (Packet->PacketType != ExpectedType)
    {
        return FALSE;
    }

    return TRUE;
}

static VOID ControllerPrepareResponse(_In_ const BKIPC_PACKET *Request, _Out_ BKIPC_PACKET *Response)
{
    ZeroMemory(Response, sizeof(*Response));
    Response->Magic = BKIPC_MAGIC;
    Response->Version = BKIPC_VERSION;
    Response->PacketType = BlackbirdIpcPacketResponse;
    Response->Command = Request->Command;
    Response->Sequence = Request->Sequence;
    Response->Status = ERROR_SUCCESS;
}

static BOOL ControllerCommandAllowedForRole(_In_ DWORD ClientRole, _In_ UINT32 Command)
{
    switch (ClientRole)
    {
    case BkctlrClientRoleHook:
        return (Command == BlackbirdIpcCommandHandshake || Command == BlackbirdIpcCommandPublishHookEvent ||
                Command == BlackbirdIpcCommandNotifyHookReady ||
                Command == BlackbirdIpcCommandRegisterInstrumentationRange ||
                Command == BlackbirdIpcCommandRegisterHookPatch);
    case BkctlrClientRoleControl:
        return (Command != BlackbirdIpcCommandPublishHookEvent && Command != BlackbirdIpcCommandNotifyHookReady &&
                Command != BlackbirdIpcCommandRegisterInstrumentationRange &&
                Command != BlackbirdIpcCommandRegisterHookPatch);
    default:
        return FALSE;
    }
}

_Success_(return) static BOOL
    ControllerQueryProcessTokenUser(_In_ DWORD ProcessId,
                                    _Outptr_result_bytebuffer_(*TokenBytesOut) PTOKEN_USER *TokenUserOut,
                                    _Out_ DWORD *TokenBytesOut)
{
    HANDLE process = NULL;
    HANDLE token = NULL;
    DWORD tokenBytes = 0;
    PTOKEN_USER tokenUser = NULL;

    if (ProcessId == 0 || TokenUserOut == NULL || TokenBytesOut == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    *TokenUserOut = NULL;
    *TokenBytesOut = 0;
    process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, ProcessId);
    if (process == NULL)
    {
        return FALSE;
    }

    if (!OpenProcessToken(process, TOKEN_QUERY, &token))
    {
        DWORD err = GetLastError();
        CloseHandle(process);
        SetLastError(err);
        return FALSE;
    }

    (void)GetTokenInformation(token, TokenUser, NULL, 0, &tokenBytes);
    if (tokenBytes == 0 || GetLastError() != ERROR_INSUFFICIENT_BUFFER)
    {
        DWORD err = GetLastError();
        CloseHandle(token);
        CloseHandle(process);
        SetLastError(err == ERROR_SUCCESS ? ERROR_BAD_LENGTH : err);
        return FALSE;
    }

    tokenUser = (PTOKEN_USER)calloc(1, tokenBytes);
    if (tokenUser == NULL)
    {
        CloseHandle(token);
        CloseHandle(process);
        SetLastError(ERROR_OUTOFMEMORY);
        return FALSE;
    }

    if (!GetTokenInformation(token, TokenUser, tokenUser, tokenBytes, &tokenBytes))
    {
        DWORD err = GetLastError();
        free(tokenUser);
        CloseHandle(token);
        CloseHandle(process);
        SetLastError(err);
        return FALSE;
    }

    CloseHandle(token);
    CloseHandle(process);
    *TokenUserOut = tokenUser;
    *TokenBytesOut = tokenBytes;
    return TRUE;
}

_Success_(return) static BOOL
    ControllerProcessesShareOwnerSid(_In_ DWORD ProcessIdA, _In_ DWORD ProcessIdB, _Out_ BOOL *SameOwner)
{
    PTOKEN_USER tokenUserA = NULL;
    PTOKEN_USER tokenUserB = NULL;
    DWORD tokenUserABytes = 0;
    DWORD tokenUserBBytes = 0;

    if (SameOwner == NULL || ProcessIdA == 0 || ProcessIdB == 0)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    *SameOwner = FALSE;
    if (!ControllerQueryProcessTokenUser(ProcessIdA, &tokenUserA, &tokenUserABytes))
    {
        return FALSE;
    }

    if (!ControllerQueryProcessTokenUser(ProcessIdB, &tokenUserB, &tokenUserBBytes))
    {
        DWORD err = GetLastError();
        free(tokenUserA);
        SetLastError(err);
        return FALSE;
    }

    *SameOwner = EqualSid(tokenUserA->User.Sid, tokenUserB->User.Sid) ? TRUE : FALSE;
    free(tokenUserA);
    free(tokenUserB);
    return TRUE;
}

static BOOL ControllerClientCanMonitorPid(_In_ const BK_CONTROLLER_CLIENT *Client, _In_ DWORD TargetPid,
                                          _Inout_opt_ BOOL *PrivilegeResolved, _Inout_opt_ BOOL *IsPrivileged)
{
    BOOL privileged = FALSE;
    DWORD targetSessionId = 0;
    BOOL sameOwner = FALSE;

    if (Client == NULL || TargetPid == 0 || Client->ProcessId == 0)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    if (TargetPid == Client->ProcessId)
    {
        return TRUE;
    }

    if (PrivilegeResolved != NULL && IsPrivileged != NULL && *PrivilegeResolved)
    {
        privileged = *IsPrivileged;
    }
    else
    {
        if (!ControllerClientIsPrivileged(Client, &privileged))
        {
            DWORD err = GetLastError();
            if (err == ERROR_NO_IMPERSONATION_TOKEN)
            {
                privileged = TRUE;
            }
            else
            {
                return FALSE;
            }
        }
        if (PrivilegeResolved != NULL)
        {
            *PrivilegeResolved = TRUE;
        }
        if (IsPrivileged != NULL)
        {
            *IsPrivileged = privileged;
        }
    }

    if (privileged)
    {
        return TRUE;
    }

    if (!ProcessIdToSessionId(TargetPid, &targetSessionId))
    {
        return FALSE;
    }
    if (targetSessionId != Client->SessionId)
    {
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }

    if (!ControllerProcessesShareOwnerSid(Client->ProcessId, TargetPid, &sameOwner))
    {
        return FALSE;
    }
    if (!sameOwner)
    {
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }

    return TRUE;
}

static DWORD ControllerClientSubscribe(_Inout_ BK_CONTROLLER_CLIENT *Client, _In_ const BK_SUBSCRIBE_REQUEST *Request)
{
    DWORD i;

    if (Client == NULL || Request == NULL || Request->ProcessId == 0 ||
        !ControllerIsValidStreamMask(Request->StreamMask))
    {
        return ERROR_INVALID_PARAMETER;
    }
    if (!ControllerClientCanMonitorPid(Client, Request->ProcessId, NULL, NULL))
    {
        DWORD err = GetLastError();
        return (err == ERROR_SUCCESS) ? ERROR_ACCESS_DENIED : err;
    }

    EnterCriticalSection(&Client->Lock);
    for (i = 0; i < Client->SubscriptionCount; ++i)
    {
        if (Client->Subscriptions[i].ProcessId == Request->ProcessId)
        {
            Client->Subscriptions[i].StreamMask |= Request->StreamMask;
            if (Client->Subscriptions[i].Dynamic)
            {
                Client->Subscriptions[i].Dynamic = FALSE;
                Client->Subscriptions[i].SourceProcessId = 0;
                Client->Subscriptions[i].Depth = 0;
                Client->Subscriptions[i].LastSeenTick = 0;
            }
            LeaveCriticalSection(&Client->Lock);
            ControllerLog("[IPC] subscribe update clientPid=%lu targetPid=%lu streamMask=0x%08lX\n", Client->ProcessId,
                          Request->ProcessId, Request->StreamMask);
            if (!ControllerRequestDriverSubscriptionApply(TRUE, BK_CONTROLLER_SUBSCRIPTION_APPLY_SYNC_TIMEOUT_MS))
            {
                return GetLastError();
            }
            return ERROR_SUCCESS;
        }
    }

    if (Client->SubscriptionCount >= BK_CONTROLLER_MAX_CLIENT_SUBSCRIPTIONS)
    {
        LeaveCriticalSection(&Client->Lock);
        return ERROR_INSUFFICIENT_BUFFER;
    }

    Client->Subscriptions[Client->SubscriptionCount].ProcessId = Request->ProcessId;
    Client->Subscriptions[Client->SubscriptionCount].StreamMask = Request->StreamMask;
    Client->Subscriptions[Client->SubscriptionCount].Dynamic = FALSE;
    Client->Subscriptions[Client->SubscriptionCount].SourceProcessId = 0;
    Client->Subscriptions[Client->SubscriptionCount].Depth = 0;
    Client->Subscriptions[Client->SubscriptionCount].LastSeenTick = 0;
    Client->SubscriptionCount += 1;
    LeaveCriticalSection(&Client->Lock);
    ControllerLog("[IPC] subscribe add clientPid=%lu targetPid=%lu streamMask=0x%08lX\n", Client->ProcessId,
                  Request->ProcessId, Request->StreamMask);

    if (!ControllerRequestDriverSubscriptionApply(TRUE, BK_CONTROLLER_SUBSCRIPTION_APPLY_SYNC_TIMEOUT_MS))
    {
        return GetLastError();
    }

    return ERROR_SUCCESS;
}

static DWORD ControllerClientUnsubscribe(_Inout_ BK_CONTROLLER_CLIENT *Client,
                                         _In_ const BK_UNSUBSCRIBE_REQUEST *Request)
{
    DWORD i;
    DWORD removedPid = 0;
    BOOL changed = FALSE;

    if (Client == NULL || Request == NULL || Request->ProcessId == 0)
    {
        return ERROR_INVALID_PARAMETER;
    }

    EnterCriticalSection(&Client->Lock);
    for (i = 0; i < Client->SubscriptionCount; ++i)
    {
        if (Client->Subscriptions[i].ProcessId == Request->ProcessId)
        {
            removedPid = Client->Subscriptions[i].ProcessId;
            ControllerRemoveSubscriptionAtLocked(Client, i);
            changed = TRUE;
            if (removedPid != 0)
            {
                changed |= ControllerDropDynamicDescendantsLocked(Client, removedPid);
            }
            LeaveCriticalSection(&Client->Lock);
            ControllerLog("[IPC] unsubscribe clientPid=%lu targetPid=%lu\n", Client->ProcessId, Request->ProcessId);
            if (changed)
            {
                (void)ControllerRequestDriverSubscriptionApply(FALSE, 0);
            }
            return ERROR_SUCCESS;
        }
    }
    LeaveCriticalSection(&Client->Lock);

    return ERROR_NOT_FOUND;
}

static DWORD ControllerClientSetPids(_Inout_ BK_CONTROLLER_CLIENT *Client, _In_ const BK_SET_PIDS_REQUEST *Request)
{
    DWORD i;
    DWORD primaryPid = 0;
    DWORD appliedCount = 0;
    DWORD replacedLaunchOwnedRootPid = 0;
    ULONGLONG sessionId = 0;
    BOOL privilegeResolved = FALSE;
    BOOL isPrivileged = FALSE;
    BK_CONTROLLER_ANALYSIS_TEARDOWN teardown;

    if (Client == NULL || Request == NULL || Request->ProcessCount > BK_MAX_PID_LIST ||
        !ControllerIsValidStreamMask(Request->StreamMask))
    {
        return ERROR_INVALID_PARAMETER;
    }

    if (Request->ProcessCount == 0)
    {
        EnterCriticalSection(&Client->Lock);
        ControllerClientStopAnalysisLocked(Client, &teardown);
        LeaveCriticalSection(&Client->Lock);

        ControllerCompleteAnalysisTeardown(Client, &teardown, "set-pids-empty");
        if (teardown.HadAnalysisLease || teardown.SubscriptionCount != 0)
        {
            (void)ControllerRequestDriverSubscriptionApply(FALSE, 0);
        }
        ControllerTerminateLaunchOwnedTeardown(&teardown, "set-pids-empty");
        return ERROR_SUCCESS;
    }

    for (i = 0; i < Request->ProcessCount; ++i)
    {
        DWORD pid = Request->ProcessIds[i];
        if (pid == 0)
        {
            continue;
        }
        if (primaryPid == 0)
        {
            primaryPid = pid;
        }

        if (!ControllerClientCanMonitorPid(Client, pid, &privilegeResolved, &isPrivileged))
        {
            DWORD err = GetLastError();
            return (err == ERROR_SUCCESS) ? ERROR_ACCESS_DENIED : err;
        }
    }

    if (primaryPid == 0)
    {
        return ERROR_INVALID_PARAMETER;
    }

    EnterCriticalSection(&Client->Lock);
    if (Client->AnalysisActive && Client->AnalysisLaunchOwned && Client->AnalysisRootProcessId != 0 &&
        Client->AnalysisRootProcessId != primaryPid)
    {
        replacedLaunchOwnedRootPid = Client->AnalysisRootProcessId;
    }
    Client->SubscriptionCount = 0;
    ZeroMemory(Client->Subscriptions, sizeof(Client->Subscriptions));
    for (i = 0; i < Request->ProcessCount; ++i)
    {
        DWORD pid = Request->ProcessIds[i];
        DWORD j;
        BOOL seen = FALSE;

        if (pid == 0)
        {
            continue;
        }

        for (j = 0; j < Client->SubscriptionCount; ++j)
        {
            if (Client->Subscriptions[j].ProcessId == pid)
            {
                Client->Subscriptions[j].StreamMask |= Request->StreamMask;
                Client->Subscriptions[j].Dynamic = FALSE;
                Client->Subscriptions[j].SourceProcessId = 0;
                Client->Subscriptions[j].Depth = 0;
                Client->Subscriptions[j].LastSeenTick = 0;
                seen = TRUE;
                break;
            }
        }

        if (!seen && Client->SubscriptionCount < BK_CONTROLLER_MAX_CLIENT_SUBSCRIPTIONS)
        {
            Client->Subscriptions[Client->SubscriptionCount].ProcessId = pid;
            Client->Subscriptions[Client->SubscriptionCount].StreamMask = Request->StreamMask;
            Client->Subscriptions[Client->SubscriptionCount].Dynamic = FALSE;
            Client->Subscriptions[Client->SubscriptionCount].SourceProcessId = 0;
            Client->Subscriptions[Client->SubscriptionCount].Depth = 0;
            Client->Subscriptions[Client->SubscriptionCount].LastSeenTick = 0;
            Client->SubscriptionCount += 1;
        }
    }
    appliedCount = Client->SubscriptionCount;
    if (appliedCount != 0 && (Client->AnalysisActive || Client->AnalysisRootProcessId != 0 ||
                              Client->AnalysisSessionId != 0 || Client->AnalysisLaunchOwned ||
                              Client->PendingLaunchPid != 0))
    {
        sessionId = ControllerClientBeginAnalysisSessionLocked(Client, primaryPid, FALSE);
    }
    LeaveCriticalSection(&Client->Lock);

    if (appliedCount == 0)
    {
        return ERROR_INVALID_PARAMETER;
    }
    ControllerLog("[IPC] set-pids clientPid=%lu sessionId=%llu rootPid=%lu count=%lu streamMask=0x%08lX\n",
                  Client->ProcessId, (unsigned long long)sessionId, primaryPid, appliedCount, Request->StreamMask);

    if (!ControllerRequestDriverSubscriptionApply(TRUE, BK_CONTROLLER_SUBSCRIPTION_APPLY_SYNC_TIMEOUT_MS))
    {
        DWORD applyErr = GetLastError();
        if (replacedLaunchOwnedRootPid != 0)
        {
            ControllerInjectionTerminateProcessTreeBestEffort(replacedLaunchOwnedRootPid, "analysis-replaced");
        }
        return applyErr;
    }
    if (replacedLaunchOwnedRootPid != 0)
    {
        ControllerInjectionTerminateProcessTreeBestEffort(replacedLaunchOwnedRootPid, "analysis-replaced");
    }

    return ERROR_SUCCESS;
}

static DWORD ControllerClientGetEvent(_Inout_ BK_CONTROLLER_CLIENT *Client, _In_ DWORD TimeoutMs,
                                      _Out_ BK_EVENT_RECORD *Record)
{
    ULONGLONG startTick;

    if (Client == NULL || Record == NULL)
    {
        return ERROR_INVALID_PARAMETER;
    }

    startTick = GetTickCount64();
    for (;;)
    {
        BOOL dequeued = FALSE;
        HANDLE dataEvent = NULL;
        HANDLE waitHandles[2];
        DWORD waitCount = 0;
        DWORD waitMs = INFINITE;
        DWORD waitResult;
        ULONGLONG elapsed = 0;

        EnterCriticalSection(&Client->Lock);
        if (Client->SharedRingEnabled && Client->IoctlSharedDataEvent != NULL &&
            Client->IoctlSharedDataEvent != INVALID_HANDLE_VALUE)
        {
            dataEvent = Client->IoctlSharedDataEvent;
        }
        else
        {
            dataEvent = Client->IoctlQueueDataEvent;
        }
        dequeued = ControllerClientDequeueRecordLocked(Client, Record);
        LeaveCriticalSection(&Client->Lock);

        if (dequeued)
        {
            return ERROR_SUCCESS;
        }
        if (ControllerShouldStop())
        {
            return ERROR_OPERATION_ABORTED;
        }
        if (TimeoutMs != INFINITE)
        {
            elapsed = GetTickCount64() - startTick;
            if (elapsed >= TimeoutMs)
            {
                return ERROR_NO_MORE_ITEMS;
            }
            waitMs = (DWORD)((ULONGLONG)TimeoutMs - elapsed);
        }

        if (g_StopEvent != NULL)
        {
            waitHandles[waitCount++] = g_StopEvent;
        }
        if (dataEvent != NULL && dataEvent != INVALID_HANDLE_VALUE)
        {
            waitHandles[waitCount++] = dataEvent;
        }
        if (waitCount == 0)
        {
            if (waitMs == 0)
            {
                return ERROR_NO_MORE_ITEMS;
            }
            Sleep((waitMs == INFINITE || waitMs > 2u) ? 2u : waitMs);
            continue;
        }

        waitResult = WaitForMultipleObjects(waitCount, waitHandles, FALSE, waitMs);
        if (waitResult == WAIT_OBJECT_0 && g_StopEvent != NULL)
        {
            return ERROR_OPERATION_ABORTED;
        }
        if (waitResult == WAIT_TIMEOUT)
        {
            if (TimeoutMs != INFINITE)
            {
                return ERROR_NO_MORE_ITEMS;
            }
            continue;
        }
        if (waitResult == WAIT_FAILED)
        {
            DWORD err = GetLastError();
            return (err == ERROR_SUCCESS) ? ERROR_GEN_FAILURE : err;
        }
    }
}

static DWORD ControllerClientGetEtwEvent(_Inout_ BK_CONTROLLER_CLIENT *Client, _In_ DWORD TimeoutMs,
                                         _Out_ BKIPC_ETW_EVENT *Event)
{
    ULONGLONG startTick;

    if (Client == NULL || Event == NULL)
    {
        return ERROR_INVALID_PARAMETER;
    }

    startTick = GetTickCount64();
    for (;;)
    {
        BOOL dequeued = FALSE;
        HANDLE dataEvent = NULL;
        HANDLE waitHandles[2];
        DWORD waitCount = 0;
        DWORD waitMs = INFINITE;
        DWORD waitResult;
        ULONGLONG elapsed = 0;

        EnterCriticalSection(&Client->Lock);
        if (Client->SharedRingEnabled && Client->EtwSharedDataEvent != NULL &&
            Client->EtwSharedDataEvent != INVALID_HANDLE_VALUE)
        {
            dataEvent = Client->EtwSharedDataEvent;
        }
        else
        {
            dataEvent = Client->EtwQueueDataEvent;
        }
        dequeued = ControllerClientDequeueEtwEventLocked(Client, Event);
        LeaveCriticalSection(&Client->Lock);

        if (dequeued)
        {
            return ERROR_SUCCESS;
        }
        if (ControllerShouldStop())
        {
            return ERROR_OPERATION_ABORTED;
        }
        if (TimeoutMs != INFINITE)
        {
            elapsed = GetTickCount64() - startTick;
            if (elapsed >= TimeoutMs)
            {
                return ERROR_NO_MORE_ITEMS;
            }
            waitMs = (DWORD)((ULONGLONG)TimeoutMs - elapsed);
        }

        if (g_StopEvent != NULL)
        {
            waitHandles[waitCount++] = g_StopEvent;
        }
        if (dataEvent != NULL && dataEvent != INVALID_HANDLE_VALUE)
        {
            waitHandles[waitCount++] = dataEvent;
        }
        if (waitCount == 0)
        {
            if (waitMs == 0)
            {
                return ERROR_NO_MORE_ITEMS;
            }
            Sleep((waitMs == INFINITE || waitMs > 2u) ? 2u : waitMs);
            continue;
        }

        waitResult = WaitForMultipleObjects(waitCount, waitHandles, FALSE, waitMs);
        if (waitResult == WAIT_OBJECT_0 && g_StopEvent != NULL)
        {
            return ERROR_OPERATION_ABORTED;
        }
        if (waitResult == WAIT_TIMEOUT)
        {
            if (TimeoutMs != INFINITE)
            {
                return ERROR_NO_MORE_ITEMS;
            }
            continue;
        }
        if (waitResult == WAIT_FAILED)
        {
            DWORD err = GetLastError();
            return (err == ERROR_SUCCESS) ? ERROR_GEN_FAILURE : err;
        }
    }
}

static DWORD ControllerClientPublishHookEvent(_Inout_ BK_CONTROLLER_CLIENT *Client,
                                              _In_ const BKIPC_HOOK_EVENT *HookEvent)
{
    BKIPC_ETW_EVENT mapped;
    DWORD eventPid = 0;
    DWORD threadId = 0;
    CHAR apiName[BKIPC_MAX_HOOK_API_NAME];
    CHAR moduleName[BKIPC_MAX_HOOK_MODULE_NAME];
    PCSTR kindName;
    int wideChars;
    UINT32 argCount;
    UINT32 sampleSize;
    BOOL integrityTampered = FALSE;
    BOOL integrityAmsiPatch = FALSE;
    BOOL integrityEtwPatch = FALSE;
    BOOL memoryEvent = FALSE;
    BOOL specializedEvent = FALSE;

    if (Client == NULL || HookEvent == NULL)
    {
        return ERROR_INVALID_PARAMETER;
    }

    if (HookEvent->Kind == BlackbirdIpcHookEventUnknown || HookEvent->Kind > BlackbirdIpcHookEventModule)
    {
        return ERROR_INVALID_PARAMETER;
    }

    eventPid = (HookEvent->ProcessId != 0) ? HookEvent->ProcessId : Client->ProcessId;
    if (eventPid == 0)
    {
        return ERROR_INVALID_PARAMETER;
    }

    if (eventPid != Client->ProcessId)
    {
        return ERROR_ACCESS_DENIED;
    }

    threadId = HookEvent->ThreadId;

    ControllerSanitizeAnsiLabel(HookEvent->ApiName, apiName, RTL_NUMBER_OF(apiName));
    ControllerSanitizeAnsiLabel(HookEvent->ModuleName, moduleName, RTL_NUMBER_OF(moduleName));
    kindName = ControllerHookEventKindName(HookEvent->Kind);
    argCount =
        (HookEvent->ArgCount > RTL_NUMBER_OF(HookEvent->Args)) ? RTL_NUMBER_OF(HookEvent->Args) : HookEvent->ArgCount;
    sampleSize = (HookEvent->DataSize > RTL_NUMBER_OF(HookEvent->DataSample)) ? RTL_NUMBER_OF(HookEvent->DataSample)
                                                                              : HookEvent->DataSize;

    ZeroMemory(&mapped, sizeof(mapped));
    mapped.Source = BlackbirdIpcEtwSourceUserHook;
    mapped.Family = BlackbirdIpcEtwFamilyUserHook;
    mapped.EventId = (UINT16)(HookEvent->Operation & 0xFFFFu);
    mapped.Opcode = (UINT16)(HookEvent->Kind & 0xFFFFu);
    mapped.Task = 0;
    mapped.EventProcessId = eventPid;
    mapped.EventThreadId = threadId;
    mapped.Severity = 1;
    mapped.Flags = 0;
    mapped.ProcessId = eventPid;
    mapped.ThreadId = threadId;
    mapped.CallerPid = eventPid;
    mapped.TargetPid = (HookEvent->Context0 <= 0xFFFFFFFFull) ? HookEvent->Context0 : 0;

    if (HookEvent->Kind == BlackbirdIpcHookEventIntegrity)
    {
        integrityAmsiPatch = (HookEvent->Operation == BK_HOOK_EVENT_OP_AMSI_PATCH);
        integrityEtwPatch = (HookEvent->Operation == BK_HOOK_EVENT_OP_ETW_PATCH);
        if (HookEvent->Operation == BK_HOOK_EVENT_OP_LAUNCH_GATE_ENTRY ||
            HookEvent->Operation == BK_HOOK_EVENT_OP_LAUNCH_GATE_TLS_CALLBACK)
        {
            integrityTampered = FALSE;
            mapped.Severity = 1u;
        }
        else if (integrityAmsiPatch || integrityEtwPatch)
        {
            integrityTampered = (HookEvent->Context0 != 0ull);
            mapped.Severity = integrityTampered ? 8u : 1u;
        }
        else
        {
            integrityTampered = (HookEvent->Context0 != 0ull || HookEvent->Operation != 0u);
            mapped.Severity = integrityTampered ? 7u : 1u;
        }
        mapped.TargetPid = eventPid;
    }

    if (moduleName[0] != '\0')
    {
        (void)StringCchCopyA(mapped.ClassName, RTL_NUMBER_OF(mapped.ClassName), moduleName);
    }
    else
    {
        (void)StringCchCopyA(mapped.ClassName, RTL_NUMBER_OF(mapped.ClassName), kindName);
    }

    if (apiName[0] != '\0')
    {
        (void)StringCchCopyA(mapped.Operation, RTL_NUMBER_OF(mapped.Operation), apiName);
    }
    else
    {
        (void)StringCchPrintfA(mapped.Operation, RTL_NUMBER_OF(mapped.Operation), "%sOp%lu", kindName,
                               (unsigned long)HookEvent->Operation);
    }

    wideChars = MultiByteToWideChar(CP_ACP, 0, (apiName[0] != '\0') ? apiName : mapped.Operation, -1, mapped.EventName,
                                    RTL_NUMBER_OF(mapped.EventName));
    if (wideChars <= 0)
    {
        (void)StringCchPrintfW(mapped.EventName, RTL_NUMBER_OF(mapped.EventName), L"%S", mapped.Operation);
    }

    if (HookEvent->Kind == BlackbirdIpcHookEventIntegrity)
    {
        if (HookEvent->Operation == BK_HOOK_EVENT_OP_LAUNCH_GATE_ENTRY ||
            HookEvent->Operation == BK_HOOK_EVENT_OP_LAUNCH_GATE_TLS_CALLBACK)
        {
            BOOL tlsTrap = HookEvent->Operation == BK_HOOK_EVENT_OP_LAUNCH_GATE_TLS_CALLBACK;
            (void)StringCchCopyA(mapped.DetectionName, RTL_NUMBER_OF(mapped.DetectionName),
                                 tlsTrap ? "BK_TLS_CALLBACK_TRAP" : "BK_LAUNCH_GATE_TRAP");
            (void)StringCchCopyA(mapped.Operation, RTL_NUMBER_OF(mapped.Operation),
                                 tlsTrap ? "TlsCallbackTrap" : "LaunchGateEntryTrap");
            (void)StringCchPrintfW(mapped.EventName, RTL_NUMBER_OF(mapped.EventName), L"%S", mapped.Operation);
            (void)StringCchCopyA(mapped.ClassName, RTL_NUMBER_OF(mapped.ClassName), "BK Instrument");
            (void)StringCchPrintfW(
                mapped.Reason, RTL_NUMBER_OF(mapped.Reason),
                L"BK launch gate trapped %ws before target user code continued address=0x%llX page=0x%llX index=%llu",
                tlsTrap ? L"TLS callback" : L"entry point", (unsigned long long)HookEvent->Context0,
                (unsigned long long)HookEvent->Context1, (unsigned long long)HookEvent->Context3);
        }
        else if (integrityAmsiPatch || integrityEtwPatch)
        {
            PCSTR detectionName = integrityAmsiPatch ? "AMSI_PATCH_TAMPERED" : "ETW_PATCH_TAMPERED";
            PCSTR okDetectionName = integrityAmsiPatch ? "AMSI_PATCH_OK" : "ETW_PATCH_OK";
            PCSTR eventLabel = integrityAmsiPatch ? "AmsiPatchTamper" : "EtwPatchTamper";
            PCSTR okEventLabel = integrityAmsiPatch ? "AmsiPatchOk" : "EtwPatchOk";
            PCWSTR reasonLabel = integrityAmsiPatch ? L"amsi" : L"etw";

            if (integrityTampered)
            {
                (void)StringCchCopyA(mapped.DetectionName, RTL_NUMBER_OF(mapped.DetectionName), detectionName);
                (void)StringCchCopyA(mapped.Operation, RTL_NUMBER_OF(mapped.Operation), eventLabel);
                (void)StringCchPrintfW(mapped.EventName, RTL_NUMBER_OF(mapped.EventName), L"%S", eventLabel);
            }
            else
            {
                (void)StringCchCopyA(mapped.DetectionName, RTL_NUMBER_OF(mapped.DetectionName), okDetectionName);
                (void)StringCchCopyA(mapped.Operation, RTL_NUMBER_OF(mapped.Operation), okEventLabel);
                (void)StringCchPrintfW(mapped.EventName, RTL_NUMBER_OF(mapped.EventName), L"%S", okEventLabel);
            }

            if (moduleName[0] != '\0')
            {
                (void)StringCchCopyA(mapped.ClassName, RTL_NUMBER_OF(mapped.ClassName), moduleName);
            }
            else
            {
                (void)StringCchCopyA(mapped.ClassName, RTL_NUMBER_OF(mapped.ClassName),
                                     integrityAmsiPatch ? "amsi" : "ntdll");
            }

            (void)StringCchPrintfW(mapped.Reason, RTL_NUMBER_OF(mapped.Reason),
                                   L"%ws tamper=%u suspiciousPrologue=%llu imageMismatch=%llu checkCount=%llu",
                                   reasonLabel, integrityTampered ? 1u : 0u, (unsigned long long)HookEvent->Context1,
                                   (unsigned long long)HookEvent->Context2, (unsigned long long)HookEvent->Context3);
        }
        else
        {
            if (integrityTampered)
            {
                (void)StringCchCopyA(mapped.DetectionName, RTL_NUMBER_OF(mapped.DetectionName),
                                     "USERMODE_HOOK_TAMPERED");
                (void)StringCchCopyA(mapped.Operation, RTL_NUMBER_OF(mapped.Operation), "HookIntegrityTamper");
                (void)StringCchCopyW(mapped.EventName, RTL_NUMBER_OF(mapped.EventName), L"HookIntegrityTamper");
            }
            else
            {
                (void)StringCchCopyA(mapped.DetectionName, RTL_NUMBER_OF(mapped.DetectionName),
                                     "USERMODE_HOOK_INTEGRITY_OK");
                (void)StringCchCopyA(mapped.Operation, RTL_NUMBER_OF(mapped.Operation), "HookIntegrityOk");
                (void)StringCchCopyW(mapped.EventName, RTL_NUMBER_OF(mapped.EventName), L"HookIntegrityOk");
            }

            (void)StringCchCopyA(mapped.ClassName, RTL_NUMBER_OF(mapped.ClassName), "SR71");
            (void)StringCchPrintfW(mapped.Reason, RTL_NUMBER_OF(mapped.Reason),
                                   L"hookIntegrity tampered=%u mask=0x%llX winsock=%llu nt=%llu ki=%llu module=%llu",
                                   integrityTampered ? 1u : 0u, (unsigned long long)HookEvent->Context0,
                                   (unsigned long long)HookEvent->Context1, (unsigned long long)HookEvent->Context2,
                                   (unsigned long long)HookEvent->Context3,
                                   (unsigned long long)((argCount > 2u) ? HookEvent->Args[2] : 0ull));
        }
    }
    else
    {
        if (HookEvent->Kind == BlackbirdIpcHookEventNt && (lstrcmpiA(apiName, "NtAllocateVirtualMemory") == 0 ||
                                                           lstrcmpiA(apiName, "NtAllocateVirtualMemoryEx") == 0))
        {
            BOOL isAllocateEx = lstrcmpiA(apiName, "NtAllocateVirtualMemoryEx") == 0;
            /* NtAllocateVirtualMemory:
             *   Args[0]=ProcessHandle, Args[1]=*BaseAddress, Args[2]=ZeroBits,
             * Args[3]=*RegionSize,
             *   Args[4]=AllocationType, Args[5]=Protect, Args[6]=TargetPid.

             * * NtAllocateVirtualMemoryEx:
             *   Args[0]=ProcessHandle, Args[1]=*BaseAddress,
             * Args[2]=*RegionSize,
             *   Args[3]=AllocationType, Args[4]=Protect,
             * Args[5]=ExtendedParameters,
             *   Args[6]=ExtendedParameterCount, Args[7]=TargetPid.
 */
            UINT32 allocType = (argCount > (isAllocateEx ? 3u : 4u))
                                   ? (UINT32)(HookEvent->Args[isAllocateEx ? 3u : 4u] & 0xFFFFFFFFull)
                                   : 0u;
            UINT32 protect = (argCount > (isAllocateEx ? 4u : 5u))
                                 ? (UINT32)(HookEvent->Args[isAllocateEx ? 4u : 5u] & 0xFFFFFFFFull)
                                 : 0u;
            UINT32 targetPid =
                (argCount > (isAllocateEx ? 7u : 6u) && HookEvent->Args[isAllocateEx ? 7u : 6u] <= 0xFFFFFFFFull)
                    ? (UINT32)HookEvent->Args[isAllocateEx ? 7u : 6u]
                    : 0u;
            BOOL remoteAlloc = (targetPid != 0 && targetPid != eventPid);
            if (targetPid == 0)
            {
                remoteAlloc = (HookEvent->Args[0] != (UINT64)(ULONG_PTR)-1) && (HookEvent->Args[0] != 0u);
            }
            BOOL rwxAlloc = (protect & 0x40u) != 0 || (protect & 0x80u) != 0;
            memoryEvent = TRUE;
            if (targetPid != 0 && targetPid != eventPid)
            {
                mapped.TargetPid = targetPid;
            }
            if (remoteAlloc && rwxAlloc)
            {
                (void)StringCchCopyA(mapped.DetectionName, RTL_NUMBER_OF(mapped.DetectionName),
                                     "SUSPICIOUS_RWX_ALLOCATION");
                mapped.Severity = 6u;
            }
            else if (rwxAlloc)
            {
                (void)StringCchCopyA(mapped.DetectionName, RTL_NUMBER_OF(mapped.DetectionName),
                                     "SUSPICIOUS_RWX_ALLOCATION");
                mapped.Severity = 5u;
            }
            else
            {
                (void)StringCchCopyA(mapped.DetectionName, RTL_NUMBER_OF(mapped.DetectionName),
                                     "USERMODE_MEMORY_ACTIVITY");
                mapped.Severity = 2u;
            }
            (void)StringCchPrintfW(
                mapped.Reason, RTL_NUMBER_OF(mapped.Reason),
                L"memory.alloc base=0x%llX size=0x%llX allocType=0x%X allocTypeName=%S protect=0x%X protectName=%S remote=%u targetPid=%lu",
                (unsigned long long)HookEvent->Args[1], (unsigned long long)HookEvent->Args[isAllocateEx ? 2u : 3u],
                allocType, ControllerMemoryAllocTypeName(allocType), protect, ControllerMemoryProtectName(protect),
                (unsigned int)remoteAlloc, (unsigned long)targetPid);
            /* Injection chain stage 2 */
            if (remoteAlloc)
            {
                ControllerInjectionChainObserve((DWORD)eventPid, targetPid, BK_CHAIN_STAGE_ALLOC);
            }
        }
        else if (HookEvent->Kind == BlackbirdIpcHookEventNt && lstrcmpiA(apiName, "NtProtectVirtualMemory") == 0)
        {
            UINT32 newProtect = (UINT32)(HookEvent->Context2 & 0xFFFFFFFFull);
            UINT32 oldProtect = (UINT32)(HookEvent->Context3 & 0xFFFFFFFFull);
            BOOL hasSyscallStubOutsideNtdll = (HookEvent->Args[5] != 0ull);
            BOOL sr71ProtectBlocked = (HookEvent->Args[6] == ControllerSr71ProtectBlockedMarker);
            UINT32 targetPid = (argCount > 7u && HookEvent->Args[7] <= 0xFFFFFFFFull) ? (UINT32)HookEvent->Args[7] : 0u;
            BOOL remoteProtect = (targetPid != 0 && targetPid != eventPid);
            CONTROLLER_IMAGE_TAMPER_CLASSIFICATION imageTamper;
            if (targetPid != 0 && targetPid != eventPid)
            {
                mapped.TargetPid = targetPid;
            }
            ZeroMemory(&imageTamper, sizeof(imageTamper));
            if (sr71ProtectBlocked)
            {
                (void)StringCchCopyA(mapped.DetectionName, RTL_NUMBER_OF(mapped.DetectionName),
                                     "SR71_HOOK_PROTECT_BLOCKED");
                mapped.Severity = 8u;
                specializedEvent = TRUE;
            }
            else if (ControllerProtectAllowsWrite(newProtect) &&
                     ControllerClassifyImageTamperTarget((targetPid != 0) ? targetPid : eventPid, HookEvent->Context0,
                                                         HookEvent->Context1, &imageTamper) &&
                     ControllerApplyImageTamperDetection(&mapped, &imageTamper, L"protect-write-enable",
                                                         HookEvent->Context0, HookEvent->Context1))
            {
                specializedEvent = TRUE;
            }
            else if (hasSyscallStubOutsideNtdll)
            {
                (void)StringCchCopyA(mapped.DetectionName, RTL_NUMBER_OF(mapped.DetectionName),
                                     "USERMODE_SUSPICIOUS_SYSCALL_STUB");
                mapped.Severity = 7u;
            }
            else
            {
                (void)StringCchCopyA(mapped.DetectionName, RTL_NUMBER_OF(mapped.DetectionName),
                                     "USERMODE_MEMORY_ACTIVITY");
                mapped.Severity = (remoteProtect && (newProtect & 0xF0u) != 0u) ? 5u : 3u;
            }
            memoryEvent = TRUE;
            if (sr71ProtectBlocked)
            {
                (void)StringCchPrintfW(
                    mapped.Reason, RTL_NUMBER_OF(mapped.Reason),
                    L"blocked SR71 hook protection change base=0x%llX size=0x%llX oldProtect=0x%X newProtect=0x%X targetPid=%lu",
                    (unsigned long long)HookEvent->Context0, (unsigned long long)HookEvent->Context1, oldProtect,
                    newProtect, (unsigned long)targetPid);
            }
            else if (imageTamper.Kind == ControllerImageTamperNone)
            {
                (void)StringCchPrintfW(
                    mapped.Reason, RTL_NUMBER_OF(mapped.Reason),
                    L"memory.protect base=0x%llX size=0x%llX oldProtect=0x%X oldProtectName=%S newProtect=0x%X newProtectName=%S remote=%u syscallStubOutsideNtdll=%u sampleBytes=%lu sampleBase=0x%llX targetPid=%lu",
                    (unsigned long long)HookEvent->Context0, (unsigned long long)HookEvent->Context1, oldProtect,
                    ControllerMemoryProtectName(oldProtect), newProtect, ControllerMemoryProtectName(newProtect),
                    (unsigned int)remoteProtect, (unsigned int)hasSyscallStubOutsideNtdll, (unsigned long)sampleSize,
                    (unsigned long long)HookEvent->Args[6], (unsigned long)targetPid);
            }
        }
        else if (HookEvent->Kind == BlackbirdIpcHookEventNt && lstrcmpiA(apiName, "NtWriteVirtualMemory") == 0)
        {
            UINT32 targetPid = (argCount > 5u && HookEvent->Args[5] <= 0xFFFFFFFFull) ? (UINT32)HookEvent->Args[5] : 0u;
            BOOL remoteWrite = (targetPid != 0 && targetPid != eventPid);
            BOOL mzHeader =
                (sampleSize >= 2u && HookEvent->DataSample[0] == 0x4Du && HookEvent->DataSample[1] == 0x5Au);
            BOOL sr71WriteBlocked = (HookEvent->Args[6] == ControllerSr71WriteBlockedMarker);
            double entropy = (HookEvent->Args[7] != 0ull)
                                 ? ((double)HookEvent->Args[7] / 1000.0)
                                 : ControllerComputeSampleEntropy(HookEvent->DataSample, sampleSize);
            CONTROLLER_IMAGE_TAMPER_CLASSIFICATION imageTamper;
            ZeroMemory(&imageTamper, sizeof(imageTamper));
            if (sr71WriteBlocked)
            {
                (void)StringCchCopyA(mapped.DetectionName, RTL_NUMBER_OF(mapped.DetectionName),
                                     "SR71_HOOK_WRITE_BLOCKED");
                mapped.Severity = 8u;
                specializedEvent = TRUE;
            }
            else if (ControllerClassifyImageTamperTarget((targetPid != 0) ? targetPid : eventPid, HookEvent->Context0,
                                                         HookEvent->Context1, &imageTamper) &&
                     ControllerApplyImageTamperDetection(&mapped, &imageTamper, L"write", HookEvent->Context0,
                                                         HookEvent->Context1))
            {
                specializedEvent = TRUE;
            }
            else
            {
                (void)StringCchCopyA(mapped.DetectionName, RTL_NUMBER_OF(mapped.DetectionName),
                                     "USERMODE_MEMORY_ACTIVITY");
                mapped.Severity = (remoteWrite && mzHeader) ? 7u : (remoteWrite ? 4u : 3u);
            }
            memoryEvent = TRUE;
            if (targetPid != 0 && targetPid != eventPid)
            {
                mapped.TargetPid = targetPid;
            }
            if (sr71WriteBlocked)
            {
                (void)StringCchPrintfW(
                    mapped.Reason, RTL_NUMBER_OF(mapped.Reason),
                    L"blocked SR71 hook write base=0x%llX size=0x%llX remote=%u sampleBytes=%lu targetPid=%lu",
                    (unsigned long long)HookEvent->Context0, (unsigned long long)HookEvent->Context1,
                    (unsigned int)remoteWrite, (unsigned long)sampleSize, (unsigned long)targetPid);
            }
            else if (imageTamper.Kind == ControllerImageTamperNone)
            {
                (void)StringCchPrintfW(
                    mapped.Reason, RTL_NUMBER_OF(mapped.Reason),
                    L"memory.write base=0x%llX size=0x%llX entropy=%.2f remote=%u mzHeader=%u sampleBytes=%lu targetPid=%lu",
                    (unsigned long long)HookEvent->Context0, (unsigned long long)HookEvent->Context1, entropy,
                    (unsigned int)remoteWrite, (unsigned int)mzHeader, (unsigned long)sampleSize,
                    (unsigned long)targetPid);
            }
        }
        else if (HookEvent->Kind == BlackbirdIpcHookEventNt && lstrcmpiA(apiName, "NtOpenProcess") == 0)
        {
            ULONG desiredAccess = (ULONG)HookEvent->Context1;
            UINT32 targetPid = (UINT32)(HookEvent->Context2 & 0xFFFFFFFFull);
            if (ControllerHookIsInterestingProcessAccess(desiredAccess))
            {
                BOOL credentialAccess = targetPid != 0 && targetPid != eventPid &&
                                        ((desiredAccess & PROCESS_VM_READ) != 0 ||
                                         (desiredAccess & PROCESS_ALL_ACCESS) == PROCESS_ALL_ACCESS) &&
                                        ControllerPidImageNameEquals(targetPid, L"lsass.exe");
                (void)StringCchCopyA(mapped.DetectionName, RTL_NUMBER_OF(mapped.DetectionName),
                                     credentialAccess ? "CREDENTIAL_ACCESS_LSASS_OPEN"
                                                      : "USERMODE_PROCESS_HANDLE_ACTIVITY");
                mapped.Severity = credentialAccess ? 7u : ControllerHookSeverityForProcessAccess(desiredAccess);
                mapped.TargetPid = targetPid;
                specializedEvent = TRUE;
                if (credentialAccess)
                {
                    (void)StringCchPrintfW(
                        mapped.Reason, RTL_NUMBER_OF(mapped.Reason),
                        L"credential-access process.open target=lsass.exe targetPid=%lu desiredAccess=0x%X",
                        (unsigned long)targetPid, (unsigned int)desiredAccess);
                }
                else
                {
                    (void)StringCchPrintfW(mapped.Reason, RTL_NUMBER_OF(mapped.Reason),
                                           L"process.open targetPid=%lu desiredAccess=0x%X", (unsigned long)targetPid,
                                           (unsigned int)desiredAccess);
                }
            }
        }
        else if (HookEvent->Kind == BlackbirdIpcHookEventNt && lstrcmpiA(apiName, "NtTerminateProcess") == 0)
        {
            UINT32 targetPid = (UINT32)(HookEvent->Context2 & 0xFFFFFFFFull);
            NTSTATUS exitStatus = (NTSTATUS)(HookEvent->Context1 & 0xFFFFFFFFull);
            BOOL currentProcessTarget = HookEvent->Context0 == 0 || HookEvent->Context0 == (UINT64)(ULONG_PTR)-1 ||
                                        targetPid == 0 || targetPid == eventPid;

            (void)StringCchCopyA(mapped.DetectionName, RTL_NUMBER_OF(mapped.DetectionName),
                                 "USERMODE_PROCESS_TERMINATE_BREAKPOINT");
            mapped.Severity = currentProcessTarget ? 8u : 6u;
            mapped.TargetPid = targetPid != 0 ? targetPid : eventPid;
            specializedEvent = TRUE;
            (void)StringCchPrintfW(
                mapped.Reason, RTL_NUMBER_OF(mapped.Reason),
                L"process.terminate breakpoint=pre-call targetPid=%lu currentProcess=%u processHandle=0x%llX exitStatus=0x%08X frames=%lu",
                (unsigned long)mapped.TargetPid, (unsigned int)currentProcessTarget,
                (unsigned long long)HookEvent->Context0, (unsigned int)exitStatus,
                (unsigned long)HookEvent->StackCount);
        }
        else if (HookEvent->Kind == BlackbirdIpcHookEventNt && lstrcmpiA(apiName, "NtOpenThread") == 0)
        {
            ULONG desiredAccess = (ULONG)HookEvent->Context1;
            UINT32 targetPid = (UINT32)(HookEvent->Context2 & 0xFFFFFFFFull);
            UINT32 targetTid = (UINT32)(HookEvent->Context3 & 0xFFFFFFFFull);
            if (ControllerHookIsInterestingThreadAccess(desiredAccess))
            {
                (void)StringCchCopyA(mapped.DetectionName, RTL_NUMBER_OF(mapped.DetectionName),
                                     "USERMODE_THREAD_HANDLE_ACTIVITY");
                mapped.Severity = ControllerHookSeverityForThreadAccess(desiredAccess);
                mapped.TargetPid = targetPid;
                specializedEvent = TRUE;
                (void)StringCchPrintfW(mapped.Reason, RTL_NUMBER_OF(mapped.Reason),
                                       L"thread.open targetPid=%lu targetTid=%lu desiredAccess=0x%X",
                                       (unsigned long)targetPid, (unsigned long)targetTid, (unsigned int)desiredAccess);
            }
        }
        else if (HookEvent->Kind == BlackbirdIpcHookEventNt && lstrcmpiA(apiName, "NtDuplicateObject") == 0)
        {
            (void)StringCchCopyA(mapped.DetectionName, RTL_NUMBER_OF(mapped.DetectionName),
                                 "USERMODE_DUP_HANDLE_ACTIVITY");
            mapped.Severity =
                ((HookEvent->Args[4] & (PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD)) != 0) ? 6u
                                                                                                                : 3u;
            specializedEvent = TRUE;
            (void)StringCchPrintfW(
                mapped.Reason, RTL_NUMBER_OF(mapped.Reason),
                L"handle.duplicate srcProcess=0x%llX srcHandle=0x%llX dstProcess=0x%llX desiredAccess=0x%llX options=0x%llX",
                (unsigned long long)HookEvent->Args[0], (unsigned long long)HookEvent->Args[1],
                (unsigned long long)HookEvent->Args[2], (unsigned long long)HookEvent->Args[4],
                (unsigned long long)HookEvent->Args[6]);
        }
        else if (HookEvent->Kind == BlackbirdIpcHookEventNt &&
                 (lstrcmpiA(apiName, "NtQueryInformationProcess") == 0 ||
                  lstrcmpiA(apiName, "NtQueryVirtualMemory") == 0 || lstrcmpiA(apiName, "NtReadVirtualMemory") == 0 ||
                  lstrcmpiA(apiName, "NtQuerySystemInformation") == 0))
        {
            BOOL lsassRead = FALSE;
            UINT32 targetPid = 0;
            if (lstrcmpiA(apiName, "NtReadVirtualMemory") == 0)
            {
                targetPid = (argCount > 7u && HookEvent->Args[7] <= 0xFFFFFFFFull) ? (UINT32)HookEvent->Args[7] : 0u;
                lsassRead = targetPid != 0 && targetPid != eventPid && HookEvent->Context3 != 0 &&
                            ControllerPidImageNameEquals(targetPid, L"lsass.exe");
            }

            (void)StringCchCopyA(mapped.DetectionName, RTL_NUMBER_OF(mapped.DetectionName),
                                 lsassRead ? "CREDENTIAL_ACCESS_LSASS_READ" : "USERMODE_PROCESS_RECON");
            mapped.Severity = lsassRead ? 8u : 3u;
            if (targetPid != 0 && targetPid != eventPid)
            {
                mapped.TargetPid = targetPid;
            }
            specializedEvent = TRUE;
            if (lsassRead)
            {
                (void)StringCchPrintfW(
                    mapped.Reason, RTL_NUMBER_OF(mapped.Reason),
                    L"credential-access memory.read target=lsass.exe targetPid=%lu base=0x%llX size=0x%llX",
                    (unsigned long)targetPid, (unsigned long long)HookEvent->Context1,
                    (unsigned long long)HookEvent->Context3);
            }
            else
            {
                (void)StringCchPrintfW(mapped.Reason, RTL_NUMBER_OF(mapped.Reason),
                                       L"process.recon api=%S c0=0x%llX c1=0x%llX c2=0x%llX", apiName,
                                       (unsigned long long)HookEvent->Context0, (unsigned long long)HookEvent->Context1,
                                       (unsigned long long)HookEvent->Context2);
            }
        }
        else if (HookEvent->Kind == BlackbirdIpcHookEventNt &&
                 (lstrcmpiA(apiName, "NtSetContextThread") == 0 || lstrcmpiA(apiName, "NtGetContextThread") == 0 ||
                  lstrcmpiA(apiName, "NtSuspendThread") == 0 || lstrcmpiA(apiName, "NtResumeThread") == 0))
        {
            (void)StringCchCopyA(mapped.DetectionName, RTL_NUMBER_OF(mapped.DetectionName),
                                 "USERMODE_THREAD_CONTEXT_ACTIVITY");
            mapped.Severity = (lstrcmpiA(apiName, "NtGetContextThread") == 0) ? 4u : 6u;
            specializedEvent = TRUE;
            if (lstrcmpiA(apiName, "NtSetContextThread") == 0 || lstrcmpiA(apiName, "NtGetContextThread") == 0)
            {
                UINT32 targetTid =
                    (argCount > 5u && HookEvent->Args[5] <= 0xFFFFFFFFull) ? (UINT32)HookEvent->Args[5] : 0u;
                UINT32 targetPid =
                    (argCount > 6u && HookEvent->Args[6] <= 0xFFFFFFFFull) ? (UINT32)HookEvent->Args[6] : 0u;
                if (targetPid != 0 && targetPid != eventPid)
                {
                    mapped.TargetPid = targetPid;
                }
                (void)StringCchPrintfW(
                    mapped.Reason, RTL_NUMBER_OF(mapped.Reason),
                    L"thread.control api=%S targetPid=%lu targetTid=%lu threadHandle=0x%llX ip=0x%llX sp=0x%llX flags=0x%llX",
                    apiName, (unsigned long)targetPid, (unsigned long)targetTid,
                    (unsigned long long)HookEvent->Context0, (unsigned long long)HookEvent->Context1,
                    (unsigned long long)HookEvent->Context2, (unsigned long long)HookEvent->Context3);
            }
            else
            {
                UINT32 targetTid = (HookEvent->Context2 <= 0xFFFFFFFFull) ? (UINT32)HookEvent->Context2 : 0u;
                UINT32 targetPid = (HookEvent->Context3 <= 0xFFFFFFFFull) ? (UINT32)HookEvent->Context3 : 0u;
                if (targetPid != 0 && targetPid != eventPid)
                {
                    mapped.TargetPid = targetPid;
                }
                (void)StringCchPrintfW(
                    mapped.Reason, RTL_NUMBER_OF(mapped.Reason),
                    L"thread.control api=%S targetPid=%lu targetTid=%lu threadHandle=0x%llX suspendCount=%llu", apiName,
                    (unsigned long)targetPid, (unsigned long)targetTid, (unsigned long long)HookEvent->Context0,
                    (unsigned long long)HookEvent->Context1);
            }
        }
        else if (HookEvent->Kind == BlackbirdIpcHookEventNt && lstrcmpiA(apiName, "NtQueueApcThread") == 0)
        {
            (void)StringCchCopyA(mapped.DetectionName, RTL_NUMBER_OF(mapped.DetectionName),
                                 "USERMODE_APC_QUEUE_ACTIVITY");
            mapped.Severity = 1u;
            specializedEvent = TRUE;
            if (argCount > 6u && HookEvent->Args[6] <= 0xFFFFFFFFull && (UINT32)HookEvent->Args[6] != eventPid)
            {
                mapped.TargetPid = (UINT32)HookEvent->Args[6];
            }
            (void)StringCchPrintfW(
                mapped.Reason, RTL_NUMBER_OF(mapped.Reason),
                L"thread.apc targetPid=%lu targetTid=%lu threadHandle=0x%llX routine=0x%llX arg1=0x%llX arg2=0x%llX arg3=0x%llX",
                (unsigned long)mapped.TargetPid,
                (unsigned long)((argCount > 5u && HookEvent->Args[5] <= 0xFFFFFFFFull) ? (UINT32)HookEvent->Args[5]
                                                                                       : 0u),
                (unsigned long long)HookEvent->Context0, (unsigned long long)HookEvent->Context1,
                (unsigned long long)HookEvent->Context2, (unsigned long long)HookEvent->Context3,
                (unsigned long long)HookEvent->Args[4]);
        }
        else if (HookEvent->Kind == BlackbirdIpcHookEventNt &&
                 (lstrcmpiA(apiName, "NtCreateThread") == 0 || lstrcmpiA(apiName, "NtCreateThreadEx") == 0))
        {
            BOOL oldCreateThread = lstrcmpiA(apiName, "NtCreateThread") == 0;
            UINT64 processHandle = oldCreateThread ? HookEvent->Args[3] : HookEvent->Context0;
            UINT64 startRoutine = oldCreateThread ? 0ull : HookEvent->Context1;
            UINT32 createFlags = oldCreateThread ? 0u : (UINT32)(HookEvent->Context2 & 0xFFFFFFFFull);
            UINT32 targetPid =
                oldCreateThread
                    ? ((argCount > 6u && HookEvent->Args[6] <= 0xFFFFFFFFull) ? (UINT32)HookEvent->Args[6] : 0u)
                    : ((argCount > 6u && HookEvent->Args[6] <= 0xFFFFFFFFull) ? (UINT32)HookEvent->Args[6] : 0u);
            BOOL remoteThread = (targetPid != 0 && targetPid != eventPid);
            BOOL createSuspended =
                oldCreateThread ? (argCount > 7u && HookEvent->Args[7] != 0u) : ((createFlags & 0x1u) != 0);
            BOOL hiddenThread = !oldCreateThread && ((createFlags & 0x4u) != 0);
            if (targetPid == 0)
            {
                remoteThread = ((processHandle != (UINT64)(ULONG_PTR)-1) && (processHandle != 0));
            }

            (void)StringCchCopyA(mapped.DetectionName, RTL_NUMBER_OF(mapped.DetectionName),
                                 "USERMODE_THREAD_CREATE_ACTIVITY");
            mapped.Severity = remoteThread ? ((hiddenThread || createSuspended) ? 3u : 2u)
                                           : ((hiddenThread || createSuspended) ? 2u : 1u);
            specializedEvent = TRUE;
            if (targetPid != 0 && targetPid != eventPid)
            {
                mapped.TargetPid = targetPid;
            }
            (void)StringCchPrintfW(
                mapped.Reason, RTL_NUMBER_OF(mapped.Reason),
                L"thread.create api=%S targetPid=%lu processHandle=0x%llX startRoutine=0x%llX argument=0x%llX createFlags=0x%X remote=%u createSuspended=%u hideFromDebugger=%u",
                apiName, (unsigned long)targetPid, (unsigned long long)processHandle, (unsigned long long)startRoutine,
                (unsigned long long)HookEvent->Context3, (unsigned int)createFlags, (unsigned int)remoteThread,
                (unsigned int)createSuspended, (unsigned int)hiddenThread);
        }
        else if (HookEvent->Kind == BlackbirdIpcHookEventNt &&
                 (lstrcmpiA(apiName, "NtQueueApcThreadEx") == 0 || lstrcmpiA(apiName, "NtQueueApcThreadEx2") == 0))
        {
            (void)StringCchCopyA(mapped.DetectionName, RTL_NUMBER_OF(mapped.DetectionName),
                                 "USERMODE_APC_QUEUE_ACTIVITY");
            mapped.Severity = 1u;
            specializedEvent = TRUE;
            if (argCount > 7u && HookEvent->Args[7] <= 0xFFFFFFFFull && (UINT32)HookEvent->Args[7] != eventPid)
            {
                mapped.TargetPid = (UINT32)HookEvent->Args[7];
            }
            (void)StringCchPrintfW(
                mapped.Reason, RTL_NUMBER_OF(mapped.Reason),
                L"thread.apcEx targetPid=%lu targetTid=%lu threadHandle=0x%llX routine=0x%llX arg1=0x%llX arg2=0x%llX reserve=0x%llX",
                (unsigned long)mapped.TargetPid,
                (unsigned long)((argCount > 6u && HookEvent->Args[6] <= 0xFFFFFFFFull) ? (UINT32)HookEvent->Args[6]
                                                                                       : 0u),
                (unsigned long long)HookEvent->Context0, (unsigned long long)HookEvent->Context1,
                (unsigned long long)HookEvent->Context2, (unsigned long long)HookEvent->Context3,
                (unsigned long long)((argCount > 1u) ? HookEvent->Args[1] : 0ull));
        }
        else if (HookEvent->Kind == BlackbirdIpcHookEventNt &&
                 (lstrcmpiA(apiName, "NtCreateSection") == 0 || lstrcmpiA(apiName, "NtCreateSectionEx") == 0))
        {
            UINT32 sectionPageProtect = (UINT32)(HookEvent->Context1 & 0xFFFFFFFFull);
            UINT32 allocAttribs = (UINT32)(HookEvent->Context2 & 0xFFFFFFFFull);
            BOOL isImage = (allocAttribs & 0x1000000u) != 0;
            BOOL isExec = (sectionPageProtect & 0xF0u) != 0;
            UINT32 sev = isImage ? 5u : (isExec ? 4u : 3u);

            (void)StringCchCopyA(mapped.DetectionName, RTL_NUMBER_OF(mapped.DetectionName),
                                 "USERMODE_IMAGE_SECTION_ACTIVITY");
            mapped.Severity = sev;
            specializedEvent = TRUE;
            (void)StringCchPrintfW(
                mapped.Reason, RTL_NUMBER_OF(mapped.Reason),
                L"section.create sectionPageProtect=0x%X allocAttribs=0x%X isImage=%u isExec=%u fileHandle=0x%llX",
                (unsigned int)sectionPageProtect, (unsigned int)allocAttribs, (unsigned int)isImage,
                (unsigned int)isExec, (unsigned long long)HookEvent->Context3);
        }
        else if (HookEvent->Kind == BlackbirdIpcHookEventNt &&
                 (lstrcmpiA(apiName, "NtMapViewOfSection") == 0 || lstrcmpiA(apiName, "NtMapViewOfSectionEx") == 0))
        {
            UINT64 processHandle = HookEvent->Context1;
            UINT32 win32Protect = (argCount > 6u) ? (UINT32)(HookEvent->Args[6] & 0xFFFFFFFFull) : 0u;
            UINT32 targetPid = (argCount > 7u && HookEvent->Args[7] <= 0xFFFFFFFFull) ? (UINT32)HookEvent->Args[7] : 0u;
            BOOL remoteMap = (targetPid != 0 && targetPid != eventPid);
            if (targetPid == 0)
            {
                remoteMap = (processHandle != (UINT64)(ULONG_PTR)-1) && (processHandle != 0);
            }
            BOOL execMap = (win32Protect & 0xF0u) != 0;
            UINT32 sev;

            if (remoteMap && execMap)
                sev = 3u;
            else if (remoteMap)
                sev = 2u;
            else if (execMap)
                sev = 2u;
            else
                sev = 1u;

            (void)StringCchCopyA(mapped.DetectionName, RTL_NUMBER_OF(mapped.DetectionName),
                                 "USERMODE_SECTION_MAP_ACTIVITY");
            mapped.Severity = sev;
            if (targetPid != 0 && targetPid != eventPid)
            {
                mapped.TargetPid = targetPid;
            }
            specializedEvent = TRUE;
            (void)StringCchPrintfW(
                mapped.Reason, RTL_NUMBER_OF(mapped.Reason),
                L"section.map sectionHandle=0x%llX processHandle=0x%llX baseAddress=0x%llX viewSize=0x%llX win32Protect=0x%X remote=%u exec=%u targetPid=%lu",
                (unsigned long long)HookEvent->Context0, (unsigned long long)processHandle,
                (unsigned long long)HookEvent->Context2, (unsigned long long)HookEvent->Context3,
                (unsigned int)win32Protect, (unsigned int)remoteMap, (unsigned int)execMap, (unsigned long)targetPid);
        }
        else if (HookEvent->Kind == BlackbirdIpcHookEventNt &&
                 (lstrcmpiA(apiName, "NtUnmapViewOfSection") == 0 || lstrcmpiA(apiName, "NtUnmapViewOfSectionEx") == 0))
        {
            UINT32 targetPid = (argCount > 2u && HookEvent->Args[2] <= 0xFFFFFFFFull) ? (UINT32)HookEvent->Args[2] : 0u;
            BOOL remoteUnmap = targetPid != 0 && targetPid != eventPid;

            (void)StringCchCopyA(mapped.DetectionName, RTL_NUMBER_OF(mapped.DetectionName),
                                 "USERMODE_SECTION_UNMAP_ACTIVITY");
            mapped.Severity = remoteUnmap ? 6u : 3u;
            if (remoteUnmap)
            {
                mapped.TargetPid = targetPid;
            }
            specializedEvent = TRUE;
            (void)StringCchPrintfW(
                mapped.Reason, RTL_NUMBER_OF(mapped.Reason),
                L"section.unmap api=%S processHandle=0x%llX baseAddress=0x%llX targetPid=%lu flags=0x%llX remote=%u",
                apiName, (unsigned long long)HookEvent->Args[0], (unsigned long long)HookEvent->Args[1],
                (unsigned long)targetPid, (unsigned long long)((argCount > 3u) ? HookEvent->Args[3] : 0ull),
                (unsigned int)remoteUnmap);
        }
        else if (HookEvent->Kind == BlackbirdIpcHookEventNt &&
                 (lstrcmpiA(apiName, "NtCreateUserProcess") == 0 || lstrcmpiA(apiName, "NtCreateProcessEx") == 0))
        {
            UINT32 createFlags = (UINT32)(HookEvent->Context2 & 0xFFFFFFFFull);
            BOOL suspended = (createFlags & 0x1u) != 0;

            (void)StringCchCopyA(mapped.DetectionName, RTL_NUMBER_OF(mapped.DetectionName),
                                 "USERMODE_PROCESS_CREATE_ACTIVITY");
            mapped.Severity = suspended ? 4u : 2u;
            specializedEvent = TRUE;
            (void)StringCchPrintfW(mapped.Reason, RTL_NUMBER_OF(mapped.Reason),
                                   L"process.create processHandle=0x%llX flags=0x%X suspended=%u",
                                   (unsigned long long)HookEvent->Context0, (unsigned int)createFlags,
                                   (unsigned int)suspended);
        }
        else if (HookEvent->Kind == BlackbirdIpcHookEventWinsock &&
                 (lstrcmpiA(apiName, "connect") == 0 || lstrcmpiA(apiName, "WSAConnect") == 0))
        {
            UINT16 family = 0;
            UINT16 port = 0;
            CHAR ipBuf[48] = {'\0'};
            (void)ControllerHookDecodeSockaddr(HookEvent->DataSample, sampleSize, &family, &port, ipBuf, sizeof(ipBuf));
            mapped.Family = BlackbirdIpcEtwFamilySocket;
            mapped.TargetPid = 0;
            (void)StringCchCopyA(mapped.DetectionName, RTL_NUMBER_OF(mapped.DetectionName), "USERMODE_NETWORK_CONNECT");
            mapped.Severity = 2u;
            specializedEvent = TRUE;
            if (ipBuf[0] != '\0')
            {
                (void)StringCchPrintfW(mapped.Reason, RTL_NUMBER_OF(mapped.Reason),
                                       L"socket.connect ip=%S port=%u family=%u socket=0x%llX api=%S", ipBuf,
                                       (unsigned int)port, (unsigned int)family,
                                       (unsigned long long)HookEvent->Context0, apiName);
            }
            else
            {
                (void)StringCchPrintfW(mapped.Reason, RTL_NUMBER_OF(mapped.Reason),
                                       L"socket.connect port=%u family=%u socket=0x%llX api=%S", (unsigned int)port,
                                       (unsigned int)family, (unsigned long long)HookEvent->Context0, apiName);
            }
        }
        else if (HookEvent->Kind == BlackbirdIpcHookEventWinsock && lstrcmpiA(apiName, "GetAddrInfoW") == 0)
        {
            mapped.Family = BlackbirdIpcEtwFamilySocket;
            mapped.TargetPid = 0;
            (void)StringCchCopyA(mapped.DetectionName, RTL_NUMBER_OF(mapped.DetectionName),
                                 "USERMODE_DOMAIN_RESOLUTION");
            mapped.Severity = 1u;
            specializedEvent = TRUE;
            ControllerHookCopyWideSampleToReason(mapped.Reason, RTL_NUMBER_OF(mapped.Reason), HookEvent->DataSample,
                                                 sampleSize);
            if (mapped.Reason[0] == L'\0')
            {
                (void)StringCchCopyW(mapped.Reason, RTL_NUMBER_OF(mapped.Reason), L"domain.resolve");
            }
        }
        else if (HookEvent->Kind == BlackbirdIpcHookEventWinsock &&
                 (lstrcmpiA(apiName, "WSASend") == 0 || lstrcmpiA(apiName, "WSARecv") == 0 ||
                  lstrcmpiA(apiName, "send") == 0 || lstrcmpiA(apiName, "recv") == 0))
        {
            mapped.Family = BlackbirdIpcEtwFamilySocket;
            mapped.TargetPid = 0;
            (void)StringCchCopyA(mapped.DetectionName, RTL_NUMBER_OF(mapped.DetectionName), "USERMODE_NETWORK_IO");
            mapped.Severity = 1u;
            specializedEvent = TRUE;
            (void)StringCchPrintfW(mapped.Reason, RTL_NUMBER_OF(mapped.Reason),
                                   L"socket.io api=%S bytes=%lu socket=0x%llX", apiName, (unsigned long)sampleSize,
                                   (unsigned long long)HookEvent->Context0);
        }
        else if (HookEvent->Kind == BlackbirdIpcHookEventKi)
        {
            (void)StringCchCopyA(mapped.DetectionName, RTL_NUMBER_OF(mapped.DetectionName), "USERMODE_KI_ACTIVITY");
            mapped.Severity = 3u;
            mapped.TargetPid = eventPid;
            specializedEvent = TRUE;
            (void)StringCchPrintfW(mapped.Reason, RTL_NUMBER_OF(mapped.Reason),
                                   L"ki.dispatch stub=%S caller=0x%llX stack=0x%llX", apiName,
                                   (unsigned long long)HookEvent->Caller, (unsigned long long)HookEvent->Context0);
        }
        else if (HookEvent->Kind == BlackbirdIpcHookEventModule)
        {
            WCHAR nameBuffer[BKIPC_MAX_ETW_REASON] = {0};
            ULONGLONG moduleHandle = HookEvent->Context0;
            ULONGLONG frontFlags = HookEvent->Context1;
            ULONGLONG auxValue = HookEvent->Context2;
            ULONGLONG thirdValue = HookEvent->Context3;
            UINT32 moduleOp = (UINT32)HookEvent->Operation;
            BOOL wmiLocator = FALSE;

            mapped.TargetPid = eventPid;
            specializedEvent = TRUE;

            switch (moduleOp)
            {
            case ControllerModuleOpRtlAddFunctionTable:
            {
                MEMORY_BASIC_INFORMATION mbi;
                WCHAR abuseReason[128];
                BOOL abusive = ControllerFunctionTableBaseLooksAbusive(eventPid, HookEvent->Args[2], &mbi, abuseReason,
                                                                       RTL_NUMBER_OF(abuseReason));
                mapped.Severity = abusive ? 6u : 5u;
                (void)StringCchCopyA(mapped.DetectionName, RTL_NUMBER_OF(mapped.DetectionName),
                                     abusive ? "DYNAMIC_FUNCTION_TABLE_ABUSE" : "USERMODE_FUNCTION_TABLE_ACTIVITY");
                if (abusive)
                {
                    (void)StringCchPrintfW(
                        mapped.Reason, RTL_NUMBER_OF(mapped.Reason),
                        L"functionTable.abuse table=0x%llX entryCount=0x%llX baseAddress=0x%llX reason=%ws state=0x%lX protect=0x%lX type=0x%lX",
                        (unsigned long long)HookEvent->Args[0], (unsigned long long)HookEvent->Args[1],
                        (unsigned long long)HookEvent->Args[2],
                        (abuseReason[0] != L'\0') ? abuseReason : L"suspicious function-table base",
                        (unsigned long)mbi.State, (unsigned long)mbi.Protect, (unsigned long)mbi.Type);
                }
                else
                {
                    (void)StringCchPrintfW(mapped.Reason, RTL_NUMBER_OF(mapped.Reason),
                                           L"functionTable.add table=0x%llX entryCount=0x%llX baseAddress=0x%llX",
                                           (unsigned long long)HookEvent->Args[0],
                                           (unsigned long long)HookEvent->Args[1],
                                           (unsigned long long)HookEvent->Args[2]);
                }
                break;
            }

            case ControllerModuleOpRtlInstallFunctionTableCallback:
            {
                MEMORY_BASIC_INFORMATION mbi;
                WCHAR abuseReason[128];
                BOOL abusive = ControllerFunctionTableBaseLooksAbusive(eventPid, HookEvent->Args[1], &mbi, abuseReason,
                                                                       RTL_NUMBER_OF(abuseReason));
                ControllerHookCopyWideSampleToReason(nameBuffer, RTL_NUMBER_OF(nameBuffer), HookEvent->DataSample,
                                                     sampleSize);
                mapped.Severity = abusive ? 6u : 5u;
                (void)StringCchCopyA(mapped.DetectionName, RTL_NUMBER_OF(mapped.DetectionName),
                                     abusive ? "DYNAMIC_FUNCTION_TABLE_ABUSE" : "USERMODE_FUNCTION_TABLE_ACTIVITY");
                if (abusive)
                {
                    (void)StringCchPrintfW(
                        mapped.Reason, RTL_NUMBER_OF(mapped.Reason),
                        L"functionTable.callback.abuse tableId=0x%llX baseAddress=0x%llX length=0x%llX callback=0x%llX reason=%ws outOfProc=%ws state=0x%lX protect=0x%lX type=0x%lX",
                        (unsigned long long)HookEvent->Args[0], (unsigned long long)HookEvent->Args[1],
                        (unsigned long long)HookEvent->Args[2], (unsigned long long)HookEvent->Args[3],
                        (abuseReason[0] != L'\0') ? abuseReason : L"suspicious function-table base",
                        (nameBuffer[0] != L'\0') ? nameBuffer : L"<none>", (unsigned long)mbi.State,
                        (unsigned long)mbi.Protect, (unsigned long)mbi.Type);
                }
                else
                {
                    (void)StringCchPrintfW(
                        mapped.Reason, RTL_NUMBER_OF(mapped.Reason),
                        L"functionTable.callback tableId=0x%llX baseAddress=0x%llX length=0x%llX callback=0x%llX outOfProc=%ws",
                        (unsigned long long)HookEvent->Args[0], (unsigned long long)HookEvent->Args[1],
                        (unsigned long long)HookEvent->Args[2], (unsigned long long)HookEvent->Args[3],
                        (nameBuffer[0] != L'\0') ? nameBuffer : L"<none>");
                }
                break;
            }

            case ControllerModuleOpRtlDeleteFunctionTable:
                mapped.Severity = 2u;
                (void)StringCchCopyA(mapped.DetectionName, RTL_NUMBER_OF(mapped.DetectionName),
                                     "USERMODE_FUNCTION_TABLE_ACTIVITY");
                (void)StringCchPrintfW(mapped.Reason, RTL_NUMBER_OF(mapped.Reason),
                                       L"functionTable.delete table=0x%llX", (unsigned long long)HookEvent->Args[0]);
                break;

            case ControllerModuleOpCoInitializeEx:
                ControllerHookCopyWideSampleToReason(nameBuffer, RTL_NUMBER_OF(nameBuffer), HookEvent->DataSample,
                                                     sampleSize);
                mapped.Severity = 1u;
                (void)StringCchCopyA(mapped.DetectionName, RTL_NUMBER_OF(mapped.DetectionName), "USERMODE_COM_INIT");
                (void)StringCchPrintfW(mapped.Reason, RTL_NUMBER_OF(mapped.Reason),
                                       L"com.init mode=%ws coinit=0x%llX hr=0x%08llX",
                                       (nameBuffer[0] != L'\0') ? nameBuffer : L"COM",
                                       (unsigned long long)HookEvent->Args[0], (unsigned long long)HookEvent->Args[1]);
                break;

            case ControllerModuleOpCoInitializeSecurity:
                mapped.Severity = 2u;
                (void)StringCchCopyA(mapped.DetectionName, RTL_NUMBER_OF(mapped.DetectionName),
                                     "USERMODE_COM_SECURITY_INIT");
                (void)StringCchPrintfW(mapped.Reason, RTL_NUMBER_OF(mapped.Reason),
                                       L"com.security authSvc=%lld authn=%llu imp=%llu caps=0x%llX",
                                       (long long)HookEvent->Args[0], (unsigned long long)HookEvent->Args[1],
                                       (unsigned long long)HookEvent->Args[2], (unsigned long long)HookEvent->Args[3]);
                break;

            case ControllerModuleOpCoCreateInstance:
                ControllerHookCopyWideSampleToReason(nameBuffer, RTL_NUMBER_OF(nameBuffer), HookEvent->DataSample,
                                                     sampleSize);
                wmiLocator = (_wcsicmp(nameBuffer, L"WMI:WbemLocator") == 0);
                mapped.Severity = wmiLocator ? 3u : 1u;
                (void)StringCchCopyA(mapped.DetectionName, RTL_NUMBER_OF(mapped.DetectionName),
                                     wmiLocator ? "USERMODE_WMI_ACTIVITY" : "USERMODE_COM_INSTANCE_CREATE");
                (void)StringCchPrintfW(mapped.Reason, RTL_NUMBER_OF(mapped.Reason),
                                       L"com.instance class=%ws clsctx=0x%llX hr=0x%08llX",
                                       (nameBuffer[0] != L'\0') ? nameBuffer : L"COMClass",
                                       (unsigned long long)HookEvent->Args[0], (unsigned long long)HookEvent->Args[3]);
                break;

            case ControllerModuleOpEventRegister:
                ControllerHookCopyWideSampleToReason(nameBuffer, RTL_NUMBER_OF(nameBuffer), HookEvent->DataSample,
                                                     sampleSize);
                mapped.Severity = 2u;
                (void)StringCchCopyA(mapped.DetectionName, RTL_NUMBER_OF(mapped.DetectionName),
                                     "USERMODE_ETW_PROVIDER_REGISTER");
                (void)StringCchPrintfW(mapped.Reason, RTL_NUMBER_OF(mapped.Reason),
                                       L"etw.provider.register provider=%ws reg=0x%llX status=0x%08llX",
                                       (nameBuffer[0] != L'\0') ? nameBuffer : L"ETWProvider",
                                       (unsigned long long)HookEvent->Args[2], (unsigned long long)HookEvent->Args[3]);
                break;

            case ControllerModuleOpEventUnregister:
                mapped.Severity = 1u;
                (void)StringCchCopyA(mapped.DetectionName, RTL_NUMBER_OF(mapped.DetectionName),
                                     "USERMODE_ETW_PROVIDER_UNREGISTER");
                (void)StringCchPrintfW(mapped.Reason, RTL_NUMBER_OF(mapped.Reason),
                                       L"etw.provider.unregister reg=0x%llX status=0x%08llX",
                                       (unsigned long long)HookEvent->Args[0], (unsigned long long)HookEvent->Args[1]);
                break;

            case ControllerModuleOpStartTraceW:
                ControllerHookCopyWideSampleToReason(nameBuffer, RTL_NUMBER_OF(nameBuffer), HookEvent->DataSample,
                                                     sampleSize);
                mapped.Severity = 3u;
                (void)StringCchCopyA(mapped.DetectionName, RTL_NUMBER_OF(mapped.DetectionName),
                                     "USERMODE_ETW_SESSION_CONTROL");
                (void)StringCchPrintfW(mapped.Reason, RTL_NUMBER_OF(mapped.Reason),
                                       L"etw.session.start name=%ws handle=0x%llX status=0x%08llX",
                                       (nameBuffer[0] != L'\0') ? nameBuffer : L"<unnamed>",
                                       (unsigned long long)HookEvent->Args[1], (unsigned long long)HookEvent->Args[3]);
                break;

            case ControllerModuleOpEnableTraceEx2:
                ControllerHookCopyWideSampleToReason(nameBuffer, RTL_NUMBER_OF(nameBuffer), HookEvent->DataSample,
                                                     sampleSize);
                mapped.Severity = 3u;
                (void)StringCchCopyA(mapped.DetectionName, RTL_NUMBER_OF(mapped.DetectionName),
                                     "USERMODE_ETW_SUBSCRIPTION");
                (void)StringCchPrintfW(
                    mapped.Reason, RTL_NUMBER_OF(mapped.Reason),
                    L"etw.subscribe provider=%ws trace=0x%llX control=%llu level=%llu status=0x%08llX",
                    (nameBuffer[0] != L'\0') ? nameBuffer : L"ETWControl", (unsigned long long)HookEvent->Args[0],
                    (unsigned long long)HookEvent->Args[1], (unsigned long long)HookEvent->Args[2],
                    (unsigned long long)HookEvent->Args[3]);
                break;

            case ControllerModuleOpCreateJobObjectW:
            case ControllerModuleOpOpenJobObjectW:
                ControllerHookCopyWideSampleToReason(nameBuffer, RTL_NUMBER_OF(nameBuffer), HookEvent->DataSample,
                                                     sampleSize);
                mapped.Severity = 2u;
                (void)StringCchCopyA(mapped.DetectionName, RTL_NUMBER_OF(mapped.DetectionName),
                                     "USERMODE_JOB_OBJECT_ACTIVITY");
                (void)StringCchPrintfW(
                    mapped.Reason, RTL_NUMBER_OF(mapped.Reason), L"job.object api=%S name=%ws handle=0x%llX", apiName,
                    (nameBuffer[0] != L'\0') ? nameBuffer : L"<unnamed>",
                    (unsigned long long)((moduleOp == ControllerModuleOpOpenJobObjectW) ? HookEvent->Args[2]
                                                                                        : HookEvent->Args[0]));
                break;

            case ControllerModuleOpAssignProcessToJobObject:
                ControllerHookCopyWideSampleToReason(nameBuffer, RTL_NUMBER_OF(nameBuffer), HookEvent->DataSample,
                                                     sampleSize);
                mapped.Severity = 3u;
                (void)StringCchCopyA(mapped.DetectionName, RTL_NUMBER_OF(mapped.DetectionName),
                                     "USERMODE_JOB_OBJECT_ACTIVITY");
                (void)StringCchPrintfW(mapped.Reason, RTL_NUMBER_OF(mapped.Reason),
                                       L"job.assign job=0x%llX process=0x%llX ok=%llu",
                                       (unsigned long long)HookEvent->Args[0], (unsigned long long)HookEvent->Args[1],
                                       (unsigned long long)HookEvent->Args[2]);
                break;

            case ControllerModuleOpSetInformationJobObject:
                ControllerHookCopyWideSampleToReason(nameBuffer, RTL_NUMBER_OF(nameBuffer), HookEvent->DataSample,
                                                     sampleSize);
                mapped.Severity = 3u;
                (void)StringCchCopyA(mapped.DetectionName, RTL_NUMBER_OF(mapped.DetectionName),
                                     "USERMODE_JOB_OBJECT_ACTIVITY");
                (void)StringCchPrintfW(
                    mapped.Reason, RTL_NUMBER_OF(mapped.Reason), L"job.config class=%ws job=0x%llX size=0x%llX ok=%llu",
                    (nameBuffer[0] != L'\0') ? nameBuffer : L"JobInfo", (unsigned long long)HookEvent->Args[0],
                    (unsigned long long)HookEvent->Args[2], (unsigned long long)HookEvent->Args[3]);
                break;

            default:
                (void)StringCchCopyA(mapped.DetectionName, RTL_NUMBER_OF(mapped.DetectionName), "USERMODE_MODULE_LOAD");

                if (moduleOp == ControllerModuleOpLoadLibraryA || moduleOp == ControllerModuleOpLoadLibraryExA)
                {
                    ControllerHookCopyAnsiSampleToReason(nameBuffer, RTL_NUMBER_OF(nameBuffer), HookEvent->DataSample,
                                                         sampleSize);
                }
                else
                {
                    ControllerHookCopyWideSampleToReason(nameBuffer, RTL_NUMBER_OF(nameBuffer), HookEvent->DataSample,
                                                         sampleSize);
                }

                if (nameBuffer[0] != L'\0')
                {
                    (void)StringCchCopyW(mapped.ImagePath, RTL_NUMBER_OF(mapped.ImagePath), nameBuffer);
                    BOOL heuristicFired = FALSE;
                    PCWSTR baseName = nameBuffer;

                    for (PCWSTR p = nameBuffer; *p != L'\0'; ++p)
                    {
                        if (*p == L'\\' || *p == L'/')
                        {
                            baseName = p + 1;
                        }
                    }

                    if (_wcsicmp(baseName, L"jscript.dll") == 0 || _wcsicmp(baseName, L"jscript9.dll") == 0 ||
                        _wcsicmp(baseName, L"vbscript.dll") == 0 || _wcsicmp(baseName, L"scrobj.dll") == 0)
                    {
                        (void)StringCchCopyA(mapped.DetectionName, RTL_NUMBER_OF(mapped.DetectionName),
                                             "SCRIPT_ENGINE_LOAD");
                        mapped.Severity = 3u;
                        heuristicFired = TRUE;
                    }
                    else if (ControllerHookWidePathContainsI(nameBuffer, L"\\") &&
                             !ControllerHookWidePathContainsI(nameBuffer, L"\\Windows\\System32\\") &&
                             !ControllerHookWidePathContainsI(nameBuffer, L"\\Windows\\SysWOW64\\") &&
                             !ControllerHookWidePathContainsI(nameBuffer, L"\\Windows\\WinSxS\\") &&
                             (_wcsicmp(baseName, L"version.dll") == 0 || _wcsicmp(baseName, L"winmm.dll") == 0 ||
                              _wcsicmp(baseName, L"wtsapi32.dll") == 0 || _wcsicmp(baseName, L"cryptsp.dll") == 0 ||
                              _wcsicmp(baseName, L"dwrite.dll") == 0 || _wcsicmp(baseName, L"dwmapi.dll") == 0 ||
                              _wcsicmp(baseName, L"propsys.dll") == 0 || _wcsicmp(baseName, L"cryptbase.dll") == 0 ||
                              _wcsicmp(baseName, L"uxtheme.dll") == 0 || _wcsicmp(baseName, L"msasn1.dll") == 0))
                    {
                        (void)StringCchCopyA(mapped.DetectionName, RTL_NUMBER_OF(mapped.DetectionName),
                                             "DLL_SEARCH_ORDER_HIJACK_USERMODE");
                        mapped.Severity = 6u;
                        heuristicFired = TRUE;
                    }
                    else if (ControllerHookWidePathContainsI(nameBuffer, L"\\Temp\\") ||
                             ControllerHookWidePathContainsI(nameBuffer, L"\\AppData\\") ||
                             ControllerHookWidePathContainsI(nameBuffer, L"\\Downloads\\") ||
                             ControllerHookWidePathContainsI(nameBuffer, L"\\Desktop\\") ||
                             ControllerHookWidePathContainsI(nameBuffer, L"\\Public\\"))
                    {
                        (void)StringCchCopyA(mapped.DetectionName, RTL_NUMBER_OF(mapped.DetectionName),
                                             "SUSPICIOUS_DLL_LOAD_PATH");
                        mapped.Severity = 4u;
                        heuristicFired = TRUE;
                    }

                    if (!heuristicFired)
                    {
                        mapped.Severity = 1u;
                    }
                }

                if (lstrcmpiA(apiName, "LdrLoadDll") == 0)
                {
                    if (lstrcmpiA(mapped.DetectionName, "USERMODE_MODULE_LOAD") == 0)
                    {
                        mapped.Severity = (((NTSTATUS)auxValue) < 0) ? 1u : 3u;
                    }
                    (void)StringCchPrintfW(
                        mapped.Reason, RTL_NUMBER_OF(mapped.Reason),
                        L"module.ldr name=%ws handle=0x%llX flags=0x%llX status=0x%08llX searchPath=0x%llX caller=0x%llX",
                        (nameBuffer[0] != L'\0') ? nameBuffer : L"<unknown>", (unsigned long long)moduleHandle,
                        (unsigned long long)frontFlags, (unsigned long long)auxValue, (unsigned long long)thirdValue,
                        (unsigned long long)HookEvent->Caller);
                }
                else if (lstrcmpiA(apiName, "LoadLibraryExA") == 0 || lstrcmpiA(apiName, "LoadLibraryExW") == 0)
                {
                    if (lstrcmpiA(mapped.DetectionName, "USERMODE_MODULE_LOAD") == 0)
                    {
                        mapped.Severity = 1u;
                    }
                    (void)StringCchPrintfW(
                        mapped.Reason, RTL_NUMBER_OF(mapped.Reason),
                        L"module.frontend api=%S name=%ws handle=0x%llX flags=0x%llX hFile=0x%llX caller=0x%llX",
                        apiName, (nameBuffer[0] != L'\0') ? nameBuffer : L"<unknown>", (unsigned long long)moduleHandle,
                        (unsigned long long)frontFlags, (unsigned long long)auxValue,
                        (unsigned long long)HookEvent->Caller);
                }
                else
                {
                    if (lstrcmpiA(mapped.DetectionName, "USERMODE_MODULE_LOAD") == 0)
                    {
                        mapped.Severity = 1u;
                    }
                    (void)StringCchPrintfW(mapped.Reason, RTL_NUMBER_OF(mapped.Reason),
                                           L"module.frontend api=%S name=%ws handle=0x%llX caller=0x%llX", apiName,
                                           (nameBuffer[0] != L'\0') ? nameBuffer : L"<unknown>",
                                           (unsigned long long)moduleHandle, (unsigned long long)HookEvent->Caller);
                }
                break;
            }
        }

        if (!memoryEvent && !specializedEvent)
        {
            (void)StringCchCopyA(mapped.DetectionName, RTL_NUMBER_OF(mapped.DetectionName), "USERMODE_HOOK_API_CALL");

            (void)StringCchPrintfW(mapped.Reason, RTL_NUMBER_OF(mapped.Reason),
                                   L"kind=%S op=%lu caller=0x%llX c0=0x%llX c1=0x%llX c2=0x%llX c3=0x%llX", kindName,
                                   (unsigned long)HookEvent->Operation, (unsigned long long)HookEvent->Caller,
                                   (unsigned long long)HookEvent->Context0, (unsigned long long)HookEvent->Context1,
                                   (unsigned long long)HookEvent->Context2, (unsigned long long)HookEvent->Context3);
        }
    }

    ControllerHookAppendArgsToReason(mapped.Reason, RTL_NUMBER_OF(mapped.Reason), HookEvent->Args, argCount);

    mapped.OriginAddress = HookEvent->Caller;
    mapped.StackCount = HookEvent->StackCount;
    if (mapped.StackCount > RTL_NUMBER_OF(mapped.Stack))
    {
        mapped.StackCount = RTL_NUMBER_OF(mapped.Stack);
    }
    if (mapped.StackCount > RTL_NUMBER_OF(HookEvent->Stack))
    {
        mapped.StackCount = RTL_NUMBER_OF(HookEvent->Stack);
    }
    if (mapped.StackCount != 0)
    {
        CopyMemory(mapped.Stack, HookEvent->Stack, mapped.StackCount * sizeof(mapped.Stack[0]));
    }
    mapped.NotifyClass = HookEvent->Kind;
    mapped.DataType = HookEvent->Operation;
    ControllerHookCopyArgs(mapped.HookArgs, &mapped.HookArgCount, HookEvent->Args, argCount);
    ControllerPrimeHookArgumentSymbols(eventPid, apiName, mapped.HookArgs, mapped.HookArgCount);

    {
        UINT32 cf = HookEvent->CallerFlags;
        if (cf & BK_HOOK_CALLER_FLAG_ALL_SYSTEM)
            mapped.Flags |= BKIPC_ETW_FLAG_HOOK_CALLER_ALL_SYSTEM;
        if (cf & BK_HOOK_CALLER_FLAG_HAS_UNMAPPED)
            mapped.Flags |= BKIPC_ETW_FLAG_HOOK_CALLER_HAS_UNMAPPED;
        if (cf & BK_HOOK_CALLER_FLAG_HAS_PROCESS_IMAGE)
            mapped.Flags |= BKIPC_ETW_FLAG_HOOK_CALLER_HAS_PROCESS_IMAGE;
        if (cf & BK_HOOK_CALLER_FLAG_HAS_NONSYSTEM_DLL)
            mapped.Flags |= BKIPC_ETW_FLAG_HOOK_CALLER_HAS_NONSYSTEM_DLL;
        if (cf & BK_HOOK_CALLER_FLAG_HAS_OWN_MODULE)
            mapped.Flags |= BKIPC_ETW_FLAG_HOOK_CALLER_HAS_OWN_MODULE;
        mapped.Flags |= (cf & (BK_HOOK_CALLER_IMMED_MASK | BK_HOOK_CALLER_DEEP_MASK));
        mapped.Flags |= ((cf & BK_HOOK_CALLER_COMPONENT_MASK) << 12u);
    }
    mapped.DataSize = sampleSize;
    mapped.DeepSampleSize = sampleSize;
    if (sampleSize != 0)
    {
        CopyMemory(mapped.DeepSample, HookEvent->DataSample, sampleSize);
    }

    {
        BOOL blackbirdOwned = FALSE;

        EnterCriticalSection(&Client->Lock);
        blackbirdOwned = ControllerIsBlackbirdOwnedAddress(Client, HookEvent->Caller);
        LeaveCriticalSection(&Client->Lock);

        if (blackbirdOwned)
        {
            mapped.Reserved2 = ControllerComputeEtwDetectionTraits(mapped) | BKIPC_ETW_TRAIT_BLACKBIRD_OWN;
            mapped.Severity = 1u;
            (void)StringCchCopyA(mapped.DetectionName, RTL_NUMBER_OF(mapped.DetectionName), "BK_INSTRUMENTATION");
            ControllerDispatchEtwEvent(&mapped);
            return ERROR_SUCCESS;
        }
    }

    if (HookEvent->Kind != BlackbirdIpcHookEventIntegrity && mapped.Severity >= 2u && mapped.ProcessId != 0u)
    {
        mapped.Reserved2 = ControllerComputeEtwDetectionTraits(mapped);
        UINT32 heurFlags = ControllerHeurFlagsFromDetectionTraits(mapped.Reserved2);
        if (heurFlags != 0u)
        {
            ControllerHeuristicsObserveEvent((DWORD)mapped.ProcessId, mapped.Severity, heurFlags);
        }
    }
    else
    {
        mapped.Reserved2 = ControllerComputeEtwDetectionTraits(mapped);
    }

    if (HookEvent->Kind != BlackbirdIpcHookEventIntegrity && mapped.Severity > 0u && mapped.Severity < 8u)
    {
        UINT32 boost = ControllerCallerOriginSeverityBoost(HookEvent->CallerFlags);
        mapped.Severity = (mapped.Severity + boost > 8u) ? 8u : (mapped.Severity + boost);
    }

    mapped.Reserved2 = ControllerComputeEtwDetectionTraits(mapped);

    ControllerObserveUserHookHollowEvent(&mapped);
    ControllerDispatchEtwEvent(&mapped);
    return ERROR_SUCCESS;
}

static DWORD ControllerClientNotifyHookReady(_Inout_ BK_CONTROLLER_CLIENT *Client,
                                             _In_ const BKIPC_NOTIFY_HOOK_READY_REQUEST *Request,
                                             _Out_ BKIPC_NOTIFY_HOOK_READY_RESPONSE *Response)
{
    DWORD observedMask;
    DWORD processId;

    if (Client == NULL || Request == NULL || Response == NULL)
    {
        return ERROR_INVALID_PARAMETER;
    }

    ZeroMemory(Response, sizeof(*Response));
    if (Request->ReadyMask == 0)
    {
        return ERROR_INVALID_PARAMETER;
    }

    processId = (Request->ProcessId != 0) ? Request->ProcessId : Client->ProcessId;
    if (processId == 0 || processId != Client->ProcessId)
    {
        return ERROR_ACCESS_DENIED;
    }

    observedMask = (DWORD)InterlockedOr(&Client->HookReadyMask, (LONG)Request->ReadyMask) | Request->ReadyMask;
    Client->HookReadyTick = GetTickCount64();

    ZeroMemory(Response, sizeof(*Response));
    Response->ProcessId = processId;
    Response->ObservedMask = observedMask;
    Response->RequiredMask = BK_CONTROLLER_HOOK_READY_REQUIRED_MASK;

    /* If the controller has flagged this client for inline Winsock hook upgrade, deliver
       the command in the PendingCommand back-channel and clear the flag atomically. */
    if (InterlockedCompareExchange(&Client->WinsockInlineUpgradePending, 0, 1) == 1)
    {
        Response->PendingCommand = BlackbirdIpcCommandUpgradeWinsockHooks;
        ControllerLog("[IPC] winsock-inline-upgrade delivered pid=%lu\n", processId);
    }

    if ((observedMask & BK_CONTROLLER_HOOK_READY_REQUIRED_MASK) == BK_CONTROLLER_HOOK_READY_REQUIRED_MASK)
    {
        ControllerLog("[IPC] hook-ready notify pid=%lu mask=0x%08lX (ready)\n", processId, observedMask);
    }

    return ERROR_SUCCESS;
}

static VOID ControllerClearDriverPendingLaunchBestEffort(_In_z_ PCSTR Reason)
{
    BK_ARM_PENDING_LAUNCH_REQUEST request;
    BOOL ok = FALSE;
    DWORD err = ERROR_SUCCESS;

    ZeroMemory(&request, sizeof(request));
    request.Flags = BK_PENDING_LAUNCH_FLAG_CLEAR;

    ok = ControllerProxyArmPendingLaunch(&request);
    err = ok ? ERROR_SUCCESS : GetLastError();

    if (!ok)
    {
        ControllerLog("[IPC][WARN] driver pending-launch clear failed reason=%s err=%lu\n", Reason, err);
        return;
    }

    ControllerLog("[IPC] driver pending-launch cleared reason=%s\n", Reason);
}

static BOOL ControllerClientDropLaunchSubscriptionsLocked(_Inout_ BK_CONTROLLER_CLIENT *Client,
                                                          _In_ DWORD RootProcessId)
{
    BOOL changed = FALSE;
    DWORD i = 0;

    if (Client == NULL || RootProcessId == 0)
    {
        return FALSE;
    }

    changed |= ControllerDropDynamicDescendantsLocked(Client, RootProcessId);
    while (i < Client->SubscriptionCount)
    {
        if (Client->Subscriptions[i].ProcessId == RootProcessId)
        {
            ControllerRemoveSubscriptionAtLocked(Client, i);
            changed = TRUE;
            ControllerLog("[IPC] launch failure subscription removed clientPid=%lu targetPid=%lu\n", Client->ProcessId,
                          RootProcessId);
            continue;
        }
        i += 1;
    }

    if (changed)
    {
        ControllerMarkDriverSubscriptionsDirty();
    }
    return changed;
}

static VOID ControllerRecoverRuntimeAfterLaunchFailure(_In_ DWORD LaunchError, _In_ DWORD RootProcessId)
{
    static const DWORD recoveryMask = BK_RUNTIME_FLAG_ANTI_VIRTUALIZATION | BK_RUNTIME_FLAG_SELF_HIDE |
                                      BK_RUNTIME_FLAG_INTERFACE_PROTECTED_ACCESS |
                                      BK_RUNTIME_FLAG_CONTROLLER_PROTECTED_ACCESS |
                                      BK_RUNTIME_FLAG_NTAPI_HOOKS_DISARMED | BK_RUNTIME_FLAG_QPC_TIMING_DISABLED;
    static const DWORD recoveryFlags = BK_RUNTIME_FLAG_NTAPI_HOOKS_DISARMED | BK_RUNTIME_FLAG_QPC_TIMING_DISABLED;

    if (!ControllerProxySetRuntimeConfig(recoveryFlags, recoveryMask))
    {
        ControllerLog("[IPC][WARN] launch failure runtime recovery failed pid=%lu launchErr=%lu err=%lu\n",
                      RootProcessId, LaunchError, GetLastError());
        return;
    }

    ControllerLog(
        "[IPC][WARN] launch failure runtime recovery disarmed hooks/protection pid=%lu launchErr=%lu flags=0x%08lX mask=0x%08lX\n",
        RootProcessId, LaunchError, recoveryFlags, recoveryMask);
}

static DWORD ControllerClientSetUserHookTarget(_Inout_ BK_CONTROLLER_CLIENT *Client,
                                               _In_ const BKIPC_SET_USER_HOOK_TARGET_REQUEST *Request,
                                               _Out_ BKIPC_SET_USER_HOOK_TARGET_RESPONSE *Response)
{
    WCHAR hookDllPath[BK_MAX_IMAGE_PATH_CHARS];
    BK_QUERY_PROCESS_IMAGE_RESPONSE kernelImage;
    WIN32_FILE_ATTRIBUTE_DATA hookAttrs;
    BOOL hookPathVisible = FALSE;
    ULONGLONG hookSize = 0;
    DWORD err = ERROR_SUCCESS;
    DWORD targetPid = 0;
    BOOL kernelAssured = FALSE;
    BOOL pendingLaunchArmed = FALSE;
    ULONGLONG analysisSessionId = 0;
    BK_ARM_PENDING_LAUNCH_REQUEST pendingLaunchRequest;

    if (Client == NULL || Request == NULL || Response == NULL)
    {
        return ERROR_INVALID_PARAMETER;
    }

    ZeroMemory(Response, sizeof(*Response));
    ZeroMemory(hookDllPath, sizeof(hookDllPath));
    ZeroMemory(&kernelImage, sizeof(kernelImage));

    if (!ControllerInjectionResolveHookDllPath(Request, hookDllPath, RTL_NUMBER_OF(hookDllPath)))
    {
        return GetLastError();
    }

    ControllerLog(
        "[IPC] set-user-hook-target mode=%lu flags=0x%08lX pid=%lu image=%ws subjectKind=%lu subject=%ws argsChars=%llu\n",
        Request->Mode, Request->Flags, Request->ProcessId, Request->ImagePath, Request->AnalysisSubjectKind,
        Request->AnalysisSubjectPath,
        Request->CommandLineArguments[0] != L'\0' ? (unsigned long long)wcslen(Request->CommandLineArguments) : 0ull);

    ZeroMemory(&hookAttrs, sizeof(hookAttrs));
    hookPathVisible = GetFileAttributesExW(hookDllPath, GetFileExInfoStandard, &hookAttrs);
    if (hookPathVisible)
    {
        hookSize = (((ULONGLONG)hookAttrs.nFileSizeHigh) << 32) | (ULONGLONG)hookAttrs.nFileSizeLow;
    }
    ControllerLog("[IPC] userhook resolved hook path=%ws visible=%u size=%llu\n", hookDllPath,
                  hookPathVisible ? 1u : 0u, (unsigned long long)hookSize);
    if (!hookPathVisible)
    {
        return ERROR_FILE_NOT_FOUND;
    }

    switch (Request->Mode)
    {
    case BlackbirdIpcUserHookTargetAttach:
        if (Request->AnalysisSubjectKind != BlackbirdAnalysisSubjectProcess || Request->AnalysisSubjectPath[0] != L'\0')
        {
            return ERROR_INVALID_PARAMETER;
        }
        EnterCriticalSection(&Client->Lock);
        ControllerClientClearPendingLaunchLocked(Client);
        LeaveCriticalSection(&Client->Lock);
        if (Request->ProcessId == 0)
        {
            return ERROR_INVALID_PARAMETER;
        }
        if (!ControllerClientCanMonitorPid(Client, Request->ProcessId, NULL, NULL))
        {
            err = GetLastError();
            return err == ERROR_SUCCESS ? ERROR_ACCESS_DENIED : err;
        }

        err = ControllerInjectionAttachAndVerify(Request->ProcessId, hookDllPath,
                                                 BK_CONTROLLER_INJECTION_VERIFY_TIMEOUT_MS);
        if (err != ERROR_SUCCESS)
        {
            return err;
        }

        targetPid = Request->ProcessId;
        ControllerLog("[IPC] attach target verified clientPid=%lu rootPid=%lu\n", Client->ProcessId, targetPid);
        break;

    case BlackbirdIpcUserHookTargetLaunch:
        if (Request->ImagePath[0] == L'\0' || !ControllerInjectionPathPointsToFile(Request->ImagePath))
        {
            return ERROR_FILE_NOT_FOUND;
        }
        if (Request->AnalysisSubjectKind != BlackbirdAnalysisSubjectProcess &&
            Request->AnalysisSubjectKind != BlackbirdAnalysisSubjectDll)
        {
            return ERROR_INVALID_PARAMETER;
        }
        if (Request->AnalysisSubjectKind == BlackbirdAnalysisSubjectDll && Request->AnalysisSubjectPath[0] == L'\0')
        {
            return ERROR_INVALID_PARAMETER;
        }
        if (Request->AnalysisSubjectKind == BlackbirdAnalysisSubjectProcess && Request->AnalysisSubjectPath[0] != L'\0')
        {
            return ERROR_INVALID_PARAMETER;
        }
        if (Request->AnalysisSubjectKind == BlackbirdAnalysisSubjectDll &&
            !ControllerInjectionPathPointsToFile(Request->AnalysisSubjectPath))
        {
            return ERROR_FILE_NOT_FOUND;
        }
        err = ControllerEnsureCaptureReadyForLaunch();
        if (err != ERROR_SUCCESS)
        {
            return err;
        }

        EnterCriticalSection(&Client->Lock);
        ControllerClientArmPendingLaunchLocked(Client, Request->ImagePath, Request->AnalysisSubjectKind,
                                               Request->AnalysisSubjectPath);
        LeaveCriticalSection(&Client->Lock);

        if (!ControllerBuildPendingLaunchRequest(Request->ImagePath, Request->AnalysisSubjectKind,
                                                 Request->AnalysisSubjectPath, BK_CONTROLLER_DRIVER_STREAM_MASK,
                                                 &pendingLaunchRequest))
        {
            EnterCriticalSection(&Client->Lock);
            ControllerClientClearPendingLaunchLocked(Client);
            LeaveCriticalSection(&Client->Lock);
            return ERROR_INVALID_PARAMETER;
        }

        if (ControllerProxyArmPendingLaunch(&pendingLaunchRequest))
        {
            pendingLaunchArmed = TRUE;
        }
        else
        {
            err = GetLastError();
        }
        if (!pendingLaunchArmed)
        {
            EnterCriticalSection(&Client->Lock);
            ControllerClientClearPendingLaunchLocked(Client);
            LeaveCriticalSection(&Client->Lock);
            return err == ERROR_SUCCESS ? ERROR_DEVICE_NOT_CONNECTED : err;
        }

        err = ControllerInjectionLaunchAndVerify(Client->Pipe, Request, hookDllPath,
                                                 BK_CONTROLLER_INJECTION_VERIFY_TIMEOUT_MS, &targetPid);
        if (err != ERROR_SUCCESS)
        {
            BOOL subscriptionsChanged = FALSE;

            if (pendingLaunchArmed)
            {
                ControllerClearDriverPendingLaunchBestEffort("userhook-launch-failed");
            }

            EnterCriticalSection(&Client->Lock);
            ControllerClientClearPendingLaunchLocked(Client);
            if (targetPid != 0)
            {
                subscriptionsChanged = ControllerClientDropLaunchSubscriptionsLocked(Client, targetPid);
            }
            LeaveCriticalSection(&Client->Lock);

            if (subscriptionsChanged)
            {
                (void)ControllerApplyDriverSubscriptionsIfDirty();
            }
            if (targetPid != 0)
            {
                ControllerRecoverRuntimeAfterLaunchFailure(err, targetPid);
            }
            return err;
        }

        EnterCriticalSection(&Client->Lock);
        ControllerClientPrimePendingLaunchPidLocked(Client, targetPid);
        analysisSessionId = ControllerClientBeginAnalysisSessionLocked(Client, targetPid, TRUE);
        LeaveCriticalSection(&Client->Lock);
        ControllerLog("[IPC] analysis session started clientPid=%lu sessionId=%llu rootPid=%lu launchOwned=1 "
                      "mode=launch\n",
                      Client->ProcessId, (unsigned long long)analysisSessionId, targetPid);
        (void)ControllerApplyDriverSubscriptionsIfDirty();
        break;

    default:
        return ERROR_INVALID_PARAMETER;
    }

    if (targetPid != 0 && ControllerProxyQueryProcessImage(targetPid, &kernelImage))
    {
        kernelAssured = TRUE;
        (void)StringCchCopyW(Response->ImagePath, RTL_NUMBER_OF(Response->ImagePath), kernelImage.ImagePath);
    }
    else if (targetPid != 0)
    {
        BOOL driverConnected = FALSE;
        DWORD kernelErr = GetLastError();
        DWORD normalizedKernelErr = kernelErr;

        driverConnected = ControllerProxyDriverConnected();
        if (driverConnected)
        {
            if (normalizedKernelErr == ERROR_SUCCESS || normalizedKernelErr == ERROR_NO_MORE_FILES ||
                normalizedKernelErr == ERROR_BAD_LENGTH || normalizedKernelErr == ERROR_PARTIAL_COPY)
            {
                normalizedKernelErr = ERROR_NOT_FOUND;
            }

            if (Request->Mode == BlackbirdIpcUserHookTargetLaunch)
            {
                ControllerLog("[IPC][WARN] userhook kernel image probe failed pid=%lu err=%lu; continuing unassured\n",
                              targetPid, normalizedKernelErr);
            }
            else
            {
                ControllerLog(
                    "[IPC] userhook kernel image probe missed pid=%lu err=%lu (attach, pre-existing process)\n",
                    targetPid, normalizedKernelErr);
            }
        }
    }

    Response->ProcessId = targetPid;
    Response->Status = kernelAssured ? 1 : 0;
    Response->AnalysisSubjectKind = Request->AnalysisSubjectKind;
    if (!kernelAssured && Request->Mode == BlackbirdIpcUserHookTargetLaunch && Request->ImagePath[0] != L'\0')
    {
        (void)StringCchCopyW(Response->ImagePath, RTL_NUMBER_OF(Response->ImagePath), Request->ImagePath);
    }
    else if (!kernelAssured && targetPid != 0)
    {
        HANDLE queryHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, targetPid);
        if (queryHandle != NULL)
        {
            DWORD imageChars = (DWORD)RTL_NUMBER_OF(Response->ImagePath);
            if (!QueryFullProcessImageNameW(queryHandle, 0, Response->ImagePath, &imageChars))
            {
                Response->ImagePath[0] = L'\0';
            }
            CloseHandle(queryHandle);
        }
    }

    if (Request->AnalysisSubjectKind == BlackbirdAnalysisSubjectDll && Request->AnalysisSubjectPath[0] != L'\0')
    {
        (void)StringCchCopyW(Response->AnalysisSubjectPath, RTL_NUMBER_OF(Response->AnalysisSubjectPath),
                             Request->AnalysisSubjectPath);
    }

    return ERROR_SUCCESS;
}

static PCSTR ControllerCommandName(_In_ UINT32 Command)
{
    switch (Command)
    {
    case BlackbirdIpcCommandHandshake:
        return "handshake";
    case BlackbirdIpcCommandSubscribe:
        return "subscribe";
    case BlackbirdIpcCommandUnsubscribe:
        return "unsubscribe";
    case BlackbirdIpcCommandSetPids:
        return "set-pids";
    case BlackbirdIpcCommandGetEvent:
        return "get-event";
    case BlackbirdIpcCommandGetStats:
        return "get-stats";
    case BlackbirdIpcCommandQueryProcessImage:
        return "query-process-image";
    case BlackbirdIpcCommandSetShutdownMode:
        return "set-shutdown-mode";
    case BlackbirdIpcCommandGetEtwEvent:
        return "get-etw-event";
    case BlackbirdIpcCommandOpenSharedRing:
        return "open-shared-ring";
    case BlackbirdIpcCommandPublishHookEvent:
        return "publish-hook-event";
    case BlackbirdIpcCommandSetUserHookTarget:
        return "set-user-hook-target";
    case BlackbirdIpcCommandNotifyHookReady:
        return "notify-hook-ready";
    case BlackbirdIpcCommandControlProcessExecution:
        return "control-process-execution";
    case BlackbirdIpcCommandSetRuntimeConfig:
        return "set-runtime-config";
    case BlackbirdIpcCommandGetRuntimeConfig:
        return "get-runtime-config";
    case BlackbirdIpcCommandGetHealth:
        return "get-health";
    case BlackbirdIpcCommandGetDiagnostics:
        return "get-diagnostics";
    case BlackbirdIpcCommandSetQpcTimingConfig:
        return "set-qpc-timing-config";
    case BlackbirdIpcCommandGetQpcTimingState:
        return "get-qpc-timing-state";
    case BlackbirdIpcCommandQueryProcessMemory:
        return "query-process-memory";
    case BlackbirdIpcCommandRegisterInstrumentationRange:
        return "register-instrumentation-range";
    case BlackbirdIpcCommandRegisterHookPatch:
        return "register-hook-patch";
    default:
        return "unknown";
    }
}

static BOOL ControllerCommandLogsBegin(_In_ UINT32 Command)
{
    switch (Command)
    {
    case BlackbirdIpcCommandSetRuntimeConfig:
    case BlackbirdIpcCommandGetRuntimeConfig:
    case BlackbirdIpcCommandSetUserHookTarget:
    case BlackbirdIpcCommandControlProcessExecution:
    case BlackbirdIpcCommandQueryProcessImage:
    case BlackbirdIpcCommandQueryProcessMemory:
        return TRUE;
    default:
        return FALSE;
    }
}

static DWORD ControllerHandleClientCommand(_Inout_ BK_CONTROLLER_CLIENT *Client, _In_ const BKIPC_PACKET *Request,
                                           _Out_ BKIPC_PACKET *Response)
{
    DWORD err = ERROR_SUCCESS;

    ControllerPrepareResponse(Request, Response);

    if (!ControllerCommandAllowedForRole(Client->Role, Request->Command))
    {
        err = ERROR_ACCESS_DENIED;
        goto Complete;
    }

    switch (Request->Command)
    {
    case BlackbirdIpcCommandHandshake:
        if (Client->Role == BkctlrClientRoleHook)
        {
            (void)InterlockedOr(&Client->HookReadyMask, (LONG)BKIPC_HOOK_READY_FLAG_IPC_CONNECTED);
            Client->HookReadyTick = GetTickCount64();
        }
        Response->Payload.HandshakeResponse.NegotiatedVersion = BKIPC_VERSION;
        Response->Payload.HandshakeResponse.Capabilities = BKIPC_CAP_DRIVER_PROXY | BKIPC_CAP_SHARED_RING |
                                                           BKIPC_CAP_USER_HOOK_INGEST | BKIPC_CAP_USER_HOOK_READY |
                                                           BKIPC_CAP_DRIVER_DIAGNOSTICS | BKIPC_CAP_QPC_TIMING;
        Response->Payload.HandshakeResponse.ThreatIntelEnabled = 0u;
        Response->Payload.HandshakeResponse.Reserved = 0u;
        break;
    case BlackbirdIpcCommandSubscribe:
        err = ControllerClientSubscribe(Client, &Request->Payload.SubscribeRequest);
        break;
    case BlackbirdIpcCommandUnsubscribe:
        err = ControllerClientUnsubscribe(Client, &Request->Payload.UnsubscribeRequest);
        break;
    case BlackbirdIpcCommandSetPids:
        err = ControllerClientSetPids(Client, &Request->Payload.SetPidsRequest);
        break;
    case BlackbirdIpcCommandGetEvent:
        err = ControllerClientGetEvent(Client, Request->Payload.GetEventRequest.TimeoutMs,
                                       &Response->Payload.EventRecord);
        break;
    case BlackbirdIpcCommandGetStats:
        err = ControllerClientGetStats(Client, &Response->Payload.StatsResponse);
        break;
    case BlackbirdIpcCommandQueryProcessImage:
        if (Request->Payload.QueryProcessImageRequest.ProcessId == 0)
        {
            err = ERROR_INVALID_PARAMETER;
            break;
        }
        if (!ControllerClientCanMonitorPid(Client, Request->Payload.QueryProcessImageRequest.ProcessId, NULL, NULL))
        {
            err = GetLastError();
            if (err == ERROR_SUCCESS)
            {
                err = ERROR_ACCESS_DENIED;
            }
            break;
        }
        if (!ControllerProxyQueryProcessImage(Request->Payload.QueryProcessImageRequest.ProcessId,
                                              &Response->Payload.QueryProcessImageResponse))
        {
            err = GetLastError();
            if (err == ERROR_SUCCESS)
            {
                err = ERROR_NOT_FOUND;
            }
        }
        break;
    case BlackbirdIpcCommandSetShutdownMode:
        if (!ControllerProxySetShutdownMode())
        {
            err = GetLastError();
        }
        break;
    case BlackbirdIpcCommandControlProcessExecution:
        if (Request->Payload.ControlProcessExecutionRequest.ProcessId == 0)
        {
            err = ERROR_INVALID_PARAMETER;
            break;
        }
        if (!ControllerProxyControlProcessExecution(Request->Payload.ControlProcessExecutionRequest.ProcessId,
                                                    Request->Payload.ControlProcessExecutionRequest.Suspend != 0))
        {
            err = GetLastError();
            if (err == ERROR_SUCCESS)
            {
                err = ERROR_GEN_FAILURE;
            }
        }
        break;
    case BlackbirdIpcCommandSetRuntimeConfig:
        if (!ControllerProxySetRuntimeConfig(Request->Payload.SetRuntimeConfigRequest.Flags,
                                             Request->Payload.SetRuntimeConfigRequest.Mask))
        {
            err = GetLastError();
        }
        break;
    case BlackbirdIpcCommandGetRuntimeConfig:
        if (!ControllerProxyGetRuntimeConfig(&Response->Payload.RuntimeConfigResponse))
        {
            err = GetLastError();
        }
        break;
    case BlackbirdIpcCommandSetQpcTimingConfig:
        if (!ControllerProxySetQpcTimingConfig(&Request->Payload.QpcTimingConfig))
        {
            err = GetLastError();
        }
        break;
    case BlackbirdIpcCommandGetQpcTimingState:
        if (!ControllerProxyGetQpcTimingState(&Response->Payload.QpcTimingState))
        {
            err = GetLastError();
        }
        break;
    case BlackbirdIpcCommandGetHealth:
        if (!ControllerProxyGetHealth(&Response->Payload.HealthResponse))
        {
            err = GetLastError();
        }
        break;
    case BlackbirdIpcCommandGetDiagnostics:
        if (!ControllerProxyGetDiagnostics(&Response->Payload.DiagnosticsResponse))
        {
            err = GetLastError();
        }
        break;
    case BlackbirdIpcCommandGetEtwEvent:
        err = ControllerClientGetEtwEvent(Client, Request->Payload.GetEventRequest.TimeoutMs,
                                          &Response->Payload.EtwEvent);
        break;
    case BlackbirdIpcCommandOpenSharedRing:
        err = ControllerClientOpenSharedRing(Client, &Request->Payload.OpenSharedRingRequest,
                                             &Response->Payload.OpenSharedRingResponse);
        break;
    case BlackbirdIpcCommandPublishHookEvent:
        err = ControllerClientPublishHookEvent(Client, &Request->Payload.HookEvent);
        break;
    case BlackbirdIpcCommandSetUserHookTarget:
        err = ControllerClientSetUserHookTarget(Client, &Request->Payload.SetUserHookTargetRequest,
                                                &Response->Payload.SetUserHookTargetResponse);
        break;
    case BlackbirdIpcCommandNotifyHookReady:
        err = ControllerClientNotifyHookReady(Client, &Request->Payload.NotifyHookReadyRequest,
                                              &Response->Payload.NotifyHookReadyResponse);
        break;
    case BlackbirdIpcCommandRegisterInstrumentationRange:
    {
        const BKIPC_REGISTER_INSTRUMENTATION_RANGE_REQUEST *range =
            &Request->Payload.RegisterInstrumentationRangeRequest;

        if (range->BaseAddress == 0 || range->RegionSize == 0)
        {
            err = ERROR_INVALID_PARAMETER;
            break;
        }

        EnterCriticalSection(&Client->Lock);
        if (Client->OwnedRangeCount < BK_CONTROLLER_MAX_OWNED_RANGES)
        {
            BK_CONTROLLER_OWNED_RANGE *slot = &Client->OwnedRanges[Client->OwnedRangeCount];
            slot->BaseAddress = range->BaseAddress;
            slot->RegionSize = range->RegionSize;
            slot->Flags = range->Flags;
            (void)StringCchCopyA(slot->Tag, RTL_NUMBER_OF(slot->Tag), range->Tag);
            Client->OwnedRangeCount += 1;
            err = ERROR_SUCCESS;
        }
        else
        {
            err = ERROR_INSUFFICIENT_BUFFER;
        }
        LeaveCriticalSection(&Client->Lock);

        if (err == ERROR_SUCCESS)
        {
            if (!ControllerProxyRegisterInstrumentationRange(Client->ProcessId, range->BaseAddress, range->RegionSize,
                                                             range->Flags, range->Tag))
            {
                DWORD kernelErr = GetLastError();
                ControllerLog(
                    "[IPC] instrumentation-range kernel registration failed pid=%lu base=0x%llX size=0x%llX win32=%lu\n",
                    Client->ProcessId, (unsigned long long)range->BaseAddress, (unsigned long long)range->RegionSize,
                    kernelErr);
            }
            ControllerLog("[IPC] instrumentation-range registered pid=%lu base=0x%llX size=0x%llX flags=0x%X tag=%s\n",
                          Client->ProcessId, (unsigned long long)range->BaseAddress,
                          (unsigned long long)range->RegionSize, (unsigned int)range->Flags,
                          range->Tag[0] != '\0' ? range->Tag : "<untagged>");
        }
        break;
    }
    case BlackbirdIpcCommandQueryProcessMemory:
    {
        HANDLE hClientProc;
        HANDLE hDupSection = NULL;
        DWORD bytesRead = 0;

        if (Request->Payload.QueryMemoryRequest.ProcessId == 0 ||
            Request->Payload.QueryMemoryRequest.RequestedSize == 0)
        {
            err = ERROR_INVALID_PARAMETER;
            break;
        }
        if (!ControllerClientCanMonitorPid(Client, Request->Payload.QueryMemoryRequest.ProcessId, NULL, NULL))
        {
            err = GetLastError();
            if (err == ERROR_SUCCESS)
            {
                err = ERROR_ACCESS_DENIED;
            }
            break;
        }
        hClientProc = OpenProcess(PROCESS_DUP_HANDLE, FALSE, Client->ProcessId);
        if (hClientProc == NULL)
        {
            err = GetLastError();
            break;
        }
        if (!ControllerProxyReadProcessMemory(
                Request->Payload.QueryMemoryRequest.ProcessId, Request->Payload.QueryMemoryRequest.BaseAddress,
                Request->Payload.QueryMemoryRequest.RequestedSize, hClientProc, &hDupSection, &bytesRead))
        {
            err = GetLastError();
            if (err == ERROR_SUCCESS)
            {
                err = ERROR_GEN_FAILURE;
            }
            CloseHandle(hClientProc);
            break;
        }
        CloseHandle(hClientProc);
        Response->Payload.QueryMemoryResponse.Status = 0;
        Response->Payload.QueryMemoryResponse.BytesRead = bytesRead;
        Response->Payload.QueryMemoryResponse.SectionHandle = (UINT64)(ULONG_PTR)hDupSection;
        break;
    }
    case BlackbirdIpcCommandRegisterHookPatch:
    {
        const BKIPC_REGISTER_HOOK_PATCH_REQUEST *patch = &Request->Payload.RegisterHookPatchRequest;
        if (patch->PatchAddress == 0 || patch->PatchSize == 0 || patch->OriginalSize == 0 ||
            patch->PatchSize > BK_MAX_HOOK_PATCH_BYTES || patch->OriginalSize > BK_MAX_HOOK_PATCH_BYTES)
        {
            err = ERROR_INVALID_PARAMETER;
            break;
        }

        if (!ControllerProxyRegisterHookPatch(Client->ProcessId, patch->PatchAddress, patch->PatchSize,
                                              patch->OriginalBytes, patch->OriginalSize, patch->Flags, patch->Tag))
        {
            err = GetLastError();
            if (err == ERROR_SUCCESS)
            {
                err = ERROR_GEN_FAILURE;
            }
            ControllerLog("[IPC] hook-patch kernel registration failed pid=%lu address=0x%llX size=%lu win32=%lu\n",
                          Client->ProcessId, (unsigned long long)patch->PatchAddress, (unsigned long)patch->PatchSize,
                          err);
            break;
        }

        ControllerLog("[IPC] hook-patch registered pid=%lu address=0x%llX size=%lu tag=%s\n", Client->ProcessId,
                      (unsigned long long)patch->PatchAddress, (unsigned long)patch->PatchSize,
                      patch->Tag[0] != '\0' ? patch->Tag : "<untagged>");
        break;
    }
    default:
        err = ERROR_INVALID_FUNCTION;
        break;
    }

Complete:
    Response->Status = err;
    if (Request->Command != BlackbirdIpcCommandGetEvent && Request->Command != BlackbirdIpcCommandGetEtwEvent &&
        Request->Command != BlackbirdIpcCommandPublishHookEvent && Request->Command != BlackbirdIpcCommandGetStats &&
        Request->Command != BlackbirdIpcCommandGetHealth && Request->Command != BlackbirdIpcCommandGetDiagnostics &&
        Request->Command != BlackbirdIpcCommandGetQpcTimingState)
    {
        ControllerLog("[IPC] cmd=%s seq=%lu role=%lu clientPid=%lu session=%lu status=%lu\n",
                      ControllerCommandName(Request->Command), Request->Sequence, Client->Role, Client->ProcessId,
                      Client->SessionId, err);
    }
    else if (err != ERROR_SUCCESS && err != ERROR_NO_MORE_ITEMS)
    {
        ControllerLog("[IPC][WARN] cmd=%s seq=%lu role=%lu clientPid=%lu session=%lu status=%lu\n",
                      ControllerCommandName(Request->Command), Request->Sequence, Client->Role, Client->ProcessId,
                      Client->SessionId, err);
    }
    return err;
}
VOID ControllerDetachClient(_Inout_ BK_CONTROLLER_CLIENT *Client)
{
    PBK_CONTROLLER_CLIENT *pp;
    BK_CONTROLLER_ANALYSIS_TEARDOWN teardown;

    if (Client == NULL)
    {
        return;
    }

    ZeroMemory(&teardown, sizeof(teardown));

    EnterCriticalSection(g_ClientListLock.get());
    pp = &g_ClientList;
    while (*pp != NULL)
    {
        if (*pp == Client)
        {
            Client->Detached = 1;
            *pp = Client->Next;
            if (Client->SlotIndex != BK_CONTROLLER_INVALID_SLOT)
            {
                ControllerReleaseClientSlotLocked(Client->SlotIndex);
                Client->SlotIndex = BK_CONTROLLER_INVALID_SLOT;
            }
            if (g_ClientCount > 0)
            {
                g_ClientCount -= 1;
            }
            ControllerLog("[IPC] active clients=%lu\n", g_ClientCount);
            break;
        }
        pp = &(*pp)->Next;
    }
    ControllerRebuildPidIndexLocked(NULL);
    LeaveCriticalSection(g_ClientListLock.get());

    (void)ControllerRequestDriverSubscriptionApply(FALSE, 0);

    EnterCriticalSection(&Client->Lock);
    ControllerClientStopAnalysisLocked(Client, &teardown);
    LeaveCriticalSection(&Client->Lock);

    ControllerCompleteAnalysisTeardown(Client, &teardown, "client-disconnect");
    if (teardown.HadState)
    {
        if (teardown.HadAnalysisLease || teardown.SubscriptionCount != 0)
        {
            (void)ControllerRequestDriverSubscriptionApply(FALSE, 0);
        }
        ControllerTerminateLaunchOwnedTeardown(&teardown, "client-disconnect");
    }
}
DWORD WINAPI ControllerClientThreadProc(_In_ LPVOID Context)
{
    BK_CONTROLLER_CLIENT *client = (BK_CONTROLLER_CLIENT *)Context;
    BKIPC_PACKET *request = NULL;
    BKIPC_PACKET *response = NULL;
    DWORD disconnectErr = ERROR_SUCCESS;

    if (client == NULL)
    {
        return 1;
    }

    request = (BKIPC_PACKET *)calloc(1, sizeof(*request));
    response = (BKIPC_PACKET *)calloc(1, sizeof(*response));
    if (request == NULL || response == NULL)
    {
        free(request);
        free(response);
        return ERROR_OUTOFMEMORY;
    }

    for (;;)
    {
        DWORD bytesRead = 0;
        DWORD bytesWritten = 0;
        BOOL ok;

        if (ControllerShouldStop())
        {
            break;
        }

        ZeroMemory(request, sizeof(*request));
        ok = ReadFile(client->Pipe, request, sizeof(*request), &bytesRead, NULL);
        if (!ok || bytesRead != sizeof(*request))
        {
            disconnectErr = GetLastError();
            break;
        }
        if (!ControllerValidatePacket(request, BlackbirdIpcPacketRequest))
        {
            disconnectErr = ERROR_BAD_FORMAT;
            break;
        }

        {
            DWORD commandErr;
            ULONGLONG commandStartTick = GetTickCount64();

            if (ControllerCommandLogsBegin(request->Command))
            {
                ControllerLog("[IPC] cmd-begin=%s seq=%lu role=%lu clientPid=%lu session=%lu\n",
                              ControllerCommandName(request->Command), request->Sequence, client->Role,
                              client->ProcessId, client->SessionId);
            }

            commandErr = ControllerHandleClientCommand(client, request, response);
            if ((GetTickCount64() - commandStartTick) >= 1000)
            {
                ControllerLog("[IPC][WARN] cmd-slow=%s seq=%lu role=%lu clientPid=%lu session=%lu elapsedMs=%llu "
                              "status=%lu\n",
                              ControllerCommandName(request->Command), request->Sequence, client->Role,
                              client->ProcessId, client->SessionId,
                              (unsigned long long)(GetTickCount64() - commandStartTick), commandErr);
            }
        }
        ok = WriteFile(client->Pipe, response, sizeof(*response), &bytesWritten, NULL);
        if (!ok || bytesWritten != sizeof(*response))
        {
            disconnectErr = GetLastError();
            break;
        }
    }

    ControllerDetachClient(client);
    if (client->Pipe != INVALID_HANDLE_VALUE)
    {
        (void)DisconnectNamedPipe(client->Pipe);
        CloseHandle(client->Pipe);
        client->Pipe = INVALID_HANDLE_VALUE;
    }
    if (client->DispatchIdleEvent != NULL)
    {
        DWORD dispatchWait = WaitForSingleObject(client->DispatchIdleEvent, 3000);
        if (dispatchWait != WAIT_OBJECT_0)
        {
            LONG refs = InterlockedCompareExchange(&client->DispatchRefCount, 0, 0);
            ControllerLog("[IPC][WARN] client quarantine pid=%lu session=%lu dispatchRefs=%ld wait=%lu; "
                          "detached object left alive to avoid dispatch use-after-free\n",
                          client->ProcessId, client->SessionId, refs, dispatchWait);
            free(request);
            free(response);
            return 0;
        }
    }
    free(request);
    free(response);
    EnterCriticalSection(&client->Lock);
    ControllerLog("[IPC] client disconnected pid=%lu session=%lu subscriptions=%lu queueDepth=%lu dropped=%lu "
                  "etwQueueDepth=%lu etwDropped=%lu lastErr=%lu\n",
                  client->ProcessId, client->SessionId, client->SubscriptionCount, client->QueueDepth,
                  client->DroppedEvents, client->EtwQueueDepth, client->EtwDroppedEvents, disconnectErr);
    client->SubscriptionCount = 0;
    ControllerClientDestroySharedRingsLocked(client);
    ControllerClientFreeQueueLocked(client);
    ControllerClientFreeEtwQueueLocked(client);
    LeaveCriticalSection(&client->Lock);
    if (client->IoctlQueueDataEvent != NULL)
    {
        (void)CloseHandle(client->IoctlQueueDataEvent);
        client->IoctlQueueDataEvent = NULL;
    }
    if (client->EtwQueueDataEvent != NULL)
    {
        (void)CloseHandle(client->EtwQueueDataEvent);
        client->EtwQueueDataEvent = NULL;
    }
    if (client->DispatchIdleEvent != NULL)
    {
        (void)CloseHandle(client->DispatchIdleEvent);
        client->DispatchIdleEvent = NULL;
    }
    DeleteCriticalSection(&client->Lock);
    if (client->IoctlNodeSlab != NULL)
    {
        free(client->IoctlNodeSlab);
        client->IoctlNodeSlab = NULL;
        client->IoctlNodeFreeHead = NULL;
    }
    if (client->EtwNodeSlab != NULL)
    {
        free(client->EtwNodeSlab);
        client->EtwNodeSlab = NULL;
        client->EtwNodeFreeHead = NULL;
    }
    free(client);
    return 0;
}
BOOL ControllerCreatePipeSecurity(_In_ DWORD ClientRole, _Out_ PSECURITY_ATTRIBUTES SecurityAttributes,
                                  _Outptr_ PSECURITY_DESCRIPTOR *SecurityDescriptor)
{
    BOOL ok;
    PCWSTR sddl = NULL;

    if (SecurityAttributes == NULL || SecurityDescriptor == NULL)
    {
        return FALSE;
    }

    *SecurityDescriptor = NULL;
    ZeroMemory(SecurityAttributes, sizeof(*SecurityAttributes));

    switch (ClientRole)
    {
    case BkctlrClientRoleHook:
        sddl = L"D:P(A;;GA;;;SY)(A;;GRGW;;;IU)";
        break;
    case BkctlrClientRoleControl:
        sddl = L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)";
        break;
    default:
        sddl = L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)";
        break;
    }

    ok = ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, SecurityDescriptor, NULL);
    if (!ok || *SecurityDescriptor == NULL)
    {
        return FALSE;
    }

    SecurityAttributes->nLength = sizeof(*SecurityAttributes);
    SecurityAttributes->lpSecurityDescriptor = *SecurityDescriptor;
    SecurityAttributes->bInheritHandle = FALSE;
    return TRUE;
}
