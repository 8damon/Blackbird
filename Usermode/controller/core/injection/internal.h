#ifndef BK_CONTROLLER_INJECTION_INTERNAL_H
#define BK_CONTROLLER_INJECTION_INTERNAL_H

#include "injection.h"

#include <stdlib.h>
#include <sddl.h>
#include <strsafe.h>
#include <tlhelp32.h>
#include <wtsapi32.h>
#include <wchar.h>
#include <algorithm>
#include <string>
#include <vector>

DWORD ControllerWaitForHookReady(_In_ DWORD ProcessId);
VOID ControllerLog(_In_z_ _Printf_format_string_ PCSTR Format, ...);
VOID ControllerDispatchEtwEvent(_In_ const BKIPC_ETW_EVENT *Event);
BOOL ControllerDropProcessSubscriptions(_In_ DWORD ProcessId, _In_z_ PCSTR Reason);

using NtSuspendProcessFn = LONG(NTAPI *)(HANDLE ProcessHandle);
using RtlNtStatusToDosErrorFn = ULONG(WINAPI *)(LONG Status);
using CreateEnvironmentBlockFn = BOOL(WINAPI *)(LPVOID *lpEnvironment, HANDLE hToken, BOOL bInherit);
using DestroyEnvironmentBlockFn = BOOL(WINAPI *)(LPVOID lpEnvironment);

typedef struct _BB_UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} BB_UNICODE_STRING, *PBB_UNICODE_STRING;

typedef enum _BB_PS_CREATE_STATE
{
    BbPsCreateInitialState = 0,
    BbPsCreateFailOnFileOpen,
    BbPsCreateFailOnSectionCreate,
    BbPsCreateFailExeFormat,
    BbPsCreateFailMachineMismatch,
    BbPsCreateFailExeName,
    BbPsCreateSuccess
} BB_PS_CREATE_STATE;

typedef struct _BB_PS_CREATE_INFO
{
    SIZE_T Size;
    BB_PS_CREATE_STATE State;
    union
    {
        struct
        {
            ULONG InitFlags;
            ACCESS_MASK AdditionalFileAccess;
        } InitState;
        struct
        {
            HANDLE FileHandle;
        } FailSection;
        struct
        {
            USHORT DllCharacteristics;
        } ExeFormat;
        struct
        {
            HANDLE IFEOKey;
        } ExeName;
        struct
        {
            ULONG OutputFlags;
            HANDLE FileHandle;
            HANDLE SectionHandle;
            ULONGLONG UserProcessParametersNative;
            ULONG UserProcessParametersWow64;
            ULONG CurrentParameterFlags;
            ULONGLONG PebAddressNative;
            ULONG PebAddressWow64;
            ULONGLONG ManifestAddress;
            ULONG ManifestSize;
        } SuccessState;
    };
} BB_PS_CREATE_INFO, *PBB_PS_CREATE_INFO;

typedef struct _BB_PS_ATTRIBUTE
{
    ULONG_PTR Attribute;
    SIZE_T Size;
    union
    {
        ULONG_PTR Value;
        PVOID ValuePtr;
    };
    PSIZE_T ReturnLength;
} BB_PS_ATTRIBUTE, *PBB_PS_ATTRIBUTE;

typedef struct _BB_PS_ATTRIBUTE_LIST
{
    SIZE_T TotalLength;
    BB_PS_ATTRIBUTE Attributes[4];
} BB_PS_ATTRIBUTE_LIST, *PBB_PS_ATTRIBUTE_LIST;

using NtCreateUserProcessFn = LONG(NTAPI *)(PHANDLE ProcessHandle, PHANDLE ThreadHandle,
                                            ACCESS_MASK ProcessDesiredAccess, ACCESS_MASK ThreadDesiredAccess,
                                            PVOID ProcessObjectAttributes, PVOID ThreadObjectAttributes,
                                            ULONG ProcessFlags, ULONG ThreadFlags, PVOID ProcessParameters,
                                            PBB_PS_CREATE_INFO CreateInfo, PBB_PS_ATTRIBUTE_LIST AttributeList);
using RtlCreateProcessParametersExFn = LONG(NTAPI *)(PVOID *ProcessParameters, PBB_UNICODE_STRING ImagePathName,
                                                     PBB_UNICODE_STRING DllPath, PBB_UNICODE_STRING CurrentDirectory,
                                                     PBB_UNICODE_STRING CommandLine, PVOID Environment,
                                                     PBB_UNICODE_STRING WindowTitle, PBB_UNICODE_STRING DesktopInfo,
                                                     PBB_UNICODE_STRING ShellInfo, PBB_UNICODE_STRING RuntimeData,
                                                     ULONG Flags);
using RtlDestroyProcessParametersFn = VOID(NTAPI *)(PVOID ProcessParameters);
using RtlDosPathNameToNtPathName_U_WithStatusFn = LONG(NTAPI *)(PCWSTR DosPathName, PBB_UNICODE_STRING NtPathName,
                                                                PWSTR *FilePart, PVOID RelativeName);
using RtlFreeUnicodeStringFn = VOID(NTAPI *)(PBB_UNICODE_STRING UnicodeString);

#define BB_RTL_USER_PROC_PARAMS_NORMALIZED 0x00000001ul
#define BB_PROCESS_CREATE_FLAGS_INHERIT_HANDLES 0x00000004ul
#define BB_THREAD_CREATE_FLAGS_CREATE_SUSPENDED 0x00000001ul
#define BB_PS_ATTRIBUTE_INPUT 0x00020000ull
#define BB_PS_ATTRIBUTE_ADDITIVE 0x00040000ull
#define BB_PS_ATTRIBUTE_PARENT_PROCESS (BB_PS_ATTRIBUTE_INPUT | BB_PS_ATTRIBUTE_ADDITIVE | 0ull)
#define BB_PS_ATTRIBUTE_TOKEN (BB_PS_ATTRIBUTE_INPUT | BB_PS_ATTRIBUTE_ADDITIVE | 2ull)
#define BB_PS_ATTRIBUTE_IMAGE_NAME (BB_PS_ATTRIBUTE_INPUT | 5ull)
#define BB_PS_ATTRIBUTE_HANDLE_LIST (BB_PS_ATTRIBUTE_INPUT | 11ull)

DWORD ControllerInjectionNtStatusToWin32(_In_ LONG Status);
VOID ControllerInjectionInitUnicodeString(_Out_ PBB_UNICODE_STRING String, _In_opt_z_ PCWSTR Buffer);
VOID ControllerInjectionLogSr71Diagnostics(_In_ DWORD ProcessId);
PCWSTR ControllerInjectionFileNameFromPath(_In_z_ PCWSTR Path);
DWORD ControllerInjectionSuspendProcessHandle(_In_ HANDLE ProcessHandle);

bool ControllerInjectionEnvironmentHasName(_In_opt_z_ PCWSTR Overrides, _In_z_ PCWSTR Name) noexcept;
BOOL ControllerInjectionBuildDeferredLaunchGateEventName(_Out_writes_z_(EventNameChars) PWSTR EventName,
                                                         _In_ size_t EventNameChars);
HANDLE ControllerInjectionCreateDeferredLaunchGateEvent(_In_z_ PCWSTR EventName, _In_ DWORD ProcessId);
BOOL ControllerInjectionBuildEnvironmentBlock(_In_opt_ HANDLE UserToken,
                                              _In_reads_or_z_(OverrideChars) PCWSTR Overrides,
                                              _In_ BOOL EnableLaunchGate, _In_ BOOL DeferLaunchGateRelease,
                                              _In_opt_z_ PCWSTR LaunchGateEventName,
                                              _Outptr_result_nullonfailure_ PWSTR *EnvironmentBlockOut);
DWORD ControllerInjectionMapPriorityClass(_In_ UINT32 PriorityClass);
BOOL ControllerInjectionBuildLaunchCommandLine(_In_z_ PCWSTR ImagePath, _In_opt_z_ PCWSTR Arguments,
                                               _Out_ std::wstring *CommandLineOut);
std::vector<WCHAR> ControllerInjectionMakeMutableCommandLine(_In_ const std::wstring &CommandLine);

BOOL ControllerInjectionReadImageSubsystem(_In_z_ PCWSTR ImagePath, _Out_ USHORT *SubsystemOut);
DWORD ControllerInjectionValidateHookArchitecture(_In_ HANDLE ProcessHandle, _In_z_ PCWSTR HookDllPath);

DWORD ControllerInjectionInjectHookDllIntoProcessHandle(_In_ HANDLE ProcessHandle, _In_z_ PCWSTR HookDllPath);
DWORD ControllerInjectionQueueHookDllEarlyBirdApc(_In_ HANDLE ProcessHandle, _In_ HANDLE ThreadHandle,
                                                  _In_z_ PCWSTR HookDllPath);
BOOL ControllerInjectionIsStealthHookModule(_In_z_ PCWSTR HookDllPath);

BOOL ControllerInjectionAcquirePrimaryTokenFromProcess(_In_ DWORD ProcessId, _Out_ HANDLE *TokenOut);
BOOL ControllerInjectionAcquireActiveInteractiveUserToken(_Out_ HANDLE *TokenOut, _Out_opt_ DWORD *SessionIdOut);
BOOL ControllerInjectionApplyRequestedIntegrity(_In_ HANDLE TokenHandle, _In_ UINT32 IntegrityLevel);
BOOL ControllerInjectionEnablePrivilege(_In_z_ PCWSTR PrivilegeName);
BOOL ControllerInjectionQueryPipeClientSession(_In_ HANDLE PipeHandle, _Out_opt_ DWORD *ClientProcessIdOut,
                                               _Out_ DWORD *SessionIdOut);
BOOL ControllerInjectionEnsureTokenSession(_In_ HANDLE TokenHandle, _In_ DWORD DesiredSessionId,
                                           _Out_opt_ DWORD *OriginalSessionIdOut, _Out_opt_ DWORD *TokenSessionIdOut);

BOOL ControllerInjectionLaunchTargetProcess(_In_ HANDLE ClientPipe,
                                            _In_ const BKIPC_SET_USER_HOOK_TARGET_REQUEST *Request,
                                            _In_opt_z_ PCWSTR DeferredLaunchGateEventName,
                                            _Out_ PROCESS_INFORMATION *ProcessInformation);

#endif
