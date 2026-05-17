#pragma once

#include <cstddef>
#include <cstdint>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

enum class ModuleHookOperation : std::uint32_t
{
    LoadLibraryA = 0,
    LoadLibraryW = 1,
    LoadLibraryExA = 2,
    LoadLibraryExW = 3,
    LdrLoadDll = 4,
    RtlAddFunctionTable = 5,
    RtlInstallFunctionTableCallback = 6,
    RtlDeleteFunctionTable = 7,
    CoInitializeEx = 8,
    CoInitializeSecurity = 9,
    CoCreateInstance = 10,
    EventRegister = 11,
    EventUnregister = 12,
    StartTraceW = 13,
    EnableTraceEx2 = 14,
    CreateJobObjectW = 15,
    OpenJobObjectW = 16,
    AssignProcessToJobObject = 17,
    SetInformationJobObject = 18,
    LsaConnectUntrusted = 19,
    LsaLookupAuthenticationPackage = 20,
    LsaCallAuthenticationPackage = 21,
    AcquireCredentialsHandleA = 22,
    AcquireCredentialsHandleW = 23,
    InitializeSecurityContextA = 24,
    InitializeSecurityContextW = 25,
    AcceptSecurityContext = 26,
    CredReadA = 27,
    CredReadW = 28,
    CredEnumerateA = 29,
    CredEnumerateW = 30,
    CredReadDomainCredentialsA = 31,
    CredReadDomainCredentialsW = 32,
    LsaOpenPolicy = 33,
    LsaQueryInformationPolicy = 34,
    VaultEnumerateVaults = 35,
    VaultOpenVault = 36,
    VaultEnumerateItems = 37,
    VaultGetItem = 38,
    CryptUnprotectData = 39,
    NCryptUnprotectSecret = 40,
    NCryptOpenStorageProvider = 41,
    NCryptOpenKey = 42,
    NCryptDecrypt = 43,
    CfAbortOperation = 44,
    CfRegisterSyncRoot = 45,
    CfConnectSyncRoot = 46,
    CfCreatePlaceholders = 47
};

struct ModuleHookContext
{
    ModuleHookOperation Operation;
    const char *FunctionName;
    const char *SourceModule;
    void *Caller;
    HMODULE ModuleHandle;
    const void *NameBuffer;
    std::size_t NameLength;
    std::uint64_t Args[4];
};

using ModuleHookCallback = void (*)(const ModuleHookContext &context) noexcept;

enum class ModuleHookInitFaultCode : std::uint32_t
{
    None = 0,
    ModuleMissing,
    ExportMissing,
    ExportOutsideImage,
    ExportRedirectedOutsideImage,
    PatchInstallFailed,
};

struct ModuleHookInitFault
{
    ModuleHookInitFaultCode Code;
    const wchar_t *ModuleName;
    const char *ExportName;
    void *Address;
    void *RedirectTarget;
    std::uint8_t Sample[16];
};

bool KeSetModuleHook(ModuleHookCallback callback) noexcept;
void KeRemoveModuleHook() noexcept;
void KeRefreshModuleHooks(HMODULE moduleHandle) noexcept;

bool KeCheckModuleHookIntegrity(std::uint32_t *mismatchCount) noexcept;
bool KeGetLastModuleHookInitFault(ModuleHookInitFault *faultOut) noexcept;

struct ModuleHookPatchInfo
{
    void *PatchAddress;
    std::size_t PatchSize;
    std::uint8_t OriginalBytes[16];
    const char *HookName;
    std::uint32_t Flags;
};

std::size_t KeCollectModuleHookPatchInfos(_Out_writes_(capacity) ModuleHookPatchInfo *out,
                                          _In_ std::size_t capacity) noexcept;
