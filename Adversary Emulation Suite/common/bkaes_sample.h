#pragma once

#include "bkaes_common.h"

#include <evntprov.h>
#include <evntrace.h>
#include <iphlpapi.h>
#include <wbemidl.h>
#include <winsvc.h>
#include <winternl.h>
#include <ws2tcpip.h>

#include <algorithm>
#include <cstdint>
#include <string>

using NtQueryVirtualMemoryFn = NTSTATUS(NTAPI *)(HANDLE, PVOID, ULONG, PVOID,
                                                 SIZE_T, PSIZE_T);
using NtReadVirtualMemoryFn = NTSTATUS(NTAPI *)(HANDLE, PVOID, PVOID, SIZE_T,
                                                PSIZE_T);
using NtProtectVirtualMemoryFn = NTSTATUS(NTAPI *)(HANDLE, PVOID *, PSIZE_T,
                                                   ULONG, PULONG);
using NtAllocateVirtualMemoryFn = NTSTATUS(NTAPI *)(HANDLE, PVOID *, ULONG_PTR,
                                                    PSIZE_T, ULONG, ULONG);
using NtWriteVirtualMemoryFn = NTSTATUS(NTAPI *)(HANDLE, PVOID, const VOID *,
                                                 SIZE_T, PSIZE_T);
using NtCreateThreadExFn = NTSTATUS(NTAPI *)(PHANDLE, ACCESS_MASK,
                                             POBJECT_ATTRIBUTES, HANDLE, PVOID,
                                             PVOID, ULONG, SIZE_T, SIZE_T,
                                             SIZE_T, PVOID);
using NtQueueApcThreadFn = NTSTATUS(NTAPI *)(HANDLE, PVOID, PVOID, PVOID,
                                             PVOID);
using NtOpenProcessFn = NTSTATUS(NTAPI *)(PHANDLE, ACCESS_MASK,
                                          POBJECT_ATTRIBUTES, PVOID);
using NtQueryInformationProcessFn = NTSTATUS(NTAPI *)(HANDLE, PROCESSINFOCLASS,
                                                      PVOID, ULONG, PULONG);
using NtQueryInformationThreadFn = NTSTATUS(NTAPI *)(HANDLE, ULONG, PVOID,
                                                     ULONG, PULONG);
using NtQuerySystemInformationFn = NTSTATUS(NTAPI *)(SYSTEM_INFORMATION_CLASS,
                                                     PVOID, ULONG, PULONG);
using NtGetNextThreadFn = NTSTATUS(NTAPI *)(HANDLE, HANDLE, ACCESS_MASK, ULONG,
                                            ULONG, PHANDLE);
using NtCreateSectionFn = NTSTATUS(NTAPI *)(PHANDLE, ACCESS_MASK,
                                            POBJECT_ATTRIBUTES, PLARGE_INTEGER,
                                            ULONG, ULONG, HANDLE);
using NtMapViewOfSectionFn = NTSTATUS(NTAPI *)(HANDLE, HANDLE, PVOID *,
                                               ULONG_PTR, SIZE_T,
                                               PLARGE_INTEGER, PSIZE_T, DWORD,
                                               ULONG, ULONG);

struct BkaesClientId {
  HANDLE UniqueProcess;
  HANDLE UniqueThread;
};

bool BkaesEnvFlagEnabled(const wchar_t *name);
std::wstring BkaesGetEnvString(const wchar_t *name);
void BkaesWriteAuditText(const wchar_t *fileName, const char *text);
bool BkaesOpenChildForInjection(PROCESS_INFORMATION *child, HANDLE *process);
int BkaesRunSuspendedCmdlines(const wchar_t *const *commands, size_t count);
void BkaesSetStringValue(HKEY root, const wchar_t *subkey, const wchar_t *name,
                         const wchar_t *value);
void BkaesQueryKeyValue(HKEY root, const wchar_t *subkey, const wchar_t *value);
void BkaesResolveProbeDomain(const wchar_t *host);
void BkaesQueryServicePresence(const wchar_t *serviceName);
void BkaesTryConnectLoopback(USHORT port);
std::wstring BkaesJoinPath(const std::wstring &base, const wchar_t *name);
DWORD BkaesReadFileChecksum(const std::wstring &path);

int RunDirectSyscallHandle();
int RunDirectSyscallStackTf();
int RunNtStubIntegrityCheck();
int RunInjectionChainComplete();
int RunPeInjectionWrite();
int RunSectionMapExecute();
int RunHollowingMarkChain();
int RunRemoteApcQueue();
int RunRemoteApcLoadLibrary();
int RunContextHijackTf();
int RunLoadLibraryRemoteThread();
int RunDirectSyscallInjectionChain();
int RunWow64InjectionChain();
int RunEvasionInjectionChain();
int RunLoadLibraryModuleNotify();
int RunEarlyBirdApc();
int RunTransactedHollowingMarker();
int RunSetWindowsHookEx(int argc, wchar_t **argv);
int RunSetWinEventHook(int argc, wchar_t **argv);
int RunGuiHookTarget(int argc, wchar_t **argv);
int RunPpidSpoof();
int RunPowerShellCmdlines();
int RunLolbinCmdlines();
int RunRegistryPersistenceHkcu();
int RunRegistryRecon();
int RunSecurityProductEnterpriseGeoProbes();
int RunEdrAvProductProbes();
int RunDllLoadSurface();
int RunImageLoadDoubleExtension();
int RunAntiDebugVmQueries();
int RunDynamicFunctionTable();
int RunMemoryFlipsEntropy();
int RunGuardOrderedJit();
int RunXorEntropyCycle();
int RunNetworkPatterns();
int RunBeaconLoopbackPattern();
int RunComWmiEtwJob();
int RunSensitiveCredentialHandles(int argc, wchar_t **argv);
int RunKerberosReconExtended();
int RunLpeSurface();
int RunFuzzNtapiQueries();
int RunFuzzRegistryPaths();
int RunFuzzModuleLoads();
int RunOkFileRegistry();
int RunOkMemoryProcess();
int RunOkNetworkLoopback();
int RunOkDocumentWorkflow();
int RunOkSystemInventory();
int RunOkComLoggingJob();
int RunOkSystemDllLoads();
int RunOkLocalhostService();
