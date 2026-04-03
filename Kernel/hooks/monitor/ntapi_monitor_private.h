#ifndef BLACKBIRD_NTAPI_MONITOR_PRIVATE_H
#define BLACKBIRD_NTAPI_MONITOR_PRIVATE_H

#include <ntddk.h>
#include "..\..\core\control.h"
#include "..\..\telemetry\etw.h"
#include "..\hook\ntapi_hook.h"

#define BLACKBIRD_NTAPI_LOG(_level, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, (_level), __VA_ARGS__)
#define BLACKBIRD_SYSTEM_INFORMATION_CLASS_PROCESS 5u
#define BLACKBIRD_SYSTEM_INFORMATION_CLASS_MODULE 11u
#define BLACKBIRD_SYSTEM_INFORMATION_CLASS_KERNEL_DEBUGGER 35u
#define BLACKBIRD_SYSTEM_INFORMATION_CLASS_FIRMWARE_TABLE 76u
#define BLACKBIRD_FIRMWARE_PROVIDER_RSMB 0x424D5352u

typedef struct _BLACKBIRD_SYSTEM_KERNEL_DEBUGGER_INFORMATION
{
    BOOLEAN KernelDebuggerEnabled;
    BOOLEAN KernelDebuggerNotPresent;
} BLACKBIRD_SYSTEM_KERNEL_DEBUGGER_INFORMATION, *PBLACKBIRD_SYSTEM_KERNEL_DEBUGGER_INFORMATION;

typedef NTSTATUS(NTAPI *PBLACKBIRD_NT_QUERY_SYSTEM_INFORMATION)(_In_ ULONG SystemInformationClass,
                                                                _Out_writes_bytes_opt_(SystemInformationLength)
                                                                    PVOID SystemInformation,
                                                                _In_ ULONG SystemInformationLength,
                                                                _Out_opt_ PULONG ReturnLength);
typedef NTSTATUS(NTAPI *PBLACKBIRD_NT_QUERY_INFORMATION_PROCESS)(_In_ HANDLE ProcessHandle,
                                                                 _In_ ULONG ProcessInformationClass,
                                                                 _Out_writes_bytes_opt_(ProcessInformationLength)
                                                                     PVOID ProcessInformation,
                                                                 _In_ ULONG ProcessInformationLength,
                                                                 _Out_opt_ PULONG ReturnLength);
typedef NTSTATUS(NTAPI *PBLACKBIRD_NT_WRITE_VIRTUAL_MEMORY)(_In_ HANDLE ProcessHandle, _In_ PVOID BaseAddress,
                                                            _In_reads_bytes_(BufferSize) PVOID Buffer,
                                                            _In_ SIZE_T BufferSize,
                                                            _Out_opt_ PSIZE_T NumberOfBytesWritten);
typedef NTSTATUS(NTAPI *PBLACKBIRD_NT_PROTECT_VIRTUAL_MEMORY)(_In_ HANDLE ProcessHandle, _Inout_ PVOID *BaseAddress,
                                                              _Inout_ PSIZE_T RegionSize, _In_ ULONG NewProtect,
                                                              _Out_ PULONG OldProtect);
typedef NTSTATUS(NTAPI *PBLACKBIRD_NT_CREATE_SECTION)(_Out_ PHANDLE SectionHandle, _In_ ACCESS_MASK DesiredAccess,
                                                      _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
                                                      _In_opt_ PLARGE_INTEGER MaximumSize,
                                                      _In_ ULONG SectionPageProtection, _In_ ULONG AllocationAttributes,
                                                      _In_opt_ HANDLE FileHandle);
typedef NTSTATUS(NTAPI *PBLACKBIRD_NT_MAP_VIEW_OF_SECTION)(_In_ HANDLE SectionHandle, _In_ HANDLE ProcessHandle,
                                                           _Inout_ PVOID *BaseAddress, _In_ ULONG_PTR ZeroBits,
                                                           _In_ SIZE_T CommitSize,
                                                           _Inout_opt_ PLARGE_INTEGER SectionOffset,
                                                           _Inout_ PSIZE_T ViewSize, _In_ ULONG InheritDisposition,
                                                           _In_ ULONG AllocationType, _In_ ULONG Win32Protect);
typedef NTSTATUS(NTAPI *PBLACKBIRD_NT_ALLOCATE_VIRTUAL_MEMORY)(_In_ HANDLE ProcessHandle, _Inout_ PVOID *BaseAddress,
                                                               _In_ ULONG_PTR ZeroBits, _Inout_ PSIZE_T RegionSize,
                                                               _In_ ULONG AllocationType, _In_ ULONG Protect);
typedef NTSTATUS(NTAPI *PBLACKBIRD_NT_QUERY_SYSTEM_INFORMATION_EX)(
    _In_ ULONG SystemInformationClass, _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength, _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
    _In_ ULONG SystemInformationLength, _Out_opt_ PULONG ReturnLength);

extern EX_RUNDOWN_REF g_NtApiRundown;
extern volatile LONG g_NtApiAllocatePreLogBudget;
extern volatile LONG g_NtApiSmbiosSanitizeBudget;
extern volatile LONG g_NtApiSmbiosSanitizeApplyBudget;

extern PBLACKBIRD_NT_QUERY_SYSTEM_INFORMATION g_OriginalNtQuerySystemInformation;
extern PBLACKBIRD_NT_QUERY_INFORMATION_PROCESS g_OriginalNtQueryInformationProcess;
extern PBLACKBIRD_NT_WRITE_VIRTUAL_MEMORY g_OriginalNtWriteVirtualMemory;
extern PBLACKBIRD_NT_PROTECT_VIRTUAL_MEMORY g_OriginalNtProtectVirtualMemory;
extern PBLACKBIRD_NT_CREATE_SECTION g_OriginalNtCreateSection;
extern PBLACKBIRD_NT_MAP_VIEW_OF_SECTION g_OriginalNtMapViewOfSection;
extern PBLACKBIRD_NT_ALLOCATE_VIRTUAL_MEMORY g_OriginalNtAllocateVirtualMemory;
extern PBLACKBIRD_NT_QUERY_SYSTEM_INFORMATION_EX g_OriginalNtQuerySystemInformationEx;

VOID BLACKBIRDNtApiHookEnter(VOID);
VOID BLACKBIRDNtApiHookExit(VOID);

VOID BLACKBIRDNtApiSanitizeKernelDebuggerInformation(_In_ ULONG SystemInformationClass,
                                                     _Out_writes_bytes_opt_(SystemInformationLength)
                                                         PVOID SystemInformation,
                                                     _In_ ULONG SystemInformationLength, _In_ NTSTATUS Status);
VOID BLACKBIRDNtApiSanitizeFirmwareTableInformation(_In_ ULONG SystemInformationClass,
                                                    _Inout_updates_bytes_opt_(SystemInformationLength)
                                                        PVOID SystemInformation,
                                                    _In_ ULONG SystemInformationLength, _In_ NTSTATUS Status);
VOID BLACKBIRDNtApiSanitizeProcessInformation(_In_ ULONG SystemInformationClass,
                                              _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
                                              _In_ ULONG SystemInformationLength, _In_ NTSTATUS Status);
VOID BLACKBIRDNtApiSanitizeModuleInformation(_In_ ULONG SystemInformationClass,
                                             _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
                                             _In_ ULONG SystemInformationLength, _In_ NTSTATUS Status);

ULONG BLACKBIRDNtApiReadUlongSafe(_In_opt_ PULONG Value);
SIZE_T BLACKBIRDNtApiReadSizeTSafe(_In_opt_ PSIZE_T Value);
PVOID BLACKBIRDNtApiReadPointerSafe(_In_opt_ PVOID *Value);
HANDLE BLACKBIRDNtApiReadHandleSafe(_In_opt_ PHANDLE Value);
ULONGLONG BLACKBIRDNtApiReadLargeIntegerSafe(_In_opt_ PLARGE_INTEGER Value);
BOOLEAN BLACKBIRDNtApiShouldLog(_Out_ HANDLE *CallerPid);
VOID BLACKBIRDNtApiLog(_In_z_ PCSTR ApiName, _In_ HANDLE CallerPid, _In_ UINT64 Arg0, _In_ UINT64 Arg1,
                       _In_ UINT64 Arg2, _In_ UINT64 Arg3, _In_ UINT64 Arg4, _In_ UINT64 Arg5, _In_ UINT64 Arg6,
                       _In_ UINT64 Arg7, _In_ NTSTATUS Status);

NTSTATUS NTAPI BLACKBIRDNtQuerySystemInformationHook(_In_ ULONG SystemInformationClass,
                                                     _Out_writes_bytes_opt_(SystemInformationLength)
                                                         PVOID SystemInformation,
                                                     _In_ ULONG SystemInformationLength, _Out_opt_ PULONG ReturnLength);
NTSTATUS NTAPI BLACKBIRDNtQueryInformationProcessHook(_In_ HANDLE ProcessHandle, _In_ ULONG ProcessInformationClass,
                                                      _Out_writes_bytes_opt_(ProcessInformationLength)
                                                          PVOID ProcessInformation,
                                                      _In_ ULONG ProcessInformationLength,
                                                      _Out_opt_ PULONG ReturnLength);
NTSTATUS NTAPI BLACKBIRDNtWriteVirtualMemoryHook(_In_ HANDLE ProcessHandle, _In_ PVOID BaseAddress,
                                                 _In_reads_bytes_(BufferSize) PVOID Buffer, _In_ SIZE_T BufferSize,
                                                 _Out_opt_ PSIZE_T NumberOfBytesWritten);
NTSTATUS NTAPI BLACKBIRDNtProtectVirtualMemoryHook(_In_ HANDLE ProcessHandle, _Inout_ PVOID *BaseAddress,
                                                   _Inout_ PSIZE_T RegionSize, _In_ ULONG NewProtect,
                                                   _Out_ PULONG OldProtect);
NTSTATUS NTAPI BLACKBIRDNtCreateSectionHook(_Out_ PHANDLE SectionHandle, _In_ ACCESS_MASK DesiredAccess,
                                            _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
                                            _In_opt_ PLARGE_INTEGER MaximumSize, _In_ ULONG SectionPageProtection,
                                            _In_ ULONG AllocationAttributes, _In_opt_ HANDLE FileHandle);
NTSTATUS NTAPI BLACKBIRDNtMapViewOfSectionHook(_In_ HANDLE SectionHandle, _In_ HANDLE ProcessHandle,
                                               _Inout_ PVOID *BaseAddress, _In_ ULONG_PTR ZeroBits,
                                               _In_ SIZE_T CommitSize, _Inout_opt_ PLARGE_INTEGER SectionOffset,
                                               _Inout_ PSIZE_T ViewSize, _In_ ULONG InheritDisposition,
                                               _In_ ULONG AllocationType, _In_ ULONG Win32Protect);
NTSTATUS NTAPI BLACKBIRDNtQuerySystemInformationExHook(
    _In_ ULONG SystemInformationClass, _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength, _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
    _In_ ULONG SystemInformationLength, _Out_opt_ PULONG ReturnLength);
NTSTATUS NTAPI BLACKBIRDNtAllocateVirtualMemoryPreLog(_In_ HANDLE ProcessHandle, _Inout_ PVOID *BaseAddress,
                                                      _In_ ULONG_PTR ZeroBits, _Inout_ PSIZE_T RegionSize,
                                                      _In_ ULONG AllocationType, _In_ ULONG Protect);

#endif
