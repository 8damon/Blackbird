#ifndef BK_NTAPI_MONITOR_PRIVATE_H
#define BK_NTAPI_MONITOR_PRIVATE_H

#include <ntddk.h>
#include <ntstrsafe.h>
#include "..\..\core\control.h"
#include "..\..\telemetry\etw.h"
#include "..\..\antivirt\qpc_timing.h"
#include "..\hook\ntapi_hook.h"

#define BK_NTAPI_LOG(_level, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, (_level), __VA_ARGS__)
#define BK_SYSTEM_INFORMATION_CLASS_PROCESS 5u
#define BK_SYSTEM_INFORMATION_CLASS_MODULE 11u
#define BK_SYSTEM_INFORMATION_CLASS_KERNEL_DEBUGGER 35u
#define BK_SYSTEM_INFORMATION_CLASS_FIRMWARE_TABLE 76u
#define BK_SYSTEM_INFORMATION_CLASS_CODE_INTEGRITY 103u
#define BK_CODE_INTEGRITY_OPTION_TESTSIGN 0x00000002u
#define BK_FIRMWARE_PROVIDER_RSMB 0x424D5352u

typedef struct _BK_SYSTEM_KERNEL_DEBUGGER_INFORMATION
{
    BOOLEAN KernelDebuggerEnabled;
    BOOLEAN KernelDebuggerNotPresent;
} BK_SYSTEM_KERNEL_DEBUGGER_INFORMATION, *PBK_SYSTEM_KERNEL_DEBUGGER_INFORMATION;

typedef struct _BK_SYSTEM_CODEINTEGRITY_INFORMATION
{
    ULONG Length;
    ULONG CodeIntegrityOptions;
} BK_SYSTEM_CODEINTEGRITY_INFORMATION, *PBK_SYSTEM_CODEINTEGRITY_INFORMATION;

typedef NTSTATUS(NTAPI *PBK_NT_QUERY_SYSTEM_INFORMATION)(_In_ ULONG SystemInformationClass,
                                                         _Out_writes_bytes_opt_(SystemInformationLength)
                                                             PVOID SystemInformation,
                                                         _In_ ULONG SystemInformationLength,
                                                         _Out_opt_ PULONG ReturnLength);
typedef NTSTATUS(NTAPI *PBK_NT_QUERY_INFORMATION_PROCESS)(_In_ HANDLE ProcessHandle, _In_ ULONG ProcessInformationClass,
                                                          _Out_writes_bytes_opt_(ProcessInformationLength)
                                                              PVOID ProcessInformation,
                                                          _In_ ULONG ProcessInformationLength,
                                                          _Out_opt_ PULONG ReturnLength);
typedef NTSTATUS(NTAPI *PBK_NT_QUERY_OBJECT)(_In_opt_ HANDLE Handle, _In_ ULONG ObjectInformationClass,
                                             _Out_writes_bytes_opt_(ObjectInformationLength) PVOID ObjectInformation,
                                             _In_ ULONG ObjectInformationLength, _Out_opt_ PULONG ReturnLength);
typedef NTSTATUS(NTAPI *PBK_NT_WRITE_VIRTUAL_MEMORY)(_In_ HANDLE ProcessHandle, _In_ PVOID BaseAddress,
                                                     _In_reads_bytes_(BufferSize) PVOID Buffer, _In_ SIZE_T BufferSize,
                                                     _Out_opt_ PSIZE_T NumberOfBytesWritten);
typedef NTSTATUS(NTAPI *PBK_NT_READ_VIRTUAL_MEMORY)(_In_ HANDLE ProcessHandle, _In_ PVOID BaseAddress,
                                                    _Out_writes_bytes_(BufferSize) PVOID Buffer, _In_ SIZE_T BufferSize,
                                                    _Out_opt_ PSIZE_T NumberOfBytesRead);
typedef NTSTATUS(NTAPI *PBK_NT_PROTECT_VIRTUAL_MEMORY)(_In_ HANDLE ProcessHandle, _Inout_ PVOID *BaseAddress,
                                                       _Inout_ PSIZE_T RegionSize, _In_ ULONG NewProtect,
                                                       _Out_ PULONG OldProtect);
typedef NTSTATUS(NTAPI *PBK_NT_CREATE_SECTION)(_Out_ PHANDLE SectionHandle, _In_ ACCESS_MASK DesiredAccess,
                                               _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
                                               _In_opt_ PLARGE_INTEGER MaximumSize, _In_ ULONG SectionPageProtection,
                                               _In_ ULONG AllocationAttributes, _In_opt_ HANDLE FileHandle);
typedef NTSTATUS(NTAPI *PBK_NT_MAP_VIEW_OF_SECTION)(_In_ HANDLE SectionHandle, _In_ HANDLE ProcessHandle,
                                                    _Inout_ PVOID *BaseAddress, _In_ ULONG_PTR ZeroBits,
                                                    _In_ SIZE_T CommitSize, _Inout_opt_ PLARGE_INTEGER SectionOffset,
                                                    _Inout_ PSIZE_T ViewSize, _In_ ULONG InheritDisposition,
                                                    _In_ ULONG AllocationType, _In_ ULONG Win32Protect);
typedef NTSTATUS(NTAPI *PBK_NT_MAP_VIEW_OF_SECTION_EX)(_In_ HANDLE SectionHandle, _In_ HANDLE ProcessHandle,
                                                       _Inout_ PVOID *BaseAddress,
                                                       _Inout_opt_ PLARGE_INTEGER SectionOffset,
                                                       _Inout_ PSIZE_T ViewSize, _In_ ULONG AllocationType,
                                                       _In_ ULONG Win32Protect, _In_opt_ PVOID ExtendedParameters,
                                                       _In_ ULONG ExtendedParameterCount);
typedef NTSTATUS(NTAPI *PBK_NT_UNMAP_VIEW_OF_SECTION)(_In_ HANDLE ProcessHandle, _In_opt_ PVOID BaseAddress);
typedef NTSTATUS(NTAPI *PBK_NT_UNMAP_VIEW_OF_SECTION_EX)(_In_ HANDLE ProcessHandle, _In_opt_ PVOID BaseAddress,
                                                         _In_ ULONG Flags);
typedef NTSTATUS(NTAPI *PBK_NT_ALLOCATE_VIRTUAL_MEMORY)(_In_ HANDLE ProcessHandle, _Inout_ PVOID *BaseAddress,
                                                        _In_ ULONG_PTR ZeroBits, _Inout_ PSIZE_T RegionSize,
                                                        _In_ ULONG AllocationType, _In_ ULONG Protect);
typedef NTSTATUS(NTAPI *PBK_NT_CREATE_THREAD)(_Out_ PHANDLE ThreadHandle, _In_ ACCESS_MASK DesiredAccess,
                                              _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes, _In_ HANDLE ProcessHandle,
                                              _Out_opt_ PCLIENT_ID ClientId, _In_ PCONTEXT ThreadContext,
                                              _In_ PVOID InitialTeb, _In_ BOOLEAN CreateSuspended);
typedef NTSTATUS(NTAPI *PBK_NT_CREATE_THREAD_EX)(_Out_ PHANDLE ThreadHandle, _In_ ACCESS_MASK DesiredAccess,
                                                 _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
                                                 _In_ HANDLE ProcessHandle, _In_ PVOID StartRoutine,
                                                 _In_opt_ PVOID Argument, _In_ ULONG CreateFlags, _In_ SIZE_T ZeroBits,
                                                 _In_ SIZE_T StackSize, _In_ SIZE_T MaximumStackSize,
                                                 _In_opt_ PVOID AttributeList);
typedef NTSTATUS(NTAPI *PBK_NT_QUEUE_APC_THREAD)(_In_ HANDLE ThreadHandle, _In_ PVOID ApcRoutine,
                                                 _In_opt_ PVOID ApcArgument1, _In_opt_ PVOID ApcArgument2,
                                                 _In_opt_ PVOID ApcArgument3);
typedef NTSTATUS(NTAPI *PBK_NT_QUEUE_APC_THREAD_EX)(_In_ HANDLE ThreadHandle, _In_opt_ HANDLE UserApcReserveHandle,
                                                    _In_ PVOID ApcRoutine, _In_opt_ PVOID ApcArgument1,
                                                    _In_opt_ PVOID ApcArgument2, _In_opt_ PVOID ApcArgument3);
typedef NTSTATUS(NTAPI *PBK_NT_QUEUE_APC_THREAD_EX2)(_In_ HANDLE ThreadHandle, _In_opt_ HANDLE UserApcReserveHandle,
                                                     _In_ ULONG QueueUserApcFlags, _In_ PVOID ApcRoutine,
                                                     _In_opt_ PVOID ApcArgument1, _In_opt_ PVOID ApcArgument2,
                                                     _In_opt_ PVOID ApcArgument3);
typedef NTSTATUS(NTAPI *PBK_NT_QUERY_SYSTEM_INFORMATION_EX)(
    _In_ ULONG SystemInformationClass, _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength, _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
    _In_ ULONG SystemInformationLength, _Out_opt_ PULONG ReturnLength);
typedef NTSTATUS(NTAPI *PBK_NT_QUERY_PERFORMANCE_COUNTER)(_Out_ PLARGE_INTEGER PerformanceCounter,
                                                          _Out_opt_ PLARGE_INTEGER PerformanceFrequency);
typedef NTSTATUS(NTAPI *PBK_NT_QUERY_VIRTUAL_MEMORY)(_In_ HANDLE ProcessHandle, _In_opt_ PVOID BaseAddress,
                                                     _In_ ULONG MemoryInformationClass,
                                                     _Out_writes_bytes_opt_(MemoryInformationLength)
                                                         PVOID MemoryInformation,
                                                     _In_ SIZE_T MemoryInformationLength,
                                                     _Out_opt_ PSIZE_T ReturnLength);
typedef NTSTATUS(NTAPI *PBK_NT_GET_NEXT_THREAD)(_In_ HANDLE ProcessHandle, _In_opt_ HANDLE ThreadHandle,
                                                _In_ ACCESS_MASK DesiredAccess, _In_ ULONG HandleAttributes,
                                                _In_ ULONG Flags, _Out_ PHANDLE NewThreadHandle);
typedef NTSTATUS(NTAPI *PBK_NT_QUERY_INFORMATION_THREAD)(_In_ HANDLE ThreadHandle,
                                                         _In_ THREADINFOCLASS ThreadInformationClass,
                                                         _Out_writes_bytes_opt_(ThreadInformationLength)
                                                             PVOID ThreadInformation,
                                                         _In_ ULONG ThreadInformationLength,
                                                         _Out_opt_ PULONG ReturnLength);
typedef NTSTATUS(NTAPI *PBK_NT_SET_INFORMATION_THREAD)(_In_ HANDLE ThreadHandle,
                                                       _In_ THREADINFOCLASS ThreadInformationClass,
                                                       _In_reads_bytes_opt_(ThreadInformationLength)
                                                           PVOID ThreadInformation,
                                                       _In_ ULONG ThreadInformationLength);
typedef NTSTATUS(NTAPI *PBK_NT_SET_INFORMATION_PROCESS)(_In_ HANDLE ProcessHandle,
                                                        _In_ PROCESSINFOCLASS ProcessInformationClass,
                                                        _In_reads_bytes_opt_(ProcessInformationLength)
                                                            PVOID ProcessInformation,
                                                        _In_ ULONG ProcessInformationLength);
typedef NTSTATUS(NTAPI *PBK_NT_RESUME_THREAD)(_In_ HANDLE ThreadHandle, _Out_opt_ PULONG PreviousSuspendCount);
typedef NTSTATUS(NTAPI *PBK_NT_SUSPEND_THREAD)(_In_ HANDLE ThreadHandle, _Out_opt_ PULONG PreviousSuspendCount);
typedef NTSTATUS(NTAPI *PBK_NT_ALERT_RESUME_THREAD)(_In_ HANDLE ThreadHandle, _Out_opt_ PULONG PreviousSuspendCount);
typedef NTSTATUS(NTAPI *PBK_NT_ALERT_THREAD)(_In_ HANDLE ThreadHandle);
typedef NTSTATUS(NTAPI *PBK_NT_TEST_ALERT)(VOID);
typedef NTSTATUS(NTAPI *PBK_NT_CREATE_USER_PROCESS)(
    _Out_ PHANDLE ProcessHandle, _Out_ PHANDLE ThreadHandle, _In_ ACCESS_MASK ProcessDesiredAccess,
    _In_ ACCESS_MASK ThreadDesiredAccess, _In_opt_ POBJECT_ATTRIBUTES ProcessObjectAttributes,
    _In_opt_ POBJECT_ATTRIBUTES ThreadObjectAttributes, _In_ ULONG ProcessFlags, _In_ ULONG ThreadFlags,
    _In_opt_ PVOID ProcessParameters, _Inout_ PVOID CreateInfo, _In_opt_ PVOID AttributeList);
typedef NTSTATUS(NTAPI *PBK_NT_CREATE_PROCESS_EX)(_Out_ PHANDLE ProcessHandle, _In_ ACCESS_MASK DesiredAccess,
                                                  _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
                                                  _In_ HANDLE ParentProcess, _In_ ULONG Flags,
                                                  _In_opt_ HANDLE SectionHandle, _In_opt_ HANDLE DebugPort,
                                                  _In_opt_ HANDLE ExceptionPort, _In_ BOOLEAN InJob);
typedef NTSTATUS(NTAPI *PBK_NT_CREATE_FILE)(_Out_ PHANDLE FileHandle, _In_ ACCESS_MASK DesiredAccess,
                                            _In_ POBJECT_ATTRIBUTES ObjectAttributes,
                                            _Out_ PIO_STATUS_BLOCK IoStatusBlock,
                                            _In_opt_ PLARGE_INTEGER AllocationSize, _In_ ULONG FileAttributes,
                                            _In_ ULONG ShareAccess, _In_ ULONG CreateDisposition,
                                            _In_ ULONG CreateOptions, _In_reads_bytes_opt_(EaLength) PVOID EaBuffer,
                                            _In_ ULONG EaLength);
typedef NTSTATUS(NTAPI *PBK_NT_OPEN_FILE)(_Out_ PHANDLE FileHandle, _In_ ACCESS_MASK DesiredAccess,
                                          _In_ POBJECT_ATTRIBUTES ObjectAttributes,
                                          _Out_ PIO_STATUS_BLOCK IoStatusBlock, _In_ ULONG ShareAccess,
                                          _In_ ULONG OpenOptions);
typedef NTSTATUS(NTAPI *PBK_NT_DEVICE_IO_CONTROL_FILE)(_In_ HANDLE FileHandle, _In_opt_ HANDLE Event,
                                                       _In_opt_ PIO_APC_ROUTINE ApcRoutine, _In_opt_ PVOID ApcContext,
                                                       _Out_ PIO_STATUS_BLOCK IoStatusBlock, _In_ ULONG IoControlCode,
                                                       _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
                                                       _In_ ULONG InputBufferLength,
                                                       _Out_writes_bytes_opt_(OutputBufferLength) PVOID OutputBuffer,
                                                       _In_ ULONG OutputBufferLength);
typedef NTSTATUS(NTAPI *PBK_NT_FS_CONTROL_FILE)(_In_ HANDLE FileHandle, _In_opt_ HANDLE Event,
                                                _In_opt_ PIO_APC_ROUTINE ApcRoutine, _In_opt_ PVOID ApcContext,
                                                _Out_ PIO_STATUS_BLOCK IoStatusBlock, _In_ ULONG FsControlCode,
                                                _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
                                                _In_ ULONG InputBufferLength,
                                                _Out_writes_bytes_opt_(OutputBufferLength) PVOID OutputBuffer,
                                                _In_ ULONG OutputBufferLength);
typedef NTSTATUS(NTAPI *PBK_NT_QUERY_DIRECTORY_FILE)(
    _In_ HANDLE FileHandle, _In_opt_ HANDLE Event, _In_opt_ PIO_APC_ROUTINE ApcRoutine, _In_opt_ PVOID ApcContext,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock, _Out_writes_bytes_(Length) PVOID FileInformation, _In_ ULONG Length,
    _In_ FILE_INFORMATION_CLASS FileInformationClass, _In_ BOOLEAN ReturnSingleEntry, _In_opt_ PUNICODE_STRING FileName,
    _In_ BOOLEAN RestartScan);
typedef NTSTATUS(NTAPI *PBK_NT_QUERY_DIRECTORY_FILE_EX)(
    _In_ HANDLE FileHandle, _In_opt_ HANDLE Event, _In_opt_ PIO_APC_ROUTINE ApcRoutine, _In_opt_ PVOID ApcContext,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock, _Out_writes_bytes_(Length) PVOID FileInformation, _In_ ULONG Length,
    _In_ FILE_INFORMATION_CLASS FileInformationClass, _In_ ULONG QueryFlags, _In_opt_ PUNICODE_STRING FileName);
typedef NTSTATUS(NTAPI *PBK_NT_ALPC_CONNECT_PORT)(
    _Out_ PHANDLE PortHandle, _In_ PUNICODE_STRING PortName, _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PVOID PortAttributes, _In_ ULONG Flags, _In_opt_ PSID RequiredServerSid,
    _Inout_updates_bytes_to_opt_(*BufferLength, *BufferLength) PVOID ConnectionMessage, _Inout_opt_ PULONG BufferLength,
    _Inout_opt_ PVOID OutMessageAttributes, _Inout_opt_ PVOID InMessageAttributes, _In_opt_ PLARGE_INTEGER Timeout);
typedef NTSTATUS(NTAPI *PBK_NT_ALPC_SEND_WAIT_RECEIVE_PORT)(
    _In_ HANDLE PortHandle, _In_ ULONG Flags, _In_reads_bytes_opt_(0) PVOID SendMessage,
    _Inout_opt_ PVOID SendMessageAttributes, _Out_writes_bytes_opt_(0) PVOID ReceiveMessage,
    _Inout_opt_ PULONG BufferLength, _Inout_opt_ PVOID ReceiveMessageAttributes, _In_opt_ PLARGE_INTEGER Timeout);
typedef NTSTATUS(NTAPI *PBK_NT_CONNECT_PORT)(
    _Out_ PHANDLE PortHandle, _In_ PUNICODE_STRING PortName, _In_ PSECURITY_QUALITY_OF_SERVICE SecurityQos,
    _Inout_opt_ PVOID ClientView, _Out_opt_ PVOID ServerView, _Out_opt_ PULONG MaxMessageLength,
    _Inout_updates_bytes_to_opt_(*ConnectionInformationLength, *ConnectionInformationLength)
        PVOID ConnectionInformation,
    _Inout_opt_ PULONG ConnectionInformationLength);
typedef NTSTATUS(NTAPI *PBK_NT_OPEN_PROCESS)(_Out_ PHANDLE ProcessHandle, _In_ ACCESS_MASK DesiredAccess,
                                             _In_ POBJECT_ATTRIBUTES ObjectAttributes, _In_opt_ PCLIENT_ID ClientId);
typedef NTSTATUS(NTAPI *PBK_NT_OPEN_THREAD)(_Out_ PHANDLE ThreadHandle, _In_ ACCESS_MASK DesiredAccess,
                                            _In_ POBJECT_ATTRIBUTES ObjectAttributes, _In_opt_ PCLIENT_ID ClientId);
typedef NTSTATUS(NTAPI *PBK_NT_DUPLICATE_OBJECT)(_In_ HANDLE SourceProcessHandle, _In_ HANDLE SourceHandle,
                                                 _In_opt_ HANDLE TargetProcessHandle, _Out_opt_ PHANDLE TargetHandle,
                                                 _In_ ACCESS_MASK DesiredAccess, _In_ ULONG HandleAttributes,
                                                 _In_ ULONG Options);
typedef NTSTATUS(NTAPI *PBK_NT_QUERY_KEY)(_In_ HANDLE KeyHandle, _In_ KEY_INFORMATION_CLASS KeyInformationClass,
                                          _Out_writes_bytes_opt_(Length) PVOID KeyInformation, _In_ ULONG Length,
                                          _Out_ PULONG ResultLength);
typedef NTSTATUS(NTAPI *PBK_NT_ENUMERATE_KEY)(_In_ HANDLE KeyHandle, _In_ ULONG Index,
                                              _In_ KEY_INFORMATION_CLASS KeyInformationClass,
                                              _Out_writes_bytes_opt_(Length) PVOID KeyInformation, _In_ ULONG Length,
                                              _Out_ PULONG ResultLength);
typedef NTSTATUS(NTAPI *PBK_NT_QUERY_VALUE_KEY)(_In_ HANDLE KeyHandle, _In_ PUNICODE_STRING ValueName,
                                                _In_ KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
                                                _Out_writes_bytes_opt_(Length) PVOID KeyValueInformation,
                                                _In_ ULONG Length, _Out_ PULONG ResultLength);
typedef NTSTATUS(NTAPI *PBK_NT_ENUMERATE_VALUE_KEY)(_In_ HANDLE KeyHandle, _In_ ULONG Index,
                                                    _In_ KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
                                                    _Out_writes_bytes_opt_(Length) PVOID KeyValueInformation,
                                                    _In_ ULONG Length, _Out_ PULONG ResultLength);

/* NtGetContextThread / NtSetContextThread — detect cross-process thread context access
   (thread hijacking, anti-debug probing, injection via SetContext). */
typedef NTSTATUS(NTAPI *PBK_NT_GET_CONTEXT_THREAD)(_In_ HANDLE ThreadHandle, _Inout_ PCONTEXT ThreadContext);
typedef NTSTATUS(NTAPI *PBK_NT_SET_CONTEXT_THREAD)(_In_ HANDLE ThreadHandle, _In_ PCONTEXT ThreadContext);

extern EX_RUNDOWN_REF g_NtApiRundown;
extern volatile LONG g_NtApiAllocatePreLogBudget;
extern volatile LONG g_NtApiSmbiosSanitizeBudget;
extern volatile LONG g_NtApiSmbiosSanitizeApplyBudget;

VOID BkntkiRecordSanitizerHit(_In_ UINT32 SanitizerId);

extern PBK_NT_QUERY_SYSTEM_INFORMATION g_OriginalNtQuerySystemInformation;
extern PBK_NT_QUERY_INFORMATION_PROCESS g_OriginalNtQueryInformationProcess;
extern PBK_NT_QUERY_OBJECT g_OriginalNtQueryObject;
extern PBK_NT_WRITE_VIRTUAL_MEMORY g_OriginalNtWriteVirtualMemory;
extern PBK_NT_READ_VIRTUAL_MEMORY g_OriginalNtReadVirtualMemory;
extern PBK_NT_PROTECT_VIRTUAL_MEMORY g_OriginalNtProtectVirtualMemory;
extern PBK_NT_CREATE_SECTION g_OriginalNtCreateSection;
extern PBK_NT_MAP_VIEW_OF_SECTION g_OriginalNtMapViewOfSection;
extern PBK_NT_MAP_VIEW_OF_SECTION_EX g_OriginalNtMapViewOfSectionEx;
extern PBK_NT_UNMAP_VIEW_OF_SECTION g_OriginalNtUnmapViewOfSection;
extern PBK_NT_UNMAP_VIEW_OF_SECTION_EX g_OriginalNtUnmapViewOfSectionEx;
extern PBK_NT_ALLOCATE_VIRTUAL_MEMORY g_OriginalNtAllocateVirtualMemory;
extern PBK_NT_CREATE_THREAD g_OriginalNtCreateThread;
extern PBK_NT_CREATE_THREAD_EX g_OriginalNtCreateThreadEx;
extern PBK_NT_QUEUE_APC_THREAD g_OriginalNtQueueApcThread;
extern PBK_NT_QUEUE_APC_THREAD_EX g_OriginalNtQueueApcThreadEx;
extern PBK_NT_QUEUE_APC_THREAD_EX2 g_OriginalNtQueueApcThreadEx2;
extern PBK_NT_QUERY_SYSTEM_INFORMATION_EX g_OriginalNtQuerySystemInformationEx;
extern PBK_NT_QUERY_PERFORMANCE_COUNTER g_OriginalNtQueryPerformanceCounter;
extern PBK_NT_QUERY_VIRTUAL_MEMORY g_OriginalNtQueryVirtualMemory;
extern PBK_NT_GET_CONTEXT_THREAD g_OriginalNtGetContextThread;
extern PBK_NT_SET_CONTEXT_THREAD g_OriginalNtSetContextThread;
extern PBK_NT_GET_NEXT_THREAD g_OriginalNtGetNextThread;
extern PBK_NT_QUERY_INFORMATION_THREAD g_OriginalNtQueryInformationThread;
extern PBK_NT_SET_INFORMATION_THREAD g_OriginalNtSetInformationThread;
extern PBK_NT_SET_INFORMATION_PROCESS g_OriginalNtSetInformationProcess;
extern PBK_NT_RESUME_THREAD g_OriginalNtResumeThread;
extern PBK_NT_SUSPEND_THREAD g_OriginalNtSuspendThread;
extern PBK_NT_ALERT_RESUME_THREAD g_OriginalNtAlertResumeThread;
extern PBK_NT_ALERT_THREAD g_OriginalNtAlertThread;
extern PBK_NT_TEST_ALERT g_OriginalNtTestAlert;
extern PBK_NT_CREATE_USER_PROCESS g_OriginalNtCreateUserProcess;
extern PBK_NT_CREATE_PROCESS_EX g_OriginalNtCreateProcessEx;
extern PBK_NT_CREATE_FILE g_OriginalNtCreateFile;
extern PBK_NT_OPEN_FILE g_OriginalNtOpenFile;
extern PBK_NT_DEVICE_IO_CONTROL_FILE g_OriginalNtDeviceIoControlFile;
extern PBK_NT_FS_CONTROL_FILE g_OriginalNtFsControlFile;
extern PBK_NT_QUERY_DIRECTORY_FILE g_OriginalNtQueryDirectoryFile;
extern PBK_NT_QUERY_DIRECTORY_FILE_EX g_OriginalNtQueryDirectoryFileEx;
extern PBK_NT_ALPC_CONNECT_PORT g_OriginalNtAlpcConnectPort;
extern PBK_NT_ALPC_SEND_WAIT_RECEIVE_PORT g_OriginalNtAlpcSendWaitReceivePort;
extern PBK_NT_CONNECT_PORT g_OriginalNtConnectPort;
extern PBK_NT_OPEN_PROCESS g_OriginalNtOpenProcess;
extern PBK_NT_OPEN_THREAD g_OriginalNtOpenThread;
extern PBK_NT_DUPLICATE_OBJECT g_OriginalNtDuplicateObject;
extern PBK_NT_QUERY_KEY g_OriginalNtQueryKey;
extern PBK_NT_ENUMERATE_KEY g_OriginalNtEnumerateKey;
extern PBK_NT_QUERY_VALUE_KEY g_OriginalNtQueryValueKey;
extern PBK_NT_ENUMERATE_VALUE_KEY g_OriginalNtEnumerateValueKey;

UINT32 BkntkiBuildExecFlags(_In_opt_ HANDLE ProcessHandle, _In_ ULONG AllocationAttributes);
VOID BkntkiHookEnter(VOID);
VOID BkntkiHookExit(VOID);

VOID BkntkiPostProcessSystemInformationQuery(_In_ ULONG SystemInformationClass,
                                             _Inout_updates_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
                                             _In_ ULONG SystemInformationLength, _In_ NTSTATUS Status);
VOID BkntkiPostProcessSystemInformationExQuery(_In_ ULONG SystemInformationClass,
                                               _Inout_updates_bytes_opt_(SystemInformationLength)
                                                   PVOID SystemInformation,
                                               _In_ ULONG SystemInformationLength, _In_ NTSTATUS Status);
VOID BkntkiSanitizeKernelDebuggerInformation(_In_ ULONG SystemInformationClass,
                                             _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
                                             _In_ ULONG SystemInformationLength, _In_ NTSTATUS Status);
VOID BkntkiSanitizeCodeIntegrityInformation(_In_ ULONG SystemInformationClass,
                                            _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
                                            _In_ ULONG SystemInformationLength, _In_ NTSTATUS Status);
VOID BkavNtSanitizeFirmwareTableInformation(_In_ ULONG SystemInformationClass,
                                            _Inout_updates_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
                                            _In_ ULONG SystemInformationLength, _In_ NTSTATUS Status);
VOID BkntkiSanitizeProcessInformation(_In_ ULONG SystemInformationClass,
                                      _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
                                      _In_ ULONG SystemInformationLength, _In_ NTSTATUS Status);
VOID BkntkiSanitizeModuleInformation(_In_ ULONG SystemInformationClass,
                                     _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
                                     _In_ ULONG SystemInformationLength, _In_ NTSTATUS Status);
BOOLEAN BkntkiShouldSanitizeCurrentCaller(_In_ UINT32 StreamMask);
BOOLEAN BkntkiShouldSanitizeProcessQuery(_In_ HANDLE ProcessHandle, _Out_opt_ UINT32 *TargetProcessId);
BOOLEAN BkntkiResolveProcessHandleToPid(_In_ HANDLE ProcessHandle, _Out_ UINT32 *ProcessId);
BOOLEAN BkntkiHandleValueIsProtectedIpc(_In_ HANDLE HandleValue);
BOOLEAN BkntkiHandleValueNameContainsLiteral(_In_ HANDLE HandleValue, _In_z_ PCWSTR Literal);
VOID BkntkiRememberNtdllSectionHandle(_In_ HANDLE SectionHandle, _In_ ULONG AllocationAttributes);
BOOLEAN BkntkiIsTrackedNtdllSectionHandle(_In_ HANDLE SectionHandle, _Out_opt_ UINT32 *AllocationAttributes);
VOID BkntkiSanitizeProcessQueryInformation(_In_ ULONG ProcessInformationClass,
                                           _Out_writes_bytes_opt_(ProcessInformationLength) PVOID ProcessInformation,
                                           _In_ ULONG ProcessInformationLength, _Out_opt_ PULONG ReturnLength,
                                           _In_ NTSTATUS Status);
BOOLEAN BkntkiAddressTouchesInstrumentationRangeForPid(_In_ UINT32 ProcessId, _In_ PVOID Address);

ULONG BkntkiReadUlongSafe(_In_opt_ PULONG Value);
SIZE_T BkntkiReadSizeTSafe(_In_opt_ PSIZE_T Value);
PVOID BkntkiReadPointerSafe(_In_opt_ PVOID *Value);
HANDLE BkntkiReadHandleSafe(_In_opt_ PHANDLE Value);
ULONGLONG BkntkiReadLargeIntegerSafe(_In_opt_ PLARGE_INTEGER Value);
VOID BkntkiWriteSizeTSafe(_In_opt_ PSIZE_T Value, _In_ SIZE_T NewValue);
BOOLEAN BkntkiReadTouchesInstrumentationRange(_In_ HANDLE ProcessHandle, _In_ PVOID BaseAddress, _In_ SIZE_T Size,
                                              _Out_opt_ UINT32 *TargetProcessId);
BOOLEAN BkntkiWriteTouchesProtectedRange(_In_ HANDLE ProcessHandle, _In_ PVOID BaseAddress, _In_ SIZE_T Size,
                                         _Out_opt_ UINT32 *TargetProcessId);
BOOLEAN BkntkiApplyProtectedWriteToCloak(_In_ HANDLE ProcessHandle, _In_ PVOID BaseAddress,
                                         _In_reads_bytes_(Size) PVOID Buffer, _In_ SIZE_T Size,
                                         _Out_opt_ UINT32 *TargetProcessId);
BOOLEAN BkntkiOverlayHookPatchBytesForHandle(_In_ HANDLE ProcessHandle, _In_ PVOID BaseAddress, _In_ SIZE_T Size,
                                             _Inout_updates_bytes_(Size) PVOID Buffer,
                                             _Out_opt_ UINT32 *TargetProcessId);
NTSTATUS BkntkiMirrorHookPatchesIntoImage(_In_ UINT32 ProcessId, _In_ UINT64 SourceImageBase,
                                          _In_ UINT64 MirrorImageBase, _In_ UINT64 MirrorImageSize);
NTSTATUS BkntkiMirrorHookPatchesIntoDataView(_In_ UINT32 ProcessId, _In_ UINT64 SourceImageBase,
                                             _In_ UINT64 MirrorViewBase, _In_ UINT64 MirrorViewSize);
BOOLEAN BkntkiShouldLog(_Out_ HANDLE *CallerPid);
VOID BkntkiLog(_In_z_ PCSTR ApiName, _In_ HANDLE CallerPid, _In_ UINT64 Arg0, _In_ UINT64 Arg1, _In_ UINT64 Arg2,
               _In_ UINT64 Arg3, _In_ UINT64 Arg4, _In_ UINT64 Arg5, _In_ UINT64 Arg6, _In_ UINT64 Arg7,
               _In_ UINT32 ExecFlags, _In_ NTSTATUS Status);

NTSTATUS NTAPI BkntkiNtQuerySystemInformationHook(_In_ ULONG SystemInformationClass,
                                                  _Out_writes_bytes_opt_(SystemInformationLength)
                                                      PVOID SystemInformation,
                                                  _In_ ULONG SystemInformationLength, _Out_opt_ PULONG ReturnLength);
NTSTATUS NTAPI BkntkiNtQueryInformationProcessHook(_In_ HANDLE ProcessHandle, _In_ ULONG ProcessInformationClass,
                                                   _Out_writes_bytes_opt_(ProcessInformationLength)
                                                       PVOID ProcessInformation,
                                                   _In_ ULONG ProcessInformationLength, _Out_opt_ PULONG ReturnLength);
NTSTATUS NTAPI BkntkiNtQueryObjectHook(_In_opt_ HANDLE Handle, _In_ ULONG ObjectInformationClass,
                                       _Out_writes_bytes_opt_(ObjectInformationLength) PVOID ObjectInformation,
                                       _In_ ULONG ObjectInformationLength, _Out_opt_ PULONG ReturnLength);
NTSTATUS NTAPI BkntkiNtWriteVirtualMemoryHook(_In_ HANDLE ProcessHandle, _In_ PVOID BaseAddress,
                                              _In_reads_bytes_(BufferSize) PVOID Buffer, _In_ SIZE_T BufferSize,
                                              _Out_opt_ PSIZE_T NumberOfBytesWritten);
NTSTATUS NTAPI BkntkiNtReadVirtualMemoryHook(_In_ HANDLE ProcessHandle, _In_ PVOID BaseAddress,
                                             _Out_writes_bytes_(BufferSize) PVOID Buffer, _In_ SIZE_T BufferSize,
                                             _Out_opt_ PSIZE_T NumberOfBytesRead);
NTSTATUS NTAPI BkntkiNtProtectVirtualMemoryHook(_In_ HANDLE ProcessHandle, _Inout_ PVOID *BaseAddress,
                                                _Inout_ PSIZE_T RegionSize, _In_ ULONG NewProtect,
                                                _Out_ PULONG OldProtect);
NTSTATUS NTAPI BkntkiNtCreateSectionHook(_Out_ PHANDLE SectionHandle, _In_ ACCESS_MASK DesiredAccess,
                                         _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
                                         _In_opt_ PLARGE_INTEGER MaximumSize, _In_ ULONG SectionPageProtection,
                                         _In_ ULONG AllocationAttributes, _In_opt_ HANDLE FileHandle);
NTSTATUS NTAPI BkntkiNtMapViewOfSectionHook(_In_ HANDLE SectionHandle, _In_ HANDLE ProcessHandle,
                                            _Inout_ PVOID *BaseAddress, _In_ ULONG_PTR ZeroBits, _In_ SIZE_T CommitSize,
                                            _Inout_opt_ PLARGE_INTEGER SectionOffset, _Inout_ PSIZE_T ViewSize,
                                            _In_ ULONG InheritDisposition, _In_ ULONG AllocationType,
                                            _In_ ULONG Win32Protect);
NTSTATUS NTAPI BkntkiNtMapViewOfSectionExHook(_In_ HANDLE SectionHandle, _In_ HANDLE ProcessHandle,
                                              _Inout_ PVOID *BaseAddress, _Inout_opt_ PLARGE_INTEGER SectionOffset,
                                              _Inout_ PSIZE_T ViewSize, _In_ ULONG AllocationType,
                                              _In_ ULONG Win32Protect, _In_opt_ PVOID ExtendedParameters,
                                              _In_ ULONG ExtendedParameterCount);
NTSTATUS NTAPI BkntkiNtUnmapViewOfSectionHook(_In_ HANDLE ProcessHandle, _In_opt_ PVOID BaseAddress);
NTSTATUS NTAPI BkntkiNtUnmapViewOfSectionExHook(_In_ HANDLE ProcessHandle, _In_opt_ PVOID BaseAddress,
                                                _In_ ULONG Flags);
NTSTATUS NTAPI BkntkiNtQuerySystemInformationExHook(_In_ ULONG SystemInformationClass,
                                                    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
                                                    _In_ ULONG InputBufferLength,
                                                    _Out_writes_bytes_opt_(SystemInformationLength)
                                                        PVOID SystemInformation,
                                                    _In_ ULONG SystemInformationLength, _Out_opt_ PULONG ReturnLength);
NTSTATUS NTAPI BkntkiNtQueryPerformanceCounterHook(_Out_ PLARGE_INTEGER PerformanceCounter,
                                                   _Out_opt_ PLARGE_INTEGER PerformanceFrequency);
NTSTATUS NTAPI BkntkiNtQueryVirtualMemoryHook(_In_ HANDLE ProcessHandle, _In_opt_ PVOID BaseAddress,
                                              _In_ ULONG MemoryInformationClass,
                                              _Out_writes_bytes_opt_(MemoryInformationLength) PVOID MemoryInformation,
                                              _In_ SIZE_T MemoryInformationLength, _Out_opt_ PSIZE_T ReturnLength);
NTSTATUS NTAPI BkntkiNtAllocateVirtualMemoryPreLog(_In_ HANDLE ProcessHandle, _Inout_ PVOID *BaseAddress,
                                                   _In_ ULONG_PTR ZeroBits, _Inout_ PSIZE_T RegionSize,
                                                   _In_ ULONG AllocationType, _In_ ULONG Protect);
NTSTATUS NTAPI BkntkiNtCreateThreadHook(_Out_ PHANDLE ThreadHandle, _In_ ACCESS_MASK DesiredAccess,
                                        _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes, _In_ HANDLE ProcessHandle,
                                        _Out_opt_ PCLIENT_ID ClientId, _In_ PCONTEXT ThreadContext,
                                        _In_ PVOID InitialTeb, _In_ BOOLEAN CreateSuspended);
NTSTATUS NTAPI BkntkiNtCreateThreadExHook(_Out_ PHANDLE ThreadHandle, _In_ ACCESS_MASK DesiredAccess,
                                          _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes, _In_ HANDLE ProcessHandle,
                                          _In_ PVOID StartRoutine, _In_opt_ PVOID Argument, _In_ ULONG CreateFlags,
                                          _In_ SIZE_T ZeroBits, _In_ SIZE_T StackSize, _In_ SIZE_T MaximumStackSize,
                                          _In_opt_ PVOID AttributeList);
NTSTATUS NTAPI BkntkiNtQueueApcThreadHook(_In_ HANDLE ThreadHandle, _In_ PVOID ApcRoutine, _In_opt_ PVOID ApcArgument1,
                                          _In_opt_ PVOID ApcArgument2, _In_opt_ PVOID ApcArgument3);
NTSTATUS NTAPI BkntkiNtQueueApcThreadExHook(_In_ HANDLE ThreadHandle, _In_opt_ HANDLE UserApcReserveHandle,
                                            _In_ PVOID ApcRoutine, _In_opt_ PVOID ApcArgument1,
                                            _In_opt_ PVOID ApcArgument2, _In_opt_ PVOID ApcArgument3);
NTSTATUS NTAPI BkntkiNtQueueApcThreadEx2Hook(_In_ HANDLE ThreadHandle, _In_opt_ HANDLE UserApcReserveHandle,
                                             _In_ ULONG QueueUserApcFlags, _In_ PVOID ApcRoutine,
                                             _In_opt_ PVOID ApcArgument1, _In_opt_ PVOID ApcArgument2,
                                             _In_opt_ PVOID ApcArgument3);
NTSTATUS NTAPI BkntkiNtGetContextThreadHook(_In_ HANDLE ThreadHandle, _Inout_ PCONTEXT ThreadContext);
NTSTATUS NTAPI BkntkiNtSetContextThreadHook(_In_ HANDLE ThreadHandle, _In_ PCONTEXT ThreadContext);
NTSTATUS NTAPI BkntkiNtGetNextThreadHook(_In_ HANDLE ProcessHandle, _In_opt_ HANDLE ThreadHandle,
                                         _In_ ACCESS_MASK DesiredAccess, _In_ ULONG HandleAttributes, _In_ ULONG Flags,
                                         _Out_ PHANDLE NewThreadHandle);
NTSTATUS NTAPI BkntkiNtQueryInformationThreadHook(_In_ HANDLE ThreadHandle, _In_ THREADINFOCLASS ThreadInformationClass,
                                                  _Out_writes_bytes_opt_(ThreadInformationLength)
                                                      PVOID ThreadInformation,
                                                  _In_ ULONG ThreadInformationLength, _Out_opt_ PULONG ReturnLength);
NTSTATUS NTAPI BkntkiNtSetInformationThreadHook(_In_ HANDLE ThreadHandle, _In_ THREADINFOCLASS ThreadInformationClass,
                                                _In_reads_bytes_opt_(ThreadInformationLength) PVOID ThreadInformation,
                                                _In_ ULONG ThreadInformationLength);
NTSTATUS NTAPI BkntkiNtSetInformationProcessHook(_In_ HANDLE ProcessHandle,
                                                 _In_ PROCESSINFOCLASS ProcessInformationClass,
                                                 _In_reads_bytes_opt_(ProcessInformationLength)
                                                     PVOID ProcessInformation,
                                                 _In_ ULONG ProcessInformationLength);
NTSTATUS NTAPI BkntkiNtResumeThreadHook(_In_ HANDLE ThreadHandle, _Out_opt_ PULONG PreviousSuspendCount);
NTSTATUS NTAPI BkntkiNtSuspendThreadHook(_In_ HANDLE ThreadHandle, _Out_opt_ PULONG PreviousSuspendCount);
NTSTATUS NTAPI BkntkiNtAlertResumeThreadHook(_In_ HANDLE ThreadHandle, _Out_opt_ PULONG PreviousSuspendCount);
NTSTATUS NTAPI BkntkiNtAlertThreadHook(_In_ HANDLE ThreadHandle);
NTSTATUS NTAPI BkntkiNtTestAlertHook(VOID);
NTSTATUS NTAPI BkntkiNtCreateUserProcessHook(
    _Out_ PHANDLE ProcessHandle, _Out_ PHANDLE ThreadHandle, _In_ ACCESS_MASK ProcessDesiredAccess,
    _In_ ACCESS_MASK ThreadDesiredAccess, _In_opt_ POBJECT_ATTRIBUTES ProcessObjectAttributes,
    _In_opt_ POBJECT_ATTRIBUTES ThreadObjectAttributes, _In_ ULONG ProcessFlags, _In_ ULONG ThreadFlags,
    _In_opt_ PVOID ProcessParameters, _Inout_ PVOID CreateInfo, _In_opt_ PVOID AttributeList);
NTSTATUS NTAPI BkntkiNtCreateProcessExHook(_Out_ PHANDLE ProcessHandle, _In_ ACCESS_MASK DesiredAccess,
                                           _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes, _In_ HANDLE ParentProcess,
                                           _In_ ULONG Flags, _In_opt_ HANDLE SectionHandle, _In_opt_ HANDLE DebugPort,
                                           _In_opt_ HANDLE ExceptionPort, _In_ BOOLEAN InJob);
NTSTATUS NTAPI BkntkiNtCreateFileHook(_Out_ PHANDLE FileHandle, _In_ ACCESS_MASK DesiredAccess,
                                      _In_ POBJECT_ATTRIBUTES ObjectAttributes, _Out_ PIO_STATUS_BLOCK IoStatusBlock,
                                      _In_opt_ PLARGE_INTEGER AllocationSize, _In_ ULONG FileAttributes,
                                      _In_ ULONG ShareAccess, _In_ ULONG CreateDisposition, _In_ ULONG CreateOptions,
                                      _In_reads_bytes_opt_(EaLength) PVOID EaBuffer, _In_ ULONG EaLength);
NTSTATUS NTAPI BkntkiNtOpenFileHook(_Out_ PHANDLE FileHandle, _In_ ACCESS_MASK DesiredAccess,
                                    _In_ POBJECT_ATTRIBUTES ObjectAttributes, _Out_ PIO_STATUS_BLOCK IoStatusBlock,
                                    _In_ ULONG ShareAccess, _In_ ULONG OpenOptions);
NTSTATUS NTAPI BkntkiNtDeviceIoControlFileHook(_In_ HANDLE FileHandle, _In_opt_ HANDLE Event,
                                               _In_opt_ PIO_APC_ROUTINE ApcRoutine, _In_opt_ PVOID ApcContext,
                                               _Out_ PIO_STATUS_BLOCK IoStatusBlock, _In_ ULONG IoControlCode,
                                               _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
                                               _In_ ULONG InputBufferLength,
                                               _Out_writes_bytes_opt_(OutputBufferLength) PVOID OutputBuffer,
                                               _In_ ULONG OutputBufferLength);
NTSTATUS NTAPI BkntkiNtFsControlFileHook(_In_ HANDLE FileHandle, _In_opt_ HANDLE Event,
                                         _In_opt_ PIO_APC_ROUTINE ApcRoutine, _In_opt_ PVOID ApcContext,
                                         _Out_ PIO_STATUS_BLOCK IoStatusBlock, _In_ ULONG FsControlCode,
                                         _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
                                         _In_ ULONG InputBufferLength,
                                         _Out_writes_bytes_opt_(OutputBufferLength) PVOID OutputBuffer,
                                         _In_ ULONG OutputBufferLength);
NTSTATUS NTAPI BkntkiNtQueryDirectoryFileHook(_In_ HANDLE FileHandle, _In_opt_ HANDLE Event,
                                              _In_opt_ PIO_APC_ROUTINE ApcRoutine, _In_opt_ PVOID ApcContext,
                                              _Out_ PIO_STATUS_BLOCK IoStatusBlock,
                                              _Out_writes_bytes_(Length) PVOID FileInformation, _In_ ULONG Length,
                                              _In_ FILE_INFORMATION_CLASS FileInformationClass,
                                              _In_ BOOLEAN ReturnSingleEntry, _In_opt_ PUNICODE_STRING FileName,
                                              _In_ BOOLEAN RestartScan);
NTSTATUS NTAPI BkntkiNtQueryDirectoryFileExHook(_In_ HANDLE FileHandle, _In_opt_ HANDLE Event,
                                                _In_opt_ PIO_APC_ROUTINE ApcRoutine, _In_opt_ PVOID ApcContext,
                                                _Out_ PIO_STATUS_BLOCK IoStatusBlock,
                                                _Out_writes_bytes_(Length) PVOID FileInformation, _In_ ULONG Length,
                                                _In_ FILE_INFORMATION_CLASS FileInformationClass, _In_ ULONG QueryFlags,
                                                _In_opt_ PUNICODE_STRING FileName);
NTSTATUS NTAPI BkntkiNtAlpcConnectPortHook(_Out_ PHANDLE PortHandle, _In_ PUNICODE_STRING PortName,
                                           _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes, _In_opt_ PVOID PortAttributes,
                                           _In_ ULONG Flags, _In_opt_ PSID RequiredServerSid,
                                           _Inout_updates_bytes_to_opt_(*BufferLength, *BufferLength)
                                               PVOID ConnectionMessage,
                                           _Inout_opt_ PULONG BufferLength, _Inout_opt_ PVOID OutMessageAttributes,
                                           _Inout_opt_ PVOID InMessageAttributes, _In_opt_ PLARGE_INTEGER Timeout);
NTSTATUS NTAPI BkntkiNtAlpcSendWaitReceivePortHook(
    _In_ HANDLE PortHandle, _In_ ULONG Flags, _In_reads_bytes_opt_(0) PVOID SendMessage,
    _Inout_opt_ PVOID SendMessageAttributes, _Out_writes_bytes_opt_(0) PVOID ReceiveMessage,
    _Inout_opt_ PULONG BufferLength, _Inout_opt_ PVOID ReceiveMessageAttributes, _In_opt_ PLARGE_INTEGER Timeout);
NTSTATUS NTAPI BkntkiNtConnectPortHook(_Out_ PHANDLE PortHandle, _In_ PUNICODE_STRING PortName,
                                       _In_ PSECURITY_QUALITY_OF_SERVICE SecurityQos, _Inout_opt_ PVOID ClientView,
                                       _Out_opt_ PVOID ServerView, _Out_opt_ PULONG MaxMessageLength,
                                       _Inout_updates_bytes_to_opt_(*ConnectionInformationLength,
                                                                    *ConnectionInformationLength)
                                           PVOID ConnectionInformation,
                                       _Inout_opt_ PULONG ConnectionInformationLength);
NTSTATUS NTAPI BkntkiNtOpenProcessHook(_Out_ PHANDLE ProcessHandle, _In_ ACCESS_MASK DesiredAccess,
                                       _In_ POBJECT_ATTRIBUTES ObjectAttributes, _In_opt_ PCLIENT_ID ClientId);
NTSTATUS NTAPI BkntkiNtOpenThreadHook(_Out_ PHANDLE ThreadHandle, _In_ ACCESS_MASK DesiredAccess,
                                      _In_ POBJECT_ATTRIBUTES ObjectAttributes, _In_opt_ PCLIENT_ID ClientId);
NTSTATUS NTAPI BkntkiNtDuplicateObjectHook(_In_ HANDLE SourceProcessHandle, _In_ HANDLE SourceHandle,
                                           _In_opt_ HANDLE TargetProcessHandle, _Out_opt_ PHANDLE TargetHandle,
                                           _In_ ACCESS_MASK DesiredAccess, _In_ ULONG HandleAttributes,
                                           _In_ ULONG Options);
NTSTATUS NTAPI BkntkiNtQueryKeyHook(_In_ HANDLE KeyHandle, _In_ KEY_INFORMATION_CLASS KeyInformationClass,
                                    _Out_writes_bytes_opt_(Length) PVOID KeyInformation, _In_ ULONG Length,
                                    _Out_ PULONG ResultLength);
NTSTATUS NTAPI BkntkiNtEnumerateKeyHook(_In_ HANDLE KeyHandle, _In_ ULONG Index,
                                        _In_ KEY_INFORMATION_CLASS KeyInformationClass,
                                        _Out_writes_bytes_opt_(Length) PVOID KeyInformation, _In_ ULONG Length,
                                        _Out_ PULONG ResultLength);
NTSTATUS NTAPI BkntkiNtQueryValueKeyHook(_In_ HANDLE KeyHandle, _In_ PUNICODE_STRING ValueName,
                                         _In_ KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
                                         _Out_writes_bytes_opt_(Length) PVOID KeyValueInformation, _In_ ULONG Length,
                                         _Out_ PULONG ResultLength);
NTSTATUS NTAPI BkntkiNtEnumerateValueKeyHook(_In_ HANDLE KeyHandle, _In_ ULONG Index,
                                             _In_ KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
                                             _Out_writes_bytes_opt_(Length) PVOID KeyValueInformation,
                                             _In_ ULONG Length, _Out_ PULONG ResultLength);

#endif
