#include <ntddk.h>
#include <ntimage.h>
#include <ntstrsafe.h>
#include "..\..\core\control.h"
#include "..\..\core\tempus_debug.h"
#include "..\..\core\runtime_config.h"
#include "..\..\core\diagnostics.h"
#include "..\..\callbacks\process_monitor.h"
#include "..\..\antivirt\qpc_timing.h"
#include "..\..\telemetry\etw.h"
#include "..\hook\ntapi_hook.h"
#include "ntapi_monitor.h"

#if defined(_AMD64_)

#define BK_NTAPI_LOG(_level, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, (_level), __VA_ARGS__)
#define BK_SYSTEM_INFORMATION_CLASS_PROCESS 5u
#define BK_SYSTEM_INFORMATION_CLASS_MODULE 11u
#define BK_SYSTEM_INFORMATION_CLASS_HANDLE 16u
#define BK_SYSTEM_INFORMATION_CLASS_KERNEL_DEBUGGER 35u
#define BK_SYSTEM_INFORMATION_CLASS_EXTENDED_HANDLE 64u
#define BK_SYSTEM_INFORMATION_CLASS_FIRMWARE_TABLE 76u
#define BK_SYSTEM_INFORMATION_CLASS_CODE_INTEGRITY 103u
#define BK_CODE_INTEGRITY_OPTION_TESTSIGN 0x00000002u
#define BK_FIRMWARE_PROVIDER_RSMB 0x424D5352u
#define BK_MAX_INSTRUMENTATION_RANGES 512u
#define BK_MAX_HOOK_PATCH_RECORDS 512u
#define BK_MAX_HOOK_PATCH_OVERLAYS 32u
#define BK_MAX_NTDLL_SECTION_HANDLES 256u
#define BK_MAX_PROCESS_INSTRUMENTATION_CALLBACKS 512u
#ifndef PROCESS_VM_READ
#define PROCESS_VM_READ 0x0010
#endif
#ifndef PROCESS_VM_OPERATION
#define PROCESS_VM_OPERATION 0x0008
#endif
#ifndef PROCESS_VM_WRITE
#define PROCESS_VM_WRITE 0x0020
#endif

NTKERNELAPI NTSTATUS PsLookupProcessByProcessId(_In_ HANDLE ProcessId, _Outptr_ PEPROCESS *Process);
NTKERNELAPI NTSTATUS ObOpenObjectByPointer(_In_ PVOID Object, _In_ ULONG HandleAttributes,
                                           _In_opt_ PACCESS_STATE PassedAccessState, _In_ ACCESS_MASK DesiredAccess,
                                           _In_opt_ POBJECT_TYPE ObjectType, _In_ KPROCESSOR_MODE AccessMode,
                                           _Out_ PHANDLE Handle);
NTKERNELAPI NTSTATUS MmCopyVirtualMemory(_In_ PEPROCESS FromProcess, _In_ const VOID *FromAddress,
                                         _In_ PEPROCESS ToProcess, _Out_ PVOID ToAddress, _In_ SIZE_T BufferSize,
                                         _In_ KPROCESSOR_MODE PreviousMode, _Out_ PSIZE_T NumberOfBytesCopied);
NTKERNELAPI NTSTATUS ObQueryNameString(_In_ PVOID Object,
                                       _Out_writes_bytes_opt_(Length) POBJECT_NAME_INFORMATION ObjectNameInfo,
                                       _In_ ULONG Length, _Out_ PULONG ReturnLength);

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

typedef struct _BK_SYSTEM_HANDLE_TABLE_ENTRY_INFO
{
    USHORT UniqueProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR ObjectTypeIndex;
    UCHAR HandleAttributes;
    USHORT HandleValue;
    PVOID Object;
    ULONG GrantedAccess;
} BK_SYSTEM_HANDLE_TABLE_ENTRY_INFO, *PBK_SYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _BK_SYSTEM_HANDLE_INFORMATION
{
    ULONG NumberOfHandles;
    BK_SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} BK_SYSTEM_HANDLE_INFORMATION, *PBK_SYSTEM_HANDLE_INFORMATION;

typedef struct _BK_SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
{
    PVOID Object;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR HandleValue;
    ULONG GrantedAccess;
    USHORT CreatorBackTraceIndex;
    USHORT ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
} BK_SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, *PBK_SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

typedef struct _BK_SYSTEM_HANDLE_INFORMATION_EX
{
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    BK_SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
} BK_SYSTEM_HANDLE_INFORMATION_EX, *PBK_SYSTEM_HANDLE_INFORMATION_EX;

typedef struct _BK_NTAPI_INSTRUMENTATION_RANGE
{
    UINT32 ProcessId;
    UINT32 Flags;
    UINT64 BaseAddress;
    UINT64 EndAddress;
    CHAR Tag[BK_INSTRUMENTATION_RANGE_TAG_CHARS];
    BOOLEAN Active;
} BK_NTAPI_INSTRUMENTATION_RANGE, *PBK_NTAPI_INSTRUMENTATION_RANGE;

typedef struct _BK_NTAPI_HOOK_PATCH
{
    UINT32 ProcessId;
    UINT32 Flags;
    UINT64 PatchAddress;
    UINT32 PatchSize;
    UINT32 OriginalSize;
    UINT8 OriginalBytes[BK_MAX_HOOK_PATCH_BYTES];
    UINT8 CloakBytes[BK_MAX_HOOK_PATCH_BYTES];
    CHAR Tag[BK_HOOK_PATCH_TAG_CHARS];
    BOOLEAN Active;
} BK_NTAPI_HOOK_PATCH, *PBK_NTAPI_HOOK_PATCH;

typedef struct _BK_NTAPI_NTDLL_SECTION_HANDLE
{
    UINT32 ProcessId;
    UINT64 HandleValue;
    UINT32 AllocationAttributes;
    BOOLEAN Active;
} BK_NTAPI_NTDLL_SECTION_HANDLE, *PBK_NTAPI_NTDLL_SECTION_HANDLE;

typedef struct _BK_NTAPI_PROCESS_INSTRUMENTATION_CALLBACK
{
    UINT32 ProcessId;
    UINT32 Flags;
    UINT64 CallbackAddress;
    UINT64 CallbackEnd;
    UINT64 BlockedSetCount;
    BOOLEAN Active;
} BK_NTAPI_PROCESS_INSTRUMENTATION_CALLBACK, *PBK_NTAPI_PROCESS_INSTRUMENTATION_CALLBACK;

typedef struct _BK_NTAPI_HOOK_PATCH_OVERLAY
{
    SIZE_T DestOffset;
    SIZE_T CopySize;
    UINT8 Bytes[BK_MAX_HOOK_PATCH_BYTES];
} BK_NTAPI_HOOK_PATCH_OVERLAY, *PBK_NTAPI_HOOK_PATCH_OVERLAY;

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
typedef NTSTATUS(NTAPI *PBK_NT_GET_CONTEXT_THREAD)(_In_ HANDLE ThreadHandle, _Inout_ PCONTEXT ThreadContext);
typedef NTSTATUS(NTAPI *PBK_NT_SET_CONTEXT_THREAD)(_In_ HANDLE ThreadHandle, _In_ PCONTEXT ThreadContext);
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
typedef PBK_NT_DEVICE_IO_CONTROL_FILE PBK_NT_FS_CONTROL_FILE;
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

typedef enum _BK_HOOK_ID
{
    BK_HOOK_QUERY_SYSTEM_INFORMATION = 0,
    BK_HOOK_QUERY_INFORMATION_PROCESS,
    BK_HOOK_QUERY_OBJECT,
    BK_HOOK_WRITE_VIRTUAL_MEMORY,
    BK_HOOK_READ_VIRTUAL_MEMORY,
    BK_HOOK_PROTECT_VIRTUAL_MEMORY,
    BK_HOOK_CREATE_SECTION,
    BK_HOOK_MAP_VIEW_OF_SECTION,
    BK_HOOK_MAP_VIEW_OF_SECTION_EX,
    BK_HOOK_UNMAP_VIEW_OF_SECTION,
    BK_HOOK_UNMAP_VIEW_OF_SECTION_EX,
    BK_HOOK_ALLOCATE_VIRTUAL_MEMORY,
    BK_HOOK_CREATE_THREAD,
    BK_HOOK_CREATE_THREAD_EX,
    BK_HOOK_QUEUE_APC_THREAD,
    BK_HOOK_QUEUE_APC_THREAD_EX,
    BK_HOOK_QUEUE_APC_THREAD_EX2,
    BK_HOOK_QUERY_SYSTEM_INFORMATION_EX,
    BK_HOOK_QUERY_PERFORMANCE_COUNTER,
    BK_HOOK_QUERY_VIRTUAL_MEMORY,
    BK_HOOK_GET_CONTEXT_THREAD,
    BK_HOOK_SET_CONTEXT_THREAD,
    BK_HOOK_GET_NEXT_THREAD,
    BK_HOOK_QUERY_INFORMATION_THREAD,
    BK_HOOK_SET_INFORMATION_THREAD,
    BK_HOOK_SET_INFORMATION_PROCESS,
    BK_HOOK_RESUME_THREAD,
    BK_HOOK_SUSPEND_THREAD,
    BK_HOOK_ALERT_RESUME_THREAD,
    BK_HOOK_ALERT_THREAD,
    BK_HOOK_TEST_ALERT,
    BK_HOOK_CREATE_USER_PROCESS,
    BK_HOOK_CREATE_PROCESS_EX,
    BK_HOOK_CREATE_FILE,
    BK_HOOK_OPEN_FILE,
    BK_HOOK_DEVICE_IO_CONTROL_FILE,
    BK_HOOK_FS_CONTROL_FILE,
    BK_HOOK_QUERY_DIRECTORY_FILE,
    BK_HOOK_QUERY_DIRECTORY_FILE_EX,
    BK_HOOK_ALPC_CONNECT_PORT,
    BK_HOOK_ALPC_SEND_WAIT_RECEIVE_PORT,
    BK_HOOK_CONNECT_PORT,
    BK_HOOK_OPEN_PROCESS,
    BK_HOOK_OPEN_THREAD,
    BK_HOOK_DUPLICATE_OBJECT,
    BK_HOOK_QUERY_KEY,
    BK_HOOK_ENUMERATE_KEY,
    BK_HOOK_QUERY_VALUE_KEY,
    BK_HOOK_ENUMERATE_VALUE_KEY,
    BK_HOOK_COUNT
} BK_HOOK_ID;

static volatile LONG g_NtApiMonitorInitialized = 0;
static volatile LONG g_NtApiMonitorUnloading = 0;
EX_RUNDOWN_REF g_NtApiRundown;
volatile LONG g_NtApiAllocatePreLogBudget = 64;
static volatile LONG g_NtApiSkipInitBudget = 8;
static volatile LONG g_NtApiSkipIrqlBudget = 8;
static volatile LONG g_NtApiSkipArmedBudget = 8;
static volatile LONG g_NtApiSkipPidBudget = 8;
static volatile LONG g_NtApiSkipLaunchBootstrapBudget = 8;
static volatile LONG g_NtApiSkipRundownBudget = 8;
static volatile LONG g_NtApiHookInFlight = 0;
static volatile LONG g_NtApiUninitWaitBudget = 16;
static volatile LONG g_NtApiKdSanitizeBudget = 16;
static volatile LONG g_NtApiKdSanitizeApplyBudget = 16;
volatile LONG g_NtApiSmbiosSanitizeBudget = 16;
volatile LONG g_NtApiSmbiosSanitizeApplyBudget = 16;
static volatile LONG g_NtApiUnderflowLogBudget = 8;
static FAST_MUTEX g_NtApiInstrumentationRangeLock;
static BK_NTAPI_INSTRUMENTATION_RANGE g_NtApiInstrumentationRanges[BK_MAX_INSTRUMENTATION_RANGES];
static FAST_MUTEX g_NtApiHookPatchLock;
static FAST_MUTEX g_NtApiHookLifecycleLock;
static BK_NTAPI_HOOK_PATCH g_NtApiHookPatches[BK_MAX_HOOK_PATCH_RECORDS];
static FAST_MUTEX g_NtApiNtdllSectionLock;
static BK_NTAPI_NTDLL_SECTION_HANDLE g_NtApiNtdllSections[BK_MAX_NTDLL_SECTION_HANDLES];
static FAST_MUTEX g_NtApiPicLock;
static BK_NTAPI_PROCESS_INSTRUMENTATION_CALLBACK
    g_NtApiProcessInstrumentationCallbacks[BK_MAX_PROCESS_INSTRUMENTATION_CALLBACKS];
static volatile LONG g_NtApiHooksArmed = 0;
static volatile LONG64 g_NtApiHookPatchOverlayCount = 0;
static volatile LONG64 g_NtApiInstrumentationReadDenyCount = 0;
static volatile LONG64 g_NtApiDuplicateNtdllMirrorCount = 0;
static volatile LONG64 g_NtApiDuplicateNtdllMirrorFailureCount = 0;
static volatile LONG64 g_NtApiSanitizerHitCount[BkDiagSanitizerCount];

NTKERNELAPI HANDLE PsGetThreadProcessId(_In_ PETHREAD Thread);
NTSYSAPI NTSTATUS NTAPI ZwProtectVirtualMemory(_In_ HANDLE ProcessHandle, _Inout_ PVOID *BaseAddress,
                                               _Inout_ PSIZE_T RegionSize, _In_ ULONG NewProtect,
                                               _Out_ PULONG OldProtect);

PBK_NT_QUERY_SYSTEM_INFORMATION g_OriginalNtQuerySystemInformation = NULL;
PBK_NT_QUERY_INFORMATION_PROCESS g_OriginalNtQueryInformationProcess = NULL;
PBK_NT_QUERY_OBJECT g_OriginalNtQueryObject = NULL;
PBK_NT_WRITE_VIRTUAL_MEMORY g_OriginalNtWriteVirtualMemory = NULL;
PBK_NT_READ_VIRTUAL_MEMORY g_OriginalNtReadVirtualMemory = NULL;
PBK_NT_PROTECT_VIRTUAL_MEMORY g_OriginalNtProtectVirtualMemory = NULL;
PBK_NT_CREATE_SECTION g_OriginalNtCreateSection = NULL;
PBK_NT_MAP_VIEW_OF_SECTION g_OriginalNtMapViewOfSection = NULL;
PBK_NT_MAP_VIEW_OF_SECTION_EX g_OriginalNtMapViewOfSectionEx = NULL;
PBK_NT_UNMAP_VIEW_OF_SECTION g_OriginalNtUnmapViewOfSection = NULL;
PBK_NT_UNMAP_VIEW_OF_SECTION_EX g_OriginalNtUnmapViewOfSectionEx = NULL;
PBK_NT_ALLOCATE_VIRTUAL_MEMORY g_OriginalNtAllocateVirtualMemory = NULL;
PBK_NT_CREATE_THREAD g_OriginalNtCreateThread = NULL;
PBK_NT_CREATE_THREAD_EX g_OriginalNtCreateThreadEx = NULL;
PBK_NT_QUEUE_APC_THREAD g_OriginalNtQueueApcThread = NULL;
PBK_NT_QUEUE_APC_THREAD_EX g_OriginalNtQueueApcThreadEx = NULL;
PBK_NT_QUEUE_APC_THREAD_EX2 g_OriginalNtQueueApcThreadEx2 = NULL;
PBK_NT_QUERY_SYSTEM_INFORMATION_EX g_OriginalNtQuerySystemInformationEx = NULL;
PBK_NT_QUERY_PERFORMANCE_COUNTER g_OriginalNtQueryPerformanceCounter = NULL;
PBK_NT_QUERY_VIRTUAL_MEMORY g_OriginalNtQueryVirtualMemory = NULL;
PBK_NT_GET_CONTEXT_THREAD g_OriginalNtGetContextThread = NULL;
PBK_NT_SET_CONTEXT_THREAD g_OriginalNtSetContextThread = NULL;
PBK_NT_GET_NEXT_THREAD g_OriginalNtGetNextThread = NULL;
PBK_NT_QUERY_INFORMATION_THREAD g_OriginalNtQueryInformationThread = NULL;
PBK_NT_SET_INFORMATION_THREAD g_OriginalNtSetInformationThread = NULL;
PBK_NT_SET_INFORMATION_PROCESS g_OriginalNtSetInformationProcess = NULL;
PBK_NT_RESUME_THREAD g_OriginalNtResumeThread = NULL;
PBK_NT_SUSPEND_THREAD g_OriginalNtSuspendThread = NULL;
PBK_NT_ALERT_RESUME_THREAD g_OriginalNtAlertResumeThread = NULL;
PBK_NT_ALERT_THREAD g_OriginalNtAlertThread = NULL;
PBK_NT_TEST_ALERT g_OriginalNtTestAlert = NULL;
PBK_NT_CREATE_USER_PROCESS g_OriginalNtCreateUserProcess = NULL;
PBK_NT_CREATE_PROCESS_EX g_OriginalNtCreateProcessEx = NULL;
PBK_NT_CREATE_FILE g_OriginalNtCreateFile = NULL;
PBK_NT_OPEN_FILE g_OriginalNtOpenFile = NULL;
PBK_NT_DEVICE_IO_CONTROL_FILE g_OriginalNtDeviceIoControlFile = NULL;
PBK_NT_FS_CONTROL_FILE g_OriginalNtFsControlFile = NULL;
PBK_NT_QUERY_DIRECTORY_FILE g_OriginalNtQueryDirectoryFile = NULL;
PBK_NT_QUERY_DIRECTORY_FILE_EX g_OriginalNtQueryDirectoryFileEx = NULL;
PBK_NT_ALPC_CONNECT_PORT g_OriginalNtAlpcConnectPort = NULL;
PBK_NT_ALPC_SEND_WAIT_RECEIVE_PORT g_OriginalNtAlpcSendWaitReceivePort = NULL;
PBK_NT_CONNECT_PORT g_OriginalNtConnectPort = NULL;
PBK_NT_OPEN_PROCESS g_OriginalNtOpenProcess = NULL;
PBK_NT_OPEN_THREAD g_OriginalNtOpenThread = NULL;
PBK_NT_DUPLICATE_OBJECT g_OriginalNtDuplicateObject = NULL;
PBK_NT_QUERY_KEY g_OriginalNtQueryKey = NULL;
PBK_NT_ENUMERATE_KEY g_OriginalNtEnumerateKey = NULL;
PBK_NT_QUERY_VALUE_KEY g_OriginalNtQueryValueKey = NULL;
PBK_NT_ENUMERATE_VALUE_KEY g_OriginalNtEnumerateValueKey = NULL;

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
extern NTSTATUS NTAPI BkntkiNtAllocateVirtualMemoryHookStub(_In_ HANDLE ProcessHandle, _Inout_ PVOID *BaseAddress,
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
VOID BkntkiHookExit(VOID);

VOID BkntkiHookEnter(VOID);
static VOID BkntkiWaitForInFlightCalls(VOID);
static VOID BkntkiClearOriginalSlots(VOID);
static NTSTATUS BkntkiInstallHooksLocked(VOID);
static VOID BkntkiDeactivateHooksLocked(VOID);
static VOID BkntkiRemoveHooksLocked(VOID);
static UINT32 BkntkiSanitizerStreamMask(_In_ UINT32 SanitizerId);
static UINT32 BkntkiSanitizerComponentId(_In_ UINT32 SanitizerId);
static UINT32 BkntkiSanitizerSourceClass(_In_ UINT32 SanitizerId);
static UINT64 BkntkiSanitizerCounterValue(_In_ UINT32 SanitizerId);
VOID BkntkiSanitizeKernelDebuggerInformation(_In_ ULONG SystemInformationClass,
                                             _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
                                             _In_ ULONG SystemInformationLength, _In_ NTSTATUS Status);
VOID BkntkiSanitizeCodeIntegrityInformation(_In_ ULONG SystemInformationClass,
                                            _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
                                            _In_ ULONG SystemInformationLength, _In_ NTSTATUS Status);
VOID BkavNtSanitizeFirmwareTableInformation(_In_ ULONG SystemInformationClass,
                                            _Inout_updates_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
                                            _In_ ULONG SystemInformationLength, _In_ NTSTATUS Status);

static BK_NTAPI_HOOK g_Hooks[BK_HOOK_COUNT];
static const BK_NTAPI_HOOK_DESCRIPTOR g_HookDescriptors[BK_HOOK_COUNT] = {
    {"NtQuerySystemInformation",
     L"NtQuerySystemInformation",
     L"ZwQuerySystemInformation",
     NULL,
     (PVOID)BkntkiNtQuerySystemInformationHook,
     18,
     TRUE,
     0,
     {0},
     0},
    {"NtQueryInformationProcess",
     L"NtQueryProcessInformation",
     L"NtQueryInformationProcess",
     L"ZwQueryInformationProcess",
     (PVOID)BkntkiNtQueryInformationProcessHook,
     19,
     TRUE,
     0,
     {0},
     0},
    {"NtQueryObject", L"NtQueryObject", L"ZwQueryObject", NULL, (PVOID)BkntkiNtQueryObjectHook, 15, FALSE, 0, {0}, 0},
    {"NtWriteVirtualMemory",
     L"NtWriteVirtualMemory",
     L"ZwWriteVirtualMemory",
     NULL,
     (PVOID)BkntkiNtWriteVirtualMemoryHook,
     17,
     TRUE,
     0,
     {0x48, 0x83, 0xEC, 0x38, 0x48, 0x8B, 0x44, 0x24},
     8},
    {"NtReadVirtualMemory",
     L"NtReadVirtualMemory",
     L"ZwReadVirtualMemory",
     NULL,
     (PVOID)BkntkiNtReadVirtualMemoryHook,
     17,
     TRUE,
     0,
     {0x48, 0x83, 0xEC, 0x38, 0x48, 0x8B, 0x44, 0x24},
     8},
    {"NtProtectVirtualMemory",
     L"NtProtectVirtualMemory",
     L"ZwProtectVirtualMemory",
     NULL,
     (PVOID)BkntkiNtProtectVirtualMemoryHook,
     20,
     TRUE,
     0,
     {0},
     0},
    {"NtCreateSection",
     L"NtCreateSection",
     L"ZwCreateSection",
     NULL,
     (PVOID)BkntkiNtCreateSectionHook,
     17,
     TRUE,
     0,
     {0},
     0},
    {"NtMapViewOfSection",
     L"NtMapViewOfSection",
     L"ZwMapViewOfSection",
     NULL,
     (PVOID)BkntkiNtMapViewOfSectionHook,
     15,
     TRUE,
     0,
     {0},
     0},
    {"NtMapViewOfSectionEx",
     L"NtMapViewOfSectionEx",
     L"ZwMapViewOfSectionEx",
     NULL,
     (PVOID)BkntkiNtMapViewOfSectionExHook,
     15,
     FALSE,
     0,
     {0},
     0},
    {"NtUnmapViewOfSection",
     L"NtUnmapViewOfSection",
     L"ZwUnmapViewOfSection",
     NULL,
     (PVOID)BkntkiNtUnmapViewOfSectionHook,
     15,
     FALSE,
     0,
     {0},
     0},
    {"NtUnmapViewOfSectionEx",
     L"NtUnmapViewOfSectionEx",
     L"ZwUnmapViewOfSectionEx",
     NULL,
     (PVOID)BkntkiNtUnmapViewOfSectionExHook,
     15,
     FALSE,
     0,
     {0},
     0},
    {"NtAllocateVirtualMemory",
     L"NtAllocateVirtualMemory",
     L"ZwAllocateVirtualMemory",
     NULL,
     (PVOID)BkntkiNtAllocateVirtualMemoryHookStub,
     20,
     TRUE,
     0,
     {0},
     0},
    {"NtCreateThread",
     L"NtCreateThread",
     L"ZwCreateThread",
     NULL,
     (PVOID)BkntkiNtCreateThreadHook,
     15,
     FALSE,
     0,
     {0},
     0},
    {"NtCreateThreadEx",
     L"NtCreateThreadEx",
     L"ZwCreateThreadEx",
     NULL,
     (PVOID)BkntkiNtCreateThreadExHook,
     15,
     FALSE,
     0,
     {0},
     0},
    {"NtQueueApcThread",
     L"NtQueueApcThread",
     L"ZwQueueApcThread",
     NULL,
     (PVOID)BkntkiNtQueueApcThreadHook,
     15,
     FALSE,
     0,
     {0},
     0},
    {"NtQueueApcThreadEx",
     L"NtQueueApcThreadEx",
     L"ZwQueueApcThreadEx",
     NULL,
     (PVOID)BkntkiNtQueueApcThreadExHook,
     15,
     FALSE,
     0,
     {0},
     0},
    {"NtQueueApcThreadEx2",
     L"NtQueueApcThreadEx2",
     L"ZwQueueApcThreadEx2",
     NULL,
     (PVOID)BkntkiNtQueueApcThreadEx2Hook,
     15,
     FALSE,
     0,
     {0},
     0},
    {"NtQuerySystemInformationEx",
     L"NtQuerySystemInformationEx",
     L"ZwQuerySystemInformationEx",
     NULL,
     (PVOID)BkntkiNtQuerySystemInformationExHook,
     20,
     TRUE,
     0,
     {0},
     0},
    {"NtQueryPerformanceCounter",
     L"NtQueryPerformanceCounter",
     L"ZwQueryPerformanceCounter",
     NULL,
     (PVOID)BkntkiNtQueryPerformanceCounterHook,
     15,
     FALSE,
     0,
     {0},
     0},
    {"NtQueryVirtualMemory",
     L"NtQueryVirtualMemory",
     L"ZwQueryVirtualMemory",
     NULL,
     (PVOID)BkntkiNtQueryVirtualMemoryHook,
     15,
     FALSE,
     0,
     {0},
     0},
    /* Thread-context hooks: detect cross-process context read/write (hijacking, debugging, injection).
       Not required — the driver still loads if these are unhookable. */
    {"NtGetContextThread",
     L"NtGetContextThread",
     L"ZwGetContextThread",
     NULL,
     (PVOID)BkntkiNtGetContextThreadHook,
     15,
     FALSE,
     0,
     {0},
     0},
    {"NtSetContextThread",
     L"NtSetContextThread",
     L"ZwSetContextThread",
     NULL,
     (PVOID)BkntkiNtSetContextThreadHook,
     15,
     FALSE,
     0,
     {0},
     0},
    {"NtGetNextThread",
     L"NtGetNextThread",
     L"ZwGetNextThread",
     NULL,
     (PVOID)BkntkiNtGetNextThreadHook,
     15,
     FALSE,
     0,
     {0},
     0},
    {"NtQueryInformationThread",
     L"NtQueryInformationThread",
     L"ZwQueryInformationThread",
     NULL,
     (PVOID)BkntkiNtQueryInformationThreadHook,
     15,
     FALSE,
     0,
     {0},
     0},
    {"NtSetInformationThread",
     L"NtSetInformationThread",
     L"ZwSetInformationThread",
     NULL,
     (PVOID)BkntkiNtSetInformationThreadHook,
     15,
     FALSE,
     0,
     {0},
     0},
    {"NtSetInformationProcess",
     L"NtSetInformationProcess",
     L"ZwSetInformationProcess",
     NULL,
     (PVOID)BkntkiNtSetInformationProcessHook,
     15,
     FALSE,
     0,
     {0},
     0},
    {"NtResumeThread",
     L"NtResumeThread",
     L"ZwResumeThread",
     NULL,
     (PVOID)BkntkiNtResumeThreadHook,
     15,
     FALSE,
     0,
     {0},
     0},
    {"NtSuspendThread",
     L"NtSuspendThread",
     L"ZwSuspendThread",
     NULL,
     (PVOID)BkntkiNtSuspendThreadHook,
     15,
     FALSE,
     0,
     {0},
     0},
    {"NtAlertResumeThread",
     L"NtAlertResumeThread",
     L"ZwAlertResumeThread",
     NULL,
     (PVOID)BkntkiNtAlertResumeThreadHook,
     15,
     FALSE,
     0,
     {0},
     0},
    {"NtAlertThread", L"NtAlertThread", L"ZwAlertThread", NULL, (PVOID)BkntkiNtAlertThreadHook, 15, FALSE, 0, {0}, 0},
    {"NtTestAlert", L"NtTestAlert", L"ZwTestAlert", NULL, (PVOID)BkntkiNtTestAlertHook, 15, FALSE, 0, {0}, 0},
    {"NtCreateUserProcess",
     L"NtCreateUserProcess",
     L"ZwCreateUserProcess",
     NULL,
     (PVOID)BkntkiNtCreateUserProcessHook,
     15,
     FALSE,
     0,
     {0},
     0},
    {"NtCreateProcessEx",
     L"NtCreateProcessEx",
     L"ZwCreateProcessEx",
     NULL,
     (PVOID)BkntkiNtCreateProcessExHook,
     15,
     FALSE,
     0,
     {0},
     0},
    {"NtCreateFile", L"NtCreateFile", L"ZwCreateFile", NULL, (PVOID)BkntkiNtCreateFileHook, 15, FALSE, 0, {0}, 0},
    {"NtOpenFile", L"NtOpenFile", L"ZwOpenFile", NULL, (PVOID)BkntkiNtOpenFileHook, 15, FALSE, 0, {0}, 0},
    {"NtDeviceIoControlFile",
     L"NtDeviceIoControlFile",
     L"ZwDeviceIoControlFile",
     NULL,
     (PVOID)BkntkiNtDeviceIoControlFileHook,
     15,
     FALSE,
     0,
     {0},
     0},
    {"NtFsControlFile",
     L"NtFsControlFile",
     L"ZwFsControlFile",
     NULL,
     (PVOID)BkntkiNtFsControlFileHook,
     15,
     FALSE,
     0,
     {0},
     0},
    {"NtQueryDirectoryFile",
     L"NtQueryDirectoryFile",
     L"ZwQueryDirectoryFile",
     NULL,
     (PVOID)BkntkiNtQueryDirectoryFileHook,
     15,
     FALSE,
     0,
     {0},
     0},
    {"NtQueryDirectoryFileEx",
     L"NtQueryDirectoryFileEx",
     L"ZwQueryDirectoryFileEx",
     NULL,
     (PVOID)BkntkiNtQueryDirectoryFileExHook,
     15,
     FALSE,
     0,
     {0},
     0},
    {"NtAlpcConnectPort",
     L"NtAlpcConnectPort",
     L"ZwAlpcConnectPort",
     NULL,
     (PVOID)BkntkiNtAlpcConnectPortHook,
     15,
     FALSE,
     0,
     {0},
     0},
    {"NtAlpcSendWaitReceivePort",
     L"NtAlpcSendWaitReceivePort",
     L"ZwAlpcSendWaitReceivePort",
     NULL,
     (PVOID)BkntkiNtAlpcSendWaitReceivePortHook,
     15,
     FALSE,
     0,
     {0},
     0},
    {"NtConnectPort", L"NtConnectPort", L"ZwConnectPort", NULL, (PVOID)BkntkiNtConnectPortHook, 15, FALSE, 0, {0}, 0},
    {"NtOpenProcess", L"NtOpenProcess", L"ZwOpenProcess", NULL, (PVOID)BkntkiNtOpenProcessHook, 15, FALSE, 0, {0}, 0},
    {"NtOpenThread", L"NtOpenThread", L"ZwOpenThread", NULL, (PVOID)BkntkiNtOpenThreadHook, 15, FALSE, 0, {0}, 0},
    {"NtDuplicateObject",
     L"NtDuplicateObject",
     L"ZwDuplicateObject",
     NULL,
     (PVOID)BkntkiNtDuplicateObjectHook,
     15,
     FALSE,
     0,
     {0},
     0},
    {"NtQueryKey", L"NtQueryKey", L"ZwQueryKey", NULL, (PVOID)BkntkiNtQueryKeyHook, 15, FALSE, 0, {0}, 0},
    {"NtEnumerateKey",
     L"NtEnumerateKey",
     L"ZwEnumerateKey",
     NULL,
     (PVOID)BkntkiNtEnumerateKeyHook,
     15,
     FALSE,
     0,
     {0},
     0},
    {"NtQueryValueKey",
     L"NtQueryValueKey",
     L"ZwQueryValueKey",
     NULL,
     (PVOID)BkntkiNtQueryValueKeyHook,
     15,
     FALSE,
     0,
     {0},
     0},
    {"NtEnumerateValueKey",
     L"NtEnumerateValueKey",
     L"ZwEnumerateValueKey",
     NULL,
     (PVOID)BkntkiNtEnumerateValueKeyHook,
     15,
     FALSE,
     0,
     {0},
     0},
};

static PVOID *BkntkiOriginalSlot(_In_ BK_HOOK_ID HookId)
{
    switch (HookId)
    {
    case BK_HOOK_QUERY_SYSTEM_INFORMATION:
        return (PVOID *)&g_OriginalNtQuerySystemInformation;
    case BK_HOOK_QUERY_INFORMATION_PROCESS:
        return (PVOID *)&g_OriginalNtQueryInformationProcess;
    case BK_HOOK_QUERY_OBJECT:
        return (PVOID *)&g_OriginalNtQueryObject;
    case BK_HOOK_WRITE_VIRTUAL_MEMORY:
        return (PVOID *)&g_OriginalNtWriteVirtualMemory;
    case BK_HOOK_READ_VIRTUAL_MEMORY:
        return (PVOID *)&g_OriginalNtReadVirtualMemory;
    case BK_HOOK_PROTECT_VIRTUAL_MEMORY:
        return (PVOID *)&g_OriginalNtProtectVirtualMemory;
    case BK_HOOK_CREATE_SECTION:
        return (PVOID *)&g_OriginalNtCreateSection;
    case BK_HOOK_MAP_VIEW_OF_SECTION:
        return (PVOID *)&g_OriginalNtMapViewOfSection;
    case BK_HOOK_MAP_VIEW_OF_SECTION_EX:
        return (PVOID *)&g_OriginalNtMapViewOfSectionEx;
    case BK_HOOK_UNMAP_VIEW_OF_SECTION:
        return (PVOID *)&g_OriginalNtUnmapViewOfSection;
    case BK_HOOK_UNMAP_VIEW_OF_SECTION_EX:
        return (PVOID *)&g_OriginalNtUnmapViewOfSectionEx;
    case BK_HOOK_ALLOCATE_VIRTUAL_MEMORY:
        return (PVOID *)&g_OriginalNtAllocateVirtualMemory;
    case BK_HOOK_CREATE_THREAD:
        return (PVOID *)&g_OriginalNtCreateThread;
    case BK_HOOK_CREATE_THREAD_EX:
        return (PVOID *)&g_OriginalNtCreateThreadEx;
    case BK_HOOK_QUEUE_APC_THREAD:
        return (PVOID *)&g_OriginalNtQueueApcThread;
    case BK_HOOK_QUEUE_APC_THREAD_EX:
        return (PVOID *)&g_OriginalNtQueueApcThreadEx;
    case BK_HOOK_QUEUE_APC_THREAD_EX2:
        return (PVOID *)&g_OriginalNtQueueApcThreadEx2;
    case BK_HOOK_QUERY_SYSTEM_INFORMATION_EX:
        return (PVOID *)&g_OriginalNtQuerySystemInformationEx;
    case BK_HOOK_QUERY_PERFORMANCE_COUNTER:
        return (PVOID *)&g_OriginalNtQueryPerformanceCounter;
    case BK_HOOK_QUERY_VIRTUAL_MEMORY:
        return (PVOID *)&g_OriginalNtQueryVirtualMemory;
    case BK_HOOK_GET_CONTEXT_THREAD:
        return (PVOID *)&g_OriginalNtGetContextThread;
    case BK_HOOK_SET_CONTEXT_THREAD:
        return (PVOID *)&g_OriginalNtSetContextThread;
    case BK_HOOK_GET_NEXT_THREAD:
        return (PVOID *)&g_OriginalNtGetNextThread;
    case BK_HOOK_QUERY_INFORMATION_THREAD:
        return (PVOID *)&g_OriginalNtQueryInformationThread;
    case BK_HOOK_SET_INFORMATION_THREAD:
        return (PVOID *)&g_OriginalNtSetInformationThread;
    case BK_HOOK_SET_INFORMATION_PROCESS:
        return (PVOID *)&g_OriginalNtSetInformationProcess;
    case BK_HOOK_RESUME_THREAD:
        return (PVOID *)&g_OriginalNtResumeThread;
    case BK_HOOK_SUSPEND_THREAD:
        return (PVOID *)&g_OriginalNtSuspendThread;
    case BK_HOOK_ALERT_RESUME_THREAD:
        return (PVOID *)&g_OriginalNtAlertResumeThread;
    case BK_HOOK_ALERT_THREAD:
        return (PVOID *)&g_OriginalNtAlertThread;
    case BK_HOOK_TEST_ALERT:
        return (PVOID *)&g_OriginalNtTestAlert;
    case BK_HOOK_CREATE_USER_PROCESS:
        return (PVOID *)&g_OriginalNtCreateUserProcess;
    case BK_HOOK_CREATE_PROCESS_EX:
        return (PVOID *)&g_OriginalNtCreateProcessEx;
    case BK_HOOK_CREATE_FILE:
        return (PVOID *)&g_OriginalNtCreateFile;
    case BK_HOOK_OPEN_FILE:
        return (PVOID *)&g_OriginalNtOpenFile;
    case BK_HOOK_DEVICE_IO_CONTROL_FILE:
        return (PVOID *)&g_OriginalNtDeviceIoControlFile;
    case BK_HOOK_FS_CONTROL_FILE:
        return (PVOID *)&g_OriginalNtFsControlFile;
    case BK_HOOK_QUERY_DIRECTORY_FILE:
        return (PVOID *)&g_OriginalNtQueryDirectoryFile;
    case BK_HOOK_QUERY_DIRECTORY_FILE_EX:
        return (PVOID *)&g_OriginalNtQueryDirectoryFileEx;
    case BK_HOOK_ALPC_CONNECT_PORT:
        return (PVOID *)&g_OriginalNtAlpcConnectPort;
    case BK_HOOK_ALPC_SEND_WAIT_RECEIVE_PORT:
        return (PVOID *)&g_OriginalNtAlpcSendWaitReceivePort;
    case BK_HOOK_CONNECT_PORT:
        return (PVOID *)&g_OriginalNtConnectPort;
    case BK_HOOK_OPEN_PROCESS:
        return (PVOID *)&g_OriginalNtOpenProcess;
    case BK_HOOK_OPEN_THREAD:
        return (PVOID *)&g_OriginalNtOpenThread;
    case BK_HOOK_DUPLICATE_OBJECT:
        return (PVOID *)&g_OriginalNtDuplicateObject;
    case BK_HOOK_QUERY_KEY:
        return (PVOID *)&g_OriginalNtQueryKey;
    case BK_HOOK_ENUMERATE_KEY:
        return (PVOID *)&g_OriginalNtEnumerateKey;
    case BK_HOOK_QUERY_VALUE_KEY:
        return (PVOID *)&g_OriginalNtQueryValueKey;
    case BK_HOOK_ENUMERATE_VALUE_KEY:
        return (PVOID *)&g_OriginalNtEnumerateValueKey;
    default:
        return NULL;
    }
}

VOID BkntkiHookEnter(VOID)
{
    InterlockedIncrement(&g_NtApiHookInFlight);
}

VOID BkntkiHookExit(VOID)
{
    LONG remaining = InterlockedDecrement(&g_NtApiHookInFlight);
    if (remaining < 0)
    {
        /* Restore to 0 only if the counter is still negative — avoids wiping
           a legitimate positive count that arrived between the decrement and this
           exchange (which was the original source of cascade underflows). */
        InterlockedCompareExchange(&g_NtApiHookInFlight, 0, remaining);

        /* Rate-limit the log to suppress spam during high-frequency hook paths */
        if (InterlockedDecrement(&g_NtApiUnderflowLogBudget) >= 0)
        {
            BK_NTAPI_LOG(DPFLTR_ERROR_LEVEL, "BK: ntapi hook in-flight underflow (remaining=%ld) — corrected.\n",
                         remaining);
        }
    }
}

static VOID BkntkiWaitForInFlightCalls(VOID)
{
    LARGE_INTEGER delay;
    LONG inFlight;

    delay.QuadPart = -10 * 1000;
    for (;;)
    {
        inFlight = InterlockedCompareExchange(&g_NtApiHookInFlight, 0, 0);
        if (inFlight == 0)
        {
            break;
        }

        if (InterlockedDecrement(&g_NtApiUninitWaitBudget) >= 0)
        {
            BK_NTAPI_LOG(DPFLTR_INFO_LEVEL, "BK: ntapi unload waiting for in-flight hooks count=%ld.\n", inFlight);
        }
        KeDelayExecutionThread(KernelMode, FALSE, &delay);
    }
}

VOID BkntkiSanitizeKernelDebuggerInformation(_In_ ULONG SystemInformationClass,
                                             _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
                                             _In_ ULONG SystemInformationLength, _In_ NTSTATUS Status)
{
    PBK_SYSTEM_KERNEL_DEBUGGER_INFORMATION info;

    if (SystemInformationClass != BK_SYSTEM_INFORMATION_CLASS_KERNEL_DEBUGGER || !NT_SUCCESS(Status) ||
        SystemInformation == NULL || SystemInformationLength < sizeof(*info))
    {
        return;
    }

    __try
    {
        info = (PBK_SYSTEM_KERNEL_DEBUGGER_INFORMATION)SystemInformation;
        info->KernelDebuggerEnabled = FALSE;
        info->KernelDebuggerNotPresent = TRUE;
        BkntkiRecordSanitizerHit(BkDiagSanitizerKernelDebugger);
        if (InterlockedDecrement(&g_NtApiKdSanitizeApplyBudget) >= 0)
        {
            BK_NTAPI_LOG(DPFLTR_INFO_LEVEL,
                         "BK: ntapi sanitized kernel-debugger info class=0x%lX enabled=0 notPresent=1.\n",
                         SystemInformationClass);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        if (InterlockedDecrement(&g_NtApiKdSanitizeBudget) >= 0)
        {
            BK_NTAPI_LOG(DPFLTR_WARNING_LEVEL,
                         "BK: ntapi kernel-debugger sanitize failed class=0x%lX status=0x%08X ex=0x%08X.\n",
                         SystemInformationClass, Status, GetExceptionCode());
        }
    }
}

VOID BkntkiSanitizeCodeIntegrityInformation(_In_ ULONG SystemInformationClass,
                                            _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
                                            _In_ ULONG SystemInformationLength, _In_ NTSTATUS Status)
{
    PBK_SYSTEM_CODEINTEGRITY_INFORMATION info;

    if (SystemInformationClass != BK_SYSTEM_INFORMATION_CLASS_CODE_INTEGRITY || !NT_SUCCESS(Status) ||
        SystemInformation == NULL || SystemInformationLength < sizeof(*info))
    {
        return;
    }

    __try
    {
        info = (PBK_SYSTEM_CODEINTEGRITY_INFORMATION)SystemInformation;
        if ((info->CodeIntegrityOptions & BK_CODE_INTEGRITY_OPTION_TESTSIGN) != 0)
        {
            BkntkiRecordSanitizerHit(BkDiagSanitizerCodeIntegrity);
        }
        info->CodeIntegrityOptions &= ~BK_CODE_INTEGRITY_OPTION_TESTSIGN;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        BK_NTAPI_LOG(DPFLTR_WARNING_LEVEL,
                     "BK: ntapi code-integrity sanitize failed class=0x%lX status=0x%08X ex=0x%08X.\n",
                     SystemInformationClass, Status, GetExceptionCode());
    }
}

typedef struct _BK_SYSTEM_PROCESS_INFORMATION
{
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize;
    ULONG HardFaultCount;
    ULONG NumberOfThreadsHighWatermark;
    ULONGLONG CycleTime;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    PVOID InheritedFromUniqueProcessId;
} BK_SYSTEM_PROCESS_INFORMATION, *PBK_SYSTEM_PROCESS_INFORMATION;

typedef struct _BK_SYSTEM_MODULE_ENTRY
{
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} BK_SYSTEM_MODULE_ENTRY, *PBK_SYSTEM_MODULE_ENTRY;

typedef struct _BK_SYSTEM_MODULE_INFORMATION
{
    ULONG NumberOfModules;
    BK_SYSTEM_MODULE_ENTRY Modules[1];
} BK_SYSTEM_MODULE_INFORMATION, *PBK_SYSTEM_MODULE_INFORMATION;

static BOOLEAN BkntkiUnicodeEqualsInsensitive(_In_ PCUNICODE_STRING Value, _In_ PCUNICODE_STRING Expected)
{
    if (Value == NULL || Expected == NULL || Value->Buffer == NULL || Expected->Buffer == NULL)
    {
        return FALSE;
    }

    return RtlEqualUnicodeString(Value, Expected, TRUE);
}

static BOOLEAN BkntkiAnsiEqualsInsensitive(_In_z_ const UCHAR *Value, _In_z_ const CHAR *Expected)
{
    SIZE_T i = 0;
    CHAR left;
    CHAR right;

    if (Value == NULL || Expected == NULL)
    {
        return FALSE;
    }

    for (;;)
    {
        left = (CHAR)Value[i];
        right = Expected[i];
        if (left >= 'A' && left <= 'Z')
        {
            left = (CHAR)(left - 'A' + 'a');
        }
        if (right >= 'A' && right <= 'Z')
        {
            right = (CHAR)(right - 'A' + 'a');
        }
        if (left != right)
        {
            return FALSE;
        }
        if (left == '\0')
        {
            return TRUE;
        }
        i++;
    }
}

VOID BkntkiSanitizeProcessInformation(_In_ ULONG SystemInformationClass,
                                      _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
                                      _In_ ULONG SystemInformationLength, _In_ NTSTATUS Status)
{
    static const UNICODE_STRING selfHiddenNames[] = {
        RTL_CONSTANT_STRING(L"BlackbirdController.exe"),
        RTL_CONSTANT_STRING(L"BlackbirdNetSvc.exe"),
    };
    static const UNICODE_STRING antiVirtualizationNames[] = {
        RTL_CONSTANT_STRING(L"vmtoolsd.exe"),
        RTL_CONSTANT_STRING(L"vm3dservice.exe"),
        RTL_CONSTANT_STRING(L"VGAuthService.exe"),
        RTL_CONSTANT_STRING(L"vboxservice.exe"),
        RTL_CONSTANT_STRING(L"vboxtray.exe"),
        RTL_CONSTANT_STRING(L"qemu-ga.exe"),
        RTL_CONSTANT_STRING(L"qga.exe"),
        RTL_CONSTANT_STRING(L"qemuwmiagent.exe"),
        RTL_CONSTANT_STRING(L"spice-vdagent.exe"),
        RTL_CONSTANT_STRING(L"spice-agent.exe"),
        RTL_CONSTANT_STRING(L"spice-vdagentd.exe"),
        RTL_CONSTANT_STRING(L"virtiofs.exe"),
        RTL_CONSTANT_STRING(L"virtiofsd.exe"),
        RTL_CONSTANT_STRING(L"prl_tools.exe"),
        RTL_CONSTANT_STRING(L"prl_cc.exe"),
        RTL_CONSTANT_STRING(L"prl_tools_service.exe"),
        RTL_CONSTANT_STRING(L"xenservice.exe"),
        RTL_CONSTANT_STRING(L"xensvc.exe"),
    };
    PUCHAR base;
    PBK_SYSTEM_PROCESS_INFORMATION previous;
    PBK_SYSTEM_PROCESS_INFORMATION current;
    BOOLEAN callerIsController;
    BOOLEAN callerIsInterface;
    BOOLEAN removedAny = FALSE;

    if (SystemInformationClass != BK_SYSTEM_INFORMATION_CLASS_PROCESS || !NT_SUCCESS(Status) ||
        SystemInformation == NULL || SystemInformationLength < sizeof(BK_SYSTEM_PROCESS_INFORMATION))
    {
        return;
    }

    callerIsController = BkcprocIsControllerPid((UINT32)(ULONG_PTR)PsGetCurrentProcessId());
    callerIsInterface = BkcprocIsInterfacePid((UINT32)(ULONG_PTR)PsGetCurrentProcessId());

    __try
    {
        base = (PUCHAR)SystemInformation;
        previous = NULL;
        current = (PBK_SYSTEM_PROCESS_INFORMATION)base;

        for (;;)
        {
            ULONG currentOffset = (ULONG)((PUCHAR)current - base);
            BOOLEAN shouldHide = FALSE;
            ULONG nameIndex;

            if (currentOffset + sizeof(*current) > SystemInformationLength)
            {
                break;
            }

            if (BkrtIsSelfHideEnabled() && !callerIsController && !callerIsInterface)
            {
                for (nameIndex = 0; nameIndex < RTL_NUMBER_OF(selfHiddenNames); ++nameIndex)
                {
                    if (BkntkiUnicodeEqualsInsensitive(&current->ImageName, &selfHiddenNames[nameIndex]))
                    {
                        shouldHide = TRUE;
                        break;
                    }
                }
            }

            if (!shouldHide && BkrtIsAntiVirtualizationEnabled())
            {
                for (nameIndex = 0; nameIndex < RTL_NUMBER_OF(antiVirtualizationNames); ++nameIndex)
                {
                    if (BkntkiUnicodeEqualsInsensitive(&current->ImageName, &antiVirtualizationNames[nameIndex]))
                    {
                        shouldHide = TRUE;
                        break;
                    }
                }
            }

            if (shouldHide)
            {
                removedAny = TRUE;
                if (current->NextEntryOffset == 0)
                {
                    if (previous != NULL)
                    {
                        previous->NextEntryOffset = 0;
                    }
                    else
                    {
                        RtlZeroMemory(current, SystemInformationLength - currentOffset);
                    }
                    break;
                }

                if (currentOffset + current->NextEntryOffset > SystemInformationLength)
                {
                    break;
                }

                if (previous == NULL)
                {
                    SIZE_T bytesToMove = SystemInformationLength - (currentOffset + current->NextEntryOffset);
                    RtlMoveMemory(current, base + currentOffset + current->NextEntryOffset, bytesToMove);
                    RtlZeroMemory(base + SystemInformationLength - current->NextEntryOffset, current->NextEntryOffset);
                    continue;
                }

                previous->NextEntryOffset += current->NextEntryOffset;
                current = (PBK_SYSTEM_PROCESS_INFORMATION)((PUCHAR)previous + previous->NextEntryOffset);
                continue;
            }

            if (current->NextEntryOffset == 0)
            {
                break;
            }
            if (currentOffset + current->NextEntryOffset > SystemInformationLength)
            {
                break;
            }

            previous = current;
            current = (PBK_SYSTEM_PROCESS_INFORMATION)(base + currentOffset + current->NextEntryOffset);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
    }

    if (removedAny)
    {
        BkntkiRecordSanitizerHit(BkDiagSanitizerSystemProcessList);
    }
}

VOID BkntkiSanitizeModuleInformation(_In_ ULONG SystemInformationClass,
                                     _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
                                     _In_ ULONG SystemInformationLength, _In_ NTSTATUS Status)
{
    PBK_SYSTEM_MODULE_INFORMATION modules;
    ULONG index;

    if (SystemInformationClass != BK_SYSTEM_INFORMATION_CLASS_MODULE || !NT_SUCCESS(Status) ||
        SystemInformation == NULL || SystemInformationLength < sizeof(BK_SYSTEM_MODULE_INFORMATION))
    {
        return;
    }

    if (!BkrtIsSelfHideEnabled())
    {
        return;
    }

    __try
    {
        modules = (PBK_SYSTEM_MODULE_INFORMATION)SystemInformation;
        if (modules->NumberOfModules == 0)
        {
            return;
        }
        if (FIELD_OFFSET(BK_SYSTEM_MODULE_INFORMATION, Modules) +
                (modules->NumberOfModules * sizeof(BK_SYSTEM_MODULE_ENTRY)) >
            SystemInformationLength)
        {
            return;
        }

        index = 0;
        while (index < modules->NumberOfModules)
        {
            PBK_SYSTEM_MODULE_ENTRY entry = &modules->Modules[index];
            const UCHAR *fileName = entry->FullPathName;

            if (entry->OffsetToFileName < RTL_NUMBER_OF(entry->FullPathName))
            {
                fileName = entry->FullPathName + entry->OffsetToFileName;
            }

            if (BkntkiAnsiEqualsInsensitive(fileName, "Blackbird.sys"))
            {
                ULONG remaining = modules->NumberOfModules - index - 1;
                if (remaining != 0)
                {
                    RtlMoveMemory(entry, entry + 1, remaining * sizeof(*entry));
                }
                modules->NumberOfModules--;
                BkntkiRecordSanitizerHit(BkDiagSanitizerSystemModuleList);
                continue;
            }

            index++;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
    }
}

#define BK_PROCESS_DEBUG_PORT 7u
#define BK_PROCESS_DEBUG_OBJECT_HANDLE 30u
#define BK_PROCESS_DEBUG_FLAGS 31u

VOID BkntkiSanitizeProcessQueryInformation(_In_ ULONG ProcessInformationClass,
                                           _Out_writes_bytes_opt_(ProcessInformationLength) PVOID ProcessInformation,
                                           _In_ ULONG ProcessInformationLength, _Out_opt_ PULONG ReturnLength,
                                           _In_ NTSTATUS Status)
{
    ULONG effectiveLength;

    if (!NT_SUCCESS(Status) || ProcessInformation == NULL || ProcessInformationLength == 0)
    {
        return;
    }

    effectiveLength = 0;
    if (ReturnLength != NULL)
    {
        __try
        {
            effectiveLength = *ReturnLength;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            effectiveLength = 0;
        }
    }
    if (effectiveLength == 0 || effectiveLength > ProcessInformationLength)
    {
        effectiveLength = ProcessInformationLength;
    }

    __try
    {
        switch (ProcessInformationClass)
        {
        case BK_PROCESS_DEBUG_PORT:
        case BK_PROCESS_DEBUG_OBJECT_HANDLE:
            if (effectiveLength >= sizeof(ULONG_PTR))
            {
                *(PULONG_PTR)ProcessInformation = 0;
                BkntkiRecordSanitizerHit(BkDiagSanitizerProcessDebugQuery);
            }
            break;
        case BK_PROCESS_DEBUG_FLAGS:
            if (effectiveLength >= sizeof(ULONG))
            {
                *(PULONG)ProcessInformation = 1u;
                BkntkiRecordSanitizerHit(BkDiagSanitizerProcessDebugQuery);
            }
            break;
        default:
            break;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
    }
}

ULONG BkntkiReadUlongSafe(_In_opt_ PULONG Value)
{
    ULONG observed = 0;

    if (Value == NULL)
    {
        return 0;
    }
    __try
    {
        observed = *Value;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        observed = 0;
    }
    return observed;
}

SIZE_T BkntkiReadSizeTSafe(_In_opt_ PSIZE_T Value)
{
    SIZE_T observed = 0;

    if (Value == NULL)
    {
        return 0;
    }
    __try
    {
        observed = *Value;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        observed = 0;
    }
    return observed;
}

PVOID BkntkiReadPointerSafe(_In_opt_ PVOID *Value)
{
    PVOID observed = NULL;

    if (Value == NULL)
    {
        return NULL;
    }
    __try
    {
        observed = *Value;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        observed = NULL;
    }
    return observed;
}

HANDLE BkntkiReadHandleSafe(_In_opt_ PHANDLE Value)
{
    HANDLE observed = NULL;

    if (Value == NULL)
    {
        return NULL;
    }
    __try
    {
        observed = *Value;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        observed = NULL;
    }
    return observed;
}

ULONGLONG BkntkiReadLargeIntegerSafe(_In_opt_ PLARGE_INTEGER Value)
{
    ULONGLONG observed = 0;

    if (Value == NULL)
    {
        return 0;
    }
    __try
    {
        observed = (ULONGLONG)Value->QuadPart;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        observed = 0;
    }
    return observed;
}

static SIZE_T BkntkiWideLiteralLength(_In_z_ PCWSTR Literal)
{
    SIZE_T length = 0;
    if (Literal == NULL)
    {
        return 0;
    }
    while (Literal[length] != L'\0')
    {
        length += 1;
    }
    return length;
}

static WCHAR BkntkiFoldWide(_In_ WCHAR Ch)
{
    if (Ch >= L'A' && Ch <= L'Z')
    {
        return (WCHAR)(Ch + (L'a' - L'A'));
    }
    return Ch;
}

static BOOLEAN BkntkiUnicodeContainsLiteral(_In_ const UNICODE_STRING *Value, _In_z_ PCWSTR Literal)
{
    SIZE_T valueChars;
    SIZE_T literalChars;
    SIZE_T i;

    if (Value == NULL || Value->Buffer == NULL || Literal == NULL)
    {
        return FALSE;
    }
    valueChars = Value->Length / sizeof(WCHAR);
    literalChars = BkntkiWideLiteralLength(Literal);
    if (literalChars == 0 || literalChars > valueChars)
    {
        return FALSE;
    }

    for (i = 0; i + literalChars <= valueChars; ++i)
    {
        SIZE_T j;
        BOOLEAN matched = TRUE;
        for (j = 0; j < literalChars; ++j)
        {
            if (BkntkiFoldWide(Value->Buffer[i + j]) != BkntkiFoldWide(Literal[j]))
            {
                matched = FALSE;
                break;
            }
        }
        if (matched)
        {
            return TRUE;
        }
    }
    return FALSE;
}

static BOOLEAN BkntkiObjectNameIsProtectedIpc(_In_ PVOID Object)
{
    ULONG bytes = 0;
    POBJECT_NAME_INFORMATION nameInfo = NULL;
    NTSTATUS status;
    BOOLEAN protectedName = FALSE;

    if (Object == NULL || KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        return FALSE;
    }

    status = ObQueryNameString(Object, NULL, 0, &bytes);
    if (bytes == 0 || (status != STATUS_INFO_LENGTH_MISMATCH && status != STATUS_BUFFER_OVERFLOW))
    {
        return FALSE;
    }

    nameInfo = (POBJECT_NAME_INFORMATION)ExAllocatePool2(POOL_FLAG_PAGED, bytes, 'hNbB');
    if (nameInfo == NULL)
    {
        return FALSE;
    }

    status = ObQueryNameString(Object, nameInfo, bytes, &bytes);
    if (NT_SUCCESS(status))
    {
        protectedName = BkntkiUnicodeContainsLiteral(&nameInfo->Name, L"BlackbirdHookIngest") ||
                        BkntkiUnicodeContainsLiteral(&nameInfo->Name, L"BlackbirdController") ||
                        BkntkiUnicodeContainsLiteral(&nameInfo->Name, L"BlackbirdNetSvc");
    }

    ExFreePoolWithTag(nameInfo, 'hNbB');
    return protectedName;
}

static BOOLEAN BkntkiObjectNameContainsLiteral(_In_ PVOID Object, _In_z_ PCWSTR Literal)
{
    ULONG bytes = 0;
    POBJECT_NAME_INFORMATION nameInfo = NULL;
    NTSTATUS status;
    BOOLEAN matched = FALSE;

    if (Object == NULL || Literal == NULL || KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        return FALSE;
    }

    status = ObQueryNameString(Object, NULL, 0, &bytes);
    if (bytes == 0 || (status != STATUS_INFO_LENGTH_MISMATCH && status != STATUS_BUFFER_OVERFLOW))
    {
        return FALSE;
    }

    nameInfo = (POBJECT_NAME_INFORMATION)ExAllocatePool2(POOL_FLAG_PAGED, bytes, 'oNbB');
    if (nameInfo == NULL)
    {
        return FALSE;
    }

    status = ObQueryNameString(Object, nameInfo, bytes, &bytes);
    if (NT_SUCCESS(status))
    {
        matched = BkntkiUnicodeContainsLiteral(&nameInfo->Name, Literal);
    }

    ExFreePoolWithTag(nameInfo, 'oNbB');
    return matched;
}

BOOLEAN BkntkiHandleValueIsProtectedIpc(_In_ HANDLE HandleValue)
{
    PVOID object = NULL;
    NTSTATUS status;
    BOOLEAN protectedName = FALSE;

    if (HandleValue == NULL || HandleValue == (HANDLE)(LONG_PTR)-1 || KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        return FALSE;
    }

    status = ObReferenceObjectByHandle(HandleValue, 0, NULL, ExGetPreviousMode(), &object, NULL);
    if (!NT_SUCCESS(status) || object == NULL)
    {
        return FALSE;
    }

    protectedName = BkntkiObjectNameIsProtectedIpc(object);
    ObDereferenceObject(object);
    return protectedName;
}

BOOLEAN BkntkiHandleValueNameContainsLiteral(_In_ HANDLE HandleValue, _In_z_ PCWSTR Literal)
{
    PVOID object = NULL;
    NTSTATUS status;
    BOOLEAN matched;

    if (HandleValue == NULL || HandleValue == (HANDLE)(LONG_PTR)-1 || Literal == NULL ||
        KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        return FALSE;
    }

    status = ObReferenceObjectByHandle(HandleValue, 0, NULL, ExGetPreviousMode(), &object, NULL);
    if (!NT_SUCCESS(status) || object == NULL)
    {
        return FALSE;
    }

    matched = BkntkiObjectNameContainsLiteral(object, Literal);
    ObDereferenceObject(object);
    return matched;
}

VOID BkntkiRememberNtdllSectionHandle(_In_ HANDLE SectionHandle, _In_ ULONG AllocationAttributes)
{
    UINT32 pid = (UINT32)(ULONG_PTR)PsGetCurrentProcessId();
    UINT64 handleValue = (UINT64)(ULONG_PTR)SectionHandle;
    UINT32 i;
    UINT32 freeIndex = BK_MAX_NTDLL_SECTION_HANDLES;

    if (pid == 0 || handleValue == 0 || KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        return;
    }

    ExAcquireFastMutex(&g_NtApiNtdllSectionLock);
    for (i = 0; i < BK_MAX_NTDLL_SECTION_HANDLES; ++i)
    {
        PBK_NTAPI_NTDLL_SECTION_HANDLE slot = &g_NtApiNtdllSections[i];
        if (!slot->Active)
        {
            if (freeIndex == BK_MAX_NTDLL_SECTION_HANDLES)
            {
                freeIndex = i;
            }
            continue;
        }
        if (slot->ProcessId == pid && slot->HandleValue == handleValue)
        {
            slot->AllocationAttributes = AllocationAttributes;
            ExReleaseFastMutex(&g_NtApiNtdllSectionLock);
            return;
        }
    }

    if (freeIndex != BK_MAX_NTDLL_SECTION_HANDLES)
    {
        g_NtApiNtdllSections[freeIndex].ProcessId = pid;
        g_NtApiNtdllSections[freeIndex].HandleValue = handleValue;
        g_NtApiNtdllSections[freeIndex].AllocationAttributes = AllocationAttributes;
        g_NtApiNtdllSections[freeIndex].Active = TRUE;
    }
    ExReleaseFastMutex(&g_NtApiNtdllSectionLock);
}

BOOLEAN BkntkiIsTrackedNtdllSectionHandle(_In_ HANDLE SectionHandle, _Out_opt_ UINT32 *AllocationAttributes)
{
    UINT32 pid = (UINT32)(ULONG_PTR)PsGetCurrentProcessId();
    UINT64 handleValue = (UINT64)(ULONG_PTR)SectionHandle;
    UINT32 i;
    BOOLEAN matched = FALSE;

    if (AllocationAttributes != NULL)
    {
        *AllocationAttributes = 0;
    }
    if (pid == 0 || handleValue == 0 || KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        return FALSE;
    }

    ExAcquireFastMutex(&g_NtApiNtdllSectionLock);
    for (i = 0; i < BK_MAX_NTDLL_SECTION_HANDLES; ++i)
    {
        const BK_NTAPI_NTDLL_SECTION_HANDLE *slot = &g_NtApiNtdllSections[i];
        if (slot->Active && slot->ProcessId == pid && slot->HandleValue == handleValue)
        {
            if (AllocationAttributes != NULL)
            {
                *AllocationAttributes = slot->AllocationAttributes;
            }
            matched = TRUE;
            break;
        }
    }
    ExReleaseFastMutex(&g_NtApiNtdllSectionLock);

    return matched;
}

static VOID BkntkiSanitizeHandleInformation(_In_ ULONG SystemInformationClass,
                                            _Inout_updates_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
                                            _In_ ULONG SystemInformationLength, _In_ NTSTATUS Status)
{
    ULONG_PTR currentPid = (ULONG_PTR)PsGetCurrentProcessId();

    if (!NT_SUCCESS(Status) || SystemInformation == NULL || SystemInformationLength == 0 ||
        KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        return;
    }

    __try
    {
        if (SystemInformationClass == BK_SYSTEM_INFORMATION_CLASS_HANDLE &&
            SystemInformationLength >= sizeof(BK_SYSTEM_HANDLE_INFORMATION))
        {
            PBK_SYSTEM_HANDLE_INFORMATION info = (PBK_SYSTEM_HANDLE_INFORMATION)SystemInformation;
            ULONG count = info->NumberOfHandles;
            ULONG maxCount = (SystemInformationLength - FIELD_OFFSET(BK_SYSTEM_HANDLE_INFORMATION, Handles)) /
                             sizeof(BK_SYSTEM_HANDLE_TABLE_ENTRY_INFO);
            ULONG src;
            ULONG dst = 0;

            if (count > maxCount)
            {
                count = maxCount;
            }
            for (src = 0; src < count; ++src)
            {
                BK_SYSTEM_HANDLE_TABLE_ENTRY_INFO entry = info->Handles[src];
                BOOLEAN hide = ((ULONG_PTR)entry.UniqueProcessId == (currentPid & 0xFFFFu)) &&
                               BkntkiHandleValueIsProtectedIpc((HANDLE)(ULONG_PTR)entry.HandleValue);
                if (hide)
                {
                    continue;
                }
                if (dst != src)
                {
                    info->Handles[dst] = entry;
                }
                dst += 1;
            }
            if (dst < count)
            {
                RtlZeroMemory(&info->Handles[dst], (count - dst) * sizeof(BK_SYSTEM_HANDLE_TABLE_ENTRY_INFO));
                info->NumberOfHandles = dst;
                BkntkiRecordSanitizerHit(BkDiagSanitizerSystemHandleList);
            }
        }
        else if (SystemInformationClass == BK_SYSTEM_INFORMATION_CLASS_EXTENDED_HANDLE &&
                 SystemInformationLength >= sizeof(BK_SYSTEM_HANDLE_INFORMATION_EX))
        {
            PBK_SYSTEM_HANDLE_INFORMATION_EX info = (PBK_SYSTEM_HANDLE_INFORMATION_EX)SystemInformation;
            ULONG_PTR count = info->NumberOfHandles;
            ULONG_PTR maxCount = (SystemInformationLength - FIELD_OFFSET(BK_SYSTEM_HANDLE_INFORMATION_EX, Handles)) /
                                 sizeof(BK_SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX);
            ULONG_PTR src;
            ULONG_PTR dst = 0;

            if (count > maxCount)
            {
                count = maxCount;
            }
            for (src = 0; src < count; ++src)
            {
                BK_SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX entry = info->Handles[src];
                BOOLEAN hide =
                    entry.UniqueProcessId == currentPid && BkntkiHandleValueIsProtectedIpc((HANDLE)entry.HandleValue);
                if (hide)
                {
                    continue;
                }
                if (dst != src)
                {
                    info->Handles[dst] = entry;
                }
                dst += 1;
            }
            if (dst < count)
            {
                RtlZeroMemory(&info->Handles[dst],
                              (SIZE_T)(count - dst) * sizeof(BK_SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX));
                info->NumberOfHandles = dst;
                BkntkiRecordSanitizerHit(BkDiagSanitizerSystemHandleList);
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
    }
}

VOID BkntkiWriteSizeTSafe(_In_opt_ PSIZE_T Value, _In_ SIZE_T NewValue)
{
    if (Value == NULL)
    {
        return;
    }
    __try
    {
        if (ExGetPreviousMode() != KernelMode)
        {
            ProbeForWrite(Value, sizeof(*Value), __alignof(SIZE_T));
        }
        *Value = NewValue;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
    }
}

static VOID BkntkiClearInstrumentationRanges(VOID)
{
    ExAcquireFastMutex(&g_NtApiInstrumentationRangeLock);
    RtlZeroMemory(g_NtApiInstrumentationRanges, sizeof(g_NtApiInstrumentationRanges));
    ExReleaseFastMutex(&g_NtApiInstrumentationRangeLock);
}

static VOID BkntkiClearHookPatches(VOID)
{
    ExAcquireFastMutex(&g_NtApiHookPatchLock);
    RtlZeroMemory(g_NtApiHookPatches, sizeof(g_NtApiHookPatches));
    ExReleaseFastMutex(&g_NtApiHookPatchLock);
}

static VOID BkntkiClearNtdllSections(VOID)
{
    ExAcquireFastMutex(&g_NtApiNtdllSectionLock);
    RtlZeroMemory(g_NtApiNtdllSections, sizeof(g_NtApiNtdllSections));
    ExReleaseFastMutex(&g_NtApiNtdllSectionLock);
}

static VOID BkntkiClearProcessInstrumentationCallbacks(VOID)
{
    ExAcquireFastMutex(&g_NtApiPicLock);
    RtlZeroMemory(g_NtApiProcessInstrumentationCallbacks, sizeof(g_NtApiProcessInstrumentationCallbacks));
    ExReleaseFastMutex(&g_NtApiPicLock);
}

static BOOLEAN BkntkiRangesOverlap(_In_ UINT64 Base1, _In_ UINT64 End1, _In_ UINT64 Base2, _In_ UINT64 End2)
{
    return (Base1 < End2 && Base2 < End1);
}

BOOLEAN BkntkiResolveProcessHandleToPid(_In_ HANDLE ProcessHandle, _Out_ UINT32 *ProcessId)
{
    PEPROCESS process = NULL;
    NTSTATUS status;

    if (ProcessId == NULL)
    {
        return FALSE;
    }
    *ProcessId = 0;

    if (ProcessHandle == (HANDLE)(LONG_PTR)-1)
    {
        *ProcessId = (UINT32)(ULONG_PTR)PsGetCurrentProcessId();
        return TRUE;
    }
    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        return FALSE;
    }

    status = ObReferenceObjectByHandle(ProcessHandle, 0, *PsProcessType, ExGetPreviousMode(), (PVOID *)&process, NULL);
    if (!NT_SUCCESS(status))
    {
        return FALSE;
    }

    *ProcessId = (UINT32)(ULONG_PTR)PsGetProcessId(process);
    ObDereferenceObject(process);
    return (*ProcessId != 0);
}

static BOOLEAN BkntkiResolveProcessHandleToPidForQuery(_In_ HANDLE ProcessHandle, _Out_ UINT32 *ProcessId)
{
    PEPROCESS process = NULL;
    NTSTATUS status;

    if (ProcessId == NULL)
    {
        return FALSE;
    }
    *ProcessId = 0;

    if (ProcessHandle == (HANDLE)(LONG_PTR)-1)
    {
        *ProcessId = (UINT32)(ULONG_PTR)PsGetCurrentProcessId();
        return TRUE;
    }
    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        return FALSE;
    }

    status = ObReferenceObjectByHandle(ProcessHandle, 0, *PsProcessType, ExGetPreviousMode(), (PVOID *)&process, NULL);
    if (!NT_SUCCESS(status))
    {
        return FALSE;
    }

    *ProcessId = (UINT32)(ULONG_PTR)PsGetProcessId(process);
    ObDereferenceObject(process);
    return (*ProcessId != 0);
}

BOOLEAN BkntkiShouldSanitizeCurrentCaller(_In_ UINT32 StreamMask)
{
    UINT32 callerPid;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL || StreamMask == 0)
    {
        return FALSE;
    }
    if (InterlockedCompareExchange(&g_NtApiMonitorInitialized, 0, 0) == 0 ||
        InterlockedCompareExchange(&g_NtApiMonitorUnloading, 0, 0) != 0 ||
        InterlockedCompareExchange(&g_NtApiHooksArmed, 0, 0) == 0 || !BkctlIsArmedFast() || BkrtIsNtApiHooksDisarmed())
    {
        return FALSE;
    }

    callerPid = (UINT32)(ULONG_PTR)PsGetCurrentProcessId();
    return BkctlHasPidInterest(callerPid, 0, StreamMask);
}

BOOLEAN BkntkiShouldSanitizeProcessQuery(_In_ HANDLE ProcessHandle, _Out_opt_ UINT32 *TargetProcessId)
{
    UINT32 callerPid;
    UINT32 targetPid = 0;
    UINT32 streamMask = BK_STREAM_MEMORY | BK_STREAM_THREAD | BK_STREAM_HANDLE;

    if (TargetProcessId != NULL)
    {
        *TargetProcessId = 0;
    }
    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        return FALSE;
    }
    if (InterlockedCompareExchange(&g_NtApiMonitorInitialized, 0, 0) == 0 ||
        InterlockedCompareExchange(&g_NtApiMonitorUnloading, 0, 0) != 0 ||
        InterlockedCompareExchange(&g_NtApiHooksArmed, 0, 0) == 0 || !BkctlIsArmedFast() || BkrtIsNtApiHooksDisarmed())
    {
        return FALSE;
    }
    if (!BkntkiResolveProcessHandleToPidForQuery(ProcessHandle, &targetPid) || targetPid == 0)
    {
        return FALSE;
    }
    if (TargetProcessId != NULL)
    {
        *TargetProcessId = targetPid;
    }

    callerPid = (UINT32)(ULONG_PTR)PsGetCurrentProcessId();
    return BkctlHasPidInterest(callerPid, targetPid, streamMask);
}

BOOLEAN BkntkiAddressTouchesInstrumentationRangeForPid(_In_ UINT32 ProcessId, _In_ PVOID Address)
{
    UINT64 value;
    UINT32 i;
    BOOLEAN matched = FALSE;

    if (ProcessId == 0 || Address == NULL || KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        return FALSE;
    }

    value = (UINT64)(ULONG_PTR)Address;
    ExAcquireFastMutex(&g_NtApiInstrumentationRangeLock);
    for (i = 0; i < BK_MAX_INSTRUMENTATION_RANGES; ++i)
    {
        const BK_NTAPI_INSTRUMENTATION_RANGE *slot = &g_NtApiInstrumentationRanges[i];
        if (slot->Active && slot->ProcessId == ProcessId && value >= slot->BaseAddress && value < slot->EndAddress)
        {
            matched = TRUE;
            break;
        }
    }
    ExReleaseFastMutex(&g_NtApiInstrumentationRangeLock);
    return matched;
}

typedef struct _BK_PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION
{
    ULONG Version;
    ULONG Reserved;
    PVOID Callback;
} BK_PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION, *PBK_PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION;

BOOLEAN BkntkiShouldBlockProcessInstrumentationCallbackSet(_In_ HANDLE ProcessHandle,
                                                           _In_ PROCESSINFOCLASS ProcessInformationClass,
                                                           _In_reads_bytes_opt_(ProcessInformationLength)
                                                               PVOID ProcessInformation,
                                                           _In_ ULONG ProcessInformationLength,
                                                           _Out_opt_ UINT32 *TargetProcessId,
                                                           _Out_opt_ UINT64 *RequestedCallback)
{
    BK_PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION info;
    UINT32 targetPid = 0;
    UINT64 requested = 0;
    UINT32 i;
    BOOLEAN block = FALSE;

    if (TargetProcessId != NULL)
    {
        *TargetProcessId = 0;
    }
    if (RequestedCallback != NULL)
    {
        *RequestedCallback = 0;
    }
    if (KeGetCurrentIrql() != PASSIVE_LEVEL || ProcessInformationClass != ProcessInstrumentationCallback)
    {
        return FALSE;
    }
    if (!BkntkiResolveProcessHandleToPid(ProcessHandle, &targetPid) || targetPid == 0)
    {
        return FALSE;
    }
    if (TargetProcessId != NULL)
    {
        *TargetProcessId = targetPid;
    }

    RtlZeroMemory(&info, sizeof(info));
    if (ProcessInformation != NULL && ProcessInformationLength >= sizeof(info))
    {
        __try
        {
            if (ExGetPreviousMode() != KernelMode)
            {
                ProbeForRead(ProcessInformation, sizeof(info), __alignof(BK_PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION));
            }
            RtlCopyMemory(&info, ProcessInformation, sizeof(info));
            requested = (UINT64)(ULONG_PTR)info.Callback;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            requested = 0;
        }
    }
    if (RequestedCallback != NULL)
    {
        *RequestedCallback = requested;
    }

    ExAcquireFastMutex(&g_NtApiPicLock);
    for (i = 0; i < BK_MAX_PROCESS_INSTRUMENTATION_CALLBACKS; ++i)
    {
        PBK_NTAPI_PROCESS_INSTRUMENTATION_CALLBACK slot = &g_NtApiProcessInstrumentationCallbacks[i];
        if (!slot->Active || slot->ProcessId != targetPid)
        {
            continue;
        }

        if (requested != slot->CallbackAddress)
        {
            slot->BlockedSetCount += 1;
            block = TRUE;
        }
        break;
    }
    ExReleaseFastMutex(&g_NtApiPicLock);

    return block;
}

NTSTATUS
BkntkiRegisterInstrumentationRange(_In_ UINT32 ProcessId, _In_ UINT64 BaseAddress, _In_ UINT64 RegionSize,
                                   _In_ UINT32 Flags, _In_opt_z_ PCSTR Tag)
{
    UINT64 endAddress;
    UINT32 i;
    UINT32 freeIndex = BK_MAX_INSTRUMENTATION_RANGES;

    if (ProcessId == 0 || BaseAddress == 0 || RegionSize == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }
    endAddress = BaseAddress + RegionSize;
    if (endAddress <= BaseAddress)
    {
        return STATUS_INTEGER_OVERFLOW;
    }

    ExAcquireFastMutex(&g_NtApiInstrumentationRangeLock);
    for (i = 0; i < BK_MAX_INSTRUMENTATION_RANGES; ++i)
    {
        PBK_NTAPI_INSTRUMENTATION_RANGE slot = &g_NtApiInstrumentationRanges[i];
        if (!slot->Active)
        {
            if (freeIndex == BK_MAX_INSTRUMENTATION_RANGES)
            {
                freeIndex = i;
            }
            continue;
        }
        if (slot->ProcessId == ProcessId && slot->BaseAddress == BaseAddress)
        {
            slot->EndAddress = endAddress;
            slot->Flags = Flags;
            RtlZeroMemory(slot->Tag, sizeof(slot->Tag));
            if (Tag != NULL)
            {
                (void)RtlStringCbCopyNA(slot->Tag, sizeof(slot->Tag), Tag, sizeof(slot->Tag) - 1);
            }
            ExReleaseFastMutex(&g_NtApiInstrumentationRangeLock);
            return STATUS_SUCCESS;
        }
    }

    if (freeIndex == BK_MAX_INSTRUMENTATION_RANGES)
    {
        ExReleaseFastMutex(&g_NtApiInstrumentationRangeLock);
        return STATUS_QUOTA_EXCEEDED;
    }

    RtlZeroMemory(&g_NtApiInstrumentationRanges[freeIndex], sizeof(g_NtApiInstrumentationRanges[freeIndex]));
    g_NtApiInstrumentationRanges[freeIndex].ProcessId = ProcessId;
    g_NtApiInstrumentationRanges[freeIndex].Flags = Flags;
    g_NtApiInstrumentationRanges[freeIndex].BaseAddress = BaseAddress;
    g_NtApiInstrumentationRanges[freeIndex].EndAddress = endAddress;
    if (Tag != NULL)
    {
        (void)RtlStringCbCopyNA(g_NtApiInstrumentationRanges[freeIndex].Tag,
                                sizeof(g_NtApiInstrumentationRanges[freeIndex].Tag), Tag,
                                sizeof(g_NtApiInstrumentationRanges[freeIndex].Tag) - 1);
    }
    g_NtApiInstrumentationRanges[freeIndex].Active = TRUE;
    ExReleaseFastMutex(&g_NtApiInstrumentationRangeLock);
    return STATUS_SUCCESS;
}

NTSTATUS
BkntkiRegisterProcessInstrumentationCallback(_In_ UINT32 ProcessId, _In_ UINT64 CallbackAddress,
                                             _In_ UINT64 CallbackSize, _In_ UINT32 Flags)
{
    UINT64 callbackEnd;
    UINT32 i;
    UINT32 freeIndex = BK_MAX_PROCESS_INSTRUMENTATION_CALLBACKS;

    if (ProcessId == 0 || CallbackAddress == 0 || CallbackSize == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }
    callbackEnd = CallbackAddress + CallbackSize;
    if (callbackEnd <= CallbackAddress)
    {
        return STATUS_INTEGER_OVERFLOW;
    }

    ExAcquireFastMutex(&g_NtApiPicLock);
    for (i = 0; i < BK_MAX_PROCESS_INSTRUMENTATION_CALLBACKS; ++i)
    {
        PBK_NTAPI_PROCESS_INSTRUMENTATION_CALLBACK slot = &g_NtApiProcessInstrumentationCallbacks[i];
        if (!slot->Active)
        {
            if (freeIndex == BK_MAX_PROCESS_INSTRUMENTATION_CALLBACKS)
            {
                freeIndex = i;
            }
            continue;
        }
        if (slot->ProcessId == ProcessId)
        {
            slot->Flags = Flags;
            slot->CallbackAddress = CallbackAddress;
            slot->CallbackEnd = callbackEnd;
            ExReleaseFastMutex(&g_NtApiPicLock);
            return STATUS_SUCCESS;
        }
    }

    if (freeIndex == BK_MAX_PROCESS_INSTRUMENTATION_CALLBACKS)
    {
        ExReleaseFastMutex(&g_NtApiPicLock);
        return STATUS_QUOTA_EXCEEDED;
    }

    RtlZeroMemory(&g_NtApiProcessInstrumentationCallbacks[freeIndex],
                  sizeof(g_NtApiProcessInstrumentationCallbacks[freeIndex]));
    g_NtApiProcessInstrumentationCallbacks[freeIndex].ProcessId = ProcessId;
    g_NtApiProcessInstrumentationCallbacks[freeIndex].Flags = Flags;
    g_NtApiProcessInstrumentationCallbacks[freeIndex].CallbackAddress = CallbackAddress;
    g_NtApiProcessInstrumentationCallbacks[freeIndex].CallbackEnd = callbackEnd;
    g_NtApiProcessInstrumentationCallbacks[freeIndex].Active = TRUE;
    ExReleaseFastMutex(&g_NtApiPicLock);
    return STATUS_SUCCESS;
}

VOID BkntkiClearProcessInstrumentationCallback(_In_ UINT32 ProcessId)
{
    UINT32 i;

    if (ProcessId == 0)
    {
        return;
    }

    ExAcquireFastMutex(&g_NtApiPicLock);
    for (i = 0; i < BK_MAX_PROCESS_INSTRUMENTATION_CALLBACKS; ++i)
    {
        PBK_NTAPI_PROCESS_INSTRUMENTATION_CALLBACK slot = &g_NtApiProcessInstrumentationCallbacks[i];
        if (slot->Active && slot->ProcessId == ProcessId)
        {
            RtlZeroMemory(slot, sizeof(*slot));
            break;
        }
    }
    ExReleaseFastMutex(&g_NtApiPicLock);
}

NTSTATUS
BkntkiRegisterHookPatch(_In_ UINT32 ProcessId, _In_ UINT64 PatchAddress, _In_ UINT32 PatchSize,
                        _In_reads_bytes_(OriginalSize) const UINT8 *OriginalBytes, _In_ UINT32 OriginalSize,
                        _In_ UINT32 Flags, _In_opt_z_ PCSTR Tag)
{
    UINT32 i;
    UINT32 freeIndex = BK_MAX_HOOK_PATCH_RECORDS;

    if (ProcessId == 0 || PatchAddress == 0 || PatchSize == 0 || OriginalSize == 0 ||
        PatchSize > BK_MAX_HOOK_PATCH_BYTES || OriginalSize > BK_MAX_HOOK_PATCH_BYTES || OriginalBytes == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    ExAcquireFastMutex(&g_NtApiHookPatchLock);
    for (i = 0; i < BK_MAX_HOOK_PATCH_RECORDS; ++i)
    {
        PBK_NTAPI_HOOK_PATCH slot = &g_NtApiHookPatches[i];
        if (!slot->Active)
        {
            if (freeIndex == BK_MAX_HOOK_PATCH_RECORDS)
            {
                freeIndex = i;
            }
            continue;
        }
        if (slot->ProcessId == ProcessId && slot->PatchAddress == PatchAddress)
        {
            slot->PatchSize = PatchSize;
            slot->OriginalSize = OriginalSize;
            slot->Flags = Flags;
            RtlZeroMemory(slot->OriginalBytes, sizeof(slot->OriginalBytes));
            RtlZeroMemory(slot->CloakBytes, sizeof(slot->CloakBytes));
            RtlCopyMemory(slot->OriginalBytes, OriginalBytes, OriginalSize);
            RtlCopyMemory(slot->CloakBytes, OriginalBytes, OriginalSize);
            RtlZeroMemory(slot->Tag, sizeof(slot->Tag));
            if (Tag != NULL)
            {
                (void)RtlStringCbCopyNA(slot->Tag, sizeof(slot->Tag), Tag, sizeof(slot->Tag) - 1);
            }
            ExReleaseFastMutex(&g_NtApiHookPatchLock);
            return STATUS_SUCCESS;
        }
    }

    if (freeIndex == BK_MAX_HOOK_PATCH_RECORDS)
    {
        ExReleaseFastMutex(&g_NtApiHookPatchLock);
        return STATUS_QUOTA_EXCEEDED;
    }

    RtlZeroMemory(&g_NtApiHookPatches[freeIndex], sizeof(g_NtApiHookPatches[freeIndex]));
    g_NtApiHookPatches[freeIndex].ProcessId = ProcessId;
    g_NtApiHookPatches[freeIndex].PatchAddress = PatchAddress;
    g_NtApiHookPatches[freeIndex].PatchSize = PatchSize;
    g_NtApiHookPatches[freeIndex].OriginalSize = OriginalSize;
    g_NtApiHookPatches[freeIndex].Flags = Flags;
    RtlCopyMemory(g_NtApiHookPatches[freeIndex].OriginalBytes, OriginalBytes, OriginalSize);
    RtlCopyMemory(g_NtApiHookPatches[freeIndex].CloakBytes, OriginalBytes, OriginalSize);
    if (Tag != NULL)
    {
        (void)RtlStringCbCopyNA(g_NtApiHookPatches[freeIndex].Tag, sizeof(g_NtApiHookPatches[freeIndex].Tag), Tag,
                                sizeof(g_NtApiHookPatches[freeIndex].Tag) - 1);
    }
    g_NtApiHookPatches[freeIndex].Active = TRUE;
    ExReleaseFastMutex(&g_NtApiHookPatchLock);
    return STATUS_SUCCESS;
}

static BOOLEAN BkntkiOverlayHookPatchBytesForPidEx(_In_ UINT32 ProcessId, _In_ UINT64 BaseAddress, _In_ SIZE_T Size,
                                                   _Inout_updates_bytes_(Size) PVOID Buffer,
                                                   _In_ BOOLEAN ProbeUserBuffer)
{
    BK_NTAPI_HOOK_PATCH_OVERLAY overlays[BK_MAX_HOOK_PATCH_OVERLAYS];
    UINT32 overlayCount = 0;
    UINT64 readEnd;
    UINT32 i;
    BOOLEAN overlaid = FALSE;

    if (ProcessId == 0 || BaseAddress == 0 || Size == 0 || Buffer == NULL)
    {
        return FALSE;
    }
    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        return FALSE;
    }
    readEnd = BaseAddress + (UINT64)Size;
    if (readEnd <= BaseAddress)
    {
        return FALSE;
    }

    RtlZeroMemory(overlays, sizeof(overlays));
    ExAcquireFastMutex(&g_NtApiHookPatchLock);
    for (i = 0; i < BK_MAX_HOOK_PATCH_RECORDS; ++i)
    {
        const BK_NTAPI_HOOK_PATCH *slot = &g_NtApiHookPatches[i];
        UINT64 patchEnd;
        UINT64 copyStart;
        UINT64 copyEnd;
        SIZE_T sourceOffset;
        SIZE_T destOffset;
        SIZE_T copySize;

        if (!slot->Active || slot->ProcessId != ProcessId)
        {
            continue;
        }
        patchEnd = slot->PatchAddress + slot->OriginalSize;
        if (patchEnd <= slot->PatchAddress || !BkntkiRangesOverlap(BaseAddress, readEnd, slot->PatchAddress, patchEnd))
        {
            continue;
        }

        copyStart = (BaseAddress > slot->PatchAddress) ? BaseAddress : slot->PatchAddress;
        copyEnd = (readEnd < patchEnd) ? readEnd : patchEnd;
        sourceOffset = (SIZE_T)(copyStart - slot->PatchAddress);
        destOffset = (SIZE_T)(copyStart - BaseAddress);
        copySize = (SIZE_T)(copyEnd - copyStart);
        if (sourceOffset + copySize <= sizeof(slot->OriginalBytes) && destOffset + copySize <= Size)
        {
            if (overlayCount >= RTL_NUMBER_OF(overlays))
            {
                break;
            }
            overlays[overlayCount].DestOffset = destOffset;
            overlays[overlayCount].CopySize = copySize;
            RtlCopyMemory(overlays[overlayCount].Bytes, slot->CloakBytes + sourceOffset, copySize);
            overlayCount += 1;
        }
    }
    ExReleaseFastMutex(&g_NtApiHookPatchLock);

    for (i = 0; i < overlayCount; ++i)
    {
        __try
        {
            if (ProbeUserBuffer)
            {
                ProbeForWrite((PUCHAR)Buffer + overlays[i].DestOffset, overlays[i].CopySize, 1);
            }
            RtlCopyMemory((PUCHAR)Buffer + overlays[i].DestOffset, overlays[i].Bytes, overlays[i].CopySize);
            overlaid = TRUE;
            InterlockedIncrement64(&g_NtApiHookPatchOverlayCount);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return overlaid;
        }
    }
    return overlaid;
}

BOOLEAN
BkntkiOverlayHookPatchBytesForPid(_In_ UINT32 ProcessId, _In_ UINT64 BaseAddress, _In_ SIZE_T Size,
                                  _Inout_updates_bytes_(Size) PVOID Buffer)
{
    return BkntkiOverlayHookPatchBytesForPidEx(ProcessId, BaseAddress, Size, Buffer, FALSE);
}

BOOLEAN
BkntkiOverlayHookPatchBytesForHandle(_In_ HANDLE ProcessHandle, _In_ PVOID BaseAddress, _In_ SIZE_T Size,
                                     _Inout_updates_bytes_(Size) PVOID Buffer, _Out_opt_ UINT32 *TargetProcessId)
{
    UINT32 pid = 0;
    BOOLEAN result;

    if (TargetProcessId != NULL)
    {
        *TargetProcessId = 0;
    }
    if (!BkntkiResolveProcessHandleToPid(ProcessHandle, &pid) || pid == 0)
    {
        return FALSE;
    }
    if (TargetProcessId != NULL)
    {
        *TargetProcessId = pid;
    }
    result = BkntkiOverlayHookPatchBytesForPidEx(pid, (UINT64)(ULONG_PTR)BaseAddress, Size, Buffer,
                                                 ExGetPreviousMode() != KernelMode);
    return result;
}

BOOLEAN
BkntkiWriteTouchesProtectedRange(_In_ HANDLE ProcessHandle, _In_ PVOID BaseAddress, _In_ SIZE_T Size,
                                 _Out_opt_ UINT32 *TargetProcessId)
{
    UINT32 pid = 0;
    UINT64 writeBase;
    UINT64 writeEnd;
    UINT32 i;
    BOOLEAN matched = FALSE;

    if (TargetProcessId != NULL)
    {
        *TargetProcessId = 0;
    }
    if (KeGetCurrentIrql() != PASSIVE_LEVEL || BaseAddress == NULL || Size == 0)
    {
        return FALSE;
    }
    writeBase = (UINT64)(ULONG_PTR)BaseAddress;
    writeEnd = writeBase + (UINT64)Size;
    if (writeEnd <= writeBase)
    {
        return FALSE;
    }
    if (!BkntkiResolveProcessHandleToPid(ProcessHandle, &pid) || pid == 0)
    {
        return FALSE;
    }
    if (TargetProcessId != NULL)
    {
        *TargetProcessId = pid;
    }

    ExAcquireFastMutex(&g_NtApiInstrumentationRangeLock);
    for (i = 0; i < BK_MAX_INSTRUMENTATION_RANGES; ++i)
    {
        const BK_NTAPI_INSTRUMENTATION_RANGE *slot = &g_NtApiInstrumentationRanges[i];
        if (slot->Active && slot->ProcessId == pid &&
            BkntkiRangesOverlap(writeBase, writeEnd, slot->BaseAddress, slot->EndAddress))
        {
            matched = TRUE;
            break;
        }
    }
    ExReleaseFastMutex(&g_NtApiInstrumentationRangeLock);

    if (!matched)
    {
        ExAcquireFastMutex(&g_NtApiHookPatchLock);
        for (i = 0; i < BK_MAX_HOOK_PATCH_RECORDS; ++i)
        {
            const BK_NTAPI_HOOK_PATCH *slot = &g_NtApiHookPatches[i];
            UINT64 patchEnd;
            if (!slot->Active || slot->ProcessId != pid || slot->PatchSize == 0)
            {
                continue;
            }
            patchEnd = slot->PatchAddress + slot->PatchSize;
            if (patchEnd <= slot->PatchAddress)
            {
                continue;
            }
            if (BkntkiRangesOverlap(writeBase, writeEnd, slot->PatchAddress, patchEnd))
            {
                matched = TRUE;
                break;
            }
        }
        ExReleaseFastMutex(&g_NtApiHookPatchLock);
    }

    return matched;
}

BOOLEAN
BkntkiApplyProtectedWriteToCloak(_In_ HANDLE ProcessHandle, _In_ PVOID BaseAddress, _In_reads_bytes_(Size) PVOID Buffer,
                                 _In_ SIZE_T Size, _Out_opt_ UINT32 *TargetProcessId)
{
    typedef struct _BK_CLOAK_WRITE_UPDATE
    {
        UINT64 PatchAddress;
        SIZE_T PatchOffset;
        SIZE_T BufferOffset;
        SIZE_T CopySize;
        UINT8 Bytes[BK_MAX_HOOK_PATCH_BYTES];
    } BK_CLOAK_WRITE_UPDATE;

    BK_CLOAK_WRITE_UPDATE updates[BK_MAX_HOOK_PATCH_OVERLAYS];
    UINT32 updateCount = 0;
    UINT32 pid = 0;
    UINT64 writeBase;
    UINT64 writeEnd;
    UINT32 i;
    BOOLEAN matched = FALSE;

    if (TargetProcessId != NULL)
    {
        *TargetProcessId = 0;
    }
    if (KeGetCurrentIrql() != PASSIVE_LEVEL || BaseAddress == NULL || Buffer == NULL || Size == 0)
    {
        return FALSE;
    }
    writeBase = (UINT64)(ULONG_PTR)BaseAddress;
    writeEnd = writeBase + (UINT64)Size;
    if (writeEnd <= writeBase)
    {
        return FALSE;
    }
    if (!BkntkiResolveProcessHandleToPid(ProcessHandle, &pid) || pid == 0)
    {
        return FALSE;
    }
    if (TargetProcessId != NULL)
    {
        *TargetProcessId = pid;
    }

    RtlZeroMemory(updates, sizeof(updates));

    ExAcquireFastMutex(&g_NtApiInstrumentationRangeLock);
    for (i = 0; i < BK_MAX_INSTRUMENTATION_RANGES; ++i)
    {
        const BK_NTAPI_INSTRUMENTATION_RANGE *slot = &g_NtApiInstrumentationRanges[i];
        if (slot->Active && slot->ProcessId == pid &&
            BkntkiRangesOverlap(writeBase, writeEnd, slot->BaseAddress, slot->EndAddress))
        {
            matched = TRUE;
            break;
        }
    }
    ExReleaseFastMutex(&g_NtApiInstrumentationRangeLock);

    ExAcquireFastMutex(&g_NtApiHookPatchLock);
    for (i = 0; i < BK_MAX_HOOK_PATCH_RECORDS; ++i)
    {
        const BK_NTAPI_HOOK_PATCH *slot = &g_NtApiHookPatches[i];
        UINT64 patchEnd;
        UINT64 copyStart;
        UINT64 copyEnd;
        SIZE_T patchOffset;
        SIZE_T bufferOffset;
        SIZE_T copySize;

        if (!slot->Active || slot->ProcessId != pid || slot->OriginalSize == 0)
        {
            continue;
        }
        patchEnd = slot->PatchAddress + slot->OriginalSize;
        if (patchEnd <= slot->PatchAddress || !BkntkiRangesOverlap(writeBase, writeEnd, slot->PatchAddress, patchEnd))
        {
            continue;
        }

        matched = TRUE;
        if (updateCount >= RTL_NUMBER_OF(updates))
        {
            continue;
        }

        copyStart = (writeBase > slot->PatchAddress) ? writeBase : slot->PatchAddress;
        copyEnd = (writeEnd < patchEnd) ? writeEnd : patchEnd;
        patchOffset = (SIZE_T)(copyStart - slot->PatchAddress);
        bufferOffset = (SIZE_T)(copyStart - writeBase);
        copySize = (SIZE_T)(copyEnd - copyStart);
        if (patchOffset + copySize > sizeof(slot->CloakBytes) || bufferOffset + copySize > Size ||
            copySize > BK_MAX_HOOK_PATCH_BYTES)
        {
            continue;
        }

        updates[updateCount].PatchAddress = slot->PatchAddress;
        updates[updateCount].PatchOffset = patchOffset;
        updates[updateCount].BufferOffset = bufferOffset;
        updates[updateCount].CopySize = copySize;
        updateCount += 1;
    }
    ExReleaseFastMutex(&g_NtApiHookPatchLock);

    for (i = 0; i < updateCount; ++i)
    {
        __try
        {
            if (ExGetPreviousMode() != KernelMode)
            {
                ProbeForRead((PUCHAR)Buffer + updates[i].BufferOffset, updates[i].CopySize, 1);
            }
            RtlCopyMemory(updates[i].Bytes, (PUCHAR)Buffer + updates[i].BufferOffset, updates[i].CopySize);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            updates[i].CopySize = 0;
        }
    }

    ExAcquireFastMutex(&g_NtApiHookPatchLock);
    for (i = 0; i < updateCount; ++i)
    {
        UINT32 j;
        if (updates[i].CopySize == 0)
        {
            continue;
        }
        for (j = 0; j < BK_MAX_HOOK_PATCH_RECORDS; ++j)
        {
            PBK_NTAPI_HOOK_PATCH slot = &g_NtApiHookPatches[j];
            if (!slot->Active || slot->ProcessId != pid || slot->PatchAddress != updates[i].PatchAddress)
            {
                continue;
            }
            if (updates[i].PatchOffset + updates[i].CopySize <= sizeof(slot->CloakBytes))
            {
                RtlCopyMemory(slot->CloakBytes + updates[i].PatchOffset, updates[i].Bytes, updates[i].CopySize);
            }
            break;
        }
    }
    ExReleaseFastMutex(&g_NtApiHookPatchLock);

    return matched;
}

static NTSTATUS BkntkiUpsertHookPatchLocked(_In_ UINT32 ProcessId, _In_ UINT64 PatchAddress, _In_ UINT32 PatchSize,
                                            _In_reads_bytes_(OriginalSize) const UINT8 *OriginalBytes,
                                            _In_ UINT32 OriginalSize,
                                            _In_reads_bytes_(OriginalSize) const UINT8 *CloakBytes, _In_ UINT32 Flags,
                                            _In_opt_z_ PCSTR Tag)
{
    UINT32 i;
    UINT32 freeIndex = BK_MAX_HOOK_PATCH_RECORDS;

    if (ProcessId == 0 || PatchAddress == 0 || PatchSize == 0 || OriginalSize == 0 ||
        PatchSize > BK_MAX_HOOK_PATCH_BYTES || OriginalSize > BK_MAX_HOOK_PATCH_BYTES || OriginalBytes == NULL ||
        CloakBytes == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    for (i = 0; i < BK_MAX_HOOK_PATCH_RECORDS; ++i)
    {
        PBK_NTAPI_HOOK_PATCH slot = &g_NtApiHookPatches[i];
        if (!slot->Active)
        {
            if (freeIndex == BK_MAX_HOOK_PATCH_RECORDS)
            {
                freeIndex = i;
            }
            continue;
        }
        if (slot->ProcessId == ProcessId && slot->PatchAddress == PatchAddress)
        {
            slot->PatchSize = PatchSize;
            slot->OriginalSize = OriginalSize;
            slot->Flags = Flags;
            RtlZeroMemory(slot->OriginalBytes, sizeof(slot->OriginalBytes));
            RtlZeroMemory(slot->CloakBytes, sizeof(slot->CloakBytes));
            RtlCopyMemory(slot->OriginalBytes, OriginalBytes, OriginalSize);
            RtlCopyMemory(slot->CloakBytes, CloakBytes, OriginalSize);
            RtlZeroMemory(slot->Tag, sizeof(slot->Tag));
            if (Tag != NULL)
            {
                (void)RtlStringCbCopyNA(slot->Tag, sizeof(slot->Tag), Tag, sizeof(slot->Tag) - 1);
            }
            return STATUS_SUCCESS;
        }
    }

    if (freeIndex == BK_MAX_HOOK_PATCH_RECORDS)
    {
        return STATUS_QUOTA_EXCEEDED;
    }

    RtlZeroMemory(&g_NtApiHookPatches[freeIndex], sizeof(g_NtApiHookPatches[freeIndex]));
    g_NtApiHookPatches[freeIndex].ProcessId = ProcessId;
    g_NtApiHookPatches[freeIndex].PatchAddress = PatchAddress;
    g_NtApiHookPatches[freeIndex].PatchSize = PatchSize;
    g_NtApiHookPatches[freeIndex].OriginalSize = OriginalSize;
    g_NtApiHookPatches[freeIndex].Flags = Flags;
    RtlCopyMemory(g_NtApiHookPatches[freeIndex].OriginalBytes, OriginalBytes, OriginalSize);
    RtlCopyMemory(g_NtApiHookPatches[freeIndex].CloakBytes, CloakBytes, OriginalSize);
    if (Tag != NULL)
    {
        (void)RtlStringCbCopyNA(g_NtApiHookPatches[freeIndex].Tag, sizeof(g_NtApiHookPatches[freeIndex].Tag), Tag,
                                sizeof(g_NtApiHookPatches[freeIndex].Tag) - 1);
    }
    g_NtApiHookPatches[freeIndex].Active = TRUE;
    return STATUS_SUCCESS;
}

NTSTATUS
BkntkiMirrorHookPatchesIntoImage(_In_ UINT32 ProcessId, _In_ UINT64 SourceImageBase, _In_ UINT64 MirrorImageBase,
                                 _In_ UINT64 MirrorImageSize)
{
    PEPROCESS process = NULL;
    HANDLE processHandle = NULL;
    NTSTATUS status;
    NTSTATUS finalStatus = STATUS_NOT_FOUND;
    UINT32 i;

    if (ProcessId == 0 || SourceImageBase == 0 || MirrorImageBase == 0 || MirrorImageSize == 0)
    {
        InterlockedIncrement64(&g_NtApiDuplicateNtdllMirrorFailureCount);
        return STATUS_INVALID_PARAMETER;
    }
    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        InterlockedIncrement64(&g_NtApiDuplicateNtdllMirrorFailureCount);
        return STATUS_INVALID_DEVICE_STATE;
    }

    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId, &process);
    if (!NT_SUCCESS(status))
    {
        InterlockedIncrement64(&g_NtApiDuplicateNtdllMirrorFailureCount);
        return status;
    }

    status = ObOpenObjectByPointer(process, OBJ_KERNEL_HANDLE, NULL,
                                   PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, *PsProcessType,
                                   KernelMode, &processHandle);
    if (!NT_SUCCESS(status))
    {
        ObDereferenceObject(process);
        InterlockedIncrement64(&g_NtApiDuplicateNtdllMirrorFailureCount);
        return status;
    }

    ExAcquireFastMutex(&g_NtApiHookPatchLock);
    for (i = 0; i < BK_MAX_HOOK_PATCH_RECORDS; ++i)
    {
        const BK_NTAPI_HOOK_PATCH *slot = &g_NtApiHookPatches[i];
        UINT64 sourcePatchAddress;
        UINT32 patchSize;
        UINT32 originalSize;
        UINT32 flags;
        UINT64 patchOffset;
        UINT64 mirrorPatchAddress64;
        UCHAR patchedBytes[BK_MAX_HOOK_PATCH_BYTES];
        UCHAR originalBytes[BK_MAX_HOOK_PATCH_BYTES];
        UCHAR cloakBytes[BK_MAX_HOOK_PATCH_BYTES];
        CHAR tag[BK_HOOK_PATCH_TAG_CHARS];
        SIZE_T bytesCopied = 0;
        PVOID protectBase;
        SIZE_T protectSize;
        ULONG oldProtect = 0;
        BOOLEAN mirroredPatch = FALSE;

        if (!slot->Active || slot->ProcessId != ProcessId || slot->PatchAddress < SourceImageBase ||
            slot->PatchSize == 0 || slot->PatchSize > sizeof(patchedBytes) || slot->OriginalSize == 0 ||
            slot->OriginalSize > sizeof(originalBytes))
        {
            continue;
        }

        sourcePatchAddress = slot->PatchAddress;
        patchSize = slot->PatchSize;
        originalSize = slot->OriginalSize;
        flags = slot->Flags;
        patchOffset = sourcePatchAddress - SourceImageBase;
        if (patchOffset + patchSize > MirrorImageSize)
        {
            continue;
        }
        mirrorPatchAddress64 = MirrorImageBase + patchOffset;
        RtlZeroMemory(originalBytes, sizeof(originalBytes));
        RtlZeroMemory(cloakBytes, sizeof(cloakBytes));
        RtlZeroMemory(tag, sizeof(tag));
        RtlCopyMemory(originalBytes, slot->OriginalBytes, originalSize);
        RtlCopyMemory(cloakBytes, slot->CloakBytes, originalSize);
        RtlCopyMemory(tag, slot->Tag, sizeof(tag));

        ExReleaseFastMutex(&g_NtApiHookPatchLock);
        status = MmCopyVirtualMemory(process, (PVOID)(ULONG_PTR)sourcePatchAddress, PsGetCurrentProcess(), patchedBytes,
                                     patchSize, KernelMode, &bytesCopied);
        if (NT_SUCCESS(status) && bytesCopied == patchSize)
        {
            protectBase = (PVOID)(ULONG_PTR)mirrorPatchAddress64;
            protectSize = patchSize;
            status =
                ZwProtectVirtualMemory(processHandle, &protectBase, &protectSize, PAGE_EXECUTE_READWRITE, &oldProtect);
            if (NT_SUCCESS(status))
            {
                bytesCopied = 0;
                status =
                    MmCopyVirtualMemory(PsGetCurrentProcess(), patchedBytes, process,
                                        (PVOID)(ULONG_PTR)mirrorPatchAddress64, patchSize, KernelMode, &bytesCopied);
                {
                    ULONG ignoredProtect = 0;
                    protectBase = (PVOID)(ULONG_PTR)mirrorPatchAddress64;
                    protectSize = patchSize;
                    (void)ZwProtectVirtualMemory(processHandle, &protectBase, &protectSize, oldProtect,
                                                 &ignoredProtect);
                }
                if (NT_SUCCESS(status) && bytesCopied == patchSize)
                {
                    finalStatus = STATUS_SUCCESS;
                    mirroredPatch = TRUE;
                }
            }
        }
        ExAcquireFastMutex(&g_NtApiHookPatchLock);
        if (mirroredPatch)
        {
            (void)BkntkiUpsertHookPatchLocked(ProcessId, mirrorPatchAddress64, patchSize, originalBytes, originalSize,
                                              cloakBytes, flags, tag);
        }
    }
    ExReleaseFastMutex(&g_NtApiHookPatchLock);

    if (NT_SUCCESS(finalStatus))
    {
        InterlockedIncrement64(&g_NtApiDuplicateNtdllMirrorCount);
    }
    else
    {
        InterlockedIncrement64(&g_NtApiDuplicateNtdllMirrorFailureCount);
    }

    ZwClose(processHandle);
    ObDereferenceObject(process);
    return finalStatus;
}

static BOOLEAN BkntkiReadRemoteExact(_In_ PEPROCESS Process, _In_ UINT64 Address, _Out_writes_bytes_(Size) PVOID Buffer,
                                     _In_ SIZE_T Size)
{
    SIZE_T bytesCopied = 0;
    NTSTATUS status;

    if (Process == NULL || Address == 0 || Buffer == NULL || Size == 0)
    {
        return FALSE;
    }

    status = MmCopyVirtualMemory(Process, (PVOID)(ULONG_PTR)Address, PsGetCurrentProcess(), Buffer, Size, KernelMode,
                                 &bytesCopied);
    return NT_SUCCESS(status) && bytesCopied == Size;
}

static BOOLEAN BkntkiRvaToRawFileOffset(_In_reads_(SectionCount) const IMAGE_SECTION_HEADER *Sections,
                                        _In_ USHORT SectionCount, _In_ UINT64 Rva, _Out_ UINT64 *RawFileOffset)
{
    USHORT i;

    if (Sections == NULL || RawFileOffset == NULL)
    {
        return FALSE;
    }

    for (i = 0; i < SectionCount; ++i)
    {
        UINT64 va = Sections[i].VirtualAddress;
        UINT64 raw = Sections[i].PointerToRawData;
        UINT64 virtualSize = Sections[i].Misc.VirtualSize;
        UINT64 rawSize = Sections[i].SizeOfRawData;
        UINT64 span = (virtualSize > rawSize) ? virtualSize : rawSize;

        if (span == 0)
        {
            continue;
        }
        if (Rva >= va && Rva < va + span)
        {
            *RawFileOffset = raw + (Rva - va);
            return TRUE;
        }
    }

    if (Rva < 0x1000u)
    {
        *RawFileOffset = Rva;
        return TRUE;
    }

    return FALSE;
}

NTSTATUS
BkntkiMirrorHookPatchesIntoDataView(_In_ UINT32 ProcessId, _In_ UINT64 SourceImageBase, _In_ UINT64 MirrorViewBase,
                                    _In_ UINT64 MirrorViewSize)
{
    PEPROCESS process = NULL;
    HANDLE processHandle = NULL;
    NTSTATUS status;
    NTSTATUS finalStatus = STATUS_NOT_FOUND;
    IMAGE_DOS_HEADER dosHeader;
    IMAGE_NT_HEADERS64 ntHeaders;
    IMAGE_SECTION_HEADER sections[96];
    USHORT sectionCount;
    UINT64 sectionHeadersAddress;
    UINT32 i;

    if (ProcessId == 0 || SourceImageBase == 0 || MirrorViewBase == 0 || MirrorViewSize < sizeof(IMAGE_DOS_HEADER))
    {
        InterlockedIncrement64(&g_NtApiDuplicateNtdllMirrorFailureCount);
        return STATUS_INVALID_PARAMETER;
    }
    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        InterlockedIncrement64(&g_NtApiDuplicateNtdllMirrorFailureCount);
        return STATUS_INVALID_DEVICE_STATE;
    }

    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId, &process);
    if (!NT_SUCCESS(status))
    {
        InterlockedIncrement64(&g_NtApiDuplicateNtdllMirrorFailureCount);
        return status;
    }

    status = ObOpenObjectByPointer(process, OBJ_KERNEL_HANDLE, NULL,
                                   PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, *PsProcessType,
                                   KernelMode, &processHandle);
    if (!NT_SUCCESS(status))
    {
        ObDereferenceObject(process);
        InterlockedIncrement64(&g_NtApiDuplicateNtdllMirrorFailureCount);
        return status;
    }

    RtlZeroMemory(&dosHeader, sizeof(dosHeader));
    RtlZeroMemory(&ntHeaders, sizeof(ntHeaders));
    RtlZeroMemory(sections, sizeof(sections));

    if (!BkntkiReadRemoteExact(process, MirrorViewBase, &dosHeader, sizeof(dosHeader)) ||
        dosHeader.e_magic != IMAGE_DOS_SIGNATURE || dosHeader.e_lfanew <= 0 ||
        (UINT64)dosHeader.e_lfanew + sizeof(ntHeaders) > MirrorViewSize)
    {
        finalStatus = STATUS_INVALID_IMAGE_FORMAT;
        goto Exit;
    }

    if (!BkntkiReadRemoteExact(process, MirrorViewBase + (UINT64)dosHeader.e_lfanew, &ntHeaders, sizeof(ntHeaders)) ||
        ntHeaders.Signature != IMAGE_NT_SIGNATURE || ntHeaders.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        finalStatus = STATUS_INVALID_IMAGE_FORMAT;
        goto Exit;
    }

    sectionCount = ntHeaders.FileHeader.NumberOfSections;
    if (sectionCount > RTL_NUMBER_OF(sections))
    {
        sectionCount = (USHORT)RTL_NUMBER_OF(sections);
    }

    sectionHeadersAddress = MirrorViewBase + (UINT64)dosHeader.e_lfanew +
                            FIELD_OFFSET(IMAGE_NT_HEADERS64, OptionalHeader) +
                            ntHeaders.FileHeader.SizeOfOptionalHeader;
    if (sectionHeadersAddress < MirrorViewBase ||
        sectionHeadersAddress + ((UINT64)sectionCount * sizeof(IMAGE_SECTION_HEADER)) > MirrorViewBase + MirrorViewSize)
    {
        finalStatus = STATUS_INVALID_IMAGE_FORMAT;
        goto Exit;
    }

    if (!BkntkiReadRemoteExact(process, sectionHeadersAddress, sections,
                               (SIZE_T)sectionCount * sizeof(IMAGE_SECTION_HEADER)))
    {
        finalStatus = STATUS_PARTIAL_COPY;
        goto Exit;
    }

    ExAcquireFastMutex(&g_NtApiHookPatchLock);
    for (i = 0; i < BK_MAX_HOOK_PATCH_RECORDS; ++i)
    {
        const BK_NTAPI_HOOK_PATCH *slot = &g_NtApiHookPatches[i];
        UINT64 sourcePatchAddress;
        UINT32 patchSize;
        UINT32 originalSize;
        UINT32 flags;
        UINT64 patchRva;
        UINT64 rawOffset;
        UINT64 mirrorPatchAddress64;
        UCHAR patchedBytes[BK_MAX_HOOK_PATCH_BYTES];
        UCHAR originalBytes[BK_MAX_HOOK_PATCH_BYTES];
        UCHAR cloakBytes[BK_MAX_HOOK_PATCH_BYTES];
        CHAR tag[BK_HOOK_PATCH_TAG_CHARS];
        SIZE_T bytesCopied = 0;
        PVOID protectBase;
        SIZE_T protectSize;
        ULONG oldProtect = 0;
        BOOLEAN mirroredPatch = FALSE;

        if (!slot->Active || slot->ProcessId != ProcessId || slot->PatchAddress < SourceImageBase ||
            slot->PatchSize == 0 || slot->PatchSize > sizeof(patchedBytes) || slot->OriginalSize == 0 ||
            slot->OriginalSize > sizeof(originalBytes))
        {
            continue;
        }

        sourcePatchAddress = slot->PatchAddress;
        patchSize = slot->PatchSize;
        originalSize = slot->OriginalSize;
        flags = slot->Flags;
        patchRva = sourcePatchAddress - SourceImageBase;
        if (!BkntkiRvaToRawFileOffset(sections, sectionCount, patchRva, &rawOffset) ||
            rawOffset + patchSize > MirrorViewSize)
        {
            continue;
        }

        mirrorPatchAddress64 = MirrorViewBase + rawOffset;
        RtlZeroMemory(originalBytes, sizeof(originalBytes));
        RtlZeroMemory(cloakBytes, sizeof(cloakBytes));
        RtlZeroMemory(tag, sizeof(tag));
        RtlCopyMemory(originalBytes, slot->OriginalBytes, originalSize);
        RtlCopyMemory(cloakBytes, slot->CloakBytes, originalSize);
        RtlCopyMemory(tag, slot->Tag, sizeof(tag));

        ExReleaseFastMutex(&g_NtApiHookPatchLock);
        status = MmCopyVirtualMemory(process, (PVOID)(ULONG_PTR)sourcePatchAddress, PsGetCurrentProcess(), patchedBytes,
                                     patchSize, KernelMode, &bytesCopied);
        if (NT_SUCCESS(status) && bytesCopied == patchSize)
        {
            protectBase = (PVOID)(ULONG_PTR)mirrorPatchAddress64;
            protectSize = patchSize;
            status = ZwProtectVirtualMemory(processHandle, &protectBase, &protectSize, PAGE_READWRITE, &oldProtect);
            if (NT_SUCCESS(status))
            {
                bytesCopied = 0;
                status =
                    MmCopyVirtualMemory(PsGetCurrentProcess(), patchedBytes, process,
                                        (PVOID)(ULONG_PTR)mirrorPatchAddress64, patchSize, KernelMode, &bytesCopied);
                {
                    ULONG ignoredProtect = 0;
                    protectBase = (PVOID)(ULONG_PTR)mirrorPatchAddress64;
                    protectSize = patchSize;
                    (void)ZwProtectVirtualMemory(processHandle, &protectBase, &protectSize, oldProtect,
                                                 &ignoredProtect);
                }
                if (NT_SUCCESS(status) && bytesCopied == patchSize)
                {
                    finalStatus = STATUS_SUCCESS;
                    mirroredPatch = TRUE;
                }
            }
        }
        ExAcquireFastMutex(&g_NtApiHookPatchLock);
        if (mirroredPatch)
        {
            (void)BkntkiUpsertHookPatchLocked(ProcessId, mirrorPatchAddress64, patchSize, originalBytes, originalSize,
                                              cloakBytes, flags, tag);
        }
    }
    ExReleaseFastMutex(&g_NtApiHookPatchLock);

Exit:
    if (NT_SUCCESS(finalStatus))
    {
        InterlockedIncrement64(&g_NtApiDuplicateNtdllMirrorCount);
    }
    else
    {
        InterlockedIncrement64(&g_NtApiDuplicateNtdllMirrorFailureCount);
    }
    ZwClose(processHandle);
    ObDereferenceObject(process);
    return finalStatus;
}

BOOLEAN
BkntkiReadTouchesInstrumentationRange(_In_ HANDLE ProcessHandle, _In_ PVOID BaseAddress, _In_ SIZE_T Size,
                                      _Out_opt_ UINT32 *TargetProcessId)
{
    UINT32 pid = 0;
    UINT64 readBase;
    UINT64 readEnd;
    UINT32 i;
    BOOLEAN matched = FALSE;

    if (TargetProcessId != NULL)
    {
        *TargetProcessId = 0;
    }
    if (KeGetCurrentIrql() != PASSIVE_LEVEL || BaseAddress == NULL || Size == 0)
    {
        return FALSE;
    }
    readBase = (UINT64)(ULONG_PTR)BaseAddress;
    readEnd = readBase + (UINT64)Size;
    if (readEnd <= readBase)
    {
        return FALSE;
    }
    if (!BkntkiResolveProcessHandleToPid(ProcessHandle, &pid) || pid == 0)
    {
        return FALSE;
    }
    if (TargetProcessId != NULL)
    {
        *TargetProcessId = pid;
    }

    ExAcquireFastMutex(&g_NtApiInstrumentationRangeLock);
    for (i = 0; i < BK_MAX_INSTRUMENTATION_RANGES; ++i)
    {
        const BK_NTAPI_INSTRUMENTATION_RANGE *slot = &g_NtApiInstrumentationRanges[i];
        if (slot->Active && slot->ProcessId == pid &&
            BkntkiRangesOverlap(readBase, readEnd, slot->BaseAddress, slot->EndAddress))
        {
            matched = TRUE;
            break;
        }
    }
    ExReleaseFastMutex(&g_NtApiInstrumentationRangeLock);
    if (matched)
    {
        InterlockedIncrement64(&g_NtApiInstrumentationReadDenyCount);
    }
    return matched;
}

VOID BkntkiQueryDiagnostics(_Out_opt_ UINT32 *InstrumentationRangeCount, _Out_opt_ UINT32 *HookPatchCount,
                            _Out_opt_ UINT64 *HookPatchOverlayCount, _Out_opt_ UINT64 *InstrumentationReadDenyCount,
                            _Out_opt_ UINT64 *DuplicateNtdllMirrorCount,
                            _Out_opt_ UINT64 *DuplicateNtdllMirrorFailureCount)
{
    UINT32 i;
    UINT32 rangeCount = 0;
    UINT32 patchCount = 0;

    if (InstrumentationRangeCount != NULL)
    {
        ExAcquireFastMutex(&g_NtApiInstrumentationRangeLock);
        for (i = 0; i < BK_MAX_INSTRUMENTATION_RANGES; ++i)
        {
            if (g_NtApiInstrumentationRanges[i].Active)
            {
                rangeCount += 1;
            }
        }
        ExReleaseFastMutex(&g_NtApiInstrumentationRangeLock);
        *InstrumentationRangeCount = rangeCount;
    }

    if (HookPatchCount != NULL)
    {
        ExAcquireFastMutex(&g_NtApiHookPatchLock);
        for (i = 0; i < BK_MAX_HOOK_PATCH_RECORDS; ++i)
        {
            if (g_NtApiHookPatches[i].Active)
            {
                patchCount += 1;
            }
        }
        ExReleaseFastMutex(&g_NtApiHookPatchLock);
        *HookPatchCount = patchCount;
    }

    if (HookPatchOverlayCount != NULL)
    {
        *HookPatchOverlayCount = (UINT64)InterlockedCompareExchange64(&g_NtApiHookPatchOverlayCount, 0, 0);
    }
    if (InstrumentationReadDenyCount != NULL)
    {
        *InstrumentationReadDenyCount =
            (UINT64)InterlockedCompareExchange64(&g_NtApiInstrumentationReadDenyCount, 0, 0);
    }
    if (DuplicateNtdllMirrorCount != NULL)
    {
        *DuplicateNtdllMirrorCount = (UINT64)InterlockedCompareExchange64(&g_NtApiDuplicateNtdllMirrorCount, 0, 0);
    }
    if (DuplicateNtdllMirrorFailureCount != NULL)
    {
        *DuplicateNtdllMirrorFailureCount =
            (UINT64)InterlockedCompareExchange64(&g_NtApiDuplicateNtdllMirrorFailureCount, 0, 0);
    }
}

VOID BkntkiRecordSanitizerHit(_In_ UINT32 SanitizerId)
{
    if (SanitizerId < (UINT32)BkDiagSanitizerCount)
    {
        InterlockedIncrement64(&g_NtApiSanitizerHitCount[SanitizerId]);
    }
}

static UINT32 BkntkiSanitizerStreamMask(_In_ UINT32 SanitizerId)
{
    switch (SanitizerId)
    {
    case BkDiagSanitizerSystemProcessList:
    case BkDiagSanitizerSystemModuleList:
    case BkDiagSanitizerReadVirtualMemoryPatchOverlay:
    case BkDiagSanitizerReadVirtualMemoryRangeDeny:
    case BkDiagSanitizerWriteVirtualMemoryCloak:
    case BkDiagSanitizerProtectVirtualMemoryDeny:
    case BkDiagSanitizerDuplicateNtdllMirror:
    case BkDiagSanitizerVirtualMemoryBasicInfo:
        return BK_STREAM_MEMORY;
    case BkDiagSanitizerSystemHandleList:
    case BkDiagSanitizerObjectName:
    case BkDiagSanitizerIpcHandle:
        return BK_STREAM_HANDLE;
    case BkDiagSanitizerGetNextThreadFilter:
        return BK_STREAM_THREAD;
    case BkDiagSanitizerDirectoryBlackbird:
    case BkDiagSanitizerFileBlackbird:
    case BkDiagSanitizerPortBlackbird:
        return BK_STREAM_FILESYSTEM | BK_STREAM_HANDLE;
    case BkDiagSanitizerRegistryBlackbird:
    case BkDiagSanitizerRegistryBam:
        return BK_STREAM_REGISTRY;
    case BkDiagSanitizerFilesystemBlackbird:
    case BkDiagSanitizerFilesystemAntiVm:
        return BK_STREAM_FILESYSTEM;
    case BkDiagSanitizerQpcTiming:
        return BK_STREAM_TIMING;
    default:
        return BK_STREAM_MEMORY | BK_STREAM_THREAD | BK_STREAM_HANDLE;
    }
}

static UINT32 BkntkiSanitizerComponentId(_In_ UINT32 SanitizerId)
{
    switch (SanitizerId)
    {
    case BkDiagSanitizerRegistryBlackbird:
    case BkDiagSanitizerRegistryBam:
        return BK_DIAG_COMPONENT_REGISTRY_MONITOR;
    case BkDiagSanitizerFilesystemBlackbird:
    case BkDiagSanitizerFilesystemAntiVm:
        return BK_DIAG_COMPONENT_FILESYSTEM_MONITOR;
    default:
        return BK_DIAG_COMPONENT_NTAPI_MONITOR;
    }
}

static UINT32 BkntkiSanitizerSourceClass(_In_ UINT32 SanitizerId)
{
    switch (SanitizerId)
    {
    case BkDiagSanitizerSystemProcessList:
        return BK_SYSTEM_INFORMATION_CLASS_PROCESS;
    case BkDiagSanitizerSystemModuleList:
        return BK_SYSTEM_INFORMATION_CLASS_MODULE;
    case BkDiagSanitizerSystemHandleList:
        return BK_SYSTEM_INFORMATION_CLASS_HANDLE;
    case BkDiagSanitizerKernelDebugger:
        return BK_SYSTEM_INFORMATION_CLASS_KERNEL_DEBUGGER;
    case BkDiagSanitizerCodeIntegrity:
        return BK_SYSTEM_INFORMATION_CLASS_CODE_INTEGRITY;
    case BkDiagSanitizerFirmwareTable:
        return BK_SYSTEM_INFORMATION_CLASS_FIRMWARE_TABLE;
    case BkDiagSanitizerVirtualMemoryBasicInfo:
        return 0u;
    default:
        return MAXULONG;
    }
}

static UINT64 BkntkiSanitizerCounterValue(_In_ UINT32 SanitizerId)
{
    switch (SanitizerId)
    {
    case BkDiagSanitizerReadVirtualMemoryPatchOverlay:
        return (UINT64)InterlockedCompareExchange64(&g_NtApiHookPatchOverlayCount, 0, 0);
    case BkDiagSanitizerReadVirtualMemoryRangeDeny:
        return (UINT64)InterlockedCompareExchange64(&g_NtApiInstrumentationReadDenyCount, 0, 0);
    case BkDiagSanitizerDuplicateNtdllMirror:
        return (UINT64)InterlockedCompareExchange64(&g_NtApiDuplicateNtdllMirrorCount, 0, 0);
    default:
        if (SanitizerId < (UINT32)BkDiagSanitizerCount)
        {
            return (UINT64)InterlockedCompareExchange64(&g_NtApiSanitizerHitCount[SanitizerId], 0, 0);
        }
        return 0;
    }
}

VOID BkntkiQueryHookDiagnostics(_Out_writes_(Capacity) PBK_DIAGNOSTIC_NTAPI_HOOK_STATE States, _In_ UINT32 Capacity,
                                _Out_ UINT32 *Count)
{
    UINT32 i;
    UINT32 written = 0;

    if (Count != NULL)
    {
        *Count = 0;
    }
    if (States == NULL || Capacity == 0 || Count == NULL)
    {
        return;
    }

    ExAcquireFastMutex(&g_NtApiHookLifecycleLock);
    for (i = 0; i < BK_HOOK_COUNT && written < Capacity; ++i)
    {
        const BK_NTAPI_HOOK *hook = &g_Hooks[i];
        PBK_DIAGNOSTIC_NTAPI_HOOK_STATE out = &States[written++];

        RtlZeroMemory(out, sizeof(*out));
        out->HookId = (UINT16)i;
        out->Required = hook->Descriptor.Required ? 1u : 0u;
        out->OverwriteLength = hook->ActiveOverwriteLength;
        out->RoutineAddress = (UINT64)(ULONG_PTR)hook->RoutineAddress;
        out->TrampolineAddress = (UINT64)(ULONG_PTR)hook->Trampoline;
        out->Flags =
            BK_DIAG_STATE_HOOK | (hook->Descriptor.Required ? BK_DIAG_STATE_REQUIRED : BK_DIAG_STATE_OPTIONAL_STATE);
        if (hook->RoutineAddress != NULL)
        {
            out->Flags |= BK_DIAG_STATE_RESOLVED;
        }
        if (hook->Installed)
        {
            out->Flags |= BK_DIAG_STATE_INSTALLED | BK_DIAG_STATE_ARMED;
        }
        if (!hook->Descriptor.Required && !hook->Installed)
        {
            out->Flags |= BK_DIAG_STATE_DEGRADED;
        }
    }
    ExReleaseFastMutex(&g_NtApiHookLifecycleLock);
    *Count = written;
}

VOID BkntkiQuerySanitizerDiagnostics(_Out_writes_(Capacity) PBK_DIAGNOSTIC_SANITIZER_STATE States, _In_ UINT32 Capacity,
                                     _Out_ UINT32 *Count)
{
    UINT32 i;
    UINT32 written = 0;
    UINT32 flags;

    if (Count != NULL)
    {
        *Count = 0;
    }
    if (States == NULL || Capacity == 0 || Count == NULL)
    {
        return;
    }

    flags = BK_DIAG_STATE_SANITIZES | BK_DIAG_STATE_FAST_PATH;
    if (BkrtIsNtApiHooksDisarmed())
    {
        flags |= BK_DIAG_STATE_POLICY_DISABLED;
    }
    for (i = 0; i < (UINT32)BkDiagSanitizerCount && written < Capacity; ++i)
    {
        PBK_DIAGNOSTIC_SANITIZER_STATE out = &States[written++];

        RtlZeroMemory(out, sizeof(*out));
        out->SanitizerId = (UINT16)i;
        out->ComponentId = (UINT16)BkntkiSanitizerComponentId(i);
        out->Flags = flags;
        out->StreamMask = BkntkiSanitizerStreamMask(i);
        out->SourceClass = BkntkiSanitizerSourceClass(i);
        out->HitCount = BkntkiSanitizerCounterValue(i);
    }
    *Count = written;
}

BOOLEAN BkntkiShouldLog(_Out_ HANDLE *CallerPid)
{
    HANDLE pid;
    HANDLE threadOwnerPid;
    KIRQL irql;

    if (InterlockedCompareExchange(&g_NtApiMonitorInitialized, 0, 0) == 0 ||
        InterlockedCompareExchange(&g_NtApiMonitorUnloading, 0, 0) != 0 ||
        InterlockedCompareExchange(&g_NtApiHooksArmed, 0, 0) == 0)
    {
        if (InterlockedDecrement(&g_NtApiSkipInitBudget) >= 0)
        {
            BK_NTAPI_LOG(DPFLTR_INFO_LEVEL,
                         "BK: ntapi should-log skip reason=init-state initialized=%ld unloading=%ld hooksArmed=%ld.\n",
                         InterlockedCompareExchange(&g_NtApiMonitorInitialized, 0, 0),
                         InterlockedCompareExchange(&g_NtApiMonitorUnloading, 0, 0),
                         InterlockedCompareExchange(&g_NtApiHooksArmed, 0, 0));
        }
        return FALSE;
    }
    irql = KeGetCurrentIrql();
    if (irql != PASSIVE_LEVEL)
    {
        if (InterlockedDecrement(&g_NtApiSkipIrqlBudget) >= 0)
        {
            BK_NTAPI_LOG(DPFLTR_INFO_LEVEL, "BK: ntapi should-log skip reason=irql value=%lu.\n", irql);
        }
        return FALSE;
    }
    if (!BkctlIsArmedFast())
    {
        if (InterlockedDecrement(&g_NtApiSkipArmedBudget) >= 0)
        {
            BK_NTAPI_LOG(DPFLTR_INFO_LEVEL, "BK: ntapi should-log skip reason=disarmed.\n");
        }
        return FALSE;
    }
    if (BkrtIsNtApiHooksDisarmed())
    {
        return FALSE;
    }

    pid = PsGetCurrentProcessId();
    if (!BkctlHasPidInterest((UINT32)(ULONG_PTR)pid, 0, BK_STREAM_MEMORY))
    {
        if (InterlockedDecrement(&g_NtApiSkipPidBudget) >= 0)
        {
            BK_NTAPI_LOG(DPFLTR_INFO_LEVEL, "BK: ntapi should-log skip reason=pid-not-monitored pid=%u.\n",
                         (UINT32)(ULONG_PTR)pid);
        }
        return FALSE;
    }
    threadOwnerPid = PsGetThreadProcessId(PsGetCurrentThread());
    if (BkcprocShouldSuppressLaunchBootstrapNtApi((UINT32)(ULONG_PTR)pid, (UINT32)(ULONG_PTR)threadOwnerPid))
    {
        if (InterlockedDecrement(&g_NtApiSkipLaunchBootstrapBudget) >= 0)
        {
            BK_NTAPI_LOG(
                DPFLTR_INFO_LEVEL,
                "BK: ntapi should-log skip reason=launch-bootstrap-owner-mismatch pid=%u threadOwnerPid=%u tid=%u.\n",
                (UINT32)(ULONG_PTR)pid, (UINT32)(ULONG_PTR)threadOwnerPid, (UINT32)(ULONG_PTR)PsGetCurrentThreadId());
        }
        return FALSE;
    }
    if (!ExAcquireRundownProtection(&g_NtApiRundown))
    {
        if (InterlockedDecrement(&g_NtApiSkipRundownBudget) >= 0)
        {
            BK_NTAPI_LOG(DPFLTR_INFO_LEVEL, "BK: ntapi should-log skip reason=rundown pid=%u.\n",
                         (UINT32)(ULONG_PTR)pid);
        }
        return FALSE;
    }

    *CallerPid = pid;
    return TRUE;
}

VOID BkntkiLog(_In_z_ PCSTR ApiName, _In_ HANDLE CallerPid, _In_ UINT64 Arg0, _In_ UINT64 Arg1, _In_ UINT64 Arg2,
               _In_ UINT64 Arg3, _In_ UINT64 Arg4, _In_ UINT64 Arg5, _In_ UINT64 Arg6, _In_ UINT64 Arg7,
               _In_ UINT32 ExecFlags, _In_ NTSTATUS Status)
{
    ULONGLONG tempusStartQpc = BktmpEnter(BktmpSubsystemNtApiMonitor);
    BketwLogNtApiEvent(ApiName, CallerPid, PsGetCurrentThreadId(), Arg0, Arg1, Arg2, Arg3, Arg4, Arg5, Arg6, Arg7,
                       ExecFlags, Status);
    BktmpLeave(BktmpSubsystemNtApiMonitor, tempusStartQpc);
}

UINT32 BkntkiBuildExecFlags(_In_opt_ HANDLE ProcessHandle, _In_ ULONG AllocationAttributes)
{
    UINT32 flags = 0;
    KPROCESSOR_MODE previousMode = ExGetPreviousMode();

    flags |= (previousMode == KernelMode) ? BK_NTAPI_EXEC_FLAG_CALLER_KERNEL : BK_NTAPI_EXEC_FLAG_CALLER_USER;
    if (ProcessHandle == (HANDLE)(LONG_PTR)-1)
    {
        flags |= BK_NTAPI_EXEC_FLAG_TARGET_CURRENT_PROCESS;
    }
    if ((AllocationAttributes & SEC_IMAGE) != 0)
    {
        flags |= BK_NTAPI_EXEC_FLAG_SECTION_IMAGE;
    }

    return flags;
}

VOID BkntkiPostProcessSystemInformationQuery(_In_ ULONG SystemInformationClass,
                                             _Inout_updates_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
                                             _In_ ULONG SystemInformationLength, _In_ NTSTATUS Status)
{
    UINT32 streamMask = BK_STREAM_MEMORY | BK_STREAM_THREAD | BK_STREAM_HANDLE;
    if (!BkntkiShouldSanitizeCurrentCaller(streamMask))
    {
        return;
    }

    BkntkiSanitizeProcessInformation(SystemInformationClass, SystemInformation, SystemInformationLength, Status);
    BkntkiSanitizeModuleInformation(SystemInformationClass, SystemInformation, SystemInformationLength, Status);
    BkntkiSanitizeKernelDebuggerInformation(SystemInformationClass, SystemInformation, SystemInformationLength, Status);
    BkntkiSanitizeCodeIntegrityInformation(SystemInformationClass, SystemInformation, SystemInformationLength, Status);
    BkavNtSanitizeFirmwareTableInformation(SystemInformationClass, SystemInformation, SystemInformationLength, Status);
    BkntkiSanitizeHandleInformation(SystemInformationClass, SystemInformation, SystemInformationLength, Status);
}

VOID BkntkiPostProcessSystemInformationExQuery(_In_ ULONG SystemInformationClass,
                                               _Inout_updates_bytes_opt_(SystemInformationLength)
                                                   PVOID SystemInformation,
                                               _In_ ULONG SystemInformationLength, _In_ NTSTATUS Status)
{
    UINT32 streamMask = BK_STREAM_MEMORY | BK_STREAM_THREAD | BK_STREAM_HANDLE;
    if (!BkntkiShouldSanitizeCurrentCaller(streamMask))
    {
        return;
    }

    BkntkiSanitizeKernelDebuggerInformation(SystemInformationClass, SystemInformation, SystemInformationLength, Status);
    BkntkiSanitizeCodeIntegrityInformation(SystemInformationClass, SystemInformation, SystemInformationLength, Status);
    BkavNtSanitizeFirmwareTableInformation(SystemInformationClass, SystemInformation, SystemInformationLength, Status);
}

static VOID BkntkiClearOriginalSlots(VOID)
{
    g_OriginalNtQuerySystemInformation = NULL;
    g_OriginalNtQueryInformationProcess = NULL;
    g_OriginalNtQueryObject = NULL;
    g_OriginalNtWriteVirtualMemory = NULL;
    g_OriginalNtReadVirtualMemory = NULL;
    g_OriginalNtProtectVirtualMemory = NULL;
    g_OriginalNtCreateSection = NULL;
    g_OriginalNtMapViewOfSection = NULL;
    g_OriginalNtMapViewOfSectionEx = NULL;
    g_OriginalNtUnmapViewOfSection = NULL;
    g_OriginalNtUnmapViewOfSectionEx = NULL;
    g_OriginalNtAllocateVirtualMemory = NULL;
    g_OriginalNtCreateThread = NULL;
    g_OriginalNtCreateThreadEx = NULL;
    g_OriginalNtQueueApcThread = NULL;
    g_OriginalNtQueueApcThreadEx = NULL;
    g_OriginalNtQueueApcThreadEx2 = NULL;
    g_OriginalNtQuerySystemInformationEx = NULL;
    g_OriginalNtQueryPerformanceCounter = NULL;
    g_OriginalNtQueryVirtualMemory = NULL;
    g_OriginalNtGetContextThread = NULL;
    g_OriginalNtSetContextThread = NULL;
    g_OriginalNtGetNextThread = NULL;
    g_OriginalNtQueryInformationThread = NULL;
    g_OriginalNtSetInformationThread = NULL;
    g_OriginalNtSetInformationProcess = NULL;
    g_OriginalNtResumeThread = NULL;
    g_OriginalNtSuspendThread = NULL;
    g_OriginalNtAlertResumeThread = NULL;
    g_OriginalNtAlertThread = NULL;
    g_OriginalNtTestAlert = NULL;
    g_OriginalNtCreateUserProcess = NULL;
    g_OriginalNtCreateProcessEx = NULL;
    g_OriginalNtCreateFile = NULL;
    g_OriginalNtOpenFile = NULL;
    g_OriginalNtDeviceIoControlFile = NULL;
    g_OriginalNtFsControlFile = NULL;
    g_OriginalNtQueryDirectoryFile = NULL;
    g_OriginalNtQueryDirectoryFileEx = NULL;
    g_OriginalNtAlpcConnectPort = NULL;
    g_OriginalNtAlpcSendWaitReceivePort = NULL;
    g_OriginalNtConnectPort = NULL;
    g_OriginalNtOpenProcess = NULL;
    g_OriginalNtOpenThread = NULL;
    g_OriginalNtDuplicateObject = NULL;
    g_OriginalNtQueryKey = NULL;
    g_OriginalNtEnumerateKey = NULL;
    g_OriginalNtQueryValueKey = NULL;
    g_OriginalNtEnumerateValueKey = NULL;
}

static NTSTATUS BkntkiInstallHooksLocked(VOID)
{
    NTSTATUS status = STATUS_SUCCESS;
    UINT32 i;

    /* KUSER_SHARED_DATA is read-only on current Windows 11 builds. Keep
     * debugger masking in the NtQuerySystemInformation sanitizer instead. */

    for (i = 0; i < BK_HOOK_COUNT; ++i)
    {
        PVOID *originalSlot = BkntkiOriginalSlot((BK_HOOK_ID)i);

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "BK: ntapi hook install begin api=%s.\n",
                   g_HookDescriptors[i].ApiName);

        status = BkntkhHookInstall(&g_Hooks[i], originalSlot);
        if (!NT_SUCCESS(status))
        {
            if (!g_HookDescriptors[i].Required || status == STATUS_PROCEDURE_NOT_FOUND)
            {
                DbgPrintEx(
                    DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                    "BK: ntapi hook unavailable api=%s required=%u status=0x%08X (continuing without this hook).\n",
                    g_HookDescriptors[i].ApiName, g_HookDescriptors[i].Required ? 1u : 0u, status);
                if (originalSlot != NULL)
                {
                    *originalSlot = NULL;
                }
                continue;
            }

            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "BK: ntapi hook install failed api=%s status=0x%08X.\n",
                       g_HookDescriptors[i].ApiName, status);
            goto Fail;
        }
    }

    return STATUS_SUCCESS;

Fail:
    BkntkiDeactivateHooksLocked();
    return status;
}

static VOID BkntkiDeactivateHooksLocked(VOID)
{
    UINT32 i;

    InterlockedExchange(&g_NtApiHooksArmed, 0);
    for (i = 0; i < BK_HOOK_COUNT; ++i)
    {
        BkntkhHookDeactivate(&g_Hooks[i]);
    }
}

static VOID BkntkiRemoveHooksLocked(VOID)
{
    UINT32 i;

    BkntkiDeactivateHooksLocked();
    BkntkiWaitForInFlightCalls();

    for (i = 0; i < BK_HOOK_COUNT; ++i)
    {
        BkntkhHookFreeTrampoline(&g_Hooks[i]);
    }

    BkntkiClearOriginalSlots();
}

NTSTATUS
BkntkiMonitorInitialize(VOID)
{
    UINT32 i;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (InterlockedCompareExchange(&g_NtApiMonitorInitialized, 1, 0) != 0)
    {
        return STATUS_SUCCESS;
    }

    InterlockedExchange(&g_NtApiMonitorUnloading, 0);
    ExInitializeRundownProtection(&g_NtApiRundown);
    ExInitializeFastMutex(&g_NtApiInstrumentationRangeLock);
    ExInitializeFastMutex(&g_NtApiHookPatchLock);
    ExInitializeFastMutex(&g_NtApiHookLifecycleLock);
    ExInitializeFastMutex(&g_NtApiNtdllSectionLock);
    ExInitializeFastMutex(&g_NtApiPicLock);
    BkntkiClearInstrumentationRanges();
    BkntkiClearHookPatches();
    BkntkiClearNtdllSections();
    BkntkiClearProcessInstrumentationCallbacks();
    BkntkiClearOriginalSlots();
    (void)BkqpcInitialize();
    InterlockedExchange(&g_NtApiHooksArmed, 0);
    InterlockedExchange64(&g_NtApiHookPatchOverlayCount, 0);
    InterlockedExchange64(&g_NtApiInstrumentationReadDenyCount, 0);
    InterlockedExchange64(&g_NtApiDuplicateNtdllMirrorCount, 0);
    InterlockedExchange64(&g_NtApiDuplicateNtdllMirrorFailureCount, 0);
    RtlZeroMemory((PVOID)g_NtApiSanitizerHitCount, sizeof(g_NtApiSanitizerHitCount));
    InterlockedExchange(&g_NtApiHookInFlight, 0);
    InterlockedExchange(&g_NtApiUninitWaitBudget, 16);
    InterlockedExchange(&g_NtApiKdSanitizeBudget, 16);
    InterlockedExchange(&g_NtApiKdSanitizeApplyBudget, 16);
    InterlockedExchange(&g_NtApiSmbiosSanitizeBudget, 16);
    InterlockedExchange(&g_NtApiSmbiosSanitizeApplyBudget, 16);
    for (i = 0; i < BK_HOOK_COUNT; ++i)
    {
        BkntkhHookInitialize(&g_Hooks[i], &g_HookDescriptors[i]);
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "BK: ntapi monitor initialized with hooks disarmed.\n");
    return STATUS_SUCCESS;
}

NTSTATUS
BkntkiMonitorArmHooks(VOID)
{
    NTSTATUS status;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (InterlockedCompareExchange(&g_NtApiMonitorInitialized, 0, 0) == 0 ||
        InterlockedCompareExchange(&g_NtApiMonitorUnloading, 0, 0) != 0)
    {
        return STATUS_DEVICE_NOT_READY;
    }
    if (BkrtIsNtApiHooksDisarmed())
    {
        BkntkiMonitorDisarmHooks();
        BkdiagRecord(BktmpSubsystemNtApiMonitor, BkDiagEventDisabledByPolicy, STATUS_SUCCESS, 0,
                     BK_DIAG_FLAG_POLICY | BK_DIAG_FLAG_CONTINUING, 0, BK_DIAG_COMPONENT_NTAPI_MONITOR);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                   "BK: ntapi hooks remain disarmed by runtime configuration.\n");
        return STATUS_SUCCESS;
    }

    ExAcquireFastMutex(&g_NtApiHookLifecycleLock);
    if (InterlockedCompareExchange(&g_NtApiHooksArmed, 0, 0) != 0)
    {
        ExReleaseFastMutex(&g_NtApiHookLifecycleLock);
        return STATUS_SUCCESS;
    }

    status = BkntkiInstallHooksLocked();
    if (NT_SUCCESS(status))
    {
        InterlockedExchange(&g_NtApiHooksArmed, 1);
        BkdiagRecord(BktmpSubsystemNtApiMonitor, BkDiagEventArmed, STATUS_SUCCESS, 0, 0, 0,
                     BK_DIAG_COMPONENT_NTAPI_MONITOR);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "BK: ntapi hooks armed.\n");
    }
    else
    {
        BkdiagRecord(BktmpSubsystemNtApiMonitor, BkDiagEventSelfCheckFailed, status, 0, BK_DIAG_FLAG_FAILURE, 0,
                     BK_DIAG_COMPONENT_NTAPI_MONITOR);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "BK: ntapi hook arm failed status=0x%08X.\n", status);
    }
    ExReleaseFastMutex(&g_NtApiHookLifecycleLock);
    return status;
}

VOID BkntkiMonitorDisarmHooks(VOID)
{
    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        return;
    }
    if (InterlockedCompareExchange(&g_NtApiMonitorInitialized, 0, 0) == 0)
    {
        return;
    }

    ExAcquireFastMutex(&g_NtApiHookLifecycleLock);
    if (InterlockedCompareExchange(&g_NtApiHooksArmed, 0, 0) != 0)
    {
        BkntkiDeactivateHooksLocked();
        BkdiagRecord(BktmpSubsystemNtApiMonitor, BkDiagEventDisarmed, STATUS_SUCCESS, 0, BK_DIAG_FLAG_SHUTDOWN, 0,
                     BK_DIAG_COMPONENT_NTAPI_MONITOR);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "BK: ntapi hooks disarmed.\n");
    }
    ExReleaseFastMutex(&g_NtApiHookLifecycleLock);
}

VOID BkntkiMonitorSetArmedState(_In_ BOOLEAN Armed)
{
    if (Armed)
    {
        NTSTATUS status = BkntkiMonitorArmHooks();
        if (!NT_SUCCESS(status))
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "BK: ntapi hooks could not arm for telemetry state status=0x%08X.\n", status);
        }
        return;
    }

    BkntkiMonitorDisarmHooks();
}

VOID BkntkiMonitorUninitialize(VOID)
{
    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        return;
    }
    if (InterlockedExchange(&g_NtApiMonitorInitialized, 0) == 0)
    {
        return;
    }

    InterlockedExchange(&g_NtApiMonitorUnloading, 1);
    ExAcquireFastMutex(&g_NtApiHookLifecycleLock);
    BkntkiRemoveHooksLocked();
    ExReleaseFastMutex(&g_NtApiHookLifecycleLock);
    BkntkiClearInstrumentationRanges();
    BkntkiClearHookPatches();
    BkntkiClearNtdllSections();
    BkntkiClearProcessInstrumentationCallbacks();
    BkqpcUninitialize();
    InterlockedExchange(&g_NtApiMonitorUnloading, 0);
}

BOOLEAN
BkntkiMonitorSelfCheck(VOID)
{
    if (InterlockedCompareExchange(&g_NtApiMonitorInitialized, 0, 0) == 0)
    {
        return FALSE;
    }

    return (InterlockedCompareExchange(&g_NtApiMonitorUnloading, 0, 0) == 0);
}

#else

NTSTATUS
BkntkiMonitorInitialize(VOID)
{
    return STATUS_SUCCESS;
}

NTSTATUS
BkntkiMonitorArmHooks(VOID)
{
    return STATUS_NOT_SUPPORTED;
}

VOID BkntkiMonitorDisarmHooks(VOID)
{
}

VOID BkntkiMonitorSetArmedState(_In_ BOOLEAN Armed)
{
    UNREFERENCED_PARAMETER(Armed);
}

VOID BkntkiMonitorUninitialize(VOID)
{
}

BOOLEAN
BkntkiMonitorSelfCheck(VOID)
{
    return TRUE;
}

NTSTATUS
BkntkiRegisterProcessInstrumentationCallback(_In_ UINT32 ProcessId, _In_ UINT64 CallbackAddress,
                                             _In_ UINT64 CallbackSize, _In_ UINT32 Flags)
{
    UNREFERENCED_PARAMETER(ProcessId);
    UNREFERENCED_PARAMETER(CallbackAddress);
    UNREFERENCED_PARAMETER(CallbackSize);
    UNREFERENCED_PARAMETER(Flags);
    return STATUS_NOT_SUPPORTED;
}

VOID BkntkiClearProcessInstrumentationCallback(_In_ UINT32 ProcessId)
{
    UNREFERENCED_PARAMETER(ProcessId);
}

#endif
