#ifndef BKIPC_H
#define BKIPC_H

#include "blackbird_ioctl.h"

#define BKIPC_PIPE_NAME L"\\\\.\\pipe\\BlackbirdController"
#define BKIPC_HOOK_PIPE_NAME L"\\\\.\\pipe\\BlackbirdHookIngest"
#define BKIPC_MAGIC 0x53574B52u
#define BKIPC_VERSION 7u

typedef enum _BK_IPC_PACKET_TYPE
{
    BlackbirdIpcPacketInvalid = 0,
    BlackbirdIpcPacketRequest = 1,
    BlackbirdIpcPacketResponse = 2
} BKIPC_PACKET_TYPE;

typedef enum _BK_IPC_COMMAND
{
    BlackbirdIpcCommandNone = 0,
    BlackbirdIpcCommandHandshake = 1,
    BlackbirdIpcCommandSubscribe = 2,
    BlackbirdIpcCommandUnsubscribe = 3,
    BlackbirdIpcCommandSetPids = 4,
    BlackbirdIpcCommandGetEvent = 5,
    BlackbirdIpcCommandGetStats = 6,
    BlackbirdIpcCommandQueryProcessImage = 7,
    BlackbirdIpcCommandSetShutdownMode = 8,
    BlackbirdIpcCommandGetEtwEvent = 9,
    BlackbirdIpcCommandOpenSharedRing = 10,
    BlackbirdIpcCommandPublishHookEvent = 11,
    BlackbirdIpcCommandSetUserHookTarget = 12,
    BlackbirdIpcCommandNotifyHookReady = 13,
    BlackbirdIpcCommandControlProcessExecution = 14,
    BlackbirdIpcCommandSetRuntimeConfig = 15,
    BlackbirdIpcCommandGetRuntimeConfig = 16,
    BlackbirdIpcCommandQueryProcessMemory = 17,
    BlackbirdIpcCommandUpgradeWinsockHooks = 18,
    BlackbirdIpcCommandRegisterInstrumentationRange = 19,
    BlackbirdIpcCommandRegisterHookPatch = 20,
    BlackbirdIpcCommandGetHealth = 21,
    BlackbirdIpcCommandGetDiagnostics = 22,
    BlackbirdIpcCommandSetQpcTimingConfig = 23,
    BlackbirdIpcCommandGetQpcTimingState = 24,
    BlackbirdIpcCommandRegisterProcessInstrumentationCallback = 25
} BKIPC_COMMAND;

typedef struct _BK_IPC_HANDSHAKE_REQUEST
{
    UINT32 RequestedVersion;
} BKIPC_HANDSHAKE_REQUEST, *PBKIPC_HANDSHAKE_REQUEST;

typedef struct _BK_IPC_HANDSHAKE_RESPONSE
{
    UINT32 NegotiatedVersion;
    UINT32 Capabilities;
    UINT32 ThreatIntelEnabled;
    UINT32 Reserved;
} BKIPC_HANDSHAKE_RESPONSE, *PBKIPC_HANDSHAKE_RESPONSE;

typedef struct _BK_IPC_GET_EVENT_REQUEST
{
    UINT32 TimeoutMs;
} BKIPC_GET_EVENT_REQUEST, *PBKIPC_GET_EVENT_REQUEST;

typedef struct _BK_IPC_OPEN_SHARED_RING_REQUEST
{
    UINT32 DesiredIoctlCapacity;
    UINT32 DesiredEtwCapacity;
} BKIPC_OPEN_SHARED_RING_REQUEST, *PBKIPC_OPEN_SHARED_RING_REQUEST;

typedef struct _BK_IPC_OPEN_SHARED_RING_RESPONSE
{
    UINT64 IoctlMappingHandle;
    UINT64 IoctlDataReadyEventHandle;
    UINT32 IoctlCapacity;
    UINT32 IoctlRecordSize;
    UINT64 EtwMappingHandle;
    UINT64 EtwDataReadyEventHandle;
    UINT32 EtwCapacity;
    UINT32 EtwRecordSize;
} BKIPC_OPEN_SHARED_RING_RESPONSE, *PBKIPC_OPEN_SHARED_RING_RESPONSE;

typedef enum _BK_IPC_HOOK_EVENT_KIND
{
    BlackbirdIpcHookEventUnknown = 0,
    BlackbirdIpcHookEventNt = 1,
    BlackbirdIpcHookEventWinsock = 2,
    BlackbirdIpcHookEventKi = 3,
    BlackbirdIpcHookEventExceptionLowNoise = 4,
    BlackbirdIpcHookEventExceptionHighPriv = 5,
    BlackbirdIpcHookEventIntegrity = 6,
    BlackbirdIpcHookEventModule = 7
} BKIPC_HOOK_EVENT_KIND;

#define BKIPC_MAX_HOOK_API_NAME 64
#define BKIPC_MAX_HOOK_MODULE_NAME 32
#define BKIPC_MAX_HOOK_DATA_SAMPLE 64
#define BKIPC_MAX_HOOK_STACK_FRAMES 16
#define BKIPC_MAX_HOOK_ARGS 8
#define BK_MAX_INSTRUMENTATION_TAG BK_INSTRUMENTATION_RANGE_TAG_CHARS
#define BK_INSTRUMENTATION_FLAG_SYSCALL_STUB 0x00000001u
#define BK_INSTRUMENTATION_FLAG_LAUNCH_GATE 0x00000002u
#define BK_INSTRUMENTATION_FLAG_PROCESS_CALLBACK 0x00000004u
#define BK_HOOK_PATCH_FLAG_NT_INLINE 0x00000001u
#define BK_HOOK_PATCH_FLAG_WINSOCK_IAT 0x00000002u
#define BK_HOOK_PATCH_FLAG_WINSOCK_INLINE 0x00000004u
#define BK_HOOK_PATCH_FLAG_KI_SLOT 0x00000008u
#define BK_HOOK_PATCH_FLAG_MODULE_INLINE 0x00000010u

typedef struct _BK_IPC_HOOK_EVENT
{
    UINT32 Kind;
    UINT32 ProcessId;
    UINT32 ThreadId;
    UINT32 Operation;
    UINT64 Caller;
    UINT64 Context0;
    UINT64 Context1;
    UINT64 Context2;
    UINT64 Context3;
    UINT32 ArgCount;
    UINT32 DataSize;
    UINT64 Args[BKIPC_MAX_HOOK_ARGS];
    UINT32 StackCount;
    UINT32 CallerFlags;
    UINT64 Stack[BKIPC_MAX_HOOK_STACK_FRAMES];
    CHAR ApiName[BKIPC_MAX_HOOK_API_NAME];
    CHAR ModuleName[BKIPC_MAX_HOOK_MODULE_NAME];
    UINT8 DataSample[BKIPC_MAX_HOOK_DATA_SAMPLE];
} BKIPC_HOOK_EVENT, *PBKIPC_HOOK_EVENT;

typedef enum _BK_IPC_USER_HOOK_TARGET_MODE
{
    BlackbirdIpcUserHookTargetNone = 0,
    BlackbirdIpcUserHookTargetAttach = 1,
    BlackbirdIpcUserHookTargetLaunch = 2
} BKIPC_USER_HOOK_TARGET_MODE;

#define BKIPC_USER_HOOK_FLAG_LAUNCH_EARLYBIRD_APC 0x00000001u
#define BKIPC_USER_HOOK_FLAG_DEFER_LAUNCH_GATE_RELEASE 0x00000002u
#define BKIPC_MAX_LAUNCH_ENVIRONMENT_CHARS 4096
#define BKIPC_MAX_LAUNCH_ARGUMENT_CHARS 2048

#define BKIPC_HOOK_READY_FLAG_IPC_CONNECTED 0x00000001u
#define BKIPC_HOOK_READY_FLAG_WINSOCK 0x00000002u
#define BKIPC_HOOK_READY_FLAG_NT 0x00000004u
#define BKIPC_HOOK_READY_FLAG_KI 0x00000008u
#define BKIPC_HOOK_READY_FLAG_MODULE 0x00000010u
#define BKIPC_HOOK_READY_REQUIRED_MASK                                                                \
    (BKIPC_HOOK_READY_FLAG_IPC_CONNECTED | BKIPC_HOOK_READY_FLAG_WINSOCK | BKIPC_HOOK_READY_FLAG_NT | \
     BKIPC_HOOK_READY_FLAG_KI | BKIPC_HOOK_READY_FLAG_MODULE)

#define BK_LAUNCH_INTEGRITY_DEFAULT 0u
#define BK_LAUNCH_INTEGRITY_UNTRUSTED 1u
#define BK_LAUNCH_INTEGRITY_LOW 2u
#define BK_LAUNCH_INTEGRITY_MEDIUM 3u
#define BK_LAUNCH_INTEGRITY_HIGH 4u
#define BK_LAUNCH_INTEGRITY_SYSTEM 5u

typedef struct _BK_IPC_SET_USER_HOOK_TARGET_REQUEST
{
    UINT32 Mode;
    UINT32 ProcessId;
    UINT32 Flags;
    UINT32 ParentProcessId;
    UINT32 PriorityClass;
    UINT32 InheritHandles;
    UINT32 IntegrityLevel;
    UINT32 AnalysisSubjectKind;
    UINT64 AffinityMask;
    WCHAR ImagePath[BK_MAX_IMAGE_PATH_CHARS];
    WCHAR AnalysisSubjectPath[BK_MAX_IMAGE_PATH_CHARS];
    WCHAR HookDllPath[BK_MAX_IMAGE_PATH_CHARS];
    WCHAR WorkingDirectory[BK_MAX_IMAGE_PATH_CHARS];
    WCHAR CommandLineArguments[BKIPC_MAX_LAUNCH_ARGUMENT_CHARS];
    WCHAR EnvironmentOverrides[BKIPC_MAX_LAUNCH_ENVIRONMENT_CHARS];
} BKIPC_SET_USER_HOOK_TARGET_REQUEST, *PBKIPC_SET_USER_HOOK_TARGET_REQUEST;

typedef struct _BK_IPC_SET_USER_HOOK_TARGET_RESPONSE
{
    UINT32 ProcessId;
    INT32 Status;
    UINT32 AnalysisSubjectKind;
    UINT32 Reserved1;
    WCHAR ImagePath[BK_MAX_IMAGE_PATH_CHARS];
    WCHAR AnalysisSubjectPath[BK_MAX_IMAGE_PATH_CHARS];
} BKIPC_SET_USER_HOOK_TARGET_RESPONSE, *PBKIPC_SET_USER_HOOK_TARGET_RESPONSE;

typedef struct _BK_IPC_NOTIFY_HOOK_READY_REQUEST
{
    UINT32 ProcessId;
    UINT32 ReadyMask;
    UINT32 Reserved0;
    UINT32 Reserved1;
} BKIPC_NOTIFY_HOOK_READY_REQUEST, *PBKIPC_NOTIFY_HOOK_READY_REQUEST;

typedef struct _BK_IPC_NOTIFY_HOOK_READY_RESPONSE
{
    UINT32 ProcessId;
    UINT32 ObservedMask;
    UINT32 RequiredMask;
    UINT32 PendingCommand;
} BKIPC_NOTIFY_HOOK_READY_RESPONSE, *PBKIPC_NOTIFY_HOOK_READY_RESPONSE;

typedef struct _BK_IPC_QUERY_PROCESS_MEMORY_REQUEST
{
    UINT32 ProcessId;
    UINT32 RequestedSize;
    UINT64 BaseAddress;
} BKIPC_QUERY_PROCESS_MEMORY_REQUEST, *PBKIPC_QUERY_PROCESS_MEMORY_REQUEST;

typedef struct _BK_IPC_QUERY_PROCESS_MEMORY_RESPONSE
{
    INT32 Status;
    UINT32 BytesRead;
    UINT64 SectionHandle;
} BKIPC_QUERY_PROCESS_MEMORY_RESPONSE, *PBKIPC_QUERY_PROCESS_MEMORY_RESPONSE;

typedef struct _BK_IPC_REGISTER_INSTRUMENTATION_RANGE_REQUEST
{
    UINT64 BaseAddress;
    UINT64 RegionSize;
    UINT32 Flags;
    UINT32 Reserved;
    CHAR Tag[BK_MAX_INSTRUMENTATION_TAG];
} BKIPC_REGISTER_INSTRUMENTATION_RANGE_REQUEST, *PBKIPC_REGISTER_INSTRUMENTATION_RANGE_REQUEST;

typedef struct _BK_IPC_REGISTER_HOOK_PATCH_REQUEST
{
    UINT64 PatchAddress;
    UINT32 PatchSize;
    UINT32 OriginalSize;
    UINT32 Flags;
    UINT32 Reserved;
    UINT8 OriginalBytes[BK_MAX_HOOK_PATCH_BYTES];
    CHAR Tag[BK_HOOK_PATCH_TAG_CHARS];
} BKIPC_REGISTER_HOOK_PATCH_REQUEST, *PBKIPC_REGISTER_HOOK_PATCH_REQUEST;

typedef struct _BK_IPC_SHARED_RING_HEADER
{
    volatile LONG WriteIndex;
    volatile LONG ReadIndex;
    volatile LONG DroppedCount;
    LONG Reserved0;
    UINT32 Capacity;
    UINT32 RecordSize;
    UINT32 Reserved1;
    UINT32 Reserved2;
} BKIPC_SHARED_RING_HEADER, *PBKIPC_SHARED_RING_HEADER;

typedef enum _BK_IPC_ETW_SOURCE
{
    BlackbirdIpcEtwSourceUnknown = 0,
    BlackbirdIpcEtwSourceBlackbird = 1,
    BlackbirdIpcEtwSourceThreatIntel = 2,
    BlackbirdIpcEtwSourceKernelNetwork = 3,
    BlackbirdIpcEtwSourceUserHook = 4
} BKIPC_ETW_SOURCE;

typedef enum _BK_IPC_ETW_FAMILY
{
    BlackbirdIpcEtwFamilyUnknown = 0,
    BlackbirdIpcEtwFamilyHandle = 1,
    BlackbirdIpcEtwFamilyThread = 2,
    BlackbirdIpcEtwFamilyProcess = 3,
    BlackbirdIpcEtwFamilyImage = 4,
    BlackbirdIpcEtwFamilyRegistry = 5,
    BlackbirdIpcEtwFamilyApc = 6,
    BlackbirdIpcEtwFamilyDetection = 7,
    BlackbirdIpcEtwFamilyThreatIntel = 8,
    BlackbirdIpcEtwFamilySocket = 9,
    BlackbirdIpcEtwFamilyUserHook = 10
} BKIPC_ETW_FAMILY;

#define BKIPC_MAX_ETW_EVENT_NAME 96
#define BKIPC_MAX_ETW_DETECTION_NAME 128
#define BKIPC_MAX_ETW_REASON 256
#define BKIPC_MAX_ETW_SHORT_TEXT 64
#define BKIPC_MAX_ETW_IMAGE_PATH 260
#define BKIPC_MAX_ETW_COMMAND_LINE 512
#define BKIPC_MAX_ETW_KEY_PATH 512
#define BKIPC_MAX_ETW_VALUE_NAME 256
#define BKIPC_MAX_ETW_STACK_FRAMES 16
#define BKIPC_MAX_ETW_DEEP_SAMPLE 64

#define BKIPC_ETW_FLAG_HANDLE_EXEC_PROTECT 0x00000001u
#define BKIPC_ETW_FLAG_HANDLE_FROM_NTDLL 0x00000002u
#define BKIPC_ETW_FLAG_HANDLE_FROM_EXE 0x00000004u
#define BKIPC_ETW_FLAG_THREAD_GOT_START 0x00000008u
#define BKIPC_ETW_FLAG_THREAD_GOT_RANGE 0x00000010u
#define BKIPC_ETW_FLAG_THREAD_REMOTE_CREATOR 0x00000020u
#define BKIPC_ETW_FLAG_THREAD_OUTSIDE_MAIN_IMAGE 0x00000040u
#define BKIPC_ETW_FLAG_PROCESS_IS_CREATE 0x00000080u
#define BKIPC_ETW_FLAG_IMAGE_SYSTEM_MODE 0x00000100u
#define BKIPC_ETW_FLAG_IMAGE_SIGNATURE_KNOWN 0x00000200u
#define BKIPC_ETW_FLAG_REGISTRY_HIGH_VALUE 0x00000400u
#define BKIPC_ETW_FLAG_APC_DUPLICATE_OPERATION 0x00000800u
#define BKIPC_ETW_FLAG_SYSCALL_EXPORT_MATCH 0x00001000u
#define BKIPC_ETW_FLAG_SYSCALL_EXPORT_MISMATCH 0x00002000u
#define BKIPC_ETW_FLAG_MODULE_CHAIN_SANE 0x00004000u
#define BKIPC_ETW_FLAG_UNWIND_METADATA_VALID 0x00008000u
#define BKIPC_ETW_FLAG_TEB_STACK_BOUNDS_VALID 0x00010000u
#define BKIPC_ETW_FLAG_FRAMES_OUTSIDE_TEB_STACK 0x00020000u
#define BKIPC_ETW_FLAG_HOOK_CALLER_ALL_SYSTEM 0x00040000u
#define BKIPC_ETW_FLAG_HOOK_CALLER_HAS_UNMAPPED 0x00080000u
#define BKIPC_ETW_FLAG_HOOK_CALLER_HAS_PROCESS_IMAGE 0x00100000u
#define BKIPC_ETW_FLAG_HOOK_CALLER_HAS_NONSYSTEM_DLL 0x00200000u
#define BKIPC_ETW_FLAG_HOOK_CALLER_HAS_OWN_MODULE 0x00400000u
#define BKIPC_ETW_FLAG_HOOK_KERNEL_CALLER 0x00800000u
#define BKIPC_ETW_FLAG_HOOK_USER_CALLER 0x01000000u
#define BKIPC_ETW_FLAG_HOOK_TARGET_CURRENT_PROCESS 0x02000000u
#define BKIPC_ETW_FLAG_HOOK_SECTION_IMAGE 0x04000000u

#define BKIPC_ETW_TRAIT_MEMORY_ALLOC_RW 0x00000001u
#define BKIPC_ETW_TRAIT_MEMORY_WRITE_VM 0x00000002u
#define BKIPC_ETW_TRAIT_MEMORY_PROTECT_RX 0x00000004u
#define BKIPC_ETW_TRAIT_NETWORK 0x00000008u
#define BKIPC_ETW_TRAIT_REMOTE_EXECUTION 0x00000010u
#define BKIPC_ETW_TRAIT_CREDENTIAL_ACCESS 0x00000020u
#define BKIPC_ETW_TRAIT_IMAGE_TAMPER 0x00000040u
#define BKIPC_ETW_TRAIT_LOLBIN 0x00000080u
#define BKIPC_ETW_TRAIT_DETECTION_CLASS 0x00000100u
#define BKIPC_ETW_TRAIT_PROCESS_LAUNCH 0x00000200u
#define BKIPC_ETW_TRAIT_IMAGE_LOAD 0x00000400u
#define BKIPC_ETW_TRAIT_DIRECT_SYSCALL 0x00000800u
#define BKIPC_ETW_TRAIT_HOOK_TAMPER 0x00001000u
#define BKIPC_ETW_TRAIT_SCAN_TARGET_PROCESS 0x00002000u
#define BKIPC_ETW_TRAIT_SCAN_IMAGE_PATH 0x00004000u
#define BKIPC_ETW_TRAIT_BLACKBIRD_OWN 0x00008000u

#define BK_HOOK_EVENT_OP_HOOK_INTEGRITY 1u
#define BK_HOOK_EVENT_OP_AMSI_PATCH 2u
#define BK_HOOK_EVENT_OP_ETW_PATCH 3u
#define BK_HOOK_EVENT_OP_LAUNCH_GATE_ENTRY 4u
#define BK_HOOK_EVENT_OP_LAUNCH_GATE_TLS_CALLBACK 5u
#define BK_HOOK_EVENT_OP_PIC_DIRECT_SYSCALL 6u
#define BK_HOOK_CALLER_FLAG_ALL_SYSTEM 0x00000001u
#define BK_HOOK_CALLER_FLAG_HAS_UNMAPPED 0x00000002u
#define BK_HOOK_CALLER_FLAG_HAS_PROCESS_IMAGE 0x00000004u
#define BK_HOOK_CALLER_FLAG_HAS_NONSYSTEM_DLL 0x00000008u
#define BK_HOOK_CALLER_FLAG_HAS_OWN_MODULE 0x00001000u
#define BK_HOOK_CALLER_IMMED_SHIFT 4u
#define BK_HOOK_CALLER_IMMED_MASK 0x000000F0u
#define BK_HOOK_CALLER_DEEP_SHIFT 8u
#define BK_HOOK_CALLER_DEEP_MASK 0x00000F00u
#define BK_HOOK_CALLER_COMPONENT_SHIFT 16u
#define BK_HOOK_CALLER_COMPONENT_MASK 0x000F0000u
#define BK_HOOK_CALLER_KIND_UNKNOWN 0u
#define BK_HOOK_CALLER_KIND_UNMAPPED 1u
#define BK_HOOK_CALLER_KIND_SYSTEM_DLL 2u
#define BK_HOOK_CALLER_KIND_PROCESS_IMAGE 3u
#define BK_HOOK_CALLER_KIND_OWN_MODULE 4u
#define BK_HOOK_CALLER_KIND_NONSYSTEM_DLL 5u
#define BK_HOOK_COMPONENT_UNKNOWN 0u
#define BK_HOOK_COMPONENT_WINSOCK 1u
#define BK_HOOK_COMPONENT_NT 2u
#define BK_HOOK_COMPONENT_KI 3u
#define BK_HOOK_COMPONENT_MODULE 4u
#define BK_HOOK_COMPONENT_INTEGRITY 5u

typedef struct _BK_IPC_ETW_EVENT
{
    UINT32 Source;
    UINT32 Family;
    UINT16 EventId;
    UINT16 Opcode;
    UINT16 Task;
    UINT16 Reserved0;
    UINT32 EventProcessId;
    UINT32 EventThreadId;
    UINT32 Severity;
    UINT32 Flags;
    UINT64 ProcessId;
    UINT64 ThreadId;
    UINT64 CallerPid;
    UINT64 TargetPid;
    UINT64 ParentProcessId;
    UINT64 CreatorProcessId;
    UINT64 CreatorThreadId;
    WCHAR EventName[BKIPC_MAX_ETW_EVENT_NAME];
    CHAR DetectionName[BKIPC_MAX_ETW_DETECTION_NAME];
    UINT32 CorrelationFlags;
    UINT32 CorrelationAccessMask;
    UINT32 CorrelationAgeMs;
    UINT32 Reserved2;
    WCHAR Reason[BKIPC_MAX_ETW_REASON];
    CHAR ClassName[BKIPC_MAX_ETW_SHORT_TEXT];
    CHAR Operation[BKIPC_MAX_ETW_SHORT_TEXT];
    UINT32 DesiredAccess;
    UINT32 OriginProtect;
    UINT64 OriginAddress;
    INT32 StatusOpenProcess;
    INT32 StatusBasicInfo;
    INT32 StatusSectionName;
    UINT32 StackCount;
    UINT32 Reserved3;
    UINT64 Stack[BKIPC_MAX_ETW_STACK_FRAMES];
    UINT64 DeepAllocationBase;
    UINT64 DeepRegionSize;
    UINT32 DeepRegionProtect;
    UINT32 DeepRegionState;
    UINT32 DeepRegionType;
    UINT32 DeepSampleSize;
    UINT8 DeepSample[BKIPC_MAX_ETW_DEEP_SAMPLE];
    WCHAR OriginPath[BKIPC_MAX_ETW_IMAGE_PATH];
    UINT64 StartAddress;
    UINT64 ImageBase;
    UINT64 ImageSize;
    UINT32 StartRegionProtect;
    UINT32 StartRegionState;
    UINT32 StartRegionType;
    INT32 StartRegionStatus;
    UINT32 SessionId;
    INT32 CreateStatus;
    UINT64 ProcessStartKey;
    UINT8 SignatureLevel;
    UINT8 SignatureType;
    UINT16 Reserved4;
    UINT32 NotifyClass;
    UINT32 DataType;
    UINT32 DataSize;
    UINT32 HookArgCount;
    UINT64 HookArgs[BKIPC_MAX_HOOK_ARGS];
    WCHAR ImagePath[BKIPC_MAX_ETW_IMAGE_PATH];
    WCHAR CommandLine[BKIPC_MAX_ETW_COMMAND_LINE];
    WCHAR KeyPath[BKIPC_MAX_ETW_KEY_PATH];
    WCHAR ValueName[BKIPC_MAX_ETW_VALUE_NAME];
} BKIPC_ETW_EVENT, *PBKIPC_ETW_EVENT;

typedef union _BK_IPC_PAYLOAD
{
    BKIPC_HANDSHAKE_REQUEST HandshakeRequest;
    BKIPC_HANDSHAKE_RESPONSE HandshakeResponse;
    BK_SUBSCRIBE_REQUEST SubscribeRequest;
    BK_UNSUBSCRIBE_REQUEST UnsubscribeRequest;
    BK_SET_PIDS_REQUEST SetPidsRequest;
    BKIPC_GET_EVENT_REQUEST GetEventRequest;
    BKIPC_OPEN_SHARED_RING_REQUEST OpenSharedRingRequest;
    BKIPC_OPEN_SHARED_RING_RESPONSE OpenSharedRingResponse;
    BKIPC_HOOK_EVENT HookEvent;
    BKIPC_SET_USER_HOOK_TARGET_REQUEST SetUserHookTargetRequest;
    BKIPC_SET_USER_HOOK_TARGET_RESPONSE SetUserHookTargetResponse;
    BKIPC_NOTIFY_HOOK_READY_REQUEST NotifyHookReadyRequest;
    BKIPC_NOTIFY_HOOK_READY_RESPONSE NotifyHookReadyResponse;
    BKIPC_QUERY_PROCESS_MEMORY_REQUEST QueryMemoryRequest;
    BKIPC_QUERY_PROCESS_MEMORY_RESPONSE QueryMemoryResponse;
    BKIPC_REGISTER_INSTRUMENTATION_RANGE_REQUEST RegisterInstrumentationRangeRequest;
    BKIPC_REGISTER_HOOK_PATCH_REQUEST RegisterHookPatchRequest;
    BK_REGISTER_PROCESS_INSTRUMENTATION_CALLBACK_REQUEST RegisterProcessInstrumentationCallbackRequest;
    BK_EVENT_RECORD EventRecord;
    BKIPC_ETW_EVENT EtwEvent;
    BK_STATS_RESPONSE StatsResponse;
    BK_HEALTH_RESPONSE HealthResponse;
    BK_DIAGNOSTICS_RESPONSE DiagnosticsResponse;
    BK_QUERY_PROCESS_IMAGE_REQUEST QueryProcessImageRequest;
    BK_QUERY_PROCESS_IMAGE_RESPONSE QueryProcessImageResponse;
    BK_CONTROL_EXECUTION_REQUEST ControlProcessExecutionRequest;
    BK_SET_RUNTIME_CONFIG_REQUEST SetRuntimeConfigRequest;
    BK_RUNTIME_CONFIG_RESPONSE RuntimeConfigResponse;
    BK_QPC_TIMING_CONFIG QpcTimingConfig;
    BK_QPC_TIMING_STATE QpcTimingState;
} BKIPC_PAYLOAD, *PBKIPC_PAYLOAD;

typedef struct _BK_IPC_PACKET
{
    UINT32 Magic;
    UINT16 Version;
    UINT16 PacketType;
    UINT32 Command;
    UINT32 Sequence;
    UINT32 Status;
    BKIPC_PAYLOAD Payload;
} BKIPC_PACKET, *PBKIPC_PACKET;

#define BKIPC_CAP_DRIVER_PROXY 0x00000001u
#define BKIPC_CAP_ETW_TI_SESSION 0x00000002u
#define BKIPC_CAP_ETW_TI_UPLINK 0x00000004u
#define BKIPC_CAP_SHARED_RING 0x00000008u
#define BKIPC_CAP_USER_HOOK_INGEST 0x00000010u
#define BKIPC_CAP_USER_HOOK_READY 0x00000020u
#define BKIPC_CAP_DRIVER_DIAGNOSTICS 0x00000040u
#define BKIPC_CAP_QPC_TIMING 0x00000080u

#endif
