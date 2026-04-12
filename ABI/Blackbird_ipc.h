#ifndef BLACKBIRD_IPC_H
#define BLACKBIRD_IPC_H

#include "blackbird_ioctl.h"

#define BLACKBIRD_IPC_PIPE_NAME L"\\\\.\\pipe\\BlackbirdController"
#define BLACKBIRD_IPC_HOOK_PIPE_NAME L"\\\\.\\pipe\\BlackbirdHookIngest"
#define BLACKBIRD_IPC_MAGIC 0x53574B52u
#define BLACKBIRD_IPC_VERSION 2u

typedef enum _BLACKBIRD_IPC_PACKET_TYPE
{
    BlackbirdIpcPacketInvalid = 0,
    BlackbirdIpcPacketRequest = 1,
    BlackbirdIpcPacketResponse = 2
} BLACKBIRD_IPC_PACKET_TYPE;

typedef enum _BLACKBIRD_IPC_COMMAND
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
    BlackbirdIpcCommandGetRuntimeConfig = 16
} BLACKBIRD_IPC_COMMAND;

typedef struct _BLACKBIRD_IPC_HANDSHAKE_REQUEST
{
    UINT32 RequestedVersion;
} BLACKBIRD_IPC_HANDSHAKE_REQUEST, *PBLACKBIRD_IPC_HANDSHAKE_REQUEST;

typedef struct _BLACKBIRD_IPC_HANDSHAKE_RESPONSE
{
    UINT32 NegotiatedVersion;
    UINT32 Capabilities;
    UINT32 ThreatIntelEnabled;
    UINT32 Reserved;
} BLACKBIRD_IPC_HANDSHAKE_RESPONSE, *PBLACKBIRD_IPC_HANDSHAKE_RESPONSE;

typedef struct _BLACKBIRD_IPC_GET_EVENT_REQUEST
{
    UINT32 TimeoutMs;
} BLACKBIRD_IPC_GET_EVENT_REQUEST, *PBLACKBIRD_IPC_GET_EVENT_REQUEST;

typedef struct _BLACKBIRD_IPC_OPEN_SHARED_RING_REQUEST
{
    UINT32 DesiredIoctlCapacity;
    UINT32 DesiredEtwCapacity;
} BLACKBIRD_IPC_OPEN_SHARED_RING_REQUEST, *PBLACKBIRD_IPC_OPEN_SHARED_RING_REQUEST;

typedef struct _BLACKBIRD_IPC_OPEN_SHARED_RING_RESPONSE
{
    UINT64 IoctlMappingHandle;
    UINT64 IoctlDataReadyEventHandle;
    UINT32 IoctlCapacity;
    UINT32 IoctlRecordSize;
    UINT64 EtwMappingHandle;
    UINT64 EtwDataReadyEventHandle;
    UINT32 EtwCapacity;
    UINT32 EtwRecordSize;
} BLACKBIRD_IPC_OPEN_SHARED_RING_RESPONSE, *PBLACKBIRD_IPC_OPEN_SHARED_RING_RESPONSE;

typedef enum _BLACKBIRD_IPC_HOOK_EVENT_KIND
{
    BlackbirdIpcHookEventUnknown = 0,
    BlackbirdIpcHookEventNt = 1,
    BlackbirdIpcHookEventWinsock = 2,
    BlackbirdIpcHookEventKi = 3,
    BlackbirdIpcHookEventExceptionLowNoise = 4,
    BlackbirdIpcHookEventExceptionHighPriv = 5,
    BlackbirdIpcHookEventIntegrity = 6,
    BlackbirdIpcHookEventModule = 7
} BLACKBIRD_IPC_HOOK_EVENT_KIND;

#define BLACKBIRD_IPC_MAX_HOOK_API_NAME 64
#define BLACKBIRD_IPC_MAX_HOOK_MODULE_NAME 32
#define BLACKBIRD_IPC_MAX_HOOK_DATA_SAMPLE 64
#define BLACKBIRD_IPC_MAX_HOOK_STACK_FRAMES 8

typedef struct _BLACKBIRD_IPC_HOOK_EVENT
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
    UINT64 Args[8];
    UINT32 StackCount;
    UINT32 CallerFlags; /* BLACKBIRD_HOOK_CALLER_FLAG_* | (ImmediateCaller kind << 4) | (DeepestOrigin kind << 8) */
    UINT64 Stack[BLACKBIRD_IPC_MAX_HOOK_STACK_FRAMES];
    CHAR ApiName[BLACKBIRD_IPC_MAX_HOOK_API_NAME];
    CHAR ModuleName[BLACKBIRD_IPC_MAX_HOOK_MODULE_NAME];
    UINT8 DataSample[BLACKBIRD_IPC_MAX_HOOK_DATA_SAMPLE];
} BLACKBIRD_IPC_HOOK_EVENT, *PBLACKBIRD_IPC_HOOK_EVENT;

typedef enum _BLACKBIRD_IPC_USER_HOOK_TARGET_MODE
{
    BlackbirdIpcUserHookTargetNone = 0,
    BlackbirdIpcUserHookTargetAttach = 1,
    BlackbirdIpcUserHookTargetLaunch = 2
} BLACKBIRD_IPC_USER_HOOK_TARGET_MODE;

#define BLACKBIRD_IPC_USER_HOOK_FLAG_LAUNCH_EARLYBIRD_APC 0x00000001u
#define BLACKBIRD_IPC_USER_HOOK_FLAG_DEFER_LAUNCH_GATE_RELEASE 0x00000002u
#define BLACKBIRD_IPC_MAX_LAUNCH_ENVIRONMENT_CHARS 4096

#define BLACKBIRD_IPC_HOOK_READY_FLAG_IPC_CONNECTED 0x00000001u
#define BLACKBIRD_IPC_HOOK_READY_FLAG_WINSOCK 0x00000002u
#define BLACKBIRD_IPC_HOOK_READY_FLAG_NT 0x00000004u
#define BLACKBIRD_IPC_HOOK_READY_FLAG_KI 0x00000008u
#define BLACKBIRD_IPC_HOOK_READY_FLAG_MODULE 0x00000010u
#define BLACKBIRD_IPC_HOOK_READY_REQUIRED_MASK                                             \
    (BLACKBIRD_IPC_HOOK_READY_FLAG_IPC_CONNECTED | BLACKBIRD_IPC_HOOK_READY_FLAG_WINSOCK | \
     BLACKBIRD_IPC_HOOK_READY_FLAG_NT | BLACKBIRD_IPC_HOOK_READY_FLAG_KI | BLACKBIRD_IPC_HOOK_READY_FLAG_MODULE)

// IntegrityLevel values for BLACKBIRD_IPC_SET_USER_HOOK_TARGET_REQUEST
#define BLACKBIRD_LAUNCH_INTEGRITY_DEFAULT 0u
#define BLACKBIRD_LAUNCH_INTEGRITY_UNTRUSTED 1u
#define BLACKBIRD_LAUNCH_INTEGRITY_LOW 2u
#define BLACKBIRD_LAUNCH_INTEGRITY_MEDIUM 3u
#define BLACKBIRD_LAUNCH_INTEGRITY_HIGH 4u
#define BLACKBIRD_LAUNCH_INTEGRITY_SYSTEM 5u

typedef struct _BLACKBIRD_IPC_SET_USER_HOOK_TARGET_REQUEST
{
    UINT32 Mode;
    UINT32 ProcessId;
    UINT32 Flags;
    UINT32 ParentProcessId;
    UINT32 PriorityClass;
    UINT32 InheritHandles;
    UINT32 IntegrityLevel;
    UINT64 AffinityMask;
    WCHAR ImagePath[BLACKBIRD_MAX_IMAGE_PATH_CHARS];
    WCHAR HookDllPath[BLACKBIRD_MAX_IMAGE_PATH_CHARS];
    WCHAR WorkingDirectory[BLACKBIRD_MAX_IMAGE_PATH_CHARS];
    WCHAR EnvironmentOverrides[BLACKBIRD_IPC_MAX_LAUNCH_ENVIRONMENT_CHARS];
} BLACKBIRD_IPC_SET_USER_HOOK_TARGET_REQUEST, *PBLACKBIRD_IPC_SET_USER_HOOK_TARGET_REQUEST;

typedef struct _BLACKBIRD_IPC_SET_USER_HOOK_TARGET_RESPONSE
{
    UINT32 ProcessId;
    INT32 Status;
    UINT32 Reserved0;
    UINT32 Reserved1;
    WCHAR ImagePath[BLACKBIRD_MAX_IMAGE_PATH_CHARS];
} BLACKBIRD_IPC_SET_USER_HOOK_TARGET_RESPONSE, *PBLACKBIRD_IPC_SET_USER_HOOK_TARGET_RESPONSE;

typedef struct _BLACKBIRD_IPC_NOTIFY_HOOK_READY_REQUEST
{
    UINT32 ProcessId;
    UINT32 ReadyMask;
    UINT32 Reserved0;
    UINT32 Reserved1;
} BLACKBIRD_IPC_NOTIFY_HOOK_READY_REQUEST, *PBLACKBIRD_IPC_NOTIFY_HOOK_READY_REQUEST;

typedef struct _BLACKBIRD_IPC_NOTIFY_HOOK_READY_RESPONSE
{
    UINT32 ProcessId;
    UINT32 ObservedMask;
    UINT32 RequiredMask;
    UINT32 Reserved;
} BLACKBIRD_IPC_NOTIFY_HOOK_READY_RESPONSE, *PBLACKBIRD_IPC_NOTIFY_HOOK_READY_RESPONSE;

typedef struct _BLACKBIRD_IPC_SHARED_RING_HEADER
{
    volatile LONG WriteIndex;
    volatile LONG ReadIndex;
    volatile LONG DroppedCount;
    LONG Reserved0;
    UINT32 Capacity;
    UINT32 RecordSize;
    UINT32 Reserved1;
    UINT32 Reserved2;
} BLACKBIRD_IPC_SHARED_RING_HEADER, *PBLACKBIRD_IPC_SHARED_RING_HEADER;

typedef enum _BLACKBIRD_IPC_ETW_SOURCE
{
    BlackbirdIpcEtwSourceUnknown = 0,
    BlackbirdIpcEtwSourceBlackbird = 1,
    BlackbirdIpcEtwSourceThreatIntel = 2,
    BlackbirdIpcEtwSourceKernelNetwork = 3,
    BlackbirdIpcEtwSourceUserHook = 4
} BLACKBIRD_IPC_ETW_SOURCE;

#define BLACKBIRD_IPC_MAX_ETW_EVENT_NAME 96
#define BLACKBIRD_IPC_MAX_ETW_DETECTION_NAME 128
#define BLACKBIRD_IPC_MAX_ETW_REASON 256
#define BLACKBIRD_IPC_MAX_ETW_SHORT_TEXT 64
#define BLACKBIRD_IPC_MAX_ETW_IMAGE_PATH 260
#define BLACKBIRD_IPC_MAX_ETW_COMMAND_LINE 512
#define BLACKBIRD_IPC_MAX_ETW_KEY_PATH 512
#define BLACKBIRD_IPC_MAX_ETW_VALUE_NAME 256
#define BLACKBIRD_IPC_MAX_ETW_STACK_FRAMES 8
#define BLACKBIRD_IPC_MAX_ETW_DEEP_SAMPLE 64
#define BLACKBIRD_IPC_MAX_HOOK_ARGS 8

typedef enum _BLACKBIRD_IPC_ETW_FAMILY
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
} BLACKBIRD_IPC_ETW_FAMILY;

#define BLACKBIRD_IPC_ETW_FLAG_HANDLE_EXEC_PROTECT 0x00000001u
#define BLACKBIRD_IPC_ETW_FLAG_HANDLE_FROM_NTDLL 0x00000002u
#define BLACKBIRD_IPC_ETW_FLAG_HANDLE_FROM_EXE 0x00000004u
#define BLACKBIRD_IPC_ETW_FLAG_THREAD_GOT_START 0x00000008u
#define BLACKBIRD_IPC_ETW_FLAG_THREAD_GOT_RANGE 0x00000010u
#define BLACKBIRD_IPC_ETW_FLAG_THREAD_REMOTE_CREATOR 0x00000020u
#define BLACKBIRD_IPC_ETW_FLAG_THREAD_OUTSIDE_MAIN_IMAGE 0x00000040u
#define BLACKBIRD_IPC_ETW_FLAG_PROCESS_IS_CREATE 0x00000080u
#define BLACKBIRD_IPC_ETW_FLAG_IMAGE_SYSTEM_MODE 0x00000100u
#define BLACKBIRD_IPC_ETW_FLAG_IMAGE_SIGNATURE_KNOWN 0x00000200u
#define BLACKBIRD_IPC_ETW_FLAG_REGISTRY_HIGH_VALUE 0x00000400u
#define BLACKBIRD_IPC_ETW_FLAG_APC_DUPLICATE_OPERATION 0x00000800u
/* Syscall origin / stack-integrity signals — mirror BLACKBIRD_HANDLE_FLAG_* at the same bit positions
   so a masked copy of BLACKBIRD_HANDLE_EVENT.Flags is a valid Flags value here. */
#define BLACKBIRD_IPC_ETW_FLAG_SYSCALL_EXPORT_MATCH 0x00001000u
#define BLACKBIRD_IPC_ETW_FLAG_SYSCALL_EXPORT_MISMATCH 0x00002000u
#define BLACKBIRD_IPC_ETW_FLAG_MODULE_CHAIN_SANE 0x00004000u
#define BLACKBIRD_IPC_ETW_FLAG_UNWIND_METADATA_VALID 0x00008000u
#define BLACKBIRD_IPC_ETW_FLAG_TEB_STACK_BOUNDS_VALID 0x00010000u
#define BLACKBIRD_IPC_ETW_FLAG_FRAMES_OUTSIDE_TEB_STACK 0x00020000u
/* Hook-event caller origin — set by the controller when mapping a BLACKBIRD_IPC_HOOK_EVENT
   to a BLACKBIRD_IPC_ETW_EVENT so the UI can classify / filter without separate ABI fields. */
#define BLACKBIRD_IPC_ETW_FLAG_HOOK_CALLER_ALL_SYSTEM 0x00040000u
#define BLACKBIRD_IPC_ETW_FLAG_HOOK_CALLER_HAS_UNMAPPED 0x00080000u
#define BLACKBIRD_IPC_ETW_FLAG_HOOK_CALLER_HAS_PROCESS_IMAGE 0x00100000u
#define BLACKBIRD_IPC_ETW_FLAG_HOOK_CALLER_HAS_NONSYSTEM_DLL 0x00200000u

/* Hook integrity operation codes — shared between the hook DLL and the controller so
   both sides agree without relying on matching magic numbers in separate translation units. */
#define BLACKBIRD_HOOK_EVENT_OP_HOOK_INTEGRITY 1u
#define BLACKBIRD_HOOK_EVENT_OP_AMSI_PATCH 2u
#define BLACKBIRD_HOOK_EVENT_OP_ETW_PATCH 3u

/* Caller-origin classification packed into BLACKBIRD_IPC_HOOK_EVENT.CallerFlags.
   SR71 classifies the captured call stack and encodes the result here so the
   controller and UI can filter noise without re-walking the frames.

   Bits [3:0]  — classification flags (BLACKBIRD_HOOK_CALLER_FLAG_*)
   Bits [7:4]  — ImmediateCaller kind (first non-own-module frame)
   Bits [11:8] — DeepestOrigin kind  (deepest non-system, non-own frame)
   CallerKind values used in both nibbles: BLACKBIRD_HOOK_CALLER_KIND_* */
#define BLACKBIRD_HOOK_CALLER_FLAG_ALL_SYSTEM 0x00000001u        /* every resolved frame is a system DLL  */
#define BLACKBIRD_HOOK_CALLER_FLAG_HAS_UNMAPPED 0x00000002u      /* at least one frame has no backing module */
#define BLACKBIRD_HOOK_CALLER_FLAG_HAS_PROCESS_IMAGE 0x00000004u /* at least one frame is in the .exe      */
#define BLACKBIRD_HOOK_CALLER_FLAG_HAS_NONSYSTEM_DLL 0x00000008u /* at least one frame is a non-system DLL */

#define BLACKBIRD_HOOK_CALLER_IMMED_SHIFT 4u
#define BLACKBIRD_HOOK_CALLER_IMMED_MASK 0x000000F0u
#define BLACKBIRD_HOOK_CALLER_DEEP_SHIFT 8u
#define BLACKBIRD_HOOK_CALLER_DEEP_MASK 0x00000F00u

#define BLACKBIRD_HOOK_CALLER_KIND_UNKNOWN 0u
#define BLACKBIRD_HOOK_CALLER_KIND_UNMAPPED 1u      /* IP has no backing module — shellcode / RWX region */
#define BLACKBIRD_HOOK_CALLER_KIND_SYSTEM_DLL 2u    /* Windows system DLL (System32 / SysWOW64)         */
#define BLACKBIRD_HOOK_CALLER_KIND_PROCESS_IMAGE 3u /* The monitored process .exe image                 */
#define BLACKBIRD_HOOK_CALLER_KIND_OWN_MODULE 4u    /* SR71 / hook-DLL infrastructure (excluded)        */
#define BLACKBIRD_HOOK_CALLER_KIND_NONSYSTEM_DLL 5u /* Loaded DLL that is not a Windows system DLL      */

typedef struct _BLACKBIRD_IPC_ETW_EVENT
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
    WCHAR EventName[BLACKBIRD_IPC_MAX_ETW_EVENT_NAME];
    CHAR DetectionName[BLACKBIRD_IPC_MAX_ETW_DETECTION_NAME];
    UINT32 CorrelationFlags;
    UINT32 CorrelationAccessMask;
    UINT32 CorrelationAgeMs;
    UINT32 Reserved2;
    WCHAR Reason[BLACKBIRD_IPC_MAX_ETW_REASON];
    CHAR ClassName[BLACKBIRD_IPC_MAX_ETW_SHORT_TEXT];
    CHAR Operation[BLACKBIRD_IPC_MAX_ETW_SHORT_TEXT];
    UINT32 DesiredAccess;
    UINT32 OriginProtect;
    UINT64 OriginAddress;
    INT32 StatusOpenProcess;
    INT32 StatusBasicInfo;
    INT32 StatusSectionName;
    UINT32 StackCount;
    UINT32 Reserved3;
    UINT64 Stack[BLACKBIRD_IPC_MAX_ETW_STACK_FRAMES];
    UINT64 DeepAllocationBase;
    UINT64 DeepRegionSize;
    UINT32 DeepRegionProtect;
    UINT32 DeepRegionState;
    UINT32 DeepRegionType;
    UINT32 DeepSampleSize;
    UINT8 DeepSample[BLACKBIRD_IPC_MAX_ETW_DEEP_SAMPLE];
    WCHAR OriginPath[BLACKBIRD_IPC_MAX_ETW_IMAGE_PATH];
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
    UINT64 HookArgs[BLACKBIRD_IPC_MAX_HOOK_ARGS];
    WCHAR ImagePath[BLACKBIRD_IPC_MAX_ETW_IMAGE_PATH];
    WCHAR CommandLine[BLACKBIRD_IPC_MAX_ETW_COMMAND_LINE];
    WCHAR KeyPath[BLACKBIRD_IPC_MAX_ETW_KEY_PATH];
    WCHAR ValueName[BLACKBIRD_IPC_MAX_ETW_VALUE_NAME];
} BLACKBIRD_IPC_ETW_EVENT, *PBLACKBIRD_IPC_ETW_EVENT;

typedef union _BLACKBIRD_IPC_PAYLOAD
{
    BLACKBIRD_IPC_HANDSHAKE_REQUEST HandshakeRequest;
    BLACKBIRD_IPC_HANDSHAKE_RESPONSE HandshakeResponse;
    BLACKBIRD_SUBSCRIBE_REQUEST SubscribeRequest;
    BLACKBIRD_UNSUBSCRIBE_REQUEST UnsubscribeRequest;
    BLACKBIRD_SET_PIDS_REQUEST SetPidsRequest;
    BLACKBIRD_IPC_GET_EVENT_REQUEST GetEventRequest;
    BLACKBIRD_IPC_OPEN_SHARED_RING_REQUEST OpenSharedRingRequest;
    BLACKBIRD_IPC_OPEN_SHARED_RING_RESPONSE OpenSharedRingResponse;
    BLACKBIRD_IPC_HOOK_EVENT HookEvent;
    BLACKBIRD_IPC_SET_USER_HOOK_TARGET_REQUEST SetUserHookTargetRequest;
    BLACKBIRD_IPC_SET_USER_HOOK_TARGET_RESPONSE SetUserHookTargetResponse;
    BLACKBIRD_IPC_NOTIFY_HOOK_READY_REQUEST NotifyHookReadyRequest;
    BLACKBIRD_IPC_NOTIFY_HOOK_READY_RESPONSE NotifyHookReadyResponse;
    BLACKBIRD_EVENT_RECORD EventRecord;
    BLACKBIRD_IPC_ETW_EVENT EtwEvent;
    BLACKBIRD_STATS_RESPONSE StatsResponse;
    BLACKBIRD_QUERY_PROCESS_IMAGE_REQUEST QueryProcessImageRequest;
    BLACKBIRD_QUERY_PROCESS_IMAGE_RESPONSE QueryProcessImageResponse;
    BLACKBIRD_CONTROL_EXECUTION_REQUEST ControlProcessExecutionRequest;
    BLACKBIRD_SET_RUNTIME_CONFIG_REQUEST SetRuntimeConfigRequest;
    BLACKBIRD_RUNTIME_CONFIG_RESPONSE RuntimeConfigResponse;
} BLACKBIRD_IPC_PAYLOAD, *PBLACKBIRD_IPC_PAYLOAD;

typedef struct _BLACKBIRD_IPC_PACKET
{
    UINT32 Magic;
    UINT16 Version;
    UINT16 PacketType;
    UINT32 Command;
    UINT32 Sequence;
    UINT32 Status;
    BLACKBIRD_IPC_PAYLOAD Payload;
} BLACKBIRD_IPC_PACKET, *PBLACKBIRD_IPC_PACKET;

#define BLACKBIRD_IPC_CAP_DRIVER_PROXY 0x00000001u
#define BLACKBIRD_IPC_CAP_ETW_TI_SESSION 0x00000002u
#define BLACKBIRD_IPC_CAP_ETW_TI_UPLINK 0x00000004u
#define BLACKBIRD_IPC_CAP_SHARED_RING 0x00000008u
#define BLACKBIRD_IPC_CAP_USER_HOOK_INGEST 0x00000010u
#define BLACKBIRD_IPC_CAP_USER_HOOK_READY 0x00000020u

#endif
