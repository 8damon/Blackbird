#ifndef SLEEPWALKER_IPC_H
#define SLEEPWALKER_IPC_H

#include "sleepwalker_ioctl.h"

#define SLEEPWALKER_IPC_PIPE_NAME L"\\\\.\\pipe\\SleepwlkrController"
#define SLEEPWALKER_IPC_MAGIC 0x53574B52u
#define SLEEPWALKER_IPC_VERSION 2u

typedef enum _SLEEPWALKER_IPC_PACKET_TYPE
{
    SleepwalkerIpcPacketInvalid = 0,
    SleepwalkerIpcPacketRequest = 1,
    SleepwalkerIpcPacketResponse = 2
} SLEEPWALKER_IPC_PACKET_TYPE;

typedef enum _SLEEPWALKER_IPC_COMMAND
{
    SleepwalkerIpcCommandNone = 0,
    SleepwalkerIpcCommandHandshake = 1,
    SleepwalkerIpcCommandSubscribe = 2,
    SleepwalkerIpcCommandUnsubscribe = 3,
    SleepwalkerIpcCommandSetPids = 4,
    SleepwalkerIpcCommandGetEvent = 5,
    SleepwalkerIpcCommandGetStats = 6,
    SleepwalkerIpcCommandQueryProcessImage = 7,
    SleepwalkerIpcCommandSetShutdownMode = 8,
    SleepwalkerIpcCommandGetEtwEvent = 9,
    SleepwalkerIpcCommandOpenSharedRing = 10
} SLEEPWALKER_IPC_COMMAND;

typedef struct _SLEEPWALKER_IPC_HANDSHAKE_REQUEST
{
    UINT32 RequestedVersion;
} SLEEPWALKER_IPC_HANDSHAKE_REQUEST, *PSLEEPWALKER_IPC_HANDSHAKE_REQUEST;

typedef struct _SLEEPWALKER_IPC_HANDSHAKE_RESPONSE
{
    UINT32 NegotiatedVersion;
    UINT32 Capabilities;
    UINT32 ThreatIntelEnabled;
    UINT32 Reserved;
} SLEEPWALKER_IPC_HANDSHAKE_RESPONSE, *PSLEEPWALKER_IPC_HANDSHAKE_RESPONSE;

typedef struct _SLEEPWALKER_IPC_GET_EVENT_REQUEST
{
    UINT32 TimeoutMs;
} SLEEPWALKER_IPC_GET_EVENT_REQUEST, *PSLEEPWALKER_IPC_GET_EVENT_REQUEST;

typedef struct _SLEEPWALKER_IPC_OPEN_SHARED_RING_REQUEST
{
    UINT32 DesiredIoctlCapacity;
    UINT32 DesiredEtwCapacity;
} SLEEPWALKER_IPC_OPEN_SHARED_RING_REQUEST, *PSLEEPWALKER_IPC_OPEN_SHARED_RING_REQUEST;

typedef struct _SLEEPWALKER_IPC_OPEN_SHARED_RING_RESPONSE
{
    UINT64 IoctlMappingHandle;
    UINT64 IoctlDataReadyEventHandle;
    UINT32 IoctlCapacity;
    UINT32 IoctlRecordSize;
    UINT64 EtwMappingHandle;
    UINT64 EtwDataReadyEventHandle;
    UINT32 EtwCapacity;
    UINT32 EtwRecordSize;
} SLEEPWALKER_IPC_OPEN_SHARED_RING_RESPONSE, *PSLEEPWALKER_IPC_OPEN_SHARED_RING_RESPONSE;

typedef struct _SLEEPWALKER_IPC_SHARED_RING_HEADER
{
    volatile LONG WriteIndex;
    volatile LONG ReadIndex;
    volatile LONG DroppedCount;
    LONG Reserved0;
    UINT32 Capacity;
    UINT32 RecordSize;
    UINT32 Reserved1;
    UINT32 Reserved2;
} SLEEPWALKER_IPC_SHARED_RING_HEADER, *PSLEEPWALKER_IPC_SHARED_RING_HEADER;

typedef enum _SLEEPWALKER_IPC_ETW_SOURCE
{
    SleepwalkerIpcEtwSourceUnknown = 0,
    SleepwalkerIpcEtwSourceSleepwalker = 1,
    SleepwalkerIpcEtwSourceThreatIntel = 2,
    SleepwalkerIpcEtwSourceKernelNetwork = 3
} SLEEPWALKER_IPC_ETW_SOURCE;

#define SLEEPWALKER_IPC_MAX_ETW_EVENT_NAME 96
#define SLEEPWALKER_IPC_MAX_ETW_DETECTION_NAME 128
#define SLEEPWALKER_IPC_MAX_ETW_REASON 256
#define SLEEPWALKER_IPC_MAX_ETW_SHORT_TEXT 64
#define SLEEPWALKER_IPC_MAX_ETW_IMAGE_PATH 260
#define SLEEPWALKER_IPC_MAX_ETW_COMMAND_LINE 512
#define SLEEPWALKER_IPC_MAX_ETW_KEY_PATH 512
#define SLEEPWALKER_IPC_MAX_ETW_VALUE_NAME 256
#define SLEEPWALKER_IPC_MAX_ETW_STACK_FRAMES 8
#define SLEEPWALKER_IPC_MAX_ETW_DEEP_SAMPLE 64

typedef enum _SLEEPWALKER_IPC_ETW_FAMILY
{
    SleepwalkerIpcEtwFamilyUnknown = 0,
    SleepwalkerIpcEtwFamilyHandle = 1,
    SleepwalkerIpcEtwFamilyThread = 2,
    SleepwalkerIpcEtwFamilyProcess = 3,
    SleepwalkerIpcEtwFamilyImage = 4,
    SleepwalkerIpcEtwFamilyRegistry = 5,
    SleepwalkerIpcEtwFamilyApc = 6,
    SleepwalkerIpcEtwFamilyDetection = 7,
    SleepwalkerIpcEtwFamilyThreatIntel = 8,
    SleepwalkerIpcEtwFamilySocket = 9
} SLEEPWALKER_IPC_ETW_FAMILY;

#define SLEEPWALKER_IPC_ETW_FLAG_HANDLE_EXEC_PROTECT 0x00000001u
#define SLEEPWALKER_IPC_ETW_FLAG_HANDLE_FROM_NTDLL 0x00000002u
#define SLEEPWALKER_IPC_ETW_FLAG_HANDLE_FROM_EXE 0x00000004u
#define SLEEPWALKER_IPC_ETW_FLAG_THREAD_GOT_START 0x00000008u
#define SLEEPWALKER_IPC_ETW_FLAG_THREAD_GOT_RANGE 0x00000010u
#define SLEEPWALKER_IPC_ETW_FLAG_THREAD_REMOTE_CREATOR 0x00000020u
#define SLEEPWALKER_IPC_ETW_FLAG_THREAD_OUTSIDE_MAIN_IMAGE 0x00000040u
#define SLEEPWALKER_IPC_ETW_FLAG_PROCESS_IS_CREATE 0x00000080u
#define SLEEPWALKER_IPC_ETW_FLAG_IMAGE_SYSTEM_MODE 0x00000100u
#define SLEEPWALKER_IPC_ETW_FLAG_IMAGE_SIGNATURE_KNOWN 0x00000200u
#define SLEEPWALKER_IPC_ETW_FLAG_REGISTRY_HIGH_VALUE 0x00000400u
#define SLEEPWALKER_IPC_ETW_FLAG_APC_DUPLICATE_OPERATION 0x00000800u

typedef struct _SLEEPWALKER_IPC_ETW_EVENT
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
    WCHAR EventName[SLEEPWALKER_IPC_MAX_ETW_EVENT_NAME];
    CHAR DetectionName[SLEEPWALKER_IPC_MAX_ETW_DETECTION_NAME];
    UINT32 CorrelationFlags;
    UINT32 CorrelationAccessMask;
    UINT32 CorrelationAgeMs;
    UINT32 Reserved2;
    WCHAR Reason[SLEEPWALKER_IPC_MAX_ETW_REASON];
    CHAR ClassName[SLEEPWALKER_IPC_MAX_ETW_SHORT_TEXT];
    CHAR Operation[SLEEPWALKER_IPC_MAX_ETW_SHORT_TEXT];
    UINT32 DesiredAccess;
    UINT32 OriginProtect;
    UINT64 OriginAddress;
    INT32 StatusOpenProcess;
    INT32 StatusBasicInfo;
    INT32 StatusSectionName;
    UINT32 StackCount;
    UINT32 Reserved3;
    UINT64 Stack[SLEEPWALKER_IPC_MAX_ETW_STACK_FRAMES];
    UINT64 DeepAllocationBase;
    UINT64 DeepRegionSize;
    UINT32 DeepRegionProtect;
    UINT32 DeepRegionState;
    UINT32 DeepRegionType;
    UINT32 DeepSampleSize;
    UINT8 DeepSample[SLEEPWALKER_IPC_MAX_ETW_DEEP_SAMPLE];
    WCHAR OriginPath[SLEEPWALKER_IPC_MAX_ETW_IMAGE_PATH];
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
    WCHAR ImagePath[SLEEPWALKER_IPC_MAX_ETW_IMAGE_PATH];
    WCHAR CommandLine[SLEEPWALKER_IPC_MAX_ETW_COMMAND_LINE];
    WCHAR KeyPath[SLEEPWALKER_IPC_MAX_ETW_KEY_PATH];
    WCHAR ValueName[SLEEPWALKER_IPC_MAX_ETW_VALUE_NAME];
} SLEEPWALKER_IPC_ETW_EVENT, *PSLEEPWALKER_IPC_ETW_EVENT;

typedef union _SLEEPWALKER_IPC_PAYLOAD
{
    SLEEPWALKER_IPC_HANDSHAKE_REQUEST HandshakeRequest;
    SLEEPWALKER_IPC_HANDSHAKE_RESPONSE HandshakeResponse;
    SLEEPWALKER_SUBSCRIBE_REQUEST SubscribeRequest;
    SLEEPWALKER_UNSUBSCRIBE_REQUEST UnsubscribeRequest;
    SLEEPWALKER_SET_PIDS_REQUEST SetPidsRequest;
    SLEEPWALKER_IPC_GET_EVENT_REQUEST GetEventRequest;
    SLEEPWALKER_IPC_OPEN_SHARED_RING_REQUEST OpenSharedRingRequest;
    SLEEPWALKER_IPC_OPEN_SHARED_RING_RESPONSE OpenSharedRingResponse;
    SLEEPWALKER_EVENT_RECORD EventRecord;
    SLEEPWALKER_IPC_ETW_EVENT EtwEvent;
    SLEEPWALKER_STATS_RESPONSE StatsResponse;
    SLEEPWALKER_QUERY_PROCESS_IMAGE_REQUEST QueryProcessImageRequest;
    SLEEPWALKER_QUERY_PROCESS_IMAGE_RESPONSE QueryProcessImageResponse;
} SLEEPWALKER_IPC_PAYLOAD, *PSLEEPWALKER_IPC_PAYLOAD;

typedef struct _SLEEPWALKER_IPC_PACKET
{
    UINT32 Magic;
    UINT16 Version;
    UINT16 PacketType;
    UINT32 Command;
    UINT32 Sequence;
    UINT32 Status;
    SLEEPWALKER_IPC_PAYLOAD Payload;
} SLEEPWALKER_IPC_PACKET, *PSLEEPWALKER_IPC_PACKET;

#define SLEEPWALKER_IPC_CAP_DRIVER_PROXY 0x00000001u
#define SLEEPWALKER_IPC_CAP_ETW_TI_SESSION 0x00000002u
#define SLEEPWALKER_IPC_CAP_ETW_TI_UPLINK 0x00000004u
#define SLEEPWALKER_IPC_CAP_SHARED_RING 0x00000008u

#endif
