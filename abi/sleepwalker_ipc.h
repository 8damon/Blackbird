#ifndef SLEEPWALKER_IPC_H
#define SLEEPWALKER_IPC_H

#include "sleepwalker_ioctl.h"

#define SLEEPWALKER_IPC_PIPE_NAME L"\\\\.\\pipe\\SleepwlkrController"
#define SLEEPWALKER_IPC_MAGIC 0x53574B52u
#define SLEEPWALKER_IPC_VERSION 1u

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
    SleepwalkerIpcCommandGetEtwEvent = 9
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

typedef enum _SLEEPWALKER_IPC_ETW_SOURCE
{
    SleepwalkerIpcEtwSourceUnknown = 0,
    SleepwalkerIpcEtwSourceSleepwalker = 1,
    SleepwalkerIpcEtwSourceThreatIntel = 2
} SLEEPWALKER_IPC_ETW_SOURCE;

#define SLEEPWALKER_IPC_MAX_ETW_EVENT_NAME 96
#define SLEEPWALKER_IPC_MAX_ETW_DETECTION_NAME 128

typedef struct _SLEEPWALKER_IPC_ETW_EVENT
{
    UINT32 Source;
    UINT16 EventId;
    UINT16 Opcode;
    UINT16 Task;
    UINT16 Reserved0;
    UINT32 EventProcessId;
    UINT32 EventThreadId;
    UINT32 Severity;
    UINT32 Reserved1;
    UINT64 PrimaryPid;
    UINT64 SecondaryPid;
    WCHAR EventName[SLEEPWALKER_IPC_MAX_ETW_EVENT_NAME];
    CHAR DetectionName[SLEEPWALKER_IPC_MAX_ETW_DETECTION_NAME];
} SLEEPWALKER_IPC_ETW_EVENT, *PSLEEPWALKER_IPC_ETW_EVENT;

typedef union _SLEEPWALKER_IPC_PAYLOAD
{
    SLEEPWALKER_IPC_HANDSHAKE_REQUEST HandshakeRequest;
    SLEEPWALKER_IPC_HANDSHAKE_RESPONSE HandshakeResponse;
    SLEEPWALKER_SUBSCRIBE_REQUEST SubscribeRequest;
    SLEEPWALKER_UNSUBSCRIBE_REQUEST UnsubscribeRequest;
    SLEEPWALKER_SET_PIDS_REQUEST SetPidsRequest;
    SLEEPWALKER_IPC_GET_EVENT_REQUEST GetEventRequest;
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

#endif
