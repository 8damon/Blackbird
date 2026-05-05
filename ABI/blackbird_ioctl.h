#ifndef BK_IOCTL_H
#define BK_IOCTL_H

#include <basetsd.h>

#ifndef CTL_CODE
#include <winioctl.h>
#endif

#define FILE_DEVICE_BK 0x00008337

#define IOCTL_BK_SUBSCRIBE CTL_CODE(FILE_DEVICE_BK, 0x801, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_BK_UNSUBSCRIBE CTL_CODE(FILE_DEVICE_BK, 0x802, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_BK_GET_EVENT CTL_CODE(FILE_DEVICE_BK, 0x803, METHOD_BUFFERED, FILE_READ_DATA)
#define IOCTL_BK_GET_STATS CTL_CODE(FILE_DEVICE_BK, 0x804, METHOD_BUFFERED, FILE_READ_DATA)
#define IOCTL_BK_SET_PIDS CTL_CODE(FILE_DEVICE_BK, 0x805, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_BK_QUERY_PROCESS_IMAGE CTL_CODE(FILE_DEVICE_BK, 0x806, METHOD_BUFFERED, FILE_READ_DATA)
#define IOCTL_BK_SET_SHUTDOWN_MODE CTL_CODE(FILE_DEVICE_BK, 0x807, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_BK_GET_HEALTH CTL_CODE(FILE_DEVICE_BK, 0x808, METHOD_BUFFERED, FILE_READ_DATA)
#define IOCTL_BK_ARM_PENDING_LAUNCH CTL_CODE(FILE_DEVICE_BK, 0x809, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_BK_CONTROL_EXECUTION CTL_CODE(FILE_DEVICE_BK, 0x80A, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_BK_SET_RUNTIME_CONFIG CTL_CODE(FILE_DEVICE_BK, 0x80B, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_BK_GET_RUNTIME_CONFIG CTL_CODE(FILE_DEVICE_BK, 0x80C, METHOD_BUFFERED, FILE_READ_DATA)
#define IOCTL_BK_GET_DIAGNOSTICS CTL_CODE(FILE_DEVICE_BK, 0x80D, METHOD_BUFFERED, FILE_READ_DATA)
#define IOCTL_BK_MARK_CONTROLLER_READY CTL_CODE(FILE_DEVICE_BK, 0x80E, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_BK_READ_MEMORY CTL_CODE(FILE_DEVICE_BK, 0x80F, METHOD_BUFFERED, FILE_READ_DATA)
#define IOCTL_BK_REGISTER_INSTRUMENTATION_RANGE CTL_CODE(FILE_DEVICE_BK, 0x810, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_BK_REGISTER_HOOK_PATCH CTL_CODE(FILE_DEVICE_BK, 0x811, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_BK_SET_ENDPOINT_GUARD CTL_CODE(FILE_DEVICE_BK, 0x812, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_BK_SET_QPC_TIMING_CONFIG CTL_CODE(FILE_DEVICE_BK, 0x813, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_BK_GET_QPC_TIMING_STATE CTL_CODE(FILE_DEVICE_BK, 0x814, METHOD_BUFFERED, FILE_READ_DATA)

#define BK_STREAM_HANDLE 0x00000001
#define BK_STREAM_MEMORY 0x00000002
#define BK_STREAM_THREAD 0x00000004
#define BK_STREAM_FILESYSTEM 0x00000008
#define BK_STREAM_REGISTRY 0x00000010
#define BK_STREAM_TIMING 0x00000020
#define BK_STREAM_ENTERPRISE 0x00000040

#define BK_MAX_MEMORY_READ_BYTES 4096
#define BK_INSTRUMENTATION_RANGE_TAG_CHARS 48
#define BK_HOOK_PATCH_TAG_CHARS 48
#define BK_MAX_HOOK_PATCH_BYTES 16

#define BK_MAX_EVENT_FRAMES 8
#define BK_MAX_FULL_EVENT_FRAMES 32
#define BK_MAX_PID_LIST 4096
#define BK_MAX_IMAGE_PATH_CHARS 1024
#define BK_MAX_DEEP_SAMPLE_BYTES 64
#define BK_MAX_STACK_SNAPSHOT_BYTES 256
#define BK_MAX_FILE_PATH_CHARS 520
#define BK_TEMPUS_SUBSYSTEM_COUNT 14
#define BK_DIAGNOSTIC_MAX_EVENTS 64
#define BK_DIAGNOSTIC_SCHEMA_VERSION 2u
#define BK_DIAGNOSTIC_MAX_COMPONENT_STATES 32
#define BK_DIAGNOSTIC_MAX_NTAPI_HOOK_STATES 64
#define BK_DIAGNOSTIC_MAX_SANITIZER_STATES 32
typedef enum _BK_EVENT_TYPE
{
    BlackbirdEventTypeNone = 0,
    BlackbirdEventTypeHandle = 1,
    BlackbirdEventTypeThread = 2,
    BlackbirdEventTypeFileSystem = 3,
    BlackbirdEventTypeRegistry = 4,
    BlackbirdEventTypeEnterprise = 5
} BK_EVENT_TYPE;

typedef enum _BK_ENTERPRISE_OPERATION
{
    BkEnterpriseOperationUnknown = 0,
    BkEnterpriseOperationProcessCredentialAccess = 1,
    BkEnterpriseOperationProcessPrivilegedAccess = 2,
    BkEnterpriseOperationTokenAccess = 3,
    BkEnterpriseOperationRegistryCredentialHiveAccess = 4,
    BkEnterpriseOperationRegistryLsaPolicyAccess = 5,
    BkEnterpriseOperationRegistryKerberosNtlmAccess = 6,
    BkEnterpriseOperationRegistryServiceConfigAccess = 7,
    BkEnterpriseOperationRegistryLpePersistenceAccess = 8,
    BkEnterpriseOperationFileCredentialStoreAccess = 9,
    BkEnterpriseOperationFileDirectoryCredentialAccess = 10,
    BkEnterpriseOperationFileDriverArtifactAccess = 11,
    BkEnterpriseOperationNetworkAdProtocolConnect = 12
} BK_ENTERPRISE_OPERATION;

#define BK_ENTERPRISE_FLAG_HIGH_SIGNAL 0x00000001u
#define BK_ENTERPRISE_FLAG_CRITICAL 0x00000002u
#define BK_ENTERPRISE_FLAG_QUERY 0x00000004u
#define BK_ENTERPRISE_FLAG_WRITE 0x00000008u
#define BK_ENTERPRISE_FLAG_CREATE 0x00000010u
#define BK_ENTERPRISE_FLAG_DELETE 0x00000020u
#define BK_ENTERPRISE_FLAG_DUPLICATE_HANDLE 0x00000040u
#define BK_ENTERPRISE_FLAG_PROCESS_OBJECT 0x00000080u
#define BK_ENTERPRISE_FLAG_THREAD_OBJECT 0x00000100u
#define BK_ENTERPRISE_FLAG_VM_READ 0x00000200u
#define BK_ENTERPRISE_FLAG_VM_WRITE 0x00000400u
#define BK_ENTERPRISE_FLAG_VM_OPERATION 0x00000800u
#define BK_ENTERPRISE_FLAG_CREATE_THREAD 0x00001000u
#define BK_ENTERPRISE_FLAG_CREDENTIAL_PROCESS 0x00002000u
#define BK_ENTERPRISE_FLAG_PRIVILEGED_TARGET 0x00004000u
#define BK_ENTERPRISE_FLAG_LSASS_TARGET 0x00008000u
#define BK_ENTERPRISE_FLAG_WINLOGON_TARGET 0x00010000u
#define BK_ENTERPRISE_FLAG_SERVICE_CONFIG 0x00020000u
#define BK_ENTERPRISE_FLAG_SECURITY_HIVE 0x00040000u
#define BK_ENTERPRISE_FLAG_LSA_POLICY 0x00080000u
#define BK_ENTERPRISE_FLAG_KERBEROS_NTLM 0x00100000u
#define BK_ENTERPRISE_FLAG_CREDENTIAL_FILE 0x00200000u
#define BK_ENTERPRISE_FLAG_DRIVER_ARTIFACT 0x00400000u
#define BK_ENTERPRISE_FLAG_AD_NETWORK 0x00800000u
#define BK_ENTERPRISE_FLAG_DIRECT_SYSCALL_SUSPECT 0x01000000u
#define BK_ENTERPRISE_FLAG_QUERY_ACCESS 0x02000000u
#define BK_ENTERPRISE_FLAG_THREAD_CONTEXT 0x04000000u
#define BK_ENTERPRISE_FLAG_SET_OR_TERMINATE 0x08000000u

#define BK_ENTERPRISE_PRODUCER_HANDLE 0x00000001u
#define BK_ENTERPRISE_PRODUCER_REGISTRY 0x00000002u
#define BK_ENTERPRISE_PRODUCER_FILESYSTEM 0x00000004u
#define BK_ENTERPRISE_PRODUCER_WFP_AD 0x00000008u

typedef struct _BK_ENTERPRISE_EVENT
{
    UINT64 ProcessId;
    UINT64 ThreadId;
    UINT64 TargetProcessId;
    UINT64 TargetThreadId;
    UINT64 ObjectAddress;
    UINT64 Aux0;
    UINT64 Aux1;
    UINT32 Operation;
    UINT32 SubOperation;
    UINT32 Flags;
    UINT32 DesiredAccess;
    UINT32 GrantedAccess;
    UINT32 Status;
    UINT32 Protocol;
    UINT32 LocalPort;
    UINT32 RemotePort;
    UINT32 Reserved;
} BK_ENTERPRISE_EVENT, *PBK_ENTERPRISE_EVENT;

typedef enum _BK_REGISTRY_OPERATION
{
    BkavRegOperationUnknown = 0,
    BkavRegOperationQueryValue = 1,
    BkavRegOperationQueryKey = 2,
    BkavRegOperationEnumerateKey = 3,
    BkavRegOperationEnumerateValue = 4,
    BkavRegOperationSetValue = 5,
    BkavRegOperationCreateKey = 6,
    BkavRegOperationOpenKey = 7,
    BkavRegOperationDeleteValue = 8,
    BkavRegOperationDeleteKey = 9
} BK_REGISTRY_OPERATION;

#define BK_REGISTRY_FLAG_HIGH_VALUE_PATH 0x00000001
#define BK_REGISTRY_FLAG_SENSITIVE_QUERY 0x00000002

typedef struct _BK_REGISTRY_EVENT
{
    UINT64 ProcessId;
    UINT64 ThreadId;
    UINT32 Operation;
    UINT32 NotifyClass;
    UINT32 DataType;
    UINT32 DataSize;
    UINT32 Flags;
    UINT32 SessionId;
    WCHAR KeyPath[512];
    WCHAR ValueName[128];
} BK_REGISTRY_EVENT, *PBK_REGISTRY_EVENT;

typedef enum _BK_FILE_OPERATION
{
    BlackbirdFileOperationUnknown = 0,
    BlackbirdFileOperationCreate = 1,
    BlackbirdFileOperationRead = 2,
    BlackbirdFileOperationWrite = 3,
    BlackbirdFileOperationClose = 4,
    BlackbirdFileOperationCleanup = 5,
    BlackbirdFileOperationSetInformation = 6,
    BlackbirdFileOperationQueryInformation = 7,
    BlackbirdFileOperationDirectoryControl = 8,
    BlackbirdFileOperationFsControl = 9
} BK_FILE_OPERATION;

typedef enum _BK_HANDLE_CLASS
{
    BlackbirdHandleClassUnknown = 0,
    BlackbirdHandleClassLegitimateSyscall = 1,
    BlackbirdHandleClassDirectSyscallSuspect = 2
} BK_HANDLE_CLASS;

typedef struct _BK_READ_MEMORY_REQUEST
{
    UINT32 ProcessId;
    UINT32 Reserved;
    UINT64 BaseAddress;
    UINT32 Size;
    UINT32 Reserved2;
} BK_READ_MEMORY_REQUEST, *PBK_READ_MEMORY_REQUEST;

typedef struct _BK_READ_MEMORY_RESPONSE
{
    UINT32 ProcessId;
    INT32 Status;
    UINT32 BytesRead;
    UINT32 Reserved;
    UINT8 Data[BK_MAX_MEMORY_READ_BYTES];
} BK_READ_MEMORY_RESPONSE, *PBK_READ_MEMORY_RESPONSE;

typedef struct _BK_REGISTER_INSTRUMENTATION_RANGE_REQUEST
{
    UINT32 ProcessId;
    UINT32 Flags;
    UINT64 BaseAddress;
    UINT64 RegionSize;
    CHAR Tag[BK_INSTRUMENTATION_RANGE_TAG_CHARS];
} BK_REGISTER_INSTRUMENTATION_RANGE_REQUEST, *PBK_REGISTER_INSTRUMENTATION_RANGE_REQUEST;

typedef struct _BK_REGISTER_HOOK_PATCH_REQUEST
{
    UINT32 ProcessId;
    UINT32 Flags;
    UINT64 PatchAddress;
    UINT32 PatchSize;
    UINT32 OriginalSize;
    UINT8 OriginalBytes[BK_MAX_HOOK_PATCH_BYTES];
    CHAR Tag[BK_HOOK_PATCH_TAG_CHARS];
} BK_REGISTER_HOOK_PATCH_REQUEST, *PBK_REGISTER_HOOK_PATCH_REQUEST;

typedef struct _BK_SUBSCRIBE_REQUEST
{
    UINT32 ProcessId;
    UINT32 StreamMask;
} BK_SUBSCRIBE_REQUEST, *PBK_SUBSCRIBE_REQUEST;

typedef struct _BK_UNSUBSCRIBE_REQUEST
{
    UINT32 ProcessId;
} BK_UNSUBSCRIBE_REQUEST, *PBK_UNSUBSCRIBE_REQUEST;

typedef struct _BK_GET_EVENT_REQUEST
{
    UINT32 TimeoutMs;
} BK_GET_EVENT_REQUEST, *PBK_GET_EVENT_REQUEST;

typedef struct _BK_SET_PIDS_REQUEST
{
    UINT32 StreamMask;
    UINT32 ProcessCount;
    UINT32 ProcessIds[BK_MAX_PID_LIST];
} BK_SET_PIDS_REQUEST, *PBK_SET_PIDS_REQUEST;

#define BK_PENDING_LAUNCH_FLAG_CLEAR 0x00000001u

#define BK_RUNTIME_FLAG_ANTI_VIRTUALIZATION 0x00000001u
#define BK_RUNTIME_FLAG_SELF_HIDE 0x00000002u
#define BK_RUNTIME_FLAG_INTERFACE_PROTECTED_ACCESS 0x00000004u
#define BK_RUNTIME_FLAG_CONTROLLER_PROTECTED_ACCESS 0x00000008u
#define BK_RUNTIME_FLAG_NTAPI_HOOKS_DISARMED 0x00000010u
#define BK_RUNTIME_FLAG_QPC_TIMING_DISABLED 0x00000020u
typedef enum _BK_RUNTIME_MODE
{
    BK_RUNTIME_MODE_LOITER = 0,
    BK_RUNTIME_MODE_GUIDED = 1
} BK_RUNTIME_MODE;

typedef struct _BK_SET_RUNTIME_CONFIG_REQUEST
{
    UINT32 Flags;
    UINT32 Mask;
} BK_SET_RUNTIME_CONFIG_REQUEST, *PBK_SET_RUNTIME_CONFIG_REQUEST;

typedef struct _BK_RUNTIME_CONFIG_RESPONSE
{
    UINT32 PersistentFlags;
    UINT32 RuntimeFlags;
    UINT32 EffectiveFlags;
    UINT32 Mode;
} BK_RUNTIME_CONFIG_RESPONSE, *PBK_RUNTIME_CONFIG_RESPONSE;

#define BK_QPC_TIMING_CONFIG_FLAG_ENABLED 0x00000001u
#define BK_QPC_TIMING_CONFIG_FLAG_MANUAL_BIAS 0x00000002u
#define BK_QPC_TIMING_SOURCE_BLACKBIRD_OVERHEAD 0x00000001u
#define BK_QPC_TIMING_SOURCE_AUTO_BIAS 0x00000002u
#define BK_QPC_TIMING_SOURCE_MANUAL_BIAS 0x00000004u
#define BK_QPC_TIMING_SOURCE_SUSPEND_PAUSE 0x00000008u
#define BK_QPC_TIMING_SOURCE_MONOTONIC_CLAMP 0x00000010u
#define BK_QPC_TIMING_SOURCE_PAIR_MATCH 0x00000020u
#define BK_QPC_TIMING_SOURCE_TIGHT_PAIR_CLAMP 0x00000040u

typedef struct _BK_QPC_TIMING_CONFIG
{
    UINT32 Flags;
    UINT32 Mask;
    UINT32 PairWindowMs;
    UINT32 MaxCorrectionUs;
    INT64 ManualBiasTicks;
} BK_QPC_TIMING_CONFIG, *PBK_QPC_TIMING_CONFIG;

typedef struct _BK_QPC_TIMING_STATE
{
    UINT32 Flags;
    UINT32 PairWindowMs;
    UINT32 MaxCorrectionUs;
    UINT32 ActiveThreadSlots;
    INT64 ManualBiasTicks;
    INT64 AutoBiasTicks;
    UINT64 Frequency;
    UINT64 QueryCount;
    UINT64 PairCount;
    UINT64 CorrectedCount;
    UINT64 TotalCorrectionTicks;
    UINT64 PauseCorrectionTicks;
    UINT64 LastCorrectionTicks;
} BK_QPC_TIMING_STATE, *PBK_QPC_TIMING_STATE;

typedef enum _BK_ANALYSIS_SUBJECT_KIND
{
    BlackbirdAnalysisSubjectProcess = 0,
    BlackbirdAnalysisSubjectDll = 1
} BK_ANALYSIS_SUBJECT_KIND;

typedef struct _BK_ARM_PENDING_LAUNCH_REQUEST
{
    UINT32 StreamMask;
    UINT32 Flags;
    UINT32 AnalysisSubjectKind;
    UINT32 Reserved0;
    WCHAR ImagePathNormDos[BK_MAX_IMAGE_PATH_CHARS];
    WCHAR ImagePathNormNt[BK_MAX_IMAGE_PATH_CHARS];
    WCHAR ImagePathTail[BK_MAX_IMAGE_PATH_CHARS];
    WCHAR AnalysisSubjectNormDos[BK_MAX_IMAGE_PATH_CHARS];
    WCHAR AnalysisSubjectNormNt[BK_MAX_IMAGE_PATH_CHARS];
    WCHAR AnalysisSubjectTail[BK_MAX_IMAGE_PATH_CHARS];
} BK_ARM_PENDING_LAUNCH_REQUEST, *PBK_ARM_PENDING_LAUNCH_REQUEST;

typedef struct _BK_QUERY_PROCESS_IMAGE_REQUEST
{
    UINT32 ProcessId;
} BK_QUERY_PROCESS_IMAGE_REQUEST, *PBK_QUERY_PROCESS_IMAGE_REQUEST;

typedef struct _BK_CONTROL_EXECUTION_REQUEST
{
    UINT32 ProcessId;
    UINT32 Suspend; /* 1 = suspend, 0 = resume */
} BK_CONTROL_EXECUTION_REQUEST, *PBK_CONTROL_EXECUTION_REQUEST;

typedef struct _BK_MARK_CONTROLLER_READY_REQUEST
{
    UINT32 ProcessId;
    UINT32 Reserved;
} BK_MARK_CONTROLLER_READY_REQUEST, *PBK_MARK_CONTROLLER_READY_REQUEST;

typedef struct _BK_QUERY_PROCESS_IMAGE_RESPONSE
{
    UINT32 ProcessId;
    INT32 Status;
    WCHAR ImagePath[BK_MAX_IMAGE_PATH_CHARS];
} BK_QUERY_PROCESS_IMAGE_RESPONSE, *PBK_QUERY_PROCESS_IMAGE_RESPONSE;

typedef struct _BK_EVENT_HEADER
{
    UINT32 Size;
    UINT32 Type;
    UINT32 StreamMask;
    UINT32 Sequence;
    INT64 TimestampQpc;
} BK_EVENT_HEADER, *PBK_EVENT_HEADER;

typedef struct _BK_HANDLE_EVENT
{
    UINT64 CallerPid;
    UINT64 TargetPid;
    UINT32 DesiredAccess;
    UINT32 ClassId;
    UINT64 OriginAddress;
    UINT32 OriginProtect;
    UINT32 Flags;
    UINT32 FrameCount;
    UINT64 Frames[BK_MAX_EVENT_FRAMES];
    INT32 StatusOpenProcess;
    INT32 StatusBasicInfo;
    INT32 StatusSectionName;
    UINT64 DeepAllocationBase;
    UINT64 DeepRegionSize;
    UINT32 DeepRegionProtect;
    UINT32 DeepRegionState;
    UINT32 DeepRegionType;
    UINT32 DeepSampleSize;
    UINT8 DeepSample[BK_MAX_DEEP_SAMPLE_BYTES];
    WCHAR OriginPath[260];
    UINT32 CaptureFlags;
    UINT32 FullFrameCount;
    UINT64 FullFrames[BK_MAX_FULL_EVENT_FRAMES];
    UINT64 RegRax;
    UINT64 RegRbx;
    UINT64 RegRcx;
    UINT64 RegRdx;
    UINT64 RegRsi;
    UINT64 RegRdi;
    UINT64 RegRbp;
    UINT64 RegRsp;
    UINT64 RegR8;
    UINT64 RegR9;
    UINT64 RegR10;
    UINT64 RegR11;
    UINT64 RegR12;
    UINT64 RegR13;
    UINT64 RegR14;
    UINT64 RegR15;
    UINT64 RegRip;
    UINT64 RegEFlags;
    UINT64 RegDr0;
    UINT64 RegDr1;
    UINT64 RegDr2;
    UINT64 RegDr3;
    UINT64 RegDr6;
    UINT64 RegDr7;
    UINT64 StackSnapshotAddress;
    UINT32 StackSnapshotSize;
    UINT8 StackSnapshot[BK_MAX_STACK_SNAPSHOT_BYTES];
} BK_HANDLE_EVENT, *PBK_HANDLE_EVENT;

typedef struct _BK_THREAD_EVENT
{
    UINT64 ProcessId;
    UINT64 ThreadId;
    UINT64 CreatorPid;
    UINT64 StartAddress;
    UINT64 ImageBase;
    UINT64 ImageSize;
    UINT32 Flags;
    UINT32 FrameCount;
    UINT64 Frames[BK_MAX_EVENT_FRAMES];
} BK_THREAD_EVENT, *PBK_THREAD_EVENT;

typedef struct _BK_FILE_EVENT
{
    UINT64 ProcessId;
    UINT64 ThreadId;
    UINT64 FileObject;
    UINT64 FileId;
    UINT64 ByteOffset;
    UINT64 Length;
    UINT64 Status;
    UINT64 Information;
    UINT32 Operation;
    UINT32 MajorCode;
    UINT32 MinorCode;
    UINT32 IrpFlags;
    UINT32 CreateOptions;
    UINT32 CreateDisposition;
    UINT32 DesiredAccess;
    UINT32 ShareAccess;
    UINT32 Flags;
    WCHAR Path[BK_MAX_FILE_PATH_CHARS];
} BK_FILE_EVENT, *PBK_FILE_EVENT;

typedef struct _BK_EVENT_RECORD
{
    BK_EVENT_HEADER Header;
    union
    {
        BK_HANDLE_EVENT Handle;
        BK_THREAD_EVENT Thread;
        BK_FILE_EVENT FileSystem;
        BK_REGISTRY_EVENT Registry;
        BK_ENTERPRISE_EVENT Enterprise;
    } Data;
} BK_EVENT_RECORD, *PBK_EVENT_RECORD;

typedef enum _BK_TEMPUS_SUBSYSTEM
{
    BktmpSubsystemDriver = 0,
    BktmpSubsystemControl = 1,
    BktmpSubsystemEtw = 2,
    BktmpSubsystemHandleMonitor = 3,
    BktmpSubsystemThreadMonitor = 4,
    BktmpSubsystemProcessMonitor = 5,
    BktmpSubsystemImageMonitor = 6,
    BktmpSubsystemRegistryMonitor = 7,
    BktmpSubsystemFileSystemMonitor = 8,
    BktmpSubsystemApcMonitor = 9,
    BktmpSubsystemCorrelation = 10,
    BktmpSubsystemHollowingEngine = 11,
    BktmpSubsystemNtApiMonitor = 12,
    BktmpSubsystemAntiTamper = 13
} BK_TEMPUS_SUBSYSTEM;

typedef struct _BK_TEMPUS_BUCKET
{
    UINT64 SampleCount;
    UINT64 TotalQpc;
    UINT64 MaxQpc;
    UINT64 LastQpc;
} BK_TEMPUS_BUCKET, *PBK_TEMPUS_BUCKET;

typedef struct _BK_STATS_RESPONSE
{
    UINT32 SubscriptionCount;
    UINT32 QueueDepth;
    UINT32 DroppedEvents;
    UINT32 TempusEnabled;
    UINT64 TempusQpcFrequency;
    UINT32 TempusSubsystemCount;
    UINT32 HookReadyMask;
    UINT32 HookReadyRequiredMask;
    UINT32 InstrumentationRangeCount;
    UINT32 HookPatchCount;
    UINT64 HookPatchOverlayCount;
    UINT64 InstrumentationReadDenyCount;
    UINT64 DuplicateNtdllMirrorCount;
    UINT64 DuplicateNtdllMirrorFailureCount;
    BK_TEMPUS_BUCKET Tempus[BK_TEMPUS_SUBSYSTEM_COUNT];
} BK_STATS_RESPONSE, *PBK_STATS_RESPONSE;

typedef struct _BK_HEALTH_RESPONSE
{
    UINT32 HealthMask;
    UINT32 TamperMask;
    UINT32 Reserved0;
    UINT32 Reserved1;
} BK_HEALTH_RESPONSE, *PBK_HEALTH_RESPONSE;

#define BK_HEALTH_BUILD_MAGIC 0xB1BDFEEDu
#define BK_HEALTH_FEATURE_ENDPOINT_GUARD_DYNAMIC_ALE 0x00000001u
#define BK_HEALTH_FEATURE_ENDPOINT_GUARD_FILTER_DIAG 0x00000002u

#define BK_HEALTH_CONTROL_READY 0x00000001u
#define BK_HEALTH_ETW_READY 0x00000002u
#define BK_HEALTH_HANDLE_MONITOR_READY 0x00000004u
#define BK_HEALTH_THREAD_MONITOR_READY 0x00000008u
#define BK_HEALTH_PROCESS_MONITOR_READY 0x00000010u
#define BK_HEALTH_IMAGE_MONITOR_READY 0x00000020u
#define BK_HEALTH_REGISTRY_MONITOR_READY 0x00000040u
#define BK_HEALTH_APC_MONITOR_READY 0x00000080u
#define BK_HEALTH_FILESYSTEM_MONITOR_READY 0x00000100u
#define BK_HEALTH_CORRELATION_READY 0x00000200u
#define BK_HEALTH_HOLLOWING_ENGINE_READY 0x00000400u
#define BK_HEALTH_NTAPI_MONITOR_READY 0x00000800u
#define BK_HEALTH_ANTI_TAMPER_READY 0x00001000u
#define BK_HEALTH_DIAGNOSTICS_READY 0x00002000u
#define BK_HEALTH_ENDPOINT_GUARD_READY 0x00004000u
#define BK_HEALTH_ENTERPRISE_MONITOR_READY 0x00008000u
#define BK_HEALTH_BUGCHECK_MONITOR_READY 0x00010000u

typedef enum _BK_DIAGNOSTIC_EVENT_TYPE
{
    BkDiagEventNone = 0,
    BkDiagEventInitBegin = 1,
    BkDiagEventInitOk = 2,
    BkDiagEventInitFailed = 3,
    BkDiagEventOnline = 4,
    BkDiagEventConfirmedOnline = 5,
    BkDiagEventDisabledByPolicy = 6,
    BkDiagEventOptionalMissingContinuing = 7,
    BkDiagEventDisarmed = 8,
    BkDiagEventArmed = 9,
    BkDiagEventShutdownBegin = 10,
    BkDiagEventShutdownOk = 11,
    BkDiagEventSelfCheckFailed = 12,
    BkDiagEventDegradedContinuing = 13
} BK_DIAGNOSTIC_EVENT_TYPE;

#define BK_DIAG_FLAG_FAILURE 0x00000001u
#define BK_DIAG_FLAG_OPTIONAL 0x00000002u
#define BK_DIAG_FLAG_CONTINUING 0x00000004u
#define BK_DIAG_FLAG_POLICY 0x00000008u
#define BK_DIAG_FLAG_SHUTDOWN 0x00000010u
#define BK_DIAG_FLAG_SELF_CHECK 0x00000020u

#define BK_DIAG_COMPONENT_NONE 0u
#define BK_DIAG_COMPONENT_DRIVER_ENTRY 1u
#define BK_DIAG_COMPONENT_RUNTIME_CONFIG 2u
#define BK_DIAG_COMPONENT_ETW 3u
#define BK_DIAG_COMPONENT_CONTROL 4u
#define BK_DIAG_COMPONENT_CORRELATION 5u
#define BK_DIAG_COMPONENT_HOLLOWING_ENGINE 6u
#define BK_DIAG_COMPONENT_APC_MONITOR 7u
#define BK_DIAG_COMPONENT_PROCESS_MONITOR 8u
#define BK_DIAG_COMPONENT_IMAGE_MONITOR 9u
#define BK_DIAG_COMPONENT_REGISTRY_MONITOR 10u
#define BK_DIAG_COMPONENT_THREAD_MONITOR 11u
#define BK_DIAG_COMPONENT_FILESYSTEM_MONITOR 12u
#define BK_DIAG_COMPONENT_HANDLE_MONITOR 13u
#define BK_DIAG_COMPONENT_NTAPI_MONITOR 14u
#define BK_DIAG_COMPONENT_ANTI_TAMPER 15u
#define BK_DIAG_COMPONENT_DIAGNOSTICS 16u
#define BK_DIAG_COMPONENT_WFP_ENDPOINT_GUARD 17u
#define BK_DIAG_COMPONENT_WFP_ENDPOINT 18u
#define BK_DIAG_COMPONENT_ENTERPRISE_MONITOR 19u
#define BK_DIAG_COMPONENT_BUGCHECK_MONITOR 20u

#define BK_DIAG_STATE_ONLINE 0x00000001u
#define BK_DIAG_STATE_REGISTERED 0x00000002u
#define BK_DIAG_STATE_ARMED 0x00000004u
#define BK_DIAG_STATE_CALLBACK 0x00000008u
#define BK_DIAG_STATE_HOOK 0x00000010u
#define BK_DIAG_STATE_REQUIRED 0x00000020u
#define BK_DIAG_STATE_OPTIONAL_STATE 0x00000040u
#define BK_DIAG_STATE_INSTALLED 0x00000080u
#define BK_DIAG_STATE_RESOLVED 0x00000100u
#define BK_DIAG_STATE_POLICY_DISABLED 0x00000200u
#define BK_DIAG_STATE_DEGRADED 0x00000400u
#define BK_DIAG_STATE_SANITIZES 0x00000800u
#define BK_DIAG_STATE_TELEMETRY 0x00001000u
#define BK_DIAG_STATE_TAMPER_ACTIVE 0x00002000u
#define BK_DIAG_STATE_FAST_PATH 0x00004000u

typedef enum _BK_DIAGNOSTIC_NTAPI_HOOK_ID
{
    BkDiagNtHookQuerySystemInformation = 0,
    BkDiagNtHookQueryInformationProcess = 1,
    BkDiagNtHookQueryObject = 2,
    BkDiagNtHookWriteVirtualMemory = 3,
    BkDiagNtHookReadVirtualMemory = 4,
    BkDiagNtHookProtectVirtualMemory = 5,
    BkDiagNtHookCreateSection = 6,
    BkDiagNtHookMapViewOfSection = 7,
    BkDiagNtHookMapViewOfSectionEx = 8,
    BkDiagNtHookUnmapViewOfSection = 9,
    BkDiagNtHookUnmapViewOfSectionEx = 10,
    BkDiagNtHookAllocateVirtualMemory = 11,
    BkDiagNtHookCreateThread = 12,
    BkDiagNtHookCreateThreadEx = 13,
    BkDiagNtHookQueueApcThread = 14,
    BkDiagNtHookQueueApcThreadEx = 15,
    BkDiagNtHookQueueApcThreadEx2 = 16,
    BkDiagNtHookQuerySystemInformationEx = 17,
    BkDiagNtHookQueryPerformanceCounter = 18,
    BkDiagNtHookQueryVirtualMemory = 19,
    BkDiagNtHookGetContextThread = 20,
    BkDiagNtHookSetContextThread = 21,
    BkDiagNtHookGetNextThread = 22,
    BkDiagNtHookQueryInformationThread = 23,
    BkDiagNtHookSetInformationThread = 24,
    BkDiagNtHookSetInformationProcess = 25,
    BkDiagNtHookResumeThread = 26,
    BkDiagNtHookSuspendThread = 27,
    BkDiagNtHookAlertResumeThread = 28,
    BkDiagNtHookAlertThread = 29,
    BkDiagNtHookTestAlert = 30,
    BkDiagNtHookCreateUserProcess = 31,
    BkDiagNtHookCreateProcessEx = 32,
    BkDiagNtHookCreateFile = 33,
    BkDiagNtHookOpenFile = 34,
    BkDiagNtHookDeviceIoControlFile = 35,
    BkDiagNtHookFsControlFile = 36,
    BkDiagNtHookQueryDirectoryFile = 37,
    BkDiagNtHookQueryDirectoryFileEx = 38,
    BkDiagNtHookAlpcConnectPort = 39,
    BkDiagNtHookAlpcSendWaitReceivePort = 40,
    BkDiagNtHookConnectPort = 41,
    BkDiagNtHookOpenProcess = 42,
    BkDiagNtHookOpenThread = 43,
    BkDiagNtHookDuplicateObject = 44,
    BkDiagNtHookQueryKey = 45,
    BkDiagNtHookEnumerateKey = 46,
    BkDiagNtHookQueryValueKey = 47,
    BkDiagNtHookEnumerateValueKey = 48,
    BkDiagNtHookCount = 49
} BK_DIAGNOSTIC_NTAPI_HOOK_ID;

typedef enum _BK_DIAGNOSTIC_SANITIZER_ID
{
    BkDiagSanitizerSystemProcessList = 0,
    BkDiagSanitizerSystemModuleList = 1,
    BkDiagSanitizerSystemHandleList = 2,
    BkDiagSanitizerKernelDebugger = 3,
    BkDiagSanitizerCodeIntegrity = 4,
    BkDiagSanitizerFirmwareTable = 5,
    BkDiagSanitizerProcessDebugQuery = 6,
    BkDiagSanitizerObjectName = 7,
    BkDiagSanitizerReadVirtualMemoryPatchOverlay = 8,
    BkDiagSanitizerReadVirtualMemoryRangeDeny = 9,
    BkDiagSanitizerWriteVirtualMemoryCloak = 10,
    BkDiagSanitizerProtectVirtualMemoryDeny = 11,
    BkDiagSanitizerDuplicateNtdllMirror = 12,
    BkDiagSanitizerGetNextThreadFilter = 13,
    BkDiagSanitizerVirtualMemoryBasicInfo = 14,
    BkDiagSanitizerDirectoryBlackbird = 15,
    BkDiagSanitizerFileBlackbird = 16,
    BkDiagSanitizerIpcHandle = 17,
    BkDiagSanitizerPortBlackbird = 18,
    BkDiagSanitizerRegistryBlackbird = 19,
    BkDiagSanitizerRegistryBam = 20,
    BkDiagSanitizerFilesystemBlackbird = 21,
    BkDiagSanitizerFilesystemAntiVm = 22,
    BkDiagSanitizerQpcTiming = 23,
    BkDiagSanitizerCount = 24
} BK_DIAGNOSTIC_SANITIZER_ID;

typedef struct _BK_DIAGNOSTIC_COMPONENT_STATE
{
    UINT16 ComponentId;
    UINT16 SubsystemId;
    UINT32 Flags;
    INT32 Status;
    UINT32 Reserved;
    UINT64 Detail0;
    UINT64 Detail1;
} BK_DIAGNOSTIC_COMPONENT_STATE, *PBK_DIAGNOSTIC_COMPONENT_STATE;

typedef struct _BK_DIAGNOSTIC_NTAPI_HOOK_STATE
{
    UINT16 HookId;
    UINT16 Required;
    UINT32 Flags;
    UINT32 OverwriteLength;
    UINT32 Reserved;
    UINT64 RoutineAddress;
    UINT64 TrampolineAddress;
} BK_DIAGNOSTIC_NTAPI_HOOK_STATE, *PBK_DIAGNOSTIC_NTAPI_HOOK_STATE;

typedef struct _BK_DIAGNOSTIC_SANITIZER_STATE
{
    UINT16 SanitizerId;
    UINT16 ComponentId;
    UINT32 Flags;
    UINT32 StreamMask;
    UINT32 SourceClass;
    UINT64 HitCount;
    UINT64 Detail0;
} BK_DIAGNOSTIC_SANITIZER_STATE, *PBK_DIAGNOSTIC_SANITIZER_STATE;

#define BK_ENDPOINT_GUARD_ACTION_ARM 1u
#define BK_ENDPOINT_GUARD_ACTION_DISARM 2u
#define BK_ENDPOINT_GUARD_DIRECTION_INBOUND 0x00000001u
#define BK_ENDPOINT_GUARD_DIRECTION_OUTBOUND 0x00000002u
#define BK_ENDPOINT_GUARD_PROTOCOL_TCP 6u
#define BK_ENDPOINT_GUARD_PROTOCOL_UDP 17u
#define BK_ENDPOINT_GUARD_FLAG_LOCAL_ADDRESS_EXACT 0x00000001u
#define BK_ENDPOINT_GUARD_FLAG_REMOTE_ADDRESS_EXACT 0x00000002u

typedef struct _BK_ENDPOINT_GUARD_REQUEST
{
    UINT32 Action;
    UINT32 ProcessId;
    UINT32 Protocol;
    UINT32 Direction;
    UINT32 LocalAddressV4;
    UINT32 RemoteAddressV4;
    UINT16 LocalPort;
    UINT16 RemotePort;
    UINT32 Flags;
    UINT32 Reserved;
} BK_ENDPOINT_GUARD_REQUEST, *PBK_ENDPOINT_GUARD_REQUEST;

typedef struct _BK_DIAGNOSTIC_EVENT
{
    UINT64 Sequence;
    INT64 TimestampQpc;
    UINT64 ElapsedQpc;
    UINT32 SubsystemId;
    UINT32 EventType;
    INT32 Status;
    UINT32 Flags;
    UINT32 DetailCode;
    UINT32 ComponentId;
} BK_DIAGNOSTIC_EVENT, *PBK_DIAGNOSTIC_EVENT;

typedef struct _BK_DIAGNOSTICS_RESPONSE
{
    UINT64 QpcFrequency;
    UINT64 OldestSequence;
    UINT64 NextSequence;
    UINT32 EventCount;
    UINT32 DroppedCount;
    BK_DIAGNOSTIC_EVENT Events[BK_DIAGNOSTIC_MAX_EVENTS];
    UINT32 SchemaVersion;
    UINT32 RuntimeFlags;
    UINT32 EffectiveRuntimeFlags;
    UINT32 HealthMask;
    UINT32 TamperMask;
    UINT32 ComponentStateCount;
    UINT32 NtApiHookStateCount;
    UINT32 SanitizerStateCount;
    UINT32 InstrumentationRangeCount;
    UINT32 HookPatchCount;
    UINT64 HookPatchOverlayCount;
    UINT64 InstrumentationReadDenyCount;
    UINT64 DuplicateNtdllMirrorCount;
    UINT64 DuplicateNtdllMirrorFailureCount;
    BK_QPC_TIMING_STATE QpcTiming;
    BK_DIAGNOSTIC_COMPONENT_STATE Components[BK_DIAGNOSTIC_MAX_COMPONENT_STATES];
    BK_DIAGNOSTIC_NTAPI_HOOK_STATE NtApiHooks[BK_DIAGNOSTIC_MAX_NTAPI_HOOK_STATES];
    BK_DIAGNOSTIC_SANITIZER_STATE Sanitizers[BK_DIAGNOSTIC_MAX_SANITIZER_STATES];
} BK_DIAGNOSTICS_RESPONSE, *PBK_DIAGNOSTICS_RESPONSE;

#define BK_HANDLE_FLAG_EXEC_PROTECT 0x00000001
#define BK_HANDLE_FLAG_FROM_NTDLL 0x00000002
#define BK_HANDLE_FLAG_FROM_EXE 0x00000004
#define BK_HANDLE_FLAG_MEMORY_RELATED 0x00000008
#define BK_HANDLE_FLAG_THREAD_OBJECT 0x00000010
#define BK_HANDLE_FLAG_DUPLICATE_OPERATION 0x00000020
#define BK_HANDLE_FLAG_DEEP_PATH_CANDIDATE 0x00000040
#define BK_HANDLE_FLAG_DEEP_PATH_CAPTURED 0x00000080
#define BK_HANDLE_FLAG_DEEP_PATH_CACHE_HIT 0x00000100
#define BK_HANDLE_FLAG_RETURN_ADDRESS_VALID 0x00000200
#define BK_HANDLE_FLAG_STACK_VALIDATED 0x00000400
#define BK_HANDLE_FLAG_STACK_SPOOF_SUSPECT 0x00000800
#define BK_HANDLE_FLAG_SYSCALL_EXPORT_MATCH 0x00001000
#define BK_HANDLE_FLAG_SYSCALL_EXPORT_MISMATCH 0x00002000
#define BK_HANDLE_FLAG_MODULE_CHAIN_SANE 0x00004000
#define BK_HANDLE_FLAG_UNWIND_METADATA_VALID 0x00008000
#define BK_HANDLE_FLAG_TEB_STACK_BOUNDS_VALID 0x00010000
#define BK_HANDLE_FLAG_FRAMES_OUTSIDE_TEB_STACK 0x00020000

#define BK_HANDLE_CAPTURE_CONTEXT_VALID 0x00000001
#define BK_HANDLE_CAPTURE_DEBUG_REGS_VALID 0x00000002
#define BK_HANDLE_CAPTURE_FULL_FRAMES_VALID 0x00000004
#define BK_HANDLE_CAPTURE_STACK_SNAPSHOT_VALID 0x00000008

#define BK_THREAD_FLAG_GOT_START 0x00000001
#define BK_THREAD_FLAG_GOT_RANGE 0x00000002
#define BK_THREAD_FLAG_REMOTE_CREATOR 0x00000004
#define BK_THREAD_FLAG_OUTSIDE_MAIN_IMG 0x00000008
#define BK_THREAD_FLAG_CORRELATED_INTENT 0x00000010
#define BK_THREAD_FLAG_CORR_MEMORY 0x00000020
#define BK_THREAD_FLAG_CORR_THREAD_CTX 0x00000040
#define BK_THREAD_FLAG_CORR_DUP_HANDLE 0x00000080
#define BK_THREAD_FLAG_START_REGION_EXEC 0x00000100

#define BK_FILE_FLAG_PRE_OPERATION 0x00000001
#define BK_FILE_FLAG_POST_OPERATION 0x00000002
#define BK_FILE_FLAG_PAGING_IO 0x00000004
#define BK_FILE_FLAG_SYNCHRONOUS_IO 0x00000008
#define BK_FILE_FLAG_NON_CACHED_IO 0x00000010
#define BK_FILE_FLAG_DIRECTORY_FILE 0x00000020
#define BK_FILE_FLAG_DELETE_ON_CLOSE 0x00000040
#define BK_FILE_FLAG_REPARSE_POINT 0x00000080
#define BK_FILE_FLAG_FAST_IO 0x00000100

#endif
