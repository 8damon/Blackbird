using System;
using System.Buffers.Binary;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Reflection;

namespace BlackbirdInterface
{
    internal static partial class BlackbirdNative
    {
        static BlackbirdNative()
        {
            NativeLibrary.SetDllImportResolver(typeof(BlackbirdNative).Assembly, ResolveNativeLibrary);
        }

        internal const uint StreamHandle = 0x00000001;
        internal const uint StreamMemory = 0x00000002;
        internal const uint StreamThread = 0x00000004;
        internal const uint StreamFilesystem = 0x00000008;
        internal const uint StreamRegistry = 0x00000010;
        internal const uint StreamTiming = 0x00000020;
        internal const uint StreamUsermodeOnly = 0x80000000;
        internal const uint StreamAll =
            StreamHandle | StreamMemory | StreamThread | StreamFilesystem | StreamRegistry | StreamTiming;

        internal const uint EventTypeHandle = 1;
        internal const uint EventTypeThread = 2;
        internal const uint EventTypeFileSystem = 3;
        internal const uint EventTypeRegistry = 4;

        internal const uint FileOperationUnknown = 0;
        internal const uint FileOperationCreate = 1;
        internal const uint FileOperationRead = 2;
        internal const uint FileOperationWrite = 3;
        internal const uint FileOperationClose = 4;
        internal const uint FileOperationCleanup = 5;
        internal const uint FileOperationSetInformation = 6;
        internal const uint FileOperationQueryInformation = 7;
        internal const uint FileOperationDirectoryControl = 8;
        internal const uint FileOperationFsControl = 9;

        internal const uint RegistryOperationUnknown = 0;
        internal const uint RegistryOperationQueryValue = 1;
        internal const uint RegistryOperationQueryKey = 2;
        internal const uint RegistryOperationEnumerateKey = 3;
        internal const uint RegistryOperationEnumerateValue = 4;
        internal const uint RegistryOperationSetValue = 5;
        internal const uint RegistryOperationCreateKey = 6;
        internal const uint RegistryOperationOpenKey = 7;
        internal const uint RegistryOperationDeleteValue = 8;
        internal const uint RegistryOperationDeleteKey = 9;

        internal const uint RegistryFlagHighValuePath = 0x00000001;
        internal const uint RegistryFlagSensitiveQuery = 0x00000002;

        internal const uint IpcCapDriverProxy = 0x00000001;
        internal const uint IpcCapEtwTiSession = 0x00000002;
        internal const uint IpcCapEtwTiUplink = 0x00000004;
        internal const uint IpcCapSharedRing = 0x00000008;
        internal const uint IpcCapUserHookIngest = 0x00000010;
        internal const uint IpcCapUserHookReady = 0x00000020;
        internal const uint IpcCapDriverDiagnostics = 0x00000040;
        internal const uint IpcCapQpcTiming = 0x00000080;
        internal const uint AnalysisSubjectKindProcess = 0;
        internal const uint AnalysisSubjectKindDll = 1;
        internal const uint HealthControlReady = 0x00000001;
        internal const uint HealthEtwReady = 0x00000002;
        internal const uint HealthHandleMonitorReady = 0x00000004;
        internal const uint HealthThreadMonitorReady = 0x00000008;
        internal const uint HealthProcessMonitorReady = 0x00000010;
        internal const uint HealthImageMonitorReady = 0x00000020;
        internal const uint HealthRegistryMonitorReady = 0x00000040;
        internal const uint HealthApcMonitorReady = 0x00000080;
        internal const uint HealthFileSystemMonitorReady = 0x00000100;
        internal const uint HealthCorrelationReady = 0x00000200;
        internal const uint HealthHollowingEngineReady = 0x00000400;
        internal const uint HealthNtApiMonitorReady = 0x00000800;
        internal const uint HealthAntiTamperReady = 0x00001000;
        internal const uint HealthDiagnosticsReady = 0x00002000;

        internal const int DiagnosticMaxEvents = 64;
        internal const uint DiagEventInitBegin = 1;
        internal const uint DiagEventInitOk = 2;
        internal const uint DiagEventInitFailed = 3;
        internal const uint DiagEventOnline = 4;
        internal const uint DiagEventConfirmedOnline = 5;
        internal const uint DiagEventDisabledByPolicy = 6;
        internal const uint DiagEventOptionalMissingContinuing = 7;
        internal const uint DiagEventDisarmed = 8;
        internal const uint DiagEventArmed = 9;
        internal const uint DiagEventShutdownBegin = 10;
        internal const uint DiagEventShutdownOk = 11;
        internal const uint DiagEventSelfCheckFailed = 12;
        internal const uint DiagEventDegradedContinuing = 13;
        internal const uint DiagFlagFailure = 0x00000001;
        internal const uint DiagFlagOptional = 0x00000002;
        internal const uint DiagFlagContinuing = 0x00000004;
        internal const uint DiagFlagPolicy = 0x00000008;
        internal const uint DiagFlagShutdown = 0x00000010;
        internal const uint DiagFlagSelfCheck = 0x00000020;
        internal const uint DiagComponentNone = 0;
        internal const uint DiagComponentDriverEntry = 1;
        internal const uint DiagComponentRuntimeConfig = 2;
        internal const uint DiagComponentEtw = 3;
        internal const uint DiagComponentControl = 4;
        internal const uint DiagComponentCorrelation = 5;
        internal const uint DiagComponentHollowingEngine = 6;
        internal const uint DiagComponentApcMonitor = 7;
        internal const uint DiagComponentProcessMonitor = 8;
        internal const uint DiagComponentImageMonitor = 9;
        internal const uint DiagComponentRegistryMonitor = 10;
        internal const uint DiagComponentThreadMonitor = 11;
        internal const uint DiagComponentFilesystemMonitor = 12;
        internal const uint DiagComponentHandleMonitor = 13;
        internal const uint DiagComponentNtApiMonitor = 14;
        internal const uint DiagComponentAntiTamper = 15;
        internal const uint DiagComponentDiagnostics = 16;

        internal const uint IpcEtwSourceUnknown = 0;
        internal const uint IpcEtwSourceBlackbird = 1;
        internal const uint IpcEtwSourceThreatIntel = 2;
        internal const uint IpcEtwSourceKernelNetwork = 3;
        internal const uint IpcEtwSourceUserHook = 4;

        internal const int ErrorNoMoreItems = 259;
        internal const int ErrorNoMoreEntries = 259;
        internal const int ErrorDeviceNotConnected = 1167;
        internal const int ErrorOperationAborted = 995;
        internal const int ErrorNotReady = 21;
        internal const int ErrorBrokenPipe = 109;
        internal const int ErrorNotSupported = 50;
        internal const int ErrorInvalidFunction = 1;

        internal const int EventReadBufferBytes = 8192;
        internal const int DiagnosticMaxComponentStates = 32;
        internal const int DiagnosticMaxNtApiHookStates = 64;
        internal const int DiagnosticMaxSanitizerStates = 32;
        internal const int MaxIpcHookImagePathChars = 1024;
        internal const int MaxIpcLaunchEnvironmentChars = 4096;
        internal const uint IpcUserHookTargetNone = 0;
        internal const uint IpcUserHookTargetAttach = 1;
        internal const uint IpcUserHookTargetLaunch = 2;
        internal const uint IpcUserHookFlagLaunchEarlybirdApc = 0x00000001;
        internal const uint IpcUserHookFlagDeferredLaunchGateRelease = 0x00000002;
        internal const uint IpcUserHookFlagUsermodeOnly = 0x00000004;
        internal const uint IpcHookEventUnknown = 0;
        internal const uint IpcHookEventNt = 1;
        internal const uint IpcHookEventWinsock = 2;
        internal const uint IpcHookEventKi = 3;
        internal const uint IpcHookEventExceptionLowNoise = 4;
        internal const uint IpcHookEventExceptionHighPriv = 5;
        internal const uint IpcHookEventIntegrity = 6;
        internal const uint IpcHookEventModule = 7;
        internal const uint RuntimeFlagAntiVirtualization = 0x00000001;
        internal const uint RuntimeFlagSelfHide = 0x00000002;
        internal const uint RuntimeFlagInterfaceProtectedAccess = 0x00000004;
        internal const uint RuntimeFlagControllerProtectedAccess = 0x00000008;
        internal const uint RuntimeFlagNtApiHooksDisarmed = 0x00000010;
        internal const uint RuntimeFlagQpcTimingDisabled = 0x00000020;
        internal const uint QpcTimingConfigFlagEnabled = 0x00000001;
        internal const uint QpcTimingConfigFlagManualBias = 0x00000002;
        internal const uint QpcTimingSourceBlackbirdOverhead = 0x00000001;
        internal const uint QpcTimingSourceAutoBias = 0x00000002;
        internal const uint QpcTimingSourceManualBias = 0x00000004;
        internal const uint QpcTimingSourceSuspendPause = 0x00000008;
        internal const uint QpcTimingSourceMonotonicClamp = 0x00000010;
        internal const uint QpcTimingSourcePairMatch = 0x00000020;
        internal const uint QpcTimingSourceTightPairClamp = 0x00000040;
        internal const uint RuntimeModeLoiter = 0;
        internal const uint RuntimeModeGuided = 1;

        internal const uint LaunchIntegrityDefault = 0;
        internal const uint LaunchIntegrityUntrusted = 1;
        internal const uint LaunchIntegrityLow = 2;
        internal const uint LaunchIntegrityMedium = 3;
        internal const uint LaunchIntegrityHigh = 4;
        internal const uint LaunchIntegritySystem = 5;

        private const int MaxIpcEventNameChars = 96;
        private const int MaxIpcDetectionNameChars = 128;
        private const int MaxIpcReasonChars = 256;
        private const int MaxIpcShortTextChars = 64;
        private const int MaxIpcImagePathChars = 260;
        private const int MaxIpcCommandLineChars = 512;
        private const int MaxIpcKeyPathChars = 512;
        private const int MaxIpcValueNameChars = 256;
        internal const int MaxIpcStackFrames = 16;
        private const int MaxIpcDeepSampleBytes = 64;
        private const int MaxIpcHookArgs = 8;

        internal const uint IpcEtwFamilyUnknown = 0;
        internal const uint IpcEtwFamilyHandle = 1;
        internal const uint IpcEtwFamilyThread = 2;
        internal const uint IpcEtwFamilyProcess = 3;
        internal const uint IpcEtwFamilyImage = 4;
        internal const uint IpcEtwFamilyRegistry = 5;
        internal const uint IpcEtwFamilyApc = 6;
        internal const uint IpcEtwFamilyDetection = 7;
        internal const uint IpcEtwFamilyThreatIntel = 8;
        internal const uint IpcEtwFamilySocket = 9;
        internal const uint IpcEtwFamilyUserHook = 10;

        internal const uint IpcEtwFlagHandleExecProtect = 0x00000001;
        internal const uint IpcEtwFlagHandleFromNtdll = 0x00000002;
        internal const uint IpcEtwFlagHandleFromExe = 0x00000004;
        internal const uint IpcEtwFlagThreadGotStart = 0x00000008;
        internal const uint IpcEtwFlagThreadGotRange = 0x00000010;
        internal const uint IpcEtwFlagThreadRemoteCreator = 0x00000020;
        internal const uint IpcEtwFlagThreadOutsideMainImage = 0x00000040;
        internal const uint IpcEtwFlagProcessIsCreate = 0x00000080;
        internal const uint IpcEtwFlagImageSystemMode = 0x00000100;
        internal const uint IpcEtwFlagImageSignatureKnown = 0x00000200;
        internal const uint IpcEtwFlagRegistryHighValue = 0x00000400;
        internal const uint IpcEtwFlagApcDuplicateOperation = 0x00000800;
        // Syscall / stack-integrity signals (kernel-side, 0x1000–0x20000)
        internal const uint IpcEtwFlagSyscallExportMatch = 0x00001000;
        internal const uint IpcEtwFlagSyscallExportMismatch = 0x00002000;
        internal const uint IpcEtwFlagModuleChainSane = 0x00004000;
        internal const uint IpcEtwFlagUnwindMetadataValid = 0x00008000;
        internal const uint IpcEtwFlagTebStackBoundsValid = 0x00010000;
        internal const uint IpcEtwFlagFramesOutsideTebStack = 0x00020000;
        // Hook-event caller origin (usermode SR71 classification, 0x40000–0x200000)
        internal const uint IpcEtwFlagHookCallerAllSystem = 0x00040000;
        internal const uint IpcEtwFlagHookCallerHasUnmapped = 0x00080000;
        internal const uint IpcEtwFlagHookCallerHasProcessImage = 0x00100000;
        internal const uint IpcEtwFlagHookCallerHasNonSystemDll = 0x00200000;
        internal const uint IpcEtwFlagHookCallerHasOwnModule = 0x04000000;
        internal const uint IpcEtwFlagHookKernelCaller = 0x00400000;
        internal const uint IpcEtwFlagHookUserCaller = 0x00800000;
        internal const uint IpcEtwFlagHookTargetCurrentProcess = 0x01000000;
        internal const uint IpcEtwFlagHookSectionImage = 0x02000000;
        internal const uint IpcEtwTraitMemoryAllocRw = 0x00000001;
        internal const uint IpcEtwTraitMemoryWriteVm = 0x00000002;
        internal const uint IpcEtwTraitMemoryProtectRx = 0x00000004;
        internal const uint IpcEtwTraitNetwork = 0x00000008;
        internal const uint IpcEtwTraitRemoteExecution = 0x00000010;
        internal const uint IpcEtwTraitCredentialAccess = 0x00000020;
        internal const uint IpcEtwTraitImageTamper = 0x00000040;
        internal const uint IpcEtwTraitLolbin = 0x00000080;
        internal const uint IpcEtwTraitDetectionClass = 0x00000100;
        internal const uint IpcEtwTraitDirectSyscall = 0x00000200;
        internal const uint IpcEtwTraitHookTamper = 0x00000400;
        internal const uint IpcEtwTraitImageLoad = 0x00000800;
        internal const uint IpcEtwTraitProcessLaunch = 0x00001000;
        internal const uint IpcEtwTraitScanImagePath = 0x00002000;
        internal const uint IpcEtwTraitScanTargetProcess = 0x00004000;
        internal const uint IpcEtwTraitBlackbirdOwn = 0x00008000;
        internal const uint HookCallerImmediateShift = 4;
        internal const uint HookCallerImmediateMask = 0x000000F0;
        internal const uint HookCallerDeepOriginShift = 8;
        internal const uint HookCallerDeepOriginMask = 0x00000F00;
        internal const uint HookCallerComponentShift = 28;
        internal const uint HookCallerComponentMask = 0xF0000000;
        internal const uint HookCallerKindUnknown = 0;
        internal const uint HookCallerKindUnmapped = 1;
        internal const uint HookCallerKindSystemDll = 2;
        internal const uint HookCallerKindProcessImage = 3;
        internal const uint HookCallerKindOwnModule = 4;
        internal const uint HookCallerKindNonSystemDll = 5;
        internal const uint HookComponentUnknown = 0;
        internal const uint HookComponentRuntime = 1;
        internal const uint HookComponentWinsock = 2;
        internal const uint HookComponentNt = 3;
        internal const uint HookComponentKi = 4;
        internal const uint HookComponentModule = 5;
        internal const uint HookComponentIntegrity = 6;
        internal const uint HookComponentLaunchGate = 7;
        internal const uint HookComponentIpc = 8;

        private static IntPtr ResolveNativeLibrary(string libraryName, Assembly assembly,
                                                   DllImportSearchPath? searchPath)
        {
            if (!string.Equals(libraryName, "J58.dll", StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(libraryName, "J58", StringComparison.OrdinalIgnoreCase))
            {
                return IntPtr.Zero;
            }

            string? preferredPath = ResolvePreferredSensorCorePath();
            if (!string.IsNullOrWhiteSpace(preferredPath) && NativeLibrary.TryLoad(preferredPath, out IntPtr handle))
            {
                return handle;
            }

            return IntPtr.Zero;
        }

        private static string? ResolvePreferredSensorCorePath()
        {
            string basePath = Path.Combine(AppContext.BaseDirectory, "J58.dll");
            if (File.Exists(basePath))
            {
                return basePath;
            }

            string currentPath = Path.Combine(Environment.CurrentDirectory, "J58.dll");
            if (!string.Equals(currentPath, basePath, StringComparison.OrdinalIgnoreCase) && File.Exists(currentPath))
            {
                return currentPath;
            }

            string? programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            if (string.IsNullOrWhiteSpace(programFiles))
            {
                return null;
            }

            string blackbirdPath = Path.Combine(programFiles, "Blackbird", "J58.dll");
            if (File.Exists(blackbirdPath))
            {
                return blackbirdPath;
            }

            string bkPath = Path.Combine(programFiles, "BK", "J58.dll");
            return File.Exists(bkPath) ? bkPath : null;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 8)]
        internal struct BkStatsResponse
        {
            public uint SubscriptionCount;
            public uint QueueDepth;
            public uint DroppedEvents;
            public uint TempusEnabled;
            public ulong TempusQpcFrequency;
            public uint TempusSubsystemCount;
            public uint HookReadyMask;
            public uint HookReadyRequiredMask;
            public uint InstrumentationRangeCount;
            public uint HookPatchCount;
            public ulong HookPatchOverlayCount;
            public ulong InstrumentationReadDenyCount;
            public ulong DuplicateNtdllMirrorCount;
            public ulong DuplicateNtdllMirrorFailureCount;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 14)]
            public BkTempusBucket[] Tempus;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 8)]
        internal struct BkHealthResponse
        {
            public uint HealthMask;
            public uint TamperMask;
            public uint Reserved0;
            public uint Reserved1;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 8)]
        internal struct BkDiagnosticEvent
        {
            public ulong Sequence;
            public long TimestampQpc;
            public ulong ElapsedQpc;
            public uint SubsystemId;
            public uint EventType;
            public int Status;
            public uint Flags;
            public uint DetailCode;
            public uint ComponentId;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 8)]
        internal struct BkDiagnosticComponentState
        {
            public ushort ComponentId;
            public ushort SubsystemId;
            public uint Flags;
            public int Status;
            public uint Reserved;
            public ulong Detail0;
            public ulong Detail1;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 8)]
        internal struct BkDiagnosticNtApiHookState
        {
            public ushort HookId;
            public ushort Required;
            public uint Flags;
            public uint OverwriteLength;
            public uint Reserved;
            public ulong RoutineAddress;
            public ulong TrampolineAddress;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 8)]
        internal struct BkDiagnosticSanitizerState
        {
            public ushort SanitizerId;
            public ushort ComponentId;
            public uint Flags;
            public uint StreamMask;
            public uint SourceClass;
            public ulong HitCount;
            public ulong Detail0;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 8)]
        internal struct BkDiagnosticsResponse
        {
            public ulong QpcFrequency;
            public ulong OldestSequence;
            public ulong NextSequence;
            public uint EventCount;
            public uint DroppedCount;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = DiagnosticMaxEvents)]
            public BkDiagnosticEvent[] Events;
            public uint SchemaVersion;
            public uint RuntimeFlags;
            public uint EffectiveRuntimeFlags;
            public uint HealthMask;
            public uint TamperMask;
            public uint ComponentStateCount;
            public uint NtApiHookStateCount;
            public uint SanitizerStateCount;
            public uint InstrumentationRangeCount;
            public uint HookPatchCount;
            public ulong HookPatchOverlayCount;
            public ulong InstrumentationReadDenyCount;
            public ulong DuplicateNtdllMirrorCount;
            public ulong DuplicateNtdllMirrorFailureCount;
            public BkQpcTimingState QpcTiming;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = DiagnosticMaxComponentStates)]
            public BkDiagnosticComponentState[] Components;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = DiagnosticMaxNtApiHookStates)]
            public BkDiagnosticNtApiHookState[] NtApiHooks;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = DiagnosticMaxSanitizerStates)]
            public BkDiagnosticSanitizerState[] Sanitizers;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 8)]
        internal struct BkTempusBucket
        {
            public ulong SampleCount;
            public ulong TotalQpc;
            public ulong MaxQpc;
            public ulong LastQpc;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 8)]
        internal struct BkIpcEtwEvent
        {
            public uint Source;
            public uint Family;
            public ushort EventId;
            public ushort Opcode;
            public ushort Task;
            public ushort Reserved0;
            public uint EventProcessId;
            public uint EventThreadId;
            public uint Severity;
            public uint Flags;
            public ulong ProcessId;
            public ulong ThreadId;
            public ulong CallerPid;
            public ulong TargetPid;
            public ulong ParentProcessId;
            public ulong CreatorProcessId;
            public ulong CreatorThreadId;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = MaxIpcEventNameChars)]
            public ushort[] EventName;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = MaxIpcDetectionNameChars)]
            public byte[] DetectionName;
            public uint CorrelationFlags;
            public uint CorrelationAccessMask;
            public uint CorrelationAgeMs;
            public uint Reserved2;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = MaxIpcReasonChars)]
            public ushort[] Reason;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = MaxIpcShortTextChars)]
            public byte[] ClassName;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = MaxIpcShortTextChars)]
            public byte[] Operation;
            public uint DesiredAccess;
            public uint OriginProtect;
            public ulong OriginAddress;
            public int StatusOpenProcess;
            public int StatusBasicInfo;
            public int StatusSectionName;
            public uint StackCount;
            public uint Reserved3;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = MaxIpcStackFrames)]
            public ulong[] Stack;
            public ulong DeepAllocationBase;
            public ulong DeepRegionSize;
            public uint DeepRegionProtect;
            public uint DeepRegionState;
            public uint DeepRegionType;
            public uint DeepSampleSize;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = MaxIpcDeepSampleBytes)]
            public byte[] DeepSample;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = MaxIpcImagePathChars)]
            public ushort[] OriginPath;
            public ulong StartAddress;
            public ulong ImageBase;
            public ulong ImageSize;
            public uint StartRegionProtect;
            public uint StartRegionState;
            public uint StartRegionType;
            public int StartRegionStatus;
            public uint SessionId;
            public int CreateStatus;
            public ulong ProcessStartKey;
            public byte SignatureLevel;
            public byte SignatureType;
            public ushort Reserved4;
            public uint NotifyClass;
            public uint DataType;
            public uint DataSize;
            public uint HookArgCount;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = MaxIpcHookArgs)]
            public ulong[] HookArgs;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = MaxIpcImagePathChars)]
            public ushort[] ImagePath;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = MaxIpcCommandLineChars)]
            public ushort[] CommandLine;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = MaxIpcKeyPathChars)]
            public ushort[] KeyPath;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = MaxIpcValueNameChars)]
            public ushort[] ValueName;
            public uint DetectionTraits
            {
                get => Reserved2;
                set => Reserved2 = value;
            }
        }

        [StructLayout(LayoutKind.Sequential, Pack = 8)]
        internal struct BkRuntimeConfigResponse
        {
            public uint PersistentFlags;
            public uint RuntimeFlags;
            public uint EffectiveFlags;
            public uint Mode;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 8)]
        internal struct BkQpcTimingConfig
        {
            public uint Flags;
            public uint Mask;
            public uint PairWindowMs;
            public uint MaxCorrectionUs;
            public long ManualBiasTicks;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 8)]
        internal struct BkQpcTimingState
        {
            public uint Flags;
            public uint PairWindowMs;
            public uint MaxCorrectionUs;
            public uint ActiveThreadSlots;
            public long ManualBiasTicks;
            public long AutoBiasTicks;
            public ulong Frequency;
            public ulong QueryCount;
            public ulong PairCount;
            public ulong CorrectedCount;
            public ulong TotalCorrectionTicks;
            public ulong PauseCorrectionTicks;
            public ulong LastCorrectionTicks;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 8)]
        internal struct BkSetUserHookTargetResponse
        {
            public uint ProcessId;
            public int Status;
            public uint AnalysisSubjectKind;
            public uint Reserved1;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = MaxIpcHookImagePathChars)]
            public ushort[] ImagePath;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = MaxIpcHookImagePathChars)]
            public ushort[] AnalysisSubjectPath;
        }

        [DllImport("J58.dll", EntryPoint = "BkscUseClientProtocol", CallingConvention = CallingConvention.Cdecl,
                   CharSet = CharSet.Unicode, SetLastError = true)]
        [return:MarshalAs(UnmanagedType.Bool)]
        internal static extern bool UseClientProtocol(string? pipeName, uint connectTimeoutMs);

        [DllImport("J58.dll", EntryPoint = "BkscOpenControlDevice", CallingConvention = CallingConvention.Cdecl,
                   SetLastError = true)]
        internal static extern IntPtr OpenControlDevice();

        [DllImport("J58.dll", EntryPoint = "BkscCloseControlDevice", CallingConvention = CallingConvention.Cdecl,
                   SetLastError = true)]
        [return:MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CloseControlDevice(IntPtr device);

        [DllImport("J58.dll", EntryPoint = "BkscGetBrokerInfo", CallingConvention = CallingConvention.Cdecl,
                   SetLastError = true)]
        [return:MarshalAs(UnmanagedType.Bool)]
        internal static extern bool GetBrokerInfo(out uint capabilities,
                                                  [MarshalAs(UnmanagedType.Bool)] out bool threatIntelEnabled);

        [DllImport("J58.dll", EntryPoint = "BkscHasSharedChannel", CallingConvention = CallingConvention.Cdecl,
                   SetLastError = true)]
        [return:MarshalAs(UnmanagedType.Bool)]
        internal static extern bool HasSharedChannel(IntPtr device,
                                                     [MarshalAs(UnmanagedType.Bool)] out bool hasIoctlChannel,
                                                     [MarshalAs(UnmanagedType.Bool)] out bool hasEtwChannel);

        [DllImport("J58.dll", EntryPoint = "BkscGetLastSharedRingError", CallingConvention = CallingConvention.Cdecl,
                   SetLastError = true)]
        internal static extern uint GetLastSharedRingError();

        [DllImport("J58.dll", EntryPoint = "BkscGetLastThreatIntelEnableError",
                   CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
        internal static extern uint GetLastThreatIntelEnableError();

        [DllImport("J58.dll", EntryPoint = "BkscSetPids", CallingConvention = CallingConvention.Cdecl,
                   SetLastError = true)]
        [return:MarshalAs(UnmanagedType.Bool)]
        internal static extern bool SetPids(IntPtr device, [In] uint[] processIds, uint processCount, uint streamMask);

        [DllImport("J58.dll", EntryPoint = "BkscGetEvent", CallingConvention = CallingConvention.Cdecl,
                   SetLastError = true)]
        [return:MarshalAs(UnmanagedType.Bool)]
        internal static extern bool GetEventRaw(IntPtr device, IntPtr recordBuffer, out uint bytesReturned);

        [DllImport("J58.dll", EntryPoint = "BkscGetEventWait", CallingConvention = CallingConvention.Cdecl,
                   SetLastError = true)]
        [return:MarshalAs(UnmanagedType.Bool)]
        internal static extern bool GetEventWait(IntPtr device, IntPtr recordBuffer, out uint bytesReturned,
                                                 uint timeoutMs);

        [DllImport("J58.dll", EntryPoint = "BkscGetEtwEvent", CallingConvention = CallingConvention.Cdecl,
                   SetLastError = true)]
        [return:MarshalAs(UnmanagedType.Bool)]
        internal static extern bool GetEtwEvent(IntPtr device, out BkIpcEtwEvent etwEvent, uint timeoutMs);

        [DllImport("J58.dll", EntryPoint = "BkscGetStats", CallingConvention = CallingConvention.Cdecl,
                   SetLastError = true)]
        [return:MarshalAs(UnmanagedType.Bool)]
        internal static extern bool GetStats(IntPtr device, out BkStatsResponse stats, out uint bytesReturned);

        [DllImport("J58.dll", EntryPoint = "BkscGetHealth", CallingConvention = CallingConvention.Cdecl,
                   SetLastError = true)]
        [return:MarshalAs(UnmanagedType.Bool)]
        internal static extern bool GetHealth(IntPtr device, out BkHealthResponse health, out uint bytesReturned);

        [DllImport("J58.dll", EntryPoint = "BkscGetDiagnostics", CallingConvention = CallingConvention.Cdecl,
                   SetLastError = true)]
        [return:MarshalAs(UnmanagedType.Bool)]
        internal static extern bool GetDiagnostics(IntPtr device, out BkDiagnosticsResponse diagnostics,
                                                   out uint bytesReturned);

        [DllImport("J58.dll", EntryPoint = "BkscSetShutdownMode", CallingConvention = CallingConvention.Cdecl,
                   SetLastError = true)]
        [return:MarshalAs(UnmanagedType.Bool)]
        internal static extern bool SetShutdownMode(IntPtr device);

        [DllImport("J58.dll", EntryPoint = "BkscControlProcessExecution", CallingConvention = CallingConvention.Cdecl,
                   SetLastError = true)]
        [return:MarshalAs(UnmanagedType.Bool)]
        internal static extern bool ControlProcessExecution(IntPtr device, uint processId,
                                                            [MarshalAs(UnmanagedType.Bool)] bool suspend);
        [DllImport("J58.dll", EntryPoint = "BkscSetRuntimeConfig", CallingConvention = CallingConvention.Cdecl,
                   SetLastError = true)]
        [return:MarshalAs(UnmanagedType.Bool)]
        internal static extern bool SetRuntimeConfig(IntPtr device, uint flags, uint mask);

        [DllImport("J58.dll", EntryPoint = "BkscGetRuntimeConfig", CallingConvention = CallingConvention.Cdecl,
                   SetLastError = true)]
        [return:MarshalAs(UnmanagedType.Bool)]
        internal static extern bool GetRuntimeConfig(IntPtr device, out BkRuntimeConfigResponse response);

        [DllImport("J58.dll", EntryPoint = "BkscSetQpcTimingConfig", CallingConvention = CallingConvention.Cdecl,
                   SetLastError = true)]
        [return:MarshalAs(UnmanagedType.Bool)]
        internal static extern bool SetQpcTimingConfig(IntPtr device, in BkQpcTimingConfig config);

        [DllImport("J58.dll", EntryPoint = "BkscGetQpcTimingState", CallingConvention = CallingConvention.Cdecl,
                   SetLastError = true)]
        [return:MarshalAs(UnmanagedType.Bool)]
        internal static extern bool GetQpcTimingState(IntPtr device, out BkQpcTimingState state);

        [DllImport("J58.dll", EntryPoint = "BkscSetUserHookTarget", CallingConvention = CallingConvention.Cdecl,
                   CharSet = CharSet.Unicode, SetLastError = true)]
        [return:MarshalAs(UnmanagedType.Bool)]
        internal static extern bool SetUserHookTarget(IntPtr device, uint mode, uint processId, uint flags,
                                                      string? imagePath, uint analysisSubjectKind,
                                                      string? analysisSubjectPath, string? hookDllPath,
                                                      string? workingDirectory, string? environmentOverrides,
                                                      string? commandLineArguments, uint parentProcessId,
                                                      uint priorityClass, ulong affinityMask,
                                                      [MarshalAs(UnmanagedType.Bool)] bool inheritHandles,
                                                      uint integrityLevel, out BkSetUserHookTargetResponse response);

        internal static string WideBufferToString(ushort[]? buffer)
        {
            if (buffer == null || buffer.Length == 0)
            {
                return string.Empty;
            }

            int len = Array.IndexOf(buffer, (ushort)0);
            if (len < 0)
            {
                len = buffer.Length;
            }

            if (len == 0)
            {
                return string.Empty;
            }

            char[] chars = new char[len];
            for (int i = 0; i < len; i += 1)
            {
                chars[i] = (char)buffer[i];
            }

            return SanitizeTelemetryText(new string(chars));
        }

        internal static string AnsiBufferToString(byte[]? buffer)
        {
            if (buffer == null || buffer.Length == 0)
            {
                return string.Empty;
            }

            int len = Array.IndexOf(buffer, (byte)0);
            if (len < 0)
            {
                len = buffer.Length;
            }

            if (len == 0)
            {
                return string.Empty;
            }

            return SanitizeTelemetryText(System.Text.Encoding.ASCII.GetString(buffer, 0, len));
        }

        private static string SanitizeTelemetryText(string? value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return string.Empty;
            }

            string trimmed = value.Replace('\0', ' ').Trim();
            if (trimmed.Length == 0)
            {
                return string.Empty;
            }

            Span<char> scratch = stackalloc char[trimmed.Length];
            int written = 0;
            for (int i = 0; i < trimmed.Length; i += 1)
            {
                char ch = trimmed[i];
                if (!char.IsControl(ch) || ch == '\t')
                {
                    scratch[written++] = ch;
                }
            }

            return written == 0 ? string.Empty : new string(scratch.Slice(0, written));
        }

        internal static Win32Exception LastError(string context)
        {
            int err = Marshal.GetLastWin32Error();
            return new Win32Exception(err, $"{context} (win32={err})");
        }

        internal static string? ValidateManagedAbiLayout()
        {
            string? error = null;

            CheckAbiSize(nameof(BkStatsResponse), Marshal.SizeOf<BkStatsResponse>(), 528, ref error);
            CheckAbiSize(nameof(BkHealthResponse), Marshal.SizeOf<BkHealthResponse>(), 16, ref error);
            CheckAbiSize(nameof(BkDiagnosticEvent), Marshal.SizeOf<BkDiagnosticEvent>(), 48, ref error);
            CheckAbiSize(nameof(BkDiagnosticComponentState), Marshal.SizeOf<BkDiagnosticComponentState>(), 32,
                         ref error);
            CheckAbiSize(nameof(BkDiagnosticNtApiHookState), Marshal.SizeOf<BkDiagnosticNtApiHookState>(), 32,
                         ref error);
            CheckAbiSize(nameof(BkDiagnosticSanitizerState), Marshal.SizeOf<BkDiagnosticSanitizerState>(), 32,
                         ref error);
            CheckAbiSize(nameof(BkQpcTimingState), Marshal.SizeOf<BkQpcTimingState>(), 88, ref error);
            CheckAbiSize(nameof(BkDiagnosticsResponse), Marshal.SizeOf<BkDiagnosticsResponse>(), 7360, ref error);

            return error;
        }

        private static void CheckAbiSize(string name, int actual, int expected, ref string? error)
        {
            if (actual == expected || error != null)
            {
                return;
            }

            error = $"{name} managed size={actual} expected native size={expected}";
        }

        internal static bool TryParseIoctlEvent(byte[] buffer, int bytesRead, out IoctlParsedEvent parsed)
        {
            parsed = new IoctlParsedEvent();
            if (bytesRead < 24)
            {
                return false;
            }

            uint type = ReadU32(buffer, 4);
            parsed.Type = type;
            parsed.StreamMask = ReadU32(buffer, 8);
            parsed.Sequence = ReadU32(buffer, 12);

            const int payloadOffset = 24;
            if (type == EventTypeHandle)
            {
                const int baseHandlePayloadSize = 744;
                const int fullFrameSlots = 32;
                const int stackSnapshotBytes = 256;
                if (bytesRead < payloadOffset + baseHandlePayloadSize)
                {
                    return false;
                }

                parsed.CallerPid = ToPid(ReadU64(buffer, payloadOffset + 0));
                parsed.TargetPid = ToPid(ReadU64(buffer, payloadOffset + 8));
                parsed.DesiredAccess = ReadU32(buffer, payloadOffset + 16);
                parsed.HandleClass = ReadU32(buffer, payloadOffset + 20);
                parsed.OriginAddress = ReadU64(buffer, payloadOffset + 24);
                parsed.OriginProtect = ReadU32(buffer, payloadOffset + 32);
                parsed.HandleFlags = ReadU32(buffer, payloadOffset + 36);
                parsed.FrameCount = ReadU32(buffer, payloadOffset + 40);
                parsed.Frames = new ulong[8];
                for (int i = 0; i < parsed.Frames.Length; i += 1)
                {
                    parsed.Frames[i] = ReadU64(buffer, payloadOffset + 48 + (i * 8));
                }
                parsed.StatusOpenProcess = ReadI32(buffer, payloadOffset + 112);
                parsed.StatusBasicInfo = ReadI32(buffer, payloadOffset + 116);
                parsed.StatusSectionName = ReadI32(buffer, payloadOffset + 120);
                parsed.DeepAllocationBase = ReadU64(buffer, payloadOffset + 128);
                parsed.DeepRegionSize = ReadU64(buffer, payloadOffset + 136);
                parsed.DeepRegionProtect = ReadU32(buffer, payloadOffset + 144);
                parsed.DeepRegionState = ReadU32(buffer, payloadOffset + 148);
                parsed.DeepRegionType = ReadU32(buffer, payloadOffset + 152);
                parsed.DeepSampleSize = ReadU32(buffer, payloadOffset + 156);
                parsed.DeepSample = new byte[64];
                int deepCopy =
                    Math.Min(parsed.DeepSample.Length,
                             Math.Min((int)parsed.DeepSampleSize, Math.Max(0, bytesRead - (payloadOffset + 160))));
                if (deepCopy > 0)
                {
                    Buffer.BlockCopy(buffer, payloadOffset + 160, parsed.DeepSample, 0, deepCopy);
                }
                parsed.OriginPath = ReadWideFixedString(buffer, payloadOffset + 224, 260);

                int extendedBase = payloadOffset + baseHandlePayloadSize;
                parsed.CaptureFlags = ReadU32(buffer, extendedBase + 0);
                parsed.FullFrameCount = ReadU32(buffer, extendedBase + 4);
                parsed.FullFrames = new ulong[fullFrameSlots];
                for (int i = 0; i < parsed.FullFrames.Length; i += 1)
                {
                    parsed.FullFrames[i] = ReadU64(buffer, extendedBase + 8 + (i * 8));
                }

                int registerOffset = extendedBase + 264;
                parsed.RegRax = ReadU64(buffer, registerOffset + 0);
                parsed.RegRbx = ReadU64(buffer, registerOffset + 8);
                parsed.RegRcx = ReadU64(buffer, registerOffset + 16);
                parsed.RegRdx = ReadU64(buffer, registerOffset + 24);
                parsed.RegRsi = ReadU64(buffer, registerOffset + 32);
                parsed.RegRdi = ReadU64(buffer, registerOffset + 40);
                parsed.RegRbp = ReadU64(buffer, registerOffset + 48);
                parsed.RegRsp = ReadU64(buffer, registerOffset + 56);
                parsed.RegR8 = ReadU64(buffer, registerOffset + 64);
                parsed.RegR9 = ReadU64(buffer, registerOffset + 72);
                parsed.RegR10 = ReadU64(buffer, registerOffset + 80);
                parsed.RegR11 = ReadU64(buffer, registerOffset + 88);
                parsed.RegR12 = ReadU64(buffer, registerOffset + 96);
                parsed.RegR13 = ReadU64(buffer, registerOffset + 104);
                parsed.RegR14 = ReadU64(buffer, registerOffset + 112);
                parsed.RegR15 = ReadU64(buffer, registerOffset + 120);
                parsed.RegRip = ReadU64(buffer, registerOffset + 128);
                parsed.RegEFlags = ReadU64(buffer, registerOffset + 136);
                parsed.RegDr0 = ReadU64(buffer, registerOffset + 144);
                parsed.RegDr1 = ReadU64(buffer, registerOffset + 152);
                parsed.RegDr2 = ReadU64(buffer, registerOffset + 160);
                parsed.RegDr3 = ReadU64(buffer, registerOffset + 168);
                parsed.RegDr6 = ReadU64(buffer, registerOffset + 176);
                parsed.RegDr7 = ReadU64(buffer, registerOffset + 184);
                parsed.StackSnapshotAddress = ReadU64(buffer, registerOffset + 192);
                parsed.StackSnapshotSize = ReadU32(buffer, registerOffset + 200);
                parsed.StackSnapshot = new byte[stackSnapshotBytes];
                int stackCopy =
                    Math.Min(parsed.StackSnapshot.Length,
                             Math.Min((int)parsed.StackSnapshotSize, Math.Max(0, bytesRead - (registerOffset + 204))));
                if (stackCopy > 0)
                {
                    Buffer.BlockCopy(buffer, registerOffset + 204, parsed.StackSnapshot, 0, stackCopy);
                }
                return true;
            }

            if (type == EventTypeThread)
            {
                const int threadPayloadSize = 120;
                if (bytesRead < payloadOffset + threadPayloadSize)
                {
                    return false;
                }

                parsed.ProcessPid = ToPid(ReadU64(buffer, payloadOffset + 0));
                parsed.ThreadId = ToPid(ReadU64(buffer, payloadOffset + 8));
                parsed.CreatorPid = ToPid(ReadU64(buffer, payloadOffset + 16));
                parsed.StartAddress = ReadU64(buffer, payloadOffset + 24);
                parsed.ImageBase = ReadU64(buffer, payloadOffset + 32);
                parsed.ImageSize = ReadU64(buffer, payloadOffset + 40);
                parsed.ThreadFlags = ReadU32(buffer, payloadOffset + 48);
                parsed.ThreadFrameCount = ReadU32(buffer, payloadOffset + 52);
                parsed.ThreadFrames = new ulong[8];
                for (int i = 0; i < parsed.ThreadFrames.Length; i += 1)
                {
                    parsed.ThreadFrames[i] = ReadU64(buffer, payloadOffset + 56 + (i * 8));
                }
                return true;
            }

            if (type == EventTypeFileSystem)
            {
                const int filePayloadSize = 1140;
                if (bytesRead < payloadOffset + filePayloadSize)
                {
                    return false;
                }

                parsed.FileProcessPid = ToPid(ReadU64(buffer, payloadOffset + 0));
                parsed.FileThreadId = ToPid(ReadU64(buffer, payloadOffset + 8));
                parsed.FileObject = ReadU64(buffer, payloadOffset + 16);
                parsed.FileId = ReadU64(buffer, payloadOffset + 24);
                parsed.FileByteOffset = ReadU64(buffer, payloadOffset + 32);
                parsed.FileLength = ReadU64(buffer, payloadOffset + 40);
                parsed.FileStatus = ReadU64(buffer, payloadOffset + 48);
                parsed.FileInformation = ReadU64(buffer, payloadOffset + 56);
                parsed.FileOperation = ReadU32(buffer, payloadOffset + 64);
                parsed.FileMajorCode = ReadU32(buffer, payloadOffset + 68);
                parsed.FileMinorCode = ReadU32(buffer, payloadOffset + 72);
                parsed.FileIrpFlags = ReadU32(buffer, payloadOffset + 76);
                parsed.FileCreateOptions = ReadU32(buffer, payloadOffset + 80);
                parsed.FileCreateDisposition = ReadU32(buffer, payloadOffset + 84);
                parsed.FileDesiredAccess = ReadU32(buffer, payloadOffset + 88);
                parsed.FileShareAccess = ReadU32(buffer, payloadOffset + 92);
                parsed.FileFlags = ReadU32(buffer, payloadOffset + 96);
                parsed.FilePath = ReadWideFixedString(buffer, payloadOffset + 100, 520);
                return true;
            }

            if (type == EventTypeRegistry)
            {
                const int registryPayloadSize = 1320;
                if (bytesRead < payloadOffset + registryPayloadSize)
                {
                    return false;
                }

                parsed.RegistryProcessPid = ToPid(ReadU64(buffer, payloadOffset + 0));
                parsed.RegistryThreadId = ToPid(ReadU64(buffer, payloadOffset + 8));
                parsed.RegistryOperation = ReadU32(buffer, payloadOffset + 16);
                parsed.RegistryNotifyClass = ReadU32(buffer, payloadOffset + 20);
                parsed.RegistryDataType = ReadU32(buffer, payloadOffset + 24);
                parsed.RegistryDataSize = ReadU32(buffer, payloadOffset + 28);
                parsed.RegistryFlags = ReadU32(buffer, payloadOffset + 32);
                parsed.RegistrySessionId = ReadU32(buffer, payloadOffset + 36);
                parsed.RegistryKeyPath = ReadWideFixedString(buffer, payloadOffset + 40, 512);
                parsed.RegistryValueName = ReadWideFixedString(buffer, payloadOffset + 1064, 128);
                return true;
            }

            return false;
        }

        private static uint ToPid(ulong value)
        {
            return value > uint.MaxValue ? 0u : (uint)value;
        }

        private static uint ReadU32(byte[] buffer, int offset)
        {
            if (offset < 0 || offset + 4 > buffer.Length)
            {
                return 0;
            }

            return BinaryPrimitives.ReadUInt32LittleEndian(buffer.AsSpan(offset, 4));
        }

        private static int ReadI32(byte[] buffer, int offset)
        {
            if (offset < 0 || offset + 4 > buffer.Length)
            {
                return 0;
            }

            return BinaryPrimitives.ReadInt32LittleEndian(buffer.AsSpan(offset, 4));
        }

        private static ulong ReadU64(byte[] buffer, int offset)
        {
            if (offset < 0 || offset + 8 > buffer.Length)
            {
                return 0;
            }

            return BinaryPrimitives.ReadUInt64LittleEndian(buffer.AsSpan(offset, 8));
        }

        private static string ReadWideFixedString(byte[] buffer, int offset, int maxChars)
        {
            if (offset < 0 || maxChars <= 0 || offset >= buffer.Length)
            {
                return string.Empty;
            }

            int maxBytes = Math.Min(maxChars * 2, buffer.Length - offset);
            if (maxBytes <= 0)
            {
                return string.Empty;
            }

            int terminator = -1;
            for (int i = 0; i + 1 < maxBytes; i += 2)
            {
                if (buffer[offset + i] == 0 && buffer[offset + i + 1] == 0)
                {
                    terminator = i;
                    break;
                }
            }

            int lenBytes = terminator >= 0 ? terminator : maxBytes;
            if (lenBytes <= 0)
            {
                return string.Empty;
            }
            return System.Text.Encoding.Unicode.GetString(buffer, offset, lenBytes);
        }
    }
}
