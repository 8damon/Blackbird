using BlackbirdInterface.Capture;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;

namespace BlackbirdInterface
{
    public partial class MainWindow
    {
        private BlackbirdBackendSession? _backendSession;
        private int _backendGeneration;
        private Action<IoctlParsedEvent>? _sessionIoctlHandler;
        private Action<BlackbirdNative.BkIpcEtwEvent>? _sessionEtwHandler;
        private Action<BackendStatsView>? _sessionStatsHandler;
        private Action<string>? _sessionStatusHandler;
        private CaptureProjectionEngine? _captureProjection;
        private PackerDetectionService? _packerDetector;
        private readonly Dictionary<int, List<GroupedEventRow>> _etwHistoryByPid = new();
        private readonly Dictionary<int, List<GroupedEventRow>> _heuristicsHistoryByPid = new();
        private readonly Dictionary<int, List<GroupedEventRow>> _filesystemHistoryByPid = new();
        private readonly Dictionary<int, List<GroupedEventRow>> _registryHistoryByPid = new();
        private readonly Dictionary<int, List<GroupedEventRow>> _relationsHistoryByPid = new();
        private readonly Dictionary<int, List<ApiCallGraphRowSnapshot>> _apiGraphHistoryByPid = new();
        private readonly Dictionary<int, List<ExtendedActivityRowSnapshot>> _extendedHistoryByPid = new();
        private readonly Dictionary<string, ApiCallGraphRowSnapshot> _apiGraphRowsByKey = new(StringComparer.Ordinal);
        private readonly Dictionary<string, ExtendedActivityRowSnapshot> _extendedRowsByKey =
            new(StringComparer.Ordinal);
        private readonly Dictionary<string, string> _apiGraphReasonByKey = new(StringComparer.Ordinal);
        private readonly Dictionary<string, string> _apiGraphActionByKey = new(StringComparer.Ordinal);
        private readonly Dictionary<string, string> _apiGraphDecodedByKey = new(StringComparer.Ordinal);
        private readonly Dictionary<string, string> _apiGraphFramesByKey = new(StringComparer.Ordinal);
        private readonly Dictionary<string, string> _apiGraphSensorByKey = new(StringComparer.Ordinal);
        private readonly Dictionary<string, DateTime> _apiGraphTimelineLastEmitByKey = new(StringComparer.Ordinal);
        private readonly Dictionary<string, DateTime> _observedHookStackLastPersistByThread =
            new(StringComparer.Ordinal);
        private readonly Dictionary<string, DateTime> _threadStackFallbackLastCaptureByThread =
            new(StringComparer.Ordinal);
        private readonly ConcurrentDictionary<string, byte> _pendingThreadStackFallbackCaptures =
            new(StringComparer.Ordinal);
        private readonly Dictionary<ulong, ApiMemoryPageSignal> _apiMemorySignalsByPage = new();
        private readonly Dictionary<uint, string> _targetExitReasonByPid = new();
        private long _usermodeHookEventCount;
        private long _kernelHookEventCount;
        private bool _apiGraphSnapshotDirty;
        private bool _extendedViewSnapshotDirty;

        private BlackbirdPreflightReport? _lastPreflight;
        private string? _lastConnectivityIssueSignature;
        private readonly ConcurrentQueue<IoctlParsedEvent> _pendingIoctlEvents = new();
        private readonly ConcurrentQueue<BlackbirdNative.BkIpcEtwEvent> _pendingEtwEvents = new();
        private readonly ConcurrentQueue<string> _pendingStatusLines = new();
        private readonly ConcurrentQueue<BackendUiWorkItem> _pendingUiWork = new();
        private readonly AutoResetEvent _backendTransformSignal = new(false);
        private CancellationTokenSource? _backendTransformCts;
        private Task? _backendTransformTask;
        private readonly ConcurrentDictionary<uint, byte> _pendingMonitoredProcessRegistrations = new();
        private long _pendingIoctlCount;
        private long _pendingEtwCount;
        private long _pendingStatusCount;
        private long _pendingUiWorkCount;
        private long _droppedIoctlForPressure;
        private long _droppedEtwForPressure;
        private long _droppedUiWorkForPressure;
        private int _backendUiFlushScheduled;
        private const int MaxBackendTransformItemsPerBatch = 1500;
        private const int MaxBackendUiItemsPerFlush = 220;
        private const int MaxBackendUiItemsPerFlushUnderPressure = 1400;
        private const int MaxBackendStatusLinesPerTransformBatch = 64;
        private const int MaxBackendStatusLinesPerUiFlush = 32;
        private const int FilesystemTimelineClusterFlushCount = 600;
        private const int MaxRecentImageFileAccesses = 2048;
        private const int MaxRecentImageMapStates = 2048;
        private const int MaxPendingIoctlEvents = 30000;
        private const int MaxPendingEtwEvents = 18000;
        private const int MaxPendingUiWorkItems = 20000;
        private const int IoctlPressureSoftLimit = (MaxPendingIoctlEvents * 7) / 10;
        private const int IoctlPressureCriticalLimit = (MaxPendingIoctlEvents * 9) / 10;
        private const int EtwPressureSoftLimit = (MaxPendingEtwEvents * 7) / 10;
        private const int EtwPressureCriticalLimit = (MaxPendingEtwEvents * 9) / 10;
        private const double MemoryHighEntropyBits = 7.15;
        private const double MemoryEntropyFlipDeltaBits = 0.55;
        private const uint MemoryEntropyMinSampleBytes = 32;
        private const uint CorrelationIntentMask = 0x00000007u;
        private const uint HandleFlagExecProtect = 0x00000001u;
        private const uint HandleFlagFromNtdll = 0x00000002u;
        private const uint HandleFlagFromExe = 0x00000004u;
        private const uint HandleFlagThreadObject = 0x00000010u;
        private const uint HandleFlagDuplicateOperation = 0x00000020u;
        private const uint HandleFlagStackValidated = 0x00000400u;
        private const uint HandleFlagStackSpoofSuspect = 0x00000800u;
        private const uint HandleFlagSyscallExportMatch = 0x00001000u;
        private const uint HandleFlagSyscallExportMismatch = 0x00002000u;
        private const uint HandleFlagTebStackBoundsValid = 0x00010000u;
        private const uint HandleFlagFramesOutsideTebStack = 0x00020000u;
        private const uint HighSignalHandleMask = HandleFlagStackSpoofSuspect | HandleFlagSyscallExportMismatch;
        private const uint ThreadHighSignalMask =
            0x00000004u | 0x00000008u | 0x00000010u | 0x00000020u | 0x00000040u | 0x00000080u | 0x00000100u;
        private static readonly TimeSpan BackendUiFlushBudget = TimeSpan.FromMilliseconds(5);
        private static readonly TimeSpan BackendUiFlushBudgetUnderPressure = TimeSpan.FromMilliseconds(18);
        private static readonly TimeSpan FilesystemTimelineClusterWindow = TimeSpan.FromMilliseconds(15000);
        private static readonly TimeSpan FilesystemTimelineClusterIdleFlush = TimeSpan.FromMilliseconds(1500);
        private static readonly TimeSpan ApiTimelineEmissionWindow = TimeSpan.FromSeconds(5);
        private static readonly TimeSpan ImageMapFileCorrelationWindow = TimeSpan.FromSeconds(4);
        private static readonly TimeSpan ImageMapRepeatWindow = TimeSpan.FromSeconds(45);
        private static readonly(string Token, string Label)[] VirtualizationArtifactPatterns = {
            ("\\VBoxGuest", "VirtualBox guest driver"),
            ("\\VBoxMouse", "VirtualBox mouse driver"),
            ("\\VBoxMini", "VirtualBox mini redirector"),
            ("\\VBoxSF", "VirtualBox shared folders"),
            ("\\VBoxVideo", "VirtualBox video driver"),
            ("VirtualBox Guest Additions", "VirtualBox guest additions"),
            ("Oracle\\VirtualBox", "VirtualBox registry key"),
            ("VBOX__", "VirtualBox ACPI firmware marker"),
            ("VEN_80EE", "VirtualBox PCI vendor"),
            ("DiskVBOX", "VirtualBox disk vendor"),
            ("SystemBiosVersion\\VBOX", "VirtualBox BIOS marker"),
            ("\\vmhgfs", "VMware shared folders"),
            ("\\vmmouse", "VMware mouse driver"),
            ("\\vmci", "VMware VMCI driver"),
            ("\\vmx_svga", "VMware SVGA driver"),
            ("VMware Tools", "VMware tools"),
            ("VMware, Inc.", "VMware registry key"),
            ("VEN_15AD", "VMware PCI vendor"),
            ("DiskVMware", "VMware disk vendor"),
            ("VMW0003", "VMware ACPI marker"),
            ("qemu-ga", "QEMU guest agent"),
            ("\\qemufwcfg", "QEMU firmware config driver"),
            ("QEMU HARDDISK", "QEMU disk vendor"),
            ("Red Hat VirtIO", "QEMU/VirtIO vendor"),
            ("\\viostor", "VirtIO storage driver"),
            ("\\viofs", "VirtIO filesystem driver"),
            ("\\netkvm", "VirtIO network driver"),
            ("\\balloon", "VirtIO balloon driver"),
            ("VEN_1AF4", "VirtIO PCI vendor"),
            ("\\xen", "Xen driver or registry key"),
            ("XenTools", "Xen tools"),
            ("VEN_5853", "Xen PCI vendor"),
            ("\\prl_", "Parallels driver"),
            ("Parallels Tools", "Parallels tools"),
            ("VEN_1AB8", "Parallels PCI vendor"),
            ("Hyper-V", "Hyper-V registry key"),
            ("\\VMBus", "Hyper-V VMBus driver"),
            ("VID_1414", "Microsoft Hyper-V vendor"),
            ("SystemManufacturer\\Microsoft Corporation", "Microsoft virtual machine manufacturer")
        };
        private string? _lastEtwTimelineSignature;
        private DateTime _lastEtwTimelineTimestampUtc;
        private readonly Dictionary<ulong, IoctlParsedEvent> _recentHandleEvidenceByPair = new();
        private DateTime _lastHandleEvidencePruneUtc = DateTime.MinValue;
        private readonly Dictionary<string, int> _filesystemClusterOperationCounts = new(StringComparer.Ordinal);
        private readonly Dictionary<string, (uint Pid, uint Tid, string Path, uint Operation)>
            _filesystemClusterSamplesByOperation = new(StringComparer.Ordinal);
        private readonly Dictionary<string, int> _crossProcWriteCountByPair = new(StringComparer.Ordinal);
        private readonly Dictionary<string, int> _crossProcRwxAllocCountByPair = new(StringComparer.Ordinal);
        private readonly Dictionary<string, int> _antiAnalysisCountByEvidence = new(StringComparer.OrdinalIgnoreCase);
        private readonly object _imageMapCorrelationLock = new();
        private readonly List<RecentImageFileAccess> _recentImageFileAccesses = new();
        private readonly Dictionary<string, RecentImageMapState> _recentImageMapByPidPath =
            new(StringComparer.OrdinalIgnoreCase);
        private DateTime _lastImageMapCorrelationPruneUtc = DateTime.MinValue;
        private readonly Dictionary<uint, DateTime> _observedProcessStartUtcByPid = new();
        private readonly Dictionary<uint, ulong> _observedProcessStartKeyByPid = new();
        private readonly Dictionary<uint, uint> _observedInitialThreadIdByPid = new();
        private readonly Dictionary<string, RegionLifecycleState> _regionLifecycleByIdentity =
            new(StringComparer.Ordinal);
        private readonly Dictionary<string, ulong> _functionTableBaseByPointer = new(StringComparer.Ordinal);
        private volatile int _filterRootPid;
        private readonly ConcurrentDictionary<uint, byte> _filterTrackedPids = new();
        private volatile int _focusedPid;
        internal ObservableCollection<MonitoredProcessEntry> MonitoredProcesses { get; } = new();
        private readonly HashSet<uint> _monitoredProcessSet = new();
        private int _filesystemClusterTotal;
        private DateTime _filesystemClusterWindowStartUtc = DateTime.MinValue;
        private DateTime _filesystemClusterLastSeenUtc = DateTime.MinValue;

        private sealed class RegionLifecycleState
        {
            public ulong ProcessStartKey { get; set; }
            public uint TargetPid { get; set; }
            public ulong BaseAddress { get; set; }
            public ulong RegionSize { get; set; }
            public string RegionKind { get; set; } = string.Empty;
            public string ExecutionContext { get; set; } = string.Empty;
            public bool ObservedByKernel { get; set; }
            public bool ObservedByUserHook { get; set; }
            public bool BlackbirdOwned { get; set; }
            public bool CrossProcess { get; set; }
            public bool ImageBacked { get; set; }
            public uint InitialProtection { get; set; }
            public uint PreviousProtection { get; set; }
            public uint CurrentProtection { get; set; }
            public bool FirstExecutableTransitionSeen { get; set; }
            public bool FirstThreadStartSeen { get; set; }
            public ulong FirstThreadStartAddress { get; set; }
            public bool FunctionTableRegistered { get; set; }
            public uint MapCount { get; set; }
            public uint WriteCount { get; set; }
            public uint ProtectCount { get; set; }
            public uint ThreadStartCount { get; set; }
            public uint ProtectFlipCount { get; set; }
            public uint RapidProtectFlipCount { get; set; }
            public uint ExecutableFlipCount { get; set; }
            public uint GuardNoAccessFlipCount { get; set; }
            public uint WritableExecutableFlipCount { get; set; }
            public string LastProtectionTransition { get; set; } = string.Empty;
            public DateTime LastProtectChangeUtc { get; set; }
            public double LastEntropyBits { get; set; } = -1;
            public double MaxEntropyBits { get; set; } = -1;
            public uint EntropyFlipCount { get; set; }
            public uint RapidEntropyFlipCount { get; set; }
            public uint HighEntropyWriteCount { get; set; }
            public DateTime LastEntropyChangeUtc { get; set; }
            public uint LastSampleBytes { get; set; }
        }
    }
}
