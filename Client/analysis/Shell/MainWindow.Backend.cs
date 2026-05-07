using BlackbirdInterface.Capture;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Globalization;
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

        public void SetFocusedPid(int pid)
        {
            _focusedPid = pid;
            BroadcastFocusedPid(pid);
            RefreshProcessSelectorBar();
        }

        private void BroadcastFocusedPid(int pid)
        {
            EtwPaneHost.FocusedPid = pid;
            EventsPaneHost.FocusedPid = pid;
            HeuristicsPaneHost.FocusedPid = pid;
            FilesystemPaneHost.FocusedPid = pid;
            ProcessRelationsPaneHost.FocusedPid = pid;
        }

        private void RefreshProcessSelectorBar()
        {
            ProcessSelectorBarPanel.Children.Clear();

            var allBtn =
                new System.Windows.Controls.Button { Content = "All", Margin = new System.Windows.Thickness(2, 2, 2, 2),
                                                     Padding = new System.Windows.Thickness(8, 2, 8, 2), FontSize = 11,
                                                     Tag = 0 };
            allBtn.Click += (_, __) => SetFocusedPid(0);
            ProcessSelectorBarPanel.Children.Add(allBtn);

            foreach (MonitoredProcessEntry entry in MonitoredProcesses)
            {
                var btn = new System.Windows.Controls.Button { Content = entry.Label,
                                                               Margin = new System.Windows.Thickness(2, 2, 2, 2),
                                                               Padding = new System.Windows.Thickness(8, 2, 8, 2),
                                                               FontSize = 11,
                                                               Tag = (int)entry.Pid,
                                                               FontWeight = (_focusedPid == (int)entry.Pid)
                                                                                ? System.Windows.FontWeights.Bold
                                                                                : System.Windows.FontWeights.Normal };
                var capturedPid = (int)entry.Pid;
                btn.Click += (_, __) => SetFocusedPid(capturedPid);
                ProcessSelectorBarPanel.Children.Add(btn);
            }

            ProcessSelectorBarBorder.Visibility =
                MonitoredProcesses.Count > 1 ? System.Windows.Visibility.Visible : System.Windows.Visibility.Collapsed;
        }

        private void TryRegisterMonitoredProcess(uint pid)
        {
            if (pid == 0 || _monitoredProcessSet.Contains(pid))
                return;

            _monitoredProcessSet.Add(pid);

            string imageName = string.Empty;
            try
            {
                imageName = ProcessIdentityResolver.Resolve(pid) ?? string.Empty;
            }
            catch
            {
            }

            MonitoredProcesses.Add(
                new MonitoredProcessEntry { Pid = pid, ImageName = imageName, FirstSeenUtc = DateTime.UtcNow });

            RefreshProcessSelectorBar();
        }

        private void RefreshSubsystemSegmentationDiagnostics()
        {
            bool kernelHooksEnabled = _currentSession?.KernelHooksEnabled ?? _kernelHooksArmed;
            bool usermodeHooksEnabled = _currentSession?.UseUsermodeHooks ?? false;
            bool signatureIntelEnabled = _currentSession?.SignatureIntelEnabled ?? _signatureIntelEnabled;
            bool memoryScanEnabled =
                _currentSession?.SignatureIntelMemoryScanEnabled ?? _signatureIntelMemoryScanEnabled;
            bool pageScanEnabled = _currentSession?.SignatureIntelPageScanEnabled ?? _signatureIntelPageScanEnabled;

            if (!kernelHooksEnabled)
            {
                DiagnosticsState.SetValue("Kernel Hooks", "Disabled by operator");
            }
            else
            {
                string? kernelHooks = DiagnosticsState.GetValue("Kernel Hooks");
                if (string.IsNullOrWhiteSpace(kernelHooks) ||
                    kernelHooks.Contains("Disabled", StringComparison.OrdinalIgnoreCase) ||
                    kernelHooks.Contains("Inactive", StringComparison.OrdinalIgnoreCase) ||
                    kernelHooks.Contains("Awaiting", StringComparison.OrdinalIgnoreCase))
                {
                    DiagnosticsState.SetValue("Kernel Hooks", "Awaiting telemetry");
                }
            }

            if (!usermodeHooksEnabled)
            {
                DiagnosticsState.SetValue("Usermode Hooks", "Disabled by operator");
                DiagnosticsState.SetValue("Hook Integrity", "Disabled (no usermode hooks)");
                DiagnosticsState.SetValue("AMSI Integrity", "Disabled (no usermode hooks)");
            }
            else
            {
                string? usermode = DiagnosticsState.GetValue("Usermode Hooks");
                if (string.IsNullOrWhiteSpace(usermode) ||
                    usermode.Contains("Inactive", StringComparison.OrdinalIgnoreCase) ||
                    usermode.Contains("Disabled", StringComparison.OrdinalIgnoreCase))
                {
                    DiagnosticsState.SetValue("Usermode Hooks", "Awaiting hook-ready");
                }

                if (string.Equals(DiagnosticsState.GetValue("Hook Integrity"), "Disabled (no usermode hooks)",
                                  StringComparison.OrdinalIgnoreCase))
                {
                    DiagnosticsState.SetValue("Hook Integrity", "Unknown");
                }
                if (string.Equals(DiagnosticsState.GetValue("AMSI Integrity"), "Disabled (no usermode hooks)",
                                  StringComparison.OrdinalIgnoreCase))
                {
                    DiagnosticsState.SetValue("AMSI Integrity", "Unknown");
                }
            }

            DiagnosticsState.SetValue(
                "Signature Intel",
                signatureIntelEnabled
                    ? $"Enabled memory={(memoryScanEnabled ? "on" : "off")} page={(pageScanEnabled ? "on" : "off")} hash=on"
                    : "Disabled by operator");
        }

        private void InitializeBackendUi()
        {
            EtwPaneHost.ClearAll();
            HeuristicsPaneHost.ClearAll();
            FilesystemPaneHost.ClearAll();
            RegistryPaneHost.ClearAll();
            ProcessRelationsPaneHost.ClearAll();
            _apiGraphRowsByKey.Clear();
            _captureProjection = null;
            _extendedRowsByKey.Clear();
            _apiGraphReasonByKey.Clear();
            _apiGraphActionByKey.Clear();
            _apiGraphDecodedByKey.Clear();
            _apiGraphFramesByKey.Clear();
            _apiGraphSensorByKey.Clear();
            _apiGraphTimelineLastEmitByKey.Clear();
            _observedHookStackLastPersistByThread.Clear();
            _threadStackFallbackLastCaptureByThread.Clear();
            _pendingThreadStackFallbackCaptures.Clear();
            _apiMemorySignalsByPage.Clear();
            _crossProcWriteCountByPair.Clear();
            _crossProcRwxAllocCountByPair.Clear();
            _antiAnalysisCountByEvidence.Clear();
            ResetImageMapCorrelationCaches();
            _observedProcessStartUtcByPid.Clear();
            _targetExitReasonByPid.Clear();
            _extendedViewRows.Clear();
            _extendedComRows.Clear();
            _extendedEtwRows.Clear();
            _extendedJobRows.Clear();
            _extendedYaraRows.Clear();
            _extendedViewSnapshotDirty = false;
            _extendedViewRefreshTimer.Stop();
            if (ExtendedViewSummaryBlock != null)
            {
                ExtendedViewSummaryBlock.Text = "No extended activity yet";
            }
            _observedProcessStartKeyByPid.Clear();
            _observedInitialThreadIdByPid.Clear();
            _regionLifecycleByIdentity.Clear();
            _functionTableBaseByPointer.Clear();
            PublishApiGraphSnapshot();
            ResetFilesystemTimelineCluster();
            ProcessRelationsPaneHost.SetRootPid(0);
            RefreshExplorerDataBadges();
            DiagnosticsState.SetValue("UI", "Initialized");
            DiagnosticsState.SetValue("Operator Connection Established", "Disabled in analyst interface");
            DiagnosticsState.SetValue("Hook Integrity", "Unknown");
            DiagnosticsState.SetValue("AMSI Integrity", "Unknown");
            DiagnosticsState.SetValue("ETW Integrity", "Unknown");
            DiagnosticsState.SetValue("ETW Status", "Ready");
            DiagnosticsState.SetValue("API Graph", "patterns=0/0 visible=False");
            RefreshSubsystemSegmentationDiagnostics();
        }

        private void StartBackendForPid(int pid, bool useUsermodeHooks, bool stopExistingSession = true,
                                        bool fastStopExistingSession = false)
        {
            BlackbirdBackendSession? preparedSession = null;

            if (stopExistingSession)
            {
                StopBackendSession(fastTeardown: fastStopExistingSession);
                OutputCapture.Clear();
            }
            else
            {
                ClearPendingBackendUiQueues();
            }

            if (pid <= 0)
            {
                DisposePreparedLaunchBackendSession();
                return;
            }

            if (_preparedLaunchBackendSession != null)
            {
                if (_preparedLaunchBackendPid == pid && useUsermodeHooks)
                {
                    preparedSession = _preparedLaunchBackendSession;
                    _preparedLaunchBackendSession = null;
                    _preparedLaunchBackendPid = 0;
                }
                else
                {
                    DisposePreparedLaunchBackendSession();
                }
            }

            _lastEtwTimelineSignature = null;
            _lastEtwTimelineTimestampUtc = DateTime.MinValue;
            ResetFilesystemTimelineCluster();
            ResetImageMapCorrelationCaches();

            int generation = ++_backendGeneration;
            try
            {
                _filterRootPid = pid;
                _captureProjection = new CaptureProjectionEngine(pid, $"ui-{pid}", "BlackbirdInterface");
                _filterTrackedPids.Clear();
                _filterTrackedPids.TryAdd((uint)pid, 0);
                _targetExitReasonByPid.Remove((uint)pid);
                _observedProcessStartUtcByPid[(uint)pid] = DateTime.UtcNow;
                MonitoredProcesses.Clear();
                _monitoredProcessSet.Clear();
                _focusedPid = 0;
                BroadcastFocusedPid(0);
                TryRegisterMonitoredProcess((uint)pid);
                if (_currentSession != null)
                {
                    _currentSession.UseUsermodeHooks = useUsermodeHooks;
                    _currentSession.KernelHooksEnabled = _kernelHooksArmed;
                    _currentSession.SignatureIntelEnabled = _signatureIntelEnabled;
                    _currentSession.SignatureIntelMemoryScanEnabled = _signatureIntelMemoryScanEnabled;
                    _currentSession.SignatureIntelPageScanEnabled = _signatureIntelPageScanEnabled;
                }
                RefreshSubsystemSegmentationDiagnostics();
                QueueSignatureIntelForRootPid(pid);

                var session =
                    preparedSession ?? BlackbirdBackendSession.Start(pid, BlackbirdNative.StreamAll, useUsermodeHooks);
                _backendSession = session;

                _sessionIoctlHandler = record =>
                {
                    if (generation != _backendGeneration)
                        return;
                    if (!ShouldTrackRawIoctlRecord(record))
                    {
                        return;
                    }

                    long pending = Interlocked.Read(ref _pendingIoctlCount);
                    if (!ShouldAdmitIoctlRecord(record, pending))
                    {
                        Interlocked.Increment(ref _droppedIoctlForPressure);
                        return;
                    }

                    _pendingIoctlEvents.Enqueue(record);
                    Interlocked.Increment(ref _pendingIoctlCount);
                    _backendTransformSignal.Set();
                };

                _sessionEtwHandler = etw =>
                {
                    if (generation != _backendGeneration)
                        return;
                    if (!ShouldTrackRawEtwEvent(etw))
                    {
                        return;
                    }

                    long pending = Interlocked.Read(ref _pendingEtwCount);
                    if (!ShouldAdmitEtwEvent(etw, pending))
                    {
                        Interlocked.Increment(ref _droppedEtwForPressure);
                        return;
                    }

                    _pendingEtwEvents.Enqueue(etw);
                    Interlocked.Increment(ref _pendingEtwCount);
                    _backendTransformSignal.Set();
                };

                _sessionStatsHandler = stats =>
                {
                    if (Dispatcher.HasShutdownStarted)
                        return;
                    Dispatcher.BeginInvoke(new Action(
                        () =>
                        {
                            if (generation != _backendGeneration)
                                return;
                            DiagnosticsState.SetValue(
                                "Session Stats",
                                $"subs={stats.SubscriptionCount} depth={stats.QueueDepth} dropped={stats.DroppedEvents}");
                        }));
                };

                _sessionStatusHandler = text =>
                {
                    if (generation != _backendGeneration)
                        return;
                    _captureProjection?.ObserveStatus(text);
                    _pendingStatusLines.Enqueue($"[session pid={pid}] {text}");
                    Interlocked.Increment(ref _pendingStatusCount);
                    _backendTransformSignal.Set();
                };

                session.IoctlEvent += _sessionIoctlHandler;
                session.EtwEvent += _sessionEtwHandler;
                session.Stats += _sessionStatsHandler;
                session.Status += _sessionStatusHandler;

                StartBackendTransformLoop(generation);

                StatusBlock.Text = $"Status: Session active for PID {pid}";
                OutputCapture.AppendLine($"Session started for PID {pid}");
                DiagnosticsState.SetValue("Session", $"Active PID {pid}");
                ProcessRelationsPaneHost.SetRootPid(pid);
            }
            catch (Exception ex)
            {
                if (preparedSession != null)
                {
                    try
                    {
                        preparedSession.Dispose();
                    }
                    catch
                    {
                    }
                }

                string displayError = FormatSessionStartError(ex);
                _backendSession = null;
                StatusBlock.Text = $"Status: Session start failed ({displayError})";
                OutputCapture.AppendLine($"Session start failed for PID {pid}: {displayError}");
                DiagnosticsState.SetValue("Session", $"Start failed PID {pid}");
                DiagnosticsState.SetValue("Connectivity", $"Session start failed: {displayError}");
                SetBackendConnectivity(false);
            }
        }

        private static string FormatSessionStartError(Exception ex)
        {
            if (ex is EntryPointNotFoundException)
            {
                return "IPC runtime DLL is outdated (missing export). Rebuild/deploy J58.dll and controller.";
            }

            if (ex is System.ComponentModel.Win32Exception wx &&
                (wx.NativeErrorCode == 127 || wx.NativeErrorCode == BlackbirdNative.ErrorInvalidFunction))
            {
                return "IPC runtime DLL/controller mismatch (missing function). Rebuild/deploy latest J58.dll and controller.";
            }

            if (ex is System.ComponentModel.Win32Exception brokerWx &&
                (brokerWx.NativeErrorCode == 109 || brokerWx.NativeErrorCode == 233))
            {
                return "Broker handshake failed because the loaded J58.dll does not match the running BlackbirdController build. Rebuild/redeploy both together.";
            }

            return ex.Message;
        }

        private void DetachSessionHandlers(BlackbirdBackendSession session)
        {
            if (_sessionIoctlHandler != null)
            {
                session.IoctlEvent -= _sessionIoctlHandler;
                _sessionIoctlHandler = null;
            }
            if (_sessionEtwHandler != null)
            {
                session.EtwEvent -= _sessionEtwHandler;
                _sessionEtwHandler = null;
            }
            if (_sessionStatsHandler != null)
            {
                session.Stats -= _sessionStatsHandler;
                _sessionStatsHandler = null;
            }
            if (_sessionStatusHandler != null)
            {
                session.Status -= _sessionStatusHandler;
                _sessionStatusHandler = null;
            }
        }

        private void StopBackendSession(bool preserveApiGraphSnapshot = false, bool fastTeardown = false)
        {
            _liveAnalysisSession = null;
            if (_backendSession == null)
            {
                StopBackendTransformLoop();
                DisposeLiveCaptureStore();
                ClearPendingBackendUiQueues();
                return;
            }

            try
            {
                DetachSessionHandlers(_backendSession);
                _backendSession.Dispose();
            }
            catch
            {
            }

            _backendSession = null;
            _captureProjection?.WaitForPendingStackCaptures(
                fastTeardown ? TimeSpan.FromMilliseconds(50) : TimeSpan.FromSeconds(1));
            _captureProjection = null;
            _filterRootPid = 0;
            _filterTrackedPids.Clear();
            _pendingMonitoredProcessRegistrations.Clear();
            StopBackendTransformLoop();
            DisposeLiveCaptureStore();
            ClearPendingBackendUiQueues();
            _lastEtwTimelineSignature = null;
            _lastEtwTimelineTimestampUtc = DateTime.MinValue;
            Interlocked.Exchange(ref _droppedIoctlForPressure, 0);
            Interlocked.Exchange(ref _droppedEtwForPressure, 0);
            Interlocked.Exchange(ref _droppedUiWorkForPressure, 0);
            ResetFilesystemTimelineCluster();
            ResetImageMapCorrelationCaches();
            if (!preserveApiGraphSnapshot)
            {
                _apiGraphRowsByKey.Clear();
                _extendedRowsByKey.Clear();
                _extendedViewRows.Clear();
                _extendedComRows.Clear();
                _extendedEtwRows.Clear();
                _extendedJobRows.Clear();
                _extendedYaraRows.Clear();
                _apiGraphReasonByKey.Clear();
                _apiGraphActionByKey.Clear();
                _apiGraphDecodedByKey.Clear();
                _apiGraphFramesByKey.Clear();
                _apiGraphSensorByKey.Clear();
                _apiGraphTimelineLastEmitByKey.Clear();
                _observedHookStackLastPersistByThread.Clear();
                _threadStackFallbackLastCaptureByThread.Clear();
                _pendingThreadStackFallbackCaptures.Clear();
                _apiMemorySignalsByPage.Clear();
                _crossProcWriteCountByPair.Clear();
                _crossProcRwxAllocCountByPair.Clear();
                _antiAnalysisCountByEvidence.Clear();
                ResetImageMapCorrelationCaches();
                _observedProcessStartUtcByPid.Clear();
                _targetExitReasonByPid.Clear();
                _extendedViewSnapshotDirty = false;
                _extendedViewRefreshTimer.Stop();
                if (ExtendedViewSummaryBlock != null)
                {
                    ExtendedViewSummaryBlock.Text = "No extended activity yet";
                }
                _observedProcessStartKeyByPid.Clear();
                _observedInitialThreadIdByPid.Clear();
                _regionLifecycleByIdentity.Clear();
                _functionTableBaseByPointer.Clear();
                PublishApiGraphSnapshot();
            }
            DiagnosticsState.SetValue("Session", "Stopped");
            DiagnosticsState.SetValue("Kernel Hooks", "Inactive");
            DiagnosticsState.SetValue("Usermode Hooks", "Inactive");
            DiagnosticsState.SetValue("Operator Connection Established", "Disabled in analyst interface");
            DiagnosticsState.SetValue("Hook Integrity", "Unknown");
            DiagnosticsState.SetValue("AMSI Integrity", "Unknown");
            DiagnosticsState.SetValue("ETW Integrity", "Unknown");
            DiagnosticsState.SetValue("Signature Intel", "Inactive");
        }

        private void ScheduleApiGraphSnapshot()
        {
            _apiGraphSnapshotDirty = true;
        }

        private void ApiGraphRefreshTimer_Tick(object? sender, EventArgs e)
        {
            if (!_apiGraphSnapshotDirty)
            {
                return;
            }

            _apiGraphSnapshotDirty = false;
            PublishApiGraphSnapshot();
        }

        private void StartBackendTransformLoop(int generation)
        {
            StopBackendTransformLoop();

            var cts = new CancellationTokenSource();
            _backendTransformCts = cts;
            _backendTransformTask = Task.Run(() => BackendTransformLoop(generation, cts.Token));
        }

        private void StopBackendTransformLoop()
        {
            CancellationTokenSource? cts = _backendTransformCts;
            Task? task = _backendTransformTask;
            _backendTransformCts = null;
            _backendTransformTask = null;
            if (cts == null)
            {
                return;
            }

            try
            {
                cts.Cancel();
                _backendTransformSignal.Set();
                task?.Wait(300);
            }
            catch
            {
            }
            finally
            {
                cts.Dispose();
            }
        }

        private void BackendTransformLoop(int generation, CancellationToken ct)
        {
            while (!ct.IsCancellationRequested && generation == _backendGeneration)
            {
                bool producedUiWork = false;
                int transformed = 0;
                int etwBudget =
                    Math.Min(MaxBackendTransformItemsPerBatch / 2, Math.Max(128, MaxBackendTransformItemsPerBatch));

                while (transformed < etwBudget && _pendingEtwEvents.TryDequeue(out var etw))
                {
                    Interlocked.Decrement(ref _pendingEtwCount);
                    BrokerEtwEventView view = BrokerEtwEventMapper.FromNative(etw);
                    _captureProjection?.ObserveEtw(view);
                    ProcessIdentityResolver.Prime(view.ActorPid);
                    ProcessIdentityResolver.Prime(view.TargetPid);

                    if (view.Family == BlackbirdNative.IpcEtwFamilyProcess &&
                        (view.Flags & BlackbirdNative.IpcEtwFlagProcessIsCreate) != 0)
                    {
                        uint etwCreator = view.CreatorPid != 0 ? view.CreatorPid : view.ActorPid;
                        uint etwChild = view.ProcessPid != 0 ? view.ProcessPid : view.TargetPid;
                        if (etwCreator != 0 && etwChild != 0 && etwCreator != etwChild &&
                            _filterTrackedPids.ContainsKey(etwCreator))
                        {
                            _filterTrackedPids.TryAdd(etwChild, 0);
                            QueueMonitoredProcessRegistration(generation, etwChild);
                        }
                    }

                    if (view.ActorPid != 0 && _filterTrackedPids.ContainsKey(view.ActorPid))
                    {
                        QueueMonitoredProcessRegistration(generation, view.ActorPid);
                    }

                    producedUiWork |= TryEnqueueUiWork(BackendUiWorkItem.FromEtw(view));
                    transformed += 1;
                }

                while (transformed < MaxBackendTransformItemsPerBatch && _pendingIoctlEvents.TryDequeue(out var ioctl))
                {
                    Interlocked.Decrement(ref _pendingIoctlCount);
                    DateTime nowUtc = DateTime.UtcNow;
                    _captureProjection?.ObserveIoctl(ioctl, nowUtc);
                    bool acceptFilesystem = ShouldAcceptFilesystemRecord(ioctl);
                    if (acceptFilesystem)
                    {
                        RememberRecentImageFileAccess(ioctl, nowUtc);
                    }

                    IReadOnlyList<TelemetryEvent> filesystemClusterEvents =
                        acceptFilesystem ? AccumulateFilesystemTimelineCluster(ioctl, nowUtc)
                                         : Array.Empty<TelemetryEvent>();
                    if (filesystemClusterEvents.Count > 0)
                    {
                        for (int i = 0; i < filesystemClusterEvents.Count; i += 1)
                        {
                            if (TryEnqueueUiWork(
                                    BackendUiWorkItem.FromIoctl(filesystemClusterEvents[i], null, null, null, null)))
                            {
                                producedUiWork = true;
                            }
                            else
                            {
                                break;
                            }
                        }
                    }

                    if (ioctl.Type == BlackbirdNative.EventTypeThread && ioctl.ProcessPid != 0 &&
                        ioctl.CreatorPid != 0 && ioctl.ProcessPid != ioctl.CreatorPid &&
                        _filterTrackedPids.ContainsKey(ioctl.CreatorPid))
                    {
                        _filterTrackedPids.TryAdd(ioctl.ProcessPid, 0);
                    }

                    TelemetryEvent? telemetry = MapIoctlRecord(ioctl);
                    ProcessRelationView? relation = MapIoctlRelation(ioctl);
                    HeuristicEventView? heuristic = MapIoctlHeuristic(ioctl);
                    IReadOnlyList<HeuristicEventView> signatureIntelIoctlFindings =
                        ShouldEvaluateSignatureIntelForIoctl(ioctl, acceptFilesystem)
                            ? EvaluateSignatureIntelForIoctl(ioctl)
                            : Array.Empty<HeuristicEventView>();
                    ThreadLifecycleEventSample? threadLifecycle = MapIoctlThreadLifecycle(ioctl);
                    IoctlParsedEvent? filesystem = acceptFilesystem ? MapIoctlFilesystem(ioctl) : null;
                    IoctlParsedEvent? registry = MapIoctlRegistry(ioctl);
                    if (relation != null)
                    {
                        ProcessIdentityResolver.Prime(relation.SourcePid);
                        ProcessIdentityResolver.Prime(relation.TargetPid);
                    }
                    if (heuristic != null)
                    {
                        ProcessIdentityResolver.Prime(heuristic.ActorPid);
                        ProcessIdentityResolver.Prime(heuristic.TargetPid);
                    }
                    if (signatureIntelIoctlFindings.Count > 0)
                    {
                        for (int i = 0; i < signatureIntelIoctlFindings.Count; i += 1)
                        {
                            ProcessIdentityResolver.Prime(signatureIntelIoctlFindings[i].ActorPid);
                            ProcessIdentityResolver.Prime(signatureIntelIoctlFindings[i].TargetPid);
                        }
                    }
                    if (filesystem != null)
                    {
                        ProcessIdentityResolver.Prime(filesystem.FileProcessPid);
                    }
                    if (registry != null)
                    {
                        ProcessIdentityResolver.Prime(registry.RegistryProcessPid);
                    }
                    if (ioctl.Type == BlackbirdNative.EventTypeEnterprise)
                    {
                        ProcessIdentityResolver.Prime(ioctl.EnterpriseProcessPid);
                        ProcessIdentityResolver.Prime(ioctl.EnterpriseTargetProcessPid);
                    }

                    if (acceptFilesystem &&
                        (ShouldPersistIoctlRecord(ioctl, telemetry, relation, heuristic, filesystem) ||
                         signatureIntelIoctlFindings.Count > 0))
                    {
                        AppendIoctlToCaptureStore(nowUtc, ioctl);
                    }

                    if (telemetry != null || relation != null || heuristic != null || threadLifecycle != null ||
                        filesystem != null || registry != null)
                    {
                        producedUiWork |= TryEnqueueUiWork(BackendUiWorkItem.FromIoctl(
                            telemetry, relation, heuristic, threadLifecycle, filesystem, registry));
                    }

                    if (signatureIntelIoctlFindings.Count > 0)
                    {
                        for (int i = 0; i < signatureIntelIoctlFindings.Count; i += 1)
                        {
                            producedUiWork |= TryEnqueueUiWork(
                                BackendUiWorkItem.FromIoctl(null, null, signatureIntelIoctlFindings[i], null, null));
                        }
                    }

                    transformed += 1;
                }

                int statusLines = 0;
                while (statusLines < MaxBackendStatusLinesPerTransformBatch &&
                       _pendingStatusLines.TryDequeue(out var statusLine))
                {
                    Interlocked.Decrement(ref _pendingStatusCount);
                    producedUiWork |= TryEnqueueUiWork(BackendUiWorkItem.FromStatus(statusLine));
                    statusLines += 1;
                }

                IReadOnlyList<TelemetryEvent> idleFilesystemClusters =
                    FlushFilesystemTimelineClusterIfNeeded(DateTime.UtcNow, force: false);
                if (idleFilesystemClusters.Count > 0)
                {
                    for (int i = 0; i < idleFilesystemClusters.Count; i += 1)
                    {
                        if (TryEnqueueUiWork(
                                BackendUiWorkItem.FromIoctl(idleFilesystemClusters[i], null, null, null, null)))
                        {
                            producedUiWork = true;
                        }
                        else
                        {
                            break;
                        }
                    }
                }

                if (producedUiWork)
                {
                    ScheduleBackendUiFlush(generation);
                    continue;
                }

                _backendTransformSignal.WaitOne(120);
            }
        }

        private void ScheduleBackendUiFlush(int generation)
        {
            if (Interlocked.Exchange(ref _backendUiFlushScheduled, 1) != 0)
            {
                return;
            }

            Dispatcher.BeginInvoke(new Action(() => FlushBackendUi(generation)), DispatcherPriority.Background);
        }

        private void FlushBackendUi(int generation)
        {
            Interlocked.Exchange(ref _backendUiFlushScheduled, 0);
            if (generation != _backendGeneration)
            {
                ClearPendingBackendUiQueues();
                return;
            }

            var stopwatch = Stopwatch.StartNew();
            int processed = 0;
            bool underPressure = Interlocked.Read(ref _pendingUiWorkCount) > (MaxPendingUiWorkItems / 2) ||
                                 Interlocked.Read(ref _pendingIoctlCount) > (MaxPendingIoctlEvents / 2) ||
                                 Interlocked.Read(ref _pendingEtwCount) > (MaxPendingEtwEvents / 2);
            int maxItemsThisFlush = underPressure ? MaxBackendUiItemsPerFlushUnderPressure : MaxBackendUiItemsPerFlush;
            TimeSpan budget = underPressure ? BackendUiFlushBudgetUnderPressure : BackendUiFlushBudget;
            var telemetryBatch = new List<TelemetryEvent>(96);
            var relationBatch = new List<ProcessRelationView>(32);
            var heuristicBatch = new List<HeuristicEventView>(32);
            var threadLifecycleBatch = new List<ThreadLifecycleEventSample>(32);
            var filesystemBatch = new List<IoctlParsedEvent>(32);
            var registryBatch = new List<IoctlParsedEvent>(32);
            var etwBatch = new List<BrokerEtwEventView>(96);
            var statusBatch = new List<string>(32);
            while (processed < maxItemsThisFlush && stopwatch.Elapsed < budget &&
                   _pendingUiWork.TryDequeue(out var uiWork))
            {
                Interlocked.Decrement(ref _pendingUiWorkCount);
                if (uiWork.Kind == BackendUiWorkKind.Status)
                {
                    if (statusBatch.Count < MaxBackendStatusLinesPerUiFlush &&
                        !string.IsNullOrWhiteSpace(uiWork.StatusLine))
                    {
                        statusBatch.Add(uiWork.StatusLine);
                    }
                }
                else if (uiWork.Kind == BackendUiWorkKind.Ioctl)
                {
                    if (uiWork.Telemetry != null)
                    {
                        telemetryBatch.Add(uiWork.Telemetry);
                    }
                    if (uiWork.Relation != null)
                    {
                        relationBatch.Add(uiWork.Relation);
                    }
                    if (uiWork.Heuristic != null)
                    {
                        heuristicBatch.Add(uiWork.Heuristic);
                    }
                    if (uiWork.ThreadLifecycle != null)
                    {
                        threadLifecycleBatch.Add(uiWork.ThreadLifecycle);
                    }
                    if (uiWork.Filesystem != null)
                    {
                        filesystemBatch.Add(uiWork.Filesystem);
                    }
                    if (uiWork.Registry != null)
                    {
                        registryBatch.Add(uiWork.Registry);
                    }
                }
                else if (uiWork.Kind == BackendUiWorkKind.Etw && uiWork.EtwView != null)
                {
                    etwBatch.Add(uiWork.EtwView);
                }

                processed += 1;
            }

            for (int i = 0; i < statusBatch.Count; i += 1)
            {
                OutputCapture.AppendLine(statusBatch[i]);
            }

            if (telemetryBatch.Count > 0)
            {
                AppendEvents(telemetryBatch);
            }

            if (relationBatch.Count > 0)
            {
                ProcessRelationsPaneHost.PushRelations(relationBatch);
                _explorer.FirstOrDefault(x => x.Name == "Process Relations")
                    ?.PushPreviewValue(ProcessRelationsPaneHost.TotalRawCount);
                SetExplorerHasData("Process Relations", ProcessRelationsPaneHost.ItemCount > 0);
            }

            if (heuristicBatch.Count > 0)
            {
                HeuristicsPaneHost.PushHeuristics(heuristicBatch);
                bool extendedChanged = false;
                for (int i = 0; i < heuristicBatch.Count; i += 1)
                {
                    extendedChanged |= ObserveSignatureIntelActivity(heuristicBatch[i]);
                }
                if (extendedChanged)
                {
                    ScheduleExtendedActivitySnapshot();
                }
                _explorer.FirstOrDefault(x => x.Name == "Heuristics")
                    ?.PushPreviewValue(HeuristicsPaneHost.TotalRawCount);
                SetExplorerHasData("Heuristics", HeuristicsPaneHost.ItemCount > 0);
                DiagnosticsState.Increment("Heuristics", heuristicBatch.Count);
            }

            if (threadLifecycleBatch.Count > 0)
            {
                PerformancePaneHost.PushThreadLifecycles(threadLifecycleBatch);
                if (_currentSession != null)
                {
                    for (int i = 0; i < threadLifecycleBatch.Count; i += 1)
                    {
                        _currentSession.ThreadLifecycleHistory.Add(CloneThreadLifecycleEvent(threadLifecycleBatch[i]));
                    }

                    if (_currentSession.ThreadLifecycleHistory.Count > 12_000)
                    {
                        _currentSession.ThreadLifecycleHistory.RemoveRange(
                            0, _currentSession.ThreadLifecycleHistory.Count - 12_000);
                    }
                }
            }

            if (filesystemBatch.Count > 0)
            {
                FilesystemPaneHost.PushFileEvents(filesystemBatch);
                _explorer.FirstOrDefault(x => x.Name == "Filesystem")
                    ?.PushPreviewValue(FilesystemPaneHost.TotalRawCount);
                SetExplorerHasData("Filesystem", FilesystemPaneHost.ItemCount > 0);
            }

            if (registryBatch.Count > 0)
            {
                RegistryPaneHost.PushRegistryEvents(registryBatch);
                _explorer.FirstOrDefault(x => x.Name == "Registry")?.PushPreviewValue(RegistryPaneHost.TotalRawCount);
                SetExplorerHasData("Registry", RegistryPaneHost.ItemCount > 0);
            }

            SpillCurrentSessionWorkingSetIfNeeded();

            if (etwBatch.Count > 0)
            {
                HandleBrokerEtwViews(etwBatch);
            }

            DiagnosticsState.SetValue(
                "UI Flush",
                $"items={processed} ms={stopwatch.Elapsed.TotalMilliseconds:0.0} pending={Interlocked.Read(ref _pendingUiWorkCount)}");

            if (HasPendingBackendUiData())
            {
                ScheduleBackendUiFlush(generation);
            }
        }

        private bool HasPendingBackendUiData()
        {
            return Interlocked.Read(ref _pendingIoctlCount) > 0 || Interlocked.Read(ref _pendingEtwCount) > 0 ||
                   Interlocked.Read(ref _pendingStatusCount) > 0 || Interlocked.Read(ref _pendingUiWorkCount) > 0;
        }

        private void ClearPendingBackendUiQueues()
        {
            while (_pendingIoctlEvents.TryDequeue(out _))
            {
            }

            while (_pendingEtwEvents.TryDequeue(out _))
            {
            }

            while (_pendingStatusLines.TryDequeue(out _))
            {
            }

            while (_pendingUiWork.TryDequeue(out _))
            {
            }

            Interlocked.Exchange(ref _pendingIoctlCount, 0);
            Interlocked.Exchange(ref _pendingEtwCount, 0);
            Interlocked.Exchange(ref _pendingStatusCount, 0);
            Interlocked.Exchange(ref _pendingUiWorkCount, 0);
            Interlocked.Exchange(ref _backendUiFlushScheduled, 0);
            ResetFilesystemTimelineCluster();
        }

        private bool TryEnqueueUiWork(BackendUiWorkItem item)
        {
            if (Interlocked.Read(ref _pendingUiWorkCount) >= MaxPendingUiWorkItems)
            {
                Interlocked.Increment(ref _droppedUiWorkForPressure);
                return false;
            }

            _pendingUiWork.Enqueue(item);
            Interlocked.Increment(ref _pendingUiWorkCount);
            return true;
        }

        private void QueueMonitoredProcessRegistration(int generation, uint pid)
        {
            if (pid == 0 || !_pendingMonitoredProcessRegistrations.TryAdd(pid, 0) || Dispatcher.HasShutdownStarted)
            {
                return;
            }

            Dispatcher.BeginInvoke(new Action(() =>
                                              {
                                                  _pendingMonitoredProcessRegistrations.TryRemove(pid, out _);
                                                  if (generation == _backendGeneration)
                                                  {
                                                      TryRegisterMonitoredProcess(pid);
                                                  }
                                              }),
                                   DispatcherPriority.Background);
        }

        private void AppendIoctlToCaptureStore(DateTime timestampUtc, IoctlParsedEvent record)
        {
            BlackbirdCaptureLiveStore? store = _liveCaptureStore;
            if (store == null)
            {
                return;
            }

            try
            {
                store.AppendIoctl(timestampUtc, record);
            }
            catch (Exception ex)
            {
                DiagnosticsState.SetValue("Capture Store", $"IOCTL append failed: {ex.Message}");
            }
        }

        private void AppendEtwToCaptureStore(BrokerEtwEventView view)
        {
            BlackbirdCaptureLiveStore? store = _liveCaptureStore;
            if (store == null)
            {
                return;
            }

            try
            {
                store.AppendEtw(view);
            }
            catch (Exception ex)
            {
                DiagnosticsState.SetValue("Capture Store", $"ETW append failed: {ex.Message}");
            }
        }

        private static ulong BuildRelationKey(uint actorPid, uint targetPid) => ((ulong)actorPid << 32) | targetPid;

        private void RememberHandleEvidence(IoctlParsedEvent record)
        {
            if (record.Type != BlackbirdNative.EventTypeHandle || record.CallerPid == 0 || record.TargetPid == 0)
            {
                return;
            }

            uint highSignalMask = 0x00000800 | 0x00002000;
            bool highRiskAccess = (record.DesiredAccess & (0x0002u | 0x0008u | 0x0010u | 0x0020u | 0x0800u)) != 0;
            if (!highRiskAccess)
            {
                bool processAll = (record.DesiredAccess & 0x001F0FFFu) == 0x001F0FFFu;
                bool threadAll = (record.DesiredAccess & 0x001F03FFu) == 0x001F03FFu;
                highRiskAccess = processAll || threadAll;
            }
            bool suspicious = record.HandleClass == 2 || ((record.HandleFlags & highSignalMask) != 0);
            if (!highRiskAccess && !suspicious)
            {
                return;
            }

            _recentHandleEvidenceByPair[BuildRelationKey(record.CallerPid, record.TargetPid)] = record;
            _recentHandleEvidenceByPair[BuildRelationKey(record.TargetPid, record.CallerPid)] = record;

            DateTime now = DateTime.UtcNow;
            if ((now - _lastHandleEvidencePruneUtc).TotalSeconds < 20)
            {
                return;
            }

            _lastHandleEvidencePruneUtc = now;
            if (_recentHandleEvidenceByPair.Count > 4096)
            {
                _recentHandleEvidenceByPair.Clear();
            }
        }

        private bool TryGetHandleEvidence(uint actorPid, uint targetPid, out IoctlParsedEvent evidence)
        {
            if (_recentHandleEvidenceByPair.TryGetValue(BuildRelationKey(actorPid, targetPid), out IoctlParsedEvent? found))
            {
                evidence = found;
                return true;
            }

            evidence = new IoctlParsedEvent();
            return false;
        }

        private static bool IsBlackbirdOwnEvent(BrokerEtwEventView view) =>
            (view.DetectionTraits & BlackbirdNative.IpcEtwTraitBlackbirdOwn) != 0 ||
            view.DetectionName.Equals("BK_INSTRUMENTATION", StringComparison.OrdinalIgnoreCase);

        private static bool ShouldKeepEtwEvent(BrokerEtwEventView view)
        {
            if (IsBlackbirdOwnEvent(view))
                return true;

            if (view.Family == BlackbirdNative.IpcEtwFamilyUserHook)
            {
                return true;
            }

            if (view.Family == BlackbirdNative.IpcEtwFamilySocket ||
                EventDetailFormatting.IsKernelNetworkEtwSource(view))
            {
                return true;
            }

            if (IsDirectSyscallDetection(view))
            {
                return true;
            }

            if (!string.IsNullOrWhiteSpace(view.DetectionName))
            {
                return true;
            }

            if (view.Severity >= 4)
            {
                return true;
            }

            if (EventDetailFormatting.IsThreatIntelEtwSource(view))
            {
                return view.Task == 1 || view.Task == 2 || view.Task == 7;
            }

            if (view.EventName.Equals("ThreadTelemetry", StringComparison.OrdinalIgnoreCase) ||
                view.EventName.Equals("ApcTelemetry", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            return false;
        }

        private static bool ShouldPromoteHeuristic(BrokerEtwEventView view)
        {
            if (IsDirectSyscallDetection(view))
            {
                return view.Severity >= 2 || IsDirectSyscallHandleTelemetry(view);
            }

            if (string.IsNullOrWhiteSpace(view.DetectionName))
            {
                return false;
            }

            string det = view.DetectionName;
            if (IsHookTamperDetection(view))
            {
                return true;
            }
            if (det.Contains("AMSI_PATCH_TAMPERED", StringComparison.OrdinalIgnoreCase) ||
                det.Contains("ETW_PATCH_TAMPERED", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            if (det.Equals("USERMODE_COM_INIT", StringComparison.OrdinalIgnoreCase) ||
                det.Equals("USERMODE_COM_SECURITY_INIT", StringComparison.OrdinalIgnoreCase) ||
                det.Equals("USERMODE_COM_INSTANCE_CREATE", StringComparison.OrdinalIgnoreCase) ||
                det.Equals("USERMODE_WMI_ACTIVITY", StringComparison.OrdinalIgnoreCase) ||
                det.Equals("USERMODE_ETW_SESSION_CONTROL", StringComparison.OrdinalIgnoreCase) ||
                det.Equals("USERMODE_ETW_SUBSCRIPTION", StringComparison.OrdinalIgnoreCase) ||
                det.Equals("USERMODE_ETW_PROVIDER_REGISTER", StringComparison.OrdinalIgnoreCase) ||
                det.Equals("USERMODE_ETW_PROVIDER_UNREGISTER", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            if (det.Contains("ANTI_DEBUG", StringComparison.OrdinalIgnoreCase) ||
                det.Contains("ANTI_VM", StringComparison.OrdinalIgnoreCase) ||
                det.Contains("ANTI_VIRTUAL", StringComparison.OrdinalIgnoreCase))
            {
                return view.Severity >= 4;
            }

            if (det.Contains("HOLLOW", StringComparison.OrdinalIgnoreCase) ||
                det.Contains("INJECTION", StringComparison.OrdinalIgnoreCase) ||
                det.Contains("THREAD_HIJACK", StringComparison.OrdinalIgnoreCase) ||
                det.Contains("REMOTE_APC", StringComparison.OrdinalIgnoreCase))
            {
                return view.Severity >= 5;
            }

            if (det.Contains("REMOTE_THREAD_WITH_RECENT_HANDLE_INTENT", StringComparison.OrdinalIgnoreCase) ||
                det.Contains("THREAD_ACTIVITY_WITH_THREAD_CONTEXT_INTENT", StringComparison.OrdinalIgnoreCase) ||
                det.Contains("REMOTE_THREAD_OUTSIDE_MAIN_IMAGE", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            return view.Severity >= 6;
        }

        private HeuristicEventView? EvaluateCrossProcessMemoryHeuristic(BrokerEtwEventView view)
        {
            string apiName = !string.IsNullOrWhiteSpace(view.EventName)
                                 ? view.EventName
                                 : (!string.IsNullOrWhiteSpace(view.Operation) ? view.Operation : string.Empty);
            if (string.IsNullOrEmpty(apiName))
            {
                return null;
            }

            uint actor = view.ActorPid != 0 ? view.ActorPid : view.ProcessPid;
            uint target = view.TargetPid != 0 ? view.TargetPid : actor;
            if (actor == 0 || actor == target)
            {
                return null;
            }

            string pairKey = $"{actor}|{target}";

            if (apiName.Equals("NtWriteVirtualMemory", StringComparison.OrdinalIgnoreCase))
            {
                _crossProcWriteCountByPair.TryGetValue(pairKey, out int count);
                count += 1;
                _crossProcWriteCountByPair[pairKey] = count;

                if (count != 5 && count != 25 && count != 100)
                {
                    return null;
                }

                uint severity = count >= 100 ? 8u : count >= 25 ? 7u : 6u;
                return new HeuristicEventView {
                    TimestampUtc = view.TimestampUtc,
                    LastSeenUtc = view.TimestampUtc,
                    Severity = severity,
                    DetectionName = "CROSS_PROCESS_WRITE_PATTERN",
                    ActorPid = actor,
                    TargetPid = target,
                    Source = "BK/MemoryPattern",
                    EventName = "NtWriteVirtualMemory",
                    Reason = $"reason=cross-process write accumulation; count={count}; actor={actor}; target={target}",
                    Evidence = $"NtWriteVirtualMemory observed {count}x from pid {actor} into pid {target}",
                    RepeatCount = 1
                };
            }

            if (apiName.Equals("NtAllocateVirtualMemory", StringComparison.OrdinalIgnoreCase))
            {
                Dictionary<string, string> fields = ParseReasonFields(view.Reason ?? string.Empty);
                uint protect = (uint)FirstU64(fields, "protect", "c3", "a5");
                bool isRwx = protect != 0 && (protect & 0x40u) != 0;
                if (!isRwx)
                {
                    return null;
                }

                _crossProcRwxAllocCountByPair.TryGetValue(pairKey, out int count);
                count += 1;
                _crossProcRwxAllocCountByPair[pairKey] = count;

                if (count != 3 && count != 12 && count != 48)
                {
                    return null;
                }

                uint severity = count >= 48 ? 9u : count >= 12 ? 8u : 7u;
                return new HeuristicEventView {
                    TimestampUtc = view.TimestampUtc,
                    LastSeenUtc = view.TimestampUtc,
                    Severity = severity,
                    DetectionName = "CROSS_PROCESS_RWX_ALLOC_PATTERN",
                    ActorPid = actor,
                    TargetPid = target,
                    Source = "BK/MemoryPattern",
                    EventName = "NtAllocateVirtualMemory",
                    Reason =
                        $"reason=repeated cross-process RWX allocation; count={count}; actor={actor}; target={target}",
                    Evidence =
                        $"NtAllocateVirtualMemory(PAGE_EXECUTE_READWRITE) observed {count}x from pid {actor} into pid {target}",
                    RepeatCount = 1
                };
            }

            return null;
        }

        private HeuristicEventView? EvaluateMemoryLifecycleHeuristic(MemoryRegionAttributionSample sample)
        {
            if (sample.BlackbirdOwned || sample.TargetPid == 0)
            {
                return null;
            }

            bool protectEvent = sample.ProtectFlipCount != 0 &&
                                sample.EventKind.Equals("ProtectChange", StringComparison.OrdinalIgnoreCase);
            bool guardNoAccessSignal = sample.GuardNoAccessFlipCount != 0;
            bool writableExecutableSignal = sample.WritableExecutableFlipCount != 0;
            bool firstHighSignalProtect = sample.ProtectFlipCount == 1 &&
                                          (guardNoAccessSignal || writableExecutableSignal || sample.CrossProcess);
            bool repeatedProtect = protectEvent && (IsMemoryPatternMilestone(sample.ProtectFlipCount) ||
                                                    sample.RapidProtectFlipCount == 1 ||
                                                    IsMemoryPatternMilestone(sample.RapidProtectFlipCount));
            if (protectEvent && (firstHighSignalProtect || repeatedProtect))
            {
                uint severity = ComputeMemoryLifecycleSeverity(sample, protectSignal: true, entropySignal: false);
                string detectionName = guardNoAccessSignal        ? "MEMORY_GUARD_NOACCESS_PROTECTION_FLIP"
                                       : writableExecutableSignal ? "MEMORY_WRITABLE_EXECUTABLE_PROTECTION_FLIP"
                                                                  : "MEMORY_PROTECTION_FLIP_PATTERN";
                string transition =
                    string.IsNullOrWhiteSpace(sample.ProtectionTransition) ? "unknown" : sample.ProtectionTransition;
                string entropyText =
                    sample.EntropyBits >= 0 ? sample.EntropyBits.ToString("F2", CultureInfo.InvariantCulture) : "n/a";
                string maxEntropyText = sample.MaxEntropyBits >= 0
                                            ? sample.MaxEntropyBits.ToString("F2", CultureInfo.InvariantCulture)
                                            : "n/a";

                return new HeuristicEventView {
                    TimestampUtc = sample.TimestampUtc == default ? DateTime.UtcNow : sample.TimestampUtc,
                    LastSeenUtc = sample.TimestampUtc == default ? DateTime.UtcNow : sample.TimestampUtc,
                    Severity = severity,
                    DetectionName = detectionName,
                    ActorPid = sample.ActorPid != 0 ? sample.ActorPid : sample.TargetPid,
                    TargetPid = sample.TargetPid,
                    Source = "BK/MemoryLifecycle",
                    EventName = string.IsNullOrWhiteSpace(sample.ApiName) ? sample.EventKind : sample.ApiName,
                    Reason =
                        $"reason=memory protection flip pattern; region=0x{sample.BaseAddress:X}; size=0x{sample.RegionSize:X}; " +
                        $"transition={transition}; flips={sample.ProtectFlipCount}; rapid={sample.RapidProtectFlipCount}; " +
                        $"execFlips={sample.ExecutableFlipCount}; guardNoAccessFlips={sample.GuardNoAccessFlipCount}; " +
                        $"wxFlips={sample.WritableExecutableFlipCount}; writes={sample.WriteCount}; entropy={entropyText}; maxEntropy={maxEntropyText}",
                    Evidence =
                        $"Region 0x{sample.BaseAddress:X} changed protection {transition}; " +
                        $"protection flips={sample.ProtectFlipCount}, rapid flips={sample.RapidProtectFlipCount}, " +
                        $"exec/guard/WX flips={sample.ExecutableFlipCount}/{sample.GuardNoAccessFlipCount}/{sample.WritableExecutableFlipCount}, " +
                        $"writes={sample.WriteCount}, entropy={entropyText} bits/byte"
                };
            }

            bool entropyEvent = sample.EventKind.Equals("MemoryWrite", StringComparison.OrdinalIgnoreCase) &&
                                HasUsableEntropySample(sample);
            bool highEntropy = entropyEvent && sample.EntropyBits >= MemoryHighEntropyBits;
            bool repeatedEntropyShift = entropyEvent && (IsMemoryPatternMilestone(sample.EntropyFlipCount) ||
                                                         sample.RapidEntropyFlipCount == 1 ||
                                                         IsMemoryPatternMilestone(sample.RapidEntropyFlipCount));
            bool highEntropyMilestone = highEntropy && IsHighEntropyWriteMilestone(sample.HighEntropyWriteCount);
            if (entropyEvent && (highEntropyMilestone || repeatedEntropyShift))
            {
                uint severity = ComputeMemoryLifecycleSeverity(sample, protectSignal: false, entropySignal: true);
                string entropyText = sample.EntropyBits.ToString("F2", CultureInfo.InvariantCulture);
                string maxEntropyText = sample.MaxEntropyBits >= 0
                                            ? sample.MaxEntropyBits.ToString("F2", CultureInfo.InvariantCulture)
                                            : entropyText;
                string detectionName =
                    highEntropy ? "MEMORY_HIGH_ENTROPY_WRITE_PATTERN" : "MEMORY_ENTROPY_SHIFT_PATTERN";

                return new HeuristicEventView {
                    TimestampUtc = sample.TimestampUtc == default ? DateTime.UtcNow : sample.TimestampUtc,
                    LastSeenUtc = sample.TimestampUtc == default ? DateTime.UtcNow : sample.TimestampUtc,
                    Severity = severity,
                    DetectionName = detectionName,
                    ActorPid = sample.ActorPid != 0 ? sample.ActorPid : sample.TargetPid,
                    TargetPid = sample.TargetPid,
                    Source = "BK/MemoryLifecycle",
                    EventName = string.IsNullOrWhiteSpace(sample.ApiName) ? sample.EventKind : sample.ApiName,
                    Reason =
                        $"reason=memory entropy pattern; region=0x{sample.BaseAddress:X}; size=0x{sample.RegionSize:X}; " +
                        $"entropy={entropyText}; maxEntropy={maxEntropyText}; entropyFlips={sample.EntropyFlipCount}; " +
                        $"rapidEntropyFlips={sample.RapidEntropyFlipCount}; highEntropyWrites={sample.HighEntropyWriteCount}; " +
                        $"sampleBytes={sample.SampleBytes}; protectFlips={sample.ProtectFlipCount}",
                    Evidence =
                        $"Region 0x{sample.BaseAddress:X} write sample entropy={entropyText} bits/byte " +
                        $"(max={maxEntropyText}, entropy flips={sample.EntropyFlipCount}, high entropy writes={sample.HighEntropyWriteCount}, " +
                        $"sample bytes={sample.SampleBytes})"
                };
            }

            return null;
        }

        private HeuristicEventView? EvaluateAntiAnalysisHeuristic(BrokerEtwEventView view)
        {
            if (IsBlackbirdOwnEvent(view))
            {
                return null;
            }

            string apiName = !string.IsNullOrWhiteSpace(view.Operation)
                                 ? view.Operation
                                 : (!string.IsNullOrWhiteSpace(view.EventName) ? view.EventName : string.Empty);
            if (string.IsNullOrWhiteSpace(apiName))
            {
                return null;
            }

            Dictionary<string, string> fields = BuildHookFieldMap(view);
            uint actor = view.ActorPid != 0 ? view.ActorPid : view.ProcessPid;
            uint target = view.TargetPid != 0 ? view.TargetPid : actor;
            if (actor == 0)
            {
                return null;
            }

            if (apiName.Equals("NtQueryInformationProcess", StringComparison.OrdinalIgnoreCase))
            {
                uint infoClass = (uint)FirstU64(fields, "processInformationClass", "ProcessInformationClass",
                                                "infoClass", "class", "a1", "c1");
                string className = infoClass switch {
                    7 => "ProcessDebugPort",
                    30 => "ProcessDebugObjectHandle",
                    31 => "ProcessDebugFlags",
                    _ => string.Empty
                };
                if (string.IsNullOrWhiteSpace(className))
                {
                    return null;
                }

                string evidence = $"{apiName} {className} actor={actor} target={target}";
                return BuildAntiAnalysisFinding(
                    view.TimestampUtc, actor, target, "ANTI_DEBUG_PROCESS_QUERY", 6, "UserHook/AntiAnalysis", apiName,
                    $"queried anti-debug process information class {className} (0x{infoClass:X})", evidence);
            }

            if (apiName.Equals("NtQuerySystemInformation", StringComparison.OrdinalIgnoreCase) ||
                apiName.Equals("NtQuerySystemInformationEx", StringComparison.OrdinalIgnoreCase))
            {
                uint infoClass = (uint)FirstU64(fields, "systemInformationClass", "SystemInformationClass", "infoClass",
                                                "class", "a0", "c0");
                if (infoClass == 35)
                {
                    string evidence = $"{apiName} SystemKernelDebuggerInformation actor={actor}";
                    return BuildAntiAnalysisFinding(
                        view.TimestampUtc, actor, target, "ANTI_DEBUG_KERNEL_DEBUGGER_QUERY", 6,
                        "UserHook/AntiAnalysis", apiName,
                        "queried kernel debugger state with SystemKernelDebuggerInformation", evidence);
                }

                if (infoClass == 76)
                {
                    string evidence = $"{apiName} SystemFirmwareTableInformation actor={actor}";
                    return BuildAntiAnalysisFinding(
                        view.TimestampUtc, actor, target, "ANTI_VM_FIRMWARE_TABLE_QUERY", 5, "UserHook/AntiAnalysis",
                        apiName, "queried firmware tables commonly used for hypervisor/vendor checks", evidence);
                }
            }

            return null;
        }

        private HeuristicEventView? EvaluateImageSectionMapHeuristic(BrokerEtwEventView view)
        {
            if (IsBlackbirdOwnEvent(view))
            {
                return null;
            }

            string apiName = !string.IsNullOrWhiteSpace(view.Operation)
                                 ? view.Operation
                                 : (!string.IsNullOrWhiteSpace(view.EventName) ? view.EventName : string.Empty);
            if (!IsImageSectionMapApi(apiName))
            {
                return null;
            }

            uint actor = view.ActorPid != 0     ? view.ActorPid
                         : view.ProcessPid != 0 ? view.ProcessPid
                                                : view.EventProcessId;
            if (actor == 0)
            {
                return null;
            }

            uint tid = view.EventThreadId != 0 ? view.EventThreadId : view.ThreadId;
            DateTime observedUtc = view.TimestampUtc == default ? DateTime.UtcNow : view.TimestampUtc;
            Dictionary<string, string> fields = BuildHookFieldMap(view);
            string mappedPath = ExtractMappedImagePath(view, fields);
            RecentImageFileAccess ? linkedAccess;
            RecentImageMapState mapState;

            lock (_imageMapCorrelationLock)
            {
                PruneImageMapCorrelationCachesLocked(observedUtc);
                linkedAccess = FindRecentImageFileAccessLocked(actor, tid, mappedPath, observedUtc);
                if (string.IsNullOrWhiteSpace(mappedPath) && linkedAccess != null)
                {
                    mappedPath = linkedAccess.Path;
                }

                mappedPath = NormalizeCorrelationPath(mappedPath);
                if (!IsImagePathForMapping(mappedPath))
                {
                    return null;
                }

                mapState = RememberImageMapLocked(actor, mappedPath, apiName, observedUtc, linkedAccess);
            }

            string fileName = ModuleNameFromPath(mappedPath);
            bool isNtdll = fileName.Equals("ntdll.dll", StringComparison.OrdinalIgnoreCase);
            bool hasFilesystemLink = linkedAccess != null;
            bool emitMilestone = mapState.Count == 2 || mapState.Count == 4 || mapState.Count == 8 ||
                                 (mapState.Count > 0 && mapState.Count % 16 == 0);
            if (!emitMilestone)
            {
                return null;
            }

            if (!isNtdll && !hasFilesystemLink && mapState.Count < 4)
            {
                return null;
            }

            uint severity = isNtdll ? 5u : hasFilesystemLink ? 4u : 3u;
            string fileEvidence =
                hasFilesystemLink
                    ? $"linkedFs={DescribeFileOperation(linkedAccess!.Operation)} pid={linkedAccess.Pid} tid={linkedAccess.Tid} path={linkedAccess.Path}"
                    : "linkedFs=<none>";
            string targetText = view.TargetPid == 0 || view.TargetPid == actor
                                    ? "self"
                                    : view.TargetPid.ToString(CultureInfo.InvariantCulture);
            string reason =
                isNtdll
                    ? "repeated mapping of ntdll.dll in one process; normal loader startup maps it once, so later repeat maps are worth review"
                    : "repeated image-backed section mapping correlated with recent filesystem image access";

            return new HeuristicEventView {
                TimestampUtc = observedUtc,
                LastSeenUtc = observedUtc,
                Severity = severity,
                DetectionName = isNtdll ? "REPEATED_NTDLL_IMAGE_MAPPING" : "REPEATED_IMAGE_SECTION_MAPPING",
                ActorPid = actor,
                TargetPid = view.TargetPid == 0 ? actor : view.TargetPid,
                Source = "BK/ImageMapCorrelation",
                EventName = apiName,
                Reason = $"reason={reason}; count={mapState.Count}; target={targetText}",
                Evidence =
                    $"api={apiName} path={mappedPath} firstSeen={mapState.FirstSeenUtc:O} lastSeen={mapState.LastSeenUtc:O} {fileEvidence}",
                RepeatCount = 1
            };
        }

        private void RememberRecentImageFileAccess(IoctlParsedEvent record, DateTime observedUtc)
        {
            if (record.Type != BlackbirdNative.EventTypeFileSystem || record.FileProcessPid == 0 ||
                (record.FileOperation != BlackbirdNative.FileOperationCreate &&
                 record.FileOperation != BlackbirdNative.FileOperationRead))
            {
                return;
            }

            string path = NormalizeCorrelationPath(record.FilePath);
            if (!IsImagePathForMapping(path))
            {
                return;
            }

            var access = new RecentImageFileAccess { TimestampUtc = observedUtc,
                                                     Pid = record.FileProcessPid,
                                                     Tid = record.FileThreadId,
                                                     Operation = record.FileOperation,
                                                     Path = path,
                                                     FileName = ModuleNameFromPath(path) };

            lock (_imageMapCorrelationLock)
            {
                PruneImageMapCorrelationCachesLocked(observedUtc);
                _recentImageFileAccesses.Add(access);
                if (_recentImageFileAccesses.Count > MaxRecentImageFileAccesses)
                {
                    _recentImageFileAccesses.RemoveRange(0,
                                                         _recentImageFileAccesses.Count - MaxRecentImageFileAccesses);
                }
            }
        }

        private void ResetImageMapCorrelationCaches()
        {
            lock (_imageMapCorrelationLock)
            {
                _recentImageFileAccesses.Clear();
                _recentImageMapByPidPath.Clear();
                _lastImageMapCorrelationPruneUtc = DateTime.MinValue;
            }
        }

        private void PruneImageMapCorrelationCachesLocked(DateTime nowUtc)
        {
            if (_lastImageMapCorrelationPruneUtc != DateTime.MinValue &&
                nowUtc < _lastImageMapCorrelationPruneUtc.AddSeconds(2))
            {
                return;
            }

            DateTime fileCutoff = nowUtc - ImageMapFileCorrelationWindow - TimeSpan.FromSeconds(2);
            _recentImageFileAccesses.RemoveAll(x => x.TimestampUtc < fileCutoff);

            DateTime mapCutoff = nowUtc - ImageMapRepeatWindow;
            foreach (string key in _recentImageMapByPidPath.Where(x => x.Value.LastSeenUtc < mapCutoff)
                         .Select(x => x.Key)
                         .ToList())
            {
                _recentImageMapByPidPath.Remove(key);
            }

            if (_recentImageMapByPidPath.Count > MaxRecentImageMapStates)
            {
                foreach (string key in _recentImageMapByPidPath.OrderBy(x => x.Value.LastSeenUtc)
                             .Take(_recentImageMapByPidPath.Count - MaxRecentImageMapStates)
                             .Select(x => x.Key)
                             .ToList())
                {
                    _recentImageMapByPidPath.Remove(key);
                }
            }

            _lastImageMapCorrelationPruneUtc = nowUtc;
        }

        private RecentImageFileAccess? FindRecentImageFileAccessLocked(uint pid, uint tid, string mappedPath,
                                                                       DateTime observedUtc)
        {
            string normalizedPath = NormalizeCorrelationPath(mappedPath);
            string fileName = ModuleNameFromPath(normalizedPath);
            bool hasPath = !string.IsNullOrWhiteSpace(normalizedPath);
            bool hasFileName =
                !string.IsNullOrWhiteSpace(fileName) && !fileName.Equals("unknown", StringComparison.OrdinalIgnoreCase);

            return _recentImageFileAccesses
                .Where(x => x.Pid == pid &&
                            IsWithinCorrelationWindow(x.TimestampUtc, observedUtc, ImageMapFileCorrelationWindow) &&
                            (!hasPath || x.Path.Equals(normalizedPath, StringComparison.OrdinalIgnoreCase) ||
                             (hasFileName && x.FileName.Equals(fileName, StringComparison.OrdinalIgnoreCase))))
                .OrderByDescending(x => x.Tid == tid && tid != 0)
                .ThenByDescending(x => x.Path.Equals(normalizedPath, StringComparison.OrdinalIgnoreCase))
                .ThenBy(x => Math.Abs((x.TimestampUtc - observedUtc).TotalMilliseconds))
                .FirstOrDefault();
        }

        private RecentImageMapState RememberImageMapLocked(uint pid, string mappedPath, string apiName,
                                                           DateTime observedUtc, RecentImageFileAccess? linkedAccess)
        {
            string key = $"{pid}|{mappedPath}";
            if (!_recentImageMapByPidPath.TryGetValue(key, out RecentImageMapState? state) ||
                observedUtc > state.LastSeenUtc.Add(ImageMapRepeatWindow))
            {
                state = new RecentImageMapState {
                    FirstSeenUtc = observedUtc, LastSeenUtc = observedUtc,           Path = mappedPath,
                    LastApi = apiName,          LastLinkedFileAccess = linkedAccess, Count = 0
                };
                _recentImageMapByPidPath[key] = state;
            }

            state.Count += 1;
            state.LastSeenUtc = observedUtc;
            state.LastApi = apiName;
            if (linkedAccess != null)
            {
                state.LastLinkedFileAccess = linkedAccess;
            }

            return state.Clone();
        }

        private static bool IsWithinCorrelationWindow(DateTime leftUtc, DateTime rightUtc, TimeSpan window) =>
            Math.Abs((leftUtc - rightUtc).TotalMilliseconds) <= window.TotalMilliseconds;

        private static bool IsImageSectionMapApi(string apiName)
        {
            string api = (apiName ?? string.Empty).Trim();
            return api.Equals("NtMapViewOfSection", StringComparison.OrdinalIgnoreCase) ||
                   api.Equals("ZwMapViewOfSection", StringComparison.OrdinalIgnoreCase) ||
                   api.Equals("NtCreateSection", StringComparison.OrdinalIgnoreCase) ||
                   api.Equals("ZwCreateSection", StringComparison.OrdinalIgnoreCase) ||
                   api.Equals("CreateFileMappingA", StringComparison.OrdinalIgnoreCase) ||
                   api.Equals("CreateFileMappingW", StringComparison.OrdinalIgnoreCase) ||
                   api.Equals("CreateFileMapping", StringComparison.OrdinalIgnoreCase) ||
                   api.Equals("MapViewOfFile", StringComparison.OrdinalIgnoreCase) ||
                   api.Equals("MapViewOfFileEx", StringComparison.OrdinalIgnoreCase);
        }

        private static string ExtractMappedImagePath(BrokerEtwEventView view,
                                                     IReadOnlyDictionary<string, string> fields)
        {
            foreach (string candidate in new[] {
                         view.ImagePath, ReadTrimmedField(fields, "sectionPath"), ReadTrimmedField(fields, "filePath"),
                         ReadTrimmedField(fields, "imagePath"), ReadTrimmedField(fields, "modulePath"),
                         ReadTrimmedField(fields, "mappedPath"), ReadTrimmedField(fields, "path"),
                         ReadTrimmedField(fields, "objectName"), ReadTrimmedField(fields, "name")
                     })
            {
                string normalized = NormalizeCorrelationPath(candidate);
                if (IsImagePathForMapping(normalized))
                {
                    return normalized;
                }
            }

            return string.Empty;
        }

        private static string NormalizeCorrelationPath(string? path)
        {
            string value = (path ?? string.Empty).Trim().Trim('"');
            if (value.Length == 0)
            {
                return string.Empty;
            }

            value = value.Replace('/', '\\');
            if (value.StartsWith("\\??\\", StringComparison.OrdinalIgnoreCase))
            {
                value = value[4..];
            }
            if (value.StartsWith("file:", StringComparison.OrdinalIgnoreCase))
            {
                value = value[5..].TrimStart('\\');
            }

            return value.Trim();
        }

        private static bool IsImagePathForMapping(string? path)
        {
            string name = ModuleNameFromPath(path ?? string.Empty);
            return name.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) ||
                   name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ||
                   name.EndsWith(".ocx", StringComparison.OrdinalIgnoreCase) ||
                   name.EndsWith(".sys", StringComparison.OrdinalIgnoreCase);
        }

        private HeuristicEventView? BuildAntiAnalysisFinding(DateTime timestampUtc, uint actor, uint target,
                                                             string detection, uint severity, string source,
                                                             string eventName, string reason, string evidence)
        {
            string key = $"{actor}|{target}|{detection}|{evidence}";
            _antiAnalysisCountByEvidence.TryGetValue(key, out int count);
            count += 1;
            _antiAnalysisCountByEvidence[key] = count;
            if (count != 1 && count != 5 && count != 25 && count != 100)
            {
                return null;
            }

            return new HeuristicEventView { TimestampUtc = timestampUtc,
                                            LastSeenUtc = timestampUtc,
                                            Severity = severity,
                                            DetectionName = detection,
                                            ActorPid = actor,
                                            TargetPid = target == 0 ? actor : target,
                                            Source = source,
                                            EventName = eventName,
                                            Reason = $"reason={reason}; hits={count}",
                                            Evidence = evidence,
                                            RepeatCount = 1 };
        }

        private static bool HasDetectionTrait(BrokerEtwEventView view, uint trait) => (view.DetectionTraits & trait) !=
                                                                                      0;

        private static bool IsDirectSyscallDetection(BrokerEtwEventView view)
        {
            if (HasDetectionTrait(view, BlackbirdNative.IpcEtwTraitDirectSyscall))
            {
                return true;
            }

            if (IsDirectSyscallHandleTelemetry(view))
            {
                return true;
            }

            string detection = view.DetectionName;
            if (string.IsNullOrWhiteSpace(detection))
            {
                return false;
            }

            return detection.Contains("DIRECT_SYSCALL", StringComparison.OrdinalIgnoreCase) ||
                   detection.Contains("DIRECT-SYSCALL", StringComparison.OrdinalIgnoreCase) ||
                   detection.Contains("SUSPECT_HANDLE_OPERATION", StringComparison.OrdinalIgnoreCase) ||
                   detection.Contains("ANOMALY_ON_HANDLE_OP", StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsDirectSyscallHandleTelemetry(BrokerEtwEventView view)
        {
            if (view.Family != BlackbirdNative.IpcEtwFamilyHandle)
            {
                return false;
            }

            if (view.ClassName.Equals("DIRECT-SYSCALL-SUSPECT", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            bool exportMismatch = (view.Flags & HandleFlagSyscallExportMismatch) != 0;
            bool stackSpoof = (view.Flags & HandleFlagStackSpoofSuspect) != 0;
            bool execOutsideNtdll =
                (view.Flags & HandleFlagExecProtect) != 0 && (view.Flags & HandleFlagFromNtdll) == 0;
            return exportMismatch || stackSpoof || execOutsideNtdll;
        }

        private static bool IsHookTamperDetection(BrokerEtwEventView view)
        {
            if (HasDetectionTrait(view, BlackbirdNative.IpcEtwTraitHookTamper))
            {
                return true;
            }

            string detection = view.DetectionName;
            if (string.IsNullOrWhiteSpace(detection))
            {
                return false;
            }

            return detection.Contains("USERMODE_HOOK_TAMPERED", StringComparison.OrdinalIgnoreCase) ||
                   detection.Contains("AMSI_PATCH_TAMPERED", StringComparison.OrdinalIgnoreCase) ||
                   detection.Contains("ETW_PATCH_TAMPERED", StringComparison.OrdinalIgnoreCase) ||
                   detection.Contains("IAT_TAMPER", StringComparison.OrdinalIgnoreCase) ||
                   detection.Contains("EAT_TAMPER", StringComparison.OrdinalIgnoreCase) ||
                   detection.Contains("NTDLL_IMAGE_TAMPER", StringComparison.OrdinalIgnoreCase) ||
                   detection.Contains("SR71_HOOK_WRITE_BLOCKED", StringComparison.OrdinalIgnoreCase) ||
                   detection.Contains("SR71_HOOK_PROTECT_BLOCKED", StringComparison.OrdinalIgnoreCase) ||
                   detection.Contains("HOOK_TAMPER", StringComparison.OrdinalIgnoreCase);
        }

        private static string BuildHandleEvidenceText(IoctlParsedEvent record)
        {
            string accessDecoded = EventDetailFormatting.DescribeHandleAccess(record.DesiredAccess);
            string flagsDecoded = EventDetailFormatting.DescribeHandleFlags(record.HandleFlags);
            string sampleHex = EventDetailFormatting.FormatSampleHex(record.DeepSample, (int)record.DeepSampleSize);
            string disasm = EventDetailFormatting.InferSampleDisassembly(record.DeepSample, (int)record.DeepSampleSize);
            string stackSnapshotHex =
                EventDetailFormatting.FormatSampleHex(record.StackSnapshot, (int)record.StackSnapshotSize);
            string stack0 = record.Frames.Length > 0 ? FormatIoctlCodeAddress(record, record.Frames[0]) : "n/a";
            string stack1 = record.Frames.Length > 1 ? FormatIoctlCodeAddress(record, record.Frames[1]) : "n/a";
            string moduleName = EventDetailFormatting.ModuleNameFromPath(record.OriginPath);
            string originAddress = FormatIoctlCodeAddress(record, record.OriginAddress);
            string allocationBase = FormatIoctlCodeAddress(record, record.DeepAllocationBase);
            string fullFrames = BuildFrameList(record, record.FullFrames, record.FullFrameCount);
            string captureFlags = DescribeCaptureFlags(record.CaptureFlags);
            string directSyscallName =
                EventDetailFormatting.ResolveDirectSyscallApi(record.DesiredAccess, record.HandleFlags);
            string directSyscallLabel = EventDetailFormatting.BuildDirectSyscallLabel(
                record.DesiredAccess, record.HandleFlags, record.DeepSample, (int)record.DeepSampleSize);
            bool hasContext = (record.CaptureFlags & 0x00000001u) != 0;
            bool hasDebugRegs = (record.CaptureFlags & 0x00000002u) != 0;
            bool hasFullFrames = (record.CaptureFlags & 0x00000004u) != 0;
            bool hasStackSnapshot = (record.CaptureFlags & 0x00000008u) != 0;

            string frameSegment = hasFullFrames ? $"fullFrameCount={record.FullFrameCount} fullFrames={fullFrames} "
                                                : "fullFrameCount=0 fullFrames=<none> ";

            string registerSegment =
                hasContext
                    ? $"rax=0x{record.RegRax:X} rbx=0x{record.RegRbx:X} rcx=0x{record.RegRcx:X} rdx=0x{record.RegRdx:X} " +
                          $"rsi=0x{record.RegRsi:X} rdi=0x{record.RegRdi:X} rbp=0x{record.RegRbp:X} rsp=0x{record.RegRsp:X} " +
                          $"r8=0x{record.RegR8:X} r9=0x{record.RegR9:X} r10=0x{record.RegR10:X} r11=0x{record.RegR11:X} " +
                          $"r12=0x{record.RegR12:X} r13=0x{record.RegR13:X} r14=0x{record.RegR14:X} r15=0x{record.RegR15:X} " +
                          $"rip=0x{record.RegRip:X} eflags=0x{record.RegEFlags:X} "
                    : string.Empty;

            string debugSegment =
                hasDebugRegs
                    ? $"dr0=0x{record.RegDr0:X} dr1=0x{record.RegDr1:X} dr2=0x{record.RegDr2:X} dr3=0x{record.RegDr3:X} dr6=0x{record.RegDr6:X} dr7=0x{record.RegDr7:X} "
                    : string.Empty;

            string stackSegment =
                hasStackSnapshot
                    ? $"stackSnapshotAddress=0x{record.StackSnapshotAddress:X} stackSnapshotSize={record.StackSnapshotSize} stackSnapshot={stackSnapshotHex} "
                    : "stackSnapshotAddress=0x0 stackSnapshotSize=0 stackSnapshot=<none> ";

            return $"ioctlEvidence class={record.HandleClass} syscallName={directSyscallName} syscallLabel={directSyscallLabel.Replace(' ', '_')} access=0x{record.DesiredAccess:X8} ({accessDecoded}) flags=0x{record.HandleFlags:X8} ({flagsDecoded}) " +
                   $"origin={originAddress} protect=0x{record.OriginProtect:X8} module={moduleName} " +
                   $"allocationBase={allocationBase} regionSize=0x{record.DeepRegionSize:X} regionProtect=0x{record.DeepRegionProtect:X8} ({EventDetailFormatting.DescribeMemoryProtection(record.DeepRegionProtect)}) " +
                   $"regionState=0x{record.DeepRegionState:X8} ({EventDetailFormatting.DescribeMemoryState(record.DeepRegionState)}) regionType=0x{record.DeepRegionType:X8} ({EventDetailFormatting.DescribeMemoryType(record.DeepRegionType)}) " +
                   $"path={record.OriginPath} stack0={stack0} stack1={stack1} " +
                   $"captureFlags=0x{record.CaptureFlags:X8} ({captureFlags}) " + frameSegment + registerSegment +
                   debugSegment + stackSegment +
                   $"deepSampleSize={record.DeepSampleSize} deepSample={sampleHex} sampleDisasmHint={disasm}";
        }

        private static string DescribeCaptureFlags(uint captureFlags)
        {
            var labels = new List<string>();
            if ((captureFlags & 0x00000001u) != 0)
            {
                labels.Add("CONTEXT");
            }
            if ((captureFlags & 0x00000002u) != 0)
            {
                labels.Add("DEBUG_REGS");
            }
            if ((captureFlags & 0x00000004u) != 0)
            {
                labels.Add("FULL_FRAMES");
            }
            if ((captureFlags & 0x00000008u) != 0)
            {
                labels.Add("STACK_SNAPSHOT");
            }

            return labels.Count == 0 ? "NONE" : string.Join("|", labels);
        }

        private static string BuildFrameList(IoctlParsedEvent record, ulong[]? frames, uint frameCount)
        {
            if (frames == null || frames.Length == 0 || frameCount == 0)
            {
                return "<none>";
            }

            int safeCount = Math.Min(frames.Length, (int)frameCount);
            var list = new List<string>(safeCount);
            for (int i = 0; i < safeCount; i += 1)
            {
                ulong frame = frames[i];
                if (frame == 0)
                {
                    continue;
                }

                list.Add(FormatIoctlCodeAddress(record, frame));
            }

            return list.Count == 0 ? "<none>" : string.Join(",", list);
        }

        private static string FormatIoctlCodeAddress(IoctlParsedEvent record, ulong address)
        {
            if (address == 0)
            {
                return "n/a";
            }

            string moduleName = EventDetailFormatting.ModuleNameFromPath(record.OriginPath);
            ulong allocationBase = record.DeepAllocationBase;
            ulong regionSize = record.DeepRegionSize;
            bool inRange = regionSize == 0 ||
                           (regionSize <= ulong.MaxValue - allocationBase && address < allocationBase + regionSize);
            if (!moduleName.Equals("unknown", StringComparison.OrdinalIgnoreCase) && allocationBase != 0 &&
                address >= allocationBase && inRange)
            {
                string section = (record.DeepRegionType & 0x01000000u) != 0 ? ".image" : ".region";
                return $"{moduleName}{section}+0x{address - allocationBase:X}";
            }

            return $"unresolved+0x{address:X}";
        }

        private static bool IsHighRiskIoctlAccess(uint desiredAccess, bool isThreadObject)
        {
            if (isThreadObject)
            {
                bool threadAll = (desiredAccess & 0x001F03FFu) == 0x001F03FFu;
                return threadAll || (desiredAccess & (0x0002u | 0x0008u | 0x0010u)) != 0;
            }

            bool processAll = (desiredAccess & 0x001F0FFFu) == 0x001F0FFFu;
            return processAll || (desiredAccess & (0x0002u | 0x0008u | 0x0010u | 0x0020u)) != 0;
        }

        private static bool ShouldKeepDirectSyscallHeuristicFromEvidence(IoctlParsedEvent record)
        {
            if (record.HandleClass == 2)
            {
                return true;
            }

            bool exportMismatch = (record.HandleFlags & HandleFlagSyscallExportMismatch) != 0;
            bool stackSpoof = (record.HandleFlags & HandleFlagStackSpoofSuspect) != 0;
            bool execOutsideNtdll =
                (record.HandleFlags & HandleFlagExecProtect) != 0 && (record.HandleFlags & HandleFlagFromNtdll) == 0;
            bool framesOutsideTeb = (record.HandleFlags & HandleFlagFramesOutsideTebStack) != 0;
            return exportMismatch || stackSpoof || execOutsideNtdll || framesOutsideTeb;
        }

        private static bool IsGdiSubsystemModule(string? originPath)
        {
            if (string.IsNullOrWhiteSpace(originPath))
            {
                return false;
            }

            string module = EventDetailFormatting.ModuleNameFromPath(originPath).ToLowerInvariant();
            return module is "win32u.dll" or "gdi32.dll" or "gdi32full.dll" or "user32.dll" or "user32full.dll";
        }

        private static string DescribeFileOperation(uint operation)
        {
            return operation switch { BlackbirdNative.FileOperationCreate => "CREATE",
                                      BlackbirdNative.FileOperationRead => "READ",
                                      BlackbirdNative.FileOperationWrite => "WRITE",
                                      BlackbirdNative.FileOperationClose => "CLOSE",
                                      BlackbirdNative.FileOperationCleanup => "CLEANUP",
                                      BlackbirdNative.FileOperationSetInformation => "SET_INFORMATION",
                                      BlackbirdNative.FileOperationQueryInformation => "QUERY_INFORMATION",
                                      BlackbirdNative.FileOperationDirectoryControl => "DIRECTORY_CONTROL",
                                      BlackbirdNative.FileOperationFsControl => "FS_CONTROL",
                                      _ => "UNKNOWN" };
        }

        private static string BuildFileSummaryPath(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                return "<unknown>";
            }

            const int maxChars = 84;
            if (path.Length <= maxChars)
            {
                return path;
            }

            return "..." + path[^maxChars..];
        }

        private static string BuildFilesystemClusterKey(IoctlParsedEvent record)
        {
            string path = string.IsNullOrWhiteSpace(record.FilePath) ? "<unknown>" : record.FilePath;
            return $"{record.FileOperation}|{record.FileProcessPid}|{path}";
        }

        private void ResetFilesystemTimelineCluster()
        {
            _filesystemClusterOperationCounts.Clear();
            _filesystemClusterSamplesByOperation.Clear();
            _filesystemClusterTotal = 0;
            _filesystemClusterWindowStartUtc = DateTime.MinValue;
            _filesystemClusterLastSeenUtc = DateTime.MinValue;
        }

        private IReadOnlyList<TelemetryEvent> FlushFilesystemTimelineClusterIfNeeded(DateTime nowUtc, bool force)
        {
            if (_filesystemClusterTotal <= 0)
            {
                return Array.Empty<TelemetryEvent>();
            }

            if (!force && (nowUtc - _filesystemClusterLastSeenUtc) < FilesystemTimelineClusterIdleFlush)
            {
                return Array.Empty<TelemetryEvent>();
            }

            double windowMs =
                Math.Max(1, (_filesystemClusterLastSeenUtc - _filesystemClusterWindowStartUtc).TotalMilliseconds);
            var emitted = new List<TelemetryEvent>(_filesystemClusterOperationCounts.Count);
            foreach (var entry in _filesystemClusterOperationCounts.OrderByDescending(x => x.Value).ThenBy(x => x.Key))
            {
                if (entry.Value <= 0)
                {
                    continue;
                }

                int count = entry.Value;
                (uint Pid, uint Tid, string Path, uint Operation) sample =
                    _filesystemClusterSamplesByOperation.TryGetValue(entry.Key, out var found)
                        ? found
                        : (0u, 0u, "<unknown>", 0u);
                string operationName = DescribeFileOperation(sample.Operation);
                string samplePath = string.IsNullOrWhiteSpace(sample.Path) ? "<unknown>" : sample.Path;
                string summaryPath = BuildFileSummaryPath(samplePath);
                emitted.Add(new TelemetryEvent {
                    TimestampUtc = _filesystemClusterLastSeenUtc, PID = unchecked((int)sample.Pid),
                    TID = unchecked((int)sample.Tid), Group = "Filesystem", SubType = operationName,
                    Summary = $"{operationName} x{count} pid={sample.Pid} path={summaryPath}",
                    Details =
                        $"windowStart={_filesystemClusterWindowStartUtc:O} windowEnd={_filesystemClusterLastSeenUtc:O} windowMs={windowMs:0} " +
                        $"operation={operationName} count={count} clusterTotal={_filesystemClusterTotal} samplePid={sample.Pid} sampleTid={sample.Tid} samplePath={samplePath}"
                });
            }

            ResetFilesystemTimelineCluster();
            return emitted;
        }

        private IReadOnlyList<TelemetryEvent> AccumulateFilesystemTimelineCluster(IoctlParsedEvent record,
                                                                                  DateTime nowUtc)
        {
            if (record.Type != BlackbirdNative.EventTypeFileSystem)
            {
                return Array.Empty<TelemetryEvent>();
            }

            var emitted = new List<TelemetryEvent>();
            if (_filesystemClusterTotal > 0 &&
                (nowUtc - _filesystemClusterWindowStartUtc) >= FilesystemTimelineClusterWindow)
            {
                emitted.AddRange(FlushFilesystemTimelineClusterIfNeeded(nowUtc, force: true));
            }

            if (_filesystemClusterTotal == 0)
            {
                _filesystemClusterWindowStartUtc = nowUtc;
            }

            string clusterKey = BuildFilesystemClusterKey(record);
            _filesystemClusterTotal += 1;
            _filesystemClusterLastSeenUtc = nowUtc;
            _filesystemClusterOperationCounts.TryGetValue(clusterKey, out int count);
            _filesystemClusterOperationCounts[clusterKey] = count + 1;
            if (!_filesystemClusterSamplesByOperation.ContainsKey(clusterKey))
            {
                _filesystemClusterSamplesByOperation[clusterKey] =
                    (record.FileProcessPid, record.FileThreadId,
                     string.IsNullOrWhiteSpace(record.FilePath) ? "<unknown>" : record.FilePath, record.FileOperation);
            }

            if (_filesystemClusterTotal >= FilesystemTimelineClusterFlushCount)
            {
                emitted.AddRange(FlushFilesystemTimelineClusterIfNeeded(nowUtc, force: true));
            }

            return emitted.Count == 0 ? Array.Empty<TelemetryEvent>() : emitted;
        }

        private TelemetryEvent? MapIoctlRecord(IoctlParsedEvent record)
        {
            DateTime now = DateTime.UtcNow;
            if (record.Type == BlackbirdNative.EventTypeHandle)
            {
                RememberHandleEvidence(record);
                uint caller = record.CallerPid;
                uint target = record.TargetPid;

                if (caller != 0 && !_filterTrackedPids.IsEmpty && !_filterTrackedPids.ContainsKey(caller))
                {
                    return null;
                }
                string originModuleForFilter = EventDetailFormatting.ModuleNameFromPath(record.OriginPath);
                if (EventDetailFormatting.IsSr71Module(originModuleForFilter))
                {
                    return null;
                }

                string className = record.HandleClass switch {
                    1 => "LEGITIMATE-SYSCALL",
                    2 => "DIRECT-SYSCALL-SUSPECT",
                    _ => "UNKNOWN"
                };
                string syscallLabel = EventDetailFormatting.BuildDirectSyscallLabel(
                    record.DesiredAccess, record.HandleFlags, record.DeepSample, (int)record.DeepSampleSize);

                return new TelemetryEvent {
                    TimestampUtc = now,
                    PID = unchecked((int)caller),
                    TID = unchecked((int)record.ThreadId),
                    Group = "Kernel-IOCTL",
                    SubType = "Handle",
                    Summary =
                        $"{className} {syscallLabel} caller={caller} target={target} access=0x{record.DesiredAccess:X8}",
                    Details = BuildHandleEvidenceText(record)
                };
            }

            if (record.Type == BlackbirdNative.EventTypeThread)
            {
                uint process = record.ProcessPid;
                uint creator = record.CreatorPid;

                if (creator != 0 && process != 0 && creator != process && !_filterTrackedPids.IsEmpty &&
                    !_filterTrackedPids.ContainsKey(creator))
                {
                    return null;
                }

                string eventKind =
                    DetermineThreadLifecycleKind(record.ThreadFlags, record.StartAddress, record.ImageSize);
                string threadFlags = EventDetailFormatting.DescribeThreadFlags(record.ThreadFlags);
                return new TelemetryEvent {
                    TimestampUtc = now,
                    PID = unchecked((int)process),
                    TID = unchecked((int)record.ThreadId),
                    Group = "Kernel-IOCTL",
                    SubType = $"Thread{eventKind}",
                    Summary = $"{eventKind} creator={creator} process={process} flags=0x{record.ThreadFlags:X8}",
                    Details =
                        $"seq={record.Sequence} start=0x{record.StartAddress:X} imageBase=0x{record.ImageBase:X} imageSize=0x{record.ImageSize:X} decodedFlags={threadFlags}"
                };
            }

            if (record.Type == BlackbirdNative.EventTypeFileSystem)
            {
                return null;
            }

            if (record.Type == BlackbirdNative.EventTypeEnterprise)
            {
                uint actor = record.EnterpriseProcessPid;
                uint target = record.EnterpriseTargetProcessPid;
                if (actor != 0 && !_filterTrackedPids.IsEmpty && !_filterTrackedPids.ContainsKey(actor))
                {
                    return null;
                }

                string operation = DescribeEnterpriseOperation(record.EnterpriseOperation);
                string flags = DescribeEnterpriseFlags(record.EnterpriseFlags);
                return new TelemetryEvent {
                    TimestampUtc = now,
                    PID = unchecked((int)actor),
                    TID = unchecked((int)record.EnterpriseThreadId),
                    Group = "Kernel-IOCTL",
                    SubType = "Enterprise",
                    Summary = $"{operation} actor={actor} target={target} flags=0x{record.EnterpriseFlags:X8}",
                    Details =
                        $"seq={record.Sequence} op={operation} subOp={record.EnterpriseSubOperation} actor={actor} tid={record.EnterpriseThreadId} " +
                        $"target={target} targetTid={record.EnterpriseTargetThreadId} desired=0x{record.EnterpriseDesiredAccess:X8} " +
                        $"granted=0x{record.EnterpriseGrantedAccess:X8} status=0x{record.EnterpriseStatus:X8} " +
                        $"object=0x{record.EnterpriseObjectAddress:X} aux0=0x{record.EnterpriseAux0:X} aux1=0x{record.EnterpriseAux1:X} " +
                        $"protocol={record.EnterpriseProtocol} localPort={record.EnterpriseLocalPort} remotePort={record.EnterpriseRemotePort} flags={flags}"
                };
            }

            return null;
        }

        private bool ShouldAcceptFilesystemRecord(IoctlParsedEvent record)
        {
            if (record.Type != BlackbirdNative.EventTypeFileSystem)
            {
                return true;
            }

            uint pid = record.FileProcessPid;
            if (pid == 0 || (!_filterTrackedPids.IsEmpty && !_filterTrackedPids.ContainsKey(pid)))
            {
                return false;
            }

            return !IsBlackbirdInternalFilesystemPath(record.FilePath);
        }

        private bool ShouldEvaluateSignatureIntelForIoctl(IoctlParsedEvent record, bool acceptFilesystem)
        {
            if (record.Type == BlackbirdNative.EventTypeFileSystem)
            {
                return acceptFilesystem;
            }

            if (record.Type == BlackbirdNative.EventTypeRegistry)
            {
                return record.RegistryProcessPid != 0 && IsTrackedPid(record.RegistryProcessPid);
            }

            if (record.Type == BlackbirdNative.EventTypeEnterprise)
            {
                return record.EnterpriseProcessPid != 0 && IsTrackedPid(record.EnterpriseProcessPid);
            }

            if (record.Type == BlackbirdNative.EventTypeHandle)
            {
                if (record.CallerPid != 0 && !IsTrackedPid(record.CallerPid))
                {
                    return false;
                }

                string originModule = EventDetailFormatting.ModuleNameFromPath(record.OriginPath);
                return !EventDetailFormatting.IsSr71Module(originModule);
            }

            if (record.Type == BlackbirdNative.EventTypeThread)
            {
                if (record.CreatorPid != 0 && record.ProcessPid != 0 && record.CreatorPid != record.ProcessPid)
                {
                    return IsTrackedPid(record.CreatorPid);
                }

                return IsTrackedPid(record.ProcessPid);
            }

            return true;
        }

        private static bool IsBlackbirdInternalFilesystemPath(string? path)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                return false;
            }

            string normalized = path.Replace('/', '\\').Trim();
            return normalized.Contains("\\ProgramData\\Blackbird", StringComparison.OrdinalIgnoreCase) ||
                   normalized.Contains("\\Device\\HarddiskVolume3\\ProgramData\\Blackbird",
                                       StringComparison.OrdinalIgnoreCase) ||
                   normalized.EndsWith("\\controller.log", StringComparison.OrdinalIgnoreCase) ||
                   normalized.EndsWith("\\controller.log.1", StringComparison.OrdinalIgnoreCase);
        }

        private static IoctlParsedEvent? MapIoctlFilesystem(IoctlParsedEvent record)
        {
            return record.Type == BlackbirdNative.EventTypeFileSystem ? record : null;
        }

        private static IoctlParsedEvent? MapIoctlRegistry(IoctlParsedEvent record)
        {
            return record.Type == BlackbirdNative.EventTypeRegistry ? record : null;
        }

        private static ThreadLifecycleEventSample? MapIoctlThreadLifecycle(IoctlParsedEvent record)
        {
            if (record.Type != BlackbirdNative.EventTypeThread)
            {
                return null;
            }

            DateTime now = DateTime.UtcNow;
            string eventKind = DetermineThreadLifecycleKind(record.ThreadFlags, record.StartAddress, record.ImageSize);
            string decodedFlags = EventDetailFormatting.DescribeThreadFlags(record.ThreadFlags);

            return new ThreadLifecycleEventSample { TimestampUtc = now,           ProcessPid = record.ProcessPid,
                                                    ThreadId = record.ThreadId,   CreatorPid = record.CreatorPid,
                                                    Flags = record.ThreadFlags,   StartAddress = record.StartAddress,
                                                    ImageBase = record.ImageBase, ImageSize = record.ImageSize,
                                                    EventKind = eventKind,        Notes = $"flags={decodedFlags}" };
        }

        private static string DetermineThreadLifecycleKind(uint threadFlags, ulong startAddress, ulong imageSize)
        {
            if ((threadFlags & 0x00000200u) != 0)
            {
                return "Exit";
            }

            if ((threadFlags & 0x00000001u) == 0 && startAddress == 0 && imageSize == 0)
            {
                return "Exit";
            }

            if ((threadFlags & 0x00000001u) != 0)
            {
                return "Start";
            }

            return "Update";
        }

        private ProcessRelationView? MapIoctlRelation(IoctlParsedEvent record)
        {
            DateTime now = DateTime.UtcNow;
            if (record.Type == BlackbirdNative.EventTypeHandle)
            {
                uint source = record.CallerPid;
                uint target = record.TargetPid;
                if (source == 0 || target == 0 || source == target)
                {
                    return null;
                }

                if (!_filterTrackedPids.IsEmpty && !_filterTrackedPids.ContainsKey(source))
                {
                    return null;
                }
                string accessDecoded = EventDetailFormatting.DescribeHandleAccess(record.DesiredAccess);
                string flagsDecoded = EventDetailFormatting.DescribeHandleFlags(record.HandleFlags);
                string originModule = EventDetailFormatting.ModuleNameFromPath(record.OriginPath);
                bool isSr71Handle = EventDetailFormatting.IsSr71Module(originModule);
                if (isSr71Handle)
                {
                    return null;
                }
                string detailSignature =
                    $"handle|{source}|{target}|{record.DesiredAccess:X8}|{record.HandleFlags:X8}|{originModule}";
                string detailText =
                    $"sourcePid={source} targetPid={target} relationType=HandleOpen access=0x{record.DesiredAccess:X8} ({accessDecoded}) " +
                    $"flags=0x{record.HandleFlags:X8} ({flagsDecoded}) originModule={originModule} " +
                    $"handleOwner={(isSr71Handle ? "SR71" : "ActorProcess")}";

                return new ProcessRelationView { FirstSeenUtc = now,
                                                 LastSeenUtc = now,
                                                 SourcePid = source,
                                                 TargetPid = target,
                                                 RelationType = "HandleOpen",
                                                 LastAccessMask = record.DesiredAccess,
                                                 LastFlags = record.HandleFlags,
                                                 OriginSource = "Kernel-IOCTL",
                                                 OriginModule = originModule,
                                                 DetailSignature = detailSignature,
                                                 DetailText = detailText,
                                                 RepeatCount = 1 };
            }

            if (record.Type == BlackbirdNative.EventTypeThread)
            {
                uint source = record.CreatorPid;
                uint target = record.ProcessPid;
                if (source == 0 || target == 0 || source == target)
                {
                    return null;
                }

                if (!_filterTrackedPids.IsEmpty && !_filterTrackedPids.ContainsKey(source))
                {
                    return null;
                }

                return new ProcessRelationView { FirstSeenUtc = now,
                                                 LastSeenUtc = now,
                                                 SourcePid = source,
                                                 TargetPid = target,
                                                 RelationType = "ThreadCreate",
                                                 LastAccessMask = 0,
                                                 LastFlags = record.ThreadFlags,
                                                 OriginSource = "Kernel-IOCTL",
                                                 OriginModule =
                                                     EventDetailFormatting.ModuleNameFromPath(record.OriginPath),
                                                 RepeatCount = 1 };
            }

            if (record.Type == BlackbirdNative.EventTypeEnterprise)
            {
                uint source = record.EnterpriseProcessPid;
                uint target = record.EnterpriseTargetProcessPid;
                if (source == 0 || target == 0 || source == target)
                {
                    return null;
                }
                if (!_filterTrackedPids.IsEmpty && !_filterTrackedPids.ContainsKey(source))
                {
                    return null;
                }

                string operation = DescribeEnterpriseOperation(record.EnterpriseOperation);
                return new ProcessRelationView {
                    FirstSeenUtc = now,
                    LastSeenUtc = now,
                    SourcePid = source,
                    TargetPid = target,
                    RelationType = "EnterpriseAccess",
                    LastAccessMask = record.EnterpriseDesiredAccess,
                    LastFlags = record.EnterpriseFlags,
                    OriginSource = "Kernel-IOCTL",
                    OriginModule = operation,
                    DetailSignature = $"enterprise|{source}|{target}|{record.EnterpriseOperation}|{record.EnterpriseFlags:X8}",
                    DetailText =
                        $"sourcePid={source} targetPid={target} relationType=EnterpriseAccess operation={operation} " +
                        $"access=0x{record.EnterpriseDesiredAccess:X8} flags=0x{record.EnterpriseFlags:X8}",
                    RepeatCount = 1
                };
            }

            return null;
        }

        private static ProcessRelationView? MapEtwRelation(BrokerEtwEventView view)
        {
            if (view.Family != BlackbirdNative.IpcEtwFamilyProcess ||
                (view.Flags & BlackbirdNative.IpcEtwFlagProcessIsCreate) == 0)
            {
                return null;
            }

            uint source =
                view.CreatorPid != 0 ? view.CreatorPid : (view.ParentPid != 0 ? view.ParentPid : view.ActorPid);
            uint target = view.ProcessPid != 0 ? view.ProcessPid : view.TargetPid;
            if (source == 0 || target == 0 || source == target)
            {
                return null;
            }

            uint createStatus = unchecked((uint)view.CreateStatus);
            string detailSignature = $"create|{source}|{target}|0x{view.ProcessStartKey:X}|0x{createStatus:X8}";
            string detailText =
                $"sourcePid={source} targetPid={target} relationType=ProcessCreate creatorPid={view.CreatorPid} " +
                $"parentPid={view.ParentPid} createStatus=0x{createStatus:X8} startKey=0x{view.ProcessStartKey:X} " +
                $"imagePath={view.ImagePath}";

            return new ProcessRelationView { FirstSeenUtc = view.TimestampUtc,
                                             LastSeenUtc = view.TimestampUtc,
                                             SourcePid = source,
                                             TargetPid = target,
                                             RelationType = "ProcessCreate",
                                             LastAccessMask = 0,
                                             LastFlags = view.Flags,
                                             OriginSource = view.Source,
                                             OriginModule = EventDetailFormatting.ModuleNameFromPath(view.ImagePath),
                                             DetailSignature = detailSignature,
                                             DetailText = detailText,
                                             RepeatCount = 1 };
        }

        private HeuristicEventView? MapIoctlHeuristic(IoctlParsedEvent record)
        {
            HeuristicEventView? antiAnalysis = EvaluateAntiAnalysisIoctlHeuristic(record);
            if (antiAnalysis != null)
            {
                return antiAnalysis;
            }

            if (record.Type == BlackbirdNative.EventTypeEnterprise)
            {
                uint actor = record.EnterpriseProcessPid;
                uint target = record.EnterpriseTargetProcessPid;
                if (actor == 0 || (!_filterTrackedPids.IsEmpty && !_filterTrackedPids.ContainsKey(actor)))
                {
                    return null;
                }

                string operation = DescribeEnterpriseOperation(record.EnterpriseOperation);
                string flags = DescribeEnterpriseFlags(record.EnterpriseFlags);
                uint enterpriseSeverity =
                    (record.EnterpriseFlags & BlackbirdNative.EnterpriseFlagCritical) != 0 ? 8u : 6u;
                return new HeuristicEventView {
                    TimestampUtc = DateTime.UtcNow,
                    LastSeenUtc = DateTime.UtcNow,
                    Severity = enterpriseSeverity,
                    DetectionName = $"ENTERPRISE_{operation}",
                    ActorPid = actor,
                    TargetPid = target,
                    Source = "Kernel-IOCTL/Enterprise",
                    EventName = "EnterpriseTelemetry",
                    CorrelationFlags = record.EnterpriseFlags,
                    CorrelationAccessMask = record.EnterpriseDesiredAccess,
                    CorrelationAgeMs = 0,
                    Reason =
                        $"enterprise operation={operation}; flags={flags}; desired=0x{record.EnterpriseDesiredAccess:X8}; " +
                        $"status=0x{record.EnterpriseStatus:X8}",
                    Evidence =
                        $"actor={actor} tid={record.EnterpriseThreadId} target={target} targetTid={record.EnterpriseTargetThreadId} " +
                        $"object=0x{record.EnterpriseObjectAddress:X} aux0=0x{record.EnterpriseAux0:X} aux1=0x{record.EnterpriseAux1:X}",
                    RepeatCount = 1
                };
            }

            if (record.Type != BlackbirdNative.EventTypeHandle || record.CallerPid == 0 || record.TargetPid == 0)
            {
                return null;
            }

            if (record.HandleClass != 2)
            {
                return null;
            }

            DateTime now = DateTime.UtcNow;
            bool isThreadObject = (record.HandleFlags & HandleFlagThreadObject) != 0;
            bool highRiskAccess = IsHighRiskIoctlAccess(record.DesiredAccess, isThreadObject);
            bool exportMismatch = (record.HandleFlags & HandleFlagSyscallExportMismatch) != 0;
            bool stackSpoof = (record.HandleFlags & HandleFlagStackSpoofSuspect) != 0;
            bool stackValidated = (record.HandleFlags & HandleFlagStackValidated) != 0;
            bool tebBoundsValid = (record.HandleFlags & HandleFlagTebStackBoundsValid) != 0;
            bool execOutsideNtdll =
                (record.HandleFlags & HandleFlagExecProtect) != 0 && (record.HandleFlags & HandleFlagFromNtdll) == 0;
            uint severity = exportMismatch ? 6u : highRiskAccess ? 5u : (stackSpoof || execOutsideNtdll) ? 4u : 3u;

            string handleFlagsDecoded = EventDetailFormatting.DescribeHandleFlags(record.HandleFlags);
            string corrAccessDecoded = EventDetailFormatting.DescribeHandleAccess(record.DesiredAccess);
            string syscallName =
                EventDetailFormatting.ResolveDirectSyscallApi(record.DesiredAccess, record.HandleFlags);
            string syscallSummary = EventDetailFormatting.BuildDirectSyscallSummary(
                record.CallerPid.ToString(CultureInfo.InvariantCulture),
                record.TargetPid.ToString(CultureInfo.InvariantCulture), record.DesiredAccess, record.HandleFlags,
                record.DeepSample, (int)record.DeepSampleSize, record.OriginPath);

            return new HeuristicEventView {
                TimestampUtc = now,
                LastSeenUtc = now,
                Severity = severity,
                DetectionName = $"DIRECT_SYSCALL_SUSPECT_HANDLE_OPERATION [{syscallName}]",
                ActorPid = record.CallerPid,
                TargetPid = record.TargetPid,
                Source = "Kernel-IOCTL",
                EventName = "HandleTelemetry",
                CorrelationFlags = 0,
                CorrelationAccessMask = record.DesiredAccess,
                CorrelationAgeMs = 0,
                Reason =
                    $"{syscallSummary}; ioctlClass={record.HandleClass}; directClass=true; highRiskAccess={highRiskAccess}; " +
                    $"exportMismatch={exportMismatch}; stackSpoof={stackSpoof}; stackValidated={stackValidated}; " +
                    $"tebBoundsValid={tebBoundsValid}; execOutsideNtdll={execOutsideNtdll}; " +
                    $"handleFlags={handleFlagsDecoded}; access={corrAccessDecoded}",
                Evidence = BuildHandleEvidenceText(record),
                RepeatCount = 1
            };
        }

        private HeuristicEventView? EvaluateAntiAnalysisIoctlHeuristic(IoctlParsedEvent record)
        {
            DateTime now = DateTime.UtcNow;
            if (record.Type == BlackbirdNative.EventTypeFileSystem)
            {
                if (!ShouldAcceptFilesystemRecord(record))
                {
                    return null;
                }

                uint pid = record.FileProcessPid;
                string path = record.FilePath ?? string.Empty;
                if (!TryMatchVirtualizationArtifact(path, out string artifact))
                {
                    return null;
                }

                string evidence =
                    $"filesystem operation=0x{record.FileOperation:X} pid={pid} tid={record.FileThreadId} artifact={artifact} path={path}";
                return BuildAntiAnalysisFinding(now, pid, pid, "ANTI_VM_FILESYSTEM_ARTIFACT_PROBE", 5,
                                                "Kernel-IOCTL/AntiAnalysis", "FileSystemTelemetry",
                                                $"probed virtualization filesystem artifact {artifact}", evidence);
            }

            if (record.Type == BlackbirdNative.EventTypeRegistry)
            {
                uint pid = record.RegistryProcessPid;
                if (pid == 0 || (!_filterTrackedPids.IsEmpty && !_filterTrackedPids.ContainsKey(pid)))
                {
                    return null;
                }
                if (!IsRegistryProbeOperation(record.RegistryOperation))
                {
                    return null;
                }

                string registryPath = BuildRegistryProbePath(record);
                if (!TryMatchVirtualizationArtifact(registryPath, out string artifact))
                {
                    return null;
                }

                string operation = DescribeRegistryProbeOperation(record.RegistryOperation);
                string evidence =
                    $"registry operation={operation} pid={pid} tid={record.RegistryThreadId} artifact={artifact} path={registryPath}";
                return BuildAntiAnalysisFinding(now, pid, pid, "ANTI_VM_REGISTRY_ARTIFACT_PROBE", 5,
                                                "Kernel-IOCTL/AntiAnalysis", "RegistryTelemetry",
                                                $"queried virtualization registry artifact {artifact}", evidence);
            }

            return null;
        }

        private static string BuildRegistryProbePath(IoctlParsedEvent record)
        {
            string key = record.RegistryKeyPath ?? string.Empty;
            string value = record.RegistryValueName ?? string.Empty;
            if (string.IsNullOrWhiteSpace(value))
            {
                return key;
            }

            return string.IsNullOrWhiteSpace(key) ? value : $"{key}\\{value}";
        }

        private static string DescribeEnterpriseOperation(uint operation)
        {
            return operation switch {
                BlackbirdNative.EnterpriseOperationProcessCredentialAccess => "PROCESS_CREDENTIAL_ACCESS",
                BlackbirdNative.EnterpriseOperationProcessPrivilegedAccess => "PROCESS_PRIVILEGED_ACCESS",
                BlackbirdNative.EnterpriseOperationTokenAccess => "TOKEN_ACCESS",
                BlackbirdNative.EnterpriseOperationRegistryCredentialHiveAccess => "REGISTRY_CREDENTIAL_HIVE",
                BlackbirdNative.EnterpriseOperationRegistryLsaPolicyAccess => "REGISTRY_LSA_POLICY",
                BlackbirdNative.EnterpriseOperationRegistryKerberosNtlmAccess => "REGISTRY_KERBEROS_NTLM",
                BlackbirdNative.EnterpriseOperationRegistryServiceConfigAccess => "REGISTRY_SERVICE_CONFIG",
                BlackbirdNative.EnterpriseOperationRegistryLpePersistenceAccess => "REGISTRY_LPE_PERSISTENCE",
                BlackbirdNative.EnterpriseOperationFileCredentialStoreAccess => "FILE_CREDENTIAL_STORE",
                BlackbirdNative.EnterpriseOperationFileDirectoryCredentialAccess => "FILE_CREDENTIAL_DIRECTORY",
                BlackbirdNative.EnterpriseOperationFileDriverArtifactAccess => "FILE_DRIVER_ARTIFACT",
                BlackbirdNative.EnterpriseOperationNetworkAdProtocolConnect => "NETWORK_AD_PROTOCOL",
                _ => $"UNKNOWN_{operation}"
            };
        }

        private static string DescribeEnterpriseFlags(uint flags)
        {
            var parts = new List<string>(8);
            if ((flags & BlackbirdNative.EnterpriseFlagCritical) != 0)
                parts.Add("Critical");
            if ((flags & BlackbirdNative.EnterpriseFlagQuery) != 0)
                parts.Add("Query");
            if ((flags & BlackbirdNative.EnterpriseFlagWrite) != 0)
                parts.Add("Write");
            if ((flags & BlackbirdNative.EnterpriseFlagCreate) != 0)
                parts.Add("Create");
            if ((flags & BlackbirdNative.EnterpriseFlagDelete) != 0)
                parts.Add("Delete");
            if ((flags & BlackbirdNative.EnterpriseFlagDuplicateHandle) != 0)
                parts.Add("DuplicateHandle");
            if ((flags & BlackbirdNative.EnterpriseFlagProcessObject) != 0)
                parts.Add("ProcessObject");
            if ((flags & BlackbirdNative.EnterpriseFlagThreadObject) != 0)
                parts.Add("ThreadObject");
            if ((flags & BlackbirdNative.EnterpriseFlagVmRead) != 0)
                parts.Add("VmRead");
            if ((flags & BlackbirdNative.EnterpriseFlagVmWrite) != 0)
                parts.Add("VmWrite");
            if ((flags & BlackbirdNative.EnterpriseFlagVmOperation) != 0)
                parts.Add("VmOperation");
            if ((flags & BlackbirdNative.EnterpriseFlagCreateThread) != 0)
                parts.Add("CreateThread");
            if ((flags & BlackbirdNative.EnterpriseFlagCredentialProcess) != 0)
                parts.Add("CredentialProcess");
            if ((flags & BlackbirdNative.EnterpriseFlagPrivilegedTarget) != 0)
                parts.Add("PrivilegedTarget");
            if ((flags & BlackbirdNative.EnterpriseFlagLsassTarget) != 0)
                parts.Add("LsassTarget");
            if ((flags & BlackbirdNative.EnterpriseFlagWinlogonTarget) != 0)
                parts.Add("WinlogonTarget");
            if ((flags & BlackbirdNative.EnterpriseFlagServiceConfig) != 0)
                parts.Add("ServiceConfig");
            if ((flags & BlackbirdNative.EnterpriseFlagSecurityHive) != 0)
                parts.Add("SecurityHive");
            if ((flags & BlackbirdNative.EnterpriseFlagLsaPolicy) != 0)
                parts.Add("LsaPolicy");
            if ((flags & BlackbirdNative.EnterpriseFlagKerberosNtlm) != 0)
                parts.Add("KerberosNtlm");
            if ((flags & BlackbirdNative.EnterpriseFlagCredentialFile) != 0)
                parts.Add("CredentialFile");
            if ((flags & BlackbirdNative.EnterpriseFlagDriverArtifact) != 0)
                parts.Add("DriverArtifact");
            if ((flags & BlackbirdNative.EnterpriseFlagAdNetwork) != 0)
                parts.Add("AdNetwork");
            if ((flags & BlackbirdNative.EnterpriseFlagDirectSyscallSuspect) != 0)
                parts.Add("DirectSyscallSuspect");
            if ((flags & BlackbirdNative.EnterpriseFlagQueryAccess) != 0)
                parts.Add("QueryAccess");
            if ((flags & BlackbirdNative.EnterpriseFlagThreadContext) != 0)
                parts.Add("ThreadContext");
            if ((flags & BlackbirdNative.EnterpriseFlagSetOrTerminate) != 0)
                parts.Add("SetOrTerminate");
            return parts.Count == 0 ? "<none>" : string.Join("|", parts);
        }

        private static bool IsRegistryProbeOperation(uint operation)
        {
            return operation is BlackbirdNative.RegistryOperationQueryValue or BlackbirdNative
                .RegistryOperationQueryKey or BlackbirdNative.RegistryOperationEnumerateKey or
                    BlackbirdNative.RegistryOperationEnumerateValue or BlackbirdNative.RegistryOperationOpenKey;
        }

        private static string DescribeRegistryProbeOperation(uint operation)
        {
            return operation switch { BlackbirdNative.RegistryOperationQueryValue => "QUERY_VALUE",
                                      BlackbirdNative.RegistryOperationQueryKey => "QUERY_KEY",
                                      BlackbirdNative.RegistryOperationEnumerateKey => "ENUMERATE_KEY",
                                      BlackbirdNative.RegistryOperationEnumerateValue => "ENUMERATE_VALUE",
                                      BlackbirdNative.RegistryOperationOpenKey => "OPEN_KEY",
                                      _ => $"0x{operation:X}" };
        }

        private static bool TryMatchVirtualizationArtifact(string? text, out string artifact)
        {
            artifact = string.Empty;
            if (string.IsNullOrWhiteSpace(text))
            {
                return false;
            }

            string normalized = text.Replace('/', '\\').Trim();
            for (int i = 0; i < VirtualizationArtifactPatterns.Length; i += 1)
            {
                if (normalized.Contains(VirtualizationArtifactPatterns[i].Token, StringComparison.OrdinalIgnoreCase))
                {
                    artifact = VirtualizationArtifactPatterns[i].Label;
                    return true;
                }
            }

            return false;
        }

        private void RememberObservedProcessStart(BrokerEtwEventView view)
        {
            DateTime observedUtc = view.TimestampUtc == default ? DateTime.UtcNow : view.TimestampUtc;
            ulong startKey = view.ProcessStartKey;

            if (view.ProcessPid != 0 && !_observedProcessStartUtcByPid.ContainsKey(view.ProcessPid))
            {
                _observedProcessStartUtcByPid[view.ProcessPid] = observedUtc;
            }

            if (view.EventProcessId != 0 && !_observedProcessStartUtcByPid.ContainsKey(view.EventProcessId))
            {
                _observedProcessStartUtcByPid[view.EventProcessId] = observedUtc;
            }

            if (startKey != 0)
            {
                if (view.ProcessPid != 0)
                {
                    _observedProcessStartKeyByPid[view.ProcessPid] = startKey;
                }
                if (view.TargetPid != 0)
                {
                    _observedProcessStartKeyByPid[view.TargetPid] = startKey;
                }
                if (view.EventProcessId != 0)
                {
                    _observedProcessStartKeyByPid[view.EventProcessId] = startKey;
                }
            }

            if (view.Family == BlackbirdNative.IpcEtwFamilyProcess &&
                (view.Flags & BlackbirdNative.IpcEtwFlagProcessIsCreate) != 0)
            {
                uint pid = view.ProcessPid != 0 ? view.ProcessPid : view.TargetPid;
                if (pid != 0)
                {
                    _observedProcessStartUtcByPid[pid] = observedUtc;
                    if (view.EventThreadId != 0)
                    {
                        _observedInitialThreadIdByPid[pid] = view.EventThreadId;
                    }
                }
            }
        }

        private bool TryDescribeHookStartupContext(BrokerEtwEventView view, out string headline, out string detail)
        {
            headline = string.Empty;
            detail = string.Empty;

            if (!EventDetailFormatting.IsApiGraphCandidate(view))
            {
                return false;
            }

            uint pid = view.ProcessPid != 0 ? view.ProcessPid : view.ActorPid;
            if (pid == 0)
            {
                return false;
            }

            if (!_observedProcessStartUtcByPid.TryGetValue(pid, out DateTime startUtc))
            {
                if (_currentSession != null && _currentSession.Pid == unchecked((int)pid))
                {
                    startUtc = _currentSession.CaptureStartUtc;
                }
                else
                {
                    return false;
                }
            }

            DateTime eventUtc = view.TimestampUtc == default ? DateTime.UtcNow : view.TimestampUtc;
            if (eventUtc < startUtc)
            {
                startUtc = eventUtc;
            }

            double ageMs = Math.Max(0, (eventUtc - startUtc).TotalMilliseconds);
            if (ageMs > 4000)
            {
                return false;
            }

            string callerOrigin = view.CallerOriginLabel;
            bool processImageCaller = callerOrigin.Equals("process-image", StringComparison.OrdinalIgnoreCase);
            bool plausibleStartupCaller = processImageCaller ||
                                          callerOrigin.Equals("system", StringComparison.OrdinalIgnoreCase) ||
                                          callerOrigin.Equals("non-system-dll", StringComparison.OrdinalIgnoreCase);
            if (!plausibleStartupCaller)
            {
                return false;
            }

            uint initialThreadId =
                _observedInitialThreadIdByPid.TryGetValue(pid, out uint trackedThreadId) ? trackedThreadId : 0;
            bool primaryThread = initialThreadId != 0 && view.EventThreadId == initialThreadId;
            string phase = ageMs <= 750 ? "very early process startup" : "early process startup";
            headline = ageMs <= 750 ? "Startup Path" : "Early Startup";

            if (processImageCaller && primaryThread && ageMs <= 750)
            {
                detail =
                    $"StartupContext: inferred {phase} on the initial thread from the process image; likely loader / CRT / compiler-generated initializer activity. " +
                    "TLS callbacks or .CRT$XL* initializer paths are possible here, but this remains an inference from timing and caller-origin telemetry.";
                return true;
            }

            if (primaryThread && ageMs <= 2000)
            {
                detail =
                    $"StartupContext: inferred {phase} on the initial thread; likely loader or CRT initialization traffic rather than steady-state behavior.";
                return true;
            }

            detail =
                $"StartupContext: inferred {phase}; this call landed inside the startup window and may still reflect loader, CRT, static-initializer, or DLL attach activity.";
            return true;
        }

        private void HandleBrokerEtwView(BrokerEtwEventView view)
        {
            HandleBrokerEtwViews(new[] { view });
        }

        private void HandleBrokerEtwViews(IReadOnlyList<BrokerEtwEventView> views)
        {
            if (views.Count == 0)
            {
                return;
            }

            var etwRows = new List<BrokerEtwEventView>(views.Count);
            var heuristics = new List<HeuristicEventView>();
            var relations = new List<ProcessRelationView>();
            var memoryAttributions = new List<MemoryRegionAttributionSample>(16);
            var timelineEvents = new List<TelemetryEvent>(views.Count);

            for (int i = 0; i < views.Count; i += 1)
            {
                BrokerEtwEventView view = views[i];
                RememberObservedProcessStart(view);
                TelemetryEvent? apiTimelineEvent = null;
                UpdateHookPipelineDiagnostics(view);
                ObserveTargetOutputEvent(view);
                ObserveTargetLifecycleEvent(view);
                IReadOnlyList<HeuristicEventView> signatureIntelFindings = QueueSignatureIntelForView(view);
                if (signatureIntelFindings.Count > 0)
                {
                    heuristics.AddRange(signatureIntelFindings);
                }
                PersistObservedHookStackSnapshot(view);
                QueueThreadStackFallbackCapture(view);
                MemoryRegionAttributionSample? memoryAttribution = CreateMemoryRegionAttributionSample(view);
                if (memoryAttribution != null)
                {
                    memoryAttributions.Add(memoryAttribution);
                    HeuristicEventView? memoryLifecycleHeuristic = EvaluateMemoryLifecycleHeuristic(memoryAttribution);
                    if (memoryLifecycleHeuristic != null)
                    {
                        heuristics.Add(memoryLifecycleHeuristic);
                    }
                }
                if (EventDetailFormatting.IsApiGraphCandidate(view))
                {
                    apiTimelineEvent = HandleApiHookEvent(view);
                    if (apiTimelineEvent != null)
                    {
                        timelineEvents.Add(apiTimelineEvent);
                    }

                    HeuristicEventView? memPatternHeuristic = EvaluateCrossProcessMemoryHeuristic(view);
                    if (memPatternHeuristic != null)
                    {
                        heuristics.Add(memPatternHeuristic);
                    }

                    HeuristicEventView? antiAnalysisHeuristic = EvaluateAntiAnalysisHeuristic(view);
                    if (antiAnalysisHeuristic != null)
                    {
                        heuristics.Add(antiAnalysisHeuristic);
                    }

                    HeuristicEventView? imageMapHeuristic = EvaluateImageSectionMapHeuristic(view);
                    if (imageMapHeuristic != null)
                    {
                        heuristics.Add(imageMapHeuristic);
                    }
                }

                bool keepEtw = ShouldKeepEtwEvent(view);
                if (keepEtw)
                {
                    etwRows.Add(view);
                }

                if (ObserveExtendedActivity(view))
                {
                    ScheduleExtendedActivitySnapshot();
                }

                ProcessRelationView? relation = MapEtwRelation(view);
                if (relation != null)
                {
                    relations.Add(relation);
                }

                string detection = view.DetectionName;
                DiagnosticsState.SetValue("ETW Status", "Live");
                if (detection.Equals("USERMODE_PROCESS_TERMINATE_BREAKPOINT", StringComparison.OrdinalIgnoreCase))
                {
                    uint terminatedPid = view.TargetPid != 0    ? view.TargetPid
                                         : view.ProcessPid != 0 ? view.ProcessPid
                                                                : view.ActorPid;
                    string reason =
                        string.IsNullOrWhiteSpace(view.Reason)
                            ? $"NtTerminateProcess observed from {ProcessIdentityResolver.Describe(view.ActorPid)}"
                            : view.Reason;
                    RememberTargetExitReason(terminatedPid, reason);
                    DiagnosticsState.SetValue("Target Exit Cause", reason);
                }
                if (detection.Equals("KERNEL_HOOK_STATUS", StringComparison.OrdinalIgnoreCase))
                {
                    uint installed = view.CorrelationFlags;
                    uint total = view.CorrelationAccessMask;
                    uint requiredMiss = view.CorrelationAgeMs;
                    string hookStatus = requiredMiss == 0
                                            ? $"OK ({installed}/{total})"
                                            : $"DEGRADED ({installed}/{total}, {requiredMiss} required miss)";
                    DiagnosticsState.SetValue("Kernel Hooks", hookStatus);
                }
                if (IsHookTamperDetection(view))
                {
                    DiagnosticsState.SetValue("Hook Integrity", "TAMPERED");
                }
                else if (detection.Equals("USERMODE_HOOK_INTEGRITY_OK", StringComparison.OrdinalIgnoreCase))
                {
                    DiagnosticsState.SetValue("Hook Integrity", "OK");
                    MarkSr71HookReadyFromTelemetry();
                }
                if (detection.Equals("AMSI_PATCH_TAMPERED", StringComparison.OrdinalIgnoreCase))
                {
                    DiagnosticsState.SetValue("AMSI Integrity", "TAMPERED");
                }
                else if (detection.Equals("AMSI_PATCH_OK", StringComparison.OrdinalIgnoreCase))
                {
                    DiagnosticsState.SetValue("AMSI Integrity", "OK");
                    MarkSr71HookReadyFromTelemetry();
                }
                if (detection.Equals("ETW_PATCH_TAMPERED", StringComparison.OrdinalIgnoreCase))
                {
                    DiagnosticsState.SetValue("ETW Integrity", "TAMPERED");
                }
                else if (detection.Equals("ETW_PATCH_OK", StringComparison.OrdinalIgnoreCase))
                {
                    DiagnosticsState.SetValue("ETW Integrity", "OK");
                    MarkSr71HookReadyFromTelemetry();
                }

                string eventName = view.EventName ?? string.Empty;
                string displayDetection = BuildFallbackDetectionLabel(detection, eventName, view.Task, view.Opcode,
                                                                      view.EventId, view.CorrelationFlags);
                string source = view.Source;
                uint actor = view.ActorPid;
                bool isSocketEvent = view.Family == BlackbirdNative.IpcEtwFamilySocket ||
                                     EventDetailFormatting.IsKernelNetworkEtwSource(view);
                if (isSocketEvent)
                {
                    PerformancePaneHost.IngestNetworkView(view);
                }
                string socketOperation = string.IsNullOrWhiteSpace(view.Operation) ? eventName : view.Operation;
                if (string.IsNullOrWhiteSpace(socketOperation))
                {
                    socketOperation = $"OP{view.Opcode}";
                }
                string timelineGroup = isSocketEvent ? "Sockets" : "BK-ETW";
                string timelineSubtype = isSocketEvent ? socketOperation : eventName;
                string summary = isSocketEvent ? $"{socketOperation} pid={actor} task={view.Task} opcode={view.Opcode}"
                                               : (!string.IsNullOrWhiteSpace(displayDetection)
                                                      ? $"{source}/{displayDetection} sev={view.Severity}"
                                                      : $"{source}/{eventName} sev={view.Severity}");
                string timelineSignature = $"{timelineGroup}|{eventName}|{actor}|{view.EventThreadId}|{summary}";
                bool duplicateTimelineEvent =
                    string.Equals(_lastEtwTimelineSignature, timelineSignature, StringComparison.OrdinalIgnoreCase) &&
                    (view.TimestampUtc - _lastEtwTimelineTimestampUtc).TotalMilliseconds <= 900;

                HeuristicEventView? heuristic = CreatePromotedHeuristic(view);
                if (heuristic != null)
                {
                    heuristics.Add(heuristic);
                }

                bool persistView = ShouldPersistEtwView(view, keepEtw, relation != null,
                                                        heuristic != null || signatureIntelFindings.Count > 0,
                                                        apiTimelineEvent != null);

                string displayDetails = string.Empty;
                if (keepEtw || apiTimelineEvent != null || persistView)
                {
                    EnsureEtwDisplayDetails(view);
                    displayDetails = view.DisplayDetails;
                }

                if (persistView)
                {
                    AppendEtwToCaptureStore(view);
                }

                if (keepEtw && !duplicateTimelineEvent)
                {
                    int timelinePid =
                        view.EventProcessId == 0 ? unchecked((int)actor) : unchecked((int)view.EventProcessId);
                    timelineEvents.Add(new TelemetryEvent { TimestampUtc = view.TimestampUtc, PID = timelinePid,
                                                            TID = unchecked((int)view.EventThreadId),
                                                            Group = timelineGroup, SubType = timelineSubtype,
                                                            Summary = summary, Details = displayDetails });
                    _lastEtwTimelineSignature = timelineSignature;
                    _lastEtwTimelineTimestampUtc = view.TimestampUtc;
                }
            }

            if (etwRows.Count > 0)
            {
                EtwPaneHost.PushEvents(etwRows);
                _explorer.FirstOrDefault(x => x.Name == "ETW")?.PushPreviewValue(EtwPaneHost.TotalRawCount);
                SetExplorerHasData("ETW", EtwPaneHost.ItemCount > 0);
            }

            if (timelineEvents.Count > 0)
            {
                AppendEvents(timelineEvents);
            }

            if (memoryAttributions.Count > 0)
            {
                PerformancePaneHost.PushMemoryRegionAttributions(memoryAttributions);
                if (_currentSession != null)
                {
                    for (int i = 0; i < memoryAttributions.Count; i += 1)
                    {
                        _currentSession.MemoryRegionAttributionHistory.Add(
                            CloneMemoryRegionAttributionSample(memoryAttributions[i]));
                    }

                    if (_currentSession.MemoryRegionAttributionHistory.Count > 12_000)
                    {
                        _currentSession.MemoryRegionAttributionHistory.RemoveRange(
                            0, _currentSession.MemoryRegionAttributionHistory.Count - 12_000);
                    }
                }
            }

            if (heuristics.Count > 0)
            {
                HeuristicsPaneHost.PushHeuristics(heuristics);
                bool extendedChanged = false;
                for (int i = 0; i < heuristics.Count; i += 1)
                {
                    extendedChanged |= ObserveSignatureIntelActivity(heuristics[i]);
                }
                if (extendedChanged)
                {
                    ScheduleExtendedActivitySnapshot();
                }
                _explorer.FirstOrDefault(x => x.Name == "Heuristics")
                    ?.PushPreviewValue(HeuristicsPaneHost.TotalRawCount);
                SetExplorerHasData("Heuristics", HeuristicsPaneHost.ItemCount > 0);
                DiagnosticsState.Increment("Heuristics", heuristics.Count);
            }

            if (relations.Count > 0)
            {
                ProcessRelationsPaneHost.PushRelations(relations);
                _explorer.FirstOrDefault(x => x.Name == "Process Relations")
                    ?.PushPreviewValue(ProcessRelationsPaneHost.TotalRawCount);
                SetExplorerHasData("Process Relations", ProcessRelationsPaneHost.ItemCount > 0);
            }
        }

        private static bool IsTargetOutputEvent(BrokerEtwEventView view) =>
            view.SourceId == BlackbirdNative.IpcEtwSourceBlackbird
            && view.EventName.Equals("TargetOutput", StringComparison.OrdinalIgnoreCase);

        private static bool IsTargetLifecycleEvent(BrokerEtwEventView view) =>
            view.SourceId == BlackbirdNative.IpcEtwSourceBlackbird
            && view.EventName.Equals("TargetExit", StringComparison.OrdinalIgnoreCase);

        private static void ObserveTargetOutputEvent(BrokerEtwEventView view)
        {
            if (!IsTargetOutputEvent(view))
            {
                return;
            }

            uint pid = view.ProcessPid != 0 ? view.ProcessPid : view.ActorPid;
            if (pid == 0 || pid > int.MaxValue)
            {
                return;
            }

            string stream = string.IsNullOrWhiteSpace(view.Operation) ? "stdout" : view.Operation.Trim();
            string message = !string.IsNullOrWhiteSpace(view.CommandLine) ? view.CommandLine : view.Reason;
            if (string.IsNullOrWhiteSpace(message))
            {
                return;
            }

            DebugConsoleService.WriteExternal($"TARGET/{stream}", unchecked((int)pid), message);
        }

        private void ObserveTargetLifecycleEvent(BrokerEtwEventView view)
        {
            if (!IsTargetLifecycleEvent(view))
            {
                return;
            }

            uint pid = view.ProcessPid != 0 ? view.ProcessPid : view.ActorPid;
            if (pid == 0 || pid > int.MaxValue)
            {
                return;
            }

            string message =
                string.IsNullOrWhiteSpace(view.Reason) ? $"target exited status=0x{view.CreateStatus:X8}" : view.Reason;
            RememberTargetExitReason(pid, message);
            DebugConsoleService.WriteExternal("TARGET/lifecycle", unchecked((int)pid), message);
        }

        private void RememberTargetExitReason(uint pid, string reason)
        {
            if (pid == 0 || string.IsNullOrWhiteSpace(reason))
            {
                return;
            }

            string normalized = reason.Trim();
            _targetExitReasonByPid[pid] = normalized;
            if (_currentSession != null && _currentSession.Pid == unchecked((int)pid))
            {
                _currentSession.TargetExitReason = normalized;
            }
        }

        private static bool ShouldPersistEtwView(BrokerEtwEventView view, bool keepEtw, bool hasRelation,
                                                 bool hasPromotedHeuristic, bool hasApiTimelineEvent)
        {
            if (hasRelation || hasPromotedHeuristic || hasApiTimelineEvent)
            {
                return true;
            }

            if (!keepEtw)
            {
                return false;
            }

            if (!string.IsNullOrWhiteSpace(view.DetectionName) || view.Severity >= 4)
            {
                return true;
            }

            return view.Family is BlackbirdNative.IpcEtwFamilyThread or BlackbirdNative
                .IpcEtwFamilyApc or BlackbirdNative.IpcEtwFamilyUserHook or BlackbirdNative.IpcEtwFamilySocket;
        }

        private void UpdateHookPipelineDiagnostics(BrokerEtwEventView view)
        {
            if (view.Family == BlackbirdNative.IpcEtwFamilyUserHook &&
                view.SourceId == BlackbirdNative.IpcEtwSourceUserHook)
            {
                long count = Interlocked.Increment(ref _usermodeHookEventCount);
                string kind = EventDetailFormatting.HookKindName(view.NotifyClass);
                string api = !string.IsNullOrWhiteSpace(view.Operation) ? view.Operation : view.EventName;
                string label = !string.IsNullOrWhiteSpace(api)    ? api
                               : !string.IsNullOrWhiteSpace(kind) ? kind
                                                                  : "event";
                DiagnosticsState.SetValue("Usermode Hooks", $"Active ({count} SR71 events, last={label})");
                DiagnosticsState.SetValue("HookDLL->Controller IPC", "Ready (SR71 telemetry)");
                DiagnosticsState.SetValue("HookDLL Hooks Set", $"OK ({kind})");
                MarkSr71HookReadyFromTelemetry();
                if (ShouldPromoteIntegrityStatus(DiagnosticsState.GetValue("Hook Integrity")))
                {
                    DiagnosticsState.SetValue("Hook Integrity", "OK");
                }
                if (ShouldPromoteIntegrityStatus(DiagnosticsState.GetValue("AMSI Integrity")))
                {
                    DiagnosticsState.SetValue("AMSI Integrity", "OK");
                }
                return;
            }

            if (EventDetailFormatting.IsKernelHookTelemetry(view))
            {
                long count = Interlocked.Increment(ref _kernelHookEventCount);
                string api = !string.IsNullOrWhiteSpace(view.Operation) ? view.Operation : view.EventName;
                DiagnosticsState.SetValue("Kernel Hooks", string.IsNullOrWhiteSpace(api)
                                                              ? $"Active ({count} events)"
                                                              : $"Active ({count} events, last={api})");
                return;
            }

            if (EventDetailFormatting.IsUsermodeSensorTelemetry(view))
            {
                string kind = EventDetailFormatting.HookKindName(view.NotifyClass);
                DiagnosticsState.SetValue("Usermode Hooks", $"Active ({kind})");
                DiagnosticsState.SetValue("HookDLL->Controller IPC", "Ready (SR71 telemetry)");
                DiagnosticsState.SetValue("HookDLL Hooks Set", $"OK ({kind})");
                MarkSr71HookReadyFromTelemetry();
                if (ShouldPromoteIntegrityStatus(DiagnosticsState.GetValue("Hook Integrity")))
                {
                    DiagnosticsState.SetValue("Hook Integrity", "OK");
                }
                if (ShouldPromoteIntegrityStatus(DiagnosticsState.GetValue("AMSI Integrity")))
                {
                    DiagnosticsState.SetValue("AMSI Integrity", "OK");
                }
            }
        }

        private static bool ShouldPromoteIntegrityStatus(string? current)
        {
            if (string.IsNullOrWhiteSpace(current))
            {
                return true;
            }

            return current.Contains("Unknown", StringComparison.OrdinalIgnoreCase) ||
                   current.Contains("Awaiting", StringComparison.OrdinalIgnoreCase) ||
                   current.Contains("Review", StringComparison.OrdinalIgnoreCase) ||
                   current.Contains("Disabled (no usermode hooks)", StringComparison.OrdinalIgnoreCase);
        }

        private static void MarkSr71HookReadyFromTelemetry()
        {
            string? hookReady = DiagnosticsState.GetValue("SR71 Hook Ready");
            if (string.IsNullOrWhiteSpace(hookReady) ||
                hookReady.Contains("Awaiting", StringComparison.OrdinalIgnoreCase) ||
                hookReady.Contains("DEGRADED", StringComparison.OrdinalIgnoreCase) ||
                hookReady.Contains("missing", StringComparison.OrdinalIgnoreCase))
            {
                DiagnosticsState.SetValue("SR71 Hook Ready", "OK observed via SR71 telemetry");
            }

            string? instrumentation = DiagnosticsState.GetValue("SR71 Instrumentation");
            if (string.IsNullOrWhiteSpace(instrumentation) ||
                instrumentation.Contains("Awaiting", StringComparison.OrdinalIgnoreCase) ||
                instrumentation.Contains("DEGRADED", StringComparison.OrdinalIgnoreCase))
            {
                DiagnosticsState.SetValue("SR71 Instrumentation", "OK observed via SR71 telemetry");
            }
        }

        private static void TryAppendObservedModule(BrokerEtwEventView view, List<ModuleInfoRow> rows)
        {
            string path = view.ImagePath ?? string.Empty;
            ulong baseAddress = view.ImageBase;
            ulong imageSize = view.ImageSize;

            if (string.IsNullOrWhiteSpace(path) && view.Family == BlackbirdNative.IpcEtwFamilyUserHook)
            {
                string apiName = !string.IsNullOrWhiteSpace(view.Operation) ? view.Operation : view.EventName;
                if (apiName.Equals("LdrLoadDll", StringComparison.OrdinalIgnoreCase) ||
                    apiName.StartsWith("LoadLibrary", StringComparison.OrdinalIgnoreCase))
                {
                    Dictionary<string, string> fields = BuildHookFieldMap(view);
                    path = DecodeModuleHookName(apiName, view);
                    baseAddress = FirstU64(fields, "handle", "module", "moduleHandle");
                }
            }

            if (string.IsNullOrWhiteSpace(path))
            {
                return;
            }

            rows.Add(new ModuleInfoRow {
                Name = ModuleNameFromPath(path), BaseAddress = baseAddress == 0 ? "observed" : $"0x{baseAddress:X}",
                Size =
                    imageSize == 0 ? "observed" : FormatObservedBytes((long)Math.Min(imageSize, (ulong) long.MaxValue)),
                Path = path
            });
        }

        private static string FormatObservedBytes(long bytes)
        {
            string[] units = { "B", "KB", "MB", "GB", "TB" };
            double value = Math.Max(0, bytes);
            int unit = 0;
            while (value >= 1024 && unit < units.Length - 1)
            {
                value /= 1024;
                unit += 1;
            }

            return unit == 0 ? $"{bytes} B" : $"{value:0.0} {units[unit]}";
        }

        private static string ModuleNameFromPath(string path)
        {
            string value = (path ?? string.Empty).Trim();
            if (value.Length == 0)
            {
                return "unknown";
            }

            int slash = Math.Max(value.LastIndexOf('\\'), value.LastIndexOf('/'));
            return slash >= 0 && slash + 1 < value.Length ? value[(slash + 1)..] : value;
        }

        private void PersistObservedHookStackSnapshot(BrokerEtwEventView view)
        {
            if (view.Family != BlackbirdNative.IpcEtwFamilyUserHook ||
                view.SourceId != BlackbirdNative.IpcEtwSourceUserHook || view.StackCount == 0)
            {
                return;
            }

            uint pid = view.ProcessPid != 0 ? view.ProcessPid : view.ActorPid;
            uint tid = view.EventThreadId != 0 ? view.EventThreadId : view.ThreadId;
            if (pid == 0 || tid == 0 || pid > int.MaxValue || tid > int.MaxValue)
            {
                return;
            }

            DateTime capturedUtc = view.TimestampUtc == default ? DateTime.UtcNow : view.TimestampUtc;
            string throttleKey = $"{pid}:{tid}";
            if (_observedHookStackLastPersistByThread.TryGetValue(throttleKey, out DateTime lastPersistUtc) &&
                capturedUtc < lastPersistUtc.AddMilliseconds(250))
            {
                return;
            }

            ThreadStackSessionSnapshot? snapshot = CreateObservedHookStackSnapshot(view, capturedUtc);
            if (snapshot == null || snapshot.Frames.Count == 0)
            {
                return;
            }

            _observedHookStackLastPersistByThread[throttleKey] = capturedUtc;
            PersistThreadStackSnapshot(unchecked((int)pid), unchecked((int)tid), string.Empty, snapshot);
        }

        private void QueueThreadStackFallbackCapture(BrokerEtwEventView view)
        {
            if (view.StackCount != 0 || !ShouldCaptureThreadStackFallback(view))
            {
                return;
            }

            uint pid = view.ProcessPid != 0 ? view.ProcessPid
                       : view.ActorPid != 0 ? view.ActorPid
                                            : view.EventProcessId;
            uint tid = view.EventThreadId != 0 ? view.EventThreadId : view.ThreadId;
            if (pid == 0 || tid == 0 || pid > int.MaxValue || tid > int.MaxValue)
            {
                return;
            }

            DateTime capturedUtc = view.TimestampUtc == default ? DateTime.UtcNow : view.TimestampUtc;
            string key = $"{pid}:{tid}";
            if (_threadStackFallbackLastCaptureByThread.TryGetValue(key, out DateTime lastCaptureUtc) &&
                capturedUtc < lastCaptureUtc.AddSeconds(6))
            {
                return;
            }

            if (_pendingThreadStackFallbackCaptures.Count >= 32)
            {
                return;
            }

            if (!_pendingThreadStackFallbackCaptures.TryAdd(key, 0))
            {
                return;
            }

            _threadStackFallbackLastCaptureByThread[key] = capturedUtc;
            int capturePid = unchecked((int)pid);
            int captureTid = unchecked((int)tid);
            _ = Task.Run(() =>
                         {
                             ThreadStackResolveResult result =
                                 ThreadStackResolver.Resolve(capturePid, captureTid, string.Empty);
                             return CreateThreadStackFallbackSnapshot(capturedUtc, result);
                         })
                    .ContinueWith(
                        task =>
                        {
                            _pendingThreadStackFallbackCaptures.TryRemove(key, out _);
                            if (task.Status != TaskStatus.RanToCompletion || task.Result == null ||
                                task.Result.Frames.Count == 0)
                            {
                                return;
                            }

                            Dispatcher.BeginInvoke(
                                new Action(
                                    () =>
                                    {
                                        PersistThreadStackSnapshot(capturePid, captureTid, string.Empty, task.Result);
                                        DebugConsoleService.WriteLocal(
                                            $"[STACK] captured fallback thread stack pid={capturePid} tid={captureTid} frames={task.Result.Frames.Count}");
                                    }),
                                DispatcherPriority.Background);
                        },
                        TaskScheduler.Default);
        }

        private static bool ShouldCaptureThreadStackFallback(BrokerEtwEventView view)
        {
            if (view.Family != BlackbirdNative.IpcEtwFamilyUserHook)
            {
                return false;
            }

            string api = !string.IsNullOrWhiteSpace(view.Operation) ? view.Operation : view.EventName;
            if (string.IsNullOrWhiteSpace(api))
            {
                return false;
            }

            if (!api.StartsWith("Nt", StringComparison.OrdinalIgnoreCase) &&
                !api.StartsWith("Zw", StringComparison.OrdinalIgnoreCase) &&
                !api.StartsWith("Co", StringComparison.OrdinalIgnoreCase) &&
                !api.Contains("Trace", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            bool highSignal = view.Severity >= 4 || IsDirectSyscallDetection(view) ||
                              api.Equals("NtMapViewOfSection", StringComparison.OrdinalIgnoreCase) ||
                              api.Equals("ZwMapViewOfSection", StringComparison.OrdinalIgnoreCase) ||
                              api.Equals("NtCreateSection", StringComparison.OrdinalIgnoreCase) ||
                              api.Equals("ZwCreateSection", StringComparison.OrdinalIgnoreCase) ||
                              api.Equals("NtWriteVirtualMemory", StringComparison.OrdinalIgnoreCase) ||
                              api.Equals("NtProtectVirtualMemory", StringComparison.OrdinalIgnoreCase) ||
                              api.Equals("NtCreateThreadEx", StringComparison.OrdinalIgnoreCase);
            if (!highSignal)
            {
                return false;
            }

            return view.SourceId == BlackbirdNative.IpcEtwSourceBlackbird ||
                   view.SourceId == BlackbirdNative.IpcEtwSourceUserHook ||
                   EventDetailFormatting.IsKernelHookTelemetry(view);
        }

        private static ThreadStackSessionSnapshot? CreateThreadStackFallbackSnapshot(DateTime capturedUtc,
                                                                                     ThreadStackResolveResult result)
        {
            if (result.Frames.Count == 0)
            {
                return null;
            }

            return new ThreadStackSessionSnapshot { CapturedAtUtc = capturedUtc,
                                                    TebAddress = result.TebAddress,
                                                    StackBase = result.StackBase,
                                                    StackTop = result.StackTop,
                                                    TebFlags = result.TebFlags,
                                                    StackPointer = result.StackPointer,
                                                    ContextSnapshot =
                                                        CloneThreadContextSnapshot(result.ContextSnapshot),
                                                    Frames = result.Frames.Select(CloneStackFrameRow).ToList() };
        }

        private static StackFrameRow
        CloneStackFrameRow(StackFrameRow frame) => new() { Index = frame.Index,
                                                           Address = frame.Address,
                                                           Module = frame.Module,
                                                           Symbol = frame.Symbol,
                                                           InstructionPointerRaw = frame.InstructionPointerRaw,
                                                           FramePointerRaw = frame.FramePointerRaw,
                                                           FrameSpanBytes = frame.FrameSpanBytes,
                                                           IsCurrent = frame.IsCurrent };

        private static ThreadContextSnapshot? CloneThreadContextSnapshot(ThreadContextSnapshot? snapshot)
        {
            if (snapshot == null)
            {
                return null;
            }

            return new ThreadContextSnapshot {
                Rip = snapshot.Rip, Rsp = snapshot.Rsp, Rbp = snapshot.Rbp, Rax = snapshot.Rax,      Rbx = snapshot.Rbx,
                Rcx = snapshot.Rcx, Rdx = snapshot.Rdx, Rsi = snapshot.Rsi, Rdi = snapshot.Rdi,      R8 = snapshot.R8,
                R9 = snapshot.R9,   R10 = snapshot.R10, R11 = snapshot.R11, R12 = snapshot.R12,      R13 = snapshot.R13,
                R14 = snapshot.R14, R15 = snapshot.R15, Dr0 = snapshot.Dr0, Dr1 = snapshot.Dr1,      Dr2 = snapshot.Dr2,
                Dr3 = snapshot.Dr3, Dr6 = snapshot.Dr6, Dr7 = snapshot.Dr7, EFlags = snapshot.EFlags
            };
        }

        private static ThreadStackSessionSnapshot? CreateObservedHookStackSnapshot(BrokerEtwEventView view,
                                                                                   DateTime capturedUtc)
        {
            ulong[] stack = view.Stack ?? Array.Empty<ulong>();
            int count = Math.Min(Math.Min((int)view.StackCount, stack.Length), BlackbirdNative.MaxIpcStackFrames);
            if (count <= 0)
            {
                return null;
            }

            Dictionary<string, string> fields = BuildHookFieldMap(view);
            var frames = new List<StackFrameRow>(count);
            for (int i = 0; i < count; i += 1)
            {
                ulong ip = stack[i];
                if (ip == 0)
                {
                    continue;
                }

                string symbol = ReadTrimmedField(fields, $"stack{i}Symbol");
                string path = ReadTrimmedField(fields, $"stack{i}Path");
                string module = ModuleNameFromPath(path);
                if (module.Equals("unknown", StringComparison.OrdinalIgnoreCase))
                {
                    module = ExtractModuleFromSymbol(symbol);
                }

                frames.Add(new StackFrameRow { Index = frames.Count, Address = $"0x{ip:X}", Module = module,
                                               Symbol = string.IsNullOrWhiteSpace(symbol) ? $"0x{ip:X}" : symbol,
                                               InstructionPointerRaw = ip, IsCurrent = frames.Count == 0 });
            }

            if (frames.Count == 0)
            {
                return null;
            }

            ulong stackPointer = FirstU64(fields, "rsp", "sp", "stackPointer", "StackPointer");
            return new ThreadStackSessionSnapshot { CapturedAtUtc = capturedUtc, StackPointer = stackPointer,
                                                    Frames = frames };
        }

        private static string ReadTrimmedField(IReadOnlyDictionary<string, string> fields, string key)
        {
            return fields.TryGetValue(key, out string? value) && !string.IsNullOrWhiteSpace(value)
                       ? value.Trim()
                       : string.Empty;
        }

        private static string ExtractModuleFromSymbol(string symbol)
        {
            string value = (symbol ?? string.Empty).Trim();
            int bang = value.IndexOf('!');
            return bang > 0 ? value[..bang].Trim() : string.Empty;
        }

        private static uint DirectSyscallSeverityFloor(BrokerEtwEventView view)
        {
            bool highRisk = IsHighRiskIoctlAccess(view.DesiredAccess, (view.Flags & HandleFlagThreadObject) != 0);
            if ((view.Flags & HandleFlagSyscallExportMismatch) != 0)
            {
                return 6;
            }
            if (highRisk || (view.Flags & HandleFlagStackSpoofSuspect) != 0)
            {
                return 5;
            }
            if ((view.Flags & HandleFlagExecProtect) != 0 && (view.Flags & HandleFlagFromNtdll) == 0)
            {
                return 4;
            }

            return 3;
        }

        private static string BuildDirectSyscallDetectionName(BrokerEtwEventView view)
        {
            string syscallName = EventDetailFormatting.ResolveDirectSyscallApi(view.DesiredAccess, view.Flags);
            return string.IsNullOrWhiteSpace(syscallName) ? "DIRECT_SYSCALL_SUSPECT_HANDLE_OPERATION"
                                                          : $"DIRECT_SYSCALL_SUSPECT_HANDLE_OPERATION [{syscallName}]";
        }

        private static string BuildEtwDirectSyscallEvidenceText(BrokerEtwEventView view)
        {
            string syscallName = EventDetailFormatting.ResolveDirectSyscallApi(view.DesiredAccess, view.Flags);
            string syscallLabel = EventDetailFormatting.BuildDirectSyscallLabel(
                view.DesiredAccess, view.Flags, view.DeepSample, (int)view.DeepSampleSize);
            string accessDecoded = EventDetailFormatting.DescribeHandleAccess(view.DesiredAccess);
            string flagsDecoded = EventDetailFormatting.DescribeHandleFlags(view.Flags);
            string originModule = EventDetailFormatting.ModuleNameFromPath(view.OriginPath);
            string sampleHex = EventDetailFormatting.FormatSampleHex(view.DeepSample, (int)view.DeepSampleSize);
            string sampleDisasm =
                EventDetailFormatting.InferSampleDisassembly(view.DeepSample, (int)view.DeepSampleSize);

            string stack0 = view.StackCount > 0 && view.Stack.Length > 0 ? $"0x{view.Stack[0]:X}" : "n/a";
            string stack1 = view.StackCount > 1 && view.Stack.Length > 1 ? $"0x{view.Stack[1]:X}" : "n/a";

            return $"etwEvidence class={view.ClassName} syscallName={syscallName} syscallLabel={syscallLabel.Replace(' ', '_')} " +
                   $"access=0x{view.DesiredAccess:X8} ({accessDecoded}) flags=0x{view.Flags:X8} ({flagsDecoded}) handleFlags=0x{view.Flags:X8} " +
                   $"origin=0x{view.OriginAddress:X} protect=0x{view.OriginProtect:X8} module={originModule} " +
                   $"path={view.OriginPath} allocationBase=0x{view.DeepAllocationBase:X} regionSize=0x{view.DeepRegionSize:X} " +
                   $"regionProtect=0x{view.DeepRegionProtect:X8} ({EventDetailFormatting.DescribeMemoryProtection(view.DeepRegionProtect)}) " +
                   $"stack0={stack0} stack1={stack1} deepSampleSize={view.DeepSampleSize} deepSample={sampleHex} sampleDisasmHint={sampleDisasm}";
        }

        private HeuristicEventView? CreatePromotedHeuristic(BrokerEtwEventView view)
        {
            if (IsBlackbirdOwnEvent(view))
                return null;

            string detection = view.DetectionName;
            if (string.IsNullOrWhiteSpace(detection) && IsDirectSyscallDetection(view))
            {
                detection = BuildDirectSyscallDetectionName(view);
            }
            if (string.IsNullOrWhiteSpace(detection) || !ShouldPromoteHeuristic(view))
            {
                return null;
            }

            uint actor = view.ActorPid;
            uint target = view.TargetPid;
            string reasonText = string.IsNullOrWhiteSpace(view.Reason) ? "<none>" : view.Reason;
            uint sanitizedCorrFlags = view.CorrelationFlags & CorrelationIntentMask;
            string corrFlagsDecoded = EventDetailFormatting.DescribeCorrelationFlags(sanitizedCorrFlags);
            string corrAccessDecoded = EventDetailFormatting.DescribeHandleAccess(view.CorrelationAccessMask);
            string heuristicEvidence = "<none>";
            bool hasEvidence = TryGetHandleEvidence(actor, target, out IoctlParsedEvent evidence);
            if (hasEvidence)
            {
                heuristicEvidence = BuildHandleEvidenceText(evidence);
            }
            if (IsDirectSyscallDetection(view))
            {
                if (hasEvidence && !ShouldKeepDirectSyscallHeuristicFromEvidence(evidence))
                {
                    return null;
                }
                if (!hasEvidence && view.Family == BlackbirdNative.IpcEtwFamilyHandle)
                {
                    heuristicEvidence = BuildEtwDirectSyscallEvidenceText(view);
                }
            }

            string rawCorrFlagsSuffix = view.CorrelationFlags == sanitizedCorrFlags
                                            ? string.Empty
                                            : $"; rawCorrFlags=0x{view.CorrelationFlags:X8}";
            uint severity = IsDirectSyscallDetection(view) ? Math.Max(view.Severity, DirectSyscallSeverityFloor(view))
                                                           : view.Severity;

            return new HeuristicEventView {
                TimestampUtc = view.TimestampUtc,
                LastSeenUtc = view.TimestampUtc,
                Severity = severity,
                DetectionName = detection,
                ActorPid = actor,
                TargetPid = target,
                Source = view.Source,
                EventName = view.EventName ?? string.Empty,
                CorrelationFlags = sanitizedCorrFlags,
                CorrelationAccessMask = view.CorrelationAccessMask,
                CorrelationAgeMs = view.CorrelationAgeMs,
                Reason =
                    $"reason={reasonText}; corrFlags={corrFlagsDecoded}; corrAccess={corrAccessDecoded}; corrAgeMs={view.CorrelationAgeMs}{rawCorrFlagsSuffix}",
                Evidence = heuristicEvidence,
                RepeatCount = 1
            };
        }

        private static string BuildFallbackDetectionLabel(string detectionName, string eventName, ushort task,
                                                          ushort opcode, ushort eventId, uint correlationFlags)
        {
            if (!string.IsNullOrWhiteSpace(detectionName) &&
                !detectionName.Equals("UNKNOWN", StringComparison.OrdinalIgnoreCase))
            {
                return detectionName;
            }

            string name = eventName?.Trim() ?? string.Empty;
            if (name.Equals("ThreadTelemetry", StringComparison.OrdinalIgnoreCase))
            {
                if (correlationFlags != 0)
                {
                    return $"THREAD_ACTIVITY[{EventDetailFormatting.DescribeCorrelationFlags(correlationFlags)}]";
                }

                return "THREAD_ACTIVITY";
            }

            if (name.Equals("HandleTelemetry", StringComparison.OrdinalIgnoreCase))
            {
                return "HANDLE_ACTIVITY";
            }

            if (name.Equals("ApcTelemetry", StringComparison.OrdinalIgnoreCase))
            {
                return "APC_ACTIVITY";
            }

            if (name.Equals("DetectionTelemetry", StringComparison.OrdinalIgnoreCase))
            {
                return "DETECTION_UNSPECIFIED";
            }

            if (!string.IsNullOrWhiteSpace(name) && name.EndsWith("Telemetry", StringComparison.OrdinalIgnoreCase))
            {
                string baseName = name[..^ "Telemetry".Length].Trim();
                if (!string.IsNullOrWhiteSpace(baseName))
                {
                    return $"{baseName.ToUpperInvariant()}_ACTIVITY";
                }
            }

            if (!string.IsNullOrWhiteSpace(detectionName))
            {
                return detectionName;
            }

            if (task == 0 && opcode == 0 && eventId == 0)
            {
                return "TELEMETRY";
            }

            if (!string.IsNullOrWhiteSpace(name))
            {
                return name;
            }

            return "UNCLASSIFIED_EVENT";
        }

        private TelemetryEvent? HandleApiHookEvent(BrokerEtwEventView view)
        {
            if (!ShouldIncludeApiGraphView(view))
            {
                return null;
            }

            string apiName = !string.IsNullOrWhiteSpace(view.EventName)
                                 ? view.EventName
                                 : (!string.IsNullOrWhiteSpace(view.Operation) ? view.Operation : "unknown");
            string sensorOrigin = EventDetailFormatting.ClassifyHookSensorOrigin(view);
            uint sourcePid = view.ActorPid != 0 ? view.ActorPid : view.ProcessPid;
            if (sourcePid == 0)
            {
                sourcePid = view.EventProcessId;
            }
            uint targetPid = view.TargetPid != 0 ? view.TargetPid : sourcePid;
            uint threadId = view.ThreadId != 0 ? view.ThreadId : view.EventThreadId;
            if (sourcePid == 0)
            {
                return null;
            }

            string callerOrigin = NormalizeApiCallerOrigin(view.CallerOriginLabel);
            Dictionary<string, string> hookFields = BuildHookFieldMap(view);
            string originModule = NormalizeApiOriginModule(ResolveHookOriginModule(view, hookFields));
            string key =
                BuildApiGraphKey(sourcePid, targetPid, threadId, apiName, sensorOrigin, callerOrigin, originModule);
            int currentHits;
            if (_apiGraphRowsByKey.TryGetValue(key, out ApiCallGraphRowSnapshot? existing))
            {
                existing.Hits = Math.Max(1, existing.Hits + 1);
                existing.LastSeenUtc = view.TimestampUtc;
                existing.SensorOrigin = sensorOrigin;
                existing.CallerOrigin = callerOrigin;
                existing.OriginModule = originModule;
                currentHits = existing.Hits;
            }
            else
            {
                _apiGraphRowsByKey[key] = new ApiCallGraphRowSnapshot { ApiName = apiName,
                                                                        SensorOrigin = sensorOrigin,
                                                                        CallerOrigin = callerOrigin,
                                                                        OriginModule = originModule,
                                                                        SourcePid = sourcePid,
                                                                        TargetPid = targetPid,
                                                                        ThreadId = threadId,
                                                                        Hits = 1,
                                                                        FirstSeenUtc = view.TimestampUtc,
                                                                        LastSeenUtc = view.TimestampUtc };
                currentHits = 1;
            }

            string rawReason = view.Reason ?? string.Empty;
            _apiGraphReasonByKey[key] = rawReason;
            (string decodedAction, string decodedDetail) = BuildApiDecodedAction(view, rawReason);
            _apiGraphActionByKey[key] = decodedAction;
            _apiGraphDecodedByKey[key] = decodedDetail;
            string frameSummary = BuildHookFrameSummary(view, hookFields);
            _apiGraphFramesByKey[key] = frameSummary;
            _apiGraphSensorByKey[key] = sensorOrigin;
            ApiCallStructuredFields structured = BuildApiCallStructuredFields(apiName, rawReason, decodedAction, view);
            ApiCallGraphRowSnapshot snapshot = _apiGraphRowsByKey[key];
            snapshot.ActionLabel = decodedAction;
            snapshot.DetailFull = decodedDetail;
            snapshot.CallChainLabel = frameSummary;
            snapshot.ContextLabel = structured.Field2Value;
            snapshot.FlagsLabel = structured.Field4Value;

            ScheduleApiGraphSnapshot();
            if (string.IsNullOrWhiteSpace(decodedDetail))
            {
                return null;
            }

            if (!ShouldEmitApiTimelineEvent(key, currentHits, view.TimestampUtc))
            {
                return null;
            }

            return new TelemetryEvent { TimestampUtc = view.TimestampUtc,
                                        PID = unchecked((int)sourcePid),
                                        TID = unchecked((int)threadId),
                                        Group = EventDetailFormatting.HookTimelineGroup(view),
                                        SubType = apiName,
                                        Summary =
                                            $"{apiName} [caller {sourcePid} target {targetPid} hits {currentHits}]",
                                        Details = decodedDetail };
        }

        private bool ShouldIncludeApiGraphView(BrokerEtwEventView view)
        {
            return EventDetailFormatting.IsApiGraphCandidate(view);
        }

        private bool ShouldEmitApiTimelineEvent(string key, int hits, DateTime timestampUtc)
        {
            if (hits <= 1)
            {
                _apiGraphTimelineLastEmitByKey[key] = timestampUtc;
                return true;
            }

            if (!_apiGraphTimelineLastEmitByKey.TryGetValue(key, out DateTime lastEmitUtc))
            {
                _apiGraphTimelineLastEmitByKey[key] = timestampUtc;
                return true;
            }

            bool milestone = (hits & (hits - 1)) == 0 || (hits % 32) == 0;
            bool elapsed = (timestampUtc - lastEmitUtc) >= ApiTimelineEmissionWindow;
            if (!milestone && !elapsed)
            {
                return false;
            }

            _apiGraphTimelineLastEmitByKey[key] = timestampUtc;
            return true;
        }

        private void PublishApiGraphSnapshot()
        {
            BackfillApiGraphFromEtwHistoryIfNeeded();

            var snapshot = _apiGraphRowsByKey.Values.Select(static x => x.Clone())
                               .OrderByDescending(x => x.Hits)
                               .ThenByDescending(x => x.LastSeenUtc)
                               .Take(800)
                               .ToList();

            _apiGraphSnapshotRows.Clear();
            _apiGraphSnapshotRows.AddRange(snapshot);
            RefreshApiViewPresentation();
        }

        private void BackfillApiGraphFromEtwHistoryIfNeeded()
        {
            if (_apiGraphRowsByKey.Count != 0)
            {
                return;
            }

            IEnumerable<GroupedEventRow> sourceGroups =
                EtwPaneHost.ItemCount > 0
                    ? EtwPaneHost.SnapshotItems()
                    : (_currentSession != null && _etwHistoryByPid.TryGetValue(_currentSession.Pid, out var history)
                           ? history
                           : Array.Empty<GroupedEventRow>());
            foreach (GroupedEventDetailRow detail in sourceGroups.SelectMany(x => x.Details))
            {
                ObserveApiGraphDetailFallback(detail);
            }
        }

        private void ObserveApiGraphDetailFallback(GroupedEventDetailRow detail)
        {
            if (detail == null || string.IsNullOrWhiteSpace(detail.Event) || !IsLikelyApiHookDetail(detail))
            {
                return;
            }

            string apiName = detail.Event;
            string sensorOrigin = detail.Source.IndexOf("kernel", StringComparison.OrdinalIgnoreCase) >= 0
                                      ? "Kernel Hook"
                                  : detail.Source.IndexOf("hook", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                          detail.Detection.StartsWith("USERMODE_", StringComparison.OrdinalIgnoreCase)
                                      ? "Usermode Hook"
                                      : "Unclassified";
            string callerOrigin = "unknown";
            string originModule = "unknown";
            uint sourcePid = detail.ActorPid;
            uint targetPid = detail.TargetPid != 0 ? detail.TargetPid : detail.ActorPid;
            uint threadId = 0;
            _ = uint.TryParse(detail.EventTid, NumberStyles.Integer, CultureInfo.InvariantCulture, out threadId);
            string key =
                BuildApiGraphKey(sourcePid, targetPid, threadId, apiName, sensorOrigin, callerOrigin, originModule);
            if (_apiGraphRowsByKey.TryGetValue(key, out ApiCallGraphRowSnapshot? existing))
            {
                existing.Hits = Math.Max(1, existing.Hits + Math.Max(1, detail.HitCount));
                existing.LastSeenUtc = detail.TimestampUtc;
                return;
            }

            _apiGraphRowsByKey[key] = new ApiCallGraphRowSnapshot {
                ApiName = apiName,
                SensorOrigin = sensorOrigin,
                CallerOrigin = callerOrigin,
                OriginModule = originModule,
                ActionLabel = string.IsNullOrWhiteSpace(detail.Detection) ? apiName : detail.Detection,
                DetailFull = string.IsNullOrWhiteSpace(detail.Details) ? detail.ArgumentSummary : detail.Details,
                CallChainLabel = string.Empty,
                ContextLabel = detail.ArgumentSummary,
                FlagsLabel = string.IsNullOrWhiteSpace(detail.Flags) ? detail.Access : detail.Flags,
                SourcePid = sourcePid,
                TargetPid = targetPid,
                ThreadId = threadId,
                Hits = Math.Max(1, detail.HitCount),
                FirstSeenUtc = detail.TimestampUtc,
                LastSeenUtc = detail.TimestampUtc
            };
            _apiGraphSensorByKey[key] = sensorOrigin;
        }

        private static bool IsLikelyApiHookDetail(GroupedEventDetailRow detail)
        {
            if (detail.Source.IndexOf("hook", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return true;
            }

            if (detail.Detection.StartsWith("USERMODE_", StringComparison.OrdinalIgnoreCase))
            {
                return !detail.Detection.Contains("INTEGRITY", StringComparison.OrdinalIgnoreCase);
            }

            return detail.Event.StartsWith("Nt", StringComparison.OrdinalIgnoreCase) ||
                   detail.Event.StartsWith("Zw", StringComparison.OrdinalIgnoreCase);
        }

        private bool ObserveExtendedActivity(BrokerEtwEventView view)
        {
            if (!TryBuildExtendedActivityRow(view, out ExtendedActivityRowSnapshot? row) || row == null)
            {
                return false;
            }

            string key = BuildExtendedActivityKey(row.TypeLabel, row.ActorLabel, row.TargetLabel, row.SubjectLabel,
                                                  row.OperationLabel);
            if (_extendedRowsByKey.TryGetValue(key, out ExtendedActivityRowSnapshot? existing))
            {
                existing.Hits = Math.Max(1, existing.Hits + 1);
                existing.LastSeenUtc = row.LastSeenUtc;
                existing.LastSeenLabel = row.LastSeenLabel;
                existing.DetailLabel = row.DetailLabel;
                return true;
            }

            _extendedRowsByKey[key] = row;
            return true;
        }

        private void ScheduleExtendedActivitySnapshot()
        {
            _extendedViewSnapshotDirty = true;
            _extendedViewRefreshTimer.Start();
        }

        private void FlushExtendedActivitySnapshot()
        {
            if (!_extendedViewSnapshotDirty)
            {
                _extendedViewRefreshTimer.Stop();
                return;
            }

            _extendedViewSnapshotDirty = false;
            PublishExtendedActivitySnapshot();
        }

        private void PublishExtendedActivitySnapshot()
        {
            List<ExtendedActivityRowSnapshot> snapshot = _extendedRowsByKey.Values.Select(static x => x.Clone())
                                                             .OrderByDescending(x => x.LastSeenUtc)
                                                             .ThenByDescending(x => x.Hits)
                                                             .Take(800)
                                                             .ToList();

            _extendedViewRows.ReplaceAll(snapshot);
            _extendedComRows.ReplaceAll(snapshot.Where(IsExtendedComRow).ToList());
            _extendedEtwRows.ReplaceAll(snapshot.Where(IsExtendedEtwRow).ToList());
            _extendedJobRows.ReplaceAll(snapshot.Where(IsExtendedJobRow).ToList());
            _extendedYaraRows.ReplaceAll(snapshot.Where(IsExtendedYaraRow).ToList());
            if (ExtendedViewSummaryBlock != null)
            {
                ExtendedViewSummaryBlock.Text =
                    snapshot.Count == 0 ? "No extended activity yet"
                                        : $"Activities: {snapshot.Count} / Hits: {snapshot.Sum(x => x.Hits)}";
            }
        }

        private static bool IsExtendedComRow(ExtendedActivityRowSnapshot row)
        {
            return row.TypeLabel.Contains("COM", StringComparison.OrdinalIgnoreCase) ||
                   row.TypeLabel.Contains("WMI", StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsExtendedEtwRow(ExtendedActivityRowSnapshot row)
        {
            return row.TypeLabel.Contains("ETW", StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsExtendedJobRow(ExtendedActivityRowSnapshot row)
        {
            return row.TypeLabel.Contains("Job", StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsExtendedYaraRow(ExtendedActivityRowSnapshot row)
        {
            return row.TypeLabel.Contains("YARA", StringComparison.OrdinalIgnoreCase) ||
                   row.TypeLabel.Contains("SIGMA", StringComparison.OrdinalIgnoreCase) ||
                   row.TypeLabel.Contains("Rules", StringComparison.OrdinalIgnoreCase);
        }

        private bool TryBuildExtendedActivityRow(BrokerEtwEventView view, out ExtendedActivityRowSnapshot? row)
        {
            row = null;
            string detection = view.DetectionName ?? string.Empty;
            string type;
            string operation;

            switch (detection)
            {
            case "USERMODE_COM_INIT":
                type = "COM Init";
                operation = "Initialize";
                break;
            case "USERMODE_COM_SECURITY_INIT":
                type = "COM Security";
                operation = "InitializeSecurity";
                break;
            case "USERMODE_COM_INSTANCE_CREATE":
                type = "COM Activation";
                operation = "CreateInstance";
                break;
            case "USERMODE_WMI_ACTIVITY":
                type = "WMI";
                operation = "Locator Activation";
                break;
            case "USERMODE_ETW_PROVIDER_REGISTER":
                type = "ETW Provider";
                operation = "Register";
                break;
            case "USERMODE_ETW_PROVIDER_UNREGISTER":
                type = "ETW Provider";
                operation = "Unregister";
                break;
            case "USERMODE_ETW_SESSION_CONTROL":
                type = "ETW Session";
                operation = "StartTrace";
                break;
            case "USERMODE_ETW_SUBSCRIPTION":
                type = "ETW Subscription";
                operation = "EnableTrace";
                break;
            case "USERMODE_JOB_OBJECT_ACTIVITY":
                type = "Job Object";
                operation = !string.IsNullOrWhiteSpace(view.EventName) ? view.EventName : "Activity";
                break;
            default:
                if (!TryBuildGenericExtendedActivityLabels(view, out type, out operation))
                {
                    return false;
                }
                break;
            }

            uint actorPid = ResolveExtendedActorPid(view);
            uint targetPid = ResolveExtendedTargetPid(view, actorPid);
            string subject = ExtractExtendedSubject(view);
            row = new ExtendedActivityRowSnapshot { TypeLabel = type,
                                                    ActorLabel = FormatApiProcessLabel(actorPid),
                                                    TargetLabel = FormatApiProcessLabel(targetPid),
                                                    SubjectLabel = subject,
                                                    OperationLabel = operation,
                                                    DetailLabel =
                                                        FirstNonBlank(view.Reason, view.ArgumentSummary, view.Details),
                                                    LastSeenUtc = view.TimestampUtc,
                                                    LastSeenLabel = FormatApiRelativeAge(view.TimestampUtc),
                                                    Hits = 1 };
            return true;
        }

        private static bool TryBuildGenericExtendedActivityLabels(BrokerEtwEventView view, out string type,
                                                                  out string operation)
        {
            type = view.Family switch { BlackbirdNative.IpcEtwFamilyHandle => "Handle",
                                        BlackbirdNative.IpcEtwFamilyThread => "Thread",
                                        BlackbirdNative.IpcEtwFamilyProcess => "Process",
                                        BlackbirdNative.IpcEtwFamilyImage => "Image",
                                        BlackbirdNative.IpcEtwFamilyRegistry => "Registry",
                                        BlackbirdNative.IpcEtwFamilyApc => "APC",
                                        BlackbirdNative.IpcEtwFamilyDetection => "Detection",
                                        BlackbirdNative.IpcEtwFamilyThreatIntel => "Threat Intel",
                                        BlackbirdNative.IpcEtwFamilySocket => "Socket",
                                        BlackbirdNative.IpcEtwFamilyUserHook => "API",
                                        _ => string.IsNullOrWhiteSpace(view.Source) ? string.Empty : view.Source };
            operation = FirstNonBlank(view.Operation, view.EventName, view.DetectionName, "Activity");

            if (string.IsNullOrWhiteSpace(type))
            {
                return false;
            }

            return view.Family == BlackbirdNative.IpcEtwFamilyUserHook ||
                   view.Family == BlackbirdNative.IpcEtwFamilySocket ||
                   view.Family == BlackbirdNative.IpcEtwFamilyRegistry ||
                   view.Family == BlackbirdNative.IpcEtwFamilyImage ||
                   view.Family == BlackbirdNative.IpcEtwFamilyProcess ||
                   view.Family == BlackbirdNative.IpcEtwFamilyThread ||
                   view.Family == BlackbirdNative.IpcEtwFamilyHandle ||
                   !string.IsNullOrWhiteSpace(view.DetectionName) || view.Severity >= 2;
        }

        private static uint ResolveExtendedActorPid(BrokerEtwEventView view) =>
            FirstNonZero(view.ActorPid, view.CallerPid, view.CreatorPid, view.ProcessPid, view.EventProcessId);

        private static uint ResolveExtendedTargetPid(BrokerEtwEventView view, uint actorPid) =>
            FirstNonZero(view.TargetPid, view.ExplicitTargetPid, view.ProcessPid, view.EventProcessId, actorPid);

        private static string ExtractExtendedSubject(BrokerEtwEventView view)
        {
            string reason = view.Reason ?? string.Empty;
            string[] tokens = new[] { "class=", "provider=", "name=", "mode=", "class=" };
            foreach (string token in tokens)
            {
                int start = reason.IndexOf(token, StringComparison.OrdinalIgnoreCase);
                if (start < 0)
                {
                    continue;
                }

                start += token.Length;
                int end = reason.IndexOf(' ', start);
                if (end < 0)
                {
                    end = reason.Length;
                }

                string value = reason.Substring(start, end - start).Trim();
                if (!string.IsNullOrWhiteSpace(value))
                {
                    return value;
                }
            }

            return FirstNonBlank(view.KeyPath, view.ValueName, view.ImagePath, view.OriginPath, view.CommandLine,
                                 view.ClassName, view.ArgumentSummary, view.EventName, view.DetectionName);
        }

        private static uint FirstNonZero(params uint[] values)
        {
            foreach (uint value in values)
            {
                if (value != 0)
                {
                    return value;
                }
            }

            return 0;
        }

        private static string FirstNonBlank(params string?[] values)
        {
            foreach (string? value in values)
            {
                if (!string.IsNullOrWhiteSpace(value))
                {
                    return value.Trim();
                }
            }

            return string.Empty;
        }

        private static string BuildExtendedActivityKey(string type, string actor, string target, string subject,
                                                       string operation)
        {
            return string.Join("|", type, actor, target, subject, operation);
        }

        private void RefreshApiViewPresentation()
        {
            string? selectedKey = (ApiViewDataGrid?.SelectedItem as ApiCallGraphMainRowView)?.GraphKey;
            bool apiViewVisible = _mainViewMode == MainInterfaceViewMode.Api && ApiViewBorder != null &&
                                  ApiViewBorder.Visibility == Visibility.Visible;
            List<ApiCallGraphMainRowView> sourceRows =
                _apiViewPresentationMode == ApiViewPresentationMode.ThreadTimeline
                    ? BuildApiThreadTimelineRows(_apiGraphSnapshotRows)
                    : BuildApiCallGraphRows(_apiGraphSnapshotRows);
            _apiViewSnapshotRows.Clear();
            _apiViewSnapshotRows.AddRange(sourceRows);

            List<ApiCallGraphMainRowView> filteredRows = ApplyApiViewFilters(sourceRows);
            _apiViewRows.ReplaceAll(filteredRows);

            if (ApiViewSummaryBlock != null)
            {
                string noun =
                    _apiViewPresentationMode == ApiViewPresentationMode.ThreadTimeline ? "Thread/API Rows" : "Patterns";
                ApiViewSummaryBlock.Text =
                    sourceRows.Count == 0 ? "No API hook data yet"
                    : filteredRows.Count == sourceRows.Count
                        ? $"{noun}: {filteredRows.Count} / Calls: {filteredRows.Sum(x => x.Hits)}"
                        : $"{noun}: {filteredRows.Count}/{sourceRows.Count} / Calls: {filteredRows.Sum(x => x.Hits)}";
            }
            if (apiViewVisible && ApiViewGraphCanvas != null)
            {
                RenderApiPresentationCanvas(filteredRows, selectedKey);
            }
            DiagnosticsState.SetValue(
                "API Graph",
                $"{(_apiViewPresentationMode == ApiViewPresentationMode.ThreadTimeline ? "threads" : "patterns")}={filteredRows.Count}/{sourceRows.Count} visible={apiViewVisible}");

            if (ApiViewDataGrid != null)
            {
                ApiCallGraphMainRowView? selected = null;
                if (!string.IsNullOrWhiteSpace(selectedKey))
                {
                    selected = _apiViewRows.FirstOrDefault(
                        x => string.Equals(x.GraphKey, selectedKey, StringComparison.Ordinal));
                }

                if (selected == null && _apiViewRows.Count > 0)
                {
                    selected = _apiViewRows[0];
                }

                ApiViewDataGrid.SelectedItem = selected;
                UpdateApiViewSelection(selected);
            }
        }

        private void RefreshApiGraphSelectionVisual()
        {
            if (_mainViewMode != MainInterfaceViewMode.Api || ApiViewBorder == null ||
                ApiViewBorder.Visibility != Visibility.Visible || ApiViewGraphCanvas == null)
            {
                return;
            }

            string? selectedKey = (ApiViewDataGrid?.SelectedItem as ApiCallGraphMainRowView)?.GraphKey;
            List<ApiCallGraphMainRowView> filteredRows = ApplyApiViewFilters(_apiViewSnapshotRows);
            RenderApiPresentationCanvas(filteredRows, selectedKey);
        }

        private List<ApiCallGraphMainRowView> BuildApiCallGraphRows(IReadOnlyList<ApiCallGraphRowSnapshot> snapshot)
        {
            int maxHits = Math.Max(1, snapshot.Count == 0 ? 1 : snapshot.Max(x => Math.Max(1, x.Hits)));
            var rows = new List<ApiCallGraphMainRowView>(snapshot.Count);
            foreach (ApiCallGraphRowSnapshot row in snapshot)
            {
                uint target = row.TargetPid != 0 ? row.TargetPid : row.SourcePid;
                string sensor = string.IsNullOrWhiteSpace(row.SensorOrigin) ? "Unclassified" : row.SensorOrigin;
                string callerOrigin = NormalizeApiCallerOrigin(row.CallerOrigin);
                string originModule = NormalizeApiOriginModule(row.OriginModule);
                string key = BuildApiGraphKey(row.SourcePid, row.TargetPid, row.ThreadId, row.ApiName, sensor,
                                              callerOrigin, originModule);
                double heatPercent = Math.Clamp((row.Hits / (double)maxHits) * 100.0, 0.0, 100.0);
                rows.Add(new ApiCallGraphMainRowView {
                    GraphKey = key,
                    ThreadGroupKey = $"{row.SourcePid}|{row.ThreadId}",
                    ViewModeKey = "call",
                    ApiName = string.IsNullOrWhiteSpace(row.ApiName) ? "unknown" : row.ApiName,
                    OriginModule = originModule,
                    ActionLabel = row.ActionLabel,
                    SensorLabel = sensor,
                    CallerOriginKey = callerOrigin,
                    CallerOriginLabel = GetApiCallerOriginDisplayLabel(callerOrigin, sensor),
                    CallChainLabel = row.CallChainLabel,
                    CallerOriginBackground = BuildApiCallerOriginBackground(callerOrigin),
                    CallerOriginForeground = BuildApiCallerOriginForeground(callerOrigin),
                    SensorBackground = BuildApiSensorBackground(sensor),
                    SensorForeground = BuildApiSensorForeground(sensor),
                    HeatTrackBackground = BuildApiHeatTrackBackground(sensor, callerOrigin),
                    HeatFillBackground = BuildApiHeatFillBackground(sensor, callerOrigin),
                    RowBackground = BuildApiRowBackground(sensor, callerOrigin),
                    RowBorderBrush = BuildApiRowBorder(sensor, callerOrigin),
                    SourceLabel = FormatApiProcessLabel(row.SourcePid),
                    TargetLabel = FormatApiProcessLabel(target),
                    ThreadLabel =
                        row.ThreadId == 0 ? string.Empty : row.ThreadId.ToString(CultureInfo.InvariantCulture),
                    SizeLabel = row.ContextLabel,
                    ProtectLabel = row.FlagsLabel,
                    Field2Label = "Context",
                    Field4Label = "Flags",
                    Hits = Math.Max(1, row.Hits),
                    HeatPercent = heatPercent,
                    ActivityFillWidth = Math.Round((heatPercent / 100.0) * 110.0),
                    FirstSeen = FormatApiRelativeAge(row.FirstSeenUtc),
                    AbsoluteFirstSeen = row.FirstSeenUtc == default
                                            ? string.Empty
                                            : row.FirstSeenUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss.fff",
                                                                                      CultureInfo.InvariantCulture),
                    FirstSeenUtc = row.FirstSeenUtc,
                    LastSeen = FormatApiRelativeAge(row.LastSeenUtc),
                    AbsoluteLastSeen = row.LastSeenUtc == default
                                           ? string.Empty
                                           : row.LastSeenUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss.fff",
                                                                                    CultureInfo.InvariantCulture),
                    LastSeenUtc = row.LastSeenUtc,
                    DetailFull = row.DetailFull
                });
            }

            return rows;
        }

        private List<ApiCallGraphMainRowView>
        BuildApiThreadTimelineRows(IReadOnlyList<ApiCallGraphRowSnapshot> snapshot)
        {
            var groups =
                snapshot
                    .GroupBy(
                        row =>
                            $"{row.SourcePid}|{row.TargetPid}|{row.ThreadId}|{NormalizeApiOriginModule(row.OriginModule)}|{row.ApiName}",
                        StringComparer.Ordinal)
                    .Select(
                        group =>
                        {
                            ApiCallGraphRowSnapshot latest = group.OrderByDescending(x => x.LastSeenUtc).First();
                            int hits = group.Sum(x => Math.Max(1, x.Hits));
                            DateTime firstSeenUtc = group.Where(x => x.FirstSeenUtc != default)
                                                        .Select(x => x.FirstSeenUtc)
                                                        .DefaultIfEmpty(latest.LastSeenUtc)
                                                        .Min();
                            DateTime lastSeenUtc = group.Max(x => x.LastSeenUtc);
                            string sensor =
                                group.Select(x => x.SensorOrigin).FirstOrDefault(x => !string.IsNullOrWhiteSpace(x)) ??
                                "Unclassified";
                            string callerOrigin = NormalizeApiCallerOrigin(latest.CallerOrigin);
                            string originModule = NormalizeApiOriginModule(latest.OriginModule);
                            return new {
                                Key =
                                    $"thread|{latest.SourcePid}|{latest.TargetPid}|{latest.ThreadId}|{originModule}|{latest.ApiName}",
                                ThreadGroupKey = $"{latest.SourcePid}|{latest.ThreadId}",
                                Latest = latest,
                                Hits = hits,
                                FirstSeenUtc = firstSeenUtc,
                                LastSeenUtc = lastSeenUtc,
                                Sensor = sensor,
                                CallerOrigin = callerOrigin,
                                OriginModule = originModule,
                                OperationSummary = BuildApiOperationSummary(group)
                            };
                        })
                    .OrderBy(x => x.ThreadGroupKey, StringComparer.Ordinal)
                    .ThenBy(x => x.FirstSeenUtc)
                    .ThenBy(x => x.LastSeenUtc)
                    .Take(600)
                    .ToList();

            int maxHits = Math.Max(1, groups.Count == 0 ? 1 : groups.Max(x => Math.Max(1, x.Hits)));
            var rows = new List<ApiCallGraphMainRowView>(groups.Count);
            foreach (var group in groups)
            {
                ApiCallGraphRowSnapshot row = group.Latest;
                uint target = row.TargetPid != 0 ? row.TargetPid : row.SourcePid;
                double heatPercent = Math.Clamp((group.Hits / (double)maxHits) * 100.0, 0.0, 100.0);
                string threadLabel =
                    BuildThreadTimelineLabel(row.SourcePid, row.ThreadId, group.FirstSeenUtc, group.LastSeenUtc);
                rows.Add(new ApiCallGraphMainRowView {
                    GraphKey = group.Key,
                    ThreadGroupKey = group.ThreadGroupKey,
                    ViewModeKey = "thread",
                    ApiName = string.IsNullOrWhiteSpace(row.ApiName) ? "unknown" : row.ApiName,
                    OriginModule = group.OriginModule,
                    ActionLabel = string.IsNullOrWhiteSpace(row.ActionLabel) ? "Call activity" : row.ActionLabel,
                    SensorLabel = group.Sensor,
                    CallerOriginKey = group.CallerOrigin,
                    CallerOriginLabel = GetApiCallerOriginDisplayLabel(group.CallerOrigin, group.Sensor),
                    CallChainLabel = BuildThreadTimelineCallChain(row, group.FirstSeenUtc, group.LastSeenUtc),
                    CallerOriginBackground = BuildApiCallerOriginBackground(group.CallerOrigin),
                    CallerOriginForeground = BuildApiCallerOriginForeground(group.CallerOrigin),
                    SensorBackground = BuildApiSensorBackground(group.Sensor),
                    SensorForeground = BuildApiSensorForeground(group.Sensor),
                    HeatTrackBackground = BuildApiHeatTrackBackground(group.Sensor, group.CallerOrigin),
                    HeatFillBackground = BuildApiHeatFillBackground(group.Sensor, group.CallerOrigin),
                    RowBackground = BuildApiRowBackground(group.Sensor, group.CallerOrigin),
                    RowBorderBrush = BuildApiRowBorder(group.Sensor, group.CallerOrigin),
                    SourceLabel = FormatApiProcessLabel(row.SourcePid),
                    TargetLabel = FormatApiProcessLabel(target),
                    ThreadLabel = threadLabel,
                    SizeLabel = group.OriginModule,
                    ProtectLabel = group.OperationSummary,
                    Field2Label = "Module",
                    Field4Label = "Ops",
                    Hits = group.Hits,
                    HeatPercent = heatPercent,
                    ActivityFillWidth = Math.Round((heatPercent / 100.0) * 110.0),
                    FirstSeen = FormatApiRelativeAge(group.FirstSeenUtc),
                    AbsoluteFirstSeen = group.FirstSeenUtc == default
                                            ? string.Empty
                                            : group.FirstSeenUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss.fff",
                                                                                        CultureInfo.InvariantCulture),
                    FirstSeenUtc = group.FirstSeenUtc,
                    LastSeen = FormatApiRelativeAge(group.LastSeenUtc),
                    AbsoluteLastSeen = group.LastSeenUtc == default
                                           ? string.Empty
                                           : group.LastSeenUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss.fff",
                                                                                      CultureInfo.InvariantCulture),
                    LastSeenUtc = group.LastSeenUtc,
                    DetailFull = BuildThreadTimelineDetail(row, group.FirstSeenUtc, group.LastSeenUtc, group.Hits,
                                                           group.OriginModule, group.OperationSummary)
                });
            }

            return rows;
        }

        private void RenderApiPresentationCanvas(IReadOnlyList<ApiCallGraphMainRowView> rows, string? selectedKey)
        {
            if (_apiViewPresentationMode == ApiViewPresentationMode.ThreadTimeline)
            {
                RenderApiThreadTimelineCanvas(rows, selectedKey);
                return;
            }

            var byKey = rows.ToDictionary(x => x.GraphKey, StringComparer.Ordinal);
            List<ApiCallGraphRowSnapshot> snapshot =
                _apiGraphSnapshotRows
                    .Where(x => byKey.ContainsKey(BuildApiGraphKey(
                               x.SourcePid, x.TargetPid, x.ThreadId, x.ApiName,
                               string.IsNullOrWhiteSpace(x.SensorOrigin) ? "Unclassified" : x.SensorOrigin,
                               NormalizeApiCallerOrigin(x.CallerOrigin), NormalizeApiOriginModule(x.OriginModule))))
                    .OrderByDescending(x => x.Hits)
                    .ThenByDescending(x => x.LastSeenUtc)
                    .ToList();
            RenderApiGraphCanvas(snapshot, selectedKey);
        }

        private string BuildThreadTimelineLabel(uint pid, uint threadId, DateTime firstSeenUtc, DateTime lastSeenUtc)
        {
            string tid = threadId == 0 ? "T?" : $"T{threadId}";
            string lifetime = BuildThreadLifetimeSummary(pid, threadId, firstSeenUtc, lastSeenUtc);
            return string.IsNullOrWhiteSpace(lifetime) ? tid : $"{tid} · {lifetime}";
        }

        private string BuildThreadLifetimeSummary(uint pid, uint threadId, DateTime firstSeenUtc, DateTime lastSeenUtc)
        {
            if (_currentSession == null || threadId == 0)
            {
                return firstSeenUtc != default && lastSeenUtc > firstSeenUtc
                           ? $"{(lastSeenUtc - firstSeenUtc).TotalSeconds:0.0}s"
                           : string.Empty;
            }

            IEnumerable<ThreadLifecycleEventSample> history =
                _currentSession.ThreadLifecycleHistory.Where(x => x.ProcessPid == pid && x.ThreadId == threadId)
                    .OrderBy(x => x.TimestampUtc);
            ThreadLifecycleEventSample? start =
                history.FirstOrDefault(x => x.EventKind.Equals("Start", StringComparison.OrdinalIgnoreCase));
            ThreadLifecycleEventSample? exit =
                history.LastOrDefault(x => x.EventKind.Equals("Exit", StringComparison.OrdinalIgnoreCase));
            DateTime startUtc = start?.TimestampUtc ?? firstSeenUtc;
            DateTime endUtc = exit?.TimestampUtc ?? lastSeenUtc;
            if (startUtc == default || endUtc == default || endUtc < startUtc)
            {
                return string.Empty;
            }

            string state = exit == null ? "live" : "exited";
            return $"{(endUtc - startUtc).TotalSeconds:0.0}s {state}";
        }

        private static string BuildApiOperationSummary(IEnumerable<ApiCallGraphRowSnapshot> rows)
        {
            int query = 0, write = 0, exec = 0, map = 0, open = 0;
            foreach (ApiCallGraphRowSnapshot row in rows)
            {
                string text = $"{row.ApiName} {row.ActionLabel} {row.DetailFull}".ToLowerInvariant();
                int weight = Math.Max(1, row.Hits);
                if (text.Contains("query") || text.Contains("read"))
                    query += weight;
                if (text.Contains("write") || text.Contains("patch") || text.Contains("protect"))
                    write += weight;
                if (text.Contains("thread") || text.Contains("apc") || text.Contains("execute"))
                    exec += weight;
                if (text.Contains("map") || text.Contains("section") || text.Contains("image"))
                    map += weight;
                if (text.Contains("open") || text.Contains("handle") || text.Contains("token"))
                    open += weight;
            }

            var parts = new List<string>(5);
            if (query != 0)
                parts.Add($"query:{query}");
            if (write != 0)
                parts.Add($"write:{write}");
            if (exec != 0)
                parts.Add($"exec:{exec}");
            if (map != 0)
                parts.Add($"map:{map}");
            if (open != 0)
                parts.Add($"open:{open}");
            return parts.Count == 0 ? "mixed" : string.Join(" ", parts);
        }

        private string BuildThreadTimelineCallChain(ApiCallGraphRowSnapshot row, DateTime firstSeenUtc,
                                                    DateTime lastSeenUtc)
        {
            string module = NormalizeApiOriginModule(row.OriginModule);
            string first = firstSeenUtc == default
                               ? string.Empty
                               : firstSeenUtc.ToLocalTime().ToString("HH:mm:ss.fff", CultureInfo.InvariantCulture);
            string last = lastSeenUtc == default
                              ? string.Empty
                              : lastSeenUtc.ToLocalTime().ToString("HH:mm:ss.fff", CultureInfo.InvariantCulture);
            string summary = $"Module {module}";
            if (first.Length != 0 || last.Length != 0)
            {
                summary += $"{Environment.NewLine}Window {first} -> {last}";
            }
            if (!string.IsNullOrWhiteSpace(row.CallChainLabel))
            {
                summary += $"{Environment.NewLine}{Environment.NewLine}{row.CallChainLabel}";
            }
            return summary.Trim();
        }

        private string BuildThreadTimelineDetail(ApiCallGraphRowSnapshot row, DateTime firstSeenUtc,
                                                 DateTime lastSeenUtc, int hits, string originModule,
                                                 string operationSummary)
        {
            var sb = new StringBuilder(512);
            sb.AppendLine($"API: {row.ApiName}");
            sb.AppendLine($"Module: {originModule}");
            sb.AppendLine($"Hits: {hits.ToString(CultureInfo.InvariantCulture)}");
            if (firstSeenUtc != default)
                sb.AppendLine($"First Seen: {firstSeenUtc.ToLocalTime():yyyy-MM-dd HH:mm:ss.fff}");
            if (lastSeenUtc != default)
                sb.AppendLine($"Last Seen: {lastSeenUtc.ToLocalTime():yyyy-MM-dd HH:mm:ss.fff}");
            sb.AppendLine($"Ops: {operationSummary}");
            if (!string.IsNullOrWhiteSpace(row.ActionLabel))
                sb.AppendLine().AppendLine(row.ActionLabel);
            if (!string.IsNullOrWhiteSpace(row.DetailFull))
                sb.AppendLine().Append(row.DetailFull.Trim());
            return sb.ToString().TrimEnd();
        }

        private void RenderApiThreadTimelineCanvas(IReadOnlyList<ApiCallGraphMainRowView> rows, string? selectedKey)
        {
            if (ApiViewGraphCanvas == null)
            {
                return;
            }

            ApiViewGraphCanvas.Children.Clear();
            if (rows.Count == 0)
            {
                ApiViewGraphCanvas.Width = 540;
                ApiViewGraphCanvas.Height = 240;
                var empty =
                    new TextBlock { Text = "No thread timeline yet",
                                    Foreground = (System.Windows.Media.Brush)FindResource("WinMutedTextBrush") };
                Canvas.SetLeft(empty, 16);
                Canvas.SetTop(empty, 16);
                ApiViewGraphCanvas.Children.Add(empty);
                return;
            }

            DateTime minUtc = rows.Where(x => x.FirstSeenUtc != default)
                                  .Select(x => x.FirstSeenUtc)
                                  .DefaultIfEmpty(rows.Min(x => x.LastSeenUtc))
                                  .Min();
            DateTime maxUtc = rows.Select(x => x.LastSeenUtc).DefaultIfEmpty(minUtc).Max();
            if (maxUtc <= minUtc)
            {
                maxUtc = minUtc.AddSeconds(1);
            }

            var lanes =
                rows.GroupBy(x => x.ThreadGroupKey, StringComparer.Ordinal)
                    .Select(g => new { ThreadGroupKey = g.Key,
                                       Rows = g.OrderBy(x => x.FirstSeenUtc == default ? x.LastSeenUtc : x.FirstSeenUtc)
                                                  .ThenBy(x => x.LastSeenUtc)
                                                  .ThenByDescending(x => x.Hits)
                                                  .Take(14)
                                                  .ToList(),
                                       Hits = g.Sum(x => x.Hits), Label = g.First().ThreadLabel,
                                       First = g.Where(x => x.FirstSeenUtc != default)
                                                   .Select(x => x.FirstSeenUtc)
                                                   .DefaultIfEmpty(g.Min(x => x.LastSeenUtc))
                                                   .Min(),
                                       Last = g.Select(x => x.LastSeenUtc).DefaultIfEmpty(minUtc).Max() })
                    .OrderBy(x => x.First)
                    .ThenBy(x => x.ThreadGroupKey, StringComparer.Ordinal)
                    .Take(24)
                    .ToList();

            double left = 132;
            double right = 22;
            double top = 34;
            double rowHeight = 22;
            double laneHeaderHeight = 24;
            double laneGap = 10;
            double durationSeconds = Math.Max(1, (maxUtc - minUtc).TotalSeconds);
            double canvasWidth = Math.Max(920, Math.Min(2400, left + right + (durationSeconds * 90)));
            double width = canvasWidth - left - right;
            double canvasHeight = Math.Max(
                260, top + lanes.Sum(x => laneHeaderHeight + Math.Max(1, x.Rows.Count) * rowHeight + laneGap) + 24);
            ApiViewGraphCanvas.Width = canvasWidth;
            ApiViewGraphCanvas.Height = canvasHeight;

            double ToX(DateTime utc) =>
                left + ((utc - minUtc).TotalMilliseconds / (maxUtc - minUtc).TotalMilliseconds) * width;

            var axis = new System.Windows.Shapes.Line { X1 = left,
                                                        X2 = left + width,
                                                        Y1 = top - 10,
                                                        Y2 = top - 10,
                                                        Stroke = (System.Windows.Media.Brush)FindResource(
                                                            "WinSubtleBorderBrush"),
                                                        StrokeThickness = 1 };
            ApiViewGraphCanvas.Children.Add(axis);

            int tickCount = Math.Min(6, Math.Max(2, (int)Math.Ceiling(width / 220.0)));
            for (int tick = 0; tick <= tickCount; tick += 1)
            {
                double ratio = tick / (double)tickCount;
                DateTime tickUtc = minUtc.AddMilliseconds((maxUtc - minUtc).TotalMilliseconds * ratio);
                double x = left + width * ratio;
                var tickLine = new System.Windows.Shapes.Line {
                    X1 = x,
                    X2 = x,
                    Y1 = top - 14,
                    Y2 = canvasHeight - 18,
                    Stroke = (System.Windows.Media.Brush)FindResource("WinSubtleBorderBrush"),
                    StrokeThickness = 1,
                    Opacity = tick == 0 || tick == tickCount ? 0.55 : 0.22
                };
                ApiViewGraphCanvas.Children.Add(tickLine);
                var tickLabel =
                    new TextBlock { Text = tickUtc.ToLocalTime().ToString("HH:mm:ss", CultureInfo.InvariantCulture),
                                    Foreground = (System.Windows.Media.Brush)FindResource("WinMutedTextBrush"),
                                    FontSize = 10 };
                Canvas.SetLeft(tickLabel, Math.Max(left, Math.Min(left + width - 54, x - 22)));
                Canvas.SetTop(tickLabel, 4);
                ApiViewGraphCanvas.Children.Add(tickLabel);
            }

            double yCursor = top;
            for (int i = 0; i < lanes.Count; i += 1)
            {
                double y = yCursor;
                double laneBlockHeight = laneHeaderHeight + Math.Max(1, lanes[i].Rows.Count) * rowHeight;
                var label = new TextBlock { Text = lanes[i].Label, Width = left - 18,
                                            TextTrimming = TextTrimming.CharacterEllipsis,
                                            Foreground = (System.Windows.Media.Brush)FindResource("WinTextBrush"),
                                            FontWeight = FontWeights.SemiBold };
                Canvas.SetLeft(label, 8);
                Canvas.SetTop(label, y + 2);
                ApiViewGraphCanvas.Children.Add(label);

                var laneBackground = new System.Windows.Shapes.Rectangle {
                    Width = width,
                    Height = laneBlockHeight,
                    Fill = System.Windows.Media.Brushes.Transparent,
                    Stroke = (System.Windows.Media.Brush)FindResource("WinSubtleBorderBrush"),
                    StrokeThickness = 1,
                    Opacity = 0.7
                };
                Canvas.SetLeft(laneBackground, left);
                Canvas.SetTop(laneBackground, y);
                ApiViewGraphCanvas.Children.Add(laneBackground);

                for (int rowIndex = 0; rowIndex < lanes[i].Rows.Count; rowIndex += 1)
                {
                    ApiCallGraphMainRowView row = lanes[i].Rows[rowIndex];
                    double rowY = y + laneHeaderHeight + rowIndex * rowHeight;
                    double x1 = ToX(row.FirstSeenUtc == default ? row.LastSeenUtc : row.FirstSeenUtc);
                    double x2 = ToX(row.LastSeenUtc);
                    if (x2 < x1)
                    {
                        (x1, x2) = (x2, x1);
                    }

                    double markerWidth = Math.Max(8, Math.Min(168, x2 - x1 + Math.Min(24, row.Hits * 1.6)));
                    bool selected = string.Equals(row.GraphKey, selectedKey, StringComparison.Ordinal);
                    var border = new Border {
                        Width = markerWidth,
                        Height = 18,
                        CornerRadius = new CornerRadius(4),
                        Background = row.HeatFillBackground,
                        BorderBrush = row.RowBorderBrush,
                        BorderThickness = new Thickness(selected ? 2 : 1),
                        Opacity = selected ? 1.0 : 0.88,
                        Child = new TextBlock { Text = $"{row.ApiName}  [{row.OriginModule}]",
                                                Margin = new Thickness(6, 1, 6, 0),
                                                Foreground = (System.Windows.Media.Brush)FindResource("WinTextBrush"),
                                                FontSize = 11, TextTrimming = TextTrimming.CharacterEllipsis }
                    };
                    Canvas.SetLeft(border, x1);
                    Canvas.SetTop(border, rowY + 1);
                    ApiViewGraphCanvas.Children.Add(border);
                }

                yCursor += laneBlockHeight + laneGap;
            }
        }

        private void EnsureEtwDisplayDetails(BrokerEtwEventView view)
        {
            if (!string.IsNullOrWhiteSpace(view.DisplayDetails))
            {
                return;
            }

            view.DisplayDetails = BuildEtwDisplayDetail(view);
        }

        private List<ApiCallGraphMainRowView> ApplyApiViewFilters(IEnumerable<ApiCallGraphMainRowView> rows)
        {
            string callFilter = (ApiFilterCallBox?.Text ?? string.Empty).Trim();
            string actionFilter = (ApiFilterActionBox?.Text ?? string.Empty).Trim();
            string sensorFilter =
                ((ApiFilterSensorBox?.SelectedItem as ComboBoxItem)?.Content as string ?? "All Sensors").Trim();
            string originFilter =
                ((ApiFilterOriginBox?.SelectedItem as ComboBoxItem)?.Content as string ?? "All Origins").Trim();
            string callerFilter = (ApiFilterCallerBox?.Text ?? string.Empty).Trim();
            string targetFilter = (ApiFilterTargetBox?.Text ?? string.Empty).Trim();
            string threadFilter = (ApiFilterThreadBox?.Text ?? string.Empty).Trim();
            string regionFilter = (ApiFilterRegionBox?.Text ?? string.Empty).Trim();
            string protectFilter = (ApiFilterProtectBox?.Text ?? string.Empty).Trim();
            string minHitsFilter = (ApiFilterMinHitsBox?.Text ?? string.Empty).Trim();
            int minHits = 0;
            _ = int.TryParse(minHitsFilter, NumberStyles.Integer, CultureInfo.InvariantCulture, out minHits);

            bool Matches(string candidate, string filter) =>
                string.IsNullOrWhiteSpace(filter) || (!string.IsNullOrWhiteSpace(candidate) &&
                                                      candidate.Contains(filter, StringComparison.OrdinalIgnoreCase));

            bool MatchesSensor(string candidate) =>
                string.IsNullOrWhiteSpace(sensorFilter) ||
                sensorFilter.Equals("All Sensors", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(candidate, sensorFilter, StringComparison.OrdinalIgnoreCase);

            bool MatchesOrigin(string candidate) =>
                string.IsNullOrWhiteSpace(originFilter) ||
                originFilter.Equals("All Origins", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(candidate, originFilter, StringComparison.OrdinalIgnoreCase);

            return rows
                .Where(row =>
                           Matches(row.ApiName, callFilter) && Matches(row.ActionLabel, actionFilter) &&
                           MatchesSensor(row.SensorLabel) && MatchesOrigin(row.CallerOriginLabel) &&
                           Matches(row.SourceLabel, callerFilter) && Matches(row.TargetLabel, targetFilter) &&
                           Matches(row.ThreadLabel, threadFilter) &&
                           (Matches(row.BaseLabel, regionFilter) || Matches(row.SizeLabel, regionFilter) ||
                            Matches(row.AllocTypeLabel, regionFilter) || Matches(row.ProtectLabel, regionFilter)) &&
                           (Matches(row.ProtectLabel, protectFilter) || Matches(row.AllocTypeLabel, protectFilter)) &&
                           row.Hits >= Math.Max(0, minHits))
                .OrderByDescending(x => x.Hits)
                .ThenByDescending(x => x.LastSeen, StringComparer.Ordinal)
                .ToList();
        }

        private ApiCallStructuredFields BuildApiCallStructuredFields(string apiName, string rawReason,
                                                                     string decodedAction, BrokerEtwEventView? view)
        {
            Dictionary<string, string> fields = ParseReasonFields(rawReason);
            string action = SummarizeApiReason(decodedAction);
            string field1Label = "Base";
            string field2Label = "Context";
            string field3Label = "Alloc Type";
            string field4Label = "Flags";
            string field1Value = string.Empty;
            string field2Value = string.Empty;
            string field3Value = string.Empty;
            string field4Value = string.Empty;

            if (apiName.Equals("NtAllocateVirtualMemory", StringComparison.OrdinalIgnoreCase))
            {
                ulong baseAddress = FirstU64(fields, "base", "c0", "a1");
                ulong regionSize = FirstU64(fields, "size", "c1", "a3");
                uint allocationType = (uint)FirstU64(fields, "allocType", "c2", "a4");
                uint protect = (uint)FirstU64(fields, "protect", "c3", "a5");
                field1Value = FormatObservedPointer(view, baseAddress);
                field2Value =
                    regionSize == 0
                        ? string.Empty
                        : $"base={(baseAddress == 0 ? "?" : FormatObservedPointer(view, baseAddress))}  size=0x{regionSize:X}";
                field3Value = allocationType == 0
                                  ? string.Empty
                                  : $"0x{allocationType:X} {DescribeMemoryAllocationType(allocationType)}";
                field4Value = protect == 0 ? string.Empty : $"0x{protect:X} {DescribeMemoryProtect(protect)}";
            }
            else if (apiName.Equals("NtProtectVirtualMemory", StringComparison.OrdinalIgnoreCase))
            {
                ulong baseAddress = FirstU64(fields, "base", "c0", "a1");
                ulong regionSize = FirstU64(fields, "size", "c1", "a2");
                uint protect = (uint)FirstU64(fields, "newProtect", "c2", "a3");
                field1Value = FormatObservedPointer(view, baseAddress);
                field2Value =
                    regionSize == 0
                        ? string.Empty
                        : $"base={(baseAddress == 0 ? "?" : FormatObservedPointer(view, baseAddress))}  size=0x{regionSize:X}";
                field4Value = protect == 0 ? string.Empty : $"0x{protect:X} {DescribeMemoryProtect(protect)}";
            }
            else if (apiName.Equals("NtWriteVirtualMemory", StringComparison.OrdinalIgnoreCase) ||
                     apiName.Equals("NtReadVirtualMemory", StringComparison.OrdinalIgnoreCase))
            {
                ulong baseAddress = FirstU64(fields, "base", "c0", "a1");
                ulong regionSize = FirstU64(fields, "size", "c1", "a3");
                field1Value = FormatObservedPointer(view, baseAddress);
                field2Value =
                    regionSize == 0
                        ? string.Empty
                        : $"base={(baseAddress == 0 ? "?" : FormatObservedPointer(view, baseAddress))}  size=0x{regionSize:X}";
            }
            else if (apiName.Equals("LdrLoadDll", StringComparison.OrdinalIgnoreCase) ||
                     apiName.StartsWith("LoadLibrary", StringComparison.OrdinalIgnoreCase))
            {
                field1Label = "Module";
                field2Label = "Context";
                field3Label = "Flags";
                field4Label = "Result";

                field1Value = DecodeModuleHookName(apiName, view);
                ulong handle = FirstU64(fields, "handle");
                ulong flags = FirstU64(fields, "flags");
                ulong status = FirstU64(fields, "status");

                field2Value = handle == 0 ? (string.IsNullOrWhiteSpace(field1Value) ? string.Empty : field1Value)
                                          : $"{field1Value}  handle=0x{handle:X}".Trim();
                field3Value = flags == 0 ? "0x0" : $"0x{flags:X}";
                field4Value =
                    apiName.Equals("LdrLoadDll", StringComparison.OrdinalIgnoreCase) ? $"0x{status:X8}" : string.Empty;
            }
            else if (apiName.Equals("RtlAddFunctionTable", StringComparison.OrdinalIgnoreCase) ||
                     apiName.Equals("RtlInstallFunctionTableCallback", StringComparison.OrdinalIgnoreCase) ||
                     apiName.Equals("RtlDeleteFunctionTable", StringComparison.OrdinalIgnoreCase))
            {
                field1Label = "Base";
                field2Label = "Context";
                field3Label = "Length";
                field4Label = "Callback";
                ulong baseAddress = FirstU64(fields, "baseAddress", "a2", "a1");
                ulong length = FirstU64(fields, "length", "a2");
                ulong callback = FirstU64(fields, "callback", "a3");
                field1Value = FormatObservedPointer(view, baseAddress);
                field2Value = apiName.Equals("RtlDeleteFunctionTable", StringComparison.OrdinalIgnoreCase)
                                  ? $"table={FormatObservedPointer(view, FirstU64(fields, "table", "a0"))}"
                                  : $"table={FormatObservedPointer(view, FirstU64(fields, "tableId", "table", "a0"))}";
                field3Value = length == 0 ? string.Empty : $"0x{length:X}";
                field4Value = FormatObservedPointer(view, callback);
            }

            return new ApiCallStructuredFields { Action = string.IsNullOrWhiteSpace(action) ? apiName : action,
                                                 Field1Label = field1Label,
                                                 Field2Label = field2Label,
                                                 Field3Label = field3Label,
                                                 Field4Label = field4Label,
                                                 Field1Value = field1Value,
                                                 Field2Value = field2Value,
                                                 Field3Value = field3Value,
                                                 Field4Value = field4Value };
        }

        private static string DecodeModuleHookName(string apiName, BrokerEtwEventView? view)
        {
            if (view == null || view.DeepSample == null || view.DeepSample.Length == 0 || view.DeepSampleSize == 0)
            {
                return string.Empty;
            }

            int sampleSize = Math.Min(view.DeepSample.Length, (int)view.DeepSampleSize);
            if (sampleSize <= 0)
            {
                return string.Empty;
            }

            if (apiName.Equals("LoadLibraryA", StringComparison.OrdinalIgnoreCase) ||
                apiName.Equals("LoadLibraryExA", StringComparison.OrdinalIgnoreCase))
            {
                int zeroIndex = Array.IndexOf(view.DeepSample, (byte)0, 0, sampleSize);
                int length = zeroIndex >= 0 ? zeroIndex : sampleSize;
                return length > 0 ? Encoding.ASCII.GetString(view.DeepSample, 0, length).Trim() : string.Empty;
            }

            int byteLength = sampleSize & ~1;
            if (byteLength <= 0)
            {
                return string.Empty;
            }

            string decoded = Encoding.Unicode.GetString(view.DeepSample, 0, byteLength);
            int nul = decoded.IndexOf('\0');
            if (nul >= 0)
            {
                decoded = decoded[..nul];
            }

            return decoded.Trim();
        }

        private void RenderApiGraphCanvas(IReadOnlyList<ApiCallGraphRowSnapshot> rows, string? selectedKey)
        {
            if (ApiViewGraphCanvas == null)
            {
                return;
            }

            ApiViewGraphCanvas.Children.Clear();

            if (rows.Count == 0)
            {
                ApiViewGraphCanvas.Width = 540;
                ApiViewGraphCanvas.Height = 240;
                var empty = new System.Windows.Controls.TextBlock {
                    Text = "No live call graph yet",
                    Foreground = (System.Windows.Media.Brush)FindResource("WinMutedTextBrush")
                };
                System.Windows.Controls.Canvas.SetLeft(empty, 16);
                System.Windows.Controls.Canvas.SetTop(empty, 16);
                ApiViewGraphCanvas.Children.Add(empty);
                return;
            }

            ApiCallGraphRowSnapshot? selectedRow = rows.FirstOrDefault(
                row =>
                {
                    string sensor = string.IsNullOrWhiteSpace(row.SensorOrigin) ? "Unclassified" : row.SensorOrigin;
                    string callerOrigin = NormalizeApiCallerOrigin(row.CallerOrigin);
                    string originModule = NormalizeApiOriginModule(row.OriginModule);
                    string key = BuildApiGraphKey(row.SourcePid, row.TargetPid, row.ThreadId, row.ApiName, sensor,
                                                  callerOrigin, originModule);
                    return string.Equals(key, selectedKey, StringComparison.Ordinal);
                });

            List<ApiCallGraphRowSnapshot> visible =
                rows.OrderByDescending(x => x.Hits).ThenByDescending(x => x.LastSeenUtc).Take(12).ToList();
            if (selectedRow != null && !visible.Contains(selectedRow))
            {
                visible.Add(selectedRow);
            }

            var sourceNodes = visible.GroupBy(x => x.SourcePid)
                                  .Select(x => new { Pid = x.Key, Hits = x.Sum(y => Math.Max(1, y.Hits)),
                                                     Selected = selectedRow != null &&
                                                                x.Any(y => y.SourcePid == selectedRow.SourcePid) })
                                  .Where(x => x.Pid != 0)
                                  .OrderByDescending(x => x.Hits)
                                  .Take(6)
                                  .ToList();
            var apiNodes =
                visible.GroupBy(x => string.IsNullOrWhiteSpace(x.ApiName) ? "unknown" : x.ApiName)
                    .Select(x => new { Api = x.Key, Hits = x.Sum(y => Math.Max(1, y.Hits)),
                                       Selected = selectedRow != null &&
                                                  x.Any(y => string.Equals(y.ApiName, selectedRow.ApiName,
                                                                           StringComparison.OrdinalIgnoreCase)) })
                    .OrderByDescending(x => x.Hits)
                    .Take(8)
                    .ToList();
            var targetNodes =
                visible.GroupBy(x => x.TargetPid != 0 ? x.TargetPid : x.SourcePid)
                    .Select(x => new { Pid = x.Key, Hits = x.Sum(y => Math.Max(1, y.Hits)),
                                       Selected = selectedRow != null &&
                                                  x.Any(y => (y.TargetPid != 0 ? y.TargetPid : y.SourcePid) ==
                                                             (selectedRow.TargetPid != 0 ? selectedRow.TargetPid
                                                                                         : selectedRow.SourcePid)) })
                    .Where(x => x.Pid != 0)
                    .OrderByDescending(x => x.Hits)
                    .Take(6)
                    .ToList();

            double canvasWidth = 920;
            double nodeWidth = 170;
            double apiNodeWidth = 188;
            double nodeHeight = 40;
            double leftX = 26;
            double middleX = 364;
            double rightX = canvasWidth - nodeWidth - 26;
            double topY = 42;
            double verticalSpacing = 56;
            double canvasHeight = Math.Max(
                264,
                topY + Math.Max(sourceNodes.Count, Math.Max(apiNodes.Count, targetNodes.Count)) * verticalSpacing + 40);
            ApiViewGraphCanvas.Width = canvasWidth;
            ApiViewGraphCanvas.Height = canvasHeight;

            var sourcePositions = new Dictionary<uint, System.Windows.Point>();
            var apiPositions = new Dictionary<string, System.Windows.Point>(StringComparer.OrdinalIgnoreCase);
            var targetPositions = new Dictionary<uint, System.Windows.Point>();

            AddColumnLabel(leftX + (nodeWidth / 2.0), 14, "CALLERS");
            AddColumnLabel(middleX + (apiNodeWidth / 2.0), 14, "APIS");
            AddColumnLabel(rightX + (nodeWidth / 2.0), 14, "TARGETS");

            for (int i = 0; i < sourceNodes.Count; i += 1)
            {
                double y = topY + (i * verticalSpacing);
                sourcePositions[sourceNodes[i].Pid] =
                    new System.Windows.Point(leftX + nodeWidth, y + (nodeHeight / 2.0));
                AddApiGraphProcessNode(leftX, y, nodeWidth, nodeHeight, sourceNodes[i].Pid, true,
                                       sourceNodes[i].Selected);
            }

            for (int i = 0; i < apiNodes.Count; i += 1)
            {
                double y = topY + (i * verticalSpacing);
                apiPositions[apiNodes[i].Api] =
                    new System.Windows.Point(middleX + apiNodeWidth / 2.0, y + (nodeHeight / 2.0));
                AddApiGraphApiNode(middleX, y, apiNodeWidth, nodeHeight, apiNodes[i].Api, apiNodes[i].Selected);
            }

            for (int i = 0; i < targetNodes.Count; i += 1)
            {
                double y = topY + (i * verticalSpacing);
                targetPositions[targetNodes[i].Pid] = new System.Windows.Point(rightX, y + (nodeHeight / 2.0));
                AddApiGraphProcessNode(rightX, y, nodeWidth, nodeHeight, targetNodes[i].Pid, false,
                                       targetNodes[i].Selected);
            }

            int maxHits = Math.Max(1, visible.Max(x => Math.Max(1, x.Hits)));
            foreach (ApiCallGraphRowSnapshot row in visible)
            {
                uint sourcePid = row.SourcePid;
                uint targetPid = row.TargetPid != 0 ? row.TargetPid : row.SourcePid;
                string apiName = string.IsNullOrWhiteSpace(row.ApiName) ? "unknown" : row.ApiName;
                string sensor = string.IsNullOrWhiteSpace(row.SensorOrigin) ? "Unclassified" : row.SensorOrigin;
                string callerOrigin = NormalizeApiCallerOrigin(row.CallerOrigin);
                string originModule = NormalizeApiOriginModule(row.OriginModule);
                string rowKey = BuildApiGraphKey(row.SourcePid, row.TargetPid, row.ThreadId, row.ApiName, sensor,
                                                 callerOrigin, originModule);
                bool isSelected = !string.IsNullOrWhiteSpace(selectedKey) &&
                                  string.Equals(rowKey, selectedKey, StringComparison.Ordinal);
                if (!sourcePositions.TryGetValue(sourcePid, out System.Windows.Point sourcePoint) ||
                    !apiPositions.TryGetValue(apiName, out System.Windows.Point apiPoint) ||
                    !targetPositions.TryGetValue(targetPid, out System.Windows.Point end))
                {
                    continue;
                }

                double heat = Math.Clamp(row.Hits / (double)maxHits, 0.0, 1.0);
                var lineBrush = BuildApiGraphEdgeBrush(sensor, callerOrigin, heat);
                bool selfLoop = sourcePid == targetPid;
                DrawCurve(sourcePoint, new System.Windows.Point(middleX, apiPoint.Y), lineBrush, heat, isSelected,
                          forward: true, selfLoop: false);
                DrawCurve(new System.Windows.Point(middleX + apiNodeWidth, apiPoint.Y), end, lineBrush, heat,
                          isSelected, forward: true, selfLoop: selfLoop);
            }

            void AddColumnLabel(double centerX, double y, string label)
            {
                var block = new System.Windows.Controls.TextBlock {
                    Text = label, FontSize = 10, FontWeight = FontWeights.SemiBold,
                    Foreground = (System.Windows.Media.Brush)FindResource("WinMutedTextBrush")
                };
                block.Measure(new Size(double.PositiveInfinity, double.PositiveInfinity));
                System.Windows.Controls.Canvas.SetLeft(block, centerX - (block.DesiredSize.Width / 2.0));
                System.Windows.Controls.Canvas.SetTop(block, y);
                ApiViewGraphCanvas.Children.Add(block);
            }

            void DrawCurve(System.Windows.Point start, System.Windows.Point end, System.Windows.Media.Brush stroke,
                           double heat, bool selected, bool forward, bool selfLoop)
            {
                var figure = new System.Windows.Media.PathFigure { StartPoint = start };
                System.Windows.Point arrowBase;
                System.Windows.Vector direction;
                if (selfLoop)
                {
                    double loopWidth = 64;
                    double loopHeight = 28;
                    var first = new System.Windows.Point(start.X + loopWidth * 0.35, start.Y - loopHeight);
                    var second = new System.Windows.Point(end.X - loopWidth * 0.35, end.Y - loopHeight);
                    figure.Segments.Add(new System.Windows.Media.BezierSegment(first, second, end, true));
                    arrowBase = second;
                    direction = end - second;
                }
                else
                {
                    double controlOffset = Math.Max(48, Math.Abs(end.X - start.X) * 0.32);
                    var first = new System.Windows.Point(start.X + controlOffset, start.Y);
                    var second = new System.Windows.Point(end.X - controlOffset, end.Y);
                    figure.Segments.Add(new System.Windows.Media.BezierSegment(first, second, end, true));
                    arrowBase = second;
                    direction = end - second;
                }
                var geometry = new System.Windows.Media.PathGeometry();
                geometry.Figures.Add(figure);

                ApiViewGraphCanvas.Children.Add(
                    new System.Windows.Shapes.Path { Data = geometry, Stroke = stroke,
                                                     StrokeThickness = (selected ? 2.1 : 1.0) + (2.9 * heat),
                                                     Opacity = selected ? 0.98 : 0.28 });

                if (forward)
                {
                    DrawArrowHead(end, direction, stroke, selected ? 0.98 : 0.45);
                }
            }

            void DrawArrowHead(System.Windows.Point tip, System.Windows.Vector direction,
                               System.Windows.Media.Brush stroke, double opacity)
            {
                if (direction.LengthSquared < 1)
                {
                    direction = new System.Windows.Vector(1, 0);
                }

                direction.Normalize();
                System.Windows.Vector normal = new(-direction.Y, direction.X);
                const double arrowLength = 9;
                const double arrowWidth = 4.5;
                System.Windows.Point p1 = tip - (direction * arrowLength) + (normal * arrowWidth);
                System.Windows.Point p2 = tip - (direction * arrowLength) - (normal * arrowWidth);
                var geometry = new System.Windows.Media.PathGeometry();
                var figure = new System.Windows.Media.PathFigure { StartPoint = tip, IsClosed = true, IsFilled = true };
                figure.Segments.Add(new System.Windows.Media.LineSegment(p1, true));
                figure.Segments.Add(new System.Windows.Media.LineSegment(p2, true));
                geometry.Figures.Add(figure);
                ApiViewGraphCanvas.Children.Add(new System.Windows.Shapes.Path { Data = geometry, Fill = stroke,
                                                                                 Stroke = stroke, Opacity = opacity });
            }

            void AddApiGraphProcessNode(double x, double y, double width, double height, uint pid, bool sourceSide,
                                        bool selected)
            {
                string processName = GetApiGraphProcessName(pid);
                string title = string.IsNullOrWhiteSpace(processName) ? "Process" : processName;
                var border = new System.Windows.Controls.Border {
                    Width = width,
                    Height = height,
                    CornerRadius = new CornerRadius(8),
                    Background = new System.Windows.Media.SolidColorBrush(
                        sourceSide ? (selected ? System.Windows.Media.Color.FromArgb(235, 22, 86, 140)
                                               : System.Windows.Media.Color.FromArgb(220, 17, 63, 103))
                                   : (selected ? System.Windows.Media.Color.FromArgb(235, 140, 34, 38)
                                               : System.Windows.Media.Color.FromArgb(220, 110, 25, 28))),
                    BorderBrush = new System.Windows.Media.SolidColorBrush(
                        sourceSide ? (selected ? System.Windows.Media.Color.FromRgb(118, 203, 255)
                                               : System.Windows.Media.Color.FromRgb(80, 172, 255))
                                   : (selected ? System.Windows.Media.Color.FromRgb(255, 139, 139)
                                               : System.Windows.Media.Color.FromRgb(255, 109, 109))),
                    BorderThickness = new Thickness(selected ? 2 : 1),
                    Opacity = selected ? 1.0 : 0.78,
                    Child =
                        new System.Windows.Controls
                            .StackPanel {
                                VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(10, 3, 10, 3),
                                Children = { new System.Windows.Controls.TextBlock {
                                                Text = title, TextAlignment = TextAlignment.Center,
                                                TextTrimming = TextTrimming.CharacterEllipsis,
                                                FontWeight = FontWeights.SemiBold,
                                                Foreground = new System.Windows.Media
                                                                 .SolidColorBrush(System.Windows.Media.Colors.White)
                                            },
                                             new System.Windows.Controls.TextBlock { Text = $"PID {pid}",
                                                                                     Margin = new Thickness(0, 1, 0, 0),
                                                                                     TextAlignment =
                                                                                         TextAlignment.Center,
                                                                                     Foreground =
                                                                                         new System.Windows.Media.SolidColorBrush(System
                                                                                                                                      .Windows
                                                                                                                                      .Media
                                                                                                                                      .Color
                                                                                                                                      .FromRgb(
                                                                                                                                          220, 225, 230)) } }
                            }
                };
                System.Windows.Controls.Canvas.SetLeft(border, x);
                System.Windows.Controls.Canvas.SetTop(border, y);
                ApiViewGraphCanvas.Children.Add(border);
            }

            void AddApiGraphApiNode(double x, double y, double width, double height, string label, bool selected)
            {
                var border =
                    new System.Windows.Controls.Border {
                        Width = width,
                        Height = height,
                        CornerRadius = new CornerRadius(8),
                        Background = new System.Windows.Media.SolidColorBrush(
                            selected ? System.Windows.Media.Color.FromArgb(236, 42, 49, 58)
                                     : System.Windows.Media.Color.FromArgb(225, 32, 36, 43)),
                        BorderBrush = new System.Windows.Media.SolidColorBrush(
                            selected ? System.Windows.Media.Color.FromRgb(195, 205, 216)
                                     : System.Windows.Media.Color.FromRgb(128, 140, 154)),
                        BorderThickness = new Thickness(selected ? 2 : 1),
                        Opacity = selected ? 1.0 : 0.82,
                        Child =
                            new System.Windows.Controls.TextBlock {
                                Text = label, Margin = new Thickness(10, 0, 10, 0),
                                VerticalAlignment = VerticalAlignment.Center, TextAlignment = TextAlignment.Center,
                                TextTrimming = TextTrimming.CharacterEllipsis, FontWeight = FontWeights.SemiBold,
                                Foreground = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Colors.White)
                            },
                        Cursor = System.Windows.Input.Cursors.Hand
                    };
                border.MouseLeftButtonDown += (_, e) =>
                {
                    SelectApiViewRowByApiName(label);
                    if (e.ClickCount >= 2)
                    {
                        OpenApiInspector(label);
                    }
                    e.Handled = true;
                };
                System.Windows.Controls.Canvas.SetLeft(border, x);
                System.Windows.Controls.Canvas.SetTop(border, y);
                ApiViewGraphCanvas.Children.Add(border);
            }
        }

        private static string SummarizeApiReason(string? reason)
        {
            if (string.IsNullOrWhiteSpace(reason))
            {
                return string.Empty;
            }

            string compact = reason.Replace('\r', ' ').Replace('\n', ' ').Trim();
            if (compact.Length <= 260)
            {
                return compact;
            }

            return compact[..260] + "...";
        }

        private static string BuildApiGraphKey(uint sourcePid, uint targetPid, uint threadId, string apiName,
                                               string sensorOrigin, string callerOrigin, string originModule) =>
            $"{sourcePid}|{targetPid}|{threadId}|{apiName}|{sensorOrigin}|{callerOrigin}|{originModule}";

        private static string NormalizeApiCallerOrigin(string? callerOrigin)
        {
            string normalized = (callerOrigin ?? string.Empty).Trim().ToLowerInvariant();
            return normalized.Length == 0 ? "unknown" : normalized;
        }

        private static string NormalizeApiOriginModule(string? originModule)
        {
            string normalized = (originModule ?? string.Empty).Trim();
            return normalized.Length == 0 ? "unknown" : normalized;
        }

        private static string GetApiCallerOriginDisplayLabel(string callerOrigin, string? sensor = null)
        {
            return NormalizeApiCallerOrigin(
                callerOrigin) switch { "process-image" => "Process Image", "non-system-dll" => "Other DLL",
                                       "unbacked" => "Unbacked / Shellcode", "system" => "System DLL Chain",
                                       _ => !string.IsNullOrWhiteSpace(sensor) &&
                                                    sensor.StartsWith("Kernel", StringComparison.OrdinalIgnoreCase)
                                                ? "Kernel / Driver"
                                                : "Unknown" };
        }

        private static bool IsInternalHookFrame(string? modulePath, string? frameText = null)
        {
            if (EventDetailFormatting.IsBlackbirdInternalPath(modulePath) ||
                EventDetailFormatting.IsBlackbirdInternalModule(modulePath))
            {
                return true;
            }

            string candidate = (frameText ?? string.Empty).Trim();
            return candidate.StartsWith("SR71", StringComparison.OrdinalIgnoreCase) ||
                   candidate.StartsWith("J58", StringComparison.OrdinalIgnoreCase) ||
                   candidate.StartsWith("BlackbirdController", StringComparison.OrdinalIgnoreCase) ||
                   candidate.StartsWith("BlackbirdInterface", StringComparison.OrdinalIgnoreCase);
        }

        private static List<string> BuildHookFrameList(BrokerEtwEventView view,
                                                       IReadOnlyDictionary<string, string> fields)
        {
            ulong[] stack = view.Stack ?? Array.Empty<ulong>();
            var frames = new List<string>(BlackbirdNative.MaxIpcStackFrames);

            void AddFrameText(string frame)
            {
                if (string.IsNullOrWhiteSpace(frame))
                {
                    return;
                }

                frame = frame.Trim();
                if (frames.Count == 0 || !string.Equals(frames[^1], frame, StringComparison.OrdinalIgnoreCase))
                {
                    frames.Add(frame);
                }
            }

            for (int i = 0; i < Math.Min((int)view.StackCount, BlackbirdNative.MaxIpcStackFrames); i += 1)
            {
                string symbolKey = $"stack{i}Symbol";
                string pathKey = $"stack{i}Path";
                if (fields.TryGetValue(symbolKey, out string? symbolValue) && !string.IsNullOrWhiteSpace(symbolValue))
                {
                    string frameText = symbolValue.Trim();
                    string? pathValue = null;
                    if (fields.TryGetValue(pathKey, out string? resolvedPath) && !string.IsNullOrWhiteSpace(resolvedPath))
                    {
                        pathValue = resolvedPath.Trim();
                    }
                    if (IsInternalHookFrame(pathValue, frameText))
                    {
                        continue;
                    }
                    if (!string.IsNullOrWhiteSpace(pathValue))
                    {
                        string moduleName = EventDetailFormatting.ModuleNameFromPath(pathValue);
                        if (!string.IsNullOrWhiteSpace(moduleName) &&
                            !moduleName.Equals("unknown", StringComparison.OrdinalIgnoreCase) &&
                            frameText.IndexOf(moduleName, StringComparison.OrdinalIgnoreCase) < 0)
                        {
                            frameText = $"{moduleName}!{frameText}";
                        }
                    }
                    AddFrameText(frameText);
                    continue;
                }

                ulong rawIp = i < stack.Length ? stack[i] : 0;
                if (rawIp != 0)
                {
                    AddFrameText($"0x{rawIp:X}");
                }
            }

            if (frames.Count == 0 &&
                fields.TryGetValue("originSymbol", out string? originSymbol) &&
                !string.IsNullOrWhiteSpace(originSymbol) &&
                !IsInternalHookFrame(null, originSymbol))
            {
                AddFrameText(originSymbol);
            }

            return frames;
        }

        private static string BuildHookCallChainText(BrokerEtwEventView view,
                                                     IReadOnlyDictionary<string, string> fields)
        {
            List<string> frames = BuildHookFrameList(view, fields);
            return frames.Count == 0 ? string.Empty : "CallChain: " + string.Join(" -> ", frames);
        }

        private string FormatObservedPointer(BrokerEtwEventView? view, ulong address, string? modulePath = null,
                                             ulong moduleBase = 0, ulong moduleSize = 0)
        {
            if (address == 0)
            {
                return string.Empty;
            }

            string directModuleText =
                EventDetailFormatting.FormatModuleRelativeAddress(modulePath, moduleBase, moduleSize, address);
            if (!string.IsNullOrWhiteSpace(directModuleText) &&
                !string.Equals(directModuleText, $"0x{address:X}", StringComparison.OrdinalIgnoreCase))
            {
                return directModuleText;
            }

            if (view != null)
            {
                uint targetPid =
                    view.TargetPid != 0 ? view.TargetPid : (view.ProcessPid != 0 ? view.ProcessPid : view.ActorPid);
                ulong processStartKey = ResolveObservedProcessStartKey(targetPid, view.ProcessStartKey);
                if (TryResolveKnownRegionForAddress(targetPid, processStartKey, address, out _, out ulong regionBase,
                                                    out ulong regionSize, out string regionKind,
                                                    out uint currentProtection))
                {
                    ulong pageBase = address & ~0xFFFUL;
                    string regionText =
                        $"{regionKind.ToLowerInvariant()}+0x{address - regionBase:X} [0x{address:X}; page 0x{pageBase:X}; region 0x{regionBase:X}+0x{regionSize:X}; {EventDetailFormatting.DescribeMemoryProtection(currentProtection)}]";

                    if (string.Equals(regionKind, "Image", StringComparison.OrdinalIgnoreCase))
                    {
                        string imageText = EventDetailFormatting.FormatModuleRelativeAddress(
                            view.ImagePath, view.ImageBase != 0 ? view.ImageBase : regionBase,
                            view.ImageSize != 0 ? view.ImageSize : regionSize, address);
                        if (!string.IsNullOrWhiteSpace(imageText) &&
                            !string.Equals(imageText, $"0x{address:X}", StringComparison.OrdinalIgnoreCase))
                        {
                            return $"{imageText}; page 0x{pageBase:X}";
                        }
                    }

                    return regionText;
                }

                string viewImageText = EventDetailFormatting.FormatModuleRelativeAddress(view.ImagePath, view.ImageBase,
                                                                                         view.ImageSize, address);
                if (!string.IsNullOrWhiteSpace(viewImageText) &&
                    !string.Equals(viewImageText, $"0x{address:X}", StringComparison.OrdinalIgnoreCase))
                {
                    return viewImageText;
                }
            }

            return $"0x{address:X}";
        }

        private string BuildHookFrameSummary(BrokerEtwEventView view, IReadOnlyDictionary<string, string> fields) =>
            AppendThreadStackFallbackSummary(view, BuildHookFrameSummaryCore(view, fields));

        private static string BuildHookFrameSummaryCore(BrokerEtwEventView view,
                                                        IReadOnlyDictionary<string, string> fields)
        {
            var sb = new StringBuilder(512);
            string sensor = EventDetailFormatting.ClassifyHookSensorOrigin(view);
            string origin = GetApiCallerOriginDisplayLabel(NormalizeApiCallerOrigin(view.CallerOriginLabel), sensor);
            string immediate = EventDetailFormatting.HookImmediateCallerLabel(view.Flags);
            string deepOrigin = EventDetailFormatting.HookDeepOriginLabel(view.Flags);
            string sr71Component = EventDetailFormatting.HookComponentLabel(view.Flags);
            string originModule = ResolveHookOriginModule(view, fields);
            string resolvedReturnAddress = ResolveHookReturnAddressLabel(view, fields, originModule);
            bool kernelCaller = (view.Flags & BlackbirdNative.IpcEtwFlagHookKernelCaller) != 0;
            bool userCaller = (view.Flags & BlackbirdNative.IpcEtwFlagHookUserCaller) != 0;
            bool currentTarget = IsHookCurrentProcessTarget(view);
            bool imageSection = IsHookImageSection(view);
            bool containsOwnModule = EventDetailFormatting.HookTraceContainsOwnModule(view.Flags);
            bool returnAddressResolved = !string.IsNullOrWhiteSpace(resolvedReturnAddress);
            bool returnAddressPresentInStack = false;
            ulong[] stack = view.Stack ?? Array.Empty<ulong>();
            int compareFrames = Math.Min((int)view.StackCount, stack.Length);
            for (int i = 0; i < compareFrames; i += 1)
            {
                if (stack[i] == view.OriginAddress && view.OriginAddress != 0)
                {
                    returnAddressPresentInStack = true;
                    break;
                }
            }

            sb.Append("Origin: ").AppendLine(origin);
            if (kernelCaller || userCaller)
            {
                sb.Append("Caller Mode: ").AppendLine(kernelCaller ? "Kernel" : "User");
            }
            sb.Append("Target Scope: ").AppendLine(currentTarget ? "Current Process" : "External / Cross-Process");
            sb.Append("Memory Backing: ").AppendLine(imageSection ? "Image-backed" : "Private / Non-image");
            if (!string.IsNullOrWhiteSpace(sr71Component))
            {
                sb.Append("SR71 Component: ").AppendLine(sr71Component);
            }
            sb.Append("SR71 Frames Present: ").AppendLine(containsOwnModule ? "yes" : "no");
            if (!string.IsNullOrWhiteSpace(immediate) &&
                !immediate.Equals("Unknown", StringComparison.OrdinalIgnoreCase))
            {
                sb.Append("Immediate Caller: ").AppendLine(immediate);
            }
            if (!string.IsNullOrWhiteSpace(deepOrigin) &&
                !deepOrigin.Equals("Unknown", StringComparison.OrdinalIgnoreCase))
            {
                sb.Append("Deep Origin: ").AppendLine(deepOrigin);
            }
            if (!string.IsNullOrWhiteSpace(originModule))
            {
                sb.Append("Origin Module: ").AppendLine(originModule);
            }
            if (view.OriginAddress != 0)
            {
                sb.Append("Return Address: ")
                    .AppendLine(!string.IsNullOrWhiteSpace(resolvedReturnAddress)
                                    ? resolvedReturnAddress
                                    : $"0x{view.OriginAddress.ToString("X", CultureInfo.InvariantCulture)}");
                sb.Append("Return Address Resolved: ").AppendLine(returnAddressResolved ? "yes" : "no");
                sb.Append("Return Address In Stack: ").AppendLine(returnAddressPresentInStack ? "yes" : "no");
            }
            sb.Append("Stack Frames Captured: ")
                .Append(view.StackCount.ToString(CultureInfo.InvariantCulture))
                .AppendLine();
            if (fields.TryGetValue("startSymbol", out string? startSymbol) && !string.IsNullOrWhiteSpace(startSymbol))
            {
                sb.Append("Start Routine: ").AppendLine(startSymbol);
            }

            List<string> frames = BuildHookFrameList(view, fields);
            if (frames.Count > 0)
            {
                sb.AppendLine("Frames:");
                for (int i = 0; i < frames.Count; i += 1)
                {
                    sb.Append("  ").Append(i + 1).Append(". ").AppendLine(frames[i]);
                    string pathKey = $"stack{i}Path";
                    if (fields.TryGetValue(pathKey, out string? framePath) && !string.IsNullOrWhiteSpace(framePath))
                    {
                        sb.Append("     ").AppendLine(framePath.Trim());
                    }
                }
            }

            if (!string.IsNullOrWhiteSpace(view.OriginPath))
            {
                sb.Append("Origin Path: ").AppendLine(view.OriginPath.Trim());
            }

            return sb.ToString().TrimEnd();
        }

        private string AppendThreadStackFallbackSummary(BrokerEtwEventView view, string summary)
        {
            if (view.StackCount != 0)
            {
                return summary;
            }

            string fallback = BuildThreadStackFallbackSummary(view);
            if (string.IsNullOrWhiteSpace(fallback))
            {
                string source = EventDetailFormatting.IsKernelHookTelemetry(view) ||
                                        view.SourceId == BlackbirdNative.IpcEtwSourceBlackbird
                                    ? "kernel/driver telemetry did not include user frames"
                                    : "hook telemetry did not include frames";
                string note = $"Thread Stack Fallback: pending or unavailable ({source})";
                return string.IsNullOrWhiteSpace(summary) ? note : $"{summary}{Environment.NewLine}{note}";
            }

            return string.IsNullOrWhiteSpace(summary) ? fallback : $"{summary}{Environment.NewLine}{fallback}";
        }

        private string BuildThreadStackFallbackSummary(BrokerEtwEventView view)
        {
            uint pid = view.ProcessPid != 0 ? view.ProcessPid
                       : view.ActorPid != 0 ? view.ActorPid
                                            : view.EventProcessId;
            uint tid = view.EventThreadId != 0 ? view.EventThreadId : view.ThreadId;
            if (pid == 0 || tid == 0 || pid > int.MaxValue || tid > int.MaxValue)
            {
                return string.Empty;
            }

            DateTime observedUtc = view.TimestampUtc == default ? DateTime.UtcNow : view.TimestampUtc;
            IReadOnlyList<ThreadStackSessionSnapshot> history =
                GetThreadStackHistory(unchecked((int)pid), unchecked((int)tid), string.Empty);
            ThreadStackSessionSnapshot? snapshot =
                history.Where(x => x.Frames.Count > 0)
                    .OrderBy(x => Math.Abs((x.CapturedAtUtc - observedUtc).TotalMilliseconds))
                    .FirstOrDefault();
            if (snapshot == null)
            {
                return string.Empty;
            }

            double deltaMs = Math.Abs((snapshot.CapturedAtUtc - observedUtc).TotalMilliseconds);
            if (deltaMs > 5000)
            {
                return string.Empty;
            }

            var sb = new StringBuilder(512);
            sb.Append("Thread Stack Fallback: ")
                .Append(snapshot.Frames.Count.ToString(CultureInfo.InvariantCulture))
                .Append(" frames from Thread Stack window history, deltaMs=")
                .Append(deltaMs.ToString("0", CultureInfo.InvariantCulture))
                .AppendLine();
            int frameCount = Math.Min(12, snapshot.Frames.Count);
            for (int i = 0; i < frameCount; i += 1)
            {
                StackFrameRow frame = snapshot.Frames[i];
                string label = !string.IsNullOrWhiteSpace(frame.Symbol)    ? frame.Symbol
                               : !string.IsNullOrWhiteSpace(frame.Address) ? frame.Address
                                                                           : $"0x{frame.InstructionPointerRaw:X}";
                if (!string.IsNullOrWhiteSpace(frame.Module) &&
                    label.IndexOf(frame.Module, StringComparison.OrdinalIgnoreCase) < 0)
                {
                    label = $"{frame.Module}!{label}";
                }
                sb.Append("  ").Append(i + 1).Append(". ").AppendLine(label);
            }

            return sb.ToString().TrimEnd();
        }

        private static string ResolveHookOriginModule(BrokerEtwEventView view,
                                                      IReadOnlyDictionary<string, string> fields)
        {
            string originModule = EventDetailFormatting.ModuleNameFromPath(view.OriginPath);
            if (!string.Equals(originModule, "unknown", StringComparison.OrdinalIgnoreCase) &&
                !EventDetailFormatting.IsBlackbirdInternalModule(originModule) &&
                !EventDetailFormatting.IsBlackbirdInternalPath(view.OriginPath))
            {
                return originModule;
            }

            if (fields.TryGetValue("originSymbol", out string? originSymbol) && !string.IsNullOrWhiteSpace(originSymbol))
            {
                string trimmed = originSymbol.Trim();
                int plus = trimmed.IndexOf('+');
                if (plus > 0)
                {
                    trimmed = trimmed[..plus].Trim();
                }

                if (!IsInternalHookFrame(null, trimmed))
                {
                    return trimmed;
                }
            }

            for (int i = 0; i < Math.Min((int)view.StackCount, BlackbirdNative.MaxIpcStackFrames); i += 1)
            {
                string pathKey = $"stack{i}Path";
                string symbolKey = $"stack{i}Symbol";
                string? pathValue = null;

                if (fields.TryGetValue(pathKey, out string? resolvedPath) && !string.IsNullOrWhiteSpace(resolvedPath))
                {
                    pathValue = resolvedPath.Trim();
                    if (!IsInternalHookFrame(pathValue))
                    {
                        string moduleFromPath = EventDetailFormatting.ModuleNameFromPath(pathValue);
                        if (!string.Equals(moduleFromPath, "unknown", StringComparison.OrdinalIgnoreCase))
                        {
                            return moduleFromPath;
                        }
                    }
                }

                if (fields.TryGetValue(symbolKey, out string? symbolValue) &&
                    !string.IsNullOrWhiteSpace(symbolValue) &&
                    !IsInternalHookFrame(pathValue, symbolValue))
                {
                    string trimmed = symbolValue.Trim();
                    int plus = trimmed.IndexOf('+');
                    if (plus > 0)
                    {
                        trimmed = trimmed[..plus].Trim();
                    }

                    if (!string.IsNullOrWhiteSpace(trimmed))
                    {
                        return trimmed;
                    }
                }
            }

            return originModule;
        }

        private static string ResolveHookReturnAddressLabel(BrokerEtwEventView view,
                                                            IReadOnlyDictionary<string, string> fields,
                                                            string originModule)
        {
            ulong[] stack = view.Stack ?? Array.Empty<ulong>();

            if (fields.TryGetValue("originSymbol", out string? originSymbol) && !string.IsNullOrWhiteSpace(originSymbol))
            {
                string trimmed = originSymbol.Trim();
                if (!IsInternalHookFrame(null, trimmed))
                {
                    return trimmed;
                }
            }

            for (int i = 0; i < Math.Min((int)view.StackCount, BlackbirdNative.MaxIpcStackFrames); i += 1)
            {
                if (stack.Length <= i || stack[i] != view.OriginAddress)
                {
                    continue;
                }

                string symbolKey = $"stack{i}Symbol";
                if (fields.TryGetValue(symbolKey, out string? stackSymbol) && !string.IsNullOrWhiteSpace(stackSymbol))
                {
                    return stackSymbol.Trim();
                }
            }

            if (!string.IsNullOrWhiteSpace(originModule) &&
                !originModule.Equals("unknown", StringComparison.OrdinalIgnoreCase) && view.OriginAddress != 0)
            {
                return $"{originModule}!0x{view.OriginAddress:X}";
            }

            return string.Empty;
        }

        private static string BuildHookFrameSummary(IReadOnlyDictionary<string, string> fields)
        {
            var view = new BrokerEtwEventView();
            if (fields.TryGetValue("originPath", out string? originPath))
            {
                view.OriginPath = originPath;
            }
            if (fields.TryGetValue("kind", out string? kind) &&
                string.Equals(kind, "kernel_ntapi", StringComparison.OrdinalIgnoreCase))
            {
                view.Source = "BK";
                view.SourceId = BlackbirdNative.IpcEtwSourceBlackbird;
                view.Family = BlackbirdNative.IpcEtwFamilyUserHook;
            }

            return BuildHookFrameSummaryCore(view, fields);
        }

        private string FormatApiProcessLabel(uint pid)
        {
            if (pid == 0)
            {
                return string.Empty;
            }

            string processName = GetApiGraphProcessName(pid);
            return string.IsNullOrWhiteSpace(processName)
                       ? pid.ToString(CultureInfo.InvariantCulture)
                       : $"{processName} ({pid.ToString(CultureInfo.InvariantCulture)})";
        }

        private static string FormatApiRelativeAge(DateTime lastSeenUtc)
        {
            if (lastSeenUtc == default)
            {
                return string.Empty;
            }

            TimeSpan age = DateTime.UtcNow - lastSeenUtc;
            if (age < TimeSpan.Zero)
            {
                age = TimeSpan.Zero;
            }

            if (age.TotalSeconds >= 1)
            {
                return $"{age.TotalSeconds:0.0}s ago";
            }

            return $"{Math.Max(0, age.TotalMilliseconds):0} ms ago";
        }

        private (string Action, string Detail) BuildApiDecodedAction(BrokerEtwEventView view, string rawReason)
        {
            string apiName = !string.IsNullOrWhiteSpace(view.Operation) ? view.Operation : view.EventName;
            if (string.IsNullOrWhiteSpace(apiName))
            {
                apiName = "unknown";
            }

            Dictionary<string, string> fields = BuildHookFieldMap(view);
            string action = BuildGenericApiActionLabel(apiName, fields);
            string detail;
            string argumentText = BuildResolvedHookArgumentsText(apiName, view, fields);
            bool hasExecutionContext =
                TryDescribeHookExecutionContext(view, fields, out string contextHeadline, out string contextDetail);

            if (TryBuildMemoryAction(apiName, view, fields, out string memoryAction, out string memoryDetail))
            {
                action = memoryAction;
                string frameSummary = BuildHookFrameSummary(view, fields);
                var detailBuilder = new StringBuilder(memoryDetail.TrimEnd());
                if (!string.IsNullOrWhiteSpace(frameSummary))
                {
                    detailBuilder.AppendLine().AppendLine().Append(frameSummary);
                }
                if (!string.IsNullOrWhiteSpace(argumentText))
                {
                    detailBuilder.AppendLine().AppendLine().Append(argumentText);
                }
                detail = detailBuilder.ToString();
                if (hasExecutionContext)
                {
                    if (contextHeadline.Equals("Loader / Image Mapping", StringComparison.OrdinalIgnoreCase))
                    {
                        action += " [loader]";
                    }
                    else if (contextHeadline.Equals("Kernel Caller", StringComparison.OrdinalIgnoreCase))
                    {
                        action += " [kernel]";
                    }

                    detail =
                        $"{contextHeadline}{Environment.NewLine}{contextDetail}{Environment.NewLine}{Environment.NewLine}{detail}";
                }
            }
            else
            {
                var sb = new StringBuilder(512);
                sb.AppendLine(action);
                if (hasExecutionContext)
                {
                    if (contextHeadline.Equals("Loader / Image Mapping", StringComparison.OrdinalIgnoreCase))
                    {
                        action += " [loader]";
                    }
                    else if (contextHeadline.Equals("Kernel Caller", StringComparison.OrdinalIgnoreCase))
                    {
                        action += " [kernel]";
                    }
                    else if (contextHeadline.Contains("Startup", StringComparison.OrdinalIgnoreCase))
                    {
                        action += " [startup]";
                    }

                    sb.AppendLine().AppendLine(contextHeadline);
                    sb.AppendLine(contextDetail);
                }
                string frameSummary = BuildHookFrameSummary(view, fields);
                if (!string.IsNullOrWhiteSpace(frameSummary))
                {
                    sb.AppendLine().AppendLine(frameSummary);
                }
                if (!string.IsNullOrWhiteSpace(argumentText))
                {
                    sb.AppendLine().AppendLine(argumentText);
                }
                string contextText = BuildGenericEtwDisplayDetail(view, fields, includeHeadline: false);
                if (!string.IsNullOrWhiteSpace(contextText))
                {
                    sb.AppendLine().Append(contextText);
                }
                detail = sb.ToString().Trim();
            }

            return (action, detail);
        }

        private bool TryBuildMemoryAction(string apiName, BrokerEtwEventView view,
                                          IReadOnlyDictionary<string, string> fields, out string action,
                                          out string detail)
        {
            action = string.Empty;
            detail = string.Empty;
            DateTime now = view.TimestampUtc == default ? DateTime.UtcNow : view.TimestampUtc;

            if (apiName.Equals("NtAllocateVirtualMemory", StringComparison.OrdinalIgnoreCase))
            {
                ulong baseAddress = FirstU64(fields, "base", "c0", "a1");
                ulong regionSize = FirstU64(fields, "size", "c1", "a3");
                ulong allocationType = FirstU64(fields, "allocType", "c2", "a4");
                uint protect = (uint)FirstU64(fields, "protect", "c3", "a5");
                ulong page = baseAddress & ~0xFFFUL;
                if (page != 0)
                {
                    ApiMemoryPageSignal state = GetOrCreateApiMemoryPageSignal(page);
                    if (protect != 0)
                    {
                        state.Protect = protect;
                        state.LastProtectChangeUtc = now;
                    }
                }

                string protectLabel = DescribeMemoryProtect(protect);
                (string contextActionSuffix, string contextDetail) =
                    DescribeMemoryRegionContext(view, baseAddress, regionSize);
                action = $"Allocates 0x{regionSize:X} bytes at 0x{baseAddress:X} ({protectLabel}){contextActionSuffix}";
                detail = $"Action: memory.alloc\n" + $"API: {apiName}\n" + $"Base: 0x{baseAddress:X}\n" +
                         $"Size: 0x{regionSize:X}\n" +
                         $"AllocType: 0x{allocationType:X} ({DescribeMemoryAllocationType((uint)allocationType)})\n" +
                         $"Protect: 0x{protect:X} ({protectLabel})\n" + contextDetail.TrimEnd();
                return true;
            }

            if (apiName.Equals("NtProtectVirtualMemory", StringComparison.OrdinalIgnoreCase))
            {
                ulong baseAddress = FirstU64(fields, "base", "c0", "a1");
                ulong regionSize = FirstU64(fields, "size", "c1", "a2");
                uint newProtect = (uint)FirstU64(fields, "newProtect", "c2", "a3");
                ulong page = baseAddress & ~0xFFFUL;
                ApiMemoryPageSignal state = GetOrCreateApiMemoryPageSignal(page);

                bool protectChanged = state.Protect != 0 && newProtect != 0 && state.Protect != newProtect;
                bool rapidFlip = false;
                if (protectChanged)
                {
                    state.ProtectFlipCount += 1;
                    rapidFlip = state.LastProtectChangeUtc != default &&
                                (now - state.LastProtectChangeUtc).TotalMilliseconds <= 900;
                }

                if (newProtect != 0)
                {
                    state.Protect = newProtect;
                }
                state.LastProtectChangeUtc = now;

                string protectLabel = DescribeMemoryProtect(newProtect);
                (string contextActionSuffix, string contextDetail) =
                    DescribeMemoryRegionContext(view, baseAddress, regionSize);
                action = $"Changes protection to {protectLabel} at 0x{baseAddress:X}{contextActionSuffix}";
                detail = $"Action: memory.protect\n" + $"API: {apiName}\n" + $"Base: 0x{baseAddress:X}\n" +
                         $"Size: 0x{regionSize:X}\n" + $"NewProtect: 0x{newProtect:X} ({protectLabel})\n" +
                         $"ProtectFlips: {state.ProtectFlipCount}\n" + $"RapidFlip: {(rapidFlip ? "yes" : "no")}\n" +
                         contextDetail.TrimEnd();
                return true;
            }

            if (apiName.Equals("NtWriteVirtualMemory", StringComparison.OrdinalIgnoreCase))
            {
                ulong baseAddress = FirstU64(fields, "base", "c0", "a1");
                ulong size = FirstU64(fields, "size", "c1", "a3");
                ulong page = baseAddress & ~0xFFFUL;
                ApiMemoryPageSignal state = GetOrCreateApiMemoryPageSignal(page);
                int sampleLen = (int)Math.Min(view.DeepSampleSize, (uint)(view.DeepSample?.Length ?? 0));
                double entropy = ComputeSampleEntropyBits(view.DeepSample, sampleLen);
                if (entropy < 0 && TryReadDouble(fields, out double parsedEntropy, "entropy"))
                {
                    entropy = parsedEntropy;
                }

                bool entropyChanged = !double.IsNaN(state.LastEntropyBits) && entropy >= 0 &&
                                      Math.Abs(state.LastEntropyBits - entropy) >= MemoryEntropyFlipDeltaBits;
                bool rapidEntropyFlip = false;
                if (entropyChanged)
                {
                    state.EntropyFlipCount += 1;
                    rapidEntropyFlip = state.LastEntropyChangeUtc != default &&
                                       (now - state.LastEntropyChangeUtc).TotalMilliseconds <= 900;
                }

                if (entropy >= 0)
                {
                    state.LastEntropyBits = entropy;
                    state.LastEntropyChangeUtc = now;
                }

                string entropyText = entropy >= 0 ? entropy.ToString("F2", CultureInfo.InvariantCulture) : "n/a";
                (string contextActionSuffix, string contextDetail) =
                    DescribeMemoryRegionContext(view, baseAddress, size);
                action = $"Writes 0x{size:X} bytes at 0x{baseAddress:X} (entropy {entropyText}){contextActionSuffix}";
                detail = $"Action: memory.write\n" + $"API: {apiName}\n" + $"Base: 0x{baseAddress:X}\n" +
                         $"Size: 0x{size:X}\n" + $"Entropy(bits/byte): {entropyText}\n" +
                         $"EntropyFlips: {state.EntropyFlipCount}\n" + $"ProtectFlips: {state.ProtectFlipCount}\n" +
                         $"RapidEntropyFlip: {(rapidEntropyFlip ? "yes" : "no")}\n" + $"SampleBytes: {sampleLen}\n" +
                         contextDetail.TrimEnd();
                return true;
            }

            return false;
        }

        private MemoryRegionAttributionSample? CreateMemoryRegionAttributionSample(BrokerEtwEventView view)
        {
            string apiName =
                string.IsNullOrWhiteSpace(view.EventName) ? view.Operation ?? string.Empty : view.EventName;
            Dictionary<string, string> fields = BuildHookFieldMap(view);
            string eventKind = string.Empty;
            string regionKind = string.Empty;
            ulong allocationBase = 0;
            ulong baseAddress = 0;
            ulong regionSize = 0;
            ulong threadStartAddress = 0;
            uint initialProtection = 0;
            uint currentProtection = 0;
            uint previousProtection = 0;
            uint protectFlipCount = 0;
            uint sampleBytes = 0;
            bool threadStartObserved = false;
            bool functionTableRegistered = false;
            ulong functionTablePointer = 0;
            double entropyBits = -1;

            switch (view.Family)
            {
            case BlackbirdNative.IpcEtwFamilyImage:
                eventKind = "ImageMap";
                regionKind = "Image";
                allocationBase = view.ImageBase;
                baseAddress = view.ImageBase;
                regionSize = view.ImageSize;
                currentProtection = view.StartRegionProtect;
                initialProtection = currentProtection;
                break;
            case BlackbirdNative.IpcEtwFamilyThread:
                eventKind = "ThreadStart";
                regionKind = view.ImageBase != 0 ? "Image" : "Unknown";
                allocationBase = view.ImageBase != 0 ? view.ImageBase : NormalizeRegionAddress(view.StartAddress);
                baseAddress = allocationBase;
                regionSize = view.ImageSize != 0 ? view.ImageSize : 1;
                currentProtection = view.StartRegionProtect;
                initialProtection = currentProtection;
                threadStartObserved = true;
                threadStartAddress = view.StartAddress;
                break;
            case BlackbirdNative.IpcEtwFamilyUserHook:
                if (string.IsNullOrWhiteSpace(apiName))
                {
                    return null;
                }

                if (apiName.Equals("NtAllocateVirtualMemory", StringComparison.OrdinalIgnoreCase) ||
                    apiName.Equals("NtAllocateVirtualMemoryEx", StringComparison.OrdinalIgnoreCase))
                {
                    eventKind = "PrivateAllocate";
                    regionKind = "Private";
                    allocationBase = FirstU64(fields, "base", "c1", "a1");
                    baseAddress = allocationBase;
                    regionSize = FirstU64(fields, "size", "c3", "a3");
                    currentProtection = (uint)FirstU64(fields, "protect", "c3", "a5", "c5");
                    initialProtection = currentProtection;
                }
                else if (apiName.Equals("NtProtectVirtualMemory", StringComparison.OrdinalIgnoreCase))
                {
                    eventKind = "ProtectChange";
                    allocationBase = FirstU64(fields, "base", "c1", "a1");
                    baseAddress = allocationBase;
                    regionSize = FirstU64(fields, "size", "c2", "a2");
                    currentProtection = (uint)FirstU64(fields, "newProtect", "c2", "a3", "c3");
                    previousProtection = (uint)FirstU64(fields, "oldProtect", "a4", "c4");
                    protectFlipCount = (uint)FirstU64(fields, "protectFlips");
                    sampleBytes = (uint)FirstU64(fields, "sampleBytes");
                }
                else if (apiName.Equals("NtWriteVirtualMemory", StringComparison.OrdinalIgnoreCase))
                {
                    eventKind = "MemoryWrite";
                    allocationBase = FirstU64(fields, "base", "c1", "a1");
                    baseAddress = allocationBase;
                    regionSize = Math.Max(1UL, FirstU64(fields, "size", "c3", "a3"));
                    protectFlipCount = (uint)FirstU64(fields, "protectFlips");
                    sampleBytes = (uint)FirstU64(fields, "sampleBytes");
                    if (TryReadDouble(fields, out double parsedEntropy, "entropy"))
                    {
                        entropyBits = parsedEntropy;
                    }
                }
                else if (apiName.Equals("NtMapViewOfSection", StringComparison.OrdinalIgnoreCase) ||
                         apiName.Equals("NtMapViewOfSectionEx", StringComparison.OrdinalIgnoreCase))
                {
                    eventKind = "SectionMap";
                    regionKind = IsHookImageSection(view) ? "Image" : "Mapped";
                    allocationBase = FirstU64(fields, "baseAddress", "base", "c2", "a2");
                    baseAddress = allocationBase;
                    regionSize = FirstU64(fields, "viewSize", "size", "c3", "a4", "a6");
                    currentProtection = (uint)FirstU64(fields, "win32Protect", "a6", "c6", "c5");
                    initialProtection = currentProtection;
                }
                else if (apiName.Equals("RtlAddFunctionTable", StringComparison.OrdinalIgnoreCase))
                {
                    eventKind = "FunctionTableRegister";
                    functionTablePointer = FirstU64(fields, "table", "a0");
                    allocationBase = FirstU64(fields, "baseAddress", "a2");
                    baseAddress = allocationBase;
                    regionSize = 1;
                    functionTableRegistered = true;
                }
                else if (apiName.Equals("RtlInstallFunctionTableCallback", StringComparison.OrdinalIgnoreCase))
                {
                    eventKind = "FunctionTableCallback";
                    functionTablePointer = FirstU64(fields, "tableId", "a0");
                    allocationBase = FirstU64(fields, "baseAddress", "a1");
                    baseAddress = allocationBase;
                    regionSize = Math.Max(1UL, FirstU64(fields, "length", "a2"));
                    functionTableRegistered = true;
                }
                else if (apiName.Equals("RtlDeleteFunctionTable", StringComparison.OrdinalIgnoreCase))
                {
                    functionTablePointer = FirstU64(fields, "table", "a0");
                    eventKind = "FunctionTableDelete";
                    allocationBase = ResolveFunctionTableBase(view, functionTablePointer);
                    baseAddress = allocationBase;
                    regionSize = 1;
                    functionTableRegistered = false;
                }
                else
                {
                    return null;
                }
                break;
            default:
                return null;
            }

            if (sampleBytes == 0 && view.DeepSampleSize != 0)
            {
                sampleBytes = view.DeepSampleSize;
            }
            if (entropyBits < 0 && view.DeepSample.Length > 1)
            {
                int sampleLength = sampleBytes == 0 ? view.DeepSample.Length
                                                    : (int)Math.Min(sampleBytes, (uint)view.DeepSample.Length);
                entropyBits = ComputeSampleEntropyBits(view.DeepSample, sampleLength);
            }

            uint targetPid = ResolveMemoryRegionTargetPid(view);
            if (targetPid == 0)
            {
                return null;
            }

            if (allocationBase == 0)
            {
                allocationBase = NormalizeRegionAddress(baseAddress != 0 ? baseAddress : threadStartAddress);
            }
            if (baseAddress == 0)
            {
                baseAddress = allocationBase;
            }
            if (allocationBase == 0 || baseAddress == 0)
            {
                return null;
            }
            if (regionSize == 0)
            {
                if (threadStartObserved || eventKind.StartsWith("FunctionTable", StringComparison.OrdinalIgnoreCase))
                {
                    regionSize = 1;
                }
                else
                {
                    return null;
                }
            }

            ulong processStartKey = ResolveObservedProcessStartKey(targetPid, view.ProcessStartKey);
            if (view.Family == BlackbirdNative.IpcEtwFamilyThread && threadStartAddress != 0 &&
                TryResolveKnownRegionForAddress(targetPid, processStartKey, threadStartAddress, out _,
                                                out ulong existingBaseAddress, out ulong existingRegionSize,
                                                out string existingRegionKind, out uint existingProtection))
            {
                allocationBase = existingBaseAddress;
                baseAddress = existingBaseAddress;
                regionSize = existingRegionSize;
                regionKind = existingRegionKind;
                if (currentProtection == 0)
                {
                    currentProtection = existingProtection;
                }
                if (initialProtection == 0)
                {
                    initialProtection = existingProtection;
                }
            }

            string regionIdentity = BuildRegionIdentity(processStartKey, targetPid, allocationBase);
            string firstUserFrameModule = ResolveHookOriginModule(view, fields);
            bool hookFamily = view.Family == BlackbirdNative.IpcEtwFamilyUserHook;
            string frameSummary = view.Family == BlackbirdNative.IpcEtwFamilyUserHook
                                      ? BuildHookFrameSummary(view, fields)
                                      : string.Empty;

            ProcessIdentityResolver.Prime(view.ActorPid);
            ProcessIdentityResolver.Prime(targetPid);

            string executionContext = string.Empty;
            if (TryDescribeHookExecutionContext(view, fields, out string contextHeadline, out _))
            {
                executionContext = contextHeadline;
            }

            var sample = new MemoryRegionAttributionSample {
                TimestampUtc = view.TimestampUtc == default ? DateTime.UtcNow : view.TimestampUtc,
                ProcessStartKey = processStartKey,
                TargetPid = targetPid,
                ActorPid = view.ActorPid != 0 ? view.ActorPid : targetPid,
                ActorTid = view.ThreadId != 0 ? view.ThreadId : view.EventThreadId,
                AllocationBase = allocationBase,
                BaseAddress = baseAddress,
                RegionSize = regionSize,
                ApiName = apiName,
                EventKind = eventKind,
                RegionKind =
                    string.IsNullOrWhiteSpace(regionKind) ? InferRegionKind(view, currentProtection) : regionKind,
                RegionIdentity = regionIdentity,
                OriginPath = view.OriginPath ?? view.ImagePath ?? string.Empty,
                SourceFamily = view.Family == BlackbirdNative.IpcEtwFamilyUserHook ? "Hook"
                               : view.Family == BlackbirdNative.IpcEtwFamilyImage  ? "ImageLoad"
                               : view.Family == BlackbirdNative.IpcEtwFamilyThread ? "Thread"
                                                                                   : "ETW",
                ExecutionContext = executionContext,
                CallerOrigin = view.CallerOriginLabel,
                FirstUserFrame = view.OriginAddress,
                FirstUserFrameModule = firstUserFrameModule,
                FrameSummary = frameSummary,
                UnwindClean = hookFamily && IsHookUnwindClean(view.Flags),
                FrameChainHadGaps = hookFamily && HookFrameChainHasGaps(view.Flags),
                ObservedByKernel = hookFamily && view.SourceId == BlackbirdNative.IpcEtwSourceBlackbird,
                ObservedByUserHook = hookFamily && view.SourceId == BlackbirdNative.IpcEtwSourceUserHook,
                BlackbirdOwned = IsBlackbirdOwnEvent(view),
                CrossProcess = targetPid != 0 && view.ActorPid != 0 && targetPid != view.ActorPid,
                ImageBacked = string.Equals(regionKind, "Image", StringComparison.OrdinalIgnoreCase) ||
                              IsHookImageSection(view) || view.Family == BlackbirdNative.IpcEtwFamilyImage,
                InitialProtection = initialProtection,
                CurrentProtection = currentProtection,
                PreviousProtection = previousProtection,
                ProtectFlipCount = protectFlipCount,
                EntropyBits = entropyBits,
                SampleBytes = sampleBytes,
                ThreadStartObserved = threadStartObserved,
                ThreadId = threadStartObserved ? (view.ThreadId != 0 ? view.ThreadId : view.EventThreadId) : 0,
                ThreadStartAddress = threadStartAddress,
                FunctionTableRegistered = functionTableRegistered,
                FunctionTablePointer = functionTablePointer,
                SignatureLevel = view.SignatureLevel,
                SignatureType = view.SignatureType
            };

            return FinalizeMemoryRegionAttribution(sample);
        }

        private MemoryRegionAttributionSample FinalizeMemoryRegionAttribution(MemoryRegionAttributionSample sample)
        {
            if (string.IsNullOrWhiteSpace(sample.RegionIdentity))
            {
                return sample;
            }

            if (!_regionLifecycleByIdentity.TryGetValue(sample.RegionIdentity, out RegionLifecycleState? state))
            {
                state = new RegionLifecycleState();
                _regionLifecycleByIdentity[sample.RegionIdentity] = state;
            }

            if (state.TargetPid == 0)
            {
                state.TargetPid = sample.TargetPid;
            }
            if (state.ProcessStartKey == 0)
            {
                state.ProcessStartKey = sample.ProcessStartKey;
            }
            if (state.BaseAddress == 0)
            {
                state.BaseAddress = sample.AllocationBase != 0 ? sample.AllocationBase : sample.BaseAddress;
            }
            if (string.IsNullOrWhiteSpace(state.ExecutionContext) &&
                !string.IsNullOrWhiteSpace(sample.ExecutionContext))
            {
                state.ExecutionContext = sample.ExecutionContext;
            }
            if (state.RegionSize == 0 && sample.RegionSize != 0)
            {
                state.RegionSize = sample.RegionSize;
            }
            else if (sample.RegionSize > state.RegionSize)
            {
                state.RegionSize = sample.RegionSize;
            }
            if (string.IsNullOrWhiteSpace(state.RegionKind) && !string.IsNullOrWhiteSpace(sample.RegionKind))
            {
                state.RegionKind = sample.RegionKind;
            }
            if (!state.ObservedByKernel && sample.ObservedByKernel)
            {
                state.ObservedByKernel = true;
            }
            if (!state.ObservedByUserHook && sample.ObservedByUserHook)
            {
                state.ObservedByUserHook = true;
            }
            if (!state.BlackbirdOwned && sample.BlackbirdOwned)
            {
                state.BlackbirdOwned = true;
            }
            if (!state.CrossProcess && sample.CrossProcess)
            {
                state.CrossProcess = true;
            }
            if (!state.ImageBacked && sample.ImageBacked)
            {
                state.ImageBacked = true;
            }

            if (sample.InitialProtection != 0 && state.InitialProtection == 0)
            {
                state.InitialProtection = sample.InitialProtection;
            }

            if (sample.CurrentProtection == 0 && state.CurrentProtection != 0)
            {
                sample.CurrentProtection = state.CurrentProtection;
            }

            if (sample.InitialProtection == 0 && state.InitialProtection != 0)
            {
                sample.InitialProtection = state.InitialProtection;
            }

            uint reportedProtectFlipCount = sample.ProtectFlipCount;
            DateTime observedUtc = sample.TimestampUtc == default ? DateTime.UtcNow : sample.TimestampUtc;
            if (sample.CurrentProtection != 0)
            {
                uint previousProtection =
                    sample.PreviousProtection != 0 ? sample.PreviousProtection : state.CurrentProtection;
                if (sample.PreviousProtection == 0 && previousProtection != 0 &&
                    (sample.EventKind.Equals("ProtectChange", StringComparison.OrdinalIgnoreCase) ||
                     sample.EventKind.Equals("SectionMap", StringComparison.OrdinalIgnoreCase) ||
                     sample.EventKind.Equals("ImageMap", StringComparison.OrdinalIgnoreCase)))
                {
                    sample.PreviousProtection = previousProtection;
                }

                bool executableNow = IsExecutableProtection(sample.CurrentProtection);
                bool executableBefore = IsExecutableProtection(previousProtection);
                if (!state.FirstExecutableTransitionSeen && executableNow && !executableBefore)
                {
                    sample.FirstExecutableTransition = true;
                    state.FirstExecutableTransitionSeen = true;
                }

                bool protectionChanged = previousProtection != 0 &&
                                         !ProtectionValuesEquivalent(previousProtection, sample.CurrentProtection);
                bool protectSignalEvent =
                    sample.EventKind.Equals("ProtectChange", StringComparison.OrdinalIgnoreCase) ||
                    reportedProtectFlipCount > state.ProtectFlipCount;
                if (protectionChanged && protectSignalEvent)
                {
                    string transition = BuildProtectionTransitionLabel(previousProtection, sample.CurrentProtection);
                    sample.ProtectionTransition = transition;
                    state.LastProtectionTransition = transition;

                    if (reportedProtectFlipCount > state.ProtectFlipCount)
                    {
                        state.ProtectFlipCount = reportedProtectFlipCount;
                    }
                    else
                    {
                        state.ProtectFlipCount += 1;
                    }

                    double protectDeltaMs = state.LastProtectChangeUtc == default
                                                ? double.MaxValue
                                                : (observedUtc - state.LastProtectChangeUtc).TotalMilliseconds;
                    if (protectDeltaMs >= 0 && protectDeltaMs <= 1000)
                    {
                        state.RapidProtectFlipCount += 1;
                    }
                    state.LastProtectChangeUtc = observedUtc;

                    if (executableNow != executableBefore)
                    {
                        state.ExecutableFlipCount += 1;
                    }
                    if (IsGuardNoAccessProtectionTransition(previousProtection, sample.CurrentProtection))
                    {
                        state.GuardNoAccessFlipCount += 1;
                    }
                    if (IsWritableExecutableProtectionTransition(previousProtection, sample.CurrentProtection))
                    {
                        state.WritableExecutableFlipCount += 1;
                    }
                }
                else if (string.IsNullOrWhiteSpace(sample.ProtectionTransition))
                {
                    sample.ProtectionTransition = state.LastProtectionTransition;
                }

                if (state.InitialProtection == 0)
                {
                    state.InitialProtection = sample.CurrentProtection;
                }
                state.PreviousProtection = previousProtection;
                state.CurrentProtection = sample.CurrentProtection;
            }

            if (sample.EventKind.Equals("SectionMap", StringComparison.OrdinalIgnoreCase) ||
                sample.EventKind.Equals("ImageMap", StringComparison.OrdinalIgnoreCase))
            {
                state.MapCount += 1;
            }
            else if (sample.EventKind.Equals("MemoryWrite", StringComparison.OrdinalIgnoreCase))
            {
                state.WriteCount += 1;
            }
            else if (sample.EventKind.Equals("ProtectChange", StringComparison.OrdinalIgnoreCase))
            {
                state.ProtectCount += 1;
            }

            if (sample.ThreadStartObserved)
            {
                state.ThreadStartCount += 1;
                if (!state.FirstThreadStartSeen)
                {
                    state.FirstThreadStartSeen = true;
                    state.FirstThreadStartAddress = sample.ThreadStartAddress;
                }
                else
                {
                    sample.ThreadStartObserved = false;
                }
            }

            if (sample.EventKind.Equals("FunctionTableRegister", StringComparison.OrdinalIgnoreCase) ||
                sample.EventKind.Equals("FunctionTableCallback", StringComparison.OrdinalIgnoreCase))
            {
                state.FunctionTableRegistered = true;
            }
            else if (sample.EventKind.Equals("FunctionTableDelete", StringComparison.OrdinalIgnoreCase))
            {
                state.FunctionTableRegistered = false;
            }

            if (reportedProtectFlipCount > state.ProtectFlipCount)
            {
                state.ProtectFlipCount = reportedProtectFlipCount;
            }
            if (sample.EntropyBits >= 0)
            {
                bool entropyChanged =
                    state.LastEntropyBits >= 0 &&
                    Math.Abs(state.LastEntropyBits - sample.EntropyBits) >= MemoryEntropyFlipDeltaBits;
                if (entropyChanged)
                {
                    state.EntropyFlipCount += 1;
                    double entropyDeltaMs = state.LastEntropyChangeUtc == default
                                                ? double.MaxValue
                                                : (observedUtc - state.LastEntropyChangeUtc).TotalMilliseconds;
                    if (entropyDeltaMs >= 0 && entropyDeltaMs <= 1000)
                    {
                        state.RapidEntropyFlipCount += 1;
                    }
                    state.LastEntropyChangeUtc = observedUtc;
                }

                if (sample.EventKind.Equals("MemoryWrite", StringComparison.OrdinalIgnoreCase) &&
                    sample.EntropyBits >= MemoryHighEntropyBits &&
                    (sample.SampleBytes == 0 || sample.SampleBytes >= MemoryEntropyMinSampleBytes))
                {
                    state.HighEntropyWriteCount += 1;
                }

                state.LastEntropyBits = sample.EntropyBits;
                if (state.MaxEntropyBits < 0 || sample.EntropyBits > state.MaxEntropyBits)
                {
                    state.MaxEntropyBits = sample.EntropyBits;
                }
            }
            if (sample.SampleBytes > state.LastSampleBytes)
            {
                state.LastSampleBytes = sample.SampleBytes;
            }

            if (sample.TargetPid != 0 && sample.BaseAddress != 0)
            {
                if (sample.ApiName.Equals("RtlAddFunctionTable", StringComparison.OrdinalIgnoreCase) &&
                    sample.FunctionTablePointer != 0)
                {
                    string tableKey = BuildFunctionTablePointerKey(sample.TargetPid, sample.FunctionTablePointer);
                    _functionTableBaseByPointer[tableKey] = sample.BaseAddress;
                }
                else if (sample.ApiName.Equals("RtlDeleteFunctionTable", StringComparison.OrdinalIgnoreCase) &&
                         sample.FunctionTablePointer != 0)
                {
                    _functionTableBaseByPointer.Remove(
                        BuildFunctionTablePointerKey(sample.TargetPid, sample.FunctionTablePointer));
                }
            }

            sample.FunctionTableRegistered = state.FunctionTableRegistered || sample.FunctionTableRegistered;
            sample.MapCount = state.MapCount;
            sample.WriteCount = state.WriteCount;
            sample.ProtectCount = state.ProtectCount;
            sample.ThreadStartCount = state.ThreadStartCount;
            sample.ProtectFlipCount = Math.Max(sample.ProtectFlipCount, state.ProtectFlipCount);
            sample.RapidProtectFlipCount = state.RapidProtectFlipCount;
            sample.ExecutableFlipCount = state.ExecutableFlipCount;
            sample.GuardNoAccessFlipCount = state.GuardNoAccessFlipCount;
            sample.WritableExecutableFlipCount = state.WritableExecutableFlipCount;
            if (string.IsNullOrWhiteSpace(sample.ProtectionTransition))
            {
                sample.ProtectionTransition = state.LastProtectionTransition;
            }
            if (sample.EntropyBits < 0)
            {
                sample.EntropyBits = state.LastEntropyBits;
            }
            sample.MaxEntropyBits = state.MaxEntropyBits;
            sample.EntropyFlipCount = state.EntropyFlipCount;
            sample.RapidEntropyFlipCount = state.RapidEntropyFlipCount;
            sample.HighEntropyWriteCount = state.HighEntropyWriteCount;
            if (sample.SampleBytes == 0)
            {
                sample.SampleBytes = state.LastSampleBytes;
            }
            sample.ObservedByKernel = sample.ObservedByKernel || state.ObservedByKernel;
            sample.ObservedByUserHook = sample.ObservedByUserHook || state.ObservedByUserHook;
            sample.BlackbirdOwned = sample.BlackbirdOwned || state.BlackbirdOwned;
            sample.CrossProcess = sample.CrossProcess || state.CrossProcess;
            sample.ImageBacked = sample.ImageBacked || state.ImageBacked;
            if (string.IsNullOrWhiteSpace(sample.ExecutionContext))
            {
                sample.ExecutionContext = state.ExecutionContext;
            }
            sample.LifecycleSummary = BuildMemoryLifecycleSummary(sample);
            return sample;
        }

        private static string BuildMemoryLifecycleSummary(MemoryRegionAttributionSample sample)
        {
            var parts = new List<string>(6);
            if (sample.MapCount != 0)
            {
                parts.Add($"map:{sample.MapCount}");
            }
            if (sample.WriteCount != 0)
            {
                parts.Add($"write:{sample.WriteCount}");
            }
            if (sample.ProtectCount != 0)
            {
                parts.Add($"protect:{sample.ProtectCount}");
            }
            if (sample.ThreadStartCount != 0)
            {
                parts.Add($"thread:{sample.ThreadStartCount}");
            }
            if (sample.FirstExecutableTransition)
            {
                parts.Add("first-exec");
            }
            if (sample.FunctionTableRegistered)
            {
                parts.Add("unwind");
            }

            string summary = parts.Count == 0 ? sample.EventKind : string.Join(" ", parts);
            if (sample.CrossProcess)
            {
                summary += " xproc";
            }
            if (sample.ImageBacked)
            {
                summary += " image";
            }
            if (sample.ProtectFlipCount != 0)
            {
                summary += $" pflip:{sample.ProtectFlipCount}";
            }
            if (sample.RapidProtectFlipCount != 0)
            {
                summary += $" rapid-pflip:{sample.RapidProtectFlipCount}";
            }
            if (!string.IsNullOrWhiteSpace(sample.ProtectionTransition))
            {
                summary += $" transition:{sample.ProtectionTransition}";
            }
            if (sample.ExecutableFlipCount != 0)
            {
                summary += $" xflip:{sample.ExecutableFlipCount}";
            }
            if (sample.GuardNoAccessFlipCount != 0)
            {
                summary += $" guard/noaccess:{sample.GuardNoAccessFlipCount}";
            }
            if (sample.WritableExecutableFlipCount != 0)
            {
                summary += $" wxflip:{sample.WritableExecutableFlipCount}";
            }
            if (sample.EntropyBits >= 0)
            {
                summary += $" H:{sample.EntropyBits:F1}";
            }
            if (sample.MaxEntropyBits >= 0 && sample.MaxEntropyBits > sample.EntropyBits + 0.05)
            {
                summary += $" Hmax:{sample.MaxEntropyBits:F1}";
            }
            if (sample.EntropyFlipCount != 0)
            {
                summary += $" eflip:{sample.EntropyFlipCount}";
            }
            if (sample.RapidEntropyFlipCount != 0)
            {
                summary += $" rapid-eflip:{sample.RapidEntropyFlipCount}";
            }
            if (sample.HighEntropyWriteCount != 0)
            {
                summary += $" high-H:{sample.HighEntropyWriteCount}";
            }

            return summary.Trim();
        }

        private uint ResolveMemoryRegionTargetPid(BrokerEtwEventView view)
        {
            return view.Family switch {
                BlackbirdNative.IpcEtwFamilyImage => view.ProcessPid != 0 ? view.ProcessPid : view.EventProcessId,
                BlackbirdNative.IpcEtwFamilyThread =>
                    view.ProcessPid != 0 ? view.ProcessPid
                                         : (view.TargetPid != 0 ? view.TargetPid : view.EventProcessId),
                BlackbirdNative.IpcEtwFamilyUserHook =>
                    view.TargetPid != 0 ? view.TargetPid : (view.ProcessPid != 0 ? view.ProcessPid : view.ActorPid),
                _ => 0
            };
        }

        private ulong ResolveObservedProcessStartKey(uint pid, ulong eventStartKey)
        {
            if (eventStartKey != 0)
            {
                _observedProcessStartKeyByPid[pid] = eventStartKey;
                return eventStartKey;
            }

            return _observedProcessStartKeyByPid.TryGetValue(pid, out ulong cached) ? cached : 0;
        }

        private static string BuildRegionIdentity(ulong processStartKey, uint targetPid, ulong allocationBase) =>
            $"{targetPid:X8}:{processStartKey:X16}:{allocationBase:X16}";

        private static string BuildFunctionTablePointerKey(uint pid,
                                                           ulong functionTable) => $"{pid:X8}:{functionTable:X16}";

        private ulong ResolveFunctionTableBase(BrokerEtwEventView view, ulong functionTable)
        {
            if (view.ProcessPid != 0 && functionTable != 0)
            {
                string key = BuildFunctionTablePointerKey(view.ProcessPid, functionTable);
                if (_functionTableBaseByPointer.TryGetValue(key, out ulong baseAddress) && baseAddress != 0)
                {
                    return baseAddress;
                }
            }

            return 0;
        }

        private bool TryResolveKnownRegionForAddress(uint targetPid, ulong processStartKey, ulong address,
                                                     out string regionIdentity, out ulong baseAddress,
                                                     out ulong regionSize, out string regionKind,
                                                     out uint currentProtection)
        {
            regionIdentity = string.Empty;
            baseAddress = 0;
            regionSize = 0;
            regionKind = string.Empty;
            currentProtection = 0;

            if (targetPid == 0 || address == 0 || _regionLifecycleByIdentity.Count == 0)
            {
                return false;
            }

            RegionLifecycleState? best = null;
            foreach ((string candidateIdentity, RegionLifecycleState candidate) in _regionLifecycleByIdentity)
            {
                if (candidate.TargetPid != targetPid || candidate.BaseAddress == 0 || candidate.RegionSize == 0)
                {
                    continue;
                }
                if (processStartKey != 0 && candidate.ProcessStartKey != 0 &&
                    candidate.ProcessStartKey != processStartKey)
                {
                    continue;
                }

                ulong regionEnd = candidate.BaseAddress + candidate.RegionSize;
                if (regionEnd <= candidate.BaseAddress)
                {
                    regionEnd = ulong.MaxValue;
                }
                if (address < candidate.BaseAddress || address >= regionEnd)
                {
                    continue;
                }

                if (best == null || candidate.BaseAddress >= best.BaseAddress)
                {
                    best = candidate;
                    regionIdentity = candidateIdentity;
                }
            }

            if (best == null)
            {
                return false;
            }

            baseAddress = best.BaseAddress;
            regionSize = best.RegionSize;
            regionKind = best.RegionKind;
            currentProtection = best.CurrentProtection;
            return true;
        }

        private static ulong NormalizeRegionAddress(ulong address) => address == 0 ? 0 : (address & ~0xFFFUL);

        private static bool IsExecutableProtection(uint protection)
        {
            uint normalized = protection & 0xFFu;
            return normalized == 0x10u || normalized == 0x20u || normalized == 0x40u || normalized == 0x80u;
        }

        private static bool IsWritableProtection(uint protection)
        {
            uint normalized = protection & 0xFFu;
            return normalized == 0x04u || normalized == 0x08u || normalized == 0x40u || normalized == 0x80u;
        }

        private static bool IsNoAccessProtection(uint protection)
        {
            return (protection & 0xFFu) == 0x01u;
        }

        private static bool HasGuardProtection(uint protection)
        {
            return (protection & 0x100u) != 0;
        }

        private static bool IsWritableExecutableProtection(uint protection)
        {
            uint normalized = protection & 0xFFu;
            return normalized == 0x40u || normalized == 0x80u;
        }

        private static uint NormalizeProtectionForFlip(uint protection)
        {
            return protection & 0x1FFu;
        }

        private static bool ProtectionValuesEquivalent(uint left, uint right)
        {
            return NormalizeProtectionForFlip(left) == NormalizeProtectionForFlip(right);
        }

        private static bool IsGuardNoAccessProtectionTransition(uint previousProtection, uint currentProtection)
        {
            return IsNoAccessProtection(previousProtection) || IsNoAccessProtection(currentProtection) ||
                   HasGuardProtection(previousProtection) || HasGuardProtection(currentProtection);
        }

        private static bool IsWritableExecutableProtectionTransition(uint previousProtection, uint currentProtection)
        {
            return IsWritableExecutableProtection(previousProtection) ||
                   IsWritableExecutableProtection(currentProtection) ||
                   (IsWritableProtection(previousProtection) && IsExecutableProtection(currentProtection)) ||
                   (IsExecutableProtection(previousProtection) && IsWritableProtection(currentProtection));
        }

        private static string BuildProtectionTransitionLabel(uint previousProtection, uint currentProtection)
        {
            return $"{CompactMemoryProtectionLabel(previousProtection)}->{CompactMemoryProtectionLabel(currentProtection)}";
        }

        private static string CompactMemoryProtectionLabel(uint protection)
        {
            string baseLabel = (protection & 0xFFu) switch {
                0x01u => "NO_ACCESS",
                0x02u => "R",
                0x04u => "RW",
                0x08u => "WC",
                0x10u => "X",
                0x20u => "RX",
                0x40u => "RWX",
                0x80u => "XWC",
                _ => protection == 0 ? "UNKNOWN" : $"0x{protection & 0xFFu:X}"
            };

            return HasGuardProtection(protection) ? $"GUARD|{baseLabel}" : baseLabel;
        }

        private static bool IsMemoryPatternMilestone(uint count)
        {
            return count == 2 || count == 3 || count == 5 || count == 10 || count == 25 || count == 50 ||
                   (count >= 100 && count % 100 == 0);
        }

        private static bool IsHighEntropyWriteMilestone(uint count)
        {
            return count == 1 || count == 3 || count == 10 || count == 25 || count == 50 ||
                   (count >= 100 && count % 100 == 0);
        }

        private static bool HasUsableEntropySample(MemoryRegionAttributionSample sample)
        {
            return sample.EntropyBits >= 0 &&
                   (sample.SampleBytes == 0 || sample.SampleBytes >= MemoryEntropyMinSampleBytes);
        }

        private static uint ComputeMemoryLifecycleSeverity(MemoryRegionAttributionSample sample, bool protectSignal,
                                                           bool entropySignal)
        {
            uint severity = protectSignal ? 5u : 4u;
            if (protectSignal)
            {
                if (sample.ProtectFlipCount >= 50 || sample.RapidProtectFlipCount >= 10)
                {
                    severity = Math.Max(severity, 9u);
                }
                else if (sample.ProtectFlipCount >= 10 || sample.RapidProtectFlipCount >= 4)
                {
                    severity = Math.Max(severity, 8u);
                }
                else if (sample.ProtectFlipCount >= 5 || sample.GuardNoAccessFlipCount != 0 ||
                         sample.WritableExecutableFlipCount != 0)
                {
                    severity = Math.Max(severity, 7u);
                }
                else if (sample.ProtectFlipCount >= 2 || sample.RapidProtectFlipCount != 0 ||
                         sample.ExecutableFlipCount != 0)
                {
                    severity = Math.Max(severity, 6u);
                }
            }

            if (entropySignal)
            {
                if (sample.MaxEntropyBits >= 7.7 || sample.HighEntropyWriteCount >= 10)
                {
                    severity = Math.Max(severity, 7u);
                }
                else if (sample.EntropyBits >= MemoryHighEntropyBits || sample.EntropyFlipCount >= 3)
                {
                    severity = Math.Max(severity, 5u);
                }
            }

            if (sample.CrossProcess)
            {
                severity = Math.Max(severity, 7u);
            }
            if (sample.FunctionTableRegistered && sample.ProtectFlipCount != 0)
            {
                severity = Math.Max(severity, 7u);
            }

            return Math.Min(severity, 9u);
        }

        private static bool IsHookUnwindClean(uint flags)
        {
            return (flags & BlackbirdNative.IpcEtwFlagModuleChainSane) != 0 &&
                   (flags & BlackbirdNative.IpcEtwFlagUnwindMetadataValid) != 0 &&
                   (flags & BlackbirdNative.IpcEtwFlagTebStackBoundsValid) != 0 &&
                   (flags & BlackbirdNative.IpcEtwFlagFramesOutsideTebStack) == 0;
        }

        private static bool HookFrameChainHasGaps(uint flags)
        {
            return (flags & BlackbirdNative.IpcEtwFlagModuleChainSane) == 0 ||
                   (flags & BlackbirdNative.IpcEtwFlagFramesOutsideTebStack) != 0;
        }

        private static string InferRegionKind(BrokerEtwEventView view, uint protection)
        {
            if (view.Family == BlackbirdNative.IpcEtwFamilyImage)
            {
                return "Image";
            }

            if (view.EventName.Equals("NtAllocateVirtualMemory", StringComparison.OrdinalIgnoreCase) ||
                view.EventName.Equals("NtAllocateVirtualMemoryEx", StringComparison.OrdinalIgnoreCase))
            {
                return "Private";
            }

            if (view.EventName.Equals("NtMapViewOfSection", StringComparison.OrdinalIgnoreCase) ||
                view.EventName.Equals("NtMapViewOfSectionEx", StringComparison.OrdinalIgnoreCase))
            {
                return IsExecutableProtection(protection) ? "Mapped-Executable" : "Mapped";
            }

            return "Unknown";
        }

        private bool ShouldTrackRawIoctlRecord(IoctlParsedEvent record)
        {
            return record.Type switch { BlackbirdNative.EventTypeHandle => ShouldTrackRawHandleIoctl(record),
                                        BlackbirdNative.EventTypeThread => ShouldTrackRawThreadIoctl(record),
                                        BlackbirdNative.EventTypeFileSystem =>
                                            record.FileProcessPid == 0 || IsTrackedPid(record.FileProcessPid),
                                        BlackbirdNative.EventTypeRegistry =>
                                            record.RegistryProcessPid == 0 || IsTrackedPid(record.RegistryProcessPid),
                                        BlackbirdNative.EventTypeEnterprise =>
                                            record.EnterpriseProcessPid == 0 ||
                                            IsTrackedPid(record.EnterpriseProcessPid),
                                        _ => false };
        }

        private bool ShouldTrackRawHandleIoctl(IoctlParsedEvent record)
        {
            if (record.CallerPid == 0 || record.TargetPid == 0)
            {
                return false;
            }

            if (!IsTrackedPid(record.CallerPid))
            {
                return false;
            }

            string originModule = EventDetailFormatting.ModuleNameFromPath(record.OriginPath);
            return !EventDetailFormatting.IsSr71Module(originModule);
        }

        private bool ShouldTrackRawThreadIoctl(IoctlParsedEvent record)
        {
            if (record.ProcessPid == 0)
            {
                return false;
            }

            if (record.CreatorPid != 0 && record.CreatorPid != record.ProcessPid && !IsTrackedPid(record.CreatorPid))
            {
                return false;
            }

            return true;
        }

        private static bool ShouldAdmitIoctlRecord(IoctlParsedEvent record, long pendingCount)
        {
            if (pendingCount >= MaxPendingIoctlEvents)
            {
                return false;
            }

            if (pendingCount < IoctlPressureSoftLimit)
            {
                return true;
            }

            return pendingCount >= IoctlPressureCriticalLimit ? IsCriticalIoctlRecord(record)
                                                              : IsImportantIoctlRecord(record);
        }

        private static bool IsImportantIoctlRecord(IoctlParsedEvent record)
        {
            return record.Type switch { BlackbirdNative.EventTypeHandle => IsImportantHandleIoctl(record),
                                        BlackbirdNative.EventTypeThread => IsImportantThreadIoctl(record),
                                        BlackbirdNative.EventTypeFileSystem => IsImportantFilesystemIoctl(record),
                                        BlackbirdNative.EventTypeEnterprise => true,
                                        _ => false };
        }

        private static bool IsCriticalIoctlRecord(IoctlParsedEvent record)
        {
            return record.Type switch { BlackbirdNative.EventTypeHandle => IsCriticalHandleIoctl(record),
                                        BlackbirdNative.EventTypeThread => IsCriticalThreadIoctl(record),
                                        BlackbirdNative.EventTypeFileSystem => IsCriticalFilesystemIoctl(record),
                                        BlackbirdNative.EventTypeEnterprise =>
                                            (record.EnterpriseFlags & BlackbirdNative.EnterpriseFlagCritical) != 0,
                                        _ => false };
        }

        private static bool IsImportantHandleIoctl(IoctlParsedEvent record)
        {
            bool isThreadObject = (record.HandleFlags & 0x00000010u) != 0;
            return record.HandleClass == 2 || (record.HandleFlags & (HighSignalHandleMask | 0x00000080u)) != 0 ||
                   IsHighRiskIoctlAccess(record.DesiredAccess, isThreadObject);
        }

        private static bool IsCriticalHandleIoctl(IoctlParsedEvent record)
        {
            bool isThreadObject = (record.HandleFlags & 0x00000010u) != 0;
            return record.HandleClass == 2 || (record.HandleFlags & HighSignalHandleMask) != 0 ||
                   ((record.HandleFlags & 0x00000080u) != 0 &&
                    IsHighRiskIoctlAccess(record.DesiredAccess, isThreadObject));
        }

        private static bool IsImportantThreadIoctl(IoctlParsedEvent record)
        {
            string kind = DetermineThreadLifecycleKind(record.ThreadFlags, record.StartAddress, record.ImageSize);
            return kind != "Update" || (record.ThreadFlags & ThreadHighSignalMask) != 0 ||
                   (record.CreatorPid != 0 && record.ProcessPid != 0 && record.CreatorPid != record.ProcessPid);
        }

        private static bool IsCriticalThreadIoctl(IoctlParsedEvent record)
        {
            return (record.ThreadFlags & ThreadHighSignalMask) != 0 ||
                   (record.CreatorPid != 0 && record.ProcessPid != 0 && record.CreatorPid != record.ProcessPid);
        }

        private static bool IsImportantFilesystemIoctl(IoctlParsedEvent record)
        {
            return record.FileOperation switch {
                BlackbirdNative.FileOperationCreate or BlackbirdNative.FileOperationWrite or
                    BlackbirdNative.FileOperationSetInformation or
                        BlackbirdNative.FileOperationDirectoryControl or BlackbirdNative.FileOperationFsControl => true,
                _ => record.FileStatus != 0
            };
        }

        private static bool IsCriticalFilesystemIoctl(IoctlParsedEvent record)
        {
            return record.FileOperation switch {
                BlackbirdNative.FileOperationCreate or BlackbirdNative.FileOperationWrite or
                    BlackbirdNative.FileOperationSetInformation or BlackbirdNative.FileOperationFsControl => true,
                _ => record.FileStatus != 0
            };
        }

        private static bool ShouldPersistIoctlRecord(IoctlParsedEvent record, TelemetryEvent? telemetry,
                                                     ProcessRelationView? relation, HeuristicEventView? heuristic,
                                                     IoctlParsedEvent? filesystem)
        {
            if (filesystem != null || heuristic != null || relation != null)
            {
                return true;
            }

            if (telemetry == null)
            {
                return false;
            }

            return record.Type switch { BlackbirdNative.EventTypeHandle => IsImportantHandleIoctl(record),
                                        BlackbirdNative.EventTypeThread => IsImportantThreadIoctl(record),
                                        BlackbirdNative.EventTypeEnterprise => true,
                                        _ => false };
        }

        private bool IsTrackedPid(uint pid)
        {
            return pid == 0 || _filterTrackedPids.IsEmpty || _filterTrackedPids.ContainsKey(pid);
        }

        private static bool ShouldTrackRawEtwEvent(BlackbirdNative.BkIpcEtwEvent etw)
        {
            byte[] detectionName = etw.DetectionName ?? Array.Empty<byte>();
            if (detectionName.Length > 0 && detectionName[0] != 0)
            {
                return true;
            }

            if (IsRawDirectSyscallEtwEvent(etw))
            {
                return true;
            }

            if (etw.Severity >= 4)
            {
                return true;
            }

            if (etw.Source == BlackbirdNative.IpcEtwSourceThreatIntel)
            {
                return etw.Task == 1 || etw.Task == 2 || etw.Task == 7;
            }

            return etw.Family switch {
                BlackbirdNative.IpcEtwFamilyProcess => (etw.Flags & BlackbirdNative.IpcEtwFlagProcessIsCreate) != 0,
                BlackbirdNative.IpcEtwFamilyThread or BlackbirdNative.IpcEtwFamilyApc or
                    BlackbirdNative.IpcEtwFamilyUserHook or BlackbirdNative.IpcEtwFamilySocket => true,
                BlackbirdNative.IpcEtwFamilyRegistry => (etw.Flags & BlackbirdNative.IpcEtwFlagRegistryHighValue) != 0,
                _ => false
            };
        }

        private static bool IsRawDirectSyscallEtwEvent(BlackbirdNative.BkIpcEtwEvent etw)
        {
            if ((etw.DetectionTraits & BlackbirdNative.IpcEtwTraitDirectSyscall) != 0)
            {
                return true;
            }

            if (etw.Family != BlackbirdNative.IpcEtwFamilyHandle)
            {
                return false;
            }

            string className = BlackbirdNative.AnsiBufferToString(etw.ClassName);
            if (className.Equals("DIRECT-SYSCALL-SUSPECT", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            bool exportMismatch = (etw.Flags & HandleFlagSyscallExportMismatch) != 0;
            bool stackSpoof = (etw.Flags & HandleFlagStackSpoofSuspect) != 0;
            bool execOutsideNtdll = (etw.Flags & HandleFlagExecProtect) != 0 && (etw.Flags & HandleFlagFromNtdll) == 0;
            return exportMismatch || stackSpoof || execOutsideNtdll;
        }

        private static bool ShouldAdmitEtwEvent(BlackbirdNative.BkIpcEtwEvent etw, long pendingCount)
        {
            byte[] detectionName = etw.DetectionName ?? Array.Empty<byte>();

            if (pendingCount >= MaxPendingEtwEvents)
            {
                return false;
            }

            if (pendingCount < EtwPressureSoftLimit)
            {
                return true;
            }

            bool critical = (detectionName.Length > 0 && detectionName[0] != 0) || etw.Severity >= 6 ||
                            IsRawDirectSyscallEtwEvent(etw) ||
                            (etw.Family == BlackbirdNative.IpcEtwFamilyProcess &&
                             (etw.Flags & BlackbirdNative.IpcEtwFlagProcessIsCreate) != 0) ||
                            etw.Family == BlackbirdNative.IpcEtwFamilyUserHook;

            if (pendingCount >= EtwPressureCriticalLimit)
            {
                return critical;
            }

            return critical || etw.Family == BlackbirdNative.IpcEtwFamilyThread ||
                   etw.Family == BlackbirdNative.IpcEtwFamilyApc ||
                   etw.Source == BlackbirdNative.IpcEtwSourceThreatIntel;
        }

        private string BuildEtwDisplayDetail(BrokerEtwEventView view)
        {
            string rawReason = view.Reason ?? string.Empty;
            if (EventDetailFormatting.IsApiGraphCandidate(view))
            {
                return BuildApiDecodedAction(view, rawReason).Detail;
            }

            return BuildGenericEtwDisplayDetail(view, BuildHookFieldMap(view), includeHeadline: true);
        }

        private string BuildFallbackApiDetail(string apiName, BrokerEtwEventView view, string rawReason, string action)
        {
            Dictionary<string, string> fields = BuildHookFieldMap(rawReason, Array.Empty<ulong>(), 0);
            string argumentText = BuildResolvedHookArgumentsText(apiName, view, fields);
            if (string.IsNullOrWhiteSpace(argumentText))
            {
                return action;
            }

            return $"{action}{Environment.NewLine}{Environment.NewLine}{argumentText}";
        }

        private string BuildGenericEtwDisplayDetail(BrokerEtwEventView view, IReadOnlyDictionary<string, string> fields,
                                                    bool includeHeadline)
        {
            var sb = new StringBuilder(512);
            string eventName = string.IsNullOrWhiteSpace(view.EventName) ? "unknown" : view.EventName.Trim();
            string detection = view.DetectionName?.Trim() ?? string.Empty;
            string operation = view.Operation?.Trim() ?? string.Empty;
            string actor = ProcessIdentityResolver.Describe(view.ActorPid);
            string target = ProcessIdentityResolver.Describe(view.TargetPid);

            if (includeHeadline)
            {
                sb.AppendLine(!string.IsNullOrWhiteSpace(detection) ? detection : eventName);
            }

            if (!string.IsNullOrWhiteSpace(view.Source))
            {
                sb.Append("Source: ").AppendLine(view.Source);
            }

            sb.Append("Event: ").AppendLine(eventName);
            if (!string.IsNullOrWhiteSpace(operation) &&
                !operation.Equals(eventName, StringComparison.OrdinalIgnoreCase))
            {
                sb.Append("Operation: ").AppendLine(operation);
            }

            if (!string.IsNullOrWhiteSpace(detection))
            {
                sb.Append("Detection: ").AppendLine(detection);
            }

            if (view.ActorPid != 0)
            {
                sb.Append("Actor: ").AppendLine(actor);
            }

            if (view.TargetPid != 0)
            {
                sb.Append("Target: ").AppendLine(target);
            }

            if (!string.IsNullOrWhiteSpace(view.ArgumentSummary))
            {
                sb.Append("Arguments: ").AppendLine(view.ArgumentSummary);
            }

            string frameSummary = BuildHookFrameSummary(view, fields);
            if (!string.IsNullOrWhiteSpace(frameSummary))
            {
                sb.AppendLine(frameSummary);
            }

            if (includeHeadline &&
                TryDescribeHookExecutionContext(view, fields, out string executionHeadline, out string executionDetail))
            {
                sb.Append(executionHeadline).Append(": ").AppendLine(executionDetail);
            }

            if (!string.IsNullOrWhiteSpace(view.ClassName))
            {
                sb.Append("Class: ").AppendLine(view.ClassName);
            }

            if (view.DesiredAccess != 0)
            {
                sb.Append("DesiredAccess: 0x")
                    .Append(view.DesiredAccess.ToString("X8", CultureInfo.InvariantCulture))
                    .AppendLine();
            }

            if (view.CorrelationFlags != 0)
            {
                sb.Append("CorrelationFlags: ")
                    .Append(EventDetailFormatting.DescribeCorrelationFlags(view.CorrelationFlags))
                    .Append(" (0x")
                    .Append(view.CorrelationFlags.ToString("X8", CultureInfo.InvariantCulture))
                    .AppendLine(")");
            }

            if (view.CorrelationAccessMask != 0)
            {
                sb.Append("CorrelationAccess: ")
                    .Append(EventDetailFormatting.DescribeHandleAccess(view.CorrelationAccessMask))
                    .Append(" (0x")
                    .Append(view.CorrelationAccessMask.ToString("X8", CultureInfo.InvariantCulture))
                    .AppendLine(")");
            }

            if (view.CorrelationAgeMs != 0)
            {
                sb.Append("CorrelationAgeMs: ")
                    .Append(view.CorrelationAgeMs.ToString(CultureInfo.InvariantCulture))
                    .AppendLine();
            }

            if (!string.IsNullOrWhiteSpace(view.ImagePath))
            {
                sb.Append("ImagePath: ").AppendLine(view.ImagePath);
            }

            if (!string.IsNullOrWhiteSpace(view.OriginPath))
            {
                sb.Append("OriginPath: ").AppendLine(view.OriginPath);
            }

            if (!string.IsNullOrWhiteSpace(view.KeyPath))
            {
                sb.Append("KeyPath: ").AppendLine(view.KeyPath);
            }

            if (!string.IsNullOrWhiteSpace(view.ValueName))
            {
                sb.Append("ValueName: ").AppendLine(view.ValueName);
            }

            if (fields.TryGetValue("status", out string? status) && !string.IsNullOrWhiteSpace(status))
            {
                sb.Append("Status: ").AppendLine(status);
            }

            return sb.ToString().Trim();
        }

        private string GetApiGraphProcessName(uint pid)
        {
            if (pid == 0)
            {
                return string.Empty;
            }

            if (_currentSession != null && _currentSession.Pid == unchecked((int)pid))
            {
                return ExtractProcessName(_currentSession.Title);
            }

            ProcessSessionTab? knownTab = _processTabs.FirstOrDefault(x => x.Pid == unchecked((int)pid));
            if (knownTab != null)
            {
                string knownName = ExtractProcessName(knownTab.Title);
                if (!string.IsNullOrWhiteSpace(knownName))
                {
                    return knownName;
                }
            }

            try
            {
                using Process process = Process.GetProcessById(unchecked((int)pid));
                return process.ProcessName;
            }
            catch
            {
                return string.Empty;
            }
        }

        private static string ExtractProcessName(string? title)
        {
            if (string.IsNullOrWhiteSpace(title))
            {
                return string.Empty;
            }

            string trimmed = title.Trim();
            int suffixIndex = trimmed.LastIndexOf(" (", StringComparison.Ordinal);
            if (suffixIndex > 0 && trimmed.EndsWith(")", StringComparison.Ordinal))
            {
                return trimmed[..suffixIndex].Trim();
            }

            return trimmed;
        }

        private (string ActionSuffix, string DetailText) DescribeMemoryContextFromPages(ulong baseAddress)
        {
            PerformanceSample? latestSample =
                _currentSession?.PerformanceHistory.Count > 0 ? _currentSession.PerformanceHistory[^1] : null;
            MemoryPageSample? page = latestSample?.MemoryPages.FirstOrDefault(
                x => baseAddress >= x.BaseAddress && baseAddress < (x.BaseAddress + x.RegionSize));
            if (page == null)
            {
                return (string.Empty, string.Empty);
            }

            string suffix = string.IsNullOrWhiteSpace(page.Category) ? string.Empty
                                                                     : $" in {page.Category.ToLowerInvariant()} region";
            string detail = $"Region: {page.Category} | Protect: {page.ProtectLabel} | Type: {page.TypeLabel}\n";
            return (suffix, detail);
        }

        private string DescribeMemoryImageContext(BrokerEtwEventView view, ulong baseAddress)
        {
            if (view.ImageBase == 0 || view.ImageSize == 0)
            {
                return string.Empty;
            }

            ulong imageEnd = view.ImageBase + view.ImageSize;
            if (baseAddress < view.ImageBase || baseAddress >= imageEnd)
            {
                return string.Empty;
            }

            string moduleName = EventDetailFormatting.ModuleNameFromPath(view.ImagePath);
            if (string.IsNullOrWhiteSpace(moduleName))
            {
                moduleName = "image";
            }

            string imagePathLine =
                string.IsNullOrWhiteSpace(view.ImagePath) ? string.Empty : $"ImagePath: {view.ImagePath}\n";
            return $"Image: {moduleName}\n" + imagePathLine + $"ImageBase: 0x{view.ImageBase:X}\n" +
                   $"ImageSize: 0x{view.ImageSize:X}\n";
        }

        private (string ActionSuffix, string DetailText)
            DescribeMemoryRegionContext(BrokerEtwEventView view, ulong baseAddress, ulong regionSize)
        {
            if (baseAddress == 0)
            {
                return (string.Empty, string.Empty);
            }

            string imageContext = DescribeMemoryImageContext(view, baseAddress);
            if (!string.IsNullOrWhiteSpace(imageContext))
            {
                string moduleName = EventDetailFormatting.ModuleNameFromPath(view.ImagePath);
                string suffix = string.IsNullOrWhiteSpace(moduleName) ? string.Empty : $" in image {moduleName}";
                return (suffix, imageContext);
            }

            (string pageActionSuffix, string pageContext) = DescribeMemoryContextFromPages(baseAddress);
            if (!string.IsNullOrWhiteSpace(pageContext))
            {
                return (pageActionSuffix, pageContext);
            }

            if (view.DeepRegionType != 0 || view.DeepRegionProtect != 0 || regionSize != 0)
            {
                string typeLabel = EventDetailFormatting.DescribeMemoryType(
                    view.DeepRegionType != 0 ? view.DeepRegionType : view.StartRegionType);
                string protectLabel = EventDetailFormatting.DescribeMemoryProtection(
                    view.DeepRegionProtect != 0 ? view.DeepRegionProtect : view.StartRegionProtect);
                string detailText = string.Empty;
                if (!string.IsNullOrWhiteSpace(typeLabel))
                {
                    detailText += $"RegionType: {typeLabel}\n";
                }
                if (!string.IsNullOrWhiteSpace(protectLabel))
                {
                    detailText += $"RegionProtect: {protectLabel}\n";
                }
                return (string.Empty, detailText);
            }

            return (string.Empty, string.Empty);
        }

        private ApiMemoryPageSignal GetOrCreateApiMemoryPageSignal(ulong page)
        {
            if (!_apiMemorySignalsByPage.TryGetValue(page, out ApiMemoryPageSignal? state))
            {
                state = new ApiMemoryPageSignal();
                _apiMemorySignalsByPage[page] = state;
            }

            return state;
        }

        private static Dictionary<string, string> ParseReasonFields(string rawReason)
        {
            return EventDetailsParsing.ParseRawFields(rawReason);
        }

        private static Dictionary<string, string> BuildHookFieldMap(string rawReason, IReadOnlyList<ulong>? hookArgs,
                                                                    uint hookArgCount)
        {
            Dictionary<string, string> fields = ParseReasonFields(rawReason);
            int count = Math.Min((int)hookArgCount, hookArgs?.Count ?? 0);
            for (int i = 0; i < count; i += 1)
            {
                string key = $"a{i}";
                if (!fields.ContainsKey(key))
                {
                    fields[key] = $"0x{hookArgs![i]:X}";
                }
            }

            return fields;
        }

        private static Dictionary<string, string>
        BuildHookFieldMap(BrokerEtwEventView view) => view.GetOrCreateHookFieldMap();

        private static bool
        IsHookKernelCaller(BrokerEtwEventView view) => (view.Flags & BlackbirdNative.IpcEtwFlagHookKernelCaller) != 0;

        private static bool IsHookCurrentProcessTarget(BrokerEtwEventView view)
        {
            if ((view.Flags & BlackbirdNative.IpcEtwFlagHookTargetCurrentProcess) != 0)
            {
                return true;
            }

            uint processPid = view.ProcessPid != 0 ? view.ProcessPid : view.ActorPid;
            return processPid != 0 && (view.TargetPid == 0 || view.TargetPid == processPid);
        }

        private static bool
        IsHookImageSection(BrokerEtwEventView view) => (view.Flags & BlackbirdNative.IpcEtwFlagHookSectionImage) != 0;

        private bool TryDescribeHookExecutionContext(BrokerEtwEventView view,
                                                     IReadOnlyDictionary<string, string> fields, out string headline,
                                                     out string detail)
        {
            headline = string.Empty;
            detail = string.Empty;

            if (!EventDetailFormatting.IsApiGraphCandidate(view))
            {
                return false;
            }

            string apiName = string.IsNullOrWhiteSpace(view.Operation) ? view.EventName : view.Operation;
            bool kernelCaller = IsHookKernelCaller(view);
            bool currentTarget = IsHookCurrentProcessTarget(view);
            bool imageSection = IsHookImageSection(view);

            if (kernelCaller)
            {
                headline = "Kernel Caller";
                detail =
                    "ExecutionContext: this hook fired on a KernelMode caller path. Treat the call as kernel-originated activity or loader/manager plumbing, not a normal user thread directly invoking the API.";
                return true;
            }

            if ((apiName.Equals("NtCreateSection", StringComparison.OrdinalIgnoreCase) ||
                 apiName.Equals("NtMapViewOfSection", StringComparison.OrdinalIgnoreCase)) &&
                currentTarget && imageSection)
            {
                headline = "Loader / Image Mapping";
                detail =
                    "ExecutionContext: image-backed section creation or mapping into the current process. This is commonly loader-style PE/DLL mapping and should be separated from private-memory execution or post-start runtime tampering.";
                return true;
            }

            if (TryDescribeHookStartupContext(view, out string startupHeadline, out string startupDetail))
            {
                headline = startupHeadline;
                detail = startupDetail;
                return true;
            }

            if (!currentTarget && view.TargetPid != 0)
            {
                headline = "Cross-Process Runtime";
                detail =
                    $"ExecutionContext: the API targets another process ({ProcessIdentityResolver.Describe(view.TargetPid)}). This is actual runtime cross-process activity, not local loader setup.";
                return true;
            }

            headline = "User Runtime";
            detail = "ExecutionContext: user-mode call path against the current process outside the startup window.";
            return true;
        }

        private string BuildResolvedHookArgumentsText(string apiName, BrokerEtwEventView view,
                                                      IReadOnlyDictionary<string, string> fields)
        {
            List<(string Name, string Value)> args = ResolveHookArguments(apiName, view, fields);
            if (args.Count == 0)
            {
                return string.Empty;
            }

            var sb = new StringBuilder(256);
            sb.AppendLine("Arguments:");
            for (int i = 0; i < args.Count; i += 1)
            {
                sb.Append("  ").Append(args[i].Name).Append(": ").AppendLine(args[i].Value);
            }

            return sb.ToString().TrimEnd();
        }

        private List<(string Name, string Value)> ResolveHookArguments(string apiName, BrokerEtwEventView view,
                                                                       IReadOnlyDictionary<string, string> fields)
        {
            string name = apiName?.Trim() ?? string.Empty;
            var args = new List<(string Name, string Value)>(8);

            switch (name)
            {
            case "NtWriteVirtualMemory":
                AddResolvedArg(args, "ProcessHandle", ResolvePointer(view, fields, "a0", "c0"));
                AddResolvedArg(args, "BaseAddress", ResolvePointer(view, fields, "a1", "c1", "base"));
                AddResolvedArg(args, "Buffer", ResolvePointer(view, fields, "a2", "c2"));
                AddResolvedArg(args, "BufferSize", ResolveSize(fields, "a3", "c3", "size"));
                AddResolvedArg(args, "BytesWritten", ResolvePointer(view, fields, "a4", "c4"));
                break;
            case "NtReadVirtualMemory":
                AddResolvedArg(args, "ProcessHandle", ResolvePointer(view, fields, "a0", "c0"));
                AddResolvedArg(args, "BaseAddress", ResolvePointer(view, fields, "a1", "c1", "base"));
                AddResolvedArg(args, "Buffer", ResolvePointer(view, fields, "a2", "c2"));
                AddResolvedArg(args, "BufferSize", ResolveSize(fields, "a3", "c3", "size"));
                AddResolvedArg(args, "BytesRead", ResolvePointer(view, fields, "a4", "c4"));
                break;
            case "NtAllocateVirtualMemory":
                AddResolvedArg(args, "ProcessHandle", ResolvePointer(view, fields, "a0", "c0"));
                AddResolvedArg(args, "BaseAddress*", ResolvePointer(view, fields, "a1", "c1", "base"));
                AddResolvedArg(args, "ZeroBits", ResolveHex(fields, "a2", "c2"));
                AddResolvedArg(args, "RegionSize*", ResolveSize(fields, "a3", "c3", "size"));
                AddResolvedArg(args, "AllocationType", ResolveAllocationType(fields, "a4", "c4", "allocType"));
                AddResolvedArg(args, "Protect", ResolveProtect(fields, "a5", "c5", "protect"));
                break;
            case "NtAllocateVirtualMemoryEx":
                AddResolvedArg(args, "ProcessHandle", ResolvePointer(view, fields, "a0", "c0"));
                AddResolvedArg(args, "BaseAddress*", ResolvePointer(view, fields, "a1", "c1", "base"));
                AddResolvedArg(args, "ZeroBits", ResolveHex(fields, "a2", "c2"));
                AddResolvedArg(args, "RegionSize*", ResolveSize(fields, "a3", "c3", "size"));
                AddResolvedArg(args, "AllocationType", ResolveAllocationType(fields, "a4", "c4", "allocType"));
                AddResolvedArg(args, "ExtendedParameters", ResolvePointer(view, fields, "a5", "c5"));
                AddResolvedArg(args, "ExtendedParameterCount", ResolveHex(fields, "a6", "c6"));
                break;
            case "NtProtectVirtualMemory":
                AddResolvedArg(args, "ProcessHandle", ResolvePointer(view, fields, "a0", "c0"));
                AddResolvedArg(args, "BaseAddress*", ResolvePointer(view, fields, "a1", "c1", "base"));
                AddResolvedArg(args, "RegionSize*", ResolveSize(fields, "a2", "c2", "size"));
                AddResolvedArg(args, "NewProtect", ResolveProtect(fields, "a3", "c3", "newProtect"));
                AddResolvedArg(args, "OldProtect*", ResolvePointer(view, fields, "a4", "c4"));
                break;
            case "NtCreateSection":
                AddResolvedArg(args, "SectionHandle*", ResolvePointer(view, fields, "a0", "c0"));
                AddResolvedArg(args, "DesiredAccess", ResolveHex(fields, "a1", "c1"));
                AddResolvedArg(args, "ObjectAttributes", ResolvePointer(view, fields, "a2", "c2"));
                AddResolvedArg(args, "MaximumSize", ResolveSize(fields, "a3", "c3"));
                AddResolvedArg(args, "SectionPageProtection", ResolveProtect(fields, "a4", "c4"));
                AddResolvedArg(args, "AllocationAttributes", ResolveHex(fields, "a5", "c5"));
                AddResolvedArg(args, "FileHandle", ResolvePointer(view, fields, "a6", "c6"));
                break;
            case "NtMapViewOfSection":
                AddResolvedArg(args, "SectionHandle", ResolvePointer(view, fields, "a0", "c0"));
                AddResolvedArg(args, "ProcessHandle", ResolvePointer(view, fields, "a1", "c1"));
                AddResolvedArg(args, "BaseAddress*", ResolvePointer(view, fields, "a2", "c2", "base"));
                AddResolvedArg(args, "ViewSize*", ResolveSize(fields, "a6", "c3", "size"));
                AddResolvedArg(args, "InheritDisposition", ResolveHex(fields, "a7", "c4"));
                AddResolvedArg(args, "AllocationType", ResolveAllocationType(fields, "c5"));
                AddResolvedArg(args, "Win32Protect", ResolveProtect(fields, "c6"));
                break;
            case "NtMapViewOfSectionEx":
                AddResolvedArg(args, "SectionHandle", ResolvePointer(view, fields, "a0", "c0"));
                AddResolvedArg(args, "ProcessHandle", ResolvePointer(view, fields, "a1", "c1"));
                AddResolvedArg(args, "BaseAddress*", ResolvePointer(view, fields, "a2", "c2", "base"));
                AddResolvedArg(args, "SectionOffset*", ResolvePointer(view, fields, "a3", "c7"));
                AddResolvedArg(args, "ViewSize*", ResolveSize(fields, "a4", "c3", "size"));
                AddResolvedArg(args, "AllocationType", ResolveAllocationType(fields, "a5", "c4"));
                AddResolvedArg(args, "Win32Protect", ResolveProtect(fields, "a6", "c5"));
                AddResolvedArg(args, "ExtendedParameters", ResolvePointer(view, fields, "a7", "c6"));
                break;
            case "NtQueryInformationProcess":
                AddResolvedArg(args, "ProcessHandle", ResolvePointer(view, fields, "a0", "c0"));
                AddResolvedArg(args, "ProcessInformationClass", ResolveProcessInformationClass(fields, "a1", "c1"));
                AddResolvedArg(args, "ProcessInformation", ResolvePointer(view, fields, "a2", "c2"));
                AddResolvedArg(args, "ProcessInformationLength", ResolveSize(fields, "a3", "c3"));
                AddResolvedArg(args, "ReturnLength", ResolvePointer(view, fields, "a4", "c4"));
                break;
            case "NtQueryInformationThread":
                AddResolvedArg(args, "ThreadHandle", ResolvePointer(view, fields, "a0", "c0"));
                AddResolvedArg(args, "ThreadInformationClass", ResolveHex(fields, "a1", "c1"));
                AddResolvedArg(args, "ThreadInformation", ResolvePointer(view, fields, "a2", "c2"));
                AddResolvedArg(args, "ThreadInformationLength", ResolveSize(fields, "a3", "c3"));
                AddResolvedArg(args, "ReturnLength", ResolvePointer(view, fields, "a4", "c4"));
                break;
            case "NtQuerySystemInformation":
            case "NtQuerySystemInformationEx":
                AddResolvedArg(args, "SystemInformationClass", ResolveSystemInformationClass(fields, "a0", "c0"));
                AddResolvedArg(args, "InputBuffer", ResolvePointer(view, fields, "a1", "c1"));
                AddResolvedArg(args, "InputBufferLength", ResolveSize(fields, "a2", "c2"));
                AddResolvedArg(args, "SystemInformation", ResolvePointer(view, fields, "a3", "c3"));
                AddResolvedArg(args, "SystemInformationLength", ResolveSize(fields, "a4", "c4"));
                AddResolvedArg(args, "ReturnLength", ResolvePointer(view, fields, "a5", "c5"));
                break;
            case "NtQueryPerformanceCounter":
                AddResolvedArg(args, "RawCounter", ResolveHex(fields, "rawCounter", "a0", "c0"));
                AddResolvedArg(args, "VirtualCounter", ResolveHex(fields, "virtualCounter", "a1", "c1"));
                AddResolvedArg(args, "RawDelta", ResolveHex(fields, "rawDelta", "a2", "c2"));
                AddResolvedArg(args, "VirtualDelta", ResolveHex(fields, "virtualDelta", "a3", "c3"));
                AddResolvedArg(args, "CorrectionTicks", ResolveHex(fields, "correctionTicks", "a4", "c4"));
                AddResolvedArg(args, "SourceFlags", ResolveHex(fields, "sourceFlags", "a5", "c5"));
                AddResolvedArg(args, "AutoBiasTicks", ResolveHex(fields, "autoBiasTicks", "a6", "c6"));
                break;
            case "NtCreateThreadEx":
                AddResolvedArg(args, "ThreadHandle*", ResolvePointer(view, fields, "a0", "c0"));
                AddResolvedArg(args, "DesiredAccess", ResolveHex(fields, "a1", "c1"));
                AddResolvedArg(args, "ProcessHandle", ResolvePointer(view, fields, "a2", "c2"));
                AddResolvedArg(args, "StartRoutine", ResolvePointer(view, fields, "a3", "c3"));
                AddResolvedArg(args, "Argument", ResolvePointer(view, fields, "a4", "c4"));
                AddResolvedArg(args, "CreateFlags", ResolveHex(fields, "a5", "c5"));
                AddResolvedArg(args, "StackSize", ResolveSize(fields, "a6", "c6"));
                AddResolvedArg(args, "MaximumStackSize", ResolveSize(fields, "a7", "c7"));
                break;
            case "RtlAddFunctionTable":
                AddResolvedArg(args, "FunctionTable", ResolvePointer(view, fields, "a0"));
                AddResolvedArg(args, "EntryCount", ResolveHex(fields, "a1"));
                AddResolvedArg(args, "BaseAddress", ResolvePointer(view, fields, "a2", "baseAddress"));
                break;
            case "RtlInstallFunctionTableCallback":
                AddResolvedArg(args, "TableIdentifier", ResolvePointer(view, fields, "a0"));
                AddResolvedArg(args, "BaseAddress", ResolvePointer(view, fields, "a1", "baseAddress"));
                AddResolvedArg(args, "Length", ResolveSize(fields, "a2", "length"));
                AddResolvedArg(args, "Callback", ResolvePointer(view, fields, "a3", "callback"));
                break;
            case "RtlDeleteFunctionTable":
                AddResolvedArg(args, "FunctionTable", ResolvePointer(view, fields, "a0", "table"));
                break;
            default:
                for (int i = 0; i < 8; i += 1)
                {
                    string value = ResolvePointer(view, fields, $"a{i}", $"c{i}");
                    AddResolvedArg(args, $"Arg{i}", value);
                }
                break;
            }

            return args;
        }

        private static void AddResolvedArg(List<(string Name, string Value)> args, string name, string? value)
        {
            if (!string.IsNullOrWhiteSpace(value))
            {
                args.Add((name, value));
            }
        }

        private string ResolvePointer(BrokerEtwEventView view, IReadOnlyDictionary<string, string> fields,
                                      params string[] keys)
        {
            ulong value = FirstU64(fields, keys);
            return value == 0 ? string.Empty : FormatObservedPointer(view, value);
        }

        private static string ResolveSize(IReadOnlyDictionary<string, string> fields, params string[] keys)
        {
            ulong value = FirstU64(fields, keys);
            return value == 0 ? string.Empty : $"0x{value:X}";
        }

        private static string ResolveHex(IReadOnlyDictionary<string, string> fields, params string[] keys)
        {
            ulong value = FirstU64(fields, keys);
            return value == 0 ? string.Empty : $"0x{value:X}";
        }

        private static string ResolveProtect(IReadOnlyDictionary<string, string> fields, params string[] keys)
        {
            uint value = (uint)FirstU64(fields, keys);
            return value == 0 ? string.Empty : $"0x{value:X} ({DescribeMemoryProtect(value)})";
        }

        private static string ResolveAllocationType(IReadOnlyDictionary<string, string> fields, params string[] keys)
        {
            uint value = (uint)FirstU64(fields, keys);
            return value == 0 ? string.Empty : $"0x{value:X} ({DescribeMemoryAllocationType(value)})";
        }

        private static string ResolveProcessInformationClass(IReadOnlyDictionary<string, string> fields,
                                                             params string[] keys)
        {
            uint value = (uint)FirstU64(fields, keys);
            if (value == 0)
            {
                return string.Empty;
            }

            string label = value switch {
                0 => "ProcessBasicInformation",
                7 => "ProcessDebugPort",
                26 => "ProcessWow64Information",
                27 => "ProcessImageFileName",
                29 => "ProcessBreakOnTermination",
                30 => "ProcessDebugObjectHandle",
                31 => "ProcessDebugFlags",
                43 => "ProcessImageFileNameWin32",
                _ => "Unknown"
            };

            return $"0x{value:X} ({label})";
        }

        private static string ResolveSystemInformationClass(IReadOnlyDictionary<string, string> fields,
                                                            params string[] keys)
        {
            uint value = (uint)FirstU64(fields, keys);
            if (value == 0)
            {
                return string.Empty;
            }

            string label = value switch {
                5 => "SystemProcessInformation",
                11 => "SystemModuleInformation",
                35 => "SystemKernelDebuggerInformation",
                76 => "SystemFirmwareTableInformation",
                103 => "SystemCodeIntegrityInformation",
                _ => "Unknown"
            };

            return $"0x{value:X} ({label})";
        }

        private static string BuildGenericApiActionLabel(string apiName, IReadOnlyDictionary<string, string> fields)
        {
            if (apiName.Equals("NtCreateThreadEx", StringComparison.OrdinalIgnoreCase))
            {
                ulong startAddress = FirstU64(fields, "a3", "c3");
                ulong targetHandle = FirstU64(fields, "a2", "c0");
                return $"Creates thread (start 0x{startAddress:X}) via target handle 0x{targetHandle:X}";
            }

            if (apiName.Equals("NtWriteVirtualMemory", StringComparison.OrdinalIgnoreCase))
            {
                ulong address = FirstU64(fields, "a1", "c0");
                ulong size = FirstU64(fields, "a3", "c1");
                return $"Writes 0x{size:X} bytes into virtual memory at 0x{address:X}";
            }

            if (apiName.Equals("NtReadVirtualMemory", StringComparison.OrdinalIgnoreCase))
            {
                ulong address = FirstU64(fields, "a1", "c0");
                ulong size = FirstU64(fields, "a3", "c1");
                return $"Reads 0x{size:X} bytes from virtual memory at 0x{address:X}";
            }

            if (apiName.Equals("RtlAddFunctionTable", StringComparison.OrdinalIgnoreCase) ||
                apiName.Equals("RtlInstallFunctionTableCallback", StringComparison.OrdinalIgnoreCase))
            {
                ulong baseAddress = FirstU64(fields, "baseAddress", "a2", "a1");
                return $"Registers unwind metadata for region near 0x{baseAddress:X}";
            }

            if (apiName.Equals("RtlDeleteFunctionTable", StringComparison.OrdinalIgnoreCase))
            {
                ulong table = FirstU64(fields, "table", "a0");
                return $"Deletes dynamic unwind metadata table 0x{table:X}";
            }

            if (apiName.Equals("WSASend", StringComparison.OrdinalIgnoreCase) ||
                apiName.Equals("send", StringComparison.OrdinalIgnoreCase))
            {
                return "Sends network payload";
            }

            if (apiName.Equals("WSARecv", StringComparison.OrdinalIgnoreCase) ||
                apiName.Equals("recv", StringComparison.OrdinalIgnoreCase))
            {
                return "Receives network payload";
            }

            if (fields.TryGetValue("kind", out string? kind) && !string.IsNullOrWhiteSpace(kind))
            {
                return $"{kind} call: {apiName}";
            }

            return apiName;
        }

        private static ulong FirstU64(IReadOnlyDictionary<string, string> fields, params string[] keys)
        {
            foreach (string key in keys)
            {
                if (fields.TryGetValue(key, out string? value) && TryReadU64(value, out ulong parsed))
                {
                    return parsed;
                }
            }

            return 0;
        }

        private static bool TryReadU64(string? text, out ulong value)
        {
            value = 0;
            if (string.IsNullOrWhiteSpace(text))
            {
                return false;
            }

            string compact = text.Trim();
            if (compact.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            {
                return ulong.TryParse(compact[2..], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out value);
            }

            return ulong.TryParse(compact, NumberStyles.Integer, CultureInfo.InvariantCulture, out value);
        }

        private static bool TryReadDouble(IReadOnlyDictionary<string, string> fields, out double value,
                                          params string[] keys)
        {
            foreach (string key in keys)
            {
                if (fields.TryGetValue(key, out string? text) &&
                    double.TryParse(text, NumberStyles.Float, CultureInfo.InvariantCulture, out value))
                {
                    return true;
                }
            }

            value = 0;
            return false;
        }

        private static string DescribeMemoryProtect(uint protect)
        {
            return EventDetailFormatting.DescribeMemoryProtection(protect);
        }

        private static string DescribeMemoryAllocationType(uint allocType)
        {
            var labels = new List<string>(4);
            if ((allocType & 0x1000) != 0)
            {
                labels.Add("MEM_COMMIT");
            }
            if ((allocType & 0x2000) != 0)
            {
                labels.Add("MEM_RESERVE");
            }
            if ((allocType & 0x1000000) != 0)
            {
                labels.Add("MEM_LARGE_PAGES");
            }
            if ((allocType & 0x20000) != 0)
            {
                labels.Add("MEM_PHYSICAL");
            }

            return labels.Count == 0 ? "<none>" : string.Join(" | ", labels);
        }

        private static double ComputeSampleEntropyBits(byte[]? data, int length)
        {
            if (data == null || data.Length == 0 || length <= 1)
            {
                return -1;
            }

            int sampleLength = Math.Min(length, data.Length);
            Span<int> counts = stackalloc int[256];
            for (int i = 0; i < sampleLength; i += 1)
            {
                counts[data[i]] += 1;
            }

            double entropy = 0;
            for (int i = 0; i < counts.Length; i += 1)
            {
                int count = counts[i];
                if (count == 0)
                {
                    continue;
                }

                double p = count / (double)sampleLength;
                entropy -= p * Math.Log(p, 2.0);
            }

            return entropy;
        }

        private sealed class ApiMemoryPageSignal
        {
            public uint Protect { get; set; }
            public int ProtectFlipCount { get; set; }
            public double LastEntropyBits { get; set; } = double.NaN;
            public int EntropyFlipCount { get; set; }
            public DateTime LastProtectChangeUtc { get; set; }
            public DateTime LastEntropyChangeUtc { get; set; }
        }

        private sealed class RecentImageFileAccess
        {
            public DateTime TimestampUtc { get; init; }
            public uint Pid { get; init; }
            public uint Tid { get; init; }
            public uint Operation { get; init; }
            public string Path { get; init; } = string.Empty;
            public string FileName { get; init; } = string.Empty;
        }

        private sealed class RecentImageMapState
        {
            public DateTime FirstSeenUtc { get; set; }
            public DateTime LastSeenUtc { get; set; }
            public string Path { get; set; } = string.Empty;
            public string LastApi { get; set; } = string.Empty;
            public int Count { get; set; }
            public RecentImageFileAccess? LastLinkedFileAccess { get; set; }

            public RecentImageMapState Clone() => new() { FirstSeenUtc = FirstSeenUtc,
                                                          LastSeenUtc = LastSeenUtc,
                                                          Path = Path,
                                                          LastApi = LastApi,
                                                          Count = Count,
                                                          LastLinkedFileAccess = LastLinkedFileAccess };
        }

        private readonly struct ApiCallStructuredFields
        {
            internal string Action { get; init; }
            internal string Field1Label { get; init; }
            internal string Field2Label { get; init; }
            internal string Field3Label { get; init; }
            internal string Field4Label { get; init; }
            internal string Field1Value { get; init; }
            internal string Field2Value { get; init; }
            internal string Field3Value { get; init; }
            internal string Field4Value { get; init; }
        }

        private enum BackendUiWorkKind
        {
            Ioctl,
            Etw,
            Status
        }

        private readonly struct BackendUiWorkItem
        {
            internal BackendUiWorkKind Kind { get; }
            internal TelemetryEvent? Telemetry { get; }
            internal ProcessRelationView? Relation { get; }
            internal HeuristicEventView? Heuristic { get; }
            internal ThreadLifecycleEventSample? ThreadLifecycle { get; }
            internal IoctlParsedEvent? Filesystem { get; }
            internal IoctlParsedEvent? Registry { get; }
            internal BrokerEtwEventView? EtwView { get; }
            internal string? StatusLine { get; }

            private BackendUiWorkItem(BackendUiWorkKind kind, TelemetryEvent? telemetry, ProcessRelationView? relation,
                                      HeuristicEventView? heuristic, ThreadLifecycleEventSample? threadLifecycle,
                                      IoctlParsedEvent? filesystem, IoctlParsedEvent? registry,
                                      BrokerEtwEventView? etwView, string? statusLine)
            {
                Kind = kind;
                Telemetry = telemetry;
                Relation = relation;
                Heuristic = heuristic;
                ThreadLifecycle = threadLifecycle;
                Filesystem = filesystem;
                Registry = registry;
                EtwView = etwView;
                StatusLine = statusLine;
            }

            internal static BackendUiWorkItem
                FromIoctl(TelemetryEvent? telemetry, ProcessRelationView? relation, HeuristicEventView? heuristic,
                          ThreadLifecycleEventSample? threadLifecycle, IoctlParsedEvent? filesystem,
                          IoctlParsedEvent? registry = null) => new(BackendUiWorkKind.Ioctl, telemetry, relation,
                                                                    heuristic, threadLifecycle, filesystem, registry,
                                                                    null, null);

            internal static BackendUiWorkItem FromEtw(BrokerEtwEventView etwView) => new(BackendUiWorkKind.Etw, null,
                                                                                         null, null, null, null, null,
                                                                                         etwView, null);

            internal static BackendUiWorkItem FromStatus(string statusLine) => new(BackendUiWorkKind.Status, null, null,
                                                                                   null, null, null, null, null,
                                                                                   statusLine);
        }

        private void SaveIntelSessionState(int pid)
        {
            if (pid <= 0)
            {
                return;
            }

            _etwHistoryByPid[pid] = EtwPaneHost.SnapshotItems().Select(x => x.Clone()).ToList();
            _heuristicsHistoryByPid[pid] = HeuristicsPaneHost.SnapshotItems().Select(x => x.Clone()).ToList();
            _filesystemHistoryByPid[pid] = FilesystemPaneHost.SnapshotItems().Select(x => x.Clone()).ToList();
            _registryHistoryByPid[pid] = RegistryPaneHost.SnapshotItems().Select(x => x.Clone()).ToList();
            _relationsHistoryByPid[pid] = ProcessRelationsPaneHost.SnapshotItems().Select(x => x.Clone()).ToList();
            _apiGraphHistoryByPid[pid] = _apiGraphRowsByKey.Values.Select(static x => x.Clone()).ToList();
            _extendedHistoryByPid[pid] = _extendedRowsByKey.Values.Select(static x => x.Clone()).ToList();
        }

        private void RestoreIntelSessionState(int pid)
        {
            IEnumerable<GroupedEventRow> etw =
                _etwHistoryByPid.TryGetValue(pid, out var a) ? a : Array.Empty<GroupedEventRow>();
            IEnumerable<GroupedEventRow> heur =
                _heuristicsHistoryByPid.TryGetValue(pid, out var c) ? c : Array.Empty<GroupedEventRow>();
            IEnumerable<GroupedEventRow> fs =
                _filesystemHistoryByPid.TryGetValue(pid, out var d) ? d : Array.Empty<GroupedEventRow>();
            IEnumerable<GroupedEventRow> reg =
                _registryHistoryByPid.TryGetValue(pid, out var dr) ? dr : Array.Empty<GroupedEventRow>();
            IEnumerable<GroupedEventRow> rel =
                _relationsHistoryByPid.TryGetValue(pid, out var e) ? e : Array.Empty<GroupedEventRow>();
            IEnumerable<ApiCallGraphRowSnapshot> apiGraph =
                _apiGraphHistoryByPid.TryGetValue(pid, out var f) ? f : Array.Empty<ApiCallGraphRowSnapshot>();
            IEnumerable<ExtendedActivityRowSnapshot> extended =
                _extendedHistoryByPid.TryGetValue(pid, out var g) ? g : Array.Empty<ExtendedActivityRowSnapshot>();

            EtwPaneHost.LoadHistory(etw.Select(x => x.Clone()).ToList());
            HeuristicsPaneHost.LoadHistory(heur.Select(x => x.Clone()).ToList());
            FilesystemPaneHost.LoadHistory(fs.Select(x => x.Clone()).ToList());
            RegistryPaneHost.LoadHistory(reg.Select(x => x.Clone()).ToList());
            ProcessRelationsPaneHost.SetRootPid(pid);
            ProcessRelationsPaneHost.LoadHistory(rel.Select(x => x.Clone()).ToList());
            _apiGraphRowsByKey.Clear();
            _extendedRowsByKey.Clear();
            _apiGraphReasonByKey.Clear();
            _apiGraphActionByKey.Clear();
            _apiGraphDecodedByKey.Clear();
            _apiGraphFramesByKey.Clear();
            _apiGraphSensorByKey.Clear();
            _apiGraphTimelineLastEmitByKey.Clear();
            _observedHookStackLastPersistByThread.Clear();
            _threadStackFallbackLastCaptureByThread.Clear();
            _pendingThreadStackFallbackCaptures.Clear();
            _apiMemorySignalsByPage.Clear();
            _crossProcWriteCountByPair.Clear();
            _crossProcRwxAllocCountByPair.Clear();
            _antiAnalysisCountByEvidence.Clear();
            ResetImageMapCorrelationCaches();
            _extendedViewRows.Clear();
            foreach (ApiCallGraphRowSnapshot row in apiGraph)
            {
                string sensorOrigin = string.IsNullOrWhiteSpace(row.SensorOrigin) ? "Unclassified" : row.SensorOrigin;
                string callerOrigin = NormalizeApiCallerOrigin(row.CallerOrigin);
                string originModule = NormalizeApiOriginModule(row.OriginModule);
                string key = BuildApiGraphKey(row.SourcePid, row.TargetPid, row.ThreadId, row.ApiName, sensorOrigin,
                                              callerOrigin, originModule);
                _apiGraphRowsByKey[key] = row.Clone();
                _apiGraphSensorByKey[key] = sensorOrigin;
            }
            foreach (ExtendedActivityRowSnapshot row in extended)
            {
                string key = BuildExtendedActivityKey(row.TypeLabel, row.ActorLabel, row.TargetLabel, row.SubjectLabel,
                                                      row.OperationLabel);
                _extendedRowsByKey[key] = row.Clone();
            }
            PublishApiGraphSnapshot();
            PublishExtendedActivitySnapshot();
            if (EtwPaneHost.ItemCount > 0)
            {
                FindExplorerItem("ETW")?.PushPreviewValue(EtwPaneHost.TotalRawCount);
            }
            if (HeuristicsPaneHost.ItemCount > 0)
            {
                FindExplorerItem("Heuristics")?.PushPreviewValue(HeuristicsPaneHost.TotalRawCount);
            }
            if (FilesystemPaneHost.ItemCount > 0)
            {
                FindExplorerItem("Filesystem")?.PushPreviewValue(FilesystemPaneHost.TotalRawCount);
            }
            if (RegistryPaneHost.ItemCount > 0)
            {
                FindExplorerItem("Registry")?.PushPreviewValue(RegistryPaneHost.TotalRawCount);
            }
            if (ProcessRelationsPaneHost.ItemCount > 0)
            {
                FindExplorerItem("Process Relations")?.PushPreviewValue(ProcessRelationsPaneHost.TotalRawCount);
            }
            RefreshExplorerDataBadges();
        }

        private static System.Windows.Media.Brush BuildApiSensorBackground(string sensor)
        {
            return sensor.StartsWith("Kernel", StringComparison.OrdinalIgnoreCase)
                       ? new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0x45, 0x1A, 0x1A))
                   : sensor.StartsWith("Usermode", StringComparison.OrdinalIgnoreCase)
                       ? new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0x12, 0x2D, 0x4A))
                       : new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0x24, 0x24, 0x24));
        }

        private static System.Windows.Media.Brush BuildApiSensorForeground(string sensor)
        {
            return sensor.StartsWith("Kernel", StringComparison.OrdinalIgnoreCase)
                       ? new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0xFF, 0xC7, 0xC7))
                   : sensor.StartsWith("Usermode", StringComparison.OrdinalIgnoreCase)
                       ? new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0xB9, 0xE3, 0xFF))
                       : new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0xD0, 0xD0, 0xD0));
        }

        private static System.Windows.Media.Brush BuildApiHeatTrackBackground(string sensor, string callerOrigin)
        {
            callerOrigin = NormalizeApiCallerOrigin(callerOrigin);
            return callerOrigin switch {
                "process-image" =>
                    new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0x0F, 0x31, 0x2C)),
                "non-system-dll" =>
                    new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0x38, 0x28, 0x10)),
                "unbacked" =>
                    new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0x3E, 0x10, 0x22)),
                "system" =>
                    new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0x23, 0x28, 0x31)),
                _ =>
                    sensor.StartsWith("Kernel", StringComparison.OrdinalIgnoreCase)
                        ? new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0x3A, 0x18, 0x18))
                    : sensor.StartsWith("Usermode", StringComparison.OrdinalIgnoreCase)
                        ? new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0x13, 0x27, 0x3D))
                        : new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0x21, 0x26, 0x2D))
            };
        }

        private static System.Windows.Media.Brush BuildApiHeatFillBackground(string sensor, string callerOrigin)
        {
            callerOrigin = NormalizeApiCallerOrigin(callerOrigin);
            return callerOrigin switch {
                "process-image" =>
                    new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0x4D, 0xBF, 0xA9)),
                "non-system-dll" =>
                    new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0xD8, 0xA1, 0x45)),
                "unbacked" =>
                    new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0xD1, 0x4E, 0x75)),
                "system" =>
                    new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0x6C, 0x78, 0x88)),
                _ =>
                    sensor.StartsWith("Kernel", StringComparison.OrdinalIgnoreCase)
                        ? new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0xB2, 0x4A, 0x4A))
                    : sensor.StartsWith("Usermode", StringComparison.OrdinalIgnoreCase)
                        ? new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0x3E, 0x84, 0xC6))
                        : new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0x5C, 0x66, 0x73))
            };
        }

        private static System.Windows.Media.Brush BuildApiRowBackground(string sensor, string callerOrigin)
        {
            callerOrigin = NormalizeApiCallerOrigin(callerOrigin);
            return callerOrigin switch { "process-image" => new System.Windows.Media.SolidColorBrush(
                                             System.Windows.Media.Color.FromArgb(0x4A, 0x0E, 0x58, 0x4D)),
                                         "non-system-dll" => new System.Windows.Media.SolidColorBrush(
                                             System.Windows.Media.Color.FromArgb(0x4A, 0x66, 0x43, 0x0D)),
                                         "unbacked" => new System.Windows.Media.SolidColorBrush(
                                             System.Windows.Media.Color.FromArgb(0x52, 0x71, 0x18, 0x33)),
                                         "system" => new System.Windows.Media.SolidColorBrush(
                                             System.Windows.Media.Color.FromArgb(0x30, 0x35, 0x3C, 0x45)),
                                         _ => sensor.StartsWith("Kernel", StringComparison.OrdinalIgnoreCase)
                                                  ? new System.Windows.Media.SolidColorBrush(
                                                        System.Windows.Media.Color.FromArgb(0x44, 0x6E, 0x1D, 0x1D))
                                              : sensor.StartsWith("Usermode", StringComparison.OrdinalIgnoreCase)
                                                  ? new System.Windows.Media.SolidColorBrush(
                                                        System.Windows.Media.Color.FromArgb(0x44, 0x16, 0x39, 0x59))
                                                  : new System.Windows.Media.SolidColorBrush(
                                                        System.Windows.Media.Color.FromArgb(0x22, 0x36, 0x36, 0x36)) };
        }

        private static System.Windows.Media.Brush BuildApiRowBorder(string sensor, string callerOrigin)
        {
            _ = sensor;
            callerOrigin = NormalizeApiCallerOrigin(callerOrigin);
            return callerOrigin switch {
                "process-image" =>
                    new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0x64, 0xD9, 0xC1)),
                "non-system-dll" =>
                    new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0xE2, 0xB0, 0x5E)),
                "unbacked" =>
                    new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0xE0, 0x65, 0x8D)),
                "system" =>
                    new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0x6F, 0x7C, 0x8A)),
                _ => new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0x44, 0x4C, 0x56))
            };
        }

        private static System.Windows.Media.Brush BuildApiGraphEdgeBrush(string sensor, string callerOrigin,
                                                                         double heat)
        {
            heat = Math.Clamp(heat, 0.0, 1.0);
            callerOrigin = NormalizeApiCallerOrigin(callerOrigin);
            if (callerOrigin == "process-image")
            {
                byte red = (byte)Math.Clamp(62 + (int)Math.Round(28 * heat), 0, 255);
                byte green = (byte)Math.Clamp(176 + (int)Math.Round(48 * heat), 0, 255);
                byte blue = (byte)Math.Clamp(152 + (int)Math.Round(40 * heat), 0, 255);
                return new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(red, green, blue));
            }

            if (callerOrigin == "non-system-dll")
            {
                byte red = (byte)Math.Clamp(180 + (int)Math.Round(48 * heat), 0, 255);
                byte green = (byte)Math.Clamp(128 + (int)Math.Round(40 * heat), 0, 255);
                byte blue = (byte)Math.Clamp(52 + (int)Math.Round(18 * heat), 0, 255);
                return new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(red, green, blue));
            }

            if (callerOrigin == "unbacked")
            {
                byte red = (byte)Math.Clamp(194 + (int)Math.Round(38 * heat), 0, 255);
                byte green = (byte)Math.Clamp(68 + (int)Math.Round(22 * heat), 0, 255);
                byte blue = (byte)Math.Clamp(112 + (int)Math.Round(32 * heat), 0, 255);
                return new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(red, green, blue));
            }

            if (callerOrigin == "system")
            {
                byte shade = (byte)Math.Clamp(118 + (int)Math.Round(52 * heat), 0, 255);
                return new System.Windows.Media.SolidColorBrush(
                    System.Windows.Media.Color.FromRgb(shade, shade, (byte)Math.Clamp(shade + 8, 0, 255)));
            }

            if (sensor.StartsWith("Kernel", StringComparison.OrdinalIgnoreCase))
            {
                byte red = (byte)Math.Clamp(150 + (int)Math.Round(80 * heat), 0, 255);
                byte green = (byte)Math.Clamp(65 + (int)Math.Round(25 * heat), 0, 255);
                byte blue = (byte)Math.Clamp(65 + (int)Math.Round(25 * heat), 0, 255);
                return new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(red, green, blue));
            }

            if (sensor.StartsWith("Usermode", StringComparison.OrdinalIgnoreCase))
            {
                byte red = (byte)Math.Clamp(70 + (int)Math.Round(25 * heat), 0, 255);
                byte green = (byte)Math.Clamp(125 + (int)Math.Round(45 * heat), 0, 255);
                byte blue = (byte)Math.Clamp(178 + (int)Math.Round(50 * heat), 0, 255);
                return new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(red, green, blue));
            }

            byte neutralShade = (byte)Math.Clamp(110 + (int)Math.Round(70 * heat), 0, 255);
            return new System.Windows.Media.SolidColorBrush(
                System.Windows.Media.Color.FromRgb(neutralShade, neutralShade, neutralShade));
        }

        private static System.Windows.Media.Brush BuildApiCallerOriginBackground(string callerOrigin)
        {
            return NormalizeApiCallerOrigin(callerOrigin) switch {
                "process-image" =>
                    new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0x14, 0x42, 0x39)),
                "non-system-dll" =>
                    new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0x4D, 0x34, 0x12)),
                "unbacked" =>
                    new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0x56, 0x16, 0x2D)),
                "system" =>
                    new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0x2C, 0x33, 0x3B)),
                _ => new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0x26, 0x26, 0x26))
            };
        }

        private static System.Windows.Media.Brush BuildApiCallerOriginForeground(string callerOrigin)
        {
            return NormalizeApiCallerOrigin(callerOrigin) switch {
                "process-image" =>
                    new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0xC0, 0xFF, 0xEE)),
                "non-system-dll" =>
                    new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0xFF, 0xE1, 0xB0)),
                "unbacked" =>
                    new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0xFF, 0xC2, 0xD4)),
                "system" =>
                    new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0xD2, 0xDA, 0xE2)),
                _ => new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0xD8, 0xD8, 0xD8))
            };
        }

        private async Task RunPreflightAsync(int pid, bool userInitiated = false)
        {
            BlackbirdPreflightReport report;
            try
            {
                report = await Task.Run(() => BlackbirdPreflight.Run(pid));
            }
            catch (Exception ex)
            {
                report = new BlackbirdPreflightReport { CheckedUtc = DateTime.UtcNow, DriverState = "Unknown",
                                                        ControllerState = "Unknown", Error = ex.Message };
                DiagnosticsState.SetValue("Preflight", $"failed: {ex.Message}");
                OutputCapture.AppendLine($"Preflight failed: {ex}");
            }

            _lastPreflight = report;
            OutputCapture.AppendLine($"Preflight: {report.Summary}");
            DiagnosticsState.SetValue("Driver Service", report.DriverDisplayState);
            DiagnosticsState.SetValue("Controller Service", report.ControllerState);
            DiagnosticsState.SetValue("Broker Caps", $"0x{report.BrokerCapabilities:X8}");
            DiagnosticsState.SetValue("Broker TI", report.ThreatIntelEnabled ? "Enabled" : "Disabled");
            DiagnosticsState.SetValue("Broker TI Enable Err", report.ThreatIntelEnableError.ToString());
            DiagnosticsState.SetValue("Hook DLL", report.HookDllExists ? "Found" : $"Missing ({report.HookDllPath})");
            ApplyConnectivityStatus(report, userInitiated);
        }

        private void ApplyConnectivityStatus(BlackbirdPreflightReport report, bool userInitiated)
        {
            var issues = new List<string>();

            if (!string.IsNullOrWhiteSpace(report.Error))
            {
                issues.Add(report.Error);
            }

            if (!report.DriverRuntimeReady)
            {
                issues.Add($"driver service={report.DriverState}");
            }

            if (!string.Equals(report.ControllerState, "Running", StringComparison.OrdinalIgnoreCase))
            {
                issues.Add($"controller service={report.ControllerState}");
            }

            if (!report.BrokerConnectOk)
            {
                issues.Add("broker link down");
            }

            if (!report.DriverProxyOk)
            {
                issues.Add("driver proxy unavailable");
            }

            if (!report.HookDllExists)
            {
                issues.Add($"hook dll missing ({report.HookDllPath})");
            }

            if (report.EtwUplinkCapable && !report.EtwUplinkQueryOk)
            {
                issues.Add("ETW uplink query failed");
            }

            if (issues.Count == 0)
            {
                _lastConnectivityIssueSignature = null;
                DiagnosticsState.SetValue("Connectivity", "OK");
                SetBackendConnectivity(true);
                return;
            }

            string detail = string.Join("; ", issues);
            string signature = detail;
            string msg = $"Could not fully connect to driver/service: {detail}";
            DiagnosticsState.SetValue("Connectivity", $"FAILED: {detail}");
            OutputCapture.AppendLine(msg);
            SetBackendConnectivity(false);

            bool shouldWarn =
                userInitiated || !string.Equals(_lastConnectivityIssueSignature, signature, StringComparison.Ordinal);
            if (shouldWarn)
            {
                ThemedMessageBox.Show(this, $"Could not fully connect to the driver/service uplink.\n\n{detail}",
                                      "Blackbird Connectivity", MessageBoxButton.OK, MessageBoxImage.Warning);
            }

            _lastConnectivityIssueSignature = signature;
        }

        private async void Preflight_Click(object sender, RoutedEventArgs e)
        {
            StatusBlock.Text = "Status: Running preflight...";
            await RunPreflightAsync(TryGetPid(), userInitiated: true);
            if (_lastPreflight == null)
            {
                StatusBlock.Text = "Status: Preflight unavailable";
            }
        }

        private async void DriverStart_Click(object sender, RoutedEventArgs e)
        {
            string message = "";
            bool ok = await Task.Run(
                () => BlackbirdServiceControl.TryStart("blackbird", TimeSpan.FromSeconds(8), out message));
            OutputCapture.AppendLine(message);
            if (!ok)
            {
                StatusBlock.Text = "Status: Failed to start blackbird";
                return;
            }

            await RunPreflightAsync(TryGetPid(), userInitiated: true);
            if (_lastConnectivityIssueSignature == null)
            {
                StatusBlock.Text = "Status: Driver started";
            }
        }

        private async void DriverStop_Click(object sender, RoutedEventArgs e)
        {
            if (ThemedMessageBox.Show(this, "Stop the kernel driver 'blackbird'?", "Driver Stop",
                                      MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes)
            {
                return;
            }

            StopBackendSession();
            string message = "";
            bool ok = await Task.Run(
                () => BlackbirdServiceControl.TryStop("blackbird", TimeSpan.FromSeconds(8), out message));
            OutputCapture.AppendLine(message);
            StatusBlock.Text = ok ? "Status: Driver stopped" : "Status: Failed to stop blackbird";
            await RunPreflightAsync(TryGetPid(), userInitiated: true);
        }

        private async void ControllerRestart_Click(object sender, RoutedEventArgs e)
        {
            StopBackendSession();
            string message = "";
            bool ok = await Task.Run(
                () => BlackbirdServiceControl.TryRestart("BlackbirdController", TimeSpan.FromSeconds(10), out message));
            OutputCapture.AppendLine(message);
            if (!ok)
            {
                StatusBlock.Text = "Status: Controller restart failed";
                return;
            }

            await RunPreflightAsync(TryGetPid(), userInitiated: true);
            int pid = TryGetPid();
            bool useUsermodeHooks = _currentSession?.UseUsermodeHooks ?? false;
            if (_currentSession != null && !_currentSession.OfflineSnapshot && !_currentSession.TargetExited &&
                _currentSession.Pid == pid)
            {
                EnsureLiveCaptureStoreForCurrentSession(pid);
                StartBackendForPid(pid, useUsermodeHooks, stopExistingSession: false);
            }
            else
            {
                StartBackendForPid(pid, useUsermodeHooks);
            }
            if (_lastConnectivityIssueSignature == null)
            {
                StatusBlock.Text = "Status: Controller restarted";
            }
        }

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
