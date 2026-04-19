using BlackbirdInterface.Capture;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
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
        private Action<BackendIpcDiagnosticsView>? _sessionIpcDiagnosticsHandler;
        private Action<string>? _sessionStatusHandler;
        private readonly Dictionary<int, List<GroupedEventRow>> _etwHistoryByPid = new();
        private readonly Dictionary<int, List<GroupedEventRow>> _heuristicsHistoryByPid = new();
        private readonly Dictionary<int, List<GroupedEventRow>> _filesystemHistoryByPid = new();
        private readonly Dictionary<int, List<GroupedEventRow>> _relationsHistoryByPid = new();
        private readonly Dictionary<int, List<ApiCallGraphRowSnapshot>> _apiGraphHistoryByPid = new();
        private readonly Dictionary<string, ApiCallGraphRowSnapshot> _apiGraphRowsByKey = new(StringComparer.Ordinal);
        private readonly Dictionary<string, string> _apiGraphReasonByKey = new(StringComparer.Ordinal);
        private readonly Dictionary<string, string> _apiGraphActionByKey = new(StringComparer.Ordinal);
        private readonly Dictionary<string, string> _apiGraphDecodedByKey = new(StringComparer.Ordinal);
        private readonly Dictionary<string, string> _apiGraphFramesByKey = new(StringComparer.Ordinal);
        private readonly Dictionary<string, string> _apiGraphSensorByKey = new(StringComparer.Ordinal);
        private readonly Dictionary<string, BrokerEtwEventView> _apiGraphViewByKey = new(StringComparer.Ordinal);
        private readonly Dictionary<string, DateTime> _apiGraphTimelineLastEmitByKey = new(StringComparer.Ordinal);
        private readonly Dictionary<ulong, ApiMemoryPageSignal> _apiMemorySignalsByPage = new();
        private bool _apiGraphSnapshotDirty;

        private BlackbirdPreflightReport? _lastPreflight;
        private string? _lastConnectivityIssueSignature;
        private readonly ConcurrentQueue<IoctlParsedEvent> _pendingIoctlEvents = new();
        private readonly ConcurrentQueue<BlackbirdNative.BkIpcEtwEvent> _pendingEtwEvents = new();
        private readonly ConcurrentQueue<string> _pendingStatusLines = new();
        private readonly ConcurrentQueue<BackendUiWorkItem> _pendingUiWork = new();
        private readonly AutoResetEvent _backendTransformSignal = new(false);
        private CancellationTokenSource? _backendTransformCts;
        private Task? _backendTransformTask;
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
        private const int MaxPendingIoctlEvents = 30000;
        private const int MaxPendingEtwEvents = 18000;
        private const int MaxPendingUiWorkItems = 20000;
        private const int IoctlPressureSoftLimit = (MaxPendingIoctlEvents * 7) / 10;
        private const int IoctlPressureCriticalLimit = (MaxPendingIoctlEvents * 9) / 10;
        private const int EtwPressureSoftLimit = (MaxPendingEtwEvents * 7) / 10;
        private const int EtwPressureCriticalLimit = (MaxPendingEtwEvents * 9) / 10;
        private const uint CorrelationIntentMask = 0x00000007u;
        private const uint HighSignalHandleMask = 0x00000800u | 0x00002000u;
        private const uint ThreadHighSignalMask =
            0x00000004u | 0x00000008u | 0x00000010u | 0x00000020u | 0x00000040u | 0x00000080u | 0x00000100u;
        private static readonly TimeSpan BackendUiFlushBudget = TimeSpan.FromMilliseconds(5);
        private static readonly TimeSpan BackendUiFlushBudgetUnderPressure = TimeSpan.FromMilliseconds(18);
        private static readonly TimeSpan FilesystemTimelineClusterWindow = TimeSpan.FromMilliseconds(15000);
        private static readonly TimeSpan FilesystemTimelineClusterIdleFlush = TimeSpan.FromMilliseconds(1500);
        private static readonly TimeSpan ApiTimelineEmissionWindow = TimeSpan.FromSeconds(5);
        private string? _lastEtwTimelineSignature;
        private DateTime _lastEtwTimelineTimestampUtc;
        private readonly Dictionary<ulong, IoctlParsedEvent> _recentHandleEvidenceByPair = new();
        private DateTime _lastHandleEvidencePruneUtc = DateTime.MinValue;
        private readonly Dictionary<string, int> _filesystemClusterOperationCounts = new(StringComparer.Ordinal);
        private readonly Dictionary<string, (uint Pid, uint Tid, string Path, uint Operation)>
            _filesystemClusterSamplesByOperation = new(StringComparer.Ordinal);
        private readonly Dictionary<string, int> _crossProcWriteCountByPair = new(StringComparer.Ordinal);
        private readonly Dictionary<string, int> _crossProcRwxAllocCountByPair = new(StringComparer.Ordinal);
        private readonly Dictionary<uint, DateTime> _observedProcessStartUtcByPid = new();
        private readonly Dictionary<uint, ulong> _observedProcessStartKeyByPid = new();
        private readonly Dictionary<uint, uint> _observedInitialThreadIdByPid = new();
        private readonly Dictionary<string, RegionLifecycleState> _regionLifecycleByIdentity = new(StringComparer.Ordinal);
        private readonly Dictionary<string, ulong> _functionTableBaseByPointer = new(StringComparer.Ordinal);
        private volatile int _filterRootPid;
        private readonly ConcurrentDictionary<uint, byte> _filterTrackedPids = new();
        private int _filesystemClusterTotal;
        private DateTime _filesystemClusterWindowStartUtc = DateTime.MinValue;
        private DateTime _filesystemClusterLastSeenUtc = DateTime.MinValue;

        private void InitializeBackendUi()
        {
            EtwPaneHost.ClearAll();
            HeuristicsPaneHost.ClearAll();
            FilesystemPaneHost.ClearAll();
            ProcessRelationsPaneHost.ClearAll();
            _apiGraphRowsByKey.Clear();
            _apiGraphReasonByKey.Clear();
            _apiGraphActionByKey.Clear();
            _apiGraphDecodedByKey.Clear();
            _apiGraphFramesByKey.Clear();
            _apiGraphSensorByKey.Clear();
            _apiGraphViewByKey.Clear();
            _apiGraphTimelineLastEmitByKey.Clear();
            _apiMemorySignalsByPage.Clear();
            _crossProcWriteCountByPair.Clear();
            _crossProcRwxAllocCountByPair.Clear();
            _observedProcessStartUtcByPid.Clear();
            _observedProcessStartKeyByPid.Clear();
            _observedInitialThreadIdByPid.Clear();
            _regionLifecycleByIdentity.Clear();
            _functionTableBaseByPointer.Clear();
            PublishApiGraphSnapshot();
            IpcUplinkPaneHost.SetInactive("No transport diagnostics yet",
                                          "Enable the uplink and wait for the first transport sample.");
            ResetFilesystemTimelineCluster();
            ProcessRelationsPaneHost.SetRootPid(0);
            RefreshExplorerDataBadges();
            DiagnosticsState.SetValue("UI", "Initialized");
            DiagnosticsState.SetValue("Kernel Hooks", "Awaiting telemetry");
            DiagnosticsState.SetValue("Usermode Hooks", "Inactive");
            DiagnosticsState.SetValue("Operator Connection Established", "Disabled in analyst interface");
            DiagnosticsState.SetValue("Hook Integrity", "Unknown");
            DiagnosticsState.SetValue("AMSI Integrity", "Unknown");
            DiagnosticsState.SetValue("ETW Integrity", "Unknown");
            DiagnosticsState.SetValue("ETW Status", "Ready");
            DiagnosticsState.SetValue("API Graph", "patterns=0/0 visible=False");
        }

        private void StartBackendForPid(int pid, bool useUsermodeHooks, bool stopExistingSession = true)
        {
            BlackbirdBackendSession? preparedSession = null;

            if (stopExistingSession)
            {
                StopBackendSession();
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

            _hasIpcUplinkData = false;
            _lastEtwTimelineSignature = null;
            _lastEtwTimelineTimestampUtc = DateTime.MinValue;
            ResetFilesystemTimelineCluster();
            SetIpcUplinkExplorerDetails("Enable to inspect IPC internals", "Waiting for session diagnostics...",
                                        hasData: false);

            int generation = ++_backendGeneration;
            try
            {
                _filterRootPid = pid;
                _filterTrackedPids.Clear();
                _filterTrackedPids.TryAdd((uint)pid, 0);
                _observedProcessStartUtcByPid[(uint)pid] = DateTime.UtcNow;
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

                _sessionIpcDiagnosticsHandler = diag =>
                {
                    if (Dispatcher.HasShutdownStarted)
                        return;
                    Dispatcher.BeginInvoke(new Action(
                        () =>
                        {
                            if (generation != _backendGeneration)
                                return;
                            diag.PendingIoctlUiQueue =
                                (int)Math.Min(int.MaxValue, Math.Max(0, Interlocked.Read(ref _pendingIoctlCount)));
                            diag.PendingEtwUiQueue =
                                (int)Math.Min(int.MaxValue, Math.Max(0, Interlocked.Read(ref _pendingEtwCount)));
                            diag.PendingStatusUiQueue =
                                (int)Math.Min(int.MaxValue, Math.Max(0, Interlocked.Read(ref _pendingStatusCount) +
                                                                            Interlocked.Read(ref _pendingUiWorkCount)));
                            diag.DroppedIoctlForPressure = Interlocked.Read(ref _droppedIoctlForPressure);
                            diag.DroppedEtwForPressure = Interlocked.Read(ref _droppedEtwForPressure);
                            diag.DroppedUiWorkForPressure = Interlocked.Read(ref _droppedUiWorkForPressure);
                            UpdateIpcUplinkExplorer(diag);
                        }));
                };

                _sessionStatusHandler = text =>
                {
                    if (generation != _backendGeneration)
                        return;
                    _pendingStatusLines.Enqueue($"[session pid={pid}] {text}");
                    Interlocked.Increment(ref _pendingStatusCount);
                    _backendTransformSignal.Set();
                };

                session.IoctlEvent += _sessionIoctlHandler;
                session.EtwEvent += _sessionEtwHandler;
                session.Stats += _sessionStatsHandler;
                session.IpcDiagnostics += _sessionIpcDiagnosticsHandler;
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
                SetIpcUplinkExplorerDetails("Session start failed", displayError, hasData: false);
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
            if (_sessionIpcDiagnosticsHandler != null)
            {
                session.IpcDiagnostics -= _sessionIpcDiagnosticsHandler;
                _sessionIpcDiagnosticsHandler = null;
            }
            if (_sessionStatusHandler != null)
            {
                session.Status -= _sessionStatusHandler;
                _sessionStatusHandler = null;
            }
        }

        private void StopBackendSession(bool preserveApiGraphSnapshot = false)
        {
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
            _filterRootPid = 0;
            _filterTrackedPids.Clear();
            StopBackendTransformLoop();
            DisposeLiveCaptureStore();
            ClearPendingBackendUiQueues();
            _lastEtwTimelineSignature = null;
            _lastEtwTimelineTimestampUtc = DateTime.MinValue;
            Interlocked.Exchange(ref _droppedIoctlForPressure, 0);
            Interlocked.Exchange(ref _droppedEtwForPressure, 0);
            Interlocked.Exchange(ref _droppedUiWorkForPressure, 0);
            ResetFilesystemTimelineCluster();
            _hasIpcUplinkData = false;
            if (!preserveApiGraphSnapshot)
            {
                _apiGraphRowsByKey.Clear();
                _apiGraphReasonByKey.Clear();
                _apiGraphActionByKey.Clear();
                _apiGraphDecodedByKey.Clear();
                _apiGraphFramesByKey.Clear();
                _apiGraphSensorByKey.Clear();
                _apiGraphViewByKey.Clear();
                _apiGraphTimelineLastEmitByKey.Clear();
                _apiMemorySignalsByPage.Clear();
                _crossProcWriteCountByPair.Clear();
                _crossProcRwxAllocCountByPair.Clear();
                _observedProcessStartUtcByPid.Clear();
                _observedProcessStartKeyByPid.Clear();
                _observedInitialThreadIdByPid.Clear();
                _regionLifecycleByIdentity.Clear();
                _functionTableBaseByPointer.Clear();
                PublishApiGraphSnapshot();
            }
            SetIpcUplinkExplorerDetails("Session stopped", "No live transport diagnostics", hasData: false);
            DiagnosticsState.SetValue("Session", "Stopped");
            DiagnosticsState.SetValue("Kernel Hooks", "Inactive");
            DiagnosticsState.SetValue("Usermode Hooks", "Inactive");
            DiagnosticsState.SetValue("Operator Connection Established", "Disabled in analyst interface");
            DiagnosticsState.SetValue("Hook Integrity", "Unknown");
            DiagnosticsState.SetValue("AMSI Integrity", "Unknown");
            DiagnosticsState.SetValue("ETW Integrity", "Unknown");
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

                while (transformed < MaxBackendTransformItemsPerBatch && _pendingIoctlEvents.TryDequeue(out var ioctl))
                {
                    Interlocked.Decrement(ref _pendingIoctlCount);
                    DateTime nowUtc = DateTime.UtcNow;
                    IReadOnlyList<TelemetryEvent> filesystemClusterEvents =
                        AccumulateFilesystemTimelineCluster(ioctl, nowUtc);
                    if (filesystemClusterEvents.Count > 0)
                    {
                        for (int i = 0; i < filesystemClusterEvents.Count; i += 1)
                        {
                            if (!TryEnqueueUiWork(
                                    BackendUiWorkItem.FromIoctl(filesystemClusterEvents[i], null, null, null, null)))
                            {
                                break;
                            }
                        }
                        producedUiWork = true;
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
                    ThreadLifecycleEventSample? threadLifecycle = MapIoctlThreadLifecycle(ioctl);
                    IoctlParsedEvent? filesystem = MapIoctlFilesystem(ioctl);
                    if (relation != null)
                    {
                        _ = ProcessIdentityResolver.Resolve(relation.SourcePid);
                        _ = ProcessIdentityResolver.Resolve(relation.TargetPid);
                    }
                    if (heuristic != null)
                    {
                        _ = ProcessIdentityResolver.Resolve(heuristic.ActorPid);
                        _ = ProcessIdentityResolver.Resolve(heuristic.TargetPid);
                    }
                    if (filesystem != null)
                    {
                        _ = ProcessIdentityResolver.Resolve(filesystem.FileProcessPid);
                    }

                    if (ShouldPersistIoctlRecord(ioctl, telemetry, relation, heuristic, filesystem))
                    {
                        AppendIoctlToCaptureStore(nowUtc, ioctl);
                    }

                    if (telemetry != null || relation != null || heuristic != null || threadLifecycle != null ||
                        filesystem != null)
                    {
                        _ = TryEnqueueUiWork(
                            BackendUiWorkItem.FromIoctl(telemetry, relation, heuristic, threadLifecycle, filesystem));
                        producedUiWork = true;
                    }

                    transformed += 1;
                }

                while (transformed < MaxBackendTransformItemsPerBatch && _pendingEtwEvents.TryDequeue(out var etw))
                {
                    Interlocked.Decrement(ref _pendingEtwCount);
                    BrokerEtwEventView view = MapBrokerEtwEvent(etw);
                    _ = ProcessIdentityResolver.Resolve(view.ActorPid);
                    _ = ProcessIdentityResolver.Resolve(view.TargetPid);

                    if (view.Family == BlackbirdNative.IpcEtwFamilyProcess &&
                        (view.Flags & BlackbirdNative.IpcEtwFlagProcessIsCreate) != 0)
                    {
                        uint etwCreator = view.CreatorPid != 0 ? view.CreatorPid : view.ActorPid;
                        uint etwChild = view.ProcessPid != 0 ? view.ProcessPid : view.TargetPid;
                        if (etwCreator != 0 && etwChild != 0 && etwCreator != etwChild &&
                            _filterTrackedPids.ContainsKey(etwCreator))
                        {
                            _filterTrackedPids.TryAdd(etwChild, 0);
                        }
                    }

                    _ = TryEnqueueUiWork(BackendUiWorkItem.FromEtw(view));
                    producedUiWork = true;
                    transformed += 1;
                }

                int statusLines = 0;
                while (statusLines < MaxBackendStatusLinesPerTransformBatch &&
                       _pendingStatusLines.TryDequeue(out var statusLine))
                {
                    Interlocked.Decrement(ref _pendingStatusCount);
                    _ = TryEnqueueUiWork(BackendUiWorkItem.FromStatus(statusLine));
                    producedUiWork = true;
                    statusLines += 1;
                }

                IReadOnlyList<TelemetryEvent> idleFilesystemClusters =
                    FlushFilesystemTimelineClusterIfNeeded(DateTime.UtcNow, force: false);
                if (idleFilesystemClusters.Count > 0)
                {
                    for (int i = 0; i < idleFilesystemClusters.Count; i += 1)
                    {
                        if (!TryEnqueueUiWork(
                                BackendUiWorkItem.FromIoctl(idleFilesystemClusters[i], null, null, null, null)))
                        {
                            break;
                        }
                    }
                    producedUiWork = true;
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

        private void UpdateIpcUplinkExplorer(BackendIpcDiagnosticsView diag)
        {
            _hasIpcUplinkData = true;
            SetExplorerHasData("IPC Uplink", true);
            IpcUplinkPaneHost.UpdateDiagnostics(diag);

            var item = FindExplorerItem("IPC Uplink");
            if (item == null)
            {
                return;
            }

            double queueScore = Math.Min(100.0, diag.DriverQueueDepth);
            double backlogScore =
                Math.Min(100.0, (diag.PendingIoctlUiQueue + diag.PendingEtwUiQueue + diag.PendingStatusUiQueue) * 2.0);
            double dropScore =
                diag.DriverDroppedEvents == 0 ? 0.0 : Math.Min(100.0, Math.Log10(diag.DriverDroppedEvents + 1) * 24.0);
            double pressure = Math.Min(100.0, Math.Max(queueScore, backlogScore) + dropScore);

            item.PushPreviewValue(pressure);

            string transport = "shared-ring+event";
            string ringState = diag.SharedRingEnabled ? "ring:ready" : $"ring:missing(err={diag.SharedRingError})";
            string primary =
                $"{transport} | {ringState} | buf {FormatIpcBytes(diag.IoctlReadBufferBytes)} | caps 0x{diag.BrokerCapabilities:X8}";
            string secondary =
                $"drvQ={diag.DriverQueueDepth} drop={diag.DriverDroppedEvents} uiQ i={diag.PendingIoctlUiQueue} e={diag.PendingEtwUiQueue} i/s={diag.IoctlEventsPerSec:0} e/s={diag.EtwEventsPerSec:0} shed i={diag.DroppedIoctlForPressure} e={diag.DroppedEtwForPressure} ui={diag.DroppedUiWorkForPressure}";

            SetIpcUplinkExplorerDetails(primary, secondary, hasData: true);

            DiagnosticsState.SetValue(
                "IPC Uplink",
                $"mode={transport} ringErr={diag.SharedRingError} queueDepth={diag.DriverQueueDepth} dropped={diag.DriverDroppedEvents} pending(ioctl={diag.PendingIoctlUiQueue},etw={diag.PendingEtwUiQueue},status={diag.PendingStatusUiQueue}) rate(ioctl={diag.IoctlEventsPerSec:0.0}/s,etw={diag.EtwEventsPerSec:0.0}/s) shed(ioctl={diag.DroppedIoctlForPressure},etw={diag.DroppedEtwForPressure},ui={diag.DroppedUiWorkForPressure}) errors(ioctl={diag.IoctlErrorsTotal},etw={diag.EtwErrorsTotal})");
        }

        private void SetIpcUplinkExplorerDetails(string primary, string secondary, bool hasData)
        {
            var item = FindExplorerItem("IPC Uplink");
            if (item == null)
            {
                return;
            }

            item.DetailPrimary = primary;
            item.DetailSecondary = secondary;
            item.ShowDetails = false;
            SetExplorerHasData("IPC Uplink", hasData);

            if (!hasData)
            {
                IpcUplinkPaneHost.SetInactive(primary, secondary);
            }
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

        private static string FormatIpcBytes(int bytes)
        {
            if (bytes < 1024)
            {
                return $"{bytes} B";
            }

            if (bytes < 1024 * 1024)
            {
                return $"{(bytes / 1024.0):0.0} KB";
            }

            return $"{(bytes / (1024.0 * 1024.0)):0.00} MB";
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

        private static bool ShouldKeepEtwEvent(BrokerEtwEventView view)
        {
            if (view.Family == BlackbirdNative.IpcEtwFamilyUserHook)
            {
                return true;
            }

            if (view.Family == BlackbirdNative.IpcEtwFamilySocket ||
                EventDetailFormatting.IsKernelNetworkEtwSource(view))
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
            if (string.IsNullOrWhiteSpace(view.DetectionName))
            {
                return false;
            }

            string det = view.DetectionName;
            if (IsHookTamperDetection(det))
            {
                return true;
            }
            if (IsDirectSyscallDetection(det))
            {
                return view.Severity >= 4;
            }
            if (det.Contains("AMSI_PATCH_TAMPERED", StringComparison.OrdinalIgnoreCase) ||
                det.Contains("ETW_PATCH_TAMPERED", StringComparison.OrdinalIgnoreCase))
            {
                return true;
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
                    Source = "Blackbird/MemoryPattern",
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
                    Source = "Blackbird/MemoryPattern",
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

        private static bool IsDirectSyscallDetection(string detection)
        {
            if (string.IsNullOrWhiteSpace(detection))
            {
                return false;
            }

            return detection.Contains("DIRECT_SYSCALL", StringComparison.OrdinalIgnoreCase) ||
                   detection.Contains("DIRECT-SYSCALL", StringComparison.OrdinalIgnoreCase) ||
                   detection.Contains("SUSPECT_HANDLE_OPERATION", StringComparison.OrdinalIgnoreCase) ||
                   detection.Contains("ANOMALY_ON_HANDLE_OP", StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsHookTamperDetection(string detection)
        {
            if (string.IsNullOrWhiteSpace(detection))
            {
                return false;
            }

            return detection.Contains("USERMODE_HOOK_TAMPERED", StringComparison.OrdinalIgnoreCase) ||
                   detection.Contains("AMSI_PATCH_TAMPERED", StringComparison.OrdinalIgnoreCase) ||
                   detection.Contains("ETW_PATCH_TAMPERED", StringComparison.OrdinalIgnoreCase) ||
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
            string stack0 = record.Frames.Length > 0 ? $"0x{record.Frames[0]:X}" : "n/a";
            string stack1 = record.Frames.Length > 1 ? $"0x{record.Frames[1]:X}" : "n/a";
            string moduleName = EventDetailFormatting.ModuleNameFromPath(record.OriginPath);
            ulong pageBase = record.OriginAddress & ~0xFFFUL;
            string fullFrames = BuildFrameList(record.FullFrames, record.FullFrameCount);
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
                   $"origin=0x{record.OriginAddress:X} protect=0x{record.OriginProtect:X8} module={moduleName} pageBase=0x{pageBase:X} " +
                   $"allocationBase=0x{record.DeepAllocationBase:X} regionSize=0x{record.DeepRegionSize:X} regionProtect=0x{record.DeepRegionProtect:X8} ({EventDetailFormatting.DescribeMemoryProtection(record.DeepRegionProtect)}) " +
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

        private static string BuildFrameList(ulong[]? frames, uint frameCount)
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

                list.Add($"0x{frame:X}");
            }

            return list.Count == 0 ? "<none>" : string.Join(",", list);
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
            bool isThreadObject = (record.HandleFlags & 0x00000010u) != 0;
            if (!IsHighRiskIoctlAccess(record.DesiredAccess, isThreadObject))
            {
                return false;
            }

            bool exportMismatch = (record.HandleFlags & 0x00002000u) != 0;
            bool stackSpoof = (record.HandleFlags & 0x00000800u) != 0;
            bool stackValidated = (record.HandleFlags & 0x00000400u) != 0;
            bool tebBoundsValid = (record.HandleFlags & 0x00010000u) != 0;
            return exportMismatch || (stackSpoof && (!stackValidated || !tebBoundsValid));
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

            return null;
        }

        private static IoctlParsedEvent? MapIoctlFilesystem(IoctlParsedEvent record)
        {
            return record.Type == BlackbirdNative.EventTypeFileSystem ? record : null;
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
            if (record.Type != BlackbirdNative.EventTypeHandle || record.CallerPid == 0 || record.TargetPid == 0)
            {
                return null;
            }

            if (record.HandleClass != 2)
            {
                return null;
            }

            bool isThreadObject = (record.HandleFlags & 0x00000010u) != 0;
            if (!IsHighRiskIoctlAccess(record.DesiredAccess, isThreadObject))
            {
                return null;
            }

            bool exportMismatch = (record.HandleFlags & 0x00002000u) != 0;
            bool stackSpoof = (record.HandleFlags & 0x00000800u) != 0;
            bool stackValidated = (record.HandleFlags & 0x00000400u) != 0;
            bool tebBoundsValid = (record.HandleFlags & 0x00010000u) != 0;
            if (!exportMismatch && (!stackSpoof || (stackValidated && tebBoundsValid)))
            {
                return null;
            }

            DateTime now = DateTime.UtcNow;
            uint severity = exportMismatch ? 6u : 5u;

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
                    $"{syscallSummary}; ioctlClass={record.HandleClass}; handleFlags={handleFlagsDecoded}; access={corrAccessDecoded}",
                Evidence = BuildHandleEvidenceText(record),
                RepeatCount = 1
            };
        }

        private static BrokerEtwEventView MapBrokerEtwEvent(BlackbirdNative.BkIpcEtwEvent etw)
        {
            string source = etw.Source switch { BlackbirdNative.IpcEtwSourceBlackbird => "Blackbird",
                                                BlackbirdNative.IpcEtwSourceThreatIntel => "ThreatIntel",
                                                BlackbirdNative.IpcEtwSourceKernelNetwork => "KernelNetwork",
                                                BlackbirdNative.IpcEtwSourceUserHook => "UserHook",
                                                _ => "Unknown" };

            string eventName = BlackbirdNative.WideBufferToString(etw.EventName);
            if (string.IsNullOrWhiteSpace(eventName))
            {
                eventName = "unknown";
            }

            string detection = BlackbirdNative.AnsiBufferToString(etw.DetectionName);
            string reason = BlackbirdNative.WideBufferToString(etw.Reason);
            uint actor = ResolveBrokerEtwActorPid(etw);
            uint target = ResolveBrokerEtwTargetPid(etw);
            DateTime now = DateTime.UtcNow;
            string operation = BlackbirdNative.AnsiBufferToString(etw.Operation);
            string actorDisplay = ProcessIdentityResolver.Resolve(actor);
            string targetDisplay = ProcessIdentityResolver.Resolve(target);
            Dictionary<string, string> hookFields =
                BuildHookFieldMap(reason, etw.HookArgs ?? Array.Empty<ulong>(), etw.HookArgCount);
            string argumentSummary = EventDetailFormatting.BuildNtApiArgumentSummary(
                !string.IsNullOrWhiteSpace(operation) ? operation : eventName, hookFields, actorDisplay, targetDisplay);

            return new BrokerEtwEventView {
                TimestampUtc = now,
                LastSeenUtc = now,
                Source = source,
                SourceId = etw.Source,
                Family = etw.Family,
                EventName = eventName,
                Task = etw.Task,
                Opcode = etw.Opcode,
                EventId = etw.EventId,
                EventProcessId = etw.EventProcessId,
                EventThreadId = etw.EventThreadId,
                Severity = etw.Severity,
                Flags = etw.Flags,
                ActorPid = actor,
                TargetPid = target,
                ProcessPid = etw.ProcessId is > 0 and <= uint.MaxValue ? (uint)etw.ProcessId : 0,
                ThreadId = etw.ThreadId is > 0 and <= uint.MaxValue ? (uint)etw.ThreadId : 0,
                CallerPid = etw.CallerPid is > 0 and <= uint.MaxValue ? (uint)etw.CallerPid : 0,
                ExplicitTargetPid = etw.TargetPid is > 0 and <= uint.MaxValue ? (uint)etw.TargetPid : 0,
                ParentPid = etw.ParentProcessId is > 0 and <= uint.MaxValue ? (uint)etw.ParentProcessId : 0,
                CreatorPid = etw.CreatorProcessId is > 0 and <= uint.MaxValue ? (uint)etw.CreatorProcessId : 0,
                CreatorThreadId = etw.CreatorThreadId is > 0 and <= uint.MaxValue ? (uint)etw.CreatorThreadId : 0,
                CorrelationFlags = etw.CorrelationFlags,
                CorrelationAccessMask = etw.CorrelationAccessMask,
                CorrelationAgeMs = etw.CorrelationAgeMs,
                DetectionName = detection,
                Reason = reason,
                ClassName = BlackbirdNative.AnsiBufferToString(etw.ClassName),
                Operation = operation,
                DesiredAccess = etw.DesiredAccess,
                OriginAddress = etw.OriginAddress,
                OriginProtect = etw.OriginProtect,
                StatusOpenProcess = etw.StatusOpenProcess,
                StatusBasicInfo = etw.StatusBasicInfo,
                StatusSectionName = etw.StatusSectionName,
                StackCount = etw.StackCount,
                Stack = etw.Stack ?? Array.Empty<ulong>(),
                DeepAllocationBase = etw.DeepAllocationBase,
                DeepRegionSize = etw.DeepRegionSize,
                DeepRegionProtect = etw.DeepRegionProtect,
                DeepRegionState = etw.DeepRegionState,
                DeepRegionType = etw.DeepRegionType,
                DeepSampleSize = etw.DeepSampleSize,
                DeepSample = etw.DeepSample ?? Array.Empty<byte>(),
                OriginPath = BlackbirdNative.WideBufferToString(etw.OriginPath),
                StartAddress = etw.StartAddress,
                ImageBase = etw.ImageBase,
                ImageSize = etw.ImageSize,
                StartRegionProtect = etw.StartRegionProtect,
                StartRegionState = etw.StartRegionState,
                StartRegionType = etw.StartRegionType,
                StartRegionStatus = etw.StartRegionStatus,
                SessionId = etw.SessionId,
                CreateStatus = etw.CreateStatus,
                ProcessStartKey = etw.ProcessStartKey,
                SignatureLevel = etw.SignatureLevel,
                SignatureType = etw.SignatureType,
                NotifyClass = etw.NotifyClass,
                DataType = etw.DataType,
                DataSize = etw.DataSize,
                HookArgCount = etw.HookArgCount,
                HookArgs = etw.HookArgs ?? Array.Empty<ulong>(),
                ImagePath = BlackbirdNative.WideBufferToString(etw.ImagePath),
                CommandLine = BlackbirdNative.WideBufferToString(etw.CommandLine),
                KeyPath = BlackbirdNative.WideBufferToString(etw.KeyPath),
                ValueName = BlackbirdNative.WideBufferToString(etw.ValueName),
                RepeatCount = 1,
                ArgumentSummary = argumentSummary
            };
        }

        private static uint ResolveBrokerEtwActorPid(BlackbirdNative.BkIpcEtwEvent etw)
        {
            return etw.Family switch {
                BlackbirdNative.IpcEtwFamilyHandle or BlackbirdNative.IpcEtwFamilyApc =>
                    NarrowPid(etw.CallerPid) ?? NarrowPid(etw.ProcessId) ?? etw.EventProcessId,
                BlackbirdNative.IpcEtwFamilyThread =>
                    NarrowPid(etw.CreatorProcessId) ?? NarrowPid(etw.ProcessId) ?? etw.EventProcessId,
                BlackbirdNative.IpcEtwFamilyProcess => NarrowPid(etw.CreatorProcessId) ??
                                                       NarrowPid(etw.ParentProcessId) ?? NarrowPid(etw.ProcessId) ??
                                                       etw.EventProcessId,
                BlackbirdNative.IpcEtwFamilyImage or BlackbirdNative.IpcEtwFamilyRegistry or
                    BlackbirdNative.IpcEtwFamilyDetection or BlackbirdNative.IpcEtwFamilyThreatIntel or
                        BlackbirdNative.IpcEtwFamilyUserHook or BlackbirdNative.IpcEtwFamilySocket =>
                    NarrowPid(etw.ProcessId) ?? etw.EventProcessId,
                _ => NarrowPid(etw.ProcessId) ?? NarrowPid(etw.CallerPid) ?? etw.EventProcessId
            };
        }

        private static uint ResolveBrokerEtwTargetPid(BlackbirdNative.BkIpcEtwEvent etw)
        {
            return etw.Family switch {
                BlackbirdNative.IpcEtwFamilyHandle or BlackbirdNative.IpcEtwFamilyApc or BlackbirdNative
                    .IpcEtwFamilyDetection or BlackbirdNative.IpcEtwFamilyThreatIntel => NarrowPid(etw.TargetPid) ?? 0,
                BlackbirdNative.IpcEtwFamilyThread or BlackbirdNative.IpcEtwFamilyProcess =>
                    NarrowPid(etw.ProcessId) ?? 0,
                BlackbirdNative.IpcEtwFamilyUserHook => NarrowPid(etw.TargetPid) ?? NarrowPid(etw.ProcessId) ?? 0,
                BlackbirdNative.IpcEtwFamilySocket => NarrowPid(etw.TargetPid) ?? NarrowPid(etw.ProcessId) ?? 0,
                _ => NarrowPid(etw.TargetPid) ?? 0
            };
        }

        private static uint? NarrowPid(ulong value)
        {
            return value is > 0 and <= uint.MaxValue ? (uint)value : null;
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
                view.DisplayDetails = BuildEtwDisplayDetail(view);
                UpdateHookPipelineDiagnostics(view);
                QueueSignatureIntelForView(view);
                MemoryRegionAttributionSample? memoryAttribution = CreateMemoryRegionAttributionSample(view);
                if (memoryAttribution != null)
                {
                    memoryAttributions.Add(memoryAttribution);
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
                }

                bool keepEtw = ShouldKeepEtwEvent(view);
                if (keepEtw)
                {
                    etwRows.Add(view);
                }

                ProcessRelationView? relation = MapEtwRelation(view);
                if (relation != null)
                {
                    relations.Add(relation);
                }

                string detection = view.DetectionName;
                DiagnosticsState.SetValue("ETW Status", "Live");
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
                if (IsHookTamperDetection(detection))
                {
                    DiagnosticsState.SetValue("Hook Integrity", "TAMPERED");
                }
                else if (detection.Equals("USERMODE_HOOK_INTEGRITY_OK", StringComparison.OrdinalIgnoreCase))
                {
                    DiagnosticsState.SetValue("Hook Integrity", "OK");
                }
                if (detection.Equals("AMSI_PATCH_TAMPERED", StringComparison.OrdinalIgnoreCase))
                {
                    DiagnosticsState.SetValue("AMSI Integrity", "TAMPERED");
                }
                else if (detection.Equals("AMSI_PATCH_OK", StringComparison.OrdinalIgnoreCase))
                {
                    DiagnosticsState.SetValue("AMSI Integrity", "OK");
                }
                if (detection.Equals("ETW_PATCH_TAMPERED", StringComparison.OrdinalIgnoreCase))
                {
                    DiagnosticsState.SetValue("ETW Integrity", "TAMPERED");
                }
                else if (detection.Equals("ETW_PATCH_OK", StringComparison.OrdinalIgnoreCase))
                {
                    DiagnosticsState.SetValue("ETW Integrity", "OK");
                }

                string eventName = view.EventName ?? string.Empty;
                string displayDetection = BuildFallbackDetectionLabel(detection, eventName, view.Task, view.Opcode,
                                                                      view.EventId, view.CorrelationFlags);
                string source = view.Source;
                uint actor = view.ActorPid;
                bool isSocketEvent = view.Family == BlackbirdNative.IpcEtwFamilySocket ||
                                     EventDetailFormatting.IsKernelNetworkEtwSource(view);
                string socketOperation = string.IsNullOrWhiteSpace(view.Operation) ? eventName : view.Operation;
                if (string.IsNullOrWhiteSpace(socketOperation))
                {
                    socketOperation = $"OP{view.Opcode}";
                }
                string timelineGroup = isSocketEvent ? "Sockets" : "Blackbird-ETW";
                string timelineSubtype = isSocketEvent ? socketOperation : eventName;
                string summary = isSocketEvent ? $"{socketOperation} pid={actor} task={view.Task} opcode={view.Opcode}"
                                               : (!string.IsNullOrWhiteSpace(displayDetection)
                                                      ? $"{source}/{displayDetection} sev={view.Severity}"
                                                      : $"{source}/{eventName} sev={view.Severity}");
                string timelineSignature = $"{timelineGroup}|{eventName}|{actor}|{view.EventThreadId}|{summary}";
                bool duplicateTimelineEvent =
                    string.Equals(_lastEtwTimelineSignature, timelineSignature, StringComparison.OrdinalIgnoreCase) &&
                    (view.TimestampUtc - _lastEtwTimelineTimestampUtc).TotalMilliseconds <= 900;
                if (keepEtw && !duplicateTimelineEvent)
                {
                    int timelinePid =
                        view.EventProcessId == 0 ? unchecked((int)actor) : unchecked((int)view.EventProcessId);
                    timelineEvents.Add(new TelemetryEvent { TimestampUtc = view.TimestampUtc, PID = timelinePid,
                                                            TID = unchecked((int)view.EventThreadId),
                                                            Group = timelineGroup, SubType = timelineSubtype,
                                                            Summary = summary, Details = view.DisplayDetails });
                    _lastEtwTimelineSignature = timelineSignature;
                    _lastEtwTimelineTimestampUtc = view.TimestampUtc;
                }

                HeuristicEventView? heuristic = CreatePromotedHeuristic(view);
                if (heuristic != null)
                {
                    heuristics.Add(heuristic);
                }

                if (ShouldPersistEtwView(view, keepEtw, relation != null, heuristic != null, apiTimelineEvent != null))
                {
                    AppendEtwToCaptureStore(view);
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
            if (EventDetailFormatting.IsKernelHookTelemetry(view))
            {
                string api = !string.IsNullOrWhiteSpace(view.Operation) ? view.Operation : view.EventName;
                DiagnosticsState.SetValue("Kernel Hooks",
                                          string.IsNullOrWhiteSpace(api) ? "Active" : $"Active ({api})");
                return;
            }

            if (EventDetailFormatting.IsUsermodeSensorTelemetry(view))
            {
                string kind = EventDetailFormatting.HookKindName(view.NotifyClass);
                DiagnosticsState.SetValue("Usermode Hooks", $"Active ({kind})");
                if (string.Equals(DiagnosticsState.GetValue("Hook Integrity"), "Unknown",
                                  StringComparison.OrdinalIgnoreCase))
                {
                    DiagnosticsState.SetValue("Hook Integrity", "OK");
                }
                if (string.Equals(DiagnosticsState.GetValue("AMSI Integrity"), "Unknown",
                                  StringComparison.OrdinalIgnoreCase))
                {
                    DiagnosticsState.SetValue("AMSI Integrity", "OK");
                }
            }
        }

        private HeuristicEventView? CreatePromotedHeuristic(BrokerEtwEventView view)
        {
            string detection = view.DetectionName;
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
            if (IsDirectSyscallDetection(detection) && hasEvidence &&
                !ShouldKeepDirectSyscallHeuristicFromEvidence(evidence))
            {
                return null;
            }

            string rawCorrFlagsSuffix = view.CorrelationFlags == sanitizedCorrFlags
                                            ? string.Empty
                                            : $"; rawCorrFlags=0x{view.CorrelationFlags:X8}";

            return new HeuristicEventView {
                TimestampUtc = view.TimestampUtc,
                LastSeenUtc = view.TimestampUtc,
                Severity = view.Severity,
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
            string key = BuildApiGraphKey(sourcePid, targetPid, threadId, apiName, sensorOrigin, callerOrigin);
            int currentHits;
            if (_apiGraphRowsByKey.TryGetValue(key, out ApiCallGraphRowSnapshot? existing))
            {
                existing.Hits = Math.Max(1, existing.Hits + 1);
                existing.LastSeenUtc = view.TimestampUtc;
                existing.SensorOrigin = sensorOrigin;
                existing.CallerOrigin = callerOrigin;
                currentHits = existing.Hits;
            }
            else
            {
                _apiGraphRowsByKey[key] = new ApiCallGraphRowSnapshot { ApiName = apiName,
                                                                        SensorOrigin = sensorOrigin,
                                                                        CallerOrigin = callerOrigin,
                                                                        SourcePid = sourcePid,
                                                                        TargetPid = targetPid,
                                                                        ThreadId = threadId,
                                                                        Hits = 1,
                                                                        LastSeenUtc = view.TimestampUtc };
                currentHits = 1;
            }

            string rawReason = view.Reason ?? string.Empty;
            _apiGraphReasonByKey[key] = rawReason;
            (string decodedAction, string decodedDetail) = BuildApiDecodedAction(view, rawReason);
            _apiGraphActionByKey[key] = decodedAction;
            _apiGraphDecodedByKey[key] = decodedDetail;
            _apiGraphFramesByKey[key] = BuildHookFrameSummary(view, BuildHookFieldMap(view));
            _apiGraphSensorByKey[key] = sensorOrigin;
            _apiGraphViewByKey[key] = view.Clone();

            ScheduleApiGraphSnapshot();
            if (string.IsNullOrWhiteSpace(view.Details))
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
            var snapshot =
                _apiGraphRowsByKey.Values
                    .Select(x => new ApiCallGraphRowSnapshot { ApiName = x.ApiName, SensorOrigin = x.SensorOrigin,
                                                               CallerOrigin = x.CallerOrigin, SourcePid = x.SourcePid,
                                                               TargetPid = x.TargetPid, ThreadId = x.ThreadId,
                                                               Hits = x.Hits, LastSeenUtc = x.LastSeenUtc })
                    .OrderByDescending(x => x.Hits)
                    .ThenByDescending(x => x.LastSeenUtc)
                    .Take(400)
                    .ToList();

            int maxHits = Math.Max(1, snapshot.Count == 0 ? 1 : snapshot.Max(x => Math.Max(1, x.Hits)));
            var rows = new List<ApiCallGraphMainRowView>(snapshot.Count);
            foreach (ApiCallGraphRowSnapshot row in snapshot)
            {
                uint target = row.TargetPid != 0 ? row.TargetPid : row.SourcePid;
                string sensor = string.IsNullOrWhiteSpace(row.SensorOrigin) ? "Unclassified" : row.SensorOrigin;
                string callerOrigin = NormalizeApiCallerOrigin(row.CallerOrigin);
                string key =
                    BuildApiGraphKey(row.SourcePid, row.TargetPid, row.ThreadId, row.ApiName, sensor, callerOrigin);
                double heatPercent = Math.Clamp((row.Hits / (double)maxHits) * 100.0, 0.0, 100.0);
                string rawReason = _apiGraphReasonByKey.TryGetValue(key, out string? reason) ? reason : string.Empty;
                string decodedAction = _apiGraphActionByKey.TryGetValue(key, out string? action)
                    ? action
                    : BuildGenericApiActionLabel(row.ApiName, ParseReasonFields(rawReason));
                string decodedDetail = _apiGraphDecodedByKey.TryGetValue(key, out string? detail)
                    ? detail
                    : BuildFallbackApiDetail(row.ApiName, rawReason, decodedAction);
                sensor = _apiGraphSensorByKey.TryGetValue(key, out string? sensorLabel) ? sensorLabel : sensor;
                BrokerEtwEventView? rowView = FindApiGraphViewForKey(key);
                ApiCallStructuredFields structured =
                    BuildApiCallStructuredFields(row.ApiName, rawReason, decodedAction, rowView);
                Dictionary<string, string> reasonFields = ParseReasonFields(rawReason);
                string frameSummary = _apiGraphFramesByKey.TryGetValue(key, out string? storedFrameSummary)
                    ? storedFrameSummary
                    : BuildHookFrameSummary(reasonFields);
                string sourceLabel = FormatApiProcessLabel(row.SourcePid);
                string targetLabel = FormatApiProcessLabel(target);
                rows.Add(new ApiCallGraphMainRowView {
                    GraphKey = key,
                    ApiName = string.IsNullOrWhiteSpace(row.ApiName) ? "unknown" : row.ApiName,
                    ActionLabel = structured.Action,
                    SensorLabel = sensor,
                    CallerOriginKey = callerOrigin,
                    CallerOriginLabel = GetApiCallerOriginDisplayLabel(callerOrigin, sensor),
                    CallChainLabel = frameSummary,
                    CallerOriginBackground = BuildApiCallerOriginBackground(callerOrigin),
                    CallerOriginForeground = BuildApiCallerOriginForeground(callerOrigin),
                    SensorBackground = BuildApiSensorBackground(sensor),
                    SensorForeground = BuildApiSensorForeground(sensor),
                    HeatTrackBackground = BuildApiHeatTrackBackground(sensor, callerOrigin),
                    HeatFillBackground = BuildApiHeatFillBackground(sensor, callerOrigin),
                    RowBackground = BuildApiRowBackground(sensor, callerOrigin),
                    RowBorderBrush = BuildApiRowBorder(sensor, callerOrigin),
                    SourceLabel = sourceLabel,
                    TargetLabel = targetLabel,
                    ThreadLabel =
                        row.ThreadId == 0 ? string.Empty : row.ThreadId.ToString(CultureInfo.InvariantCulture),
                    BaseLabel = structured.Field1Value,
                    SizeLabel = structured.Field2Value,
                    AllocTypeLabel = structured.Field3Value,
                    ProtectLabel = structured.Field4Value,
                    Field2Label = structured.Field2Label,
                    Field4Label = structured.Field4Label,
                    Hits = Math.Max(1, row.Hits),
                    HeatPercent = heatPercent,
                    ActivityFillWidth = Math.Round((heatPercent / 100.0) * 110.0),
                    LastSeen = FormatApiRelativeAge(row.LastSeenUtc),
                    AbsoluteLastSeen = row.LastSeenUtc == default
                                           ? string.Empty
                                           : row.LastSeenUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss.fff",
                                                                                    CultureInfo.InvariantCulture),
                    LastSeenUtc = row.LastSeenUtc,
                    DetailFull = decodedDetail
                });
            }

            _apiGraphSnapshotRows.Clear();
            _apiGraphSnapshotRows.AddRange(snapshot);
            _apiViewSnapshotRows.Clear();
            _apiViewSnapshotRows.AddRange(rows);
            RefreshApiViewPresentation();
        }

        private void RefreshApiViewPresentation()
        {
            string? selectedKey = (ApiViewDataGrid?.SelectedItem as ApiCallGraphMainRowView)?.GraphKey;
            bool apiViewVisible = _mainViewMode == MainInterfaceViewMode.Api && ApiViewBorder != null &&
                                  ApiViewBorder.Visibility == Visibility.Visible;
            List<ApiCallGraphMainRowView> filteredRows = ApplyApiViewFilters(_apiViewSnapshotRows);
            _apiViewRows.ReplaceAll(filteredRows);

            var filteredKeys = new HashSet<string>(filteredRows.Select(x => x.GraphKey), StringComparer.Ordinal);
            List<ApiCallGraphRowSnapshot> filteredSnapshot =
                _apiGraphSnapshotRows
                    .Where(row =>
                           {
                               string sensor =
                                   string.IsNullOrWhiteSpace(row.SensorOrigin) ? "Unclassified" : row.SensorOrigin;
                               string callerOrigin = NormalizeApiCallerOrigin(row.CallerOrigin);
                               string key = BuildApiGraphKey(row.SourcePid, row.TargetPid, row.ThreadId, row.ApiName,
                                                             sensor, callerOrigin);
                               return filteredKeys.Contains(key);
                           })
                    .OrderByDescending(x => x.Hits)
                    .ThenByDescending(x => x.LastSeenUtc)
                    .ToList();

            if (ApiViewSummaryBlock != null)
            {
                ApiViewSummaryBlock.Text =
                    _apiGraphSnapshotRows.Count == 0 ? "No API hook data yet"
                    : filteredRows.Count == _apiViewSnapshotRows.Count
                        ? $"Patterns: {filteredRows.Count} / Calls: {filteredRows.Sum(x => x.Hits)}"
                        : $"Patterns: {filteredRows.Count}/{_apiViewSnapshotRows.Count} / Calls: {filteredRows.Sum(x => x.Hits)}";
            }
            if (apiViewVisible && ApiViewGraphCanvas != null)
            {
                RenderApiGraphCanvas(filteredSnapshot, selectedKey);
            }
            DiagnosticsState.SetValue(
                "API Graph", $"patterns={filteredRows.Count}/{_apiViewSnapshotRows.Count} visible={apiViewVisible}");

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
            var filteredKeys = new HashSet<string>(filteredRows.Select(x => x.GraphKey), StringComparer.Ordinal);
            List<ApiCallGraphRowSnapshot> filteredSnapshot =
                _apiGraphSnapshotRows
                    .Where(row =>
                           {
                               string sensor =
                                   string.IsNullOrWhiteSpace(row.SensorOrigin) ? "Unclassified" : row.SensorOrigin;
                               string callerOrigin = NormalizeApiCallerOrigin(row.CallerOrigin);
                               string key = BuildApiGraphKey(row.SourcePid, row.TargetPid, row.ThreadId, row.ApiName,
                                                             sensor, callerOrigin);
                               return filteredKeys.Contains(key);
                           })
                    .OrderByDescending(x => x.Hits)
                    .ThenByDescending(x => x.LastSeenUtc)
                    .ToList();

            RenderApiGraphCanvas(filteredSnapshot, selectedKey);
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

        private BrokerEtwEventView? FindApiGraphViewForKey(string key)
        {
            return _apiGraphViewByKey.TryGetValue(key, out BrokerEtwEventView? view) ? view : null;
        }

        private static ApiCallStructuredFields
        BuildApiCallStructuredFields(string apiName, string rawReason, string decodedAction, BrokerEtwEventView? view)
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
                field1Value = baseAddress == 0 ? string.Empty : $"0x{baseAddress:X}";
                field2Value = regionSize == 0
                                  ? string.Empty
                                  : $"base={(baseAddress == 0 ? "?" : $"0x{baseAddress:X}")}  size=0x{regionSize:X}";
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
                field1Value = baseAddress == 0 ? string.Empty : $"0x{baseAddress:X}";
                field2Value = regionSize == 0
                                  ? string.Empty
                                  : $"base={(baseAddress == 0 ? "?" : $"0x{baseAddress:X}")}  size=0x{regionSize:X}";
                field4Value = protect == 0 ? string.Empty : $"0x{protect:X} {DescribeMemoryProtect(protect)}";
            }
            else if (apiName.Equals("NtWriteVirtualMemory", StringComparison.OrdinalIgnoreCase) ||
                     apiName.Equals("NtReadVirtualMemory", StringComparison.OrdinalIgnoreCase))
            {
                ulong baseAddress = FirstU64(fields, "base", "c0", "a1");
                ulong regionSize = FirstU64(fields, "size", "c1", "a3");
                field1Value = baseAddress == 0 ? string.Empty : $"0x{baseAddress:X}";
                field2Value = regionSize == 0
                                  ? string.Empty
                                  : $"base={(baseAddress == 0 ? "?" : $"0x{baseAddress:X}")}  size=0x{regionSize:X}";
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
                field1Value = baseAddress == 0 ? string.Empty : $"0x{baseAddress:X}";
                field2Value = apiName.Equals("RtlDeleteFunctionTable", StringComparison.OrdinalIgnoreCase)
                                  ? $"table=0x{FirstU64(fields, "table", "a0"):X}"
                                  : $"table=0x{FirstU64(fields, "tableId", "table", "a0"):X}";
                field3Value = length == 0 ? string.Empty : $"0x{length:X}";
                field4Value = callback == 0 ? string.Empty : $"0x{callback:X}";
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
                    string key =
                        BuildApiGraphKey(row.SourcePid, row.TargetPid, row.ThreadId, row.ApiName, sensor, callerOrigin);
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
                string rowKey =
                    BuildApiGraphKey(row.SourcePid, row.TargetPid, row.ThreadId, row.ApiName, sensor, callerOrigin);
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
                                               string sensorOrigin, string callerOrigin) =>
            $"{sourcePid}|{targetPid}|{threadId}|{apiName}|{sensorOrigin}|{callerOrigin}";

        private static string NormalizeApiCallerOrigin(string? callerOrigin)
        {
            string normalized = (callerOrigin ?? string.Empty).Trim().ToLowerInvariant();
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
                if (fields.TryGetValue(symbolKey, out string? symbolValue) && !string.IsNullOrWhiteSpace(symbolValue))
                {
                    AddFrameText(symbolValue);
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
                !string.IsNullOrWhiteSpace(originSymbol))
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

        private static string BuildHookFrameSummary(BrokerEtwEventView view, IReadOnlyDictionary<string, string> fields)
        {
            var sb = new StringBuilder(512);
            string sensor = EventDetailFormatting.ClassifyHookSensorOrigin(view);
            string origin = GetApiCallerOriginDisplayLabel(NormalizeApiCallerOrigin(view.CallerOriginLabel), sensor);
            string immediate = EventDetailFormatting.HookImmediateCallerLabel(view.Flags);
            string deepOrigin = EventDetailFormatting.HookDeepOriginLabel(view.Flags);
            string originModule = ResolveHookOriginModule(view, fields);
            string resolvedReturnAddress = ResolveHookReturnAddressLabel(view, fields, originModule);
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
                }
            }

            if (!string.IsNullOrWhiteSpace(view.OriginPath))
            {
                sb.Append("Origin Path: ").AppendLine(view.OriginPath.Trim());
            }

            return sb.ToString().TrimEnd();
        }

        private static string ResolveHookOriginModule(BrokerEtwEventView view,
                                                      IReadOnlyDictionary<string, string> fields)
        {
            string originModule = EventDetailFormatting.ModuleNameFromPath(view.OriginPath);
            if (!string.Equals(originModule, "unknown", StringComparison.OrdinalIgnoreCase))
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

                return trimmed;
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
                return originSymbol.Trim();
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
                view.Source = "Blackbird";
                view.SourceId = BlackbirdNative.IpcEtwSourceBlackbird;
                view.Family = BlackbirdNative.IpcEtwFamilyUserHook;
            }

            return BuildHookFrameSummary(view, fields);
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
            string argumentText = BuildResolvedHookArgumentsText(apiName, fields);
            bool hasStartupContext =
                TryDescribeHookStartupContext(view, out string startupHeadline, out string startupDetail);

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
                if (hasStartupContext)
                {
                    action += " [startup]";
                    detail =
                        $"{startupHeadline}{Environment.NewLine}{startupDetail}{Environment.NewLine}{Environment.NewLine}{detail}";
                }
            }
            else
            {
                var sb = new StringBuilder(512);
                sb.AppendLine(action);
                if (hasStartupContext)
                {
                    action += " [startup]";
                    sb.AppendLine().AppendLine(startupHeadline);
                    sb.AppendLine(startupDetail);
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
                                      Math.Abs(state.LastEntropyBits - entropy) >= 0.55;
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
            bool threadStartObserved = false;
            bool functionTableRegistered = false;
            ulong functionTablePointer = 0;

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
                }
                else if (apiName.Equals("NtMapViewOfSection", StringComparison.OrdinalIgnoreCase) ||
                         apiName.Equals("NtMapViewOfSectionEx", StringComparison.OrdinalIgnoreCase))
                {
                    eventKind = "SectionMap";
                    regionKind = "Mapped";
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
                RegionKind = string.IsNullOrWhiteSpace(regionKind) ? InferRegionKind(view, currentProtection) : regionKind,
                RegionIdentity = regionIdentity,
                OriginPath = view.OriginPath ?? view.ImagePath ?? string.Empty,
                CallerOrigin = view.CallerOriginLabel,
                FirstUserFrame = view.OriginAddress,
                FirstUserFrameModule = firstUserFrameModule,
                FrameSummary = frameSummary,
                UnwindClean = hookFamily && IsHookUnwindClean(view.Flags),
                FrameChainHadGaps = hookFamily && HookFrameChainHasGaps(view.Flags),
                InitialProtection = initialProtection,
                CurrentProtection = currentProtection,
                PreviousProtection = previousProtection,
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

            if (sample.PreviousProtection == 0 && state.CurrentProtection != 0 &&
                (sample.EventKind.Equals("ProtectChange", StringComparison.OrdinalIgnoreCase) ||
                 sample.EventKind.Equals("SectionMap", StringComparison.OrdinalIgnoreCase) ||
                 sample.EventKind.Equals("ImageMap", StringComparison.OrdinalIgnoreCase)))
            {
                sample.PreviousProtection = state.CurrentProtection;
            }

            if (sample.CurrentProtection != 0)
            {
                bool executableNow = IsExecutableProtection(sample.CurrentProtection);
                bool executableBefore = IsExecutableProtection(
                    sample.PreviousProtection != 0 ? sample.PreviousProtection : state.CurrentProtection);
                if (!state.FirstExecutableTransitionSeen && executableNow && !executableBefore)
                {
                    sample.FirstExecutableTransition = true;
                    state.FirstExecutableTransitionSeen = true;
                }

                if (state.InitialProtection == 0)
                {
                    state.InitialProtection = sample.CurrentProtection;
                }
                state.CurrentProtection = sample.CurrentProtection;
            }

            if (sample.ThreadStartObserved)
            {
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
            return sample;
        }

        private uint ResolveMemoryRegionTargetPid(BrokerEtwEventView view)
        {
            return view.Family switch {
                BlackbirdNative.IpcEtwFamilyImage => view.ProcessPid != 0 ? view.ProcessPid : view.EventProcessId,
                BlackbirdNative.IpcEtwFamilyThread =>
                    view.ProcessPid != 0 ? view.ProcessPid : (view.TargetPid != 0 ? view.TargetPid : view.EventProcessId),
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

        private static string BuildRegionIdentity(ulong processStartKey, uint targetPid, ulong allocationBase)
            => $"{targetPid:X8}:{processStartKey:X16}:{allocationBase:X16}";

        private static string BuildFunctionTablePointerKey(uint pid, ulong functionTable)
            => $"{pid:X8}:{functionTable:X16}";

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

        private static ulong NormalizeRegionAddress(ulong address)
            => address == 0 ? 0 : (address & ~0xFFFUL);

        private static bool IsExecutableProtection(uint protection)
        {
            uint normalized = protection & 0xFFu;
            return normalized == 0x10u || normalized == 0x20u || normalized == 0x40u || normalized == 0x80u;
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
                                        _ => false };
        }

        private static bool IsCriticalIoctlRecord(IoctlParsedEvent record)
        {
            return record.Type switch { BlackbirdNative.EventTypeHandle => IsCriticalHandleIoctl(record),
                                        BlackbirdNative.EventTypeThread => IsCriticalThreadIoctl(record),
                                        BlackbirdNative.EventTypeFileSystem => IsCriticalFilesystemIoctl(record),
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

        private string BuildFallbackApiDetail(string apiName, string rawReason, string action)
        {
            Dictionary<string, string> fields = BuildHookFieldMap(rawReason, Array.Empty<ulong>(), 0);
            string argumentText = BuildResolvedHookArgumentsText(apiName, fields);
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
                TryDescribeHookStartupContext(view, out string startupHeadline, out string startupDetail))
            {
                sb.Append(startupHeadline).Append(": ").AppendLine(startupDetail);
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
            var fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            if (string.IsNullOrWhiteSpace(rawReason))
            {
                return fields;
            }

            foreach (string token in rawReason.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries))
            {
                int sep = token.IndexOf('=');
                if (sep <= 0 || sep >= token.Length - 1)
                {
                    continue;
                }

                string key = token[..sep].Trim();
                string value = token[(sep + 1)..].Trim().TrimEnd(',', ';');
                if (key.Length == 0)
                {
                    continue;
                }

                fields[key] = value;
            }

            return fields;
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

        private static Dictionary<string, string> BuildHookFieldMap(BrokerEtwEventView view) =>
            BuildHookFieldMap(view.Reason ?? string.Empty, view.HookArgs, view.HookArgCount);

        private static string BuildResolvedHookArgumentsText(string apiName, IReadOnlyDictionary<string, string> fields)
        {
            List<(string Name, string Value)> args = ResolveHookArguments(apiName, fields);
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

        private static List<(string Name, string Value)>
        ResolveHookArguments(string apiName, IReadOnlyDictionary<string, string> fields)
        {
            string name = apiName?.Trim() ?? string.Empty;
            var args = new List<(string Name, string Value)>(8);

            switch (name)
            {
            case "NtWriteVirtualMemory":
                AddResolvedArg(args, "ProcessHandle", ResolvePointer(fields, "a0", "c0"));
                AddResolvedArg(args, "BaseAddress", ResolvePointer(fields, "a1", "c1", "base"));
                AddResolvedArg(args, "Buffer", ResolvePointer(fields, "a2", "c2"));
                AddResolvedArg(args, "BufferSize", ResolveSize(fields, "a3", "c3", "size"));
                AddResolvedArg(args, "BytesWritten", ResolveSize(fields, "a4", "c4"));
                break;
            case "NtReadVirtualMemory":
                AddResolvedArg(args, "ProcessHandle", ResolvePointer(fields, "a0", "c0"));
                AddResolvedArg(args, "BaseAddress", ResolvePointer(fields, "a1", "c1", "base"));
                AddResolvedArg(args, "Buffer", ResolvePointer(fields, "a2", "c2"));
                AddResolvedArg(args, "BufferSize", ResolveSize(fields, "a3", "c3", "size"));
                AddResolvedArg(args, "BytesRead", ResolveSize(fields, "a4", "c4"));
                break;
            case "NtAllocateVirtualMemory":
                AddResolvedArg(args, "ProcessHandle", ResolvePointer(fields, "a0", "c0"));
                AddResolvedArg(args, "BaseAddress*", ResolvePointer(fields, "a1", "c1", "base"));
                AddResolvedArg(args, "ZeroBits", ResolveHex(fields, "a2", "c2"));
                AddResolvedArg(args, "RegionSize*", ResolveSize(fields, "a3", "c3", "size"));
                AddResolvedArg(args, "AllocationType", ResolveAllocationType(fields, "a4", "c4", "allocType"));
                AddResolvedArg(args, "Protect", ResolveProtect(fields, "a5", "c5", "protect"));
                break;
            case "NtAllocateVirtualMemoryEx":
                AddResolvedArg(args, "ProcessHandle", ResolvePointer(fields, "a0", "c0"));
                AddResolvedArg(args, "BaseAddress*", ResolvePointer(fields, "a1", "c1", "base"));
                AddResolvedArg(args, "ZeroBits", ResolveHex(fields, "a2", "c2"));
                AddResolvedArg(args, "RegionSize*", ResolveSize(fields, "a3", "c3", "size"));
                AddResolvedArg(args, "AllocationType", ResolveAllocationType(fields, "a4", "c4", "allocType"));
                AddResolvedArg(args, "ExtendedParameters", ResolvePointer(fields, "a5", "c5"));
                AddResolvedArg(args, "ExtendedParameterCount", ResolveHex(fields, "a6", "c6"));
                break;
            case "NtProtectVirtualMemory":
                AddResolvedArg(args, "ProcessHandle", ResolvePointer(fields, "a0", "c0"));
                AddResolvedArg(args, "BaseAddress*", ResolvePointer(fields, "a1", "c1", "base"));
                AddResolvedArg(args, "RegionSize*", ResolveSize(fields, "a2", "c2", "size"));
                AddResolvedArg(args, "NewProtect", ResolveProtect(fields, "a3", "c3", "newProtect"));
                AddResolvedArg(args, "OldProtect*", ResolvePointer(fields, "a4", "c4"));
                break;
            case "NtCreateSection":
                AddResolvedArg(args, "SectionHandle*", ResolvePointer(fields, "a0", "c0"));
                AddResolvedArg(args, "DesiredAccess", ResolveHex(fields, "a1", "c1"));
                AddResolvedArg(args, "ObjectAttributes", ResolvePointer(fields, "a2", "c2"));
                AddResolvedArg(args, "MaximumSize", ResolveSize(fields, "a3", "c3"));
                AddResolvedArg(args, "SectionPageProtection", ResolveProtect(fields, "a4", "c4"));
                AddResolvedArg(args, "AllocationAttributes", ResolveHex(fields, "a5", "c5"));
                AddResolvedArg(args, "FileHandle", ResolvePointer(fields, "a6", "c6"));
                break;
            case "NtMapViewOfSection":
                AddResolvedArg(args, "SectionHandle", ResolvePointer(fields, "a0", "c0"));
                AddResolvedArg(args, "ProcessHandle", ResolvePointer(fields, "a1", "c1"));
                AddResolvedArg(args, "BaseAddress*", ResolvePointer(fields, "a2", "c2", "base"));
                AddResolvedArg(args, "ViewSize*", ResolveSize(fields, "a6", "c3", "size"));
                AddResolvedArg(args, "InheritDisposition", ResolveHex(fields, "a7", "c4"));
                AddResolvedArg(args, "AllocationType", ResolveAllocationType(fields, "c5"));
                AddResolvedArg(args, "Win32Protect", ResolveProtect(fields, "c6"));
                break;
            case "NtMapViewOfSectionEx":
                AddResolvedArg(args, "SectionHandle", ResolvePointer(fields, "a0", "c0"));
                AddResolvedArg(args, "ProcessHandle", ResolvePointer(fields, "a1", "c1"));
                AddResolvedArg(args, "BaseAddress*", ResolvePointer(fields, "a2", "c2", "base"));
                AddResolvedArg(args, "SectionOffset*", ResolvePointer(fields, "a3", "c7"));
                AddResolvedArg(args, "ViewSize*", ResolveSize(fields, "a4", "c3", "size"));
                AddResolvedArg(args, "AllocationType", ResolveAllocationType(fields, "a5", "c4"));
                AddResolvedArg(args, "Win32Protect", ResolveProtect(fields, "a6", "c5"));
                AddResolvedArg(args, "ExtendedParameters", ResolvePointer(fields, "a7", "c6"));
                break;
            case "NtQueryInformationProcess":
                AddResolvedArg(args, "ProcessHandle", ResolvePointer(fields, "a0", "c0"));
                AddResolvedArg(args, "ProcessInformationClass", ResolveProcessInformationClass(fields, "a1", "c1"));
                AddResolvedArg(args, "ProcessInformation", ResolvePointer(fields, "a2", "c2"));
                AddResolvedArg(args, "ProcessInformationLength", ResolveSize(fields, "a3", "c3"));
                AddResolvedArg(args, "ReturnLength", ResolvePointer(fields, "a4", "c4"));
                break;
            case "NtQuerySystemInformation":
            case "NtQuerySystemInformationEx":
                AddResolvedArg(args, "SystemInformationClass", ResolveSystemInformationClass(fields, "a0", "c0"));
                AddResolvedArg(args, "InputBuffer", ResolvePointer(fields, "a1", "c1"));
                AddResolvedArg(args, "InputBufferLength", ResolveSize(fields, "a2", "c2"));
                AddResolvedArg(args, "SystemInformation", ResolvePointer(fields, "a3", "c3"));
                AddResolvedArg(args, "SystemInformationLength", ResolveSize(fields, "a4", "c4"));
                AddResolvedArg(args, "ReturnLength", ResolvePointer(fields, "a5", "c5"));
                break;
            case "NtCreateThreadEx":
                AddResolvedArg(args, "ThreadHandle*", ResolvePointer(fields, "a0", "c0"));
                AddResolvedArg(args, "DesiredAccess", ResolveHex(fields, "a1", "c1"));
                AddResolvedArg(args, "ProcessHandle", ResolvePointer(fields, "a2", "c2"));
                AddResolvedArg(args, "StartRoutine", ResolvePointer(fields, "a3", "c3"));
                AddResolvedArg(args, "Argument", ResolvePointer(fields, "a4", "c4"));
                AddResolvedArg(args, "CreateFlags", ResolveHex(fields, "a5", "c5"));
                AddResolvedArg(args, "StackSize", ResolveSize(fields, "a6", "c6"));
                AddResolvedArg(args, "MaximumStackSize", ResolveSize(fields, "a7", "c7"));
                break;
            case "RtlAddFunctionTable":
                AddResolvedArg(args, "FunctionTable", ResolvePointer(fields, "a0"));
                AddResolvedArg(args, "EntryCount", ResolveHex(fields, "a1"));
                AddResolvedArg(args, "BaseAddress", ResolvePointer(fields, "a2", "baseAddress"));
                break;
            case "RtlInstallFunctionTableCallback":
                AddResolvedArg(args, "TableIdentifier", ResolvePointer(fields, "a0"));
                AddResolvedArg(args, "BaseAddress", ResolvePointer(fields, "a1", "baseAddress"));
                AddResolvedArg(args, "Length", ResolveSize(fields, "a2", "length"));
                AddResolvedArg(args, "Callback", ResolvePointer(fields, "a3", "callback"));
                break;
            case "RtlDeleteFunctionTable":
                AddResolvedArg(args, "FunctionTable", ResolvePointer(fields, "a0", "table"));
                break;
            default:
                for (int i = 0; i < 8; i += 1)
                {
                    string value = ResolveHex(fields, $"a{i}", $"c{i}");
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

        private static string ResolvePointer(IReadOnlyDictionary<string, string> fields,
                                             params string[] keys) => ResolveHex(fields, keys);

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
            internal BrokerEtwEventView? EtwView { get; }
            internal string? StatusLine { get; }

            private BackendUiWorkItem(BackendUiWorkKind kind, TelemetryEvent? telemetry, ProcessRelationView? relation,
                                      HeuristicEventView? heuristic, ThreadLifecycleEventSample? threadLifecycle,
                                      IoctlParsedEvent? filesystem, BrokerEtwEventView? etwView, string? statusLine)
            {
                Kind = kind;
                Telemetry = telemetry;
                Relation = relation;
                Heuristic = heuristic;
                ThreadLifecycle = threadLifecycle;
                Filesystem = filesystem;
                EtwView = etwView;
                StatusLine = statusLine;
            }

            internal static BackendUiWorkItem
                FromIoctl(TelemetryEvent? telemetry, ProcessRelationView? relation, HeuristicEventView? heuristic,
                          ThreadLifecycleEventSample? threadLifecycle,
                          IoctlParsedEvent? filesystem) => new(BackendUiWorkKind.Ioctl, telemetry, relation, heuristic,
                                                               threadLifecycle, filesystem, null, null);

            internal static BackendUiWorkItem FromEtw(BrokerEtwEventView etwView) => new(BackendUiWorkKind.Etw, null,
                                                                                         null, null, null, null,
                                                                                         etwView, null);

            internal static BackendUiWorkItem FromStatus(string statusLine) => new(BackendUiWorkKind.Status, null, null,
                                                                                   null, null, null, null, statusLine);
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
            _relationsHistoryByPid[pid] = ProcessRelationsPaneHost.SnapshotItems().Select(x => x.Clone()).ToList();
            _apiGraphHistoryByPid[pid] =
                _apiGraphRowsByKey.Values
                    .Select(x => new ApiCallGraphRowSnapshot { ApiName = x.ApiName, SensorOrigin = x.SensorOrigin,
                                                               SourcePid = x.SourcePid, TargetPid = x.TargetPid,
                                                               ThreadId = x.ThreadId, Hits = x.Hits,
                                                               LastSeenUtc = x.LastSeenUtc })
                    .ToList();
        }

        private void RestoreIntelSessionState(int pid)
        {
            IEnumerable<GroupedEventRow> etw =
                _etwHistoryByPid.TryGetValue(pid, out var a) ? a : Array.Empty<GroupedEventRow>();
            IEnumerable<GroupedEventRow> heur =
                _heuristicsHistoryByPid.TryGetValue(pid, out var c) ? c : Array.Empty<GroupedEventRow>();
            IEnumerable<GroupedEventRow> fs =
                _filesystemHistoryByPid.TryGetValue(pid, out var d) ? d : Array.Empty<GroupedEventRow>();
            IEnumerable<GroupedEventRow> rel =
                _relationsHistoryByPid.TryGetValue(pid, out var e) ? e : Array.Empty<GroupedEventRow>();
            IEnumerable<ApiCallGraphRowSnapshot> apiGraph =
                _apiGraphHistoryByPid.TryGetValue(pid, out var f) ? f : Array.Empty<ApiCallGraphRowSnapshot>();

            EtwPaneHost.LoadHistory(etw.Select(x => x.Clone()).ToList());
            HeuristicsPaneHost.LoadHistory(heur.Select(x => x.Clone()).ToList());
            FilesystemPaneHost.LoadHistory(fs.Select(x => x.Clone()).ToList());
            ProcessRelationsPaneHost.SetRootPid(pid);
            ProcessRelationsPaneHost.LoadHistory(rel.Select(x => x.Clone()).ToList());
            _apiGraphRowsByKey.Clear();
            _apiGraphReasonByKey.Clear();
            _apiGraphActionByKey.Clear();
            _apiGraphDecodedByKey.Clear();
            _apiGraphFramesByKey.Clear();
            _apiGraphSensorByKey.Clear();
            _apiGraphTimelineLastEmitByKey.Clear();
            _apiMemorySignalsByPage.Clear();
            _crossProcWriteCountByPair.Clear();
            _crossProcRwxAllocCountByPair.Clear();
            foreach (ApiCallGraphRowSnapshot row in apiGraph)
            {
                string sensorOrigin = string.IsNullOrWhiteSpace(row.SensorOrigin) ? "Unclassified" : row.SensorOrigin;
                string callerOrigin = NormalizeApiCallerOrigin(row.CallerOrigin);
                string key = BuildApiGraphKey(row.SourcePid, row.TargetPid, row.ThreadId, row.ApiName, sensorOrigin,
                                              callerOrigin);
                _apiGraphRowsByKey[key] = new ApiCallGraphRowSnapshot {
                    ApiName = row.ApiName,     SensorOrigin = row.SensorOrigin, CallerOrigin = row.CallerOrigin,
                    SourcePid = row.SourcePid, TargetPid = row.TargetPid,       ThreadId = row.ThreadId,
                    Hits = row.Hits,           LastSeenUtc = row.LastSeenUtc
                };
                _apiGraphSensorByKey[key] = sensorOrigin;
            }
            PublishApiGraphSnapshot();
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
            BlackbirdPreflightReport report = await Task.Run(() => BlackbirdPreflight.Run(pid));
            _lastPreflight = report;
            OutputCapture.AppendLine($"Preflight: {report.Summary}");
            DiagnosticsState.SetValue("Driver Service", report.DriverState);
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

            if (!string.Equals(report.DriverState, "Running", StringComparison.OrdinalIgnoreCase))
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
            public uint InitialProtection { get; set; }
            public uint CurrentProtection { get; set; }
            public bool FirstExecutableTransitionSeen { get; set; }
            public bool FirstThreadStartSeen { get; set; }
            public ulong FirstThreadStartAddress { get; set; }
            public bool FunctionTableRegistered { get; set; }
        }
    }
}
