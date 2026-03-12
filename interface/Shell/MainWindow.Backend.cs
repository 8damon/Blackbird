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
using System.Windows.Threading;

namespace BlackbirdInterface
{
    public partial class MainWindow
    {
        private BlackbirdBackendSession? _backendSession;
        private int _backendGeneration;
        private readonly Dictionary<int, List<GroupedEventRow>> _etwHistoryByPid = new();
        private readonly Dictionary<int, List<GroupedEventRow>> _heuristicsHistoryByPid = new();
        private readonly Dictionary<int, List<GroupedEventRow>> _filesystemHistoryByPid = new();
        private readonly Dictionary<int, List<GroupedEventRow>> _relationsHistoryByPid = new();
        private readonly Dictionary<int, List<ApiCallGraphRowSnapshot>> _apiGraphHistoryByPid = new();
        private readonly Dictionary<string, ApiCallGraphRowSnapshot> _apiGraphRowsByKey = new(StringComparer.Ordinal);
        private readonly Dictionary<string, string> _apiGraphReasonByKey = new(StringComparer.Ordinal);
        private readonly Dictionary<string, string> _apiGraphActionByKey = new(StringComparer.Ordinal);
        private readonly Dictionary<string, string> _apiGraphDecodedByKey = new(StringComparer.Ordinal);
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
        private int _backendUiFlushScheduled;
        private const int MaxBackendTransformItemsPerBatch = 1500;
        private const int MaxBackendUiItemsPerFlush = 220;
        private const int MaxBackendStatusLinesPerTransformBatch = 64;
        private const int MaxBackendStatusLinesPerUiFlush = 32;
        private const int FilesystemTimelineClusterFlushCount = 600;
        private const uint CorrelationIntentMask = 0x00000007u;
        private static readonly TimeSpan BackendUiFlushBudget = TimeSpan.FromMilliseconds(5);
        private static readonly TimeSpan FilesystemTimelineClusterWindow = TimeSpan.FromMilliseconds(3000);
        private static readonly TimeSpan FilesystemTimelineClusterIdleFlush = TimeSpan.FromMilliseconds(1500);
        private string? _lastEtwTimelineSignature;
        private DateTime _lastEtwTimelineTimestampUtc;
        private readonly Dictionary<ulong, IoctlParsedEvent> _recentHandleEvidenceByPair = new();
        private DateTime _lastHandleEvidencePruneUtc = DateTime.MinValue;
        private readonly Dictionary<uint, int> _filesystemClusterOperationCounts = new();
        private readonly Dictionary<uint, (uint Pid, uint Tid, string Path)> _filesystemClusterSamplesByOperation = new();
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
            _apiMemorySignalsByPage.Clear();
            PublishApiGraphSnapshot();
            IpcUplinkPaneHost.SetInactive("No IPC diagnostics yet", "Enable uplink and wait for stats sample.");
            ResetFilesystemTimelineCluster();
            RefreshExplorerDataBadges();
            DiagnosticsState.SetValue("UI", "Initialized");
            DiagnosticsState.SetValue("Hook Integrity", "Unknown");
            DiagnosticsState.SetValue("AMSI Integrity", "Unknown");
            DiagnosticsState.SetValue("ETW Integrity", "Unknown");
        }

        private void StartBackendForPid(int pid, bool useUsermodeHooks)
        {
            BlackbirdBackendSession? preparedSession = null;

            StopBackendSession();
            ClearPendingBackendUiQueues();

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
            SetIpcUplinkExplorerDetails("Enable to inspect IPC internals", "Waiting for session diagnostics...", hasData: false);

            int generation = ++_backendGeneration;
            try
            {
                var session = preparedSession ?? BlackbirdBackendSession.Start(pid, BlackbirdNative.StreamAll, useUsermodeHooks);
                _backendSession = session;

                session.IoctlEvent += record =>
                {
                    if (generation != _backendGeneration)
                    {
                        return;
                    }

                    _pendingIoctlEvents.Enqueue(record);
                    Interlocked.Increment(ref _pendingIoctlCount);
                    _backendTransformSignal.Set();
                };

                session.EtwEvent += etw =>
                {
                    if (generation != _backendGeneration)
                    {
                        return;
                    }

                    _pendingEtwEvents.Enqueue(etw);
                    Interlocked.Increment(ref _pendingEtwCount);
                    _backendTransformSignal.Set();
                };

                session.Stats += stats => Dispatcher.BeginInvoke(new Action(() =>
                {
                    if (generation != _backendGeneration)
                    {
                        return;
                    }

                    DiagnosticsState.SetValue(
                        "Session Stats",
                        $"subs={stats.SubscriptionCount} depth={stats.QueueDepth} dropped={stats.DroppedEvents}");
                }));

                session.IpcDiagnostics += diag => Dispatcher.BeginInvoke(new Action(() =>
                {
                    if (generation != _backendGeneration)
                    {
                        return;
                    }

                    diag.PendingIoctlUiQueue = (int)Math.Min(int.MaxValue, Math.Max(0, Interlocked.Read(ref _pendingIoctlCount)));
                    diag.PendingEtwUiQueue = (int)Math.Min(int.MaxValue, Math.Max(0, Interlocked.Read(ref _pendingEtwCount)));
                    diag.PendingStatusUiQueue = (int)Math.Min(
                        int.MaxValue,
                        Math.Max(0, Interlocked.Read(ref _pendingStatusCount) + Interlocked.Read(ref _pendingUiWorkCount)));
                    UpdateIpcUplinkExplorer(diag);
                }));

                session.Status += text =>
                {
                    if (generation != _backendGeneration)
                    {
                        return;
                    }

                    _pendingStatusLines.Enqueue($"[session pid={pid}] {text}");
                    Interlocked.Increment(ref _pendingStatusCount);
                    _backendTransformSignal.Set();
                };

                StartBackendTransformLoop(generation);

                StatusBlock.Text = $"Status: Session active for PID {pid}";
                OutputCapture.AppendLine($"Session started for PID {pid}");
                DiagnosticsState.SetValue("Session", $"Active PID {pid}");
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
                return "IPC runtime DLL is outdated (missing export). Rebuild/deploy BlackbirdSensorCore.dll and controller.";
            }

            if (ex is System.ComponentModel.Win32Exception wx &&
                (wx.NativeErrorCode == 127 || wx.NativeErrorCode == BlackbirdNative.ErrorInvalidFunction))
            {
                return "IPC runtime DLL/controller mismatch (missing function). Rebuild/deploy latest BlackbirdSensorCore.dll and controller.";
            }

            return ex.Message;
        }

        private void StopBackendSession(bool preserveApiGraphSnapshot = false)
        {
            if (_backendSession == null)
            {
                StopBackendTransformLoop();
                ClearPendingBackendUiQueues();
                return;
            }

            try
            {
                _backendSession.Dispose();
            }
            catch
            {
            }

            _backendSession = null;
            StopBackendTransformLoop();
            ClearPendingBackendUiQueues();
            _lastEtwTimelineSignature = null;
            _lastEtwTimelineTimestampUtc = DateTime.MinValue;
            ResetFilesystemTimelineCluster();
            _hasIpcUplinkData = false;
            if (!preserveApiGraphSnapshot)
            {
                _apiGraphRowsByKey.Clear();
                _apiGraphReasonByKey.Clear();
                _apiGraphActionByKey.Clear();
                _apiGraphDecodedByKey.Clear();
                _apiMemorySignalsByPage.Clear();
                PublishApiGraphSnapshot();
            }
            SetIpcUplinkExplorerDetails("Session stopped", "No live IPC diagnostics", hasData: false);
            DiagnosticsState.SetValue("Session", "Stopped");
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
                task?.Wait(1200);
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
                    IReadOnlyList<TelemetryEvent> filesystemClusterEvents = AccumulateFilesystemTimelineCluster(ioctl, nowUtc);
                    if (filesystemClusterEvents.Count > 0)
                    {
                        for (int i = 0; i < filesystemClusterEvents.Count; i += 1)
                        {
                            _pendingUiWork.Enqueue(
                                BackendUiWorkItem.FromIoctl(filesystemClusterEvents[i], null, null, null, null));
                            Interlocked.Increment(ref _pendingUiWorkCount);
                        }
                        producedUiWork = true;
                    }

                    TelemetryEvent? telemetry = MapIoctlRecord(ioctl);
                    ProcessRelationView? relation = MapIoctlRelation(ioctl);
                    HeuristicEventView? heuristic = MapIoctlHeuristic(ioctl);
                    ThreadLifecycleEventSample? threadLifecycle = MapIoctlThreadLifecycle(ioctl);
                    IoctlParsedEvent? filesystem = MapIoctlFilesystem(ioctl);
                    if (relation != null)
                    {
                        ProcessIdentityResolver.Prime(relation.SourcePid);
                        ProcessIdentityResolver.Prime(relation.TargetPid);
                    }
                    if (telemetry != null || relation != null || heuristic != null || threadLifecycle != null ||
                        filesystem != null)
                    {
                        _pendingUiWork.Enqueue(
                            BackendUiWorkItem.FromIoctl(telemetry, relation, heuristic, threadLifecycle, filesystem));
                        Interlocked.Increment(ref _pendingUiWorkCount);
                        producedUiWork = true;
                    }

                    transformed += 1;
                }

                while (transformed < MaxBackendTransformItemsPerBatch && _pendingEtwEvents.TryDequeue(out var etw))
                {
                    Interlocked.Decrement(ref _pendingEtwCount);

                    BrokerEtwEventView view = MapBrokerEtwEvent(etw);
                    ProcessIdentityResolver.Prime(view.ActorPid);
                    ProcessIdentityResolver.Prime(view.TargetPid);

                    _pendingUiWork.Enqueue(BackendUiWorkItem.FromEtw(view));
                    Interlocked.Increment(ref _pendingUiWorkCount);
                    producedUiWork = true;
                    transformed += 1;
                }

                int statusLines = 0;
                while (statusLines < MaxBackendStatusLinesPerTransformBatch &&
                       _pendingStatusLines.TryDequeue(out var statusLine))
                {
                    Interlocked.Decrement(ref _pendingStatusCount);
                    _pendingUiWork.Enqueue(BackendUiWorkItem.FromStatus(statusLine));
                    Interlocked.Increment(ref _pendingUiWorkCount);
                    producedUiWork = true;
                    statusLines += 1;
                }

                IReadOnlyList<TelemetryEvent> idleFilesystemClusters =
                    FlushFilesystemTimelineClusterIfNeeded(DateTime.UtcNow, force: false);
                if (idleFilesystemClusters.Count > 0)
                {
                    for (int i = 0; i < idleFilesystemClusters.Count; i += 1)
                    {
                        _pendingUiWork.Enqueue(
                            BackendUiWorkItem.FromIoctl(idleFilesystemClusters[i], null, null, null, null));
                        Interlocked.Increment(ref _pendingUiWorkCount);
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
            var telemetryBatch = new List<TelemetryEvent>(96);
            var relationBatch = new List<ProcessRelationView>(32);
            var heuristicBatch = new List<HeuristicEventView>(32);
            var threadLifecycleBatch = new List<ThreadLifecycleEventSample>(32);
            var filesystemBatch = new List<IoctlParsedEvent>(32);
            var etwBatch = new List<BrokerEtwEventView>(96);
            var statusBatch = new List<string>(32);
            while (processed < MaxBackendUiItemsPerFlush &&
                   stopwatch.Elapsed < BackendUiFlushBudget &&
                   _pendingUiWork.TryDequeue(out var uiWork))
            {
                Interlocked.Decrement(ref _pendingUiWorkCount);
                if (uiWork.Kind == BackendUiWorkKind.Status)
                {
                    if (statusBatch.Count < MaxBackendStatusLinesPerUiFlush && !string.IsNullOrWhiteSpace(uiWork.StatusLine))
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
                _explorer.FirstOrDefault(x => x.Name == "Process Relations")?.PushPreviewValue(
                    ProcessRelationsPaneHost.TotalRawCount);
                SetExplorerHasData("Process Relations", ProcessRelationsPaneHost.ItemCount > 0);
            }

            if (heuristicBatch.Count > 0)
            {
                HeuristicsPaneHost.PushHeuristics(heuristicBatch);
                _explorer.FirstOrDefault(x => x.Name == "Heuristics")?.PushPreviewValue(
                    HeuristicsPaneHost.TotalRawCount);
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

                    if (_currentSession.ThreadLifecycleHistory.Count > 40_000)
                    {
                        _currentSession.ThreadLifecycleHistory.RemoveRange(
                            0,
                            _currentSession.ThreadLifecycleHistory.Count - 40_000);
                    }
                }
            }

            if (filesystemBatch.Count > 0)
            {
                FilesystemPaneHost.PushFileEvents(filesystemBatch);
                _explorer.FirstOrDefault(x => x.Name == "Filesystem")?.PushPreviewValue(
                    FilesystemPaneHost.TotalRawCount);
                SetExplorerHasData("Filesystem", FilesystemPaneHost.ItemCount > 0);
            }

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
            return Interlocked.Read(ref _pendingIoctlCount) > 0 ||
                   Interlocked.Read(ref _pendingEtwCount) > 0 ||
                   Interlocked.Read(ref _pendingStatusCount) > 0 ||
                   Interlocked.Read(ref _pendingUiWorkCount) > 0;
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
            double backlogScore = Math.Min(100.0, (diag.PendingIoctlUiQueue + diag.PendingEtwUiQueue + diag.PendingStatusUiQueue) * 2.0);
            double dropScore = diag.DriverDroppedEvents == 0
                ? 0.0
                : Math.Min(100.0, Math.Log10(diag.DriverDroppedEvents + 1) * 24.0);
            double pressure = Math.Min(100.0, Math.Max(queueScore, backlogScore) + dropScore);

            item.PushPreviewValue(pressure);

            string transport = "shared-ring+event";
            string ringState = diag.SharedRingEnabled ? "ring:ready" : $"ring:missing(err={diag.SharedRingError})";
            string primary = $"{transport} | {ringState} | buf {FormatIpcBytes(diag.IoctlReadBufferBytes)} | caps 0x{diag.BrokerCapabilities:X8}";
            string secondary =
                $"drvQ={diag.DriverQueueDepth} drop={diag.DriverDroppedEvents} uiQ i={diag.PendingIoctlUiQueue} e={diag.PendingEtwUiQueue} i/s={diag.IoctlEventsPerSec:0} e/s={diag.EtwEventsPerSec:0}";

            SetIpcUplinkExplorerDetails(primary, secondary, hasData: true);

            DiagnosticsState.SetValue(
                "IPC Uplink",
                $"mode={transport} ringErr={diag.SharedRingError} queueDepth={diag.DriverQueueDepth} dropped={diag.DriverDroppedEvents} pending(ioctl={diag.PendingIoctlUiQueue},etw={diag.PendingEtwUiQueue},status={diag.PendingStatusUiQueue}) rate(ioctl={diag.IoctlEventsPerSec:0.0}/s,etw={diag.EtwEventsPerSec:0.0}/s) errors(ioctl={diag.IoctlErrorsTotal},etw={diag.EtwErrorsTotal})");
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

        private static ulong BuildRelationKey(uint actorPid, uint targetPid)
            => ((ulong)actorPid << 32) | targetPid;

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
                view.Source.Equals("KernelNetwork", StringComparison.OrdinalIgnoreCase))
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

            if (view.Source.Equals("ThreatIntel", StringComparison.OrdinalIgnoreCase))
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
            string stackSnapshotHex = EventDetailFormatting.FormatSampleHex(record.StackSnapshot, (int)record.StackSnapshotSize);
            string stack0 = record.Frames.Length > 0 ? $"0x{record.Frames[0]:X}" : "n/a";
            string stack1 = record.Frames.Length > 1 ? $"0x{record.Frames[1]:X}" : "n/a";
            string moduleName = EventDetailFormatting.ModuleNameFromPath(record.OriginPath);
            ulong pageBase = record.OriginAddress & ~0xFFFUL;
            string fullFrames = BuildFrameList(record.FullFrames, record.FullFrameCount);
            string captureFlags = DescribeCaptureFlags(record.CaptureFlags);
            string directSyscallName = EventDetailFormatting.ResolveDirectSyscallApi(record.DesiredAccess, record.HandleFlags);
            string directSyscallLabel = EventDetailFormatting.BuildDirectSyscallLabel(
                record.DesiredAccess,
                record.HandleFlags,
                record.DeepSample,
                (int)record.DeepSampleSize);
            bool hasContext = (record.CaptureFlags & 0x00000001u) != 0;
            bool hasDebugRegs = (record.CaptureFlags & 0x00000002u) != 0;
            bool hasFullFrames = (record.CaptureFlags & 0x00000004u) != 0;
            bool hasStackSnapshot = (record.CaptureFlags & 0x00000008u) != 0;

            string frameSegment = hasFullFrames
                ? $"fullFrameCount={record.FullFrameCount} fullFrames={fullFrames} "
                : "fullFrameCount=0 fullFrames=<none> ";

            string registerSegment = hasContext
                ? $"rax=0x{record.RegRax:X} rbx=0x{record.RegRbx:X} rcx=0x{record.RegRcx:X} rdx=0x{record.RegRdx:X} " +
                  $"rsi=0x{record.RegRsi:X} rdi=0x{record.RegRdi:X} rbp=0x{record.RegRbp:X} rsp=0x{record.RegRsp:X} " +
                  $"r8=0x{record.RegR8:X} r9=0x{record.RegR9:X} r10=0x{record.RegR10:X} r11=0x{record.RegR11:X} " +
                  $"r12=0x{record.RegR12:X} r13=0x{record.RegR13:X} r14=0x{record.RegR14:X} r15=0x{record.RegR15:X} " +
                  $"rip=0x{record.RegRip:X} eflags=0x{record.RegEFlags:X} "
                : string.Empty;

            string debugSegment = hasDebugRegs
                ? $"dr0=0x{record.RegDr0:X} dr1=0x{record.RegDr1:X} dr2=0x{record.RegDr2:X} dr3=0x{record.RegDr3:X} dr6=0x{record.RegDr6:X} dr7=0x{record.RegDr7:X} "
                : string.Empty;

            string stackSegment = hasStackSnapshot
                ? $"stackSnapshotAddress=0x{record.StackSnapshotAddress:X} stackSnapshotSize={record.StackSnapshotSize} stackSnapshot={stackSnapshotHex} "
                : "stackSnapshotAddress=0x0 stackSnapshotSize=0 stackSnapshot=<none> ";

            return
                $"ioctlEvidence class={record.HandleClass} syscallName={directSyscallName} syscallLabel={directSyscallLabel.Replace(' ', '_')} access=0x{record.DesiredAccess:X8} ({accessDecoded}) flags=0x{record.HandleFlags:X8} ({flagsDecoded}) " +
                $"origin=0x{record.OriginAddress:X} protect=0x{record.OriginProtect:X8} module={moduleName} pageBase=0x{pageBase:X} " +
                $"allocationBase=0x{record.DeepAllocationBase:X} regionSize=0x{record.DeepRegionSize:X} regionProtect=0x{record.DeepRegionProtect:X8} ({EventDetailFormatting.DescribeMemoryProtection(record.DeepRegionProtect)}) " +
                $"regionState=0x{record.DeepRegionState:X8} ({EventDetailFormatting.DescribeMemoryState(record.DeepRegionState)}) regionType=0x{record.DeepRegionType:X8} ({EventDetailFormatting.DescribeMemoryType(record.DeepRegionType)}) " +
                $"path={record.OriginPath} stack0={stack0} stack1={stack1} " +
                $"captureFlags=0x{record.CaptureFlags:X8} ({captureFlags}) " +
                frameSegment +
                registerSegment +
                debugSegment +
                stackSegment +
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
            return operation switch
            {
                BlackbirdNative.FileOperationCreate => "CREATE",
                BlackbirdNative.FileOperationRead => "READ",
                BlackbirdNative.FileOperationWrite => "WRITE",
                BlackbirdNative.FileOperationClose => "CLOSE",
                BlackbirdNative.FileOperationCleanup => "CLEANUP",
                BlackbirdNative.FileOperationSetInformation => "SET_INFORMATION",
                BlackbirdNative.FileOperationQueryInformation => "QUERY_INFORMATION",
                BlackbirdNative.FileOperationDirectoryControl => "DIRECTORY_CONTROL",
                BlackbirdNative.FileOperationFsControl => "FS_CONTROL",
                _ => "UNKNOWN"
            };
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

            double windowMs = Math.Max(1, (_filesystemClusterLastSeenUtc - _filesystemClusterWindowStartUtc).TotalMilliseconds);
            var emitted = new List<TelemetryEvent>(_filesystemClusterOperationCounts.Count);
            foreach (var entry in _filesystemClusterOperationCounts.OrderByDescending(x => x.Value).ThenBy(x => x.Key))
            {
                if (entry.Value <= 0)
                {
                    continue;
                }

                uint operation = entry.Key;
                int count = entry.Value;
                string operationName = DescribeFileOperation(operation);
                (uint Pid, uint Tid, string Path) sample = _filesystemClusterSamplesByOperation.TryGetValue(operation, out var found)
                    ? found
                    : (0u, 0u, "<unknown>");
                string samplePath = string.IsNullOrWhiteSpace(sample.Path) ? "<unknown>" : sample.Path;
                string summaryPath = BuildFileSummaryPath(samplePath);
                emitted.Add(new TelemetryEvent
                {
                    TimestampUtc = _filesystemClusterLastSeenUtc,
                    PID = unchecked((int)sample.Pid),
                    TID = unchecked((int)sample.Tid),
                    Group = "Filesystem",
                    SubType = operationName,
                    Summary = $"{operationName} x{count} pid={sample.Pid} path={summaryPath}",
                    Details =
                        $"windowStart={_filesystemClusterWindowStartUtc:O} windowEnd={_filesystemClusterLastSeenUtc:O} windowMs={windowMs:0} " +
                        $"operation={operationName} count={count} clusterTotal={_filesystemClusterTotal} samplePid={sample.Pid} sampleTid={sample.Tid} samplePath={samplePath}"
                });
            }

            ResetFilesystemTimelineCluster();
            return emitted;
        }

        private IReadOnlyList<TelemetryEvent> AccumulateFilesystemTimelineCluster(IoctlParsedEvent record, DateTime nowUtc)
        {
            if (record.Type != BlackbirdNative.EventTypeFileSystem)
            {
                return Array.Empty<TelemetryEvent>();
            }

            var emitted = new List<TelemetryEvent>();
            if (_filesystemClusterTotal > 0 && (nowUtc - _filesystemClusterWindowStartUtc) >= FilesystemTimelineClusterWindow)
            {
                emitted.AddRange(FlushFilesystemTimelineClusterIfNeeded(nowUtc, force: true));
            }

            if (_filesystemClusterTotal == 0)
            {
                _filesystemClusterWindowStartUtc = nowUtc;
            }

            _filesystemClusterTotal += 1;
            _filesystemClusterLastSeenUtc = nowUtc;
            _filesystemClusterOperationCounts.TryGetValue(record.FileOperation, out int count);
            _filesystemClusterOperationCounts[record.FileOperation] = count + 1;
            if (!_filesystemClusterSamplesByOperation.ContainsKey(record.FileOperation))
            {
                _filesystemClusterSamplesByOperation[record.FileOperation] =
                    (record.FileProcessPid,
                     record.FileThreadId,
                     string.IsNullOrWhiteSpace(record.FilePath) ? "<unknown>" : record.FilePath);
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
                string className = record.HandleClass switch
                {
                    1 => "LEGITIMATE-SYSCALL",
                    2 => "DIRECT-SYSCALL-SUSPECT",
                    _ => "UNKNOWN"
                };
                string syscallLabel = EventDetailFormatting.BuildDirectSyscallLabel(
                    record.DesiredAccess,
                    record.HandleFlags,
                    record.DeepSample,
                    (int)record.DeepSampleSize);

                return new TelemetryEvent
                {
                    TimestampUtc = now,
                    PID = unchecked((int)caller),
                    TID = unchecked((int)record.ThreadId),
                    Group = "Kernel-IOCTL",
                    SubType = "Handle",
                    Summary = $"{className} {syscallLabel} caller={caller} target={target} access=0x{record.DesiredAccess:X8}",
                    Details = BuildHandleEvidenceText(record)
                };
            }

            if (record.Type == BlackbirdNative.EventTypeThread)
            {
                uint process = record.ProcessPid;
                uint creator = record.CreatorPid;
                string eventKind = DetermineThreadLifecycleKind(record.ThreadFlags, record.StartAddress, record.ImageSize);
                string threadFlags = EventDetailFormatting.DescribeThreadFlags(record.ThreadFlags);
                return new TelemetryEvent
                {
                    TimestampUtc = now,
                    PID = unchecked((int)process),
                    TID = unchecked((int)record.ThreadId),
                    Group = "Kernel-IOCTL",
                    SubType = $"Thread{eventKind}",
                    Summary = $"{eventKind} creator={creator} process={process} flags=0x{record.ThreadFlags:X8}",
                    Details = $"seq={record.Sequence} start=0x{record.StartAddress:X} imageBase=0x{record.ImageBase:X} imageSize=0x{record.ImageSize:X} decodedFlags={threadFlags}"
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

            return new ThreadLifecycleEventSample
            {
                TimestampUtc = now,
                ProcessPid = record.ProcessPid,
                ThreadId = record.ThreadId,
                CreatorPid = record.CreatorPid,
                Flags = record.ThreadFlags,
                StartAddress = record.StartAddress,
                ImageBase = record.ImageBase,
                ImageSize = record.ImageSize,
                EventKind = eventKind,
                Notes = $"flags={decodedFlags}"
            };
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

                return new ProcessRelationView
                {
                    FirstSeenUtc = now,
                    LastSeenUtc = now,
                    SourcePid = source,
                    TargetPid = target,
                    RelationType = "HandleOpen",
                    LastAccessMask = record.DesiredAccess,
                    LastFlags = record.HandleFlags,
                    RepeatCount = 1
                };
            }

            if (record.Type == BlackbirdNative.EventTypeThread)
            {
                uint source = record.CreatorPid;
                uint target = record.ProcessPid;
                if (source == 0 || target == 0 || source == target)
                {
                    return null;
                }

                return new ProcessRelationView
                {
                    FirstSeenUtc = now,
                    LastSeenUtc = now,
                    SourcePid = source,
                    TargetPid = target,
                    RelationType = "ThreadCreate",
                    LastAccessMask = 0,
                    LastFlags = record.ThreadFlags,
                    RepeatCount = 1
                };
            }

            return null;
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
            string syscallName = EventDetailFormatting.ResolveDirectSyscallApi(record.DesiredAccess, record.HandleFlags);
            string syscallSummary = EventDetailFormatting.BuildDirectSyscallSummary(
                record.CallerPid.ToString(CultureInfo.InvariantCulture),
                record.TargetPid.ToString(CultureInfo.InvariantCulture),
                record.DesiredAccess,
                record.HandleFlags,
                record.DeepSample,
                (int)record.DeepSampleSize,
                record.OriginPath);

            return new HeuristicEventView
            {
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
                Reason = $"{syscallSummary}; ioctlClass={record.HandleClass}; handleFlags={handleFlagsDecoded}; access={corrAccessDecoded}",
                Evidence = BuildHandleEvidenceText(record),
                RepeatCount = 1
            };
        }

        private static BrokerEtwEventView MapBrokerEtwEvent(BlackbirdNative.BkIpcEtwEvent etw)
        {
            string source = etw.Source switch
            {
                BlackbirdNative.IpcEtwSourceBlackbird => "Blackbird",
                BlackbirdNative.IpcEtwSourceThreatIntel => "ThreatIntel",
                BlackbirdNative.IpcEtwSourceKernelNetwork => "KernelNetwork",
                _ => "Unknown"
            };

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

            return new BrokerEtwEventView
            {
                TimestampUtc = now,
                LastSeenUtc = now,
                Source = source,
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
                Operation = BlackbirdNative.AnsiBufferToString(etw.Operation),
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
                ImagePath = BlackbirdNative.WideBufferToString(etw.ImagePath),
                CommandLine = BlackbirdNative.WideBufferToString(etw.CommandLine),
                KeyPath = BlackbirdNative.WideBufferToString(etw.KeyPath),
                ValueName = BlackbirdNative.WideBufferToString(etw.ValueName),
                RepeatCount = 1
            };
        }

        private static uint ResolveBrokerEtwActorPid(BlackbirdNative.BkIpcEtwEvent etw)
        {
            return etw.Family switch
            {
                BlackbirdNative.IpcEtwFamilyHandle or BlackbirdNative.IpcEtwFamilyApc =>
                    NarrowPid(etw.CallerPid) ?? NarrowPid(etw.ProcessId) ?? etw.EventProcessId,
                BlackbirdNative.IpcEtwFamilyThread =>
                    NarrowPid(etw.CreatorProcessId) ?? NarrowPid(etw.ProcessId) ?? etw.EventProcessId,
                BlackbirdNative.IpcEtwFamilyProcess =>
                    NarrowPid(etw.CreatorProcessId) ?? NarrowPid(etw.ParentProcessId) ?? NarrowPid(etw.ProcessId) ??
                    etw.EventProcessId,
                BlackbirdNative.IpcEtwFamilyImage or
                BlackbirdNative.IpcEtwFamilyRegistry or
                BlackbirdNative.IpcEtwFamilyDetection or
                BlackbirdNative.IpcEtwFamilyThreatIntel or
                BlackbirdNative.IpcEtwFamilyUserHook or
                BlackbirdNative.IpcEtwFamilySocket =>
                    NarrowPid(etw.ProcessId) ?? etw.EventProcessId,
                _ => NarrowPid(etw.ProcessId) ?? NarrowPid(etw.CallerPid) ?? etw.EventProcessId
            };
        }

        private static uint ResolveBrokerEtwTargetPid(BlackbirdNative.BkIpcEtwEvent etw)
        {
            return etw.Family switch
            {
                BlackbirdNative.IpcEtwFamilyHandle or
                BlackbirdNative.IpcEtwFamilyApc or
                BlackbirdNative.IpcEtwFamilyDetection or
                BlackbirdNative.IpcEtwFamilyThreatIntel =>
                    NarrowPid(etw.TargetPid) ?? 0,
                BlackbirdNative.IpcEtwFamilyThread or
                BlackbirdNative.IpcEtwFamilyProcess =>
                    NarrowPid(etw.ProcessId) ?? 0,
                BlackbirdNative.IpcEtwFamilyUserHook =>
                    NarrowPid(etw.TargetPid) ?? NarrowPid(etw.ProcessId) ?? 0,
                BlackbirdNative.IpcEtwFamilySocket =>
                    NarrowPid(etw.TargetPid) ?? NarrowPid(etw.ProcessId) ?? 0,
                _ => NarrowPid(etw.TargetPid) ?? 0
            };
        }

        private static uint? NarrowPid(ulong value)
        {
            return value is > 0 and <= uint.MaxValue ? (uint)value : null;
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
            var timelineEvents = new List<TelemetryEvent>(views.Count);

            for (int i = 0; i < views.Count; i += 1)
            {
                BrokerEtwEventView view = views[i];
                bool isApiHookCall = view.Family == BlackbirdNative.IpcEtwFamilyUserHook &&
                                     (string.Equals(view.DetectionName, "USERMODE_HOOK_API_CALL", StringComparison.OrdinalIgnoreCase) ||
                                      string.Equals(view.DetectionName, "USERMODE_MEMORY_ACTIVITY", StringComparison.OrdinalIgnoreCase));
                if (isApiHookCall)
                {
                    TelemetryEvent? apiTimelineEvent = HandleApiHookEvent(view);
                    if (apiTimelineEvent != null)
                    {
                        timelineEvents.Add(apiTimelineEvent);
                    }
                }

                bool keepEtw = ShouldKeepEtwEvent(view);
                if (keepEtw)
                {
                    etwRows.Add(view);
                }

                string detection = view.DetectionName;
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
                string displayDetection = BuildFallbackDetectionLabel(
                    detection,
                    eventName,
                    view.Task,
                    view.Opcode,
                    view.EventId,
                    view.CorrelationFlags);
                string source = view.Source;
                uint actor = view.ActorPid;
                bool isSocketEvent = view.Family == BlackbirdNative.IpcEtwFamilySocket ||
                                     source.Equals("KernelNetwork", StringComparison.OrdinalIgnoreCase);
                string socketOperation = string.IsNullOrWhiteSpace(view.Operation) ? eventName : view.Operation;
                if (string.IsNullOrWhiteSpace(socketOperation))
                {
                    socketOperation = $"OP{view.Opcode}";
                }
                string timelineGroup = isSocketEvent ? "Sockets" : "Blackbird-ETW";
                string timelineSubtype = isSocketEvent ? socketOperation : eventName;
                string summary = isSocketEvent
                    ? $"{socketOperation} pid={actor} task={view.Task} opcode={view.Opcode}"
                    : (!string.IsNullOrWhiteSpace(displayDetection)
                        ? $"{source}/{displayDetection} sev={view.Severity}"
                        : $"{source}/{eventName} sev={view.Severity}");
                string timelineSignature = $"{timelineGroup}|{eventName}|{actor}|{view.EventThreadId}|{summary}";
                bool duplicateTimelineEvent =
                    string.Equals(_lastEtwTimelineSignature, timelineSignature, StringComparison.OrdinalIgnoreCase) &&
                    (view.TimestampUtc - _lastEtwTimelineTimestampUtc).TotalMilliseconds <= 900;
                if (keepEtw && !duplicateTimelineEvent)
                {
                    int timelinePid = view.EventProcessId == 0
                        ? unchecked((int)actor)
                        : unchecked((int)view.EventProcessId);
                    timelineEvents.Add(new TelemetryEvent
                    {
                        TimestampUtc = view.TimestampUtc,
                        PID = timelinePid,
                        TID = unchecked((int)view.EventThreadId),
                        Group = timelineGroup,
                        SubType = timelineSubtype,
                        Summary = summary,
                        Details = view.Details
                    });
                    _lastEtwTimelineSignature = timelineSignature;
                    _lastEtwTimelineTimestampUtc = view.TimestampUtc;
                }

                HeuristicEventView? heuristic = CreatePromotedHeuristic(view);
                if (heuristic != null)
                {
                    heuristics.Add(heuristic);
                }
            }

            if (etwRows.Count > 0)
            {
                EtwPaneHost.PushEvents(etwRows);
                _explorer.FirstOrDefault(x => x.Name == "ETW")?.PushPreviewValue(
                    EtwPaneHost.TotalRawCount);
                SetExplorerHasData("ETW", EtwPaneHost.ItemCount > 0);
            }

            if (timelineEvents.Count > 0)
            {
                AppendEvents(timelineEvents);
            }

            if (heuristics.Count > 0)
            {
                HeuristicsPaneHost.PushHeuristics(heuristics);
                _explorer.FirstOrDefault(x => x.Name == "Heuristics")?.PushPreviewValue(
                    HeuristicsPaneHost.TotalRawCount);
                SetExplorerHasData("Heuristics", HeuristicsPaneHost.ItemCount > 0);
                DiagnosticsState.Increment("Heuristics", heuristics.Count);
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
            if (IsDirectSyscallDetection(detection) &&
                hasEvidence &&
                !ShouldKeepDirectSyscallHeuristicFromEvidence(evidence))
            {
                return null;
            }

            string rawCorrFlagsSuffix = view.CorrelationFlags == sanitizedCorrFlags
                ? string.Empty
                : $"; rawCorrFlags=0x{view.CorrelationFlags:X8}";

            return new HeuristicEventView
            {
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
                Reason = $"reason={reasonText}; corrFlags={corrFlagsDecoded}; corrAccess={corrAccessDecoded}; corrAgeMs={view.CorrelationAgeMs}{rawCorrFlagsSuffix}",
                Evidence = heuristicEvidence,
                RepeatCount = 1
            };
        }

        private static string BuildFallbackDetectionLabel(
            string detectionName,
            string eventName,
            ushort task,
            ushort opcode,
            ushort eventId,
            uint correlationFlags)
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

            if (!string.IsNullOrWhiteSpace(name) &&
                name.EndsWith("Telemetry", StringComparison.OrdinalIgnoreCase))
            {
                string baseName = name[..^"Telemetry".Length].Trim();
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

            string key = BuildApiGraphKey(sourcePid, targetPid, threadId, apiName);
            if (_apiGraphRowsByKey.TryGetValue(key, out ApiCallGraphRowSnapshot? existing))
            {
                existing.Hits = Math.Max(1, existing.Hits + 1);
                existing.LastSeenUtc = view.TimestampUtc;
            }
            else
            {
                _apiGraphRowsByKey[key] = new ApiCallGraphRowSnapshot
                {
                    ApiName = apiName,
                    SourcePid = sourcePid,
                    TargetPid = targetPid,
                    ThreadId = threadId,
                    Hits = 1,
                    LastSeenUtc = view.TimestampUtc
                };
            }

            string rawReason = view.Reason ?? string.Empty;
            _apiGraphReasonByKey[key] = rawReason;
            (string decodedAction, string decodedDetail) = BuildApiDecodedAction(view, rawReason);
            _apiGraphActionByKey[key] = decodedAction;
            _apiGraphDecodedByKey[key] = decodedDetail;

            ScheduleApiGraphSnapshot();
            if (string.IsNullOrWhiteSpace(view.Details))
            {
                return null;
            }

            return new TelemetryEvent
            {
                TimestampUtc = view.TimestampUtc,
                PID = unchecked((int)sourcePid),
                TID = unchecked((int)threadId),
                Group = "API Hooks",
                SubType = apiName,
                Summary = $"{apiName} [{sourcePid}->{targetPid}]",
                Details = view.Details
            };
        }

        private void PublishApiGraphSnapshot()
        {
            string? selectedKey = (ApiViewDataGrid?.SelectedItem as ApiCallGraphMainRowView)?.GraphKey;
            bool apiViewVisible = _mainViewMode == MainInterfaceViewMode.Api &&
                                  ApiViewBorder != null &&
                                  ApiViewBorder.Visibility == Visibility.Visible;
            var snapshot = _apiGraphRowsByKey.Values
                .Select(x => new ApiCallGraphRowSnapshot
                {
                    ApiName = x.ApiName,
                    SourcePid = x.SourcePid,
                    TargetPid = x.TargetPid,
                    ThreadId = x.ThreadId,
                    Hits = x.Hits,
                    LastSeenUtc = x.LastSeenUtc
                })
                .OrderByDescending(x => x.Hits)
                .ThenByDescending(x => x.LastSeenUtc)
                .Take(400)
                .ToList();

            int maxHits = Math.Max(1, snapshot.Count == 0 ? 1 : snapshot.Max(x => Math.Max(1, x.Hits)));
            var rows = new List<ApiCallGraphMainRowView>(snapshot.Count);
            foreach (ApiCallGraphRowSnapshot row in snapshot)
            {
                uint target = row.TargetPid != 0 ? row.TargetPid : row.SourcePid;
                string key = BuildApiGraphKey(row.SourcePid, row.TargetPid, row.ThreadId, row.ApiName);
                int flameWidth = Math.Clamp((int)Math.Round((row.Hits / (double)maxHits) * 24.0), 1, 24);
                double heatPercent = Math.Clamp((row.Hits / (double)maxHits) * 100.0, 0.0, 100.0);
                string rawReason = _apiGraphReasonByKey.TryGetValue(key, out string? reason) ? reason : string.Empty;
                string decodedAction = _apiGraphActionByKey.TryGetValue(key, out string? action)
                    ? action
                    : BuildGenericApiActionLabel(row.ApiName, ParseReasonFields(rawReason));
                string decodedDetail = _apiGraphDecodedByKey.TryGetValue(key, out string? detail)
                    ? detail
                    : rawReason;
                rows.Add(new ApiCallGraphMainRowView
                {
                    GraphKey = key,
                    ApiName = string.IsNullOrWhiteSpace(row.ApiName) ? "unknown" : row.ApiName,
                    PathLabel = $"{row.SourcePid} -> {target}",
                    ThreadLabel = row.ThreadId == 0 ? "-" : row.ThreadId.ToString(CultureInfo.InvariantCulture),
                    Hits = Math.Max(1, row.Hits),
                    FlameBar = new string('|', flameWidth),
                    HeatPercent = heatPercent,
                    HeatLabel = $"{Math.Round(heatPercent, MidpointRounding.AwayFromZero):F0}%",
                    LastSeen = row.LastSeenUtc == default ? "-" : row.LastSeenUtc.ToString("HH:mm:ss.fff", CultureInfo.InvariantCulture),
                    DecodedAction = SummarizeApiReason(decodedAction),
                    DetailFull = decodedDetail
                });
            }

            _apiViewRows.ReplaceAll(rows);

            if (ApiViewSummaryBlock != null)
            {
                ApiViewSummaryBlock.Text = snapshot.Count == 0
                    ? "No API hook data yet"
                    : $"Patterns: {_apiViewRows.Count} / Calls: {_apiViewRows.Sum(x => x.Hits)}";
            }
            if (ApiViewSubSummaryBlock != null)
            {
                ApiViewSubSummaryBlock.Text = snapshot.Count == 0
                    ? "live call graph + memory telemetry"
                    : $"last update: {snapshot.Max(x => x.LastSeenUtc):HH:mm:ss.fff}Z";
            }
            if (apiViewVisible && ApiViewDotGraphTextBox != null)
            {
                string dotGraph = BuildApiDotGraph(snapshot);
                ApiViewDotGraphTextBox.Text = string.IsNullOrWhiteSpace(dotGraph) ? "digraph ApiCalls {\n}" : dotGraph;
            }
            DiagnosticsState.SetValue("API Graph", $"patterns={snapshot.Count} visible={apiViewVisible}");

            if (ApiViewDataGrid != null)
            {
                ApiCallGraphMainRowView? selected = null;
                if (!string.IsNullOrWhiteSpace(selectedKey))
                {
                    selected = _apiViewRows.FirstOrDefault(x => string.Equals(x.GraphKey, selectedKey, StringComparison.Ordinal));
                }

                if (selected == null && _apiViewRows.Count > 0)
                {
                    selected = _apiViewRows[0];
                }

                ApiViewDataGrid.SelectedItem = selected;
                UpdateApiViewSelection(selected);
            }
        }

        private static string BuildApiDotGraph(IReadOnlyList<ApiCallGraphRowSnapshot> rows)
        {
            var sb = new StringBuilder(1024);
            sb.AppendLine("digraph ApiCalls {");
            sb.AppendLine("  rankdir=LR;");
            sb.AppendLine("  node [shape=box, style=rounded];");
            int maxHits = Math.Max(1, rows.Count == 0 ? 1 : rows.Max(x => Math.Max(1, x.Hits)));
            foreach (ApiCallGraphRowSnapshot row in rows.Take(180))
            {
                uint source = row.SourcePid;
                uint target = row.TargetPid != 0 ? row.TargetPid : row.SourcePid;
                string api = string.IsNullOrWhiteSpace(row.ApiName) ? "unknown" : row.ApiName.Replace("\"", "'");
                double heat = Math.Clamp(row.Hits / (double)maxHits, 0.0, 1.0);
                int red = Math.Clamp((int)Math.Round(96 + (150 * heat)), 0, 255);
                int green = Math.Clamp((int)Math.Round(188 - (125 * heat)), 0, 255);
                int blue = Math.Clamp((int)Math.Round(238 - (175 * heat)), 0, 255);
                double penWidth = 1.0 + (4.0 * heat);
                sb.Append("  \"PID ");
                sb.Append(source);
                sb.Append("\" -> \"PID ");
                sb.Append(target);
                sb.Append("\" [label=\"");
                sb.Append(api);
                sb.Append(" x");
                sb.Append(row.Hits);
                sb.Append("\" color=\"#");
                sb.Append(red.ToString("X2", CultureInfo.InvariantCulture));
                sb.Append(green.ToString("X2", CultureInfo.InvariantCulture));
                sb.Append(blue.ToString("X2", CultureInfo.InvariantCulture));
                sb.Append("\" penwidth=\"");
                sb.Append(penWidth.ToString("F2", CultureInfo.InvariantCulture));
                sb.AppendLine("\"];");
            }
            sb.AppendLine("}");
            return sb.ToString();
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

        private static string BuildApiGraphKey(uint sourcePid, uint targetPid, uint threadId, string apiName)
            => $"{sourcePid}|{targetPid}|{threadId}|{apiName}";

        private (string Action, string Detail) BuildApiDecodedAction(BrokerEtwEventView view, string rawReason)
        {
            string apiName = !string.IsNullOrWhiteSpace(view.Operation) ? view.Operation : view.EventName;
            if (string.IsNullOrWhiteSpace(apiName))
            {
                apiName = "unknown";
            }

            Dictionary<string, string> fields = ParseReasonFields(rawReason);
            string action = BuildGenericApiActionLabel(apiName, fields);
            string detail;

            if (TryBuildMemoryAction(apiName, view, fields, out string memoryAction, out string memoryDetail))
            {
                action = memoryAction;
                detail = memoryDetail;
            }
            else
            {
                var sb = new StringBuilder(512);
                sb.AppendLine(action);
                if (!string.IsNullOrWhiteSpace(rawReason))
                {
                    sb.Append("Raw: ").AppendLine(rawReason);
                }
                if (!string.IsNullOrWhiteSpace(view.Details))
                {
                    sb.Append("Event: ").Append(view.Details);
                }
                detail = sb.ToString().Trim();
            }

            return (action, detail);
        }

        private bool TryBuildMemoryAction(
            string apiName,
            BrokerEtwEventView view,
            IReadOnlyDictionary<string, string> fields,
            out string action,
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
                action = $"Allocates 0x{regionSize:X} bytes at 0x{baseAddress:X} ({protectLabel})";
                detail = $"Action: memory.alloc\n" +
                         $"API: {apiName}\n" +
                         $"Base: 0x{baseAddress:X}\n" +
                         $"Size: 0x{regionSize:X}\n" +
                         $"AllocType: 0x{allocationType:X} ({DescribeMemoryAllocationType((uint)allocationType)})\n" +
                         $"Protect: 0x{protect:X} ({protectLabel})\n" +
                         $"Raw: {view.Reason}";
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
                action = $"Changes protection to {protectLabel} at 0x{baseAddress:X}";
                detail = $"Action: memory.protect\n" +
                         $"API: {apiName}\n" +
                         $"Base: 0x{baseAddress:X}\n" +
                         $"Size: 0x{regionSize:X}\n" +
                         $"NewProtect: 0x{newProtect:X} ({protectLabel})\n" +
                         $"ProtectFlips: {state.ProtectFlipCount}\n" +
                         $"RapidFlip: {(rapidFlip ? "yes" : "no")}\n" +
                         $"Raw: {view.Reason}";
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

                string entropyText = entropy >= 0
                    ? entropy.ToString("F2", CultureInfo.InvariantCulture)
                    : "n/a";
                action = $"Writes 0x{size:X} bytes at 0x{baseAddress:X} (entropy {entropyText})";
                detail = $"Action: memory.write\n" +
                         $"API: {apiName}\n" +
                         $"Base: 0x{baseAddress:X}\n" +
                         $"Size: 0x{size:X}\n" +
                         $"Entropy(bits/byte): {entropyText}\n" +
                         $"EntropyFlips: {state.EntropyFlipCount}\n" +
                         $"ProtectFlips: {state.ProtectFlipCount}\n" +
                         $"RapidEntropyFlip: {(rapidEntropyFlip ? "yes" : "no")}\n" +
                         $"SampleBytes: {sampleLen}\n" +
                         $"Raw: {view.Reason}";
                return true;
            }

            return false;
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

        private static bool TryReadDouble(IReadOnlyDictionary<string, string> fields, out double value, params string[] keys)
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
            return protect switch
            {
                0x01 => "PAGE_NOACCESS",
                0x02 => "PAGE_READONLY",
                0x04 => "PAGE_READWRITE",
                0x08 => "PAGE_WRITECOPY",
                0x10 => "PAGE_EXECUTE",
                0x20 => "PAGE_EXECUTE_READ",
                0x40 => "PAGE_EXECUTE_READWRITE",
                0x80 => "PAGE_EXECUTE_WRITECOPY",
                _ => $"0x{protect:X}"
            };
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

            private BackendUiWorkItem(
                BackendUiWorkKind kind,
                TelemetryEvent? telemetry,
                ProcessRelationView? relation,
                HeuristicEventView? heuristic,
                ThreadLifecycleEventSample? threadLifecycle,
                IoctlParsedEvent? filesystem,
                BrokerEtwEventView? etwView,
                string? statusLine)
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

            internal static BackendUiWorkItem FromIoctl(
                TelemetryEvent? telemetry,
                ProcessRelationView? relation,
                HeuristicEventView? heuristic,
                ThreadLifecycleEventSample? threadLifecycle,
                IoctlParsedEvent? filesystem)
                => new(BackendUiWorkKind.Ioctl, telemetry, relation, heuristic, threadLifecycle, filesystem, null, null);

            internal static BackendUiWorkItem FromEtw(BrokerEtwEventView etwView)
                => new(BackendUiWorkKind.Etw, null, null, null, null, null, etwView, null);

            internal static BackendUiWorkItem FromStatus(string statusLine)
                => new(BackendUiWorkKind.Status, null, null, null, null, null, null, statusLine);
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
            _apiGraphHistoryByPid[pid] = _apiGraphRowsByKey.Values
                .Select(x => new ApiCallGraphRowSnapshot
                {
                    ApiName = x.ApiName,
                    SourcePid = x.SourcePid,
                    TargetPid = x.TargetPid,
                    ThreadId = x.ThreadId,
                    Hits = x.Hits,
                    LastSeenUtc = x.LastSeenUtc
                })
                .ToList();
        }

        private void RestoreIntelSessionState(int pid)
        {
            IEnumerable<GroupedEventRow> etw = _etwHistoryByPid.TryGetValue(pid, out var a)
                ? a
                : Array.Empty<GroupedEventRow>();
            IEnumerable<GroupedEventRow> heur = _heuristicsHistoryByPid.TryGetValue(pid, out var c)
                ? c
                : Array.Empty<GroupedEventRow>();
            IEnumerable<GroupedEventRow> fs = _filesystemHistoryByPid.TryGetValue(pid, out var d)
                ? d
                : Array.Empty<GroupedEventRow>();
            IEnumerable<GroupedEventRow> rel = _relationsHistoryByPid.TryGetValue(pid, out var e)
                ? e
                : Array.Empty<GroupedEventRow>();
            IEnumerable<ApiCallGraphRowSnapshot> apiGraph = _apiGraphHistoryByPid.TryGetValue(pid, out var f)
                ? f
                : Array.Empty<ApiCallGraphRowSnapshot>();

            EtwPaneHost.LoadHistory(CompactGroupsForMemory(etw, 48));
            HeuristicsPaneHost.LoadHistory(CompactGroupsForMemory(heur, 48));
            FilesystemPaneHost.LoadHistory(CompactGroupsForMemory(fs, 48));
            ProcessRelationsPaneHost.LoadHistory(CompactGroupsForMemory(rel, 48));
            _apiGraphRowsByKey.Clear();
            _apiGraphReasonByKey.Clear();
            _apiGraphActionByKey.Clear();
            _apiGraphDecodedByKey.Clear();
            _apiMemorySignalsByPage.Clear();
            foreach (ApiCallGraphRowSnapshot row in apiGraph)
            {
                string key = $"{row.SourcePid}|{row.TargetPid}|{row.ThreadId}|{row.ApiName}";
                _apiGraphRowsByKey[key] = new ApiCallGraphRowSnapshot
                {
                    ApiName = row.ApiName,
                    SourcePid = row.SourcePid,
                    TargetPid = row.TargetPid,
                    ThreadId = row.ThreadId,
                    Hits = row.Hits,
                    LastSeenUtc = row.LastSeenUtc
                };
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

            bool shouldWarn = userInitiated || !string.Equals(_lastConnectivityIssueSignature, signature, StringComparison.Ordinal);
            if (shouldWarn)
            {
                ThemedMessageBox.Show(
                    this,
                    $"Could not fully connect to the driver/service uplink.\n\n{detail}",
                    "Blackbird Connectivity",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
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
            bool ok = await Task.Run(() => BlackbirdServiceControl.TryStart("blackbird", TimeSpan.FromSeconds(8), out message));
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
            if (ThemedMessageBox.Show(
                    this,
                    "Stop the kernel driver 'blackbird'?",
                    "Driver Stop",
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Warning) != MessageBoxResult.Yes)
            {
                return;
            }

            StopBackendSession();
            string message = "";
            bool ok = await Task.Run(() => BlackbirdServiceControl.TryStop("blackbird", TimeSpan.FromSeconds(8), out message));
            OutputCapture.AppendLine(message);
            StatusBlock.Text = ok ? "Status: Driver stopped" : "Status: Failed to stop blackbird";
            await RunPreflightAsync(TryGetPid(), userInitiated: true);
        }

        private async void ControllerRestart_Click(object sender, RoutedEventArgs e)
        {
            StopBackendSession();
            string message = "";
            bool ok = await Task.Run(() => BlackbirdServiceControl.TryRestart("BlackbirdController", TimeSpan.FromSeconds(10), out message));
            OutputCapture.AppendLine(message);
            if (!ok)
            {
                StatusBlock.Text = "Status: Controller restart failed";
                return;
            }

            await RunPreflightAsync(TryGetPid(), userInitiated: true);
            StartBackendForPid(TryGetPid(), _currentSession?.UseUsermodeHooks ?? false);
            if (_lastConnectivityIssueSignature == null)
            {
                StatusBlock.Text = "Status: Controller restarted";
            }
        }
    }
}
