using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Threading;

namespace SleepwalkerInterface
{
    public partial class MainWindow
    {
        private SleepwalkerBackendSession? _backendSession;
        private int _backendGeneration;
        private readonly Dictionary<int, List<GroupedEventRow>> _etwHistoryByPid = new();
        private readonly Dictionary<int, List<GroupedEventRow>> _heuristicsHistoryByPid = new();
        private readonly Dictionary<int, List<GroupedEventRow>> _relationsHistoryByPid = new();

        private SleepwalkerPreflightReport? _lastPreflight;
        private string? _lastConnectivityIssueSignature;
        private readonly ConcurrentQueue<IoctlParsedEvent> _pendingIoctlEvents = new();
        private readonly ConcurrentQueue<SleepwalkerNative.SwIpcEtwEvent> _pendingEtwEvents = new();
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
        private const uint CorrelationIntentMask = 0x00000007u;
        private static readonly TimeSpan BackendUiFlushBudget = TimeSpan.FromMilliseconds(5);
        private string? _lastEtwTimelineSignature;
        private DateTime _lastEtwTimelineTimestampUtc;
        private readonly Dictionary<ulong, IoctlParsedEvent> _recentHandleEvidenceByPair = new();
        private DateTime _lastHandleEvidencePruneUtc = DateTime.MinValue;

        private void InitializeBackendUi()
        {
            EtwPaneHost.ClearAll();
            HeuristicsPaneHost.ClearAll();
            ProcessRelationsPaneHost.ClearAll();
            IpcUplinkPaneHost.SetInactive("No IPC diagnostics yet", "Enable uplink and wait for stats sample.");
            RefreshExplorerDataBadges();
            DiagnosticsState.SetValue("UI", "Initialized");
        }

        private void StartBackendForPid(int pid)
        {
            StopBackendSession();
            ClearPendingBackendUiQueues();

            if (pid <= 0)
            {
                return;
            }

            _hasIpcUplinkData = false;
            _lastEtwTimelineSignature = null;
            _lastEtwTimelineTimestampUtc = DateTime.MinValue;
            SetIpcUplinkExplorerDetails("Enable to inspect IPC internals", "Waiting for session diagnostics...", hasData: false);

            int generation = ++_backendGeneration;
            try
            {
                var session = SleepwalkerBackendSession.Start(pid, SleepwalkerNative.StreamAll);
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
                return "IPC runtime DLL is outdated (missing export). Rebuild/deploy SleepwalkerSensorCore.dll and controller.";
            }

            if (ex is System.ComponentModel.Win32Exception wx &&
                (wx.NativeErrorCode == 127 || wx.NativeErrorCode == SleepwalkerNative.ErrorInvalidFunction))
            {
                return "IPC runtime DLL/controller mismatch (missing function). Rebuild/deploy latest SleepwalkerSensorCore.dll and controller.";
            }

            return ex.Message;
        }

        private void StopBackendSession()
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
            _hasIpcUplinkData = false;
            SetIpcUplinkExplorerDetails("Session stopped", "No live IPC diagnostics", hasData: false);
            DiagnosticsState.SetValue("Session", "Stopped");
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

                    TelemetryEvent? telemetry = MapIoctlRecord(ioctl);
                    ProcessRelationView? relation = MapIoctlRelation(ioctl);
                    HeuristicEventView? heuristic = MapIoctlHeuristic(ioctl);
                    ThreadLifecycleEventSample? threadLifecycle = MapIoctlThreadLifecycle(ioctl);
                    if (relation != null)
                    {
                        ProcessIdentityResolver.Prime(relation.SourcePid);
                        ProcessIdentityResolver.Prime(relation.TargetPid);
                    }
                    if (telemetry != null || relation != null || heuristic != null || threadLifecycle != null)
                    {
                        _pendingUiWork.Enqueue(BackendUiWorkItem.FromIoctl(telemetry, relation, heuristic, threadLifecycle));
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
            int statusLines = 0;
            while (processed < MaxBackendUiItemsPerFlush &&
                   stopwatch.Elapsed < BackendUiFlushBudget &&
                   _pendingUiWork.TryDequeue(out var uiWork))
            {
                Interlocked.Decrement(ref _pendingUiWorkCount);
                if (uiWork.Kind == BackendUiWorkKind.Status)
                {
                    if (statusLines < MaxBackendStatusLinesPerUiFlush && !string.IsNullOrWhiteSpace(uiWork.StatusLine))
                    {
                        OutputCapture.AppendLine(uiWork.StatusLine);
                        statusLines += 1;
                    }
                }
                else if (uiWork.Kind == BackendUiWorkKind.Ioctl)
                {
                    if (uiWork.Telemetry != null)
                    {
                        AppendEvent(uiWork.Telemetry);
                    }
                    if (uiWork.Relation != null)
                    {
                        ProcessRelationsPaneHost.PushRelation(uiWork.Relation);
                        _explorer.FirstOrDefault(x => x.Name == "Process Relations")?.PushPreviewValue(
                            ProcessRelationsPaneHost.TotalRawCount);
                        SetExplorerHasData("Process Relations", ProcessRelationsPaneHost.ItemCount > 0);
                    }
                    if (uiWork.Heuristic != null)
                    {
                        HeuristicsPaneHost.PushHeuristic(uiWork.Heuristic);
                        _explorer.FirstOrDefault(x => x.Name == "Heuristics")?.PushPreviewValue(
                            HeuristicsPaneHost.TotalRawCount);
                        SetExplorerHasData("Heuristics", HeuristicsPaneHost.ItemCount > 0);
                        DiagnosticsState.Increment("Heuristics");
                    }
                    if (uiWork.ThreadLifecycle != null)
                    {
                        PerformancePaneHost.PushThreadLifecycle(uiWork.ThreadLifecycle);
                        if (_currentSession != null)
                        {
                            _currentSession.ThreadLifecycleHistory.Add(CloneThreadLifecycleEvent(uiWork.ThreadLifecycle));
                            if (_currentSession.ThreadLifecycleHistory.Count > 40_000)
                            {
                                _currentSession.ThreadLifecycleHistory.RemoveRange(
                                    0,
                                    _currentSession.ThreadLifecycleHistory.Count - 40_000);
                            }
                        }
                    }
                }
                else if (uiWork.Kind == BackendUiWorkKind.Etw && uiWork.EtwView != null)
                {
                    HandleBrokerEtwView(uiWork.EtwView);
                }

                processed += 1;
            }

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
            if (record.Type != SleepwalkerNative.EventTypeHandle || record.CallerPid == 0 || record.TargetPid == 0)
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
            if (IsDirectSyscallDetection(det))
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
                $"ioctlEvidence class={record.HandleClass} access=0x{record.DesiredAccess:X8} ({accessDecoded}) flags=0x{record.HandleFlags:X8} ({flagsDecoded}) " +
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

        private TelemetryEvent? MapIoctlRecord(IoctlParsedEvent record)
        {
            DateTime now = DateTime.UtcNow;
            if (record.Type == SleepwalkerNative.EventTypeHandle)
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

                return new TelemetryEvent
                {
                    TimestampUtc = now,
                    PID = unchecked((int)caller),
                    TID = unchecked((int)record.ThreadId),
                    Group = "Kernel-IOCTL",
                    SubType = "Handle",
                    Summary = $"{className} caller={caller} target={target} access=0x{record.DesiredAccess:X8}",
                    Details = BuildHandleEvidenceText(record)
                };
            }

            if (record.Type == SleepwalkerNative.EventTypeThread)
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

            return null;
        }

        private static ThreadLifecycleEventSample? MapIoctlThreadLifecycle(IoctlParsedEvent record)
        {
            if (record.Type != SleepwalkerNative.EventTypeThread)
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
            if (record.Type == SleepwalkerNative.EventTypeHandle)
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

            if (record.Type == SleepwalkerNative.EventTypeThread)
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
            if (record.Type != SleepwalkerNative.EventTypeHandle || record.CallerPid == 0 || record.TargetPid == 0)
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

            return new HeuristicEventView
            {
                TimestampUtc = now,
                LastSeenUtc = now,
                Severity = severity,
                DetectionName = "DIRECT_SYSCALL_SUSPECT_HANDLE_OPERATION",
                ActorPid = record.CallerPid,
                TargetPid = record.TargetPid,
                Source = "Kernel-IOCTL",
                EventName = "HandleTelemetry",
                CorrelationFlags = 0,
                CorrelationAccessMask = record.DesiredAccess,
                CorrelationAgeMs = 0,
                Reason = $"ioctlClass={record.HandleClass}; handleFlags={handleFlagsDecoded}; access={corrAccessDecoded}",
                Evidence = BuildHandleEvidenceText(record),
                RepeatCount = 1
            };
        }

        private static BrokerEtwEventView MapBrokerEtwEvent(SleepwalkerNative.SwIpcEtwEvent etw)
        {
            string source = etw.Source switch
            {
                SleepwalkerNative.IpcEtwSourceSleepwalker => "Sleepwalker",
                SleepwalkerNative.IpcEtwSourceThreatIntel => "ThreatIntel",
                _ => "Unknown"
            };

            string eventName = SleepwalkerNative.WideBufferToString(etw.EventName);
            if (string.IsNullOrWhiteSpace(eventName))
            {
                eventName = "unknown";
            }

            string detection = SleepwalkerNative.AnsiBufferToString(etw.DetectionName);
            string reason = SleepwalkerNative.WideBufferToString(etw.Reason);
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
                ClassName = SleepwalkerNative.AnsiBufferToString(etw.ClassName),
                Operation = SleepwalkerNative.AnsiBufferToString(etw.Operation),
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
                OriginPath = SleepwalkerNative.WideBufferToString(etw.OriginPath),
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
                ImagePath = SleepwalkerNative.WideBufferToString(etw.ImagePath),
                CommandLine = SleepwalkerNative.WideBufferToString(etw.CommandLine),
                KeyPath = SleepwalkerNative.WideBufferToString(etw.KeyPath),
                ValueName = SleepwalkerNative.WideBufferToString(etw.ValueName),
                RepeatCount = 1
            };
        }

        private static uint ResolveBrokerEtwActorPid(SleepwalkerNative.SwIpcEtwEvent etw)
        {
            return etw.Family switch
            {
                SleepwalkerNative.IpcEtwFamilyHandle or SleepwalkerNative.IpcEtwFamilyApc =>
                    NarrowPid(etw.CallerPid) ?? NarrowPid(etw.ProcessId) ?? etw.EventProcessId,
                SleepwalkerNative.IpcEtwFamilyThread =>
                    NarrowPid(etw.CreatorProcessId) ?? NarrowPid(etw.ProcessId) ?? etw.EventProcessId,
                SleepwalkerNative.IpcEtwFamilyProcess =>
                    NarrowPid(etw.CreatorProcessId) ?? NarrowPid(etw.ParentProcessId) ?? NarrowPid(etw.ProcessId) ??
                    etw.EventProcessId,
                SleepwalkerNative.IpcEtwFamilyImage or
                SleepwalkerNative.IpcEtwFamilyRegistry or
                SleepwalkerNative.IpcEtwFamilyDetection or
                SleepwalkerNative.IpcEtwFamilyThreatIntel =>
                    NarrowPid(etw.ProcessId) ?? etw.EventProcessId,
                _ => NarrowPid(etw.ProcessId) ?? NarrowPid(etw.CallerPid) ?? etw.EventProcessId
            };
        }

        private static uint ResolveBrokerEtwTargetPid(SleepwalkerNative.SwIpcEtwEvent etw)
        {
            return etw.Family switch
            {
                SleepwalkerNative.IpcEtwFamilyHandle or
                SleepwalkerNative.IpcEtwFamilyApc or
                SleepwalkerNative.IpcEtwFamilyDetection or
                SleepwalkerNative.IpcEtwFamilyThreatIntel =>
                    NarrowPid(etw.TargetPid) ?? 0,
                SleepwalkerNative.IpcEtwFamilyThread or
                SleepwalkerNative.IpcEtwFamilyProcess =>
                    NarrowPid(etw.ProcessId) ?? 0,
                _ => NarrowPid(etw.TargetPid) ?? 0
            };
        }

        private static uint? NarrowPid(ulong value)
        {
            return value is > 0 and <= uint.MaxValue ? (uint)value : null;
        }

        private void HandleBrokerEtwView(BrokerEtwEventView view)
        {
            bool keepEtw = ShouldKeepEtwEvent(view);
            if (keepEtw)
            {
                EtwPaneHost.PushEvent(view);
                _explorer.FirstOrDefault(x => x.Name == "ETW")?.PushPreviewValue(
                    EtwPaneHost.TotalRawCount);
                SetExplorerHasData("ETW", EtwPaneHost.ItemCount > 0);
            }

            string timelineGroup = "Sleepwalker-ETW";
            string detection = view.DetectionName;
            string displayDetection = BuildFallbackDetectionLabel(
                detection,
                view.EventName,
                view.Task,
                view.Opcode,
                view.EventId,
                view.CorrelationFlags);
            string source = view.Source;
            string eventName = view.EventName;
            uint actor = view.ActorPid;
            uint target = view.TargetPid;
            string summary = !string.IsNullOrWhiteSpace(displayDetection)
                ? $"{source}/{displayDetection} sev={view.Severity}"
                : $"{source}/{eventName} sev={view.Severity}";
            string timelineSignature = $"{timelineGroup}|{eventName}|{actor}|{view.EventThreadId}|{summary}";
            bool duplicateTimelineEvent =
                string.Equals(_lastEtwTimelineSignature, timelineSignature, StringComparison.OrdinalIgnoreCase) &&
                (view.TimestampUtc - _lastEtwTimelineTimestampUtc).TotalMilliseconds <= 900;
            if (keepEtw && !duplicateTimelineEvent)
            {
                int timelinePid = view.EventProcessId == 0
                    ? unchecked((int)actor)
                    : unchecked((int)view.EventProcessId);
                AppendEvent(new TelemetryEvent
                {
                    TimestampUtc = view.TimestampUtc,
                    PID = timelinePid,
                    TID = unchecked((int)view.EventThreadId),
                    Group = timelineGroup,
                    SubType = eventName,
                    Summary = summary,
                    Details = view.Details
                });
                _lastEtwTimelineSignature = timelineSignature;
                _lastEtwTimelineTimestampUtc = view.TimestampUtc;
            }

            if (!string.IsNullOrWhiteSpace(detection) && ShouldPromoteHeuristic(view))
            {
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
                    return;
                }

                string rawCorrFlagsSuffix = view.CorrelationFlags == sanitizedCorrFlags
                    ? string.Empty
                    : $"; rawCorrFlags=0x{view.CorrelationFlags:X8}";

                var heuristic = new HeuristicEventView
                {
                    TimestampUtc = view.TimestampUtc,
                    LastSeenUtc = view.TimestampUtc,
                    Severity = view.Severity,
                    DetectionName = detection,
                    ActorPid = actor,
                    TargetPid = target,
                    Source = source,
                    EventName = eventName,
                    CorrelationFlags = sanitizedCorrFlags,
                    CorrelationAccessMask = view.CorrelationAccessMask,
                    CorrelationAgeMs = view.CorrelationAgeMs,
                    Reason = $"reason={reasonText}; corrFlags={corrFlagsDecoded}; corrAccess={corrAccessDecoded}; corrAgeMs={view.CorrelationAgeMs}{rawCorrFlagsSuffix}",
                    Evidence = heuristicEvidence,
                    RepeatCount = 1
                };
                HeuristicsPaneHost.PushHeuristic(heuristic);
                _explorer.FirstOrDefault(x => x.Name == "Heuristics")?.PushPreviewValue(
                    HeuristicsPaneHost.TotalRawCount);
                SetExplorerHasData("Heuristics", HeuristicsPaneHost.ItemCount > 0);
                DiagnosticsState.Increment("Heuristics");
            }
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
            internal BrokerEtwEventView? EtwView { get; }
            internal string? StatusLine { get; }

            private BackendUiWorkItem(
                BackendUiWorkKind kind,
                TelemetryEvent? telemetry,
                ProcessRelationView? relation,
                HeuristicEventView? heuristic,
                ThreadLifecycleEventSample? threadLifecycle,
                BrokerEtwEventView? etwView,
                string? statusLine)
            {
                Kind = kind;
                Telemetry = telemetry;
                Relation = relation;
                Heuristic = heuristic;
                ThreadLifecycle = threadLifecycle;
                EtwView = etwView;
                StatusLine = statusLine;
            }

            internal static BackendUiWorkItem FromIoctl(
                TelemetryEvent? telemetry,
                ProcessRelationView? relation,
                HeuristicEventView? heuristic,
                ThreadLifecycleEventSample? threadLifecycle)
                => new(BackendUiWorkKind.Ioctl, telemetry, relation, heuristic, threadLifecycle, null, null);

            internal static BackendUiWorkItem FromEtw(BrokerEtwEventView etwView)
                => new(BackendUiWorkKind.Etw, null, null, null, null, etwView, null);

            internal static BackendUiWorkItem FromStatus(string statusLine)
                => new(BackendUiWorkKind.Status, null, null, null, null, null, statusLine);
        }

        private void SaveIntelSessionState(int pid)
        {
            if (pid <= 0)
            {
                return;
            }

            _etwHistoryByPid[pid] = EtwPaneHost.SnapshotItems().Select(x => x.Clone()).ToList();
            _heuristicsHistoryByPid[pid] = HeuristicsPaneHost.SnapshotItems().Select(x => x.Clone()).ToList();
            _relationsHistoryByPid[pid] = ProcessRelationsPaneHost.SnapshotItems().Select(x => x.Clone()).ToList();
        }

        private void RestoreIntelSessionState(int pid)
        {
            IEnumerable<GroupedEventRow> etw = _etwHistoryByPid.TryGetValue(pid, out var a)
                ? a
                : Array.Empty<GroupedEventRow>();
            IEnumerable<GroupedEventRow> heur = _heuristicsHistoryByPid.TryGetValue(pid, out var c)
                ? c
                : Array.Empty<GroupedEventRow>();
            IEnumerable<GroupedEventRow> rel = _relationsHistoryByPid.TryGetValue(pid, out var d)
                ? d
                : Array.Empty<GroupedEventRow>();

            EtwPaneHost.LoadHistory(CompactGroupsForMemory(etw, 48));
            HeuristicsPaneHost.LoadHistory(CompactGroupsForMemory(heur, 48));
            ProcessRelationsPaneHost.LoadHistory(CompactGroupsForMemory(rel, 48));
            if (EtwPaneHost.ItemCount > 0)
            {
                FindExplorerItem("ETW")?.PushPreviewValue(EtwPaneHost.TotalRawCount);
            }
            if (HeuristicsPaneHost.ItemCount > 0)
            {
                FindExplorerItem("Heuristics")?.PushPreviewValue(HeuristicsPaneHost.TotalRawCount);
            }
            if (ProcessRelationsPaneHost.ItemCount > 0)
            {
                FindExplorerItem("Process Relations")?.PushPreviewValue(ProcessRelationsPaneHost.TotalRawCount);
            }
            RefreshExplorerDataBadges();
        }

        private async Task RunPreflightAsync(int pid, bool userInitiated = false)
        {
            SleepwalkerPreflightReport report = await Task.Run(() => SleepwalkerPreflight.Run(pid));
            _lastPreflight = report;
            OutputCapture.AppendLine($"Preflight: {report.Summary}");
            DiagnosticsState.SetValue("Driver Service", report.DriverState);
            DiagnosticsState.SetValue("Controller Service", report.ControllerState);
            DiagnosticsState.SetValue("Broker Caps", $"0x{report.BrokerCapabilities:X8}");
            DiagnosticsState.SetValue("Broker TI", report.ThreatIntelEnabled ? "Enabled" : "Disabled");
            DiagnosticsState.SetValue("Broker TI Enable Err", report.ThreatIntelEnableError.ToString());
            ApplyConnectivityStatus(report, userInitiated);
        }

        private void ApplyConnectivityStatus(SleepwalkerPreflightReport report, bool userInitiated)
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
                    "Sleepwalker Connectivity",
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
            bool ok = await Task.Run(() => SleepwalkerServiceControl.TryStart("sleepwlkr", TimeSpan.FromSeconds(8), out message));
            OutputCapture.AppendLine(message);
            if (!ok)
            {
                StatusBlock.Text = "Status: Failed to start sleepwlkr";
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
                    "Stop the kernel driver 'sleepwlkr'?",
                    "Driver Stop",
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Warning) != MessageBoxResult.Yes)
            {
                return;
            }

            StopBackendSession();
            string message = "";
            bool ok = await Task.Run(() => SleepwalkerServiceControl.TryStop("sleepwlkr", TimeSpan.FromSeconds(8), out message));
            OutputCapture.AppendLine(message);
            StatusBlock.Text = ok ? "Status: Driver stopped" : "Status: Failed to stop sleepwlkr";
            await RunPreflightAsync(TryGetPid(), userInitiated: true);
        }

        private async void ControllerRestart_Click(object sender, RoutedEventArgs e)
        {
            StopBackendSession();
            string message = "";
            bool ok = await Task.Run(() => SleepwalkerServiceControl.TryRestart("SleepwlkrController", TimeSpan.FromSeconds(10), out message));
            OutputCapture.AppendLine(message);
            if (!ok)
            {
                StatusBlock.Text = "Status: Controller restart failed";
                return;
            }

            await RunPreflightAsync(TryGetPid(), userInitiated: true);
            StartBackendForPid(TryGetPid());
            if (_lastConnectivityIssueSignature == null)
            {
                StatusBlock.Text = "Status: Controller restarted";
            }
        }
    }
}
