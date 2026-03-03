using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
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
        private readonly Dictionary<int, List<BrokerEtwEventView>> _sleepwalkerEtwHistoryByPid = new();
        private readonly Dictionary<int, List<BrokerEtwEventView>> _tiEtwHistoryByPid = new();
        private readonly Dictionary<int, List<HeuristicEventView>> _heuristicsHistoryByPid = new();

        private SleepwalkerPreflightReport? _lastPreflight;
        private string? _lastConnectivityIssueSignature;
        private readonly ConcurrentQueue<IoctlParsedEvent> _pendingIoctlEvents = new();
        private readonly ConcurrentQueue<SleepwalkerNative.SwIpcEtwEvent> _pendingEtwEvents = new();
        private readonly ConcurrentQueue<string> _pendingStatusLines = new();
        private int _backendUiFlushScheduled;
        private const int MaxBackendUiItemsPerFlush = 600;

        private void InitializeBackendUi()
        {
            EtwPaneHost.ClearAll();
            HeuristicsPaneHost.ClearAll();
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
                    ScheduleBackendUiFlush(generation);
                };

                session.EtwEvent += etw =>
                {
                    if (generation != _backendGeneration)
                    {
                        return;
                    }

                    _pendingEtwEvents.Enqueue(etw);
                    ScheduleBackendUiFlush(generation);
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

                session.Status += text =>
                {
                    if (generation != _backendGeneration)
                    {
                        return;
                    }

                    _pendingStatusLines.Enqueue($"[session pid={pid}] {text}");
                    ScheduleBackendUiFlush(generation);
                };

                StatusBlock.Text = $"Status: Session active for PID {pid}";
                OutputCapture.AppendLine($"Session started for PID {pid}");
                DiagnosticsState.SetValue("Session", $"Active PID {pid}");
            }
            catch (Exception ex)
            {
                _backendSession = null;
                StatusBlock.Text = $"Status: Session start failed ({ex.Message})";
                OutputCapture.AppendLine($"Session start failed for PID {pid}: {ex.Message}");
                DiagnosticsState.SetValue("Session", $"Start failed PID {pid}");
                DiagnosticsState.SetValue("Connectivity", $"Session start failed: {ex.Message}");
                SetBackendConnectivity(false);
            }
        }

        private void StopBackendSession()
        {
            if (_backendSession == null)
            {
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
            ClearPendingBackendUiQueues();
            DiagnosticsState.SetValue("Session", "Stopped");
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

            int processed = 0;

            while (processed < MaxBackendUiItemsPerFlush && _pendingIoctlEvents.TryDequeue(out var ioctl))
            {
                var telemetry = MapIoctlRecord(ioctl);
                if (telemetry != null)
                {
                    AppendEvent(telemetry);
                }

                processed += 1;
            }

            while (processed < MaxBackendUiItemsPerFlush && _pendingEtwEvents.TryDequeue(out var etw))
            {
                HandleBrokerEtwEvent(etw);
                processed += 1;
            }

            int statusLines = 0;
            while (statusLines < 32 && _pendingStatusLines.TryDequeue(out var status))
            {
                OutputCapture.AppendLine(status);
                statusLines += 1;
            }

            if (HasPendingBackendUiData())
            {
                ScheduleBackendUiFlush(generation);
            }
        }

        private bool HasPendingBackendUiData()
        {
            return !_pendingIoctlEvents.IsEmpty || !_pendingEtwEvents.IsEmpty || !_pendingStatusLines.IsEmpty;
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

            Interlocked.Exchange(ref _backendUiFlushScheduled, 0);
        }

        private TelemetryEvent? MapIoctlRecord(IoctlParsedEvent record)
        {
            DateTime now = DateTime.UtcNow;
            if (record.Type == SleepwalkerNative.EventTypeHandle)
            {
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
                    TID = 0,
                    Group = "Kernel-IOCTL",
                    SubType = "Handle",
                    Summary = $"{className} caller={caller} target={target} access=0x{record.DesiredAccess:X8}",
                    Details = $"seq={record.Sequence} flags=0x{record.HandleFlags:X8} origin=0x{record.OriginAddress:X}"
                };
            }

            if (record.Type == SleepwalkerNative.EventTypeThread)
            {
                uint process = record.ProcessPid;
                uint creator = record.CreatorPid;
                return new TelemetryEvent
                {
                    TimestampUtc = now,
                    PID = unchecked((int)process),
                    TID = unchecked((int)record.ThreadId),
                    Group = "Kernel-IOCTL",
                    SubType = "Thread",
                    Summary = $"creator={creator} process={process} flags=0x{record.ThreadFlags:X8}",
                    Details = $"seq={record.Sequence} start=0x{record.StartAddress:X} imageBase=0x{record.ImageBase:X} imageSize=0x{record.ImageSize:X}"
                };
            }

            return null;
        }

        private void HandleBrokerEtwEvent(SleepwalkerNative.SwIpcEtwEvent etw)
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
            uint actor = etw.PrimaryPid is > 0 and <= uint.MaxValue ? (uint)etw.PrimaryPid : etw.EventProcessId;
            uint target = etw.SecondaryPid is > 0 and <= uint.MaxValue ? (uint)etw.SecondaryPid : 0;

            var view = new BrokerEtwEventView
            {
                TimestampUtc = DateTime.UtcNow,
                Source = source,
                EventName = eventName,
                Task = etw.Task,
                Opcode = etw.Opcode,
                EventId = etw.EventId,
                EventProcessId = etw.EventProcessId,
                EventThreadId = etw.EventThreadId,
                Severity = etw.Severity,
                ActorPid = actor,
                TargetPid = target,
                DetectionName = detection
            };

            EtwPaneHost.PushEvent(view);
            _explorer.FirstOrDefault(x => x.Name == "Sleepwalker ETW")?.PushPreviewValue(
                EtwPaneHost.SleepwalkerCount);
            _explorer.FirstOrDefault(x => x.Name == "ETW-TI")?.PushPreviewValue(EtwPaneHost.TiCount);
            SetExplorerHasData("Sleepwalker ETW", EtwPaneHost.SleepwalkerCount > 0);
            SetExplorerHasData("ETW-TI", EtwPaneHost.TiCount > 0);

            string timelineGroup = source == "ThreatIntel" ? "ETW-TI" : "Sleepwalker-ETW";
            string summary = !string.IsNullOrWhiteSpace(detection)
                ? $"{detection} sev={etw.Severity}"
                : $"task={etw.Task} opcode={etw.Opcode}";

            AppendEvent(new TelemetryEvent
            {
                TimestampUtc = view.TimestampUtc,
                PID = unchecked((int)actor),
                TID = unchecked((int)view.EventThreadId),
                Group = timelineGroup,
                SubType = eventName,
                Summary = summary,
                Details = view.Details
            });

            if (!string.IsNullOrWhiteSpace(detection))
            {
                var heuristic = new HeuristicEventView
                {
                    TimestampUtc = view.TimestampUtc,
                    Severity = etw.Severity,
                    DetectionName = detection,
                    ActorPid = actor,
                    TargetPid = target,
                    Source = source,
                    EventName = eventName
                };
                HeuristicsPaneHost.PushHeuristic(heuristic);
                _explorer.FirstOrDefault(x => x.Name == "Heuristics")?.PushPreviewValue(
                    HeuristicsPaneHost.ItemCount);
                SetExplorerHasData("Heuristics", HeuristicsPaneHost.ItemCount > 0);
                DiagnosticsState.Increment("Heuristics");
            }
        }

        private void SaveIntelSessionState(int pid)
        {
            if (pid <= 0)
            {
                return;
            }

            _sleepwalkerEtwHistoryByPid[pid] = EtwPaneHost.SnapshotSleepwalkerEvents().Select(x => x.Clone()).ToList();
            _tiEtwHistoryByPid[pid] = EtwPaneHost.SnapshotTiEvents().Select(x => x.Clone()).ToList();
            _heuristicsHistoryByPid[pid] = HeuristicsPaneHost.SnapshotItems().Select(x => x.Clone()).ToList();
        }

        private void RestoreIntelSessionState(int pid)
        {
            IEnumerable<BrokerEtwEventView> sleepwalker = _sleepwalkerEtwHistoryByPid.TryGetValue(pid, out var a)
                ? a
                : Array.Empty<BrokerEtwEventView>();
            IEnumerable<BrokerEtwEventView> ti = _tiEtwHistoryByPid.TryGetValue(pid, out var b)
                ? b
                : Array.Empty<BrokerEtwEventView>();
            IEnumerable<HeuristicEventView> heur = _heuristicsHistoryByPid.TryGetValue(pid, out var c)
                ? c
                : Array.Empty<HeuristicEventView>();

            EtwPaneHost.LoadHistory(sleepwalker, ti);
            HeuristicsPaneHost.LoadHistory(heur);
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
                StatusBlock.Text = "Status: Driver/service uplink healthy";
                SetBackendConnectivity(true);
                return;
            }

            string detail = string.Join("; ", issues);
            string signature = detail;
            string msg = $"Could not fully connect to driver/service: {detail}";

            DiagnosticsState.SetValue("Connectivity", $"FAILED: {detail}");
            OutputCapture.AppendLine(msg);
            StatusBlock.Text = "Status: Driver/service uplink failed";
            SetBackendConnectivity(false);

            bool shouldWarn = userInitiated || !string.Equals(_lastConnectivityIssueSignature, signature, StringComparison.Ordinal);
            if (shouldWarn)
            {
                MessageBox.Show(
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
                StatusBlock.Text = "Status: Driver started and uplink healthy";
            }
        }

        private async void DriverStop_Click(object sender, RoutedEventArgs e)
        {
            if (MessageBox.Show(this, "Stop the kernel driver 'sleepwlkr'?", "Driver Stop", MessageBoxButton.YesNo,
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
                StatusBlock.Text = "Status: Controller restarted and uplink healthy";
            }
        }
    }
}
