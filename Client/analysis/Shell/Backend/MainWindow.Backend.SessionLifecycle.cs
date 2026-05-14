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
using System.Windows.Media;

namespace BlackbirdInterface
{
    public partial class MainWindow
    {
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
            _extendedStringRows.Clear();
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
                _captureProjection.SetExecutionPhase(
                    _targetExecutionSuspended ? CaptureExecutionPhase.PreResume : CaptureExecutionPhase.Active,
                    DateTime.UtcNow, _targetExecutionSuspended ? "session-start-suspended" : "session-start-active");
                _captureProjection.HeuristicsMaterialized += findings =>
                    PublishProjectionFindings(generation, findings);
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

                var session = preparedSession ?? BlackbirdBackendSession.Start(pid, BlackbirdNative.StreamAll,
                                                                               useUsermodeHooks, _useKernelDriver);
                _backendSession = session;
                StartPackerDetectorForSession(pid, generation);

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
                DisposePackerDetector();
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

        private void StartPackerDetectorForSession(int pid, int generation)
        {
            DisposePackerDetector();
            if (pid <= 0)
            {
                return;
            }

            string? workspaceRoot = _currentSession?.BackingStorePath;
            if (string.IsNullOrWhiteSpace(workspaceRoot))
            {
                workspaceRoot = Path.Combine(Path.GetTempPath(), "Blackbird", "live", $"pid-{pid}");
            }

            _packerDetector =
                new PackerDetectionService(pid, workspaceRoot, _liveCaptureStore,
                                           message =>
                                           {
                                               _pendingStatusLines.Enqueue($"[packer pid={pid}] {message}");
                                               Interlocked.Increment(ref _pendingStatusCount);
                                               _backendTransformSignal.Set();
                                           },
                                           findings => PublishPackerDetectorFindings(generation, findings));
            if (_captureProjection != null)
            {
                _packerDetector.SetExecutionPhase(_captureProjection.ExecutionPhase);
            }

            string? imagePath =
                TryResolveProcessImagePath((uint)pid, out string resolvedImagePath) ? resolvedImagePath : null;
            _packerDetector.QueueInitialImageScan(imagePath);
        }

        private void PublishPackerDetectorFindings(int generation, IReadOnlyList<HeuristicEventView> findings)
        {
            if (findings.Count == 0 || generation != _backendGeneration)
            {
                return;
            }

            if (_captureProjection != null)
            {
                _captureProjection.ObserveHeuristics(findings);
                return;
            }

            PublishProjectionFindings(generation, findings);
        }

        private void PublishProjectionFindings(int generation, IReadOnlyList<HeuristicEventView> findings)
        {
            if (findings.Count == 0 || generation != _backendGeneration)
            {
                return;
            }

            for (int i = 0; i < findings.Count; i += 1)
            {
                HeuristicEventView finding = findings[i];
                ProcessIdentityResolver.Prime(finding.ActorPid);
                ProcessIdentityResolver.Prime(finding.TargetPid);
                TryEnqueueUiWork(BackendUiWorkItem.FromIoctl(null, null, finding, null, null));
            }

            ScheduleBackendUiFlush(generation);
        }

        private void DisposePackerDetector()
        {
            PackerDetectionService? detector = _packerDetector;
            _packerDetector = null;
            if (detector == null)
            {
                return;
            }

            try
            {
                detector.Dispose();
            }
            catch
            {
            }
        }

        private void StopBackendSession(bool preserveApiGraphSnapshot = false, bool fastTeardown = false)
        {
            _liveAnalysisSession = null;
            if (_backendSession == null)
            {
                DisposePackerDetector();
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
            DisposePackerDetector();
            _captureProjection?.WaitForPendingStackCaptures(fastTeardown ? TimeSpan.FromMilliseconds(50)
                                                                         : TimeSpan.FromSeconds(1));
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
                _extendedStringRows.Clear();
                _extendedCapabilityRows.Clear();
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
    }
}
