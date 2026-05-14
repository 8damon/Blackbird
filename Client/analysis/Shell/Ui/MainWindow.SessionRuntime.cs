using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Input;
using System.Windows.Threading;

namespace BlackbirdInterface
{
    public partial class MainWindow
    {
        private void Perf_SampleArrived(object? sender, PerformanceSample e)
        {
            if (!Dispatcher.CheckAccess())
            {
                Dispatcher.BeginInvoke(new Action(() => Perf_SampleArrived(sender, e)));
                return;
            }

            if (_currentSession != null)
            {
                _captureProjection?.ObservePerformance(e);
                _currentSession.PerformanceHistory.Add(ClonePerformanceSample(e));
                if (_currentSession.PerformanceHistory.Count > 4000)
                    _currentSession.PerformanceHistory.RemoveRange(0, _currentSession.PerformanceHistory.Count - 4000);
            }

            var evCount = _focusedEvents.Count;
            var eventsItem = _explorer.FirstOrDefault(x => x.Name == "Events");
            eventsItem?.PushPreviewValue(evCount);

            var perfItem = _explorer.FirstOrDefault(x => x.Name == "Performance");
            perfItem?.PushPreviewValue(e.CpuPercent);
            _hasPerformanceData = true;
            SetExplorerHasData("Performance", true);

            PerformancePaneHost.PushSample(e);

            SyncPerformanceViewToTimeline();
        }

        private void StartLiveCaptureForPid(int pid, bool useUsermodeHooks, bool launchStartsSuspended = false,
                                            bool fastBackendRestart = false)
        {
            if (pid <= 0 || _perf == null)
                return;

            _targetExecutionSuspended = launchStartsSuspended;
            ConfigureSr71PreResumeGate(pid, useUsermodeHooks && launchStartsSuspended);

            if (_currentSession != null && _currentSession.Pid == pid && _currentSession.Events.Count == 0 &&
                _currentSession.PerformanceHistory.Count == 0 && _currentSession.ThreadLifecycleHistory.Count == 0)
            {
                double viewDuration = Math.Max(1, EventsPaneHost.Timeline.ViewDurationSeconds);
                _captureStartUtc = AnchorCaptureStartUtc(viewDuration);
                _latestEventTimestampUtc = _captureStartUtc;
                _currentSession.CaptureStartUtc = _captureStartUtc;
                _currentSession.ViewDurationSeconds = viewDuration;
                _currentSession.ViewStartSeconds = 0;

                EventsPaneHost.Timeline.CaptureStartUtc = _captureStartUtc;
                EventsPaneHost.Timeline.ViewDurationSeconds = viewDuration;
                EventsPaneHost.Timeline.ViewStartSeconds = 0;
                EventsPaneHost.Scroll.Value = 0;
                UpdateScrollBar();
                FocusViewport();
                PerformancePaneHost.SetCaptureStart(_captureStartUtc);
                SyncPerformanceViewToTimeline();
            }

            _perf.SetTargetPid(pid);
            _perf.Start();
            _samplerPid = pid;
            PerformancePaneHost.SetProcessLiveDataAvailable(true);
            PerformancePaneHost.SetTargetSuspended(launchStartsSuspended);
            PerformancePaneHost.RefreshLiveProcessDetails();
            StartTargetExitWatcher(pid);
            EnsureLiveCaptureStoreForCurrentSession(pid);
            StartBackendForPid(pid, useUsermodeHooks, fastStopExistingSession: fastBackendRestart);
            if (_backendSession != null)
            {
                TrackLiveAnalysisSession(pid, _currentSession);
            }
            bool autoOpenApiGraph = _currentSession?.AutoOpenApiGraphOnNextStart == true;
            if (_currentSession != null)
            {
                _currentSession.AutoOpenApiGraphOnNextStart = false;
            }
            SetMainInterfaceViewMode(useUsermodeHooks && autoOpenApiGraph ? MainInterfaceViewMode.Api
                                                                          : MainInterfaceViewMode.Telemetry);
            StatusBlock.Text = $"LIVE CAPTURE: {NormalizeSessionTitle(_currentSession?.Title ?? $"PID {pid}")}";
            RefreshProcessStateBadge();
        }

        private void StartTargetExitWatcher(int pid)
        {
            StopTargetExitWatcher();
            if (pid <= 0)
                return;

            Process? process = null;
            try
            {
                process = Process.GetProcessById(pid);
                process.EnableRaisingEvents = true;
                process.Exited += TargetExitWatchProcess_Exited;
                _targetExitWatchProcess = process;
                _targetExitWatchPid = pid;
                process = null;
                if (_targetExitWatchProcess.HasExited)
                {
                    HandleTargetProcessExit(pid, BuildProcessExitReason(_targetExitWatchProcess));
                }
            }
            catch
            {
                process?.Dispose();
                _targetExitWatchProcess?.Dispose();
                _targetExitWatchProcess = null;
                _targetExitWatchPid = 0;
                if (!Dispatcher.HasShutdownStarted)
                    Dispatcher.BeginInvoke(new Action(ValidateCurrentSessionState));
            }
        }

        private void StopTargetExitWatcher()
        {
            if (_targetExitWatchProcess != null)
            {
                try
                {
                    _targetExitWatchProcess.Exited -= TargetExitWatchProcess_Exited;
                }
                catch
                {
                }

                try
                {
                    _targetExitWatchProcess.Dispose();
                }
                catch
                {
                }
            }

            _targetExitWatchProcess = null;
            _targetExitWatchPid = 0;
        }

        private void TargetExitWatchProcess_Exited(object? sender, EventArgs e)
        {
            int pid = 0;
            string exitReason = string.Empty;
            if (sender is Process p)
            {
                try
                {
                    pid = p.Id;
                    exitReason = BuildProcessExitReason(p);
                }
                catch
                {
                    pid = 0;
                }
            }

            if (pid <= 0)
                pid = _targetExitWatchPid;

            Dispatcher.BeginInvoke(new Action(() => HandleTargetProcessExit(pid, exitReason)));
        }

        private static string BuildProcessExitReason(Process process)
        {
            try
            {
                return $"process exited exitCode=0x{unchecked((uint)process.ExitCode):X8}";
            }
            catch
            {
                return "process exited; exit code unavailable";
            }
        }

        private void HandleTargetProcessExit(int pid, string? observedReason = null)
        {
            if (pid <= 0)
                return;

            ProcessSessionTab? exitedTab = _processTabs.FirstOrDefault(x => x.Pid == pid);
            if (exitedTab == null || exitedTab.TargetExited)
                return;

            exitedTab.TargetExited = true;
            _targetExitReasonByPid.TryGetValue(unchecked((uint)pid), out string? remembered);
            string exitReason = !string.IsNullOrWhiteSpace(remembered)
                                    ? remembered
                                    : (!string.IsNullOrWhiteSpace(observedReason)
                                           ? observedReason.Trim()
                                           : "process exited; cause not observed before teardown");
            exitedTab.TargetExitReason = exitReason;
            MarkSessionExited(exitedTab);

            if (!ReferenceEquals(_currentSession, exitedTab))
            {
                if (exitedTab.ActivePauseStartUtc.HasValue)
                {
                    exitedTab.PausedTimelineSpans.Add(
                        new PausedTimelineSpan { StartUtc = exitedTab.ActivePauseStartUtc.Value,
                                                 EndUtc = DateTime.UtcNow });
                    exitedTab.ActivePauseStartUtc = null;
                }
                SaveTabToBackingStore(exitedTab);
                RefreshProcessStateBadge();
                return;
            }

            AppendEvent(new TelemetryEvent { TimestampUtc = DateTime.UtcNow, PID = pid, TID = 0, Group = "Session",
                                             SubType = "ProcessExit", Summary = "TARGET PROCESS EXITED",
                                             Details = $"{exitReason}. Data capture stopped for this tab." });
            AppendOutputFromAnyThread($"Target process exited pid={pid} reason={exitReason}");

            StopLiveAnalysisSession(LiveAnalysisStopReason.TargetExited, preserveApiGraphSnapshot: true,
                                    fastTeardown: true, stopPerformance: true);
            if (exitedTab.ActivePauseStartUtc.HasValue)
            {
                exitedTab.PausedTimelineSpans.Add(
                    new PausedTimelineSpan { StartUtc = exitedTab.ActivePauseStartUtc.Value,
                                             EndUtc = DateTime.UtcNow });
                exitedTab.ActivePauseStartUtc = null;
            }
            SyncCurrentSessionStateToMemory();
            _ = TryPersistCurrentSessionAfterStop();

            StatusBlock.Text = $"Capture stopped; target exited: {exitReason}";
            RefreshProcessStateBadge();
            ThemedMessageBox.ShowToast(this, $"Target process {pid} exited: {exitReason}", "Target Exited",
                                       MessageBoxImage.Warning, durationMs: 5000);
        }

        private void ValidateCurrentSessionState()
        {
            if (_currentSession == null || _currentSession.Pid <= 0 || _currentSession.OfflineSnapshot ||
                _currentSession.TargetExited)
            {
                return;
            }

            if (TryOpenTargetProcess(_currentSession.Pid, out _, out _, out bool accessDenied))
            {
                return;
            }

            if (!accessDenied)
            {
                HandleTargetProcessExit(_currentSession.Pid);
            }
        }

        private static void MarkSessionExited(ProcessSessionTab tab)
        {
            tab.Title = NormalizeSessionTitle(tab.Title);
        }

        private bool TryOpenTargetProcess(int pid, out string processName, out string failure, out bool accessDenied)
        {
            processName = string.Empty;
            failure = string.Empty;
            accessDenied = false;

            Process? process = null;
            try
            {
                process = Process.GetProcessById(pid);
                processName = process.ProcessName;
                if (process.HasExited)
                {
                    failure = $"TARGET PID {pid} HAS EXITED";
                    return false;
                }
            }
            catch (ArgumentException)
            {
                failure = $"PID {pid} NOT FOUND";
                return false;
            }
            catch (InvalidOperationException)
            {
                failure = $"PID {pid} IS NOT AVAILABLE";
                return false;
            }
            catch (Win32Exception ex)
            {
                if (ex.NativeErrorCode != 5)
                {
                    failure = $"FAILED TO OPEN PID {pid} (WIN32 {ex.NativeErrorCode})";
                    return false;
                }

                processName = $"PID {pid}";
            }
            finally
            {
                try
                {
                    process?.Dispose();
                }
                catch
                {
                }
            }

            IntPtr handle = Kernel32Native.OpenProcess(ProcessQueryLimitedInformation | ProcessSynchronize, false,
                                                       unchecked((uint)pid));
            if (handle == IntPtr.Zero)
            {
                int err = Marshal.GetLastWin32Error();
                accessDenied = err == 5;
                failure = accessDenied ? $"ACCESS DENIED TO PID {pid}" : $"FAILED TO OPEN PID {pid} (WIN32 {err})";
                return false;
            }

            _ = Kernel32Native.CloseHandle(handle);
            return true;
        }

        private int TryGetPid()
        {
            if (PidBox == null)
                return 0;
            var s = PidBox.Text?.Trim();
            if (string.IsNullOrWhiteSpace(s))
                return _currentSession?.Pid ?? 0;
            if (int.TryParse(s, out int pid) && pid > 0)
                return pid;
            return 0;
        }

        private string GetProcessTabTitle(int pid)
        {
            try
            {
                using var p = Process.GetProcessById(pid);
                return $"{p.ProcessName} (Silo)";
            }
            catch
            {
                return $"PID {pid} (Silo)";
            }
        }

        private void FlashSwitchToast(string label)
        {
            SwitchToastText.Text = label;
            SwitchToastBorder.Visibility = Visibility.Visible;

            var fadeIn = new DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(120));
            var fadeOut = new DoubleAnimation(
                1, 0, TimeSpan.FromMilliseconds(300)) { BeginTime = TimeSpan.FromMilliseconds(900) };
            fadeOut.Completed += (_, __) => SwitchToastBorder.Visibility = Visibility.Collapsed;

            var storyboard = new Storyboard();
            Storyboard.SetTarget(fadeIn, SwitchToastBorder);
            Storyboard.SetTargetProperty(fadeIn, new PropertyPath(OpacityProperty));
            Storyboard.SetTarget(fadeOut, SwitchToastBorder);
            Storyboard.SetTargetProperty(fadeOut, new PropertyPath(OpacityProperty));
            storyboard.Children.Add(fadeIn);
            storyboard.Children.Add(fadeOut);
            storyboard.Begin();
        }

        private ProcessSessionTab AddOrSelectProcessTab(int pid, string title, bool select)
        {
            var existing = _processTabs.FirstOrDefault(t => t.Pid == pid);
            if (existing == null)
            {
                double initialDuration = EventsPaneHost?.Timeline != null
                                             ? Math.Clamp(EventsPaneHost.Timeline.ViewDurationSeconds, 1, 120)
                                             : DefaultTimelineViewDurationSeconds;
                existing = new ProcessSessionTab { Pid = pid,
                                                   Title = NormalizeSessionTitle(title),
                                                   CaptureStartUtc = AnchorCaptureStartUtc(initialDuration),
                                                   ViewDurationSeconds = initialDuration,
                                                   ViewStartSeconds = 0,
                                                   KernelHooksEnabled = _kernelHooksArmed,
                                                   SignatureIntelEnabled = _signatureIntelEnabled,
                                                   SignatureIntelMemoryScanEnabled = _signatureIntelMemoryScanEnabled,
                                                   SignatureIntelPageScanEnabled = _signatureIntelPageScanEnabled };
                _processTabs.Add(existing);
            }
            else
            {
                existing.Title = NormalizeSessionTitle(title);
            }

            if (select)
            {
                _suppressTabSelectionChange = true;
                ProcessTabs.SelectedItem = existing;
                _suppressTabSelectionChange = false;
            }

            return existing;
        }

        private static string NormalizeSessionTitle(string? title)
        {
            string value = string.IsNullOrWhiteSpace(title) ? "PID" : title.Trim();
            while (value.EndsWith("[EXITED]", StringComparison.OrdinalIgnoreCase))
            {
                value = value[..^ "[EXITED]".Length].TrimEnd();
            }

            return value;
        }

        private void SyncCurrentSessionViewportStateToMemory()
        {
            if (_currentSession == null)
                return;

            _currentSession.CaptureStartUtc = _captureStartUtc;
            _currentSession.LaneFocusKey = _laneFocusKey;
            _currentSession.ViewDurationSeconds = EventsPaneHost.Timeline.ViewDurationSeconds;
            _currentSession.ViewStartSeconds = EventsPaneHost.Timeline.ViewStartSeconds;
            SaveIntelSessionState(_currentSession.Pid);
        }

        private void SyncCurrentSessionStateToMemory()
        {
            if (_currentSession == null)
                return;

            SyncCurrentSessionViewportStateToMemory();
            if (!CurrentSessionEventMirrorLooksCurrent())
            {
                _currentSession.Events.Clear();
                _currentSession.Events.AddRange(_allEvents.Select(CloneTelemetryEvent));
            }
        }

        private bool CurrentSessionEventMirrorLooksCurrent()
        {
            if (_currentSession == null || _currentSession.Events.Count != _allEvents.Count)
            {
                return false;
            }

            if (_allEvents.Count == 0)
            {
                return true;
            }

            TelemetryEvent mirrored = _currentSession.Events[^1];
            TelemetryEvent live = _allEvents[^1];
            return mirrored.TimestampUtc == live.TimestampUtc && mirrored.PID == live.PID && mirrored.TID == live.TID &&
                   string.Equals(mirrored.Group, live.Group, StringComparison.Ordinal) &&
                   string.Equals(mirrored.SubType, live.SubType, StringComparison.Ordinal);
        }

        private void SaveCurrentSessionState()
        {
            if (_currentSession == null)
                return;

            SyncCurrentSessionStateToMemory();
            if (_currentSession.OfflineSnapshot || _liveCaptureStore == null)
            {
                SaveTabToBackingStore(_currentSession);
            }
        }

        private bool TryPersistCurrentSessionAfterStop()
        {
            if (_currentSession == null)
            {
                return false;
            }

            try
            {
                SyncCurrentSessionStateToMemory();
                SaveTabToBackingStore(_currentSession);
                return true;
            }
            catch
            {
                return false;
            }
        }

        private void RestoreSessionState(ProcessSessionTab tab)
        {
            EnsureSessionMaterialized(tab);
            double restoredDuration = Math.Clamp(
                tab.ViewDurationSeconds <= 0 ? DefaultTimelineViewDurationSeconds : tab.ViewDurationSeconds, 1, 120);
            bool freshSession = !tab.OfflineSnapshot && tab.Events.Count == 0 && tab.PerformanceHistory.Count == 0 &&
                                tab.ThreadLifecycleHistory.Count == 0;
            if (freshSession)
            {
                tab.CaptureStartUtc = AnchorCaptureStartUtc(restoredDuration);
                tab.ViewStartSeconds = 0;
            }

            _captureStartUtc =
                tab.CaptureStartUtc == default ? AnchorCaptureStartUtc(restoredDuration) : tab.CaptureStartUtc;
            _laneFocusKey = tab.LaneFocusKey;

            _allEvents.Clear();
            _knownLaneKeys.Clear();
            _telemetryTextPool.Clear();
            _focusedEvents.Clear();
            EventsPaneHost.Timeline.Items.Clear();
            EventsPaneHost.Timeline.ClearAllLaneFilters();
            ClearSelectedEvent();

            IEnumerable<TelemetryEvent> restoreEvents =
                TelemetryEventsAreTimestampSorted(tab.Events) ? tab.Events : tab.Events.OrderBy(x => x.TimestampUtc);
            foreach (var ev in restoreEvents)
            {
                _allEvents.Add(NormalizeTelemetryEventForStore(ev));
            }
            _latestEventTimestampUtc = _allEvents.Count > 0 ? _allEvents[^1].TimestampUtc : _captureStartUtc;

            EventsPaneHost.Timeline.CaptureStartUtc = _captureStartUtc;
            EventsPaneHost.Timeline.ViewDurationSeconds = restoredDuration;
            EventsPaneHost.Timeline.ViewStartSeconds = Math.Max(0, tab.ViewStartSeconds);
            ApplyPausedTimelineRanges();
            UpdateScrollBar();
            EventsPaneHost.Scroll.Value =
                Math.Min(EventsPaneHost.Scroll.Maximum, EventsPaneHost.Timeline.ViewStartSeconds);
            FocusViewport();

            PerformancePaneHost.SetCaptureStart(_captureStartUtc);
            PerformancePaneHost.SetPid(tab.Pid);
            PerformancePaneHost.SetAnalysisSubject(tab.AnalysisSubjectPath, tab.AnalysisHostPath);
            DiagnosticsState.SetValue("Analysis Subject", tab.AnalysisSubjectKind == LaunchTargetKind.Dll &&
                                                                  !string.IsNullOrWhiteSpace(tab.AnalysisSubjectPath)
                                                              ? tab.AnalysisSubjectPath
                                                              : "Process image");
            PerformancePaneHost.LoadHistory(tab.PerformanceHistory);
            PerformancePaneHost.LoadMemoryRegionAttributionHistory(tab.MemoryRegionAttributionHistory);
            PerformancePaneHost.LoadThreadLifecycleHistory(tab.ThreadLifecycleHistory);
            PerformancePaneHost.LoadThreadStackHistory(tab.ThreadStackHistories);
            RestoreIntelSessionState(tab.Pid);
            SyncPerformanceViewToTimeline();
            _hasPerformanceData = tab.PerformanceHistory.Count > 0;
            SetExplorerHasData("Performance", tab.PerformanceHistory.Count > 0);
            EventsPaneHost.SetHasData(_allEvents.Count > 0);
            RefreshExplorerDataBadges();
            RefreshChildProcessGraphWindowIfOpen();
        }

        private void SwitchToSession(ProcessSessionTab tab)
        {
            if (ReferenceEquals(_currentSession, tab))
            {
                return;
            }

            if (_currentSession != null && !ReferenceEquals(_currentSession, tab))
            {
                SaveChildProcessGraphStateToSession(_currentSession);
                SyncCurrentSessionViewportStateToMemory();
                FlashSwitchToast($"Switched to {tab.Title}");
            }

            _currentSession = tab;
            PidBox.Text = tab.Pid.ToString();
            RefreshSubsystemSegmentationDiagnostics();
            RestoreChildProcessGraphStateFromSession(tab);

            RestoreSessionState(tab);

            if (tab.OfflineSnapshot)
            {
                StopLiveAnalysisSession(LiveAnalysisStopReason.SessionSwitch, preserveApiGraphSnapshot: true,
                                        fastTeardown: true, stopPerformance: true);
                StatusBlock.Text = $"OFFLINE SESSION: {tab.Title}";
                RefreshProcessStateBadge();
                return;
            }

            if (tab.TargetExited)
            {
                StopLiveAnalysisSession(LiveAnalysisStopReason.SessionSwitch, preserveApiGraphSnapshot: true,
                                        fastTeardown: true, stopPerformance: true);
                StatusBlock.Text = "Capture stopped; historical data remains available.";
                RefreshProcessStateBadge();
                return;
            }

            bool allowPreparedProtectedAttach =
                _preparedLaunchBackendSession != null && _preparedLaunchBackendPid == tab.Pid && tab.UseUsermodeHooks;

            if (!TryOpenTargetProcess(tab.Pid, out _, out var failure, out var accessDenied))
            {
                if (!allowPreparedProtectedAttach)
                {
                    StopLiveAnalysisSession(LiveAnalysisStopReason.SessionSwitch, preserveApiGraphSnapshot: true,
                                            fastTeardown: true, stopPerformance: true);
                    if (!accessDenied)
                    {
                        tab.TargetExited = true;
                        MarkSessionExited(tab);
                        StatusBlock.Text = "Capture stopped; historical data remains available.";
                    }
                    else
                    {
                        StatusBlock.Text = $"Access denied to PID {tab.Pid}. Capture stopped.";
                    }
                    RefreshProcessStateBadge();
                    return;
                }

                OutputCapture.AppendLine(
                    $"Protected launch session accepted without direct process-open access: PID {tab.Pid}");
            }

            bool launchStartsSuspended = tab.LaunchStartsSuspendedPending;
            tab.LaunchStartsSuspendedPending = false;
            StartLiveCaptureForPid(tab.Pid, tab.UseUsermodeHooks, launchStartsSuspended, fastBackendRestart: true);
        }

        private static bool TelemetryEventsAreTimestampSorted(IReadOnlyList<TelemetryEvent> events)
        {
            for (int i = 1; i < events.Count; i += 1)
            {
                if (events[i].TimestampUtc < events[i - 1].TimestampUtc)
                {
                    return false;
                }
            }

            return true;
        }
    }
}
