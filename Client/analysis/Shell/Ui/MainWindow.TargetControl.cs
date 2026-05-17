using BlackbirdInterface.Capture;
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
        private void Suspend_Click(object sender, RoutedEventArgs e)
        {
            if (!TryControlTargetExecution(suspend: true, out string error))
            {
                ThemedMessageBox.Show(this, error, "Suspend Target", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            _targetExecutionSuspended = true;
            _captureProjection?.SetExecutionPhase(CaptureExecutionPhase.Paused, DateTime.UtcNow, "operator-suspend");
            _packerDetector?.SetExecutionPhase(
                _captureProjection?.ExecutionPhase ??
                CaptureExecutionPolicy.CreateState(CaptureExecutionPhase.Paused, DateTime.UtcNow,
                                                   CaptureExecutionPhaseState.ActiveDefault));
            if (_currentSession != null && !_currentSession.OfflineSnapshot && !_currentSession.TargetExited &&
                !_currentSession.ActivePauseStartUtc.HasValue)
            {
                _currentSession.ActivePauseStartUtc = DateTime.UtcNow;
            }
            _perf?.Stop();
            PerformancePaneHost.SetTargetSuspended(true);
            PerformancePaneHost.SetProcessLiveDataAvailable(false);
            PerformancePaneHost.RefreshLiveProcessDetails();
            ApplyPausedTimelineRanges();
            SetIntegrityDiagnosticsForSuspension();
            StatusBlock.Text = $"TARGET PAUSED: PID {TryGetPid()}";
            RefreshProcessStateBadge();
            RefreshToolbarCommandState();
        }

        private void Resume_Click(object sender, RoutedEventArgs e)
        {
            if (!TryControlTargetExecution(suspend: false, out string error))
            {
                ThemedMessageBox.Show(this, error, "Resume Target", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            if (_currentSession != null)
            {
                _currentSession.DeferredLaunchGateResumePending = false;
            }
            DateTime resumeUtc = DateTime.UtcNow;
            MarkSr71PreResumeGateReleased(resumeUtc);
            _targetExecutionSuspended = false;
            ClearIntegrityDiagnosticsForSuspension();
            PerformancePaneHost.SetTargetSuspended(false);
            if (_currentSession != null && _currentSession.ActivePauseStartUtc.HasValue)
            {
                _currentSession.PausedTimelineSpans.Add(
                    new PausedTimelineSpan { StartUtc = _currentSession.ActivePauseStartUtc.Value,
                                             EndUtc = resumeUtc });
                _currentSession.ActivePauseStartUtc = null;
                _latestEventTimestampUtc = resumeUtc;
                ApplyPausedTimelineRanges();
                UpdateScrollBar();
                _followLiveTimeline = true;
                double viewport = Math.Max(1, EventsPaneHost.Scroll.ViewportSize);
                double maxStart = ComputeTimelineMaxStart(viewport);
                EventsPaneHost.Timeline.ViewStartSeconds = maxStart;
                EventsPaneHost.Scroll.Value = maxStart;
                SyncPerformanceViewToTimeline();
            }
            if (_currentSession != null && !_currentSession.OfflineSnapshot && !_currentSession.TargetExited &&
                _perf != null)
            {
                _perf.SetTargetPid(_currentSession.Pid);
                _perf.ResetBaselines();
                _perf.Start();
                _perf.RequestImmediateSample();
            }
            PerformancePaneHost.SetProcessLiveDataAvailable(true);
            PerformancePaneHost.RefreshLiveProcessDetails();
            SchedulePostResumeProcessRefresh(pid: _currentSession?.Pid ?? TryGetPid());
            StatusBlock.Text = $"TARGET RESUMED: PID {TryGetPid()}";
            RefreshProcessStateBadge();
            RefreshToolbarCommandState();
        }

        private void SchedulePostResumeProcessRefresh(int pid)
        {
            if (pid <= 0)
            {
                return;
            }

            _ = Task.Run(async () =>
                         {
                             await Task.Delay(250).ConfigureAwait(false);
                             await Dispatcher.InvokeAsync(
                                 () =>
                                 {
                                     ProcessSessionTab? session = _currentSession;
                                     if (_targetExecutionSuspended || session == null || session.Pid != pid ||
                                         session.TargetExited)
                                     {
                                         return;
                                     }

                                     _perf?.RequestImmediateSample();
                                     PerformancePaneHost.SetProcessLiveDataAvailable(true);
                                     PerformancePaneHost.RefreshLiveProcessDetails();
                                     RefreshProcessStateBadge();
                                     RefreshToolbarCommandState();
                                 },
                                 DispatcherPriority.Background);
                         });
        }

        private static readonly string[] _integrityDiagnosticKeys =
            ["Hook Integrity", "AMSI Integrity", "ETW Integrity"];

        private static void SetIntegrityDiagnosticsForSuspension()
        {
            foreach (string key in _integrityDiagnosticKeys)
            {
                string? current = DiagnosticsState.GetValue(key);
                if (current != null && current.Contains("Disabled", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                DiagnosticsState.SetValue(
                    key,
                    "Awaiting target resume (pre-arm; SR71 injected but integrity verdicts are deferred until user code runs)");
            }
            if (DiagnosticsState.GetValue("Usermode Hooks")?.Contains("Disabled", StringComparison.OrdinalIgnoreCase) !=
                true)
            {
                DiagnosticsState.SetValue("Usermode Hooks", "Awaiting target resume (pre-arm)");
            }
        }

        private static void ClearIntegrityDiagnosticsForSuspension()
        {
            foreach (string key in _integrityDiagnosticKeys)
            {
                string? current = DiagnosticsState.GetValue(key);
                if (current != null &&
                    (current.Contains("INACTIVE", StringComparison.OrdinalIgnoreCase) ||
                     current.Contains("pre-arm", StringComparison.OrdinalIgnoreCase)))
                {
                    DiagnosticsState.SetValue(key, "Awaiting SR71 telemetry (target resumed)");
                }
            }
            string? usermodeHooks = DiagnosticsState.GetValue("Usermode Hooks");
            if (usermodeHooks?.Contains("INACTIVE", StringComparison.OrdinalIgnoreCase) == true ||
                usermodeHooks?.Contains("pre-arm", StringComparison.OrdinalIgnoreCase) == true)
            {
                DiagnosticsState.SetValue("Usermode Hooks", "Awaiting SR71 telemetry (target resumed)");
            }
        }

        private void TerminateLaunchOwnedTargetsOnShutdown()
        {
            foreach (ProcessSessionTab tab in _processTabs)
            {
                if (!tab.LaunchOwnedByInterface || tab.OfflineSnapshot || tab.TargetExited || tab.Pid <= 0)
                {
                    continue;
                }

                if (TryTerminateTargetProcess(tab.Pid, out _))
                {
                    tab.TargetExited = true;
                }
            }
        }

        private void TerminateTarget_Click(object sender, RoutedEventArgs e)
        {
            int pid = _currentSession?.Pid ?? TryGetPid();
            if (pid <= 0)
            {
                ThemedMessageBox.Show(this, "No target process is selected.", "Terminate Target", MessageBoxButton.OK,
                                      MessageBoxImage.Warning);
                return;
            }

            if (_currentSession?.OfflineSnapshot == true)
            {
                ThemedMessageBox.Show(this, "Cannot terminate an offline session.", "Terminate Target",
                                      MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            if (_currentSession?.TargetExited == true)
            {
                ThemedMessageBox.Show(this, $"PID {pid} has already exited.", "Terminate Target", MessageBoxButton.OK,
                                      MessageBoxImage.Information);
                return;
            }

            var confirm = ThemedMessageBox.Show(this, $"Terminate PID {pid} and stop live capture for this tab?",
                                                "Terminate Target", MessageBoxButton.YesNo, MessageBoxImage.Warning);
            if (confirm != MessageBoxResult.Yes)
            {
                return;
            }

            if (!TryTerminateTargetProcess(pid, out string error))
            {
                ThemedMessageBox.Show(this, error, "Terminate Target", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            HandleTargetProcessExit(pid);
        }
        private void Restart_Click(object sender, RoutedEventArgs e)
        {
        }

        private bool TryControlTargetExecution(bool suspend, out string error)
        {
            error = string.Empty;
            int pid = _currentSession?.Pid ?? TryGetPid();
            if (pid <= 0)
            {
                error = "No target process is selected.";
                return false;
            }

            if (_currentSession?.OfflineSnapshot == true)
            {
                error = "Cannot control execution for an offline session.";
                return false;
            }

            if (_currentSession?.TargetExited == true)
            {
                error = $"PID {pid} has already exited.";
                return false;
            }

            if (_backendSession == null)
            {
                error = "No active backend session.";
                return false;
            }

            bool ok = _backendSession.ControlProcessExecution(unchecked((uint)pid), suspend);
            if (!ok)
            {
                int ioErr = Marshal.GetLastWin32Error();
                error = $"{(suspend ? "Suspend" : "Resume")} failed via controller (win32={ioErr}).";
                return false;
            }

            return true;
        }

        private static string AppendEnvironmentOverride(string existing, string line)
        {
            if (string.IsNullOrWhiteSpace(line))
            {
                return existing ?? string.Empty;
            }

            if (string.IsNullOrWhiteSpace(existing))
            {
                return line;
            }

            string[] entries = existing.Replace("\r\n", "\n", StringComparison.Ordinal)
                                   .Replace('\r', '\n')
                                   .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

            int separator = line.IndexOf('=');
            if (separator > 0)
            {
                string name = line[..separator];
                foreach (string entry in entries)
                {
                    int existingSeparator = entry.IndexOf('=');
                    if (existingSeparator > 0 &&
                        string.Equals(entry[..existingSeparator], name, StringComparison.OrdinalIgnoreCase))
                    {
                        return existing;
                    }
                }
            }

            return existing + "\n" + line;
        }

        private bool TryTerminateTargetProcess(int pid, out string error)
        {
            error = string.Empty;
            IntPtr handle = Kernel32Native.OpenProcess(
                ProcessTerminate | ProcessQueryLimitedInformation | ProcessSynchronize, false, unchecked((uint)pid));
            if (handle == IntPtr.Zero)
            {
                int openErr = Marshal.GetLastWin32Error();
                error = $"Failed to open PID {pid} for termination (win32={openErr}).";
                return false;
            }

            try
            {
                if (!Kernel32Native.TerminateProcess(handle, 1))
                {
                    int terminateErr = Marshal.GetLastWin32Error();
                    error = $"TerminateProcess failed for PID {pid} (win32={terminateErr}).";
                    return false;
                }

                return true;
            }
            finally
            {
                _ = Kernel32Native.CloseHandle(handle);
            }
        }
    }
}
