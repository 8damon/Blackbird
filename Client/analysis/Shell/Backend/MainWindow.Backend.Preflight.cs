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
using System.Windows.Shapes;

namespace BlackbirdInterface
{
    public partial class MainWindow
    {
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
    }
}
