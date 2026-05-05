using System;
using System.IO;
using System.Runtime.InteropServices;

namespace BlackbirdInterface
{
    internal sealed class BlackbirdPreflightReport
    {
        public DateTime CheckedUtc { get; set; }
        public string DriverState { get; set; } = "Unknown";
        public string ControllerState { get; set; } = "Unknown";
        public string HookDllPath { get; set; } = string.Empty;
        public bool HookDllExists { get; set; }
        public bool BrokerConnectOk { get; set; }
        public bool DriverProxyOk { get; set; }
        public bool DriverProxyRequired { get; set; } = true;
        public bool EtwUplinkCapable { get; set; }
        public bool EtwUplinkQueryOk { get; set; }
        public bool ThreatIntelEnabled { get; set; }
        public uint BrokerCapabilities { get; set; }
        public uint ThreatIntelEnableError { get; set; }
        public string DriverEnsureMessage { get; set; } = string.Empty;
        public string ControllerEnsureMessage { get; set; } = string.Empty;
        public string Error { get; set; } = "";

        public bool DriverServiceRunning => string.Equals(DriverState, "Running", StringComparison.OrdinalIgnoreCase);

        public bool DriverRuntimeReady => DriverServiceRunning || DriverProxyOk;

        public string DriverDisplayState =>
            DriverServiceRunning || !DriverProxyOk ? DriverState : $"{DriverState} (runtime OK via controller proxy)";

        public bool StartupReady => string.IsNullOrWhiteSpace(Error) && DriverRuntimeReady &&
                                    string.Equals(ControllerState, "Running", StringComparison.OrdinalIgnoreCase) &&
                                    HookDllExists && BrokerConnectOk && (!DriverProxyRequired || DriverProxyOk);

        public string Summary
        {
            get {
                if (!string.IsNullOrWhiteSpace(Error))
                {
                    return $"preflight failed: {Error}";
                }

                string proxyState =
                    DriverProxyRequired ? (DriverProxyOk ? "ok" : "fail") : (DriverProxyOk ? "ok" : "deferred");
                return $"driver={DriverDisplayState} controller={ControllerState} broker={(BrokerConnectOk ? "ok" : "down")} proxy={proxyState} hookDll={(HookDllExists ? "ok" : "missing")} etwUplink={(EtwUplinkCapable ? "yes" : "no")}";
            }
        }

        public string BuildStartupFailureMessage()
        {
            return "Startup preflight failed.\n\n" + $"Driver service: {DriverDisplayState}\n" +
                   $"Controller service: {ControllerState}\n" +
                   $"Hook DLL: {(HookDllExists ? "Found" : "Missing")} ({HookDllPath})\n" +
                   $"Broker link: {(BrokerConnectOk ? "OK" : "Failed")}\n" +
                   $"Driver proxy: {(DriverProxyRequired ? (DriverProxyOk ? "OK" : "Failed") : (DriverProxyOk ? "OK" : "Deferred until interface authentication"))}\n" +
                   $"{(string.IsNullOrWhiteSpace(DriverEnsureMessage) ? string.Empty : $"Driver ensure: {DriverEnsureMessage}\n")}" +
                   $"{(string.IsNullOrWhiteSpace(ControllerEnsureMessage) ? string.Empty : $"Controller ensure: {ControllerEnsureMessage}\n")}" +
                   $"{(string.IsNullOrWhiteSpace(Error) ? string.Empty : $"\nError: {Error}\n")}";
        }
    }

    internal static class BlackbirdPreflight
    {
        private static void ReportProgress(Action<double, string, string?>? progress, double percent, string status,
                                           string? detail = null)
        {
            progress?.Invoke(percent, status, detail);
        }

        public static BlackbirdPreflightReport Run(int targetPid, bool ensureServicesRunning = false,
                                                   string? hookDllPath = null, bool requireDriverProxy = true,
                                                   Action<double, string, string?>? progress = null)
        {
            ReportProgress(progress, 8, "Running startup preflight...",
                           "Checking services, SR71 availability, and controller uplink.");
            Console.WriteLine($"[Preflight] Starting  pid={targetPid} ensureServices={ensureServicesRunning}");
            var report = new BlackbirdPreflightReport {
                CheckedUtc = DateTime.UtcNow, DriverState = BlackbirdServiceControl.QueryDriverState("blackbird"),
                ControllerState = BlackbirdServiceControl.QueryState("BlackbirdController"),
                HookDllPath = ResolveHookDllPath(hookDllPath), DriverProxyRequired = requireDriverProxy
            };
            report.HookDllExists = File.Exists(report.HookDllPath);
            Console.WriteLine(
                $"[Preflight] Services  driver={report.DriverState} controller={report.ControllerState} hookDll={report.HookDllPath} exists={report.HookDllExists}");
            DiagnosticsState.SetValue("HookDLL", report.HookDllExists ? "Found" : $"Missing ({report.HookDllPath})");
            DiagnosticsState.SetValue("HookDLL Presence",
                                      report.HookDllExists ? "Found" : $"Missing ({report.HookDllPath})");
            DiagnosticsState.SetValue("Driver Service", report.DriverDisplayState);
            DiagnosticsState.SetValue("Controller Service", report.ControllerState);

            string? abiError = BlackbirdNative.ValidateManagedAbiLayout();
            if (!string.IsNullOrWhiteSpace(abiError))
            {
                report.Error = $"managed/native ABI mismatch: {abiError}";
                DiagnosticsState.SetValue("Interface ABI", report.Error);
                DiagnosticsState.SetValue("Preflight", report.Summary);
                ReportProgress(progress, 100, "Startup preflight blocked", report.Error);
                Console.WriteLine($"[Preflight] Complete  {report.Summary}  error={report.Error}");
                return report;
            }
            DiagnosticsState.SetValue("Interface ABI", "OK");

            if (ensureServicesRunning)
            {
                ReportProgress(progress, 26, "Ensuring Blackbird services are running...",
                               "Starting the driver/controller if they are not already online.");
                Console.WriteLine("[Preflight] Ensuring services are running...");
                report.DriverState = EnsureDriverRunning("blackbird", TimeSpan.FromSeconds(8), out string driverMsg);
                report.DriverEnsureMessage = driverMsg;
                Console.WriteLine($"[Preflight] Driver ensure: state={report.DriverState} msg={driverMsg}");
                report.ControllerState =
                    EnsureServiceRunning("BlackbirdController", TimeSpan.FromSeconds(10), out string controllerMsg);
                report.ControllerEnsureMessage = controllerMsg;
                Console.WriteLine($"[Preflight] Controller ensure: state={report.ControllerState} msg={controllerMsg}");
                DiagnosticsState.SetValue("Driver Service", report.DriverDisplayState);
                DiagnosticsState.SetValue("Controller Service", report.ControllerState);
            }

            ReportProgress(progress, 54, "Opening controller uplink...", "Verifying interface-to-controller IPC.");
            if (!BkctlDeviceSession.TryOpen(out var control, out string error))
            {
                report.Error = error;
                DiagnosticsState.SetValue("Interface->Controller IPC", $"FAILED: {error}");
                if (error.IndexOf("access denied", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    DiagnosticsState.SetValue("DACLs", "Access denied");
                }
                DiagnosticsState.SetValue("Preflight", report.Summary);
                ReportProgress(progress, 100, "Startup preflight blocked",
                               string.IsNullOrWhiteSpace(error) ? report.Summary : error);
                Console.WriteLine(
                    $"[Preflight] Complete  {report.Summary}{(string.IsNullOrEmpty(report.Error) ? "" : $"  error={report.Error}")}");
                return report;
            }

            using (control)
            {
                ReportProgress(progress, 72, "Controller uplink ready...",
                               "Checking broker capabilities and driver proxy state.");
                report.BrokerConnectOk = true;
                DiagnosticsState.SetValue("BrokerHandle", "Open");
                DiagnosticsState.SetValue("Interface->Controller IPC", "OK");
                DiagnosticsState.SetValue("DACLs", "OK");

                if (BlackbirdNative.GetBrokerInfo(out uint caps, out bool tiEnabled))
                {
                    report.BrokerCapabilities = caps;
                    report.ThreatIntelEnabled = tiEnabled;
                    report.EtwUplinkCapable = (caps & BlackbirdNative.IpcCapEtwTiUplink) != 0;
                }

                report.ThreatIntelEnableError = BlackbirdNative.GetLastThreatIntelEnableError();

                if (targetPid > 0)
                {
                    ReportProgress(progress, 74, "Configuring driver monitor set...",
                                   "Sending target PID selection through the controller proxy.");
                    var pids = new[] { (uint)targetPid };
                    _ = BlackbirdNative.SetPids(control.Handle, pids, 1, BlackbirdNative.StreamAll);
                }

                ReportProgress(progress, 76, "Checking driver proxy...",
                               "Querying controller-to-driver statistics.");
                if (BlackbirdNative.GetStats(control.Handle, out var stats, out _))
                {
                    report.DriverProxyOk = true;
                    DiagnosticsState.SetValue("Driver Runtime", "OK via controller proxy");
                    DiagnosticsState.SetValue("Driver Service", report.DriverDisplayState);
                    DiagnosticsState.SetValue("DriverProxy", "OK");
                    DiagnosticsState.SetValue(
                        "DriverStats",
                        $"subs={stats.SubscriptionCount} depth={stats.QueueDepth} dropped={stats.DroppedEvents}");
                    DiagnosticsState.SetValue("SR71 Hook Ready", BlackbirdBackendSession.BuildHookReadySummary(
                                                                     stats.HookReadyMask, stats.HookReadyRequiredMask));
                    DiagnosticsState.SetValue("SR71 Instrumentation",
                                              BlackbirdBackendSession.BuildInstrumentationSummary(
                                                  stats.InstrumentationRangeCount, stats.HookPatchCount,
                                                  stats.HookPatchOverlayCount, stats.InstrumentationReadDenyCount,
                                                  stats.HookReadyMask, stats.HookReadyRequiredMask));
                    DiagnosticsState.SetValue("Controller<->Driver Comms",
                                              $"OK depth={stats.QueueDepth} dropped={stats.DroppedEvents}");
                }
                else
                {
                    report.DriverProxyOk = false;
                    int err = Marshal.GetLastWin32Error();
                    string proxyState = !report.DriverProxyRequired && err == 5
                                            ? "Deferred (awaiting interface authentication)"
                                            : $"Error {err}";
                    DiagnosticsState.SetValue("DriverProxy", proxyState);
                    DiagnosticsState.SetValue("Driver Runtime",
                                              report.DriverServiceRunning ? "OK via service state" : proxyState);
                    DiagnosticsState.SetValue("Controller<->Driver Comms", proxyState);
                }

                ReportProgress(progress, 80, "Checking driver health...",
                               "Reading kernel subsystem readiness flags.");
                if (BlackbirdNative.GetHealth(control.Handle, out var health, out _))
                {
                    DiagnosticsState.SetValue("Driver Health", $"mask=0x{health.HealthMask:X8}");
                    DiagnosticsState.SetValue("Driver Tamper", health.TamperMask == 0
                                                                   ? "OK mask=0x00000000"
                                                                    : $"DEGRADED mask=0x{health.TamperMask:X8}");
                }
                ReportProgress(progress, 84, "Checking driver diagnostics...",
                               "Reading kernel init and subsystem state snapshot.");
                if (BlackbirdNative.GetDiagnostics(control.Handle, out var diagnostics, out _))
                {
                    DiagnosticsState.SetValue(
                        "Driver Diagnostics",
                        $"OK events={diagnostics.EventCount} nextSeq={diagnostics.NextSequence} dropped={diagnostics.DroppedCount}");
                }

                if (report.EtwUplinkCapable)
                {
                    ReportProgress(progress, 88, "Checking ETW uplink...",
                                   "Validating ETW/threat-intel query readiness.");
                    bool ok = BlackbirdNative.GetEtwEvent(control.Handle, out _, 0);
                    if (ok)
                    {
                        report.EtwUplinkQueryOk = true;
                    }
                    else
                    {
                        int err = Marshal.GetLastWin32Error();
                        report.EtwUplinkQueryOk = err == BlackbirdNative.ErrorNoMoreItems;
                    }
                }
                else
                {
                    report.EtwUplinkQueryOk = false;
                }

                DiagnosticsState.SetValue(
                    "ETW Status", report.EtwUplinkCapable
                                      ? (report.EtwUplinkQueryOk
                                             ? (report.ThreatIntelEnabled ? "Ready (ThreatIntel enabled)" : "Ready")
                                             : "Degraded")
                                      : "Unsupported");
            }

            DiagnosticsState.SetValue("Preflight", report.Summary);
            ReportProgress(progress, 100,
                           report.StartupReady ? "Startup preflight ready" : "Startup preflight degraded",
                           report.Summary);
            Console.WriteLine(
                $"[Preflight] Complete  {report.Summary}{(string.IsNullOrEmpty(report.Error) ? "" : $"  error={report.Error}")}");
            return report;
        }

        private static string EnsureDriverRunning(string serviceName, TimeSpan timeout, out string message)
        {
            string before = BlackbirdServiceControl.QueryDriverState(serviceName);
            if (string.Equals(before, "Running", StringComparison.OrdinalIgnoreCase))
            {
                message = "already running";
                return before;
            }

            if (string.Equals(before, "NotInstalled", StringComparison.OrdinalIgnoreCase))
            {
                message = "service not installed";
                return before;
            }

            if (BlackbirdServiceControl.TryStart(serviceName, timeout, out string startMessage))
            {
                message = startMessage;
            }
            else
            {
                message = startMessage;
            }

            return BlackbirdServiceControl.QueryDriverState(serviceName);
        }

        private static string ResolveHookDllPath(string? requestedPath)
        {
            if (!string.IsNullOrWhiteSpace(requestedPath))
            {
                return requestedPath;
            }

            string baseDirectory = AppContext.BaseDirectory;
            if (string.IsNullOrWhiteSpace(baseDirectory))
            {
                baseDirectory = Environment.CurrentDirectory;
            }

            return Path.Combine(baseDirectory, "SR71.dll");
        }

        private static string EnsureServiceRunning(string serviceName, TimeSpan timeout, out string message)
        {
            string before = BlackbirdServiceControl.QueryState(serviceName);
            if (string.Equals(before, "Running", StringComparison.OrdinalIgnoreCase))
            {
                message = "already running";
                return before;
            }

            if (string.Equals(before, "NotInstalled", StringComparison.OrdinalIgnoreCase))
            {
                message = "service not installed";
                return before;
            }

            if (BlackbirdServiceControl.TryStart(serviceName, timeout, out string startMessage))
            {
                message = startMessage;
            }
            else
            {
                message = startMessage;
            }

            return BlackbirdServiceControl.QueryState(serviceName);
        }
    }
}
