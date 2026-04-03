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

        public bool StartupReady =>
            string.IsNullOrWhiteSpace(Error) &&
            string.Equals(DriverState, "Running", StringComparison.OrdinalIgnoreCase) &&
            string.Equals(ControllerState, "Running", StringComparison.OrdinalIgnoreCase) &&
            HookDllExists &&
            BrokerConnectOk &&
            (!DriverProxyRequired || DriverProxyOk);

        public string Summary
        {
            get
            {
                if (!string.IsNullOrWhiteSpace(Error))
                {
                    return $"preflight failed: {Error}";
                }

                string proxyState = DriverProxyRequired ? (DriverProxyOk ? "ok" : "fail") : (DriverProxyOk ? "ok" : "deferred");
                return $"driver={DriverState} controller={ControllerState} broker={(BrokerConnectOk ? "ok" : "down")} proxy={proxyState} hookDll={(HookDllExists ? "ok" : "missing")} etwUplink={(EtwUplinkCapable ? "yes" : "no")}";
            }
        }

        public string BuildStartupFailureMessage()
        {
            return
                "Startup preflight failed.\n\n" +
                $"Driver service: {DriverState}\n" +
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
        public static BlackbirdPreflightReport Run(int targetPid, bool ensureServicesRunning = false, string? hookDllPath = null,
                                                   bool requireDriverProxy = true)
        {
            Console.WriteLine($"[Preflight] Starting  pid={targetPid} ensureServices={ensureServicesRunning}");
            var report = new BlackbirdPreflightReport
            {
                CheckedUtc = DateTime.UtcNow,
                DriverState = BlackbirdServiceControl.QueryState("blackbird"),
                ControllerState = BlackbirdServiceControl.QueryState("BlackbirdController"),
                HookDllPath = ResolveHookDllPath(hookDllPath),
                DriverProxyRequired = requireDriverProxy
            };
            report.HookDllExists = File.Exists(report.HookDllPath);
            Console.WriteLine($"[Preflight] Services  driver={report.DriverState} controller={report.ControllerState} hookDll={report.HookDllPath} exists={report.HookDllExists}");
            DiagnosticsState.SetValue("HookDLL", report.HookDllExists ? "Found" : $"Missing ({report.HookDllPath})");

            if (ensureServicesRunning)
            {
                Console.WriteLine("[Preflight] Ensuring services are running...");
                report.DriverState = EnsureServiceRunning("blackbird", TimeSpan.FromSeconds(8), out string driverMsg);
                report.DriverEnsureMessage = driverMsg;
                Console.WriteLine($"[Preflight] Driver ensure: state={report.DriverState} msg={driverMsg}");
                report.ControllerState = EnsureServiceRunning("BlackbirdController", TimeSpan.FromSeconds(10), out string controllerMsg);
                report.ControllerEnsureMessage = controllerMsg;
                Console.WriteLine($"[Preflight] Controller ensure: state={report.ControllerState} msg={controllerMsg}");
            }

            if (!BlackbirdControlDeviceSession.TryOpen(out var control, out string error))
            {
                report.Error = error;
                DiagnosticsState.SetValue("Preflight", report.Summary);
                Console.WriteLine($"[Preflight] Complete  {report.Summary}{(string.IsNullOrEmpty(report.Error) ? "" : $"  error={report.Error}")}");
                return report;
            }

            using (control)
            {
                report.BrokerConnectOk = true;
                DiagnosticsState.SetValue("BrokerHandle", "Open");

                if (BlackbirdNative.GetBrokerInfo(out uint caps, out bool tiEnabled))
                {
                    report.BrokerCapabilities = caps;
                    report.ThreatIntelEnabled = tiEnabled;
                    report.EtwUplinkCapable = (caps & BlackbirdNative.IpcCapEtwTiUplink) != 0;
                }

                report.ThreatIntelEnableError = BlackbirdNative.GetLastThreatIntelEnableError();

                if (targetPid > 0)
                {
                    var pids = new[] { (uint)targetPid };
                    _ = BlackbirdNative.SetPids(control.Handle, pids, 1, BlackbirdNative.StreamAll);
                }

                if (BlackbirdNative.GetStats(control.Handle, out var stats, out _))
                {
                    report.DriverProxyOk = true;
                    DiagnosticsState.SetValue("DriverProxy", "OK");
                    DiagnosticsState.SetValue("DriverStats", $"subs={stats.SubscriptionCount} depth={stats.QueueDepth} dropped={stats.DroppedEvents}");
                }
                else
                {
                    report.DriverProxyOk = false;
                    int err = Marshal.GetLastWin32Error();
                    string proxyState = !report.DriverProxyRequired && err == 5
                        ? "Deferred (awaiting interface authentication)"
                        : $"Error {err}";
                    DiagnosticsState.SetValue("DriverProxy", proxyState);
                }

                if (report.EtwUplinkCapable)
                {
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
            }

            DiagnosticsState.SetValue("Preflight", report.Summary);
            Console.WriteLine($"[Preflight] Complete  {report.Summary}{(string.IsNullOrEmpty(report.Error) ? "" : $"  error={report.Error}")}");
            return report;
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

