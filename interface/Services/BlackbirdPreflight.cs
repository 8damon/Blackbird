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
            DriverProxyOk;

        public string Summary
        {
            get
            {
                if (!string.IsNullOrWhiteSpace(Error))
                {
                    return $"preflight failed: {Error}";
                }

                return $"driver={DriverState} controller={ControllerState} broker={(BrokerConnectOk ? "ok" : "down")} proxy={(DriverProxyOk ? "ok" : "fail")} hookDll={(HookDllExists ? "ok" : "missing")} etwUplink={(EtwUplinkCapable ? "yes" : "no")}";
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
                $"Driver proxy: {(DriverProxyOk ? "OK" : "Failed")}\n" +
                $"{(string.IsNullOrWhiteSpace(DriverEnsureMessage) ? string.Empty : $"Driver ensure: {DriverEnsureMessage}\n")}" +
                $"{(string.IsNullOrWhiteSpace(ControllerEnsureMessage) ? string.Empty : $"Controller ensure: {ControllerEnsureMessage}\n")}" +
                $"{(string.IsNullOrWhiteSpace(Error) ? string.Empty : $"\nError: {Error}\n")}";
        }
    }

    internal static class BlackbirdPreflight
    {
        public static BlackbirdPreflightReport Run(int targetPid, bool ensureServicesRunning = false, string? hookDllPath = null)
        {
            var report = new BlackbirdPreflightReport
            {
                CheckedUtc = DateTime.UtcNow,
                DriverState = BlackbirdServiceControl.QueryState("blackbird"),
                ControllerState = BlackbirdServiceControl.QueryState("BlackbirdController"),
                HookDllPath = ResolveHookDllPath(hookDllPath)
            };
            report.HookDllExists = File.Exists(report.HookDllPath);
            DiagnosticsState.SetValue("HookDLL", report.HookDllExists ? "Found" : $"Missing ({report.HookDllPath})");

            if (ensureServicesRunning)
            {
                report.DriverState = EnsureServiceRunning("blackbird", TimeSpan.FromSeconds(8), out string driverMsg);
                report.DriverEnsureMessage = driverMsg;
                report.ControllerState = EnsureServiceRunning("BlackbirdController", TimeSpan.FromSeconds(10), out string controllerMsg);
                report.ControllerEnsureMessage = controllerMsg;
            }

            IntPtr h = IntPtr.Zero;
            try
            {
                if (!BlackbirdNative.UseClientProtocol(null, 1500))
                {
                    throw BlackbirdNative.LastError("UseClientProtocol failed");
                }

                h = BlackbirdNative.OpenControlDevice();
                if (h == IntPtr.Zero || h == new IntPtr(-1))
                {
                    throw BlackbirdNative.LastError("OpenControlDevice failed");
                }

                report.BrokerConnectOk = true;
                DiagnosticsState.SetValue("BrokerHandle", "Open");

                if (BlackbirdNative.GetBrokerInfo(out uint caps, out bool tiEnabled))
                {
                    report.BrokerCapabilities = caps;
                    report.ThreatIntelEnabled = tiEnabled;
                    report.EtwUplinkCapable = (caps & BlackbirdNative.IpcCapEtwTiUplink) != 0;
                }

                report.ThreatIntelEnableError = BlackbirdNative.GetBrokerThreatIntelEnableError();

                if (targetPid > 0)
                {
                    var pids = new[] { (uint)targetPid };
                    _ = BlackbirdNative.SetPids(h, pids, 1, BlackbirdNative.StreamAll);
                }

                if (BlackbirdNative.GetStats(h, out var stats, out _))
                {
                    report.DriverProxyOk = true;
                    DiagnosticsState.SetValue("DriverProxy", "OK");
                    DiagnosticsState.SetValue("DriverStats", $"subs={stats.SubscriptionCount} depth={stats.QueueDepth} dropped={stats.DroppedEvents}");
                }
                else
                {
                    report.DriverProxyOk = false;
                    int err = Marshal.GetLastWin32Error();
                    DiagnosticsState.SetValue("DriverProxy", $"Error {err}");
                }

                if (report.EtwUplinkCapable)
                {
                    bool ok = BlackbirdNative.GetEtwEvent(h, out _, 0);
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
            catch (Exception ex)
            {
                report.Error = ex.Message;
            }
            finally
            {
                if (h != IntPtr.Zero && h != new IntPtr(-1))
                {
                    _ = BlackbirdNative.CloseControlDevice(h);
                }
            }

            DiagnosticsState.SetValue("Preflight", report.Summary);
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

            return Path.Combine(baseDirectory, "sr71.dll");
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
