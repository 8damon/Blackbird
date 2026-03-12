using System;
using System.Runtime.InteropServices;

namespace BlackbirdInterface
{
    internal sealed class BlackbirdPreflightReport
    {
        public DateTime CheckedUtc { get; set; }
        public string DriverState { get; set; } = "Unknown";
        public string ControllerState { get; set; } = "Unknown";
        public bool BrokerConnectOk { get; set; }
        public bool DriverProxyOk { get; set; }
        public bool EtwUplinkCapable { get; set; }
        public bool EtwUplinkQueryOk { get; set; }
        public bool ThreatIntelEnabled { get; set; }
        public uint BrokerCapabilities { get; set; }
        public uint ThreatIntelEnableError { get; set; }
        public string Error { get; set; } = "";

        public string Summary
        {
            get
            {
                if (!string.IsNullOrWhiteSpace(Error))
                {
                    return $"preflight failed: {Error}";
                }

                return $"driver={DriverState} controller={ControllerState} broker={(BrokerConnectOk ? "ok" : "down")} proxy={(DriverProxyOk ? "ok" : "fail")} etwUplink={(EtwUplinkCapable ? "yes" : "no")}";
            }
        }
    }

    internal static class BlackbirdPreflight
    {
        public static BlackbirdPreflightReport Run(int targetPid)
        {
            var report = new BlackbirdPreflightReport
            {
                CheckedUtc = DateTime.UtcNow,
                DriverState = BlackbirdServiceControl.QueryState("blackbird"),
                ControllerState = BlackbirdServiceControl.QueryState("BlackbirdController")
            };

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

    }
}
