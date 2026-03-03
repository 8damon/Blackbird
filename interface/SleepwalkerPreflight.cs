using System;
using System.Runtime.InteropServices;

namespace SleepwalkerInterface
{
    internal sealed class SleepwalkerPreflightReport
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

    internal static class SleepwalkerPreflight
    {
        public static SleepwalkerPreflightReport Run(int targetPid)
        {
            var report = new SleepwalkerPreflightReport
            {
                CheckedUtc = DateTime.UtcNow,
                DriverState = SleepwalkerServiceControl.QueryState("sleepwlkr"),
                ControllerState = SleepwalkerServiceControl.QueryState("SleepwlkrController")
            };

            IntPtr h = IntPtr.Zero;
            try
            {
                if (!SleepwalkerNative.UseClientProtocol(null, 1500))
                {
                    throw SleepwalkerNative.LastError("UseClientProtocol failed");
                }

                h = SleepwalkerNative.OpenControlDevice();
                if (h == IntPtr.Zero || h == new IntPtr(-1))
                {
                    throw SleepwalkerNative.LastError("OpenControlDevice failed");
                }

                report.BrokerConnectOk = true;
                DiagnosticsState.SetValue("BrokerHandle", "Open");

                if (SleepwalkerNative.GetBrokerInfo(out uint caps, out bool tiEnabled))
                {
                    report.BrokerCapabilities = caps;
                    report.ThreatIntelEnabled = tiEnabled;
                    report.EtwUplinkCapable = (caps & SleepwalkerNative.IpcCapEtwTiUplink) != 0;
                }

                report.ThreatIntelEnableError = SleepwalkerNative.GetBrokerThreatIntelEnableError();

                if (targetPid > 0)
                {
                    var pids = new[] { (uint)targetPid };
                    _ = SleepwalkerNative.SetPids(h, pids, 1, SleepwalkerNative.StreamAll);
                }

                if (SleepwalkerNative.GetStats(h, out var stats, out _))
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
                    bool ok = SleepwalkerNative.GetEtwEvent(h, out _, 0);
                    if (ok)
                    {
                        report.EtwUplinkQueryOk = true;
                    }
                    else
                    {
                        int err = Marshal.GetLastWin32Error();
                        report.EtwUplinkQueryOk = err == SleepwalkerNative.ErrorNoMoreItems;
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
                    _ = SleepwalkerNative.CloseHandle(h);
                }
            }

            DiagnosticsState.SetValue("Preflight", report.Summary);
            return report;
        }

    }
}
