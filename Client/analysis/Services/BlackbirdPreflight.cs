using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using Microsoft.Win32;

namespace BlackbirdInterface
{
    internal sealed class BlackbirdPreflightReport
    {
        public DateTime CheckedUtc { get; set; }
        public string DriverState { get; set; } = "Unknown";
        public string ControllerState { get; set; } = "Unknown";
        public string HookDllPath { get; set; } = string.Empty;
        public bool HookDllExists { get; set; }
        public string ControllerBinaryPath { get; set; } = string.Empty;
        public bool ControllerBinaryOk { get; set; }
        public string ControllerBinaryMessage { get; set; } = string.Empty;
        public bool BrokerConnectOk { get; set; }
        public bool HookPipeReady { get; set; }
        public string HookPipeMessage { get; set; } = string.Empty;
        public bool DriverProxyOk { get; set; }
        public bool DriverProxyRequired { get; set; } = true;
        public bool KernelDriverEnabled { get; set; } = true;
        public bool EtwUplinkCapable { get; set; }
        public bool EtwUplinkQueryOk { get; set; }
        public bool ThreatIntelEnabled { get; set; }
        public uint BrokerCapabilities { get; set; }
        public uint ThreatIntelEnableError { get; set; }
        public string DriverEnsureMessage { get; set; } = string.Empty;
        public string ControllerEnsureMessage { get; set; } = string.Empty;
        public string AutoRegistrationMessage { get; set; } = string.Empty;
        public string Error { get; set; } = "";

        public bool DriverServiceRunning => string.Equals(DriverState, "Running", StringComparison.OrdinalIgnoreCase);

        public bool DriverRuntimeReady => DriverServiceRunning || DriverProxyOk;

        public string DriverDisplayState =>
            DriverServiceRunning || !DriverProxyOk ? DriverState : $"{DriverState} (runtime OK via controller proxy)";

        public bool StartupReady => string.IsNullOrWhiteSpace(Error) && (!KernelDriverEnabled || DriverRuntimeReady) &&
                                    string.Equals(ControllerState, "Running", StringComparison.OrdinalIgnoreCase) &&
                                    ControllerBinaryOk && HookDllExists && BrokerConnectOk && HookPipeReady &&
                                    (!KernelDriverEnabled || !DriverProxyRequired || DriverProxyOk);

        public bool CanContinueDriverless =>
            string.Equals(ControllerState, "Running", StringComparison.OrdinalIgnoreCase) && ControllerBinaryOk &&
            HookDllExists && BrokerConnectOk && HookPipeReady;

        public string Summary
        {
            get {
                if (!string.IsNullOrWhiteSpace(Error))
                {
                    return $"preflight failed: {Error}";
                }

                string driverState = KernelDriverEnabled ? DriverDisplayState : "Driverless";
                string proxyState = !KernelDriverEnabled ? "driverless"
                                                         : (DriverProxyRequired ? (DriverProxyOk ? "ok" : "fail")
                                                                                : (DriverProxyOk ? "ok" : "deferred"));
                return $"driver={driverState} controller={ControllerState} controllerImage={(ControllerBinaryOk ? "ok" : "bad")} broker={(BrokerConnectOk ? "ok" : "down")} hookPipe={(HookPipeReady ? "ok" : "down")} proxy={proxyState} hookDll={(HookDllExists ? "ok" : "missing")} etwUplink={(EtwUplinkCapable ? "yes" : "no")}";
            }
        }

        public string BuildStartupFailureMessage()
        {
            return "Startup preflight failed.\n\n" +
                   $"Driver service: {(KernelDriverEnabled ? DriverDisplayState : "Driverless mode")}\n" +
                   $"Controller service: {ControllerState}\n" +
                   $"Controller binary: {(ControllerBinaryOk ? "OK" : "Invalid")} ({ControllerBinaryMessage})\n" +
                   $"Hook DLL: {(HookDllExists ? "Found" : "Missing")} ({HookDllPath})\n" +
                   $"Broker link: {(BrokerConnectOk ? "OK" : "Failed")}\n" +
                   $"Hook ingest pipe: {(HookPipeReady ? "OK" : "Failed")} ({HookPipeMessage})\n" +
                   $"Driver proxy: {(!KernelDriverEnabled ? "Skipped" : (DriverProxyRequired ? (DriverProxyOk ? "OK" : "Failed") : (DriverProxyOk ? "OK" : "Deferred until interface authentication")))}\n" +
                   $"{(string.IsNullOrWhiteSpace(DriverEnsureMessage) ? string.Empty : $"Driver ensure: {DriverEnsureMessage}\n")}" +
                   $"{(string.IsNullOrWhiteSpace(ControllerEnsureMessage) ? string.Empty : $"Controller ensure: {ControllerEnsureMessage}\n")}" +
                   $"{(string.IsNullOrWhiteSpace(AutoRegistrationMessage) ? string.Empty : $"Auto registration: {AutoRegistrationMessage}\n")}" +
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
                                                   bool enableKernelDriver = true,
                                                   Action<double, string, string?>? progress = null)
        {
            ReportProgress(progress, 8, "Running startup preflight...",
                           enableKernelDriver ? "Checking services, SR71 availability, and controller uplink."
                                              : "Checking controller, SR71 availability, and user-mode uplink.");
            Console.WriteLine(
                $"[Preflight] Starting  pid={targetPid} ensureServices={ensureServicesRunning} kernelDriver={enableKernelDriver}");
            string fallbackControllerPath =
                BlackbirdPackageResolver.ResolvePackageArtifact("BlackbirdController.exe") ??
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Blackbird",
                             "BlackbirdController.exe");
            var report = new BlackbirdPreflightReport {
                CheckedUtc = DateTime.UtcNow,
                DriverState = BlackbirdServiceControl.QueryDriverState("blackbird"),
                ControllerState = BlackbirdServiceControl.QueryState("BlackbirdController"),
                HookDllPath = ResolveHookDllPath(hookDllPath),
                DriverProxyRequired = requireDriverProxy,
                KernelDriverEnabled = enableKernelDriver,
                ControllerBinaryPath = ResolveServiceBinaryPath("BlackbirdController", fallbackControllerPath)
            };
            report.HookDllExists = File.Exists(report.HookDllPath);
            report.ControllerBinaryOk =
                ValidateControllerServiceBinary(report.ControllerBinaryPath, out string controllerBinaryMessage);
            report.ControllerBinaryMessage = controllerBinaryMessage;
            Console.WriteLine(
                $"[Preflight] Services  driver={report.DriverState} controller={report.ControllerState} controllerImage={report.ControllerBinaryPath} controllerImageOk={report.ControllerBinaryOk} hookDll={report.HookDllPath} exists={report.HookDllExists}");
            DiagnosticsState.SetValue("HookDLL", report.HookDllExists ? "Found" : $"Missing ({report.HookDllPath})");
            DiagnosticsState.SetValue("HookDLL Presence",
                                      report.HookDllExists ? "Found" : $"Missing ({report.HookDllPath})");
            DiagnosticsState.SetValue("Controller Binary", report.ControllerBinaryMessage);
            DiagnosticsState.SetValue("Driver Service",
                                      enableKernelDriver ? report.DriverDisplayState : "Skipped (driverless mode)");
            DiagnosticsState.SetValue("Controller Service", report.ControllerState);

            if (ensureServicesRunning && ShouldAttemptAutoRegistration(report))
            {
                ReportProgress(progress, 18, "Registering Blackbird services...",
                               "Services or required binaries are missing; running the bundled installer.");
                Console.WriteLine("[Preflight] Automatic service registration required");
                bool registered = BlackbirdAutoRegistration.TryRunOnce(progress, out string registrationMessage);
                report.AutoRegistrationMessage = registrationMessage;
                DiagnosticsState.SetValue("Auto Registration", registrationMessage);
                Console.WriteLine($"[Preflight] Automatic registration: ok={registered} msg={registrationMessage}");
                if (registered)
                {
                    RefreshInstallSensitiveState(report, hookDllPath);
                    DiagnosticsState.SetValue("HookDLL",
                                              report.HookDllExists ? "Found" : $"Missing ({report.HookDllPath})");
                    DiagnosticsState.SetValue("HookDLL Presence",
                                              report.HookDllExists ? "Found" : $"Missing ({report.HookDllPath})");
                    DiagnosticsState.SetValue("Controller Binary", report.ControllerBinaryMessage);
                    DiagnosticsState.SetValue("Driver Service", enableKernelDriver ? report.DriverDisplayState
                                                                                   : "Skipped (driverless mode)");
                    DiagnosticsState.SetValue("Controller Service", report.ControllerState);
                }
            }

            if (!report.ControllerBinaryOk)
            {
                report.Error = report.ControllerBinaryMessage;
                DiagnosticsState.SetValue("Preflight", report.Summary);
                ReportProgress(progress, 100, "Startup preflight blocked", report.Error);
                Console.WriteLine($"[Preflight] Complete  {report.Summary}  error={report.Error}");
                return report;
            }

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
                               enableKernelDriver ? "Starting the driver/controller if they are not already online."
                                                  : "Starting the controller if it is not already online.");
                Console.WriteLine("[Preflight] Ensuring services are running...");
                if (enableKernelDriver)
                {
                    report.DriverState =
                        EnsureDriverRunning("blackbird", TimeSpan.FromSeconds(8), out string driverMsg);
                    report.DriverEnsureMessage = driverMsg;
                    Console.WriteLine($"[Preflight] Driver ensure: state={report.DriverState} msg={driverMsg}");
                }
                else
                {
                    report.DriverEnsureMessage = "skipped by driverless startup option";
                    Console.WriteLine("[Preflight] Driver ensure skipped by driverless startup option");
                }
                report.ControllerState =
                    EnsureServiceRunning("BlackbirdController", TimeSpan.FromSeconds(10), out string controllerMsg);
                report.ControllerEnsureMessage = controllerMsg;
                Console.WriteLine($"[Preflight] Controller ensure: state={report.ControllerState} msg={controllerMsg}");
                DiagnosticsState.SetValue("Driver Service",
                                          enableKernelDriver ? report.DriverDisplayState : "Skipped (driverless mode)");
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
                report.HookPipeReady = ProbeHookIngestPipe(TimeSpan.FromSeconds(2), out string hookPipeMessage);
                report.HookPipeMessage = hookPipeMessage;
                DiagnosticsState.SetValue("HookDLL->Controller IPC", report.HookPipeReady
                                                                         ? $"OK ({hookPipeMessage})"
                                                                         : $"FAILED: {hookPipeMessage}");
                if (!report.HookPipeReady)
                {
                    report.Error = $"controller hook ingest pipe unavailable: {hookPipeMessage}";
                    DiagnosticsState.SetValue("Preflight", report.Summary);
                    ReportProgress(progress, 100, "Startup preflight blocked", report.Error);
                    Console.WriteLine($"[Preflight] Complete  {report.Summary}  error={report.Error}");
                    return report;
                }

                if (BlackbirdNative.GetBrokerInfo(out uint caps, out bool tiEnabled))
                {
                    report.BrokerCapabilities = caps;
                    report.ThreatIntelEnabled = tiEnabled;
                    report.EtwUplinkCapable = (caps & BlackbirdNative.IpcCapEtwTiUplink) != 0;
                    report.DriverProxyOk = enableKernelDriver && (caps & BlackbirdNative.IpcCapDriverProxy) != 0;
                }

                report.ThreatIntelEnableError = BlackbirdNative.GetLastThreatIntelEnableError();

                if (targetPid > 0)
                {
                    ReportProgress(progress, 74,
                                   enableKernelDriver ? "Configuring driver monitor set..."
                                                      : "Configuring user-mode monitor set...",
                                   enableKernelDriver ? "Sending target PID selection through the controller proxy."
                                                      : "Sending target PID selection for SR71 and ETW routing.");
                    var pids = new[] { (uint)targetPid };
                    uint streamMask = enableKernelDriver
                                          ? BlackbirdNative.StreamAll
                                          : BlackbirdNative.StreamAll | BlackbirdNative.StreamUsermodeOnly;
                    _ = BlackbirdNative.SetPids(control.Handle, pids, 1, streamMask);
                }

                ReportProgress(progress, 76,
                               enableKernelDriver ? "Checking driver proxy..." : "Skipping driver proxy...",
                               enableKernelDriver ? "Querying controller-to-driver statistics."
                                                  : "Driverless mode keeps controller/user-mode telemetry active.");
                if (BlackbirdNative.GetStats(control.Handle, out var stats, out _))
                {
                    DiagnosticsState.SetValue("Driver Runtime", report.DriverProxyOk
                                                                    ? "OK via controller proxy"
                                                                    : "Unavailable (driverless capable)");
                    DiagnosticsState.SetValue("Driver Service", enableKernelDriver ? report.DriverDisplayState
                                                                                   : "Skipped (driverless mode)");
                    DiagnosticsState.SetValue("DriverProxy", report.DriverProxyOk ? "OK" : "Unavailable");
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
                                              report.DriverProxyOk
                                                  ? $"OK depth={stats.QueueDepth} dropped={stats.DroppedEvents}"
                                                  : "Driverless mode");
                }
                else
                {
                    int err = Marshal.GetLastWin32Error();
                    string proxyState = !report.DriverProxyRequired && err == 5
                                            ? "Deferred (awaiting interface authentication)"
                                            : $"Error {err}";
                    DiagnosticsState.SetValue("DriverProxy", proxyState);
                    DiagnosticsState.SetValue("Driver Runtime",
                                              report.DriverServiceRunning ? "OK via service state" : proxyState);
                    DiagnosticsState.SetValue("Controller<->Driver Comms", proxyState);
                }

                ReportProgress(progress, 80,
                               report.DriverProxyOk ? "Checking driver health..." : "Skipping driver health...",
                               report.DriverProxyOk ? "Reading kernel subsystem readiness flags."
                                                    : "Kernel subsystem readiness is unavailable in driverless mode.");
                if (report.DriverProxyOk && BlackbirdNative.GetHealth(control.Handle, out var health, out _))
                {
                    DiagnosticsState.SetValue("Driver Health",
                                              BlackbirdBackendSession.BuildDriverHealthSummary(health));
                    DiagnosticsState.SetValue("Driver Tamper", health.TamperMask == 0
                                                                   ? "OK mask=0x00000000"
                                                                   : $"DEGRADED mask=0x{health.TamperMask:X8}");
                }
                ReportProgress(progress, 84,
                               report.DriverProxyOk ? "Checking driver diagnostics..."
                                                    : "Skipping driver diagnostics...",
                               report.DriverProxyOk ? "Reading kernel init and subsystem state snapshot."
                                                    : "Driver diagnostics are unavailable in driverless mode.");
                if (report.DriverProxyOk && BlackbirdNative.GetDiagnostics(control.Handle, out var diagnostics, out _))
                {
                    DiagnosticsState.SetValue(
                        "Driver Diagnostics",
                        $"OK events={diagnostics.EventCount} nextSeq={diagnostics.NextSequence} overwrittenTotal={diagnostics.DroppedCount}");
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

            return BlackbirdPackageResolver.ResolveRuntimeFile("SR71.dll");
        }

        private static bool ShouldAttemptAutoRegistration(BlackbirdPreflightReport report)
        {
            return IsMissing(report.DriverState) || IsMissing(report.ControllerState) || !report.ControllerBinaryOk ||
                   !report.HookDllExists;
        }

        private static bool IsMissing(string state) => state.Equals("NotInstalled",
                                                                    StringComparison.OrdinalIgnoreCase) ||
                                                       state.Equals("Unknown", StringComparison.OrdinalIgnoreCase);

        private static void RefreshInstallSensitiveState(BlackbirdPreflightReport report, string? hookDllPath)
        {
            string fallbackControllerPath =
                BlackbirdPackageResolver.ResolvePackageArtifact("BlackbirdController.exe") ??
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Blackbird",
                             "BlackbirdController.exe");
            report.DriverState = BlackbirdServiceControl.QueryDriverState("blackbird");
            report.ControllerState = BlackbirdServiceControl.QueryState("BlackbirdController");
            report.HookDllPath = ResolveHookDllPath(hookDllPath);
            report.HookDllExists = File.Exists(report.HookDllPath);
            report.ControllerBinaryPath = ResolveServiceBinaryPath("BlackbirdController", fallbackControllerPath);
            report.ControllerBinaryOk =
                ValidateControllerServiceBinary(report.ControllerBinaryPath, out string controllerBinaryMessage);
            report.ControllerBinaryMessage = controllerBinaryMessage;
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

        internal static bool ProbeHookIngestPipe(TimeSpan timeout, out string message)
        {
            const string pipeName = @"\\.\pipe\BlackbirdHookIngest";
            DateTime deadline = DateTime.UtcNow + timeout;
            int lastError = 0;

            do
            {
                if (WaitNamedPipeW(pipeName, 250))
                {
                    message = $"{pipeName} available";
                    return true;
                }

                lastError = Marshal.GetLastWin32Error();
                Thread.Sleep(50);
            } while (DateTime.UtcNow < deadline);

            message = $"{pipeName} unavailable win32={lastError}";
            return false;
        }

        private static string ResolveServiceBinaryPath(string serviceName, string fallback)
        {
            try
            {
                using RegistryKey? key =
                    Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{serviceName}");
                if (key?.GetValue("ImagePath") is string imagePath && !string.IsNullOrWhiteSpace(imagePath))
                {
                    imagePath = ExtractExecutablePath(Environment.ExpandEnvironmentVariables(imagePath.Trim()));
                    string winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
                    imagePath = imagePath.Replace(@"\SystemRoot", winDir, StringComparison.OrdinalIgnoreCase)
                                    .Replace("%SystemRoot%", winDir, StringComparison.OrdinalIgnoreCase);
                    if (imagePath.StartsWith(@"\??\", StringComparison.Ordinal))
                    {
                        imagePath = imagePath[4..];
                    }
                    if (!string.IsNullOrWhiteSpace(imagePath))
                    {
                        return imagePath;
                    }
                }
            }
            catch
            {
            }

            return fallback;
        }

        private static string ExtractExecutablePath(string imagePath)
        {
            if (string.IsNullOrWhiteSpace(imagePath))
            {
                return string.Empty;
            }

            if (imagePath.StartsWith('"'))
            {
                int end = imagePath.IndexOf('"', 1);
                return end > 1 ? imagePath[1..end] : imagePath.Trim('"');
            }

            int exeIndex = imagePath.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
            if (exeIndex >= 0)
            {
                return imagePath[..(exeIndex + 4)];
            }

            int firstSpace = imagePath.IndexOf(' ');
            return firstSpace > 0 ? imagePath[..firstSpace] : imagePath;
        }

        private static bool ValidateControllerServiceBinary(string path, out string message)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                message = "controller service ImagePath is empty";
                return false;
            }

            if (!File.Exists(path))
            {
                message = $"controller service image missing: {path}";
                return false;
            }

            if (!TryReadPeSubsystem(path, out ushort subsystem, out string peError))
            {
                message = $"controller service image is not a readable PE: {path} ({peError})";
                return false;
            }

            if (subsystem == 1)
            {
                message = $"controller service image is a native/driver image, not a user-mode service EXE: {path}";
                return false;
            }

            if (!path.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            {
                message = $"controller service image has unexpected extension: {path}";
                return false;
            }

            message = $"OK {path} subsystem={subsystem}";
            return true;
        }

        private static bool TryReadPeSubsystem(string path, out ushort subsystem, out string error)
        {
            subsystem = 0;
            error = string.Empty;
            try
            {
                using var fs =
                    new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                using var br = new BinaryReader(fs);
                if (fs.Length < 0x100)
                {
                    error = "file too small";
                    return false;
                }

                if (br.ReadUInt16() != 0x5A4D)
                {
                    error = "missing MZ";
                    return false;
                }

                fs.Seek(0x3C, SeekOrigin.Begin);
                int peOffset = br.ReadInt32();
                if (peOffset <= 0 || peOffset + 0x5A > fs.Length)
                {
                    error = "invalid PE offset";
                    return false;
                }

                fs.Seek(peOffset, SeekOrigin.Begin);
                if (br.ReadUInt32() != 0x00004550)
                {
                    error = "missing PE signature";
                    return false;
                }

                fs.Seek(16, SeekOrigin.Current);
                ushort optionalHeaderSize = br.ReadUInt16();
                fs.Seek(2, SeekOrigin.Current);
                long optionalHeaderStart = fs.Position;
                if (optionalHeaderSize < 70 || optionalHeaderStart + optionalHeaderSize > fs.Length)
                {
                    error = "invalid optional header";
                    return false;
                }

                ushort magic = br.ReadUInt16();
                if (magic != 0x10B && magic != 0x20B)
                {
                    error = $"unsupported optional header magic=0x{magic:X}";
                    return false;
                }

                fs.Seek(optionalHeaderStart + 68, SeekOrigin.Begin);
                subsystem = br.ReadUInt16();
                return true;
            }
            catch (Exception ex)
            {
                error = ex.Message;
                return false;
            }
        }

        [DllImport("kernel32.dll", EntryPoint = "WaitNamedPipeW", CharSet = CharSet.Unicode, SetLastError = true)]
        [return:MarshalAs(UnmanagedType.Bool)]
        private static extern bool WaitNamedPipeW(string lpNamedPipeName, uint nTimeOut);
    }
}
