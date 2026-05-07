using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading;
using Microsoft.Win32.SafeHandles;

namespace BlackbirdInterface
{
    internal static class BlackbirdServiceControl
    {
        public static string Start(string serviceName, TimeSpan timeout)
        {
            ValidateServiceName(serviceName);
            _ = RunSc($"start {serviceName}");
            return WaitForState(serviceName, "RUNNING", timeout);
        }

        public static string Stop(string serviceName, TimeSpan timeout)
        {
            ValidateServiceName(serviceName);
            _ = RunSc($"stop {serviceName}");
            return WaitForState(serviceName, "STOPPED", timeout);
        }

        public static string Restart(string serviceName, TimeSpan timeout)
        {
            ValidateServiceName(serviceName);
            _ = RunSc($"stop {serviceName}");
            _ = WaitForState(serviceName, "STOPPED", TimeSpan.FromSeconds(Math.Min(8, timeout.TotalSeconds)));
            _ = RunSc($"start {serviceName}");
            return WaitForState(serviceName, "RUNNING", timeout);
        }

        public static bool TryStart(string serviceName, TimeSpan timeout, out string message)
        {
            try
            {
                string state = Start(serviceName, timeout);
                message = $"{serviceName} -> {state}";
                return true;
            }
            catch (Exception ex)
            {
                message = $"{serviceName} start failed: {ex.Message}";
                return false;
            }
        }

        public static bool TryStop(string serviceName, TimeSpan timeout, out string message)
        {
            try
            {
                string state = Stop(serviceName, timeout);
                message = $"{serviceName} -> {state}";
                return true;
            }
            catch (Exception ex)
            {
                message = $"{serviceName} stop failed: {ex.Message}";
                return false;
            }
        }

        public static bool TryRestart(string serviceName, TimeSpan timeout, out string message)
        {
            try
            {
                string state = Restart(serviceName, timeout);
                message = $"{serviceName} -> {state}";
                return true;
            }
            catch (Exception ex)
            {
                message = $"{serviceName} restart failed: {ex.Message}";
                return false;
            }
        }

        public static string QueryState(string serviceName)
        {
            ValidateServiceName(serviceName);
            if (TryQueryStateNative(serviceName, out string state))
            {
                return state;
            }

            var result = RunSc($"query {serviceName}");
            if (result.ExitCode != 0)
            {
                return "NotInstalled";
            }

            if (result.Output.IndexOf("RUNNING", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return "Running";
            }
            if (result.Output.IndexOf("STOPPED", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return "Stopped";
            }

            return "Unknown";
        }

        public static string QueryDriverState(string serviceName)
        {
            string serviceState = QueryState(serviceName);
            if (serviceState.Equals("Running", StringComparison.OrdinalIgnoreCase))
            {
                return serviceState;
            }

            if (TryQueryMinifilterLoaded(serviceName, out bool loaded) && loaded)
            {
                return "Running";
            }

            return serviceState;
        }

        private static bool TryQueryStateNative(string serviceName, out string state)
        {
            state = "Unknown";
            IntPtr scm = OpenSCManager(null, null, ScManagerConnect);
            if (scm == IntPtr.Zero)
            {
                return false;
            }

            try
            {
                IntPtr service = OpenService(scm, serviceName, ServiceQueryStatus);
                if (service == IntPtr.Zero)
                {
                    state = Marshal.GetLastWin32Error() == ErrorServiceDoesNotExist ? "NotInstalled" : "Unknown";
                    return true;
                }

                try
                {
                    int bytesNeeded;
                    var status = new ServiceStatusProcess();
                    if (!QueryServiceStatusEx(service, ScStatusProcessInfo, ref status,
                                              Marshal.SizeOf<ServiceStatusProcess>(), out bytesNeeded))
                    {
                        state = "Unknown";
                        return true;
                    }

                    state = status.CurrentState switch { ServiceRunning => "Running",
                                                         ServiceStopped => "Stopped",
                                                         ServiceStartPending => "StartPending",
                                                         ServiceStopPending => "StopPending",
                                                         ServicePausePending => "PausePending",
                                                         ServicePaused => "Paused",
                                                         ServiceContinuePending => "ContinuePending",
                                                         _ => "Unknown" };
                    return true;
                }
                finally
                {
                    _ = CloseServiceHandle(service);
                }
            }
            finally
            {
                _ = CloseServiceHandle(scm);
            }
        }

        private static string WaitForState(string serviceName, string desiredState, TimeSpan timeout)
        {
            DateTime deadline = DateTime.UtcNow + timeout;
            string last = "Unknown";

            while (DateTime.UtcNow < deadline)
            {
                last = QueryState(serviceName);
                if (last.Equals(desiredState, StringComparison.OrdinalIgnoreCase))
                {
                    return last;
                }
                Thread.Sleep(250);
            }

            throw new TimeoutException($"Timed out waiting for {serviceName} -> {desiredState}. last={last}");
        }

        private static bool TryQueryMinifilterLoaded(string filterName, out bool loaded)
        {
            loaded = false;
            ValidateServiceName(filterName);

            try
            {
                ScResult result = RunSystemTool("fltmc.exe", "filters");
                if (result.ExitCode != 0)
                {
                    return false;
                }

                foreach (string rawLine in result.Output.Split(new[] { '\r', '\n' },
                                                               StringSplitOptions.RemoveEmptyEntries))
                {
                    string line = rawLine.Trim();
                    if (line.Length < filterName.Length)
                    {
                        continue;
                    }

                    if (!line.StartsWith(filterName, StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    if (line.Length == filterName.Length || char.IsWhiteSpace(line[filterName.Length]))
                    {
                        loaded = true;
                        return true;
                    }
                }

                return true;
            }
            catch
            {
                return false;
            }
        }

        private static ScResult RunSc(string args) => RunSystemTool("sc.exe", args);

        private static ScResult RunSystemTool(string fileName, string args)
        {
            using var proc = new Process();
            proc.StartInfo =
                new ProcessStartInfo { FileName = fileName, Arguments = args, UseShellExecute = false,
                                       CreateNoWindow = true, RedirectStandardOutput = true,
                                       RedirectStandardError = true, StandardOutputEncoding = Encoding.UTF8,
                                       StandardErrorEncoding = Encoding.UTF8,
                                       WorkingDirectory = Environment.SystemDirectory };

            /* Revert any thread-level impersonation before calling CreateProcess.
               If the calling thread is impersonating the monitored process with
               SecurityIdentification level, CreateProcess fails with 1346
               (ERROR_BAD_IMPERSONATION_LEVEL). Passing a null/zero token handle
               to RunImpersonated reverts the thread to the process identity. */
            WindowsIdentity.RunImpersonated(new SafeAccessTokenHandle(IntPtr.Zero), () => proc.Start());
            string stdOut = proc.StandardOutput.ReadToEnd();
            string stdErr = proc.StandardError.ReadToEnd();
            if (!proc.WaitForExit(10000))
            {
                try
                {
                    proc.Kill(entireProcessTree: true);
                }
                catch
                {
                }

                throw new TimeoutException($"{fileName} timed out: {args}");
            }

            return new ScResult(proc.ExitCode, (stdOut + Environment.NewLine + stdErr).Trim());
        }

        private const uint ScManagerConnect = 0x0001;
        private const uint ServiceQueryStatus = 0x0004;
        private const int ScStatusProcessInfo = 0;
        private const int ErrorServiceDoesNotExist = 1060;
        private const uint ServiceStopped = 0x00000001;
        private const uint ServiceStartPending = 0x00000002;
        private const uint ServiceStopPending = 0x00000003;
        private const uint ServiceRunning = 0x00000004;
        private const uint ServiceContinuePending = 0x00000005;
        private const uint ServicePausePending = 0x00000006;
        private const uint ServicePaused = 0x00000007;

        [StructLayout(LayoutKind.Sequential)]
        private struct ServiceStatusProcess
        {
            public uint ServiceType;
            public uint CurrentState;
            public uint ControlsAccepted;
            public uint Win32ExitCode;
            public uint ServiceSpecificExitCode;
            public uint CheckPoint;
            public uint WaitHint;
            public uint ProcessId;
            public uint ServiceFlags;
        }

        [DllImport("advapi32.dll", EntryPoint = "OpenSCManagerW", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr OpenSCManager(string? machineName, string? databaseName, uint desiredAccess);

        [DllImport("advapi32.dll", EntryPoint = "OpenServiceW", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr OpenService(IntPtr serviceControlManager, string serviceName, uint desiredAccess);

        [DllImport("advapi32.dll", EntryPoint = "QueryServiceStatusEx", SetLastError = true)]
        [return:MarshalAs(UnmanagedType.Bool)]
        private static extern bool QueryServiceStatusEx(IntPtr service, int infoLevel, ref ServiceStatusProcess buffer,
                                                        int bufferSize, out int bytesNeeded);

        [DllImport("advapi32.dll", EntryPoint = "CloseServiceHandle", SetLastError = true)]
        [return:MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseServiceHandle(IntPtr handle);

        private static void ValidateServiceName(string serviceName)
        {
            if (string.IsNullOrWhiteSpace(serviceName))
            {
                throw new ArgumentException("Service name is required.", nameof(serviceName));
            }

            foreach (char ch in serviceName)
            {
                bool isOk = (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') ||
                            ch == '_' || ch == '-' || ch == '.';

                if (!isOk)
                {
                    throw new ArgumentException($"Invalid service name '{serviceName}'.", nameof(serviceName));
                }
            }
        }

        private readonly struct ScResult
        {
            public ScResult(int exitCode, string output)
            {
                ExitCode = exitCode;
                Output = output;
            }

            public int ExitCode { get; }
            public string Output { get; }
        }
    }
}
