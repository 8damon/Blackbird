using System;
using System.Diagnostics;
using System.Text;
using System.Threading;

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

        private static ScResult RunSc(string args)
        {
            using var proc = new Process();
            proc.StartInfo = new ProcessStartInfo
            {
                FileName = "sc.exe",
                Arguments = args,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8
            };

            proc.Start();
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

                throw new TimeoutException($"sc.exe timed out: {args}");
            }

            return new ScResult(proc.ExitCode, (stdOut + Environment.NewLine + stdErr).Trim());
        }

        private static void ValidateServiceName(string serviceName)
        {
            if (string.IsNullOrWhiteSpace(serviceName))
            {
                throw new ArgumentException("Service name is required.", nameof(serviceName));
            }

            foreach (char ch in serviceName)
            {
                bool isOk =
                    (ch >= 'a' && ch <= 'z') ||
                    (ch >= 'A' && ch <= 'Z') ||
                    (ch >= '0' && ch <= '9') ||
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
