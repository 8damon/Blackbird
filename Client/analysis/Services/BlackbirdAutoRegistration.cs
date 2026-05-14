using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;

namespace BlackbirdInterface
{
    internal static class BlackbirdAutoRegistration
    {
        private static int _attempted;

        internal static bool TryRunOnce(Action<double, string, string?>? progress, out string message)
        {
            if (System.Threading.Interlocked.Exchange(ref _attempted, 1) != 0)
            {
                message = "automatic registration already attempted in this interface process";
                return false;
            }

            return TryRun(progress, out message);
        }

        private static bool TryRun(Action<double, string, string?>? progress, out string message)
        {
            if (!IsAdministrator())
            {
                message = "automatic registration requires an elevated administrator token";
                return false;
            }

            string? installer = BlackbirdPackageResolver.ResolveScript("installer.ps1");
            if (string.IsNullOrWhiteSpace(installer))
            {
                message = "Scripts\\installer.ps1 was not found from the interface package root";
                return false;
            }

            var args = new List<string> { "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", installer };
            AddArtifact(args, "-DriverSys", "blackbird.sys");
            AddArtifact(args, "-ControllerExe", "BlackbirdController.exe");
            AddArtifact(args, "-SensorCoreDll", "J58.dll");
            AddArtifact(args, "-HookDll", "SR71.dll");
            AddArtifact(args, "-RunnerExe", "BlackbirdRunner.exe");

            progress?.Invoke(30, "Registering Blackbird services...",
                             "Running the bundled installer because services or installed binaries are missing.");
            DiagnosticsState.SetValue("Auto Registration", $"Running {installer}");

            return RunPowerShell(args, BlackbirdPackageResolver.ResolvePackageRoot(), out message);
        }

        private static void AddArtifact(List<string> args, string parameter, string fileName)
        {
            string? path = BlackbirdPackageResolver.ResolvePackageArtifact(fileName);
            if (string.IsNullOrWhiteSpace(path))
            {
                return;
            }

            AddValue(args, parameter, path);
        }

        private static void AddValue(List<string> args, string parameter, string value)
        {
            args.Add(parameter);
            args.Add(value);
        }

        private static bool RunPowerShell(IReadOnlyList<string> arguments, string? workingDirectory, out string message)
        {
            using var process = new Process();
            process.StartInfo =
                new ProcessStartInfo { FileName = "powershell.exe",
                                       UseShellExecute = false,
                                       CreateNoWindow = true,
                                       RedirectStandardOutput = true,
                                       RedirectStandardError = true,
                                       StandardOutputEncoding = Encoding.UTF8,
                                       StandardErrorEncoding = Encoding.UTF8,
                                       WorkingDirectory = string.IsNullOrWhiteSpace(workingDirectory)
                                                              ? BlackbirdPackageResolver.ResolveBaseDirectory()
                                                              : workingDirectory };

            foreach (string argument in arguments)
            {
                process.StartInfo.ArgumentList.Add(argument);
            }

            try
            {
                process.Start();
                Task<string> stdout = process.StandardOutput.ReadToEndAsync();
                Task<string> stderr = process.StandardError.ReadToEndAsync();
                if (!process.WaitForExit((int)TimeSpan.FromMinutes(5).TotalMilliseconds))
                {
                    TryKill(process);
                    message = "automatic registration timed out after 5 minutes";
                    return false;
                }

                string output = stdout.GetAwaiter().GetResult();
                string error = stderr.GetAwaiter().GetResult();
                string combined = (output + Environment.NewLine + error).Trim();
                if (process.ExitCode == 0)
                {
                    message = string.IsNullOrWhiteSpace(combined)
                                  ? "automatic registration completed"
                                  : $"automatic registration completed: {TrimForUi(combined)}";
                    return true;
                }

                message = $"automatic registration failed exit={process.ExitCode}: {TrimForUi(combined)}";
                return false;
            }
            catch (Exception ex)
            {
                message = $"automatic registration failed: {ex.Message}";
                return false;
            }
        }

        private static string TrimForUi(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return string.Empty;
            }

            value = value.Replace("\r", string.Empty).Trim();
            return value.Length <= 1600 ? value : value[^1600..];
        }

        private static void TryKill(Process process)
        {
            try
            {
                process.Kill(entireProcessTree: true);
            }
            catch
            {
            }
        }

        private static bool IsAdministrator()
        {
            try
            {
                using WindowsIdentity identity = WindowsIdentity.GetCurrent();
                return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch
            {
                return false;
            }
        }
    }
}
