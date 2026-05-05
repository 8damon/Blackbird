using System;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace BlackbirdInterface
{
    internal static class VmRegistrationPackageService
    {
        private static readonly Regex FingerprintPattern = new("^[0-9a-fA-F]{64}$", RegexOptions.Compiled);

        public sealed class RegistrationPackageResult
        {
            public string EnrollmentId { get; init; } = string.Empty;
            public string PackageRoot { get; init; } = string.Empty;
            public string InstallCommand { get; init; } = string.Empty;
        }

        public static RegistrationPackageResult CreatePackage(string blackbirdRoot, string outputRoot,
                                                              string machineName, string operatorFingerprint)
        {
            if (string.IsNullOrWhiteSpace(blackbirdRoot) || !Directory.Exists(blackbirdRoot))
            {
                throw new DirectoryNotFoundException("Blackbird source root was not found.");
            }
            if (string.IsNullOrWhiteSpace(outputRoot))
            {
                throw new InvalidOperationException("Output folder is required.");
            }
            string normalizedFingerprint = operatorFingerprint ?? string.Empty;
            if (!FingerprintPattern.IsMatch(normalizedFingerprint))
            {
                throw new InvalidOperationException("Operator fingerprint must be 64 hex characters.");
            }
            normalizedFingerprint = normalizedFingerprint.ToLowerInvariant();

            string safeMachine = MakeSafeName(machineName);
            string enrollmentId = $"{safeMachine}-{Guid.NewGuid():N}";
            string packageRoot = Path.Combine(outputRoot, enrollmentId);
            string payloadRoot = Path.Combine(packageRoot, "Blackbird");
            Directory.CreateDirectory(payloadRoot);

            CopyTree(blackbirdRoot, payloadRoot);

            var enrollment = new { protocol = 1,
                                   enrollmentId,
                                   machineName = safeMachine,
                                   createdUtc = DateTime.UtcNow.ToString("o"),
                                   operatorFingerprint = normalizedFingerprint,
                                   operatorFingerprints = new[] { normalizedFingerprint } };

            string enrollmentJson =
                JsonSerializer.Serialize(enrollment, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(Path.Combine(packageRoot, "enroll.json"), enrollmentJson, Encoding.UTF8);
            File.WriteAllText(Path.Combine(payloadRoot, "enroll.json"), enrollmentJson, Encoding.UTF8);

            string installCommand = @"powershell.exe -ExecutionPolicy Bypass -File .\Register-BlackbirdVm.ps1";
            File.WriteAllText(
                Path.Combine(packageRoot, "REGISTER_VM.txt"),
                "Blackbird VM enrollment package\r\n" + "================================\r\n\r\n" +
                    "This package does not register a live VM from the server UI.\r\n" +
                    "It carries install-time trust material for the VM.\r\n\r\n" + "Operator fingerprint:\r\n" +
                    normalizedFingerprint + "\r\n\r\n" + "What that means:\r\n" +
                    "The operator fingerprint is the 64-character hex fingerprint of the analyst/operator identity public key.\r\n" +
                    "During the secure command-channel handshake, NetSvc compares the connecting operator fingerprint against the value staged by this package.\r\n" +
                    "If it does not match, the VM rejects the channel.\r\n\r\n" + "Inside the VM:\r\n" +
                    "1. Open an elevated PowerShell prompt.\r\n" +
                    "2. Change directory to the copied Blackbird folder.\r\n" + "3. Run:\r\n\r\n" + installCommand +
                    "\r\n\r\n" +
                    "After the installer finishes, use discovery or manual connect from the analyst/server UI.\r\n",
                Encoding.UTF8);

            return new RegistrationPackageResult { EnrollmentId = enrollmentId, PackageRoot = packageRoot,
                                                   InstallCommand = installCommand };
        }

        public static void CopyPackageToRemote(string packageRoot, string remotePath)
        {
            if (string.IsNullOrWhiteSpace(packageRoot) || !Directory.Exists(packageRoot))
            {
                throw new DirectoryNotFoundException("Registration package folder was not found.");
            }
            if (string.IsNullOrWhiteSpace(remotePath))
            {
                throw new InvalidOperationException("Remote copy path is required.");
            }

            CopyTree(packageRoot, remotePath);
        }

        private static void CopyTree(string sourceRoot, string destinationRoot)
        {
            string fullDestination =
                Path.GetFullPath(destinationRoot).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            string[] directories = Directory.GetDirectories(sourceRoot, "*", SearchOption.AllDirectories);
            string[] files = Directory.GetFiles(sourceRoot, "*", SearchOption.AllDirectories);

            Directory.CreateDirectory(destinationRoot);
            foreach (string directory in directories)
            {
                if (IsInside(directory, fullDestination))
                {
                    continue;
                }

                string relative = Path.GetRelativePath(sourceRoot, directory);
                if (ShouldSkip(relative))
                {
                    continue;
                }

                Directory.CreateDirectory(Path.Combine(destinationRoot, relative));
            }

            foreach (string file in files)
            {
                if (IsInside(file, fullDestination))
                {
                    continue;
                }

                string relative = Path.GetRelativePath(sourceRoot, file);
                if (ShouldSkip(relative))
                {
                    continue;
                }

                string destination = Path.Combine(destinationRoot, relative);
                Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
                File.Copy(file, destination, overwrite: true);
            }
        }

        private static bool IsInside(string path, string root)
        {
            string fullPath = Path.GetFullPath(path);
            return string.Equals(fullPath, root, StringComparison.OrdinalIgnoreCase) ||
                   fullPath.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
        }

        private static bool ShouldSkip(string relativePath)
        {
            string normalized = relativePath.Replace('\\', '/');
            return normalized.StartsWith(".git/", StringComparison.OrdinalIgnoreCase) ||
                   normalized.StartsWith(".build/", StringComparison.OrdinalIgnoreCase) ||
                   normalized.StartsWith(".tmp/", StringComparison.OrdinalIgnoreCase) ||
                   normalized.StartsWith(".vs/", StringComparison.OrdinalIgnoreCase) ||
                   normalized.StartsWith(".dotnet/", StringComparison.OrdinalIgnoreCase) ||
                   normalized.StartsWith(".cargo-home/", StringComparison.OrdinalIgnoreCase) ||
                   normalized.StartsWith(".dotnet_home/", StringComparison.OrdinalIgnoreCase) ||
                   normalized.StartsWith(".dotnet-home/", StringComparison.OrdinalIgnoreCase) ||
                   normalized.StartsWith("Server/target/", StringComparison.OrdinalIgnoreCase) ||
                   normalized.StartsWith("Server/target-codex/", StringComparison.OrdinalIgnoreCase) ||
                   normalized.StartsWith("Server/target-preview/", StringComparison.OrdinalIgnoreCase) ||
                   normalized.StartsWith("Server/data/", StringComparison.OrdinalIgnoreCase) ||
                   normalized.StartsWith("Server/data-dev/", StringComparison.OrdinalIgnoreCase) ||
                   normalized.StartsWith("Server/data-test/", StringComparison.OrdinalIgnoreCase) ||
                   normalized.StartsWith("Scripts/enrollments/", StringComparison.OrdinalIgnoreCase) ||
                   normalized.Contains("/target/", StringComparison.OrdinalIgnoreCase) ||
                   normalized.Contains("/.cargo-home/", StringComparison.OrdinalIgnoreCase) ||
                   normalized.Contains("/obj/", StringComparison.OrdinalIgnoreCase) ||
                   normalized.Contains("/bin/", StringComparison.OrdinalIgnoreCase) ||
                   normalized.Contains("/.vs/", StringComparison.OrdinalIgnoreCase) ||
                   normalized.EndsWith(".pfx", StringComparison.OrdinalIgnoreCase) ||
                   normalized.EndsWith(".key", StringComparison.OrdinalIgnoreCase) ||
                   normalized.EndsWith(".bkcap", StringComparison.OrdinalIgnoreCase);
        }

        private static string MakeSafeName(string machineName)
        {
            string value = string.IsNullOrWhiteSpace(machineName) ? $"Blackbird-vm-{DateTime.UtcNow:yyyyMMdd-HHmmss}"
                                                                  : machineName.Trim();

            var builder = new StringBuilder(value.Length);
            foreach (char ch in value)
            {
                builder.Append(char.IsLetterOrDigit(ch) || ch is '-' or '_' ? ch : '-');
            }

            string safe = builder.ToString().Trim('-');
            return string.IsNullOrWhiteSpace(safe) ? $"Blackbird-vm-{DateTime.UtcNow:yyyyMMdd-HHmmss}" : safe;
        }
    }
}
