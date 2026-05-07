using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using Microsoft.Win32;

namespace BlackbirdInterface
{
    internal sealed class ComponentEntry
    {
        public string Name { get; init; } = string.Empty;
        public string Description { get; init; } = string.Empty;
        public string Path { get; init; } = string.Empty;
        public string Version { get; init; } = string.Empty;
        public string HashHex { get; init; } = string.Empty;
        public bool Found { get; init; }
    }

    internal static class ComponentIdentityService
    {
        private static IReadOnlyList<ComponentEntry>? _cached;

        public static IReadOnlyList<ComponentEntry> GetEntries() => _cached ??= Build();

        public static IReadOnlyList<ComponentEntry> Refresh()
        {
            _cached = Build();
            return _cached;
        }

        private static IReadOnlyList<ComponentEntry> Build()
        {
            string baseDir = AppContext.BaseDirectory;
            if (string.IsNullOrWhiteSpace(baseDir))
                baseDir = System.IO.Path.GetDirectoryName(Environment.ProcessPath ?? string.Empty) ?? string.Empty;

            string sys32Drivers =
                System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "drivers");
            string pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);

            return new List<ComponentEntry> {
                BuildEntry("Interface", "Analyst interface.", Environment.ProcessPath ?? string.Empty),
                BuildEntry("SR71",
                           "User-mode sensor injected into targets for NT, Winsock, module, and runtime telemetry.",
                           System.IO.Path.Combine(baseDir, "SR71.dll")),
                BuildEntry("J58", "User-mode ABI and control bridge used by the interface, controller, and tooling.",
                           System.IO.Path.Combine(baseDir, "J58.dll")),
                BuildEntry(
                    "DllHost",
                    "DLL invocation and instrumentation host used when analyzing DLLs instead of launching EXEs directly.",
                    ResolveDllHostPath(baseDir, pf)),
                BuildEntry("BKDC", "Disassembly helper used by the analyst interface.", ResolveBkdcPath(baseDir, pf)),
                BuildEntry("Driver", "Kernel driver and policy enforcement layer.",
                           ResolveServiceBinaryPath("BK", System.IO.Path.Combine(sys32Drivers, "Blackbird.sys"))),
                BuildEntry(
                    "Controller",
                    "Service broker and communication relay between interface, SR71, ETW, and the driver.",
                    ResolveServiceBinaryPath("BlackbirdController",
                                             System.IO.Path.Combine(pf, "Blackbird", "BlackbirdController.exe")))
            };
        }

        private static ComponentEntry BuildEntry(string name, string description, string path)
        {
            if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
            {
                return new ComponentEntry { Name = name,
                                            Description = description,
                                            Path = string.IsNullOrWhiteSpace(path) ? string.Empty : path,
                                            Version = "—",
                                            HashHex = string.Empty,
                                            Found = false };
            }

            return new ComponentEntry { Name = name,
                                        Description = description,
                                        Path = path,
                                        Version = GetFileVersion(path),
                                        HashHex = ComputeSha256Hex(path),
                                        Found = true };
        }

        private static string GetFileVersion(string path)
        {
            try
            {
                FileVersionInfo fvi = FileVersionInfo.GetVersionInfo(path);
                string v = fvi.ProductVersion ?? fvi.FileVersion ?? string.Empty;
                return string.IsNullOrWhiteSpace(v) ? "0.0.0.0" : v.Trim();
            }
            catch
            {
                return "unknown";
            }
        }

        private static string ComputeSha256Hex(string path)
        {
            try
            {
                using SHA256 sha = SHA256.Create();
                using var fs =
                    new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                byte[] hash = sha.ComputeHash(fs);
                return Convert.ToHexString(hash).ToLowerInvariant();
            }
            catch
            {
                return string.Empty;
            }
        }

        private static string ResolveBkdcPath(string baseDir, string pf)
        {
            string[] candidates = { System.IO.Path.Combine(baseDir, "BKDC.dll"),
                                    System.IO.Path.Combine(Environment.CurrentDirectory, "BKDC.dll"),
                                    System.IO.Path.Combine(pf, "Blackbird", "BKDC.dll") };
            foreach (string c in candidates)
                if (File.Exists(c))
                    return c;
            return System.IO.Path.Combine(baseDir, "BKDC.dll");
        }

        private static string ResolveServiceBinaryPath(string serviceName, string fallback)
        {
            try
            {
                using RegistryKey? key =
                    Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{serviceName}");
                if (key?.GetValue("ImagePath") is string imagePath && !string.IsNullOrWhiteSpace(imagePath))
                {
                    imagePath = imagePath.Trim();

                    if (imagePath.StartsWith('"'))
                    {
                        int end = imagePath.IndexOf('"', 1);
                        if (end > 1)
                            imagePath = imagePath[1..end];
                    }

                    string winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
                    imagePath = imagePath.Replace(@"\SystemRoot", winDir, StringComparison.OrdinalIgnoreCase)
                                    .Replace("%SystemRoot%", winDir, StringComparison.OrdinalIgnoreCase);
                    imagePath = Environment.ExpandEnvironmentVariables(imagePath);

                    if (imagePath.StartsWith(@"\??\", StringComparison.Ordinal))
                        imagePath = imagePath[4..];

                    if (File.Exists(imagePath))
                        return imagePath;
                }
            }
            catch
            {
            }

            return fallback;
        }

        private static string ResolveDllHostPath(string baseDir, string pf)
        {
            string[] candidates = { System.IO.Path.Combine(baseDir, "BlackbirdDllHost.exe"),
                                    System.IO.Path.Combine(Environment.CurrentDirectory, "BlackbirdDllHost.exe"),
                                    System.IO.Path.Combine(pf, "Blackbird", "BlackbirdDllHost.exe") };
            foreach (string c in candidates)
                if (File.Exists(c))
                    return c;
            return System.IO.Path.Combine(baseDir, "BlackbirdDllHost.exe");
        }
    }
}
