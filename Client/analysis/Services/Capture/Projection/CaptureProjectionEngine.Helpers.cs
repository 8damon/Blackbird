using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace BlackbirdInterface.Capture
{
    internal sealed partial class CaptureProjectionEngine
    {
        private static uint ResolveActorPid(BrokerEtwEventView view) => FirstNonZero(view.ActorPid, view.CallerPid,
                                                                                     view.EventProcessId,
                                                                                     view.ProcessPid);

        private static uint ResolveTargetPid(BrokerEtwEventView view) => FirstNonZero(view.TargetPid,
                                                                                      view.ExplicitTargetPid,
                                                                                      view.ProcessPid,
                                                                                      view.EventProcessId);

        private static uint ResolveMemoryTargetPid(BrokerEtwEventView view) =>
            FirstNonZero(view.TargetPid, view.ExplicitTargetPid, view.ProcessPid, view.EventProcessId, view.ActorPid);

        private static uint FirstNonZero(params uint[] values)
        {
            foreach (uint value in values)
            {
                if (value != 0)
                {
                    return value;
                }
            }

            return 0;
        }

        private static string PidLabel(uint pid) => pid == 0 ? "-" : $"{ProcessIdentityResolver.Describe(pid)} ({pid})";

        private static string
        DescribeEtwFamily(uint family) => family switch { BlackbirdNative.IpcEtwFamilyHandle => "Handle",
                                                          BlackbirdNative.IpcEtwFamilyThread => "Thread",
                                                          BlackbirdNative.IpcEtwFamilyProcess => "Process",
                                                          BlackbirdNative.IpcEtwFamilyImage => "Image",
                                                          BlackbirdNative.IpcEtwFamilyRegistry => "Registry",
                                                          BlackbirdNative.IpcEtwFamilyApc => "APC",
                                                          BlackbirdNative.IpcEtwFamilyDetection => "Detection",
                                                          BlackbirdNative.IpcEtwFamilyThreatIntel => "ThreatIntel",
                                                          BlackbirdNative.IpcEtwFamilySocket => "Socket",
                                                          BlackbirdNative.IpcEtwFamilyUserHook => "API",
                                                          _ => "ETW" };

        private static string DescribeFileOperation(uint operation) => operation switch {
            BlackbirdNative.FileOperationCreate => "Create",
            BlackbirdNative.FileOperationRead => "Read",
            BlackbirdNative.FileOperationWrite => "Write",
            BlackbirdNative.FileOperationClose => "Close",
            BlackbirdNative.FileOperationCleanup => "Cleanup",
            BlackbirdNative.FileOperationSetInformation => "SetInformation",
            BlackbirdNative.FileOperationQueryInformation => "QueryInformation",
            BlackbirdNative.FileOperationDirectoryControl => "DirectoryControl",
            BlackbirdNative.FileOperationFsControl => "FsControl",
            _ => "Unknown"
        };

        private static string DescribeRegistryOperation(uint operation) => operation switch {
            BlackbirdNative.RegistryOperationQueryValue => "QueryValue",
            BlackbirdNative.RegistryOperationQueryKey => "QueryKey",
            BlackbirdNative.RegistryOperationEnumerateKey => "EnumerateKey",
            BlackbirdNative.RegistryOperationEnumerateValue => "EnumerateValue",
            BlackbirdNative.RegistryOperationSetValue => "SetValue",
            BlackbirdNative.RegistryOperationCreateKey => "CreateKey",
            BlackbirdNative.RegistryOperationOpenKey => "OpenKey",
            BlackbirdNative.RegistryOperationDeleteValue => "DeleteValue",
            BlackbirdNative.RegistryOperationDeleteKey => "DeleteKey",
            _ => "Unknown"
        };

        private static string BuildRegistryPath(string keyPath,
                                                string valueName) => string.IsNullOrWhiteSpace(valueName)
                                                                         ? FirstNonEmpty(keyPath, "(registry)")
                                                                         : $"{keyPath}\\{valueName}";

        private static string SeverityLabel(uint severity)
        {
            if (severity >= 5)
            {
                return "Critical";
            }
            if (severity >= 4)
            {
                return "High";
            }
            if (severity >= 2)
            {
                return "Medium";
            }

            return "Info";
        }

        private static int SeverityRank(string severity) =>
            (severity ?? string.Empty).Trim().ToLowerInvariant() switch { "critical" => 5, "high" => 4, "medium" => 3,
                                                                          "low" => 2,      "info" => 1,
                                                                          _ => 0 };

        private static string BuildStackSummary(ulong[]? stack, uint stackCount)
        {
            int count = Math.Min(stack?.Length ?? 0, (int)Math.Min(stackCount, 8));
            if (count <= 0)
            {
                return string.Empty;
            }

            return string.Join(" <- ", stack!.Take(count).Select(x => $"0x{x:X}"));
        }

        private static ulong NormalizeRegionAddress(ulong address) => address & ~0xFFFUL;

        private static ulong FirstU64(IReadOnlyDictionary<string, string> fields, params string[] keys)
        {
            foreach (string key in keys)
            {
                if (!fields.TryGetValue(key, out string? value) || string.IsNullOrWhiteSpace(value))
                {
                    continue;
                }

                string trimmed = value.Trim();
                if (trimmed.StartsWith("0x", StringComparison.OrdinalIgnoreCase) &&
                    ulong.TryParse(trimmed.AsSpan(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture,
                                   out ulong parsedHex))
                {
                    return parsedHex;
                }

                if (ulong.TryParse(trimmed, NumberStyles.Integer, CultureInfo.InvariantCulture, out ulong parsed))
                {
                    return parsed;
                }
            }

            return 0;
        }

        private static string FirstNonEmpty(params string?[] values)
        {
            foreach (string? value in values)
            {
                if (!string.IsNullOrWhiteSpace(value))
                {
                    return value.Trim();
                }
            }

            return string.Empty;
        }

        private static string Truncate(string? value, int maxChars)
        {
            if (string.IsNullOrEmpty(value) || value.Length <= maxChars)
            {
                return value ?? string.Empty;
            }

            return value[..maxChars];
        }

        private static void TrimHead<T>(List<T> rows, int maxRows)
        {
            if (rows.Count > maxRows)
            {
                rows.RemoveRange(0, rows.Count - maxRows);
            }
        }

        private static FileInfo? TryGetFileInfo(string path)
        {
            try
            {
                return File.Exists(path) ? new FileInfo(path) : null;
            }
            catch
            {
                return null;
            }
        }

        private static string SafeModulePath(ProcessModule module)
        {
            try
            {
                return module.FileName ?? module.ModuleName ?? string.Empty;
            }
            catch
            {
                return module.ModuleName ?? string.Empty;
            }
        }

        private static string SafeWaitReason(ProcessThread thread)
        {
            try
            {
                return thread.ThreadState == System.Diagnostics.ThreadState.Wait ? thread.WaitReason.ToString()
                                                                                 : string.Empty;
            }
            catch
            {
                return string.Empty;
            }
        }

        private static DateTime? SafeThreadStart(ProcessThread thread)
        {
            try
            {
                return thread.StartTime.ToUniversalTime();
            }
            catch
            {
                return null;
            }
        }

        private static string FormatNullableUtc(DateTime? value) =>
            value.HasValue ? value.Value.ToString("O", CultureInfo.InvariantCulture) : string.Empty;
    }
}
