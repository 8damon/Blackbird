using System;
using System.Collections.Generic;
using System.Linq;

namespace BlackbirdInterface
{
    public enum LaunchPriorityPreset
    {
        Inherit = 0,
        Idle,
        BelowNormal,
        Normal,
        AboveNormal,
        High,
        Realtime
    }

    public enum LaunchIntegrityLevel : uint
    {
        Default = 0,
        Untrusted = 1,
        Low = 2,
        Medium = 3,
        High = 4,
        System = 5,
    }

    public enum LaunchTargetKind
    {
        Executable = 0,
        Dll = 1
    }

    public enum DllLaunchMode
    {
        Load = 0,
        Export,
        Rundll,
        Register,
        Unregister,
        Install
    }

    public sealed class LaunchProfile
    {
        public LaunchTargetKind TargetKind { get; set; } = LaunchTargetKind.Executable;
        public string AnalysisSubjectPath { get; set; } = string.Empty;
        public string AnalysisHostPath { get; set; } = string.Empty;
        public string CommandLineArguments { get; set; } = string.Empty;
        public string WorkingDirectory { get; set; } = string.Empty;
        public string EnvironmentOverridesText { get; set; } = string.Empty;
        public DllLaunchMode DllMode { get; set; } = DllLaunchMode.Load;
        public string DllExportName { get; set; } = string.Empty;
        public uint DllExportOrdinal { get; set; }
        public string DllArgument { get; set; } = string.Empty;
        public uint DllLoadFlags { get; set; }
        public uint DllWaitMilliseconds { get; set; } = 60000;
        public bool DllFreeOnExit { get; set; }
        public bool DllInstallDisable { get; set; }
        public bool LeaveSuspendedAfterReady { get; set; }
        public uint ParentProcessId { get; set; }
        public bool InheritHandles { get; set; }
        public bool EnableKernelHooks { get; set; } = true;
        public bool EnableAntiVirtualizationMasking { get; set; }
        public bool EnableQpcTimingCompensation { get; set; } = true;
        public LaunchIntegrityLevel IntegrityLevel { get; set; } = LaunchIntegrityLevel.Default;
        public bool EnableControllerConcealment { get; set; }
        public bool EnableInterfaceProtectedAccess { get; set; }
        public bool EnableControllerProtectedAccess { get; set; }
        public bool ConcealHookPresence { get; set; }
        public LaunchPriorityPreset Priority { get; set; } = LaunchPriorityPreset.Inherit;
        public ulong AffinityMask { get; set; }

        public bool HasEnvironmentOverrides => !string.IsNullOrWhiteSpace(EnvironmentOverridesText);
        public bool HasCommandLineArguments => !string.IsNullOrWhiteSpace(CommandLineArguments);
        public bool HasWorkingDirectory => !string.IsNullOrWhiteSpace(WorkingDirectory);
        public bool HasAnalysisSubject =>
            TargetKind == LaunchTargetKind.Dll && !string.IsNullOrWhiteSpace(AnalysisSubjectPath);
        public bool HasParentProcess => ParentProcessId != 0;
        public bool HasAffinityMask => AffinityMask != 0;
        public bool HasDllArgument => !string.IsNullOrWhiteSpace(DllArgument);
        public bool HasDllExportName => !string.IsNullOrWhiteSpace(DllExportName);
        public bool HasDllExportOrdinal => DllExportOrdinal != 0;
        public bool HasDllLoadFlags => DllLoadFlags != 0;

        public static bool TryParseAffinityMask(string? text, out ulong mask)
        {
            mask = 0;
            string value = (text ?? string.Empty).Trim();
            if (value.Length == 0)
            {
                return true;
            }

            if (value.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            {
                return ulong.TryParse(value.AsSpan(2), System.Globalization.NumberStyles.HexNumber, null, out mask);
            }

            return ulong.TryParse(value, out mask);
        }

        public bool TryParseEnvironmentOverrides(out List<KeyValuePair<string, string>> variables, out string error)
        {
            variables = new List<KeyValuePair<string, string>>();
            error = string.Empty;

            string[] lines = EnvironmentOverridesText.Replace("\r\n", "\n", StringComparison.Ordinal)
                                 .Replace('\r', '\n')
                                 .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

            for (int i = 0; i < lines.Length; i += 1)
            {
                string line = lines[i];
                if (line.Length == 0)
                {
                    continue;
                }

                int separator = line.IndexOf('=');
                if (separator <= 0)
                {
                    error = $"Environment override line {i + 1} must use NAME=VALUE.";
                    variables.Clear();
                    return false;
                }

                string name = line[..separator].Trim();
                string value = line[(separator + 1)..];
                if (name.Length == 0)
                {
                    error = $"Environment override line {i + 1} has an empty variable name.";
                    variables.Clear();
                    return false;
                }

                if (name.Contains('\0') || value.Contains('\0'))
                {
                    error = $"Environment override line {i + 1} contains an invalid NUL character.";
                    variables.Clear();
                    return false;
                }

                variables.Add(new KeyValuePair<string, string>(name, value));
            }

            return true;
        }

        public string ToIpcEnvironmentOverrideBlock()
        {
            if (!TryParseEnvironmentOverrides(out List<KeyValuePair<string, string>> variables, out _))
            {
                return string.Empty;
            }

            if (ConcealHookPresence)
            {
                variables.RemoveAll(static p => p.Key.Equals("BK_HOOK_CONCEAL", StringComparison.OrdinalIgnoreCase));
                variables.Add(new KeyValuePair<string, string>("BK_HOOK_CONCEAL", "1"));
            }

            variables.RemoveAll(static p =>
                                    p.Key.Equals("BK_ANALYSIS_SUBJECT_KIND", StringComparison.OrdinalIgnoreCase) ||
                                    p.Key.Equals("BK_ANALYSIS_SUBJECT_PATH", StringComparison.OrdinalIgnoreCase) ||
                                    p.Key.Equals("BK_ANALYSIS_HOST_PATH", StringComparison.OrdinalIgnoreCase));
            variables.Add(
                new KeyValuePair<string, string>("BK_ANALYSIS_SUBJECT_KIND", HasAnalysisSubject ? "DLL" : "PROCESS"));
            if (HasAnalysisSubject)
            {
                variables.Add(new KeyValuePair<string, string>("BK_ANALYSIS_SUBJECT_PATH", AnalysisSubjectPath));
                if (!string.IsNullOrWhiteSpace(AnalysisHostPath))
                {
                    variables.Add(new KeyValuePair<string, string>("BK_ANALYSIS_HOST_PATH", AnalysisHostPath));
                }
            }

            return string.Join("\n", variables.Select(static pair => $"{pair.Key}={pair.Value}"));
        }
    }
}
