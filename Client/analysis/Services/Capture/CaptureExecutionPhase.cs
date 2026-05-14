using System;
using System.Collections.Generic;
using System.Globalization;

namespace BlackbirdInterface.Capture
{
    internal enum CaptureExecutionPhase
    {
        Active = 0,
        PreResume = 1,
        PostResumeStartup = 2,
        Paused = 3,
        Exited = 4
    }

    internal readonly record struct CaptureExecutionPhaseState(CaptureExecutionPhase Phase, DateTime? ResumeUtc,
                                                               DateTime? StartupUntilUtc)
    {
        internal bool IsPreResume => Phase == CaptureExecutionPhase.PreResume;

        internal bool IsStartup(DateTime observedUtc)
        {
            if (Phase != CaptureExecutionPhase.PostResumeStartup)
            {
                return false;
            }

            return !StartupUntilUtc.HasValue || observedUtc <= StartupUntilUtc.Value;
        }

        internal static CaptureExecutionPhaseState ActiveDefault { get; } =
            new(CaptureExecutionPhase.Active, null, null);
    }

    internal static class CaptureExecutionPolicy
    {
        internal static readonly TimeSpan DefaultStartupWindow = TimeSpan.FromSeconds(3);

        private const uint MemImage = 0x01000000;
        private const uint MemPrivate = 0x00020000;
        private const uint MemCommit = 0x00001000;

        private static readonly HashSet<string> StartupSuppressedDetections =
            new(StringComparer.OrdinalIgnoreCase) { "HOOK_API_CALL",
                                                    "MEMORY_ACTIVITY",
                                                    "PROCESS_RECON",
                                                    "REMOTE_THREAD_WITH_RECENT_HANDLE_INTENT",
                                                    "REMOTE_THREAD_START_IN_NON_IMAGE_EXECUTABLE_REGION",
                                                    "POSSIBLE_MANUAL_MAP_OR_HOLLOWING_EXECUTION",
                                                    "SECTION_MAP_ACTIVITY",
                                                    "USERMODE_HOOK_API_CALL",
                                                    "USERMODE_MEMORY_ACTIVITY",
                                                    "USERMODE_PROCESS_RECON",
                                                    "USERMODE_SECTION_MAP_ACTIVITY" };

        private static readonly HashSet<string> BrokerNames = new(StringComparer.OrdinalIgnoreCase) {
            "csrss",       "csrss.exe",       "smss",          "smss.exe",         "wininit", "wininit.exe",
            "winlogon",    "winlogon.exe",    "services",      "services.exe",     "lsass",   "lsass.exe",
            "werfault",    "werfault.exe",    "wermgr",        "wermgr.exe",       "conhost", "conhost.exe",
            "openconsole", "openconsole.exe", "runtimebroker", "runtimebroker.exe"
        };

        internal static CaptureExecutionPhaseState CreateState(CaptureExecutionPhase phase, DateTime timestampUtc,
                                                               CaptureExecutionPhaseState previous)
        {
            DateTime safeTimestamp = timestampUtc == default ? DateTime.UtcNow : timestampUtc;
            return phase switch {
                CaptureExecutionPhase.PreResume => new CaptureExecutionPhaseState(phase, null, null),
                CaptureExecutionPhase.PostResumeStartup =>
                    new CaptureExecutionPhaseState(phase, safeTimestamp, safeTimestamp + DefaultStartupWindow),
                CaptureExecutionPhase.Active =>
                    new CaptureExecutionPhaseState(phase, previous.ResumeUtc, previous.StartupUntilUtc),
                CaptureExecutionPhase.Paused =>
                    new CaptureExecutionPhaseState(phase, previous.ResumeUtc, previous.StartupUntilUtc),
                CaptureExecutionPhase.Exited =>
                    new CaptureExecutionPhaseState(phase, previous.ResumeUtc, previous.StartupUntilUtc),
                _ => CaptureExecutionPhaseState.ActiveDefault
            };
        }

        internal static bool ShouldSuppressPromotion(CaptureExecutionPhaseState state, DateTime observedUtc, uint actor,
                                                     uint target, Func<uint, bool> isTrackedPid, string detectionName,
                                                     string eventName, string evidence, bool strongEvidence = false)
        {
            if (!TouchesTrackedScope(actor, target, isTrackedPid))
            {
                return false;
            }

            if (state.IsPreResume)
            {
                return true;
            }

            if (!state.IsStartup(observedUtc))
            {
                return false;
            }

            if (strongEvidence || HasConcreteInjectionEvidence(detectionName, eventName, evidence))
            {
                return false;
            }

            string normalizedDetection = NormalizeToken(detectionName);
            if (StartupSuppressedDetections.Contains(normalizedDetection) ||
                normalizedDetection.StartsWith("USERMODE_", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            if (normalizedDetection is "MEMORY_STRING_DIFF" or "MEMORY_STRING_DIFF_NEW_STRINGS")
            {
                return true;
            }

            return IsKnownOsBrokerPid(actor) && actor != 0 && actor != target &&
                   LooksLikeBootstrapOrBrokerEvidence(eventName, evidence);
        }

        internal static bool IsImageBackedStart(ulong startAddress, ulong imageBase, ulong imageSize,
                                                uint startRegionType, string evidence)
        {
            if (startAddress == 0)
            {
                return false;
            }

            if (startRegionType == MemImage)
            {
                return true;
            }

            if (imageBase != 0 && imageSize != 0 && startAddress >= imageBase && startAddress < imageBase + imageSize)
            {
                return true;
            }

            return ContainsAny(evidence, "startSymbol=ntdll.dll", "startSymbol=kernel32.dll",
                               "startSymbol=kernelbase.dll", "startRegionType=0x01000000", "MEM_IMAGE");
        }

        internal static bool IsPrivateExecutableStart(ulong startAddress, uint startRegionProtect,
                                                      uint startRegionState, uint startRegionType, string evidence)
        {
            if (startAddress == 0)
            {
                return false;
            }

            bool privateCommitted =
                startRegionType == MemPrivate && (startRegionState == 0 || startRegionState == MemCommit);
            bool executable = IsExecutableProtection(startRegionProtect) ||
                              ContainsAny(evidence, "MEM_PRIVATE", "private executable", "private-exec");
            return privateCommitted && executable;
        }

        internal static bool IsKnownOsBrokerPid(uint pid)
        {
            if (pid == 0)
            {
                return false;
            }

            string name;
            try
            {
                name = ProcessIdentityResolver.ResolveImmediate(pid);
            }
            catch
            {
                return false;
            }

            string normalized = NormalizeProcessName(name);
            return BrokerNames.Contains(normalized);
        }

        internal static bool IsExecutableProtection(uint protect) => (protect & 0xF0u) != 0;

        internal static bool IsWritableExecutableProtection(uint protect)
        {
            uint baseProtect = protect & 0xFFu;
            return baseProtect == 0x40u || baseProtect == 0x80u;
        }

        private static bool TouchesTrackedScope(uint actor, uint target,
                                                Func<uint, bool> isTrackedPid) => (actor != 0 && isTrackedPid(actor)) ||
                                                                                  (target != 0 && isTrackedPid(target));

        private static bool HasConcreteInjectionEvidence(string detectionName, string eventName, string evidence)
        {
            string text = $"{detectionName} {eventName} {evidence}";
            if (ContainsAny(text, "peHeader=true", "amsiPatch=true", "private-exec-dump",
                            "private-exec-staged-executed", "direct_syscall_stub", "rule=direct_syscall_stub",
                            "YARA_DIRECT_SYSCALL_STUB"))
            {
                return true;
            }

            if (ContainsAny(text, "MEM_PRIVATE", "startRegionType=0x00020000", "private executable") &&
                ContainsAny(text, "PAGE_EXECUTE", "protect=0x00000040", "protect=0x40", "RWX"))
            {
                return true;
            }

            return false;
        }

        private static bool LooksLikeBootstrapOrBrokerEvidence(string eventName, string evidence)
        {
            string text = $"{eventName} {evidence}";
            return ContainsAny(text, "ThreadTelemetry", "ThreadCreate", "startSymbol=ntdll.dll",
                               "startRegionType=0x01000000", "MEM_IMAGE", "OpenConsole", "conhost", "WerFault",
                               "wermgr", "operation=ProcessCreate", "operation=ThreadTelemetry");
        }

        private static bool ContainsAny(string? value, params string[] needles)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return false;
            }

            foreach (string needle in needles)
            {
                if (!string.IsNullOrWhiteSpace(needle) &&
                    value.IndexOf(needle, StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    return true;
                }
            }

            return false;
        }

        private static string
            NormalizeToken(string? value) => (value ?? string.Empty).Trim().Replace('-', '_').ToUpperInvariant();

        private static string NormalizeProcessName(string value)
        {
            string trimmed = (value ?? string.Empty).Trim();
            int pidStart = trimmed.IndexOf(" (PID ", StringComparison.OrdinalIgnoreCase);
            if (pidStart >= 0)
            {
                trimmed = trimmed[..pidStart];
            }

            if (trimmed.StartsWith("pid:", StringComparison.OrdinalIgnoreCase))
            {
                return trimmed;
            }

            string file = trimmed;
            int slash = Math.Max(file.LastIndexOf('\\'), file.LastIndexOf('/'));
            if (slash >= 0 && slash + 1 < file.Length)
            {
                file = file[(slash + 1)..];
            }

            return file.ToLower(CultureInfo.InvariantCulture);
        }
    }
}
