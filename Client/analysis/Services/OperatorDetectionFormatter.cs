using System;

namespace BlackbirdInterface
{
    internal static class OperatorDetectionFormatter
    {
        internal static string Format(string? detection, uint actorPid, uint targetPid, string? operation = null)
        {
            string raw = (detection ?? string.Empty).Trim();
            if (string.IsNullOrWhiteSpace(raw))
            {
                raw = "DETECTION";
            }
            if (IsSuppressedSignal(raw))
            {
                return string.Empty;
            }
            if (LooksAlreadyFormatted(raw))
            {
                return raw;
            }

            string apiSuffix = ExtractBracketSuffix(raw);
            string name = RemoveBracketSuffix(raw).Replace('-', '_').Trim();
            if (IsSuppressedSignal(name))
            {
                return string.Empty;
            }

            string operationSuffix = NormalizeOperationSuffix(operation);
            if (string.IsNullOrWhiteSpace(apiSuffix))
            {
                apiSuffix = operationSuffix;
            }

            if (IsDirectSyscall(name))
            {
                string title = HasExternalTarget(actorPid, targetPid) ? $"DIRECT_SYSCALL to {ProcessName(targetPid)}"
                                                                      : WithActor("DIRECT_SYSCALL", actorPid);
                return AppendApi(title, apiSuffix);
            }

            name = NormalizeBaseName(name);
            if (IsSuppressedSignal(name))
            {
                return string.Empty;
            }

            if (name.Equals("SYSCALL_NUMBER_EXTRACTION", StringComparison.OrdinalIgnoreCase))
            {
                return WithActor(name, actorPid);
            }

            if (IsRemoteOrTargeted(name))
            {
                return AppendApi(WithTarget(name, actorPid, targetPid), apiSuffix);
            }

            if (IsLocalProcessContext(name))
            {
                return WithActor(name, actorPid);
            }

            return AppendApi(name, apiSuffix);
        }

        internal static string FormatProcessIdentity(uint pid, bool includePid = true)
        {
            if (pid == 0)
            {
                return "-";
            }

            string name = ProcessIdentityResolver.DescribeImmediate(pid);
            if (string.IsNullOrWhiteSpace(name) || name.StartsWith("pid:", StringComparison.OrdinalIgnoreCase))
            {
                return $"PID {pid}";
            }

            return includePid ? $"{name} ({pid})" : name;
        }

        private static string NormalizeBaseName(string name)
        {
            string value = name.Trim();
            value = RemovePrefix(value, "ENTERPRISE_");
            value = RemovePrefix(value, "USERMODE_");
            value = RemovePrefix(value, "KERNEL_");
            value = RemovePrefix(value, "POSSIBLE_");

            value = value switch { "DIRECT_SYSCALL_SUSPECT_HANDLE_OPERATION" => "DIRECT_SYSCALL",
                                   "REMOTE_APC_CREATION_SUSPECT" => "REMOTE_APC_CREATION",
                                   "REMOTE_APC_QUEUE_NTAPI" => "REMOTE_APC_QUEUE",
                                   "REMOTE_THREAD_CREATE_NTAPI" => "REMOTE_THREAD_CREATE",
                                   "REMOTE_PROCESS_MEMORY_WRITE" => "REMOTE_MEMORY_WRITE",
                                   "REMOTE_PROCESS_SET_INFORMATION" => "REMOTE_PROCESS_SET_INFORMATION",
                                   "REMOTE_THREAD_WITH_RECENT_HANDLE_INTENT" => "REMOTE_THREAD_CREATE",
                                   "REMOTE_THREAD_START_IN_NON_IMAGE_EXECUTABLE_REGION" =>
                                       "REMOTE_THREAD_START_NON_IMAGE_EXEC",
                                   "THREAD_ACTIVITY_WITH_THREAD_CONTEXT_INTENT" => "THREAD_CONTEXT_INTENT",
                                   "THREAD_CONTEXT_HIJACK" => "THREAD_HIJACK",
                                   "THREAD_HIJACK_INTENT" => "THREAD_HIJACK",
                                   "STACK_INTEGRITY_ANOMALY_ON_HANDLE_OP" => "STACK_INTEGRITY_ANOMALY",
                                   "KERNEL_PROCESS_HOLLOWING_MARK_CHAIN_STRONG" => "PROCESS_HOLLOWING_CHAIN",
                                   "PROCESS_HOLLOWING_MARK_CHAIN_STRONG" => "PROCESS_HOLLOWING_CHAIN",
                                   "POSSIBLE_MANUAL_MAP_OR_HOLLOWING_EXECUTION" => "MANUAL_MAP_OR_HOLLOWING_EXECUTION",
                                   "MANUAL_MAP_LIKELY_PRIVATE_EXEC_CHAIN" => "MANUAL_MAP_PRIVATE_EXEC_CHAIN",
                                   "MANUAL_MAP_CONFIRMED_PRIVATE_EXEC_PE" => "MANUAL_MAP_PRIVATE_EXEC_PE",
                                   "MANUAL_MAP_HEADERLESS_PRIVATE_EXEC" => "MANUAL_MAP_HEADERLESS_PRIVATE_EXEC",
                                   "CROSS_PROCESS_WRITE_PATTERN" => "CROSS_PROCESS_WRITE",
                                   "CROSS_PROCESS_RWX_ALLOC_PATTERN" => "CROSS_PROCESS_RWX_ALLOC",
                                   "MEMORY_PROTECTION_FLIP_PATTERN" => "MEMORY_PROTECTION_FLIP",
                                   "MEMORY_HIGH_ENTROPY_WRITE_PATTERN" => "MEMORY_HIGH_ENTROPY_WRITE",
                                   "MEMORY_ENTROPY_SHIFT_PATTERN" => "MEMORY_ENTROPY_SHIFT",
                                   "MEMORY_STRING_DIFF_NEW_STRINGS" => "MEMORY_NEW_STRINGS",
                                   "PROCESS_IC_CALLBACK_CLAIM_ATTEMPT" => "PROCESS_INSTRUMENTATION_CALLBACK_CLAIM",
                                   "NTDLL_DIRECT_SYSCALL_EXTRACTION" => "SYSCALL_NUMBER_EXTRACTION",
                                   "HIGH_VALUE_REGISTRY_ACTIVITY" => "REGISTRY_HIGH_VALUE_ACTIVITY",
                                   "ANALYSIS_SUBJECT_DLL_LOADED" => "DLL_LOADED_IN_ANALYSIS_SUBJECT",
                                   "SUSPICIOUS_DLL_LOAD_SENSITIVE_PROCESS" => "DLL_LOAD_IN_SENSITIVE_PROCESS",
                                   "SUSPICIOUS_NTDLL_IMAGE_PATH" => "NTDLL_IMAGE_PATH_ANOMALY",
                                   "MULTIPLE_NTDLL_IMAGE_MAPPINGS" => "MULTIPLE_NTDLL_MAPPINGS",
                                   _ => value };

            value = RemoveSuffix(value, "_SUSPECT");
            value = RemoveSuffix(value, "_NTAPI");
            value = RemoveSuffix(value, "_PATTERN");
            value = RemoveSuffix(value, "_HANDLE_OPERATION");
            value = RemoveSuffix(value, "_HANDLE_OP");
            value = RemoveSuffix(value, "_HANDLE");
            return value;
        }

        private static bool IsDirectSyscall(string name) =>
            name.Contains("DIRECT_SYSCALL", StringComparison.OrdinalIgnoreCase) ||
            name.Contains("DIRECT_SYSCALL_SUSPECT_HANDLE_OPERATION", StringComparison.OrdinalIgnoreCase) ||
            name.Contains("SUSPECT_HANDLE_OPERATION", StringComparison.OrdinalIgnoreCase);

        private static bool
        LooksAlreadyFormatted(string value) => (value.Contains(" to ", StringComparison.OrdinalIgnoreCase) ||
                                                value.Contains(" in ", StringComparison.OrdinalIgnoreCase)) &&
                                               !value.Contains("_SUSPECT", StringComparison.OrdinalIgnoreCase) &&
                                               !value.Contains("SUSPECT_HANDLE", StringComparison.OrdinalIgnoreCase) &&
                                               !value.StartsWith("ENTERPRISE_", StringComparison.OrdinalIgnoreCase);

        private static bool IsRemoteOrTargeted(string name) =>
            name.StartsWith("REMOTE_", StringComparison.OrdinalIgnoreCase) ||
            name.StartsWith("CROSS_PROCESS_", StringComparison.OrdinalIgnoreCase) ||
            name.StartsWith("PROCESS_CREDENTIAL_ACCESS", StringComparison.OrdinalIgnoreCase) ||
            name.StartsWith("PROCESS_PRIVILEGED_ACCESS", StringComparison.OrdinalIgnoreCase) ||
            name.StartsWith("TOKEN_ACCESS", StringComparison.OrdinalIgnoreCase) ||
            name.StartsWith("CREDENTIAL_ACCESS", StringComparison.OrdinalIgnoreCase) ||
            name.StartsWith("STACK_", StringComparison.OrdinalIgnoreCase) ||
            name.StartsWith("THREAD_", StringComparison.OrdinalIgnoreCase) ||
            name.Contains("HOLLOW", StringComparison.OrdinalIgnoreCase) ||
            name.Contains("HIJACK", StringComparison.OrdinalIgnoreCase) ||
            name.Contains("INJECTION", StringComparison.OrdinalIgnoreCase) ||
            name.Contains("BREAKPOINT", StringComparison.OrdinalIgnoreCase) ||
            name.Contains("THREAD_CREATE", StringComparison.OrdinalIgnoreCase) ||
            name.Contains("THREAD_EXECUTION", StringComparison.OrdinalIgnoreCase);

        private static bool IsLocalProcessContext(string name) =>
            name.StartsWith("ANTI_", StringComparison.OrdinalIgnoreCase) ||
            name.StartsWith("AMSI_", StringComparison.OrdinalIgnoreCase) ||
            name.StartsWith("ETW_", StringComparison.OrdinalIgnoreCase) ||
            name.StartsWith("HOOK_", StringComparison.OrdinalIgnoreCase) ||
            name.StartsWith("IAT_", StringComparison.OrdinalIgnoreCase) ||
            name.StartsWith("EAT_", StringComparison.OrdinalIgnoreCase) ||
            name.StartsWith("NTDLL_", StringComparison.OrdinalIgnoreCase) ||
            name.StartsWith("PACKER_", StringComparison.OrdinalIgnoreCase) ||
            name.StartsWith("YARA_", StringComparison.OrdinalIgnoreCase) ||
            name.StartsWith("SIGMA_", StringComparison.OrdinalIgnoreCase) ||
            name.StartsWith("SIGNATURE_", StringComparison.OrdinalIgnoreCase) ||
            name.StartsWith("FILE_", StringComparison.OrdinalIgnoreCase) ||
            name.StartsWith("REGISTRY_", StringComparison.OrdinalIgnoreCase) ||
            name.StartsWith("NETWORK_", StringComparison.OrdinalIgnoreCase) ||
            name.StartsWith("IMAGE_", StringComparison.OrdinalIgnoreCase) ||
            name.StartsWith("DLL_", StringComparison.OrdinalIgnoreCase) ||
            name.StartsWith("PROCESS_IMAGE_", StringComparison.OrdinalIgnoreCase) ||
            name.StartsWith("PROCESS_INSTRUMENTATION_", StringComparison.OrdinalIgnoreCase) ||
            name.StartsWith("PARENT_PID_", StringComparison.OrdinalIgnoreCase) ||
            name.StartsWith("POWERSHELL_", StringComparison.OrdinalIgnoreCase) ||
            name.StartsWith("LOLBIN_", StringComparison.OrdinalIgnoreCase) ||
            name.StartsWith("SCRIPT_HOST_", StringComparison.OrdinalIgnoreCase) ||
            name.StartsWith("MEMORY_", StringComparison.OrdinalIgnoreCase) ||
            name.StartsWith("REPEATED_", StringComparison.OrdinalIgnoreCase) ||
            name.StartsWith("DRIVER_", StringComparison.OrdinalIgnoreCase) ||
            name.StartsWith("HARDWARE_", StringComparison.OrdinalIgnoreCase) ||
            name.StartsWith("SUSPICIOUS_", StringComparison.OrdinalIgnoreCase) ||
            name.StartsWith("MULTIPLE_", StringComparison.OrdinalIgnoreCase) ||
            name.StartsWith("ANALYSIS_", StringComparison.OrdinalIgnoreCase) ||
            name.StartsWith("COM_", StringComparison.OrdinalIgnoreCase) ||
            name.StartsWith("WMI_", StringComparison.OrdinalIgnoreCase) ||
            name.StartsWith("JOB_OBJECT_", StringComparison.OrdinalIgnoreCase);

        private static string WithTarget(string name, uint actorPid,
                                         uint targetPid) => HasExternalTarget(actorPid, targetPid)
                                                                ? $"{name} to {ProcessName(targetPid)}"
                                                                : WithActor(name, actorPid);

        private static string WithActor(string name,
                                        uint actorPid) => actorPid == 0 ? name : $"{name} in {ProcessName(actorPid)}";

        private static bool HasExternalTarget(uint actorPid, uint targetPid) => targetPid != 0 && targetPid != actorPid;

        private static string ProcessName(uint pid) => FormatProcessIdentity(pid, includePid: false);

        private static string AppendApi(string title, string api)
        {
            if (string.IsNullOrWhiteSpace(api) || title.Contains($"[{api}]", StringComparison.OrdinalIgnoreCase))
            {
                return title;
            }

            return $"{title} [{api}]";
        }

        private static string NormalizeOperationSuffix(string? operation)
        {
            string value = (operation ?? string.Empty).Trim();
            if (string.IsNullOrWhiteSpace(value) || value.EndsWith("Telemetry", StringComparison.OrdinalIgnoreCase) ||
                value.Equals("heuristic", StringComparison.OrdinalIgnoreCase))
            {
                return string.Empty;
            }

            return value.StartsWith("Nt", StringComparison.OrdinalIgnoreCase) ||
                           value.StartsWith("Zw", StringComparison.OrdinalIgnoreCase)
                       ? value
                       : string.Empty;
        }

        private static string ExtractBracketSuffix(string value)
        {
            int start = value.LastIndexOf('[');
            int end = value.LastIndexOf(']');
            return start >= 0 && end > start ? value[(start + 1)..end].Trim() : string.Empty;
        }

        private static string RemoveBracketSuffix(string value)
        {
            int start = value.LastIndexOf('[');
            return start > 0 ? value[..start].Trim() : value;
        }

        private static string RemovePrefix(string value, string prefix) =>
            value.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) ? value[prefix.Length..] : value;

        private static string RemoveSuffix(string value,
                                           string suffix) => value.EndsWith(suffix, StringComparison.OrdinalIgnoreCase)
                                                                 ? value[..^ suffix.Length]
                                                                 : value;

        private static bool IsSuppressedSignal(string value)
        {
            string normalized = RemoveBracketSuffix(value ?? string.Empty).Replace('-', '_').Replace(' ', '_').Trim();
            return normalized.Equals("AGGREGATE_THREAD_SIGNAL", StringComparison.OrdinalIgnoreCase) ||
                   normalized.Equals("AGGREGATE_THREAT_SIGNAL", StringComparison.OrdinalIgnoreCase) ||
                   normalized.Contains("AGGREGATE_THREAD_SIGNAL", StringComparison.OrdinalIgnoreCase) ||
                   normalized.Contains("AGGREGATE_THREAT_SIGNAL", StringComparison.OrdinalIgnoreCase);
        }
    }
}
