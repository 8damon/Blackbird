using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;

namespace BlackbirdInterface
{
    internal sealed class SecurityProductProbeReport
    {
        public IReadOnlyList<string> Findings { get; init; } = Array.Empty<string>();
        public bool Detected => Findings.Count != 0;
        public string Summary => Detected ? string.Join("; ", Findings.Take(6)) : "None detected";

        public string BuildDetails()
        {
            var sb = new StringBuilder();
            sb.AppendLine("Blackbird detected another endpoint security product on this host.");
            sb.AppendLine();
            sb.AppendLine("This can interfere with kernel callbacks, user-mode hooks, ETW routing, process access, memory reads, and stack walking. Blackbird may be unstable or may not work properly until conflicting protections are disabled or Blackbird is run in a clean analysis VM.");
            sb.AppendLine();
            sb.AppendLine("Detected signals:");
            foreach (string finding in Findings)
            {
                sb.AppendLine($"- {finding}");
            }
            return sb.ToString().TrimEnd();
        }
    }

    internal static class SecurityProductProbe
    {
        private static readonly SecurityProductSignal[] Signals = {
            new("Microsoft Defender Antivirus", new[] { "WinDefend", "WdNisSvc", "WdFilter", "WdBoot", "WdNisDrv" },
                new[] { "MsMpEng", "NisSrv", "SecurityHealthService" }),
            new("Microsoft Defender for Endpoint", new[] { "Sense", "SenseIR" }, new[] { "SenseNdr", "SenseCE" }),
            new("CrowdStrike Falcon", new[] { "CSFalconService", "CSAgent", "csagent" },
                new[] { "CSFalconService", "CSFalconContainer", "CSAgent" }),
            new("SentinelOne", new[] { "SentinelAgent", "SentinelHelperService", "SentinelStaticEngine" },
                new[] { "SentinelAgent", "SentinelHelperService", "SentinelServiceHost" }),
            new("Palo Alto Cortex XDR", new[] { "cyserver", "cyverak", "cyvrfsfd" }, new[] { "cyserver", "cytray" }),
            new("Trellix/FireEye", new[] { "xagt", "xagtnotif", "FeKern" }, new[] { "xagt", "xagtnotif" }),
            new("Carbon Black", new[] { "CarbonBlack", "CbDefense", "Parity", "RepMgr" },
                new[] { "RepMgr", "CbDefense", "CarbonBlack" }),
            new("Elastic Endpoint", new[] { "ElasticEndpoint", "Elastic Agent" },
                new[] { "elastic-endpoint", "elastic-agent" }),
            new("Sophos", new[] { "Sophos Endpoint Defense", "Sophos MCS Agent", "Sophos Anti-Virus" },
                new[] { "SophosHealth", "SophosUI", "SophosFileScanner" }),
            new("Kaspersky", new[] { "AVP", "klflt", "klhk", "klim6" }, new[] { "avp" }),
            new("Symantec/Broadcom Endpoint", new[] { "SepMasterService", "Symantec Endpoint Protection" },
                new[] { "ccSvcHst", "Smc" }),
            new("Cylance", new[] { "CylanceSvc", "CyProtectDrv" }, new[] { "CylanceSvc", "CylanceUI" }),
            new("Tanium", new[] { "Tanium Client" }, new[] { "TaniumClient", "TaniumCX" }),
            new("Qualys", new[] { "QualysAgent" }, new[] { "QualysAgent" })
        };

        public static SecurityProductProbeReport Run()
        {
            var findings = new List<string>();
            var processNames = CollectProcessNames();

            foreach (SecurityProductSignal signal in Signals)
            {
                var evidence = new List<string>();
                foreach (string serviceName in signal.ServiceNames)
                {
                    if (TryReadServiceState(serviceName, out string state))
                    {
                        evidence.Add($"service={serviceName} ({state})");
                    }
                }

                foreach (string processName in signal.ProcessNames)
                {
                    if (processNames.Contains(NormalizeProcessName(processName)))
                    {
                        evidence.Add($"process={processName}");
                    }
                }

                if (evidence.Count != 0)
                {
                    findings.Add($"{signal.ProductName}: {string.Join(", ", evidence.Take(4))}");
                }
            }

            return new SecurityProductProbeReport { Findings = findings };
        }

        private static HashSet<string> CollectProcessNames()
        {
            var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            try
            {
                foreach (Process process in Process.GetProcesses())
                {
                    try
                    {
                        names.Add(NormalizeProcessName(process.ProcessName));
                    }
                    catch
                    {
                    }
                    finally
                    {
                        process.Dispose();
                    }
                }
            }
            catch
            {
            }
            return names;
        }

        private static string NormalizeProcessName(string name)
        {
            return name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? name[..^4] : name;
        }

        private static bool TryReadServiceState(string serviceName, out string state)
        {
            state = string.Empty;
            try
            {
                using RegistryKey? key =
                    Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{serviceName}");
                if (key == null)
                {
                    return false;
                }

                int start = key.GetValue("Start") is int startValue ? startValue : -1;
                state = start switch {
                    0 => "boot",
                    1 => "system",
                    2 => "auto",
                    3 => "manual",
                    4 => "disabled",
                    _ => "installed"
                };
                return start != 4;
            }
            catch
            {
                return false;
            }
        }

        private sealed record SecurityProductSignal(string ProductName, IReadOnlyList<string> ServiceNames,
                                                    IReadOnlyList<string> ProcessNames);
    }
}
