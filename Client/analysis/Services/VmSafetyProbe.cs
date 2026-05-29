using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Text;

namespace BlackbirdInterface
{
    internal enum VmSafetySeverity
    {
        Info = 0,
        Low = 1,
        Medium = 2,
        High = 3
    }

    internal sealed record VmSafetyFinding(VmSafetySeverity Severity, string Category, string Summary, string Evidence);

    internal sealed class VmSafetyProbeReport
    {
        public VirtualizationProbeReport Virtualization { get; init; } = new();
        public IReadOnlyList<VmSafetyFinding> Findings { get; init; } = Array.Empty<VmSafetyFinding>();
        public VmSafetySeverity HighestSeverity =>
            Findings.Count == 0 ? VmSafetySeverity.Info : Findings.Max(static x => x.Severity);
        public int HighCount => Findings.Count(static x => x.Severity == VmSafetySeverity.High);
        public int MediumCount => Findings.Count(static x => x.Severity == VmSafetySeverity.Medium);
        public bool ShouldWarn => HighCount != 0;

        public string Summary
        {
            get {
                if (Findings.Count == 0)
                {
                    return Virtualization.VmLikely ? "VM detected; no high-risk isolation findings"
                                                   : "No VM signal detected; no high-risk isolation findings";
                }

                return $"highest={HighestSeverity} high={HighCount} medium={MediumCount} findings={Findings.Count}";
            }
        }

        public string BuildToastMessage()
        {
            return HighCount == 1
                       ? "Blackbird detected a high-risk VM isolation issue. The analysis guest may expose host resources or adjacent network services."
                       : $"Blackbird detected {HighCount} high-risk VM isolation issues. The analysis guest may expose host resources or adjacent network services.";
        }

        public string BuildDetails()
        {
            var sb = new StringBuilder();
            sb.AppendLine("Blackbird VM safety preflight");
            sb.AppendLine();
            sb.AppendLine($"VM likely: {(Virtualization.VmLikely ? "yes" : "no")}");
            sb.AppendLine($"Hypervisor: {(string.IsNullOrWhiteSpace(Virtualization.HypervisorVendor) ? "<unknown>" : Virtualization.HypervisorVendor)}");
            sb.AppendLine($"Highest severity: {HighestSeverity}");
            sb.AppendLine();
            sb.AppendLine("This check is passive and best-effort from inside the guest. Host-side clipboard, drag/drop, VSOCK listener policy, USB passthrough, and 3D acceleration may still need manual verification in the hypervisor UI.");
            sb.AppendLine();

            if (Findings.Count == 0)
            {
                sb.AppendLine("Detected findings: none");
            }
            else
            {
                sb.AppendLine("Detected findings:");
                foreach (VmSafetyFinding finding in Findings.OrderByDescending(static x => x.Severity)
                                                            .ThenBy(static x => x.Category))
                {
                    sb.AppendLine($"- [{finding.Severity}] {finding.Category}: {finding.Summary}");
                    if (!string.IsNullOrWhiteSpace(finding.Evidence))
                    {
                        sb.AppendLine($"  evidence: {finding.Evidence}");
                    }
                }
            }

            return sb.ToString().TrimEnd();
        }
    }

    internal static class VmSafetyProbe
    {
        private static readonly string[] HostShareDriverServices = {
            "VBoxSF", "vmhgfs", "viofs", "prl_fs"
        };

        private static readonly string[] GuestRpcServices = {
            "VMTools", "vmci", "vsock", "viosock", "VBoxService", "VBoxGuest", "qemu-ga", "vmicguestinterface",
            "vmicvmsession", "vmicheartbeat", "vmickvpexchange", "vmictimesync"
        };

        private static readonly string[] GuestIntegrationProcesses = {
            "vmtoolsd", "vmwaretray", "VBoxTray", "VBoxService", "qemu-ga", "prl_tools", "rdpclip"
        };

        public static VmSafetyProbeReport Run()
        {
            var findings = new List<VmSafetyFinding>();
            VirtualizationProbeReport virtualization = VirtualizationProbe.Run();
            bool sharedStorageVisible = false;
            bool cfaDisabledOrUnknown = false;

            if (!virtualization.VmLikely)
            {
                Add(findings, VmSafetySeverity.Low, "VM boundary",
                    "No strong virtualization signal detected; use a dedicated VM for hostile sample work.",
                    $"score={virtualization.EvidenceScore}/{virtualization.DetectionThreshold}");
            }

            sharedStorageVisible = ProbeMappedNetworkDrives(findings);
            ProbeHostShareDrivers(findings);
            ProbeGuestIntegrationChannels(findings);
            ProbeSessionRedirection(findings);
            cfaDisabledOrUnknown = ProbeControlledFolderAccess(findings);
            ProbeFirewall(findings);
            ProbeSensitiveListeners(findings);
            ProbeDomainAndDnsLeakage(findings);

            if (sharedStorageVisible && cfaDisabledOrUnknown)
            {
                Add(findings, VmSafetySeverity.High, "Folder protection",
                    "Host/share-like storage is visible while Controlled Folder Access is disabled or unknown.",
                    "shared-storage-signal=true cfa=disabled-or-unknown");
            }

            return new VmSafetyProbeReport { Virtualization = virtualization, Findings = findings };
        }

        private static bool ProbeMappedNetworkDrives(List<VmSafetyFinding> findings)
        {
            bool found = false;
            try
            {
                foreach (DriveInfo drive in DriveInfo.GetDrives())
                {
                    if (drive.DriveType != DriveType.Network)
                    {
                        continue;
                    }

                    found = true;
                    Add(findings, VmSafetySeverity.High, "Shared filesystem",
                        "Network-mapped drive is visible inside the analysis guest.",
                        $"drive={drive.Name}");
                }
            }
            catch (Exception ex)
            {
                Add(findings, VmSafetySeverity.Low, "Shared filesystem",
                    "Unable to enumerate logical drives for shared-folder exposure.", ex.Message);
            }

            return found;
        }

        private static bool ProbeHostShareDrivers(List<VmSafetyFinding> findings)
        {
            bool found = false;
            foreach (string serviceName in HostShareDriverServices)
            {
                if (!TryReadServiceState(serviceName, out string state))
                {
                    continue;
                }

                found = true;
                Add(findings, VmSafetySeverity.Medium, "Shared filesystem",
                    "Host/guest shared-filesystem driver or service is enabled.",
                    $"service={serviceName} state={state}");
            }
            return found;
        }

        private static void ProbeGuestIntegrationChannels(List<VmSafetyFinding> findings)
        {
            foreach (string serviceName in GuestRpcServices)
            {
                if (TryReadServiceState(serviceName, out string state))
                {
                    Add(findings, VmSafetySeverity.Medium, "Host-guest channel",
                        "Guest integration or host-guest RPC service is enabled.",
                        $"service={serviceName} state={state}");
                }
            }

            HashSet<string> processes = CollectProcessNames();
            foreach (string processName in GuestIntegrationProcesses)
            {
                if (processes.Contains(NormalizeProcessName(processName)))
                {
                    Add(findings, VmSafetySeverity.Medium, "Host-guest channel",
                        "Guest integration process is running; verify clipboard, drag/drop, and drive redirection are disabled.",
                        $"process={processName}");
                }
            }
        }

        private static void ProbeSessionRedirection(List<VmSafetyFinding> findings)
        {
            string sessionName = Environment.GetEnvironmentVariable("SESSIONNAME") ?? string.Empty;
            string clientName = Environment.GetEnvironmentVariable("CLIENTNAME") ?? string.Empty;
            if (sessionName.StartsWith("RDP-", StringComparison.OrdinalIgnoreCase) ||
                !string.IsNullOrWhiteSpace(clientName))
            {
                Add(findings, VmSafetySeverity.Medium, "Session redirection",
                    "RDP/Enhanced Session context detected; verify clipboard, local drive, printer, and smartcard redirection are disabled.",
                    $"session={sessionName} client={clientName}");
            }
        }

        private static bool ProbeControlledFolderAccess(List<VmSafetyFinding> findings)
        {
            int? cfa = ReadControlledFolderAccessValue();
            if (cfa == 1)
            {
                Add(findings, VmSafetySeverity.Info, "Folder protection", "Controlled Folder Access is enabled.",
                    "EnableControlledFolderAccess=1");
                return false;
            }

            if (cfa == 2)
            {
                Add(findings, VmSafetySeverity.Low, "Folder protection",
                    "Controlled Folder Access is in audit mode, not block mode.", "EnableControlledFolderAccess=2");
                return false;
            }

            Add(findings, VmSafetySeverity.Medium, "Folder protection",
                "Controlled Folder Access appears disabled or unavailable.", cfa.HasValue
                                                                                ? $"EnableControlledFolderAccess={cfa.Value}"
                                                                                : "value not found");
            return true;
        }

        private static void ProbeFirewall(List<VmSafetyFinding> findings)
        {
            foreach ((string label, string subKey) in new[] {
                         ("Domain", @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile"),
                         ("Private/Public", @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile"),
                         ("Public", @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile")
                     })
            {
                int? enabled = ReadDword(Registry.LocalMachine, subKey, "EnableFirewall");
                if (enabled == 0)
                {
                    Add(findings, VmSafetySeverity.High, "Firewall",
                        $"{label} Windows Firewall profile is disabled.", $"{subKey}\\EnableFirewall=0");
                }
            }
        }

        private static void ProbeSensitiveListeners(List<VmSafetyFinding> findings)
        {
            try
            {
                IPEndPoint[] listeners = IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners();
                foreach (int port in new[] { 135, 139, 445, 3389, 5985, 5986 })
                {
                    IPEndPoint[] matches = listeners.Where(x => x.Port == port && IsExternallyReachableListener(x))
                                                    .Take(3)
                                                    .ToArray();
                    if (matches.Length == 0)
                    {
                        continue;
                    }

                    Add(findings, VmSafetySeverity.Medium, "Network exposure",
                        $"Sensitive inbound listener is exposed on TCP/{port}.",
                        string.Join(",", matches.Select(static x => x.Address.ToString())));
                }
            }
            catch (Exception ex)
            {
                Add(findings, VmSafetySeverity.Low, "Network exposure",
                    "Unable to enumerate active TCP listeners.", ex.Message);
            }
        }

        private static void ProbeDomainAndDnsLeakage(List<VmSafetyFinding> findings)
        {
            try
            {
                IPGlobalProperties props = IPGlobalProperties.GetIPGlobalProperties();
                string domain = props.DomainName ?? string.Empty;
                if (!string.IsNullOrWhiteSpace(domain) && !LooksLikeHomeDnsSuffix(domain))
                {
                    Add(findings, VmSafetySeverity.Medium, "Network identity",
                        "Domain/DNS suffix is visible in the analysis guest; verify this VM is not joined to production infrastructure.",
                        $"domain={domain}");
                }
            }
            catch
            {
            }

            try
            {
                foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (nic.OperationalStatus != OperationalStatus.Up ||
                        nic.NetworkInterfaceType is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel)
                    {
                        continue;
                    }

                    IPInterfaceProperties props = nic.GetIPProperties();
                    bool hasGateway = props.GatewayAddresses.Any(static x => x.Address != null &&
                                                                             !IPAddress.IsLoopback(x.Address));
                    string suffix = props.DnsSuffix ?? string.Empty;
                    if (hasGateway && !string.IsNullOrWhiteSpace(suffix) && !LooksLikeHomeDnsSuffix(suffix))
                    {
                        Add(findings, VmSafetySeverity.Medium, "Network identity",
                            "Active adapter has a non-local DNS suffix and a default gateway.",
                            $"adapter={nic.Name} suffix={suffix}");
                    }
                }
            }
            catch
            {
            }
        }

        private static bool IsExternallyReachableListener(IPEndPoint endpoint)
        {
            IPAddress address = endpoint.Address;
            return address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any) ||
                   (!IPAddress.IsLoopback(address) && !address.Equals(IPAddress.IPv6Loopback));
        }

        private static bool LooksLikeHomeDnsSuffix(string value)
        {
            string lower = value.Trim().ToLowerInvariant();
            return lower.Length == 0 || lower is "local" or "localdomain" or "lan" or "home" ||
                   lower.EndsWith(".local", StringComparison.OrdinalIgnoreCase) ||
                   lower.EndsWith(".lan", StringComparison.OrdinalIgnoreCase) ||
                   lower.EndsWith(".home", StringComparison.OrdinalIgnoreCase);
        }

        private static int? ReadControlledFolderAccessValue()
        {
            foreach ((RegistryKey root, string subKey) in new[] {
                         (Registry.LocalMachine,
                          @"SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access"),
                         (Registry.LocalMachine,
                          @"SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access")
                     })
            {
                int? value = ReadDword(root, subKey, "EnableControlledFolderAccess");
                if (value.HasValue)
                {
                    return value;
                }
            }

            return null;
        }

        private static int? ReadDword(RegistryKey root, string subKey, string valueName)
        {
            try
            {
                using RegistryKey? key = root.OpenSubKey(subKey);
                object? raw = key?.GetValue(valueName);
                return raw switch { int intValue => intValue,
                                    string text when int.TryParse(text, out int parsed) => parsed,
                                    _ => null };
            }
            catch
            {
                return null;
            }
        }

        private static bool TryReadServiceState(string serviceName, out string state)
        {
            state = string.Empty;
            int? start = ReadDword(Registry.LocalMachine, $@"SYSTEM\CurrentControlSet\Services\{serviceName}", "Start");
            if (!start.HasValue || start.Value == 4)
            {
                return false;
            }

            state = start.Value switch {
                0 => "boot",
                1 => "system",
                2 => "auto",
                3 => "manual",
                _ => "installed"
            };
            return true;
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

        private static void Add(List<VmSafetyFinding> findings, VmSafetySeverity severity, string category,
                                string summary, string evidence)
        {
            findings.Add(new VmSafetyFinding(severity, category, summary, evidence));
        }
    }
}
