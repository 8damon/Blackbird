using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Runtime.Intrinsics.X86;
using System.Text;

namespace BlackbirdInterface
{
    internal sealed class VirtualizationProbeReport
    {
        public bool CpuidSupported { get; init; }
        public bool HypervisorPresent { get; init; }
        public string HypervisorVendor { get; init; } = "";
        public bool VmLikely { get; init; }
        public int EvidenceScore { get; init; }
        public int DetectionThreshold { get; init; }
        public IReadOnlyList<string> Signals { get; init; } = Array.Empty<string>();

        public string BuildOperatorMessage()
        {
            var sb = new StringBuilder();
            sb.AppendLine("Startup environment check (CPUID + VM heuristics)");
            sb.AppendLine();
            sb.AppendLine($"CPUID supported: {(CpuidSupported ? "yes" : "no")}");
            sb.AppendLine($"Hypervisor bit: {(HypervisorPresent ? "set" : "not set")}");
            sb.AppendLine($"Hypervisor vendor: {(string.IsNullOrWhiteSpace(HypervisorVendor) ? "<none>" : HypervisorVendor)}");
            sb.AppendLine($"VM likely: {(VmLikely ? "yes" : "no")}");
            sb.AppendLine($"Evidence score: {EvidenceScore} / {DetectionThreshold}");

            sb.AppendLine();
            if (VmLikely)
            {
                sb.AppendLine("Result: virtualized environment detected. This is suitable for anti-VM-aware analysis workflows.");
            }
            else
            {
                sb.AppendLine("Result: no strong VM signal detected.");
                sb.AppendLine("If samples use anti-VM checks, run Blackbird inside a dedicated VM.");
                sb.AppendLine("Recommended: Hyper-V, VMware, or VirtualBox with hardware virtualization enabled.");
            }

            sb.AppendLine();
            if (Signals.Count == 0)
            {
                sb.AppendLine("Detected signals: none");
            }
            else
            {
                sb.AppendLine("Detected signals:");
                foreach (string signal in Signals)
                {
                    sb.AppendLine($"- {signal}");
                }
            }

            return sb.ToString().TrimEnd();
        }
    }

    internal static class VirtualizationProbe
    {
        private static readonly string[] VmIndicators =
        {
            "vmware", "virtualbox", "vbox", "kvm", "qemu", "xen", "hyper-v", "hyperv", "parallels", "bhyve"
        };
        private const int VmDetectionThreshold = 4;
        private const int WeightCpuidHypervisorBit = 8;
        private const int WeightCpuidVendor = 5;
        private const int WeightRegistryIndicator = 4;
        private const int WeightVmServicePresent = 1;
        private const int WeightVmServiceEnabled = 1;

        public static VirtualizationProbeReport Run()
        {
            bool cpuidSupported = false;
            bool hypervisorPresent = false;
            string hypervisorVendor = string.Empty;
            var signals = new List<string>(8);
            int score = 0;

            try
            {
                cpuidSupported = X86Base.IsSupported;
                if (cpuidSupported)
                {
                    var leaf1 = X86Base.CpuId(1, 0);
                    hypervisorPresent = ((leaf1.Ecx & (1 << 31)) != 0);
                    if (hypervisorPresent)
                    {
                        score += WeightCpuidHypervisorBit;
                        signals.Add($"+{WeightCpuidHypervisorBit} CPUID hypervisor bit is set.");

                        var hvLeaf = X86Base.CpuId(unchecked((int)0x40000000), 0);
                        hypervisorVendor = DecodeVendorString(
                            hvLeaf.Ebx,
                            hvLeaf.Ecx,
                            hvLeaf.Edx);
                        if (!string.IsNullOrWhiteSpace(hypervisorVendor))
                        {
                            score += WeightCpuidVendor;
                            signals.Add($"+{WeightCpuidVendor} CPUID hypervisor vendor: {hypervisorVendor}");
                        }
                    }
                }
            }
            catch
            {
            }

            score += TryCollectRegistryVmSignals(signals);
            bool vmLikely = score >= VmDetectionThreshold;

            return new VirtualizationProbeReport
            {
                CpuidSupported = cpuidSupported,
                HypervisorPresent = hypervisorPresent,
                HypervisorVendor = hypervisorVendor,
                VmLikely = vmLikely,
                EvidenceScore = score,
                DetectionThreshold = VmDetectionThreshold,
                Signals = signals
            };
        }

        private static int TryCollectRegistryVmSignals(List<string> signals)
        {
            int score = 0;
            string? biosVendor = ReadRegistryString(
                Registry.LocalMachine,
                @"HARDWARE\DESCRIPTION\System\BIOS",
                "BIOSVendor");
            string? systemManufacturer = ReadRegistryString(
                Registry.LocalMachine,
                @"HARDWARE\DESCRIPTION\System\BIOS",
                "SystemManufacturer");
            string? systemProductName = ReadRegistryString(
                Registry.LocalMachine,
                @"HARDWARE\DESCRIPTION\System\BIOS",
                "SystemProductName");
            string? videoBiosVersion = ReadRegistryString(
                Registry.LocalMachine,
                @"HARDWARE\DESCRIPTION\System",
                "VideoBiosVersion");

            score += AddSignalIfVmIndicator(signals, "BIOSVendor", biosVendor);
            score += AddSignalIfVmIndicator(signals, "SystemManufacturer", systemManufacturer);
            score += AddSignalIfVmIndicator(signals, "SystemProductName", systemProductName);
            score += AddSignalIfVmIndicator(signals, "VideoBiosVersion", videoBiosVersion);

            score += TryAddServiceSignal(signals, "vmicheartbeat");
            score += TryAddServiceSignal(signals, "VBoxGuest");
            score += TryAddServiceSignal(signals, "vmhgfs");
            score += TryAddServiceSignal(signals, "vmmouse");
            score += TryAddServiceSignal(signals, "xenbus");

            return score;
        }

        private static int TryAddServiceSignal(List<string> signals, string serviceName)
        {
            try
            {
                using RegistryKey? key =
                    Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{serviceName}");
                if (key != null)
                {
                    int score = WeightVmServicePresent;
                    signals.Add($"+{WeightVmServicePresent} VM-related service key present: {serviceName}");

                    object? rawStart = key.GetValue("Start");
                    int? startType = rawStart as int?;
                    if (startType.HasValue && startType.Value != 4)
                    {
                        score += WeightVmServiceEnabled;
                        signals.Add($"+{WeightVmServiceEnabled} VM-related service enabled: {serviceName} (Start={startType.Value})");
                    }

                    return score;
                }
            }
            catch
            {
            }

            return 0;
        }

        private static string? ReadRegistryString(RegistryKey root, string subKey, string valueName)
        {
            try
            {
                using RegistryKey? key = root.OpenSubKey(subKey);
                return key?.GetValue(valueName) as string;
            }
            catch
            {
                return null;
            }
        }

        private static int AddSignalIfVmIndicator(List<string> signals, string label, string? value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return 0;
            }

            string lower = value.ToLowerInvariant();
            foreach (string indicator in VmIndicators)
            {
                if (lower.Contains(indicator))
                {
                    signals.Add($"+{WeightRegistryIndicator} {label}: {value} (matched '{indicator}')");
                    return WeightRegistryIndicator;
                }
            }

            return 0;
        }

        private static string DecodeVendorString(int ebx, int ecx, int edx)
        {
            Span<byte> bytes = stackalloc byte[12];
            WriteInt32LittleEndian(bytes.Slice(0, 4), ebx);
            WriteInt32LittleEndian(bytes.Slice(4, 4), ecx);
            WriteInt32LittleEndian(bytes.Slice(8, 4), edx);
            return Encoding.ASCII.GetString(bytes).Trim('\0', ' ');
        }

        private static void WriteInt32LittleEndian(Span<byte> destination, int value)
        {
            destination[0] = (byte)(value & 0xFF);
            destination[1] = (byte)((value >> 8) & 0xFF);
            destination[2] = (byte)((value >> 16) & 0xFF);
            destination[3] = (byte)((value >> 24) & 0xFF);
        }
    }
}

