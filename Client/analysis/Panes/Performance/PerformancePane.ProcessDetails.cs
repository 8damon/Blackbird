using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;

namespace BlackbirdInterface
{
    public partial class PerformancePane
    {
        private void RefreshProcessDetails()
        {
            int targetPid = _pid > 0 ? _pid : Environment.ProcessId;
            _ = Kernel32Native.EnableDebugPrivilege(out _);
            try
            {
                using var process = Process.GetProcessById(targetPid);

                RefreshModules(process);
                RefreshPeInfo(process);
                if (_historySamples.Count == 0 || _lastSample == null)
                {
                    RefreshThreadSnapshot(process);
                    RefreshMemoryMetrics(process);
                }
                RefreshNetworkPeers(targetPid);
                _processLiveDataAvailable = true;
                DiagnosticsState.SetValue("Target Handle Access", $"Direct inspection ready pid={targetPid}");
            }
            catch (Exception ex)
            {
                if (_historySamples.Count == 0)
                {
                    TopThreads.Clear();
                    CoreUsageRows.Clear();
                    ThreadLifecycleRows.Clear();
                    MemoryMetrics.Clear();
                    MemoryAttributionRows.Clear();
                }
                NetworkPeers.Clear();
                UpdateMemoryTreemap();
                _processLiveDataAvailable = false;
                DiagnosticsState.SetValue("Target Handle Access",
                                          $"Direct inspection failed pid={targetPid}: {ex.GetType().Name}");
            }

            UpdateLiveDataOverlays();
        }

        private void RefreshThreadSnapshot(Process process)
        {
            var rows = new List<ThreadUsageSample>();
            try
            {
                foreach (ProcessThread thread in process.Threads)
                {
                    string state = thread.ThreadState.ToString();
                    string waitReason = string.Empty;
                    if (thread.ThreadState == System.Diagnostics.ThreadState.Wait)
                    {
                        try
                        {
                            waitReason = thread.WaitReason.ToString();
                        }
                        catch
                        {
                            waitReason = string.Empty;
                        }
                    }

                    DateTime? startTime = null;
                    try
                    {
                        startTime = thread.StartTime.ToUniversalTime();
                    }
                    catch
                    {
                        startTime = null;
                    }

                    rows.Add(new ThreadUsageSample { Tid = thread.Id, CpuMsDelta = 0, State = state,
                                                     WaitReason = waitReason, Kind = InferThreadKind(state, waitReason),
                                                     StartTimeUtc = startTime, TargetSuspended = _targetSuspended });
                }
            }
            catch
            {
            }

            ApplyUnifiedThreadRows(BuildUnifiedThreadRows(
                rows.OrderByDescending(x => x.StartTimeUtc ?? DateTime.MinValue).Take(20), DateTime.UtcNow));
        }

        private static void NormalizeThreadKinds(List<ThreadUsageSample> threads)
        {
            if (threads.Count == 0)
            {
                return;
            }

            ThreadUsageSample? mainThread = threads.Where(static thread => thread.StartTimeUtc.HasValue)
                                                .OrderBy(static thread => thread.StartTimeUtc!.Value)
                                                .ThenBy(static thread => thread.Tid)
                                                .FirstOrDefault();

            if (mainThread != null)
            {
                mainThread.Kind = "Main Thread";
            }

            for (int i = 0; i < threads.Count; i += 1)
            {
                ThreadUsageSample thread = threads[i];
                if (ReferenceEquals(thread, mainThread))
                {
                    continue;
                }

                thread.Kind = InferThreadKind(thread.State, thread.WaitReason);
            }
        }

        private static string InferThreadKind(string state, string waitReason)
        {
            if (!string.IsNullOrWhiteSpace(waitReason))
            {
                if (waitReason.Equals("ExecutionDelay", StringComparison.OrdinalIgnoreCase) ||
                    waitReason.Equals("WrQueue", StringComparison.OrdinalIgnoreCase) ||
                    waitReason.Equals("WrLpcReceive", StringComparison.OrdinalIgnoreCase) ||
                    waitReason.Equals("WrLpcReply", StringComparison.OrdinalIgnoreCase) ||
                    waitReason.Equals("WrExecutive", StringComparison.OrdinalIgnoreCase) ||
                    waitReason.Equals("WrUserRequest", StringComparison.OrdinalIgnoreCase) ||
                    waitReason.Equals("WrKernel", StringComparison.OrdinalIgnoreCase))
                {
                    return "OS-Managed";
                }

                if (waitReason.Equals("Suspended", StringComparison.OrdinalIgnoreCase) ||
                    waitReason.Equals("UserRequest", StringComparison.OrdinalIgnoreCase))
                {
                    return "User Thread";
                }
            }

            if (state.Equals("Wait", StringComparison.OrdinalIgnoreCase) ||
                state.Equals("Transition", StringComparison.OrdinalIgnoreCase))
            {
                return "OS-Managed";
            }

            return "User Thread";
        }

        private void RefreshModules(Process process)
        {
            var rows = new List<ModuleInfoRow>();
            try
            {
                foreach (ProcessModule module in process.Modules)
                {
                    string role = ResolveModuleRole(module.FileName);
                    rows.Add(new ModuleInfoRow { Name = module.ModuleName,
                                                 BaseAddress = $"0x{module.BaseAddress.ToInt64():X}",
                                                 Size = FormatBytes(module.ModuleMemorySize), Path = module.FileName,
                                                 Role = role });
                }
            }
            catch (Exception ex)
            {
                DiagnosticsState.SetValue("Target Modules", $"Process.Modules failed: {ex.GetType().Name}");
            }

            Modules.Clear();
            foreach (var row in rows.OrderBy(r => r.Name, StringComparer.OrdinalIgnoreCase).Take(1024))
                Modules.Add(row);
            if (rows.Count > 0)
            {
                DiagnosticsState.SetValue("Target Modules", $"Loaded {rows.Count} modules");
            }
        }

        private string ResolveModuleRole(string? path)
        {
            if (!string.IsNullOrWhiteSpace(_analysisSubjectPath) &&
                string.Equals(path, _analysisSubjectPath, StringComparison.OrdinalIgnoreCase))
            {
                return "Subject";
            }

            if (!string.IsNullOrWhiteSpace(_analysisHostPath) &&
                string.Equals(path, _analysisHostPath, StringComparison.OrdinalIgnoreCase))
            {
                return "Host";
            }

            return string.Empty;
        }

        private void RefreshPeInfo(Process process)
        {
            var rows = new List<PeInfoRow>();

            rows.Add(new PeInfoRow("PID", process.Id.ToString()));
            rows.Add(new PeInfoRow("Process Name", process.ProcessName));
            try
            {
                rows.Add(new PeInfoRow("Start Time",
                                       process.StartTime.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss 'UTC'")));
            }
            catch
            {
            }
            try
            {
                rows.Add(new PeInfoRow("Priority Class", process.PriorityClass.ToString()));
            }
            catch
            {
            }

            string? imagePath = null;
            try
            {
                imagePath = process.MainModule?.FileName;
            }
            catch
            {
            }
            if (!string.IsNullOrWhiteSpace(imagePath))
            {
                rows.Add(new PeInfoRow("Image Path", imagePath));

                if (TryReadPeInfo(imagePath, out var pe))
                {
                    rows.Add(new PeInfoRow("PE Machine", pe.Machine));
                    rows.Add(new PeInfoRow("PE Type", pe.IsPePlus ? "PE32+" : "PE32"));
                    rows.Add(new PeInfoRow("Image Base", pe.ImageBase));
                    rows.Add(new PeInfoRow("Subsystem", pe.Subsystem));
                    rows.Add(new PeInfoRow("DLL Characteristics", pe.DllCharacteristics));
                }
            }

            if (TryGetMitigationFlags(process, out var mitigations))
            {
                foreach (var m in mitigations)
                    rows.Add(new PeInfoRow(m.Field, m.Value));
            }

            PeInfo.Clear();
            foreach (var row in rows)
                PeInfo.Add(row);
        }

        private static bool TryReadPeInfo(string path, out PeSummary pe)
        {
            pe = default;
            try
            {
                using var fs =
                    new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                using var br = new BinaryReader(fs);
                if (br.ReadUInt16() != 0x5A4D)
                    return false;

                fs.Position = 0x3C;
                int peOffset = br.ReadInt32();
                if (peOffset <= 0 || peOffset > fs.Length - 0x100)
                    return false;

                fs.Position = peOffset;
                if (br.ReadUInt32() != 0x00004550)
                    return false;

                ushort machine = br.ReadUInt16();
                _ = br.ReadUInt16();
                _ = br.ReadUInt32();
                _ = br.ReadUInt32();
                _ = br.ReadUInt32();
                ushort sizeOfOptionalHeader = br.ReadUInt16();
                _ = br.ReadUInt16();

                long optStart = fs.Position;
                ushort magic = br.ReadUInt16();
                bool isPePlus = magic == 0x20B;
                if (!isPePlus && magic != 0x10B)
                    return false;

                ushort subsystem;
                ushort dllChars;
                string imageBase;
                if (isPePlus)
                {
                    fs.Position = optStart + 0x18;
                    ulong imageBase64 = br.ReadUInt64();
                    fs.Position = optStart + 0x44;
                    subsystem = br.ReadUInt16();
                    dllChars = br.ReadUInt16();
                    imageBase = $"0x{imageBase64:X}";
                }
                else
                {
                    fs.Position = optStart + 0x1C;
                    uint imageBase32 = br.ReadUInt32();
                    fs.Position = optStart + 0x44;
                    subsystem = br.ReadUInt16();
                    dllChars = br.ReadUInt16();
                    imageBase = $"0x{imageBase32:X}";
                }

                pe =
                    new PeSummary { Machine = MachineToString(machine), IsPePlus = isPePlus, ImageBase = imageBase,
                                    Subsystem = SubsystemToString(subsystem), DllCharacteristics = $"0x{dllChars:X4}" };
                return true;
            }
            catch
            {
                return false;
            }
        }

        private static bool TryGetMitigationFlags(Process process, out List<PeInfoRow> rows)
        {
            rows = new List<PeInfoRow>();
            try
            {
                if (GetProcessMitigationPolicy(process.Handle, ProcessMitigationPolicy.DepPolicy,
                                               out PROCESS_MITIGATION_DEP_POLICY dep,
                                               Marshal.SizeOf<PROCESS_MITIGATION_DEP_POLICY>()))
                {
                    rows.Add(new PeInfoRow("Mitigation DEP", (dep.Flags & 0x1) != 0 ? "Enabled" : "Disabled"));
                }

                if (GetProcessMitigationPolicy(process.Handle, ProcessMitigationPolicy.AslrPolicy,
                                               out PROCESS_MITIGATION_ASLR_POLICY aslr,
                                               Marshal.SizeOf<PROCESS_MITIGATION_ASLR_POLICY>()))
                {
                    rows.Add(new PeInfoRow("Mitigation ASLR", (aslr.Flags & 0x7) != 0 ? "Enabled" : "Disabled"));
                }

                if (GetProcessMitigationPolicy(process.Handle, ProcessMitigationPolicy.ControlFlowGuardPolicy,
                                               out PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY cfg,
                                               Marshal.SizeOf<PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY>()))
                {
                    rows.Add(new PeInfoRow("Mitigation CFG", (cfg.Flags & 0x1) != 0 ? "Enabled" : "Disabled"));
                }

                if (GetProcessMitigationPolicy(process.Handle, ProcessMitigationPolicy.DynamicCodePolicy,
                                               out PROCESS_MITIGATION_DYNAMIC_CODE_POLICY dyn,
                                               Marshal.SizeOf<PROCESS_MITIGATION_DYNAMIC_CODE_POLICY>()))
                {
                    rows.Add(
                        new PeInfoRow("Mitigation DynamicCode", (dyn.Flags & 0x1) != 0 ? "Prohibited" : "Allowed"));
                }

                return rows.Count > 0;
            }
            catch
            {
                return false;
            }
        }

        private static string MachineToString(ushort machine)
        {
            return machine switch {
                0x014C => "x86",
                0x8664 => "x64",
                0xAA64 => "ARM64",
                _ => $"0x{machine:X4}"
            };
        }

        private static string SubsystemToString(ushort subsystem)
        {
            return subsystem switch {
                2 => "Windows GUI",
                3 => "Windows CUI",
                _ => subsystem.ToString()
            };
        }

        private void RefreshMemoryMetrics(Process process)
        {
            var rows = new List<MemoryMetricRow> {
                new() { Metric = "Working Set", Value = FormatBytes(process.WorkingSet64),
                        BytesValue = process.WorkingSet64 },
                new() { Metric = "Peak Working Set", Value = FormatBytes(process.PeakWorkingSet64),
                        BytesValue = process.PeakWorkingSet64 },
                new() { Metric = "Private Bytes", Value = FormatBytes(process.PrivateMemorySize64),
                        BytesValue = process.PrivateMemorySize64 },
                new() { Metric = "Virtual Bytes", Value = FormatBytes(process.VirtualMemorySize64), BytesValue = null },
                new() { Metric = "Paged Memory", Value = FormatBytes(process.PagedMemorySize64),
                        BytesValue = process.PagedMemorySize64 },
                new() { Metric = "Nonpaged System Memory", Value = FormatBytes(process.NonpagedSystemMemorySize64),
                        BytesValue = process.NonpagedSystemMemorySize64 },
                new() { Metric = "Paged System Memory", Value = FormatBytes(process.PagedSystemMemorySize64),
                        BytesValue = process.PagedSystemMemorySize64 },
                new() { Metric = "Handle Count", Value = process.HandleCount.ToString(), BytesValue = null },
                new() { Metric = "Thread Count", Value = process.Threads.Count.ToString(), BytesValue = null }
            };

            MemoryMetrics.Clear();
            foreach (var row in rows)
                MemoryMetrics.Add(row);

            try
            {
                List<MemoryPageSample> pages = CaptureLiveMemoryPages(process);
                RebuildMemoryAttributionRows(pages, DateTime.UtcNow);
            }
            catch
            {
                MemoryAttributionRows.Clear();
            }

            UpdateMemoryTreemap();
            UpdateLiveDataOverlays();
        }
    }
}
