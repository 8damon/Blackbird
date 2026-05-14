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
        private List<ThreadUsageRow> BuildUnifiedThreadRows(IEnumerable<ThreadUsageSample> topThreads,
                                                            DateTime cutoffUtc)
        {
            var normalizedThreads = topThreads.Take(20).Select(CloneThreadUsage).ToList();
            NormalizeThreadKinds(normalizedThreads);

            var rows =
                normalizedThreads.Take(20).Select(thread => new ThreadUsageRow(thread, _targetSuspended)).ToList();
            var seen = new HashSet<uint>(rows.Select(x => unchecked((uint)x.Tid)));

            Dictionary<uint, ThreadLifecycleEventSample> latestByTid = BuildLatestThreadLifecycleMap(cutoffUtc);
            foreach (ThreadLifecycleEventSample sample in latestByTid.Values.OrderByDescending(x => x.TimestampUtc)
                         .Take(20))
            {
                if (sample.ThreadId == 0 || seen.Contains(sample.ThreadId))
                {
                    continue;
                }

                string state = _targetSuspended                                                       ? "Suspended"
                               : sample.EventKind.Equals("Start", StringComparison.OrdinalIgnoreCase) ? "Started"
                                                                                                      : "Observed";
                string kind =
                    string.IsNullOrWhiteSpace(sample.EventKind) ? "Lifecycle" : $"Lifecycle/{sample.EventKind}";

                rows.Add(new ThreadUsageRow(
                    new ThreadUsageSample { Tid = unchecked((int)sample.ThreadId), CpuMsDelta = 0, State = state,
                                            WaitReason = _targetSuspended ? "Suspended" : string.Empty, Kind = kind,
                                            StartTimeUtc = sample.TimestampUtc, TargetSuspended = _targetSuspended },
                    _targetSuspended));
                seen.Add(sample.ThreadId);
            }

            var sorted = rows.OrderByDescending(x => x.CpuMs)
                             .ThenByDescending(x => x.StartTimeUtc ?? DateTime.MinValue)
                             .ThenBy(x => x.Tid)
                             .Take(24)
                             .ToList();

            int mainIdx = sorted.FindIndex(x => x.ThreadKind == "Main Thread");
            if (mainIdx > 0)
            {
                var main = sorted[mainIdx];
                sorted.RemoveAt(mainIdx);
                sorted.Insert(0, main);
            }

            return sorted;
        }

        private Dictionary<uint, ThreadLifecycleEventSample> BuildLatestThreadLifecycleMap(DateTime cutoffUtc)
        {
            var latestByTid = new Dictionary<uint, ThreadLifecycleEventSample>();
            foreach (ThreadLifecycleEventSample sample in _threadLifecycleHistory)
            {
                if (sample.TimestampUtc > cutoffUtc || sample.ThreadId == 0)
                {
                    continue;
                }

                if (sample.EventKind.Equals("Exit", StringComparison.OrdinalIgnoreCase))
                {
                    latestByTid.Remove(sample.ThreadId);
                    continue;
                }

                latestByTid[sample.ThreadId] = sample;
            }

            return latestByTid;
        }

        private void ApplyUnifiedThreadRows(IReadOnlyList<ThreadUsageRow> rows)
        {
            TopThreads.Clear();
            if (rows.Count == 0)
            {
                CoreUsageRows.Clear();
            }

            foreach (ThreadUsageRow row in rows)
            {
                TopThreads.Add(row);
            }
        }

        private void ApplyCoreUsageRows(IReadOnlyList<CoreUsageSample> cores, int coreCount)
        {
            CoreUsageRows.Clear();
            int count = Math.Max(coreCount, cores.Count);
            if (count <= 0)
            {
                return;
            }

            Dictionary<int, CoreUsageSample> byCore = cores.ToDictionary(x => x.CoreIndex, x => x);
            for (int i = 0; i < count; i += 1)
            {
                byCore.TryGetValue(i, out CoreUsageSample? sample);
                CoreUsageRows.Add(new CoreUsageRow(sample, i));
            }
        }

        private static string DetermineMemoryPriorityBand(MemoryPageSample page, string trust)
        {
            if (page.Sr71Owned)
            {
                return "Image";
            }

            bool isPrivate = (page.Type & 0x00020000u) != 0;
            bool isMapped = (page.Type & 0x00040000u) != 0;
            bool isImage = (page.Type & 0x01000000u) != 0;
            bool hasImageBacking = !string.IsNullOrWhiteSpace(page.ModulePath) || LooksLikeImagePath(page.BackingPath);
            bool isUnsigned = string.Equals(trust, "Unsigned", StringComparison.OrdinalIgnoreCase);
            bool isExecutable = IsExecutableProtect(page.Protect);
            bool isWritable = IsWritableProtect(page.Protect);

            if (isPrivate && isUnsigned)
            {
                return "PrivateUnsigned";
            }
            if (isPrivate && isExecutable && isWritable)
            {
                return "PrivateExecutable";
            }
            if (isPrivate)
            {
                return "Private";
            }
            if (isUnsigned)
            {
                return "Unsigned";
            }
            if (isImage || hasImageBacking)
            {
                return "Image";
            }
            if (isMapped)
            {
                return "Mapped";
            }

            return "Normal";
        }

        private static string DetermineMemoryPriorityBand(MemoryPageSample page, string trust,
                                                          MemoryRegionAttributionSample? attribution)
        {
            if (IsSr71OwnedMemoryPage(page, attribution))
            {
                return "Image";
            }

            if (attribution != null)
            {
                if (attribution.CrossProcess &&
                    (attribution.WriteCount != 0 || attribution.ProtectCount != 0 || attribution.ThreadStartCount != 0))
                {
                    return "PrivateUnsigned";
                }
                if (attribution.FirstExecutableTransition || attribution.ThreadStartCount != 0)
                {
                    return "PrivateExecutable";
                }
                if (attribution.ProtectFlipCount >= 3 || attribution.RapidProtectFlipCount >= 2 ||
                    attribution.GuardNoAccessFlipCount != 0 || attribution.WritableExecutableFlipCount != 0)
                {
                    return "PrivateExecutable";
                }
                if (attribution.HighEntropyWriteCount != 0 || attribution.EntropyFlipCount >= 2)
                {
                    return "Unsigned";
                }
                if (attribution.WriteCount != 0 && attribution.ImageBacked)
                {
                    return "Unsigned";
                }
            }

            return DetermineMemoryPriorityBand(page, trust);
        }

        private static string DetermineMemoryPriorityBand(MemoryPageSample page, string trust,
                                                          MemoryRegionAttributionSample? attribution,
                                                          ThreadExecutionMemoryHeuristic? threadHeuristic)
        {
            string band = DetermineMemoryPriorityBand(page, trust, attribution);
            if (threadHeuristic != null && (band.Equals("Private", StringComparison.OrdinalIgnoreCase) ||
                                            band.Equals("Mapped", StringComparison.OrdinalIgnoreCase) ||
                                            band.Equals("Normal", StringComparison.OrdinalIgnoreCase)))
            {
                return "PrivateExecutable";
            }

            return band;
        }

        private static bool LooksLikeImagePath(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                return false;
            }

            string extension = Path.GetExtension(path);
            return extension.Equals(".dll", StringComparison.OrdinalIgnoreCase) ||
                   extension.Equals(".exe", StringComparison.OrdinalIgnoreCase) ||
                   extension.Equals(".mui", StringComparison.OrdinalIgnoreCase) ||
                   extension.Equals(".cpl", StringComparison.OrdinalIgnoreCase) ||
                   extension.Equals(".drv", StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsExecutableProtect(uint protect)
        {
            uint baseProtect = protect & 0xFFu;
            return baseProtect == 0x10 || baseProtect == 0x20 || baseProtect == 0x40 || baseProtect == 0x80;
        }

        private static bool IsWritableProtect(uint protect)
        {
            uint baseProtect = protect & 0xFFu;
            return baseProtect == 0x04 || baseProtect == 0x08 || baseProtect == 0x40 || baseProtect == 0x80;
        }

        private static int MemoryPriorityBandRank(string priorityBand)
        {
            return priorityBand switch { "PrivateUnsigned" => 0,
                                         "PrivateExecutable" => 1,
                                         "Private" => 2,
                                         "Unsigned" => 3,
                                         "Image" => 4,
                                         "Mapped" => 5,
                                         _ => 6 };
        }

        private static PerformanceSample CloneSample(PerformanceSample src)
        {
            return new PerformanceSample {
                TimestampUtc = src.TimestampUtc,
                CoreCount = src.CoreCount,
                CpuPercent = src.CpuPercent,
                CoresUsedPercent = src.CoresUsedPercent,
                DiskReadBytesPerSec = src.DiskReadBytesPerSec,
                DiskWriteBytesPerSec = src.DiskWriteBytesPerSec,
                PrivateBytes = src.PrivateBytes,
                ReservedBytes = src.ReservedBytes,
                CommitBytes = src.CommitBytes,
                ImageBytes = src.ImageBytes,
                MappedBytes = src.MappedBytes,
                PrivateVadBytes = src.PrivateVadBytes,
                NetInBytesPerSec = src.NetInBytesPerSec,
                NetOutBytesPerSec = src.NetOutBytesPerSec,
                NetPacketsPerSec = src.NetPacketsPerSec,
                TopThreads = src.TopThreads
                                 .Select(t => new ThreadUsageSample { Tid = t.Tid, CpuMsDelta = t.CpuMsDelta,
                                                                      State = t.State, WaitReason = t.WaitReason,
                                                                      Kind = t.Kind, StartTimeUtc = t.StartTimeUtc,
                                                                      TargetSuspended = t.TargetSuspended })
                                 .ToList(),
                CoreUsage = src.CoreUsage
                                .Select(c => new CoreUsageSample { CoreIndex = c.CoreIndex, BusyPercent = c.BusyPercent,
                                                                   DominantTid = c.DominantTid,
                                                                   DominantThreadKind = c.DominantThreadKind,
                                                                   DominantThreadCpuMs = c.DominantThreadCpuMs,
                                                                   ThreadCount = c.ThreadCount })
                                .ToList(),
                MemoryMetrics = src.MemoryMetrics
                                    .Select(m => new MemoryMetricSample { Metric = m.Metric, Value = m.Value,
                                                                          BytesValue = m.BytesValue })
                                    .ToList(),
                MemoryPages = src.MemoryPages
                                  .Select(m => new MemoryPageSample {
                                      BaseAddress = m.BaseAddress,
                                      AllocationBase = m.AllocationBase,
                                      RegionSize = m.RegionSize,
                                      State = m.State,
                                      Protect = m.Protect,
                                      AllocationProtect = m.AllocationProtect,
                                      Type = m.Type,
                                      StateLabel = m.StateLabel,
                                      ProtectLabel = m.ProtectLabel,
                                      TypeLabel = m.TypeLabel,
                                      Category = m.Category,
                                      SpecialUse = m.SpecialUse,
                                      BackingPath = m.BackingPath,
                                      ModulePath = m.ModulePath,
                                      Sr71Owned = m.Sr71Owned,
                                      Sr71OwnerTag = m.Sr71OwnerTag,
                                      WorkingSetValid = m.WorkingSetValid,
                                      WorkingSetShared = m.WorkingSetShared,
                                      WorkingSetShareCount = m.WorkingSetShareCount,
                                      WorkingSetLocked = m.WorkingSetLocked,
                                      WorkingSetLargePage = m.WorkingSetLargePage,
                                  })
                                  .ToList()
            };
        }

        private static string DescribeCallsiteOwnership(string? moduleName, string? originPath)
        {
            string module = !string.IsNullOrWhiteSpace(moduleName)
                                ? moduleName.Trim()
                                : EventDetailFormatting.ModuleNameFromPath(originPath ?? string.Empty);
            if (string.IsNullOrWhiteSpace(module))
            {
                return string.Empty;
            }

            string lowered = module.ToLowerInvariant();
            if (lowered is "ucrtbase.dll" or "msvcrt.dll" or "vcruntime140.dll" or "vcruntime140_1.dll" or
                           "concrt140.dll")
            {
                return "CRT/Runtime";
            }

            if (lowered is "ntdll.dll" or "kernel32.dll" or "kernelbase.dll" or "rpcrt4.dll" or "user32.dll" or
                           "gdi32.dll" or "advapi32.dll")
            {
                return "Windows OS";
            }

            if (lowered.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            {
                return "Process Code";
            }

            return module;
        }

        private static MemoryRegionAttributionSample
        CloneMemoryRegionAttributionSample(MemoryRegionAttributionSample src)
        {
            return new MemoryRegionAttributionSample { TimestampUtc = src.TimestampUtc,
                                                       ProcessStartKey = src.ProcessStartKey,
                                                       TargetPid = src.TargetPid,
                                                       ActorPid = src.ActorPid,
                                                       ActorTid = src.ActorTid,
                                                       AllocationBase = src.AllocationBase,
                                                       BaseAddress = src.BaseAddress,
                                                       RegionSize = src.RegionSize,
                                                       ApiName = src.ApiName,
                                                       EventKind = src.EventKind,
                                                       RegionKind = src.RegionKind,
                                                       RegionIdentity = src.RegionIdentity,
                                                       OriginPath = src.OriginPath,
                                                       SourceFamily = src.SourceFamily,
                                                       ExecutionContext = src.ExecutionContext,
                                                       CallerOrigin = src.CallerOrigin,
                                                       FirstUserFrame = src.FirstUserFrame,
                                                       FirstUserFrameModule = src.FirstUserFrameModule,
                                                       FrameSummary = src.FrameSummary,
                                                       UnwindClean = src.UnwindClean,
                                                       FrameChainHadGaps = src.FrameChainHadGaps,
                                                       ObservedByKernel = src.ObservedByKernel,
                                                       ObservedByUserHook = src.ObservedByUserHook,
                                                       BlackbirdOwned = src.BlackbirdOwned,
                                                       CrossProcess = src.CrossProcess,
                                                       ImageBacked = src.ImageBacked,
                                                       InitialProtection = src.InitialProtection,
                                                       CurrentProtection = src.CurrentProtection,
                                                       PreviousProtection = src.PreviousProtection,
                                                       FirstExecutableTransition = src.FirstExecutableTransition,
                                                       MapCount = src.MapCount,
                                                       WriteCount = src.WriteCount,
                                                       ProtectCount = src.ProtectCount,
                                                       ThreadStartCount = src.ThreadStartCount,
                                                       ProtectFlipCount = src.ProtectFlipCount,
                                                       RapidProtectFlipCount = src.RapidProtectFlipCount,
                                                       ExecutableFlipCount = src.ExecutableFlipCount,
                                                       GuardNoAccessFlipCount = src.GuardNoAccessFlipCount,
                                                       WritableExecutableFlipCount = src.WritableExecutableFlipCount,
                                                       ProtectionTransition = src.ProtectionTransition,
                                                       EntropyBits = src.EntropyBits,
                                                       MaxEntropyBits = src.MaxEntropyBits,
                                                       EntropyFlipCount = src.EntropyFlipCount,
                                                       RapidEntropyFlipCount = src.RapidEntropyFlipCount,
                                                       HighEntropyWriteCount = src.HighEntropyWriteCount,
                                                       SampleBytes = src.SampleBytes,
                                                       LifecycleSummary = src.LifecycleSummary,
                                                       ThreadStartObserved = src.ThreadStartObserved,
                                                       ThreadId = src.ThreadId,
                                                       ThreadStartAddress = src.ThreadStartAddress,
                                                       FunctionTableRegistered = src.FunctionTableRegistered,
                                                       FunctionTablePointer = src.FunctionTablePointer,
                                                       SignatureLevel = src.SignatureLevel,
                                                       SignatureType = src.SignatureType };
        }

        private static ThreadLifecycleEventSample CloneThreadLifecycleEvent(ThreadLifecycleEventSample src)
        {
            return new ThreadLifecycleEventSample { TimestampUtc = src.TimestampUtc,
                                                    ProcessPid = src.ProcessPid,
                                                    ThreadId = src.ThreadId,
                                                    CreatorPid = src.CreatorPid,
                                                    Flags = src.Flags,
                                                    StartAddress = src.StartAddress,
                                                    ImageBase = src.ImageBase,
                                                    ImageSize = src.ImageSize,
                                                    EventKind = src.EventKind,
                                                    Notes = src.Notes };
        }
    }
}
