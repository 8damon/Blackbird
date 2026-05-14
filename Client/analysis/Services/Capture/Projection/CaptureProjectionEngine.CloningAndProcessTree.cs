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
        private static PerformanceSample ClonePerformanceSample(PerformanceSample src) => new() {
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
                              .Select(m => new MemoryPageSample { BaseAddress = m.BaseAddress,
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
                                                                  WorkingSetLargePage = m.WorkingSetLargePage })
                              .ToList()
        };

        private static ThreadLifecycleEventSample
        CloneThreadLifecycleEvent(ThreadLifecycleEventSample src) => new() { TimestampUtc = src.TimestampUtc,
                                                                             ProcessPid = src.ProcessPid,
                                                                             ThreadId = src.ThreadId,
                                                                             CreatorPid = src.CreatorPid,
                                                                             Flags = src.Flags,
                                                                             StartAddress = src.StartAddress,
                                                                             ImageBase = src.ImageBase,
                                                                             ImageSize = src.ImageSize,
                                                                             EventKind = src.EventKind,
                                                                             Notes = src.Notes };

        private static MemoryRegionAttributionSample CloneMemoryRegionAttributionSample(
            MemoryRegionAttributionSample src) => new() { TimestampUtc = src.TimestampUtc,
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

        private static class ProcessTreeSnapshot
        {
            private const uint TH32CS_SNAPPROCESS = 0x00000002;
            private static readonly IntPtr InvalidHandleValue = new(-1);

            internal static int[] DiscoverDescendants(int[] roots)
            {
                HashSet<int> rootSet = roots.Where(static processId => processId > 0).ToHashSet();
                if (rootSet.Count == 0)
                {
                    return Array.Empty<int>();
                }

                Dictionary<int, int> parentByPid = SnapshotParents();
                if (parentByPid.Count == 0)
                {
                    return Array.Empty<int>();
                }

                var descendants = new HashSet<int>();
                bool changed;
                do
                {
                    changed = false;
                    foreach ((int processId, int parentPid) in parentByPid)
                    {
                        if (processId <= 0 || rootSet.Contains(processId) || descendants.Contains(processId))
                        {
                            continue;
                        }

                        if (rootSet.Contains(parentPid) || descendants.Contains(parentPid))
                        {
                            descendants.Add(processId);
                            changed = true;
                        }
                    }
                } while (changed);

                return descendants.OrderBy(static processId => processId).ToArray();
            }

            private static Dictionary<int, int> SnapshotParents()
            {
                IntPtr snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
                if (snapshot == IntPtr.Zero || snapshot == InvalidHandleValue)
                {
                    return new Dictionary<int, int>();
                }

                try
                {
                    var entry = new PROCESSENTRY32 { dwSize = (uint)Marshal.SizeOf<PROCESSENTRY32>() };
                    var parents = new Dictionary<int, int>();
                    if (!Process32FirstW(snapshot, ref entry))
                    {
                        return parents;
                    }

                    do
                    {
                        if (entry.th32ProcessID <= int.MaxValue && entry.th32ParentProcessID <= int.MaxValue)
                        {
                            parents[unchecked((int)entry.th32ProcessID)] = unchecked((int)entry.th32ParentProcessID);
                        }
                    } while (Process32NextW(snapshot, ref entry));

                    return parents;
                }
                finally
                {
                    _ = CloseHandle(snapshot);
                }
            }

            [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
            private struct PROCESSENTRY32
            {
                internal uint dwSize;
                internal uint cntUsage;
                internal uint th32ProcessID;
                internal IntPtr th32DefaultHeapID;
                internal uint th32ModuleID;
                internal uint cntThreads;
                internal uint th32ParentProcessID;
                internal int pcPriClassBase;
                internal uint dwFlags;
                [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
                internal string szExeFile;
            }

            [DllImport("kernel32.dll", SetLastError = true)]
            private static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

            [DllImport("kernel32.dll", SetLastError = true)]
            [return:MarshalAs(UnmanagedType.Bool)]
            private static extern bool Process32FirstW(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

            [DllImport("kernel32.dll", SetLastError = true)]
            [return:MarshalAs(UnmanagedType.Bool)]
            private static extern bool Process32NextW(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

            [DllImport("kernel32.dll", SetLastError = true)]
            [return:MarshalAs(UnmanagedType.Bool)]
            private static extern bool CloseHandle(IntPtr hObject);
        }
    }
}
