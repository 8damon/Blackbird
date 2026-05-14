using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Threading;

namespace BlackbirdInterface
{
    [SupportedOSPlatform("windows")]
    public sealed class PerformanceSampler
    {
        public event EventHandler<PerformanceSample>? SampleArrived;

        private Timer? _timer;
        private readonly object _lock = new();
        private int _tickActive;

        private int _targetPid = Process.GetCurrentProcess().Id;
        private DateTime _lastWall;
        private TimeSpan _lastProcCpu;
        private ulong _lastIoRead;
        private ulong _lastIoWrite;
        private ulong _lastIoOther;
        private int _lastIoPid;
        private bool _lastIoValid;

        private PerformanceCounter? _cpuTotal;

        private PerformanceCounter? _diskRead;
        private PerformanceCounter? _diskWrite;

        private long _lastBytesIn;
        private long _lastBytesOut;
        private long _lastPackets;

        private readonly Dictionary<int, TimeSpan> _threadCpuBaseline = new();
        private DateTime _lastMemorySnapshotUtc;
        private readonly List<MemoryMetricSample> _cachedMemoryMetrics = new();
        private readonly List<MemoryPageSample> _cachedMemoryPages = new();

        public PerformanceSampler()
        {
            TryInitCounters();
        }

        public void Start()
        {
            _lastWall = DateTime.UtcNow;
            _lastProcCpu = TimeSpan.Zero;
            PrimeNetwork();
            Tick();
            lock (_lock)
            {
                _timer?.Dispose();
                _timer = new Timer(
                    _ => Tick(), null, TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(1));
            }
        }

        public void ResetBaselines()
        {
            lock (_lock)
            {
                _lastWall = DateTime.UtcNow;
                _lastProcCpu = TimeSpan.Zero;
                _lastIoValid = false;
                _lastMemorySnapshotUtc = DateTime.MinValue;
                _threadCpuBaseline.Clear();
            }

            PrimeNetwork();
        }

        public void RequestImmediateSample()
        {
            Tick();
        }

        public void Stop()
        {
            lock (_lock)
            {
                _timer?.Dispose();
                _timer = null;
            }
        }

        public void SetTargetPid(int pid)
        {
            lock (_lock)
            {
                if (_targetPid == pid)
                    return;

                _targetPid = pid;
                _lastProcCpu = TimeSpan.Zero;
                _threadCpuBaseline.Clear();
                _lastIoValid = false;
                _cachedMemoryMetrics.Clear();
                _cachedMemoryPages.Clear();
                _lastMemorySnapshotUtc = DateTime.MinValue;
            }
        }

        private void TryInitCounters()
        {
            try
            {
                _cpuTotal = new PerformanceCounter("Processor", "% Processor Time", "_Total");
                _ = _cpuTotal.NextValue();
            }
            catch
            {
                _cpuTotal = null;
            }
            try
            {
                _diskRead = new PerformanceCounter("PhysicalDisk", "Disk Read Bytes/sec", "_Total");
                _ = _diskRead.NextValue();
            }
            catch
            {
                _diskRead = null;
            }
            try
            {
                _diskWrite = new PerformanceCounter("PhysicalDisk", "Disk Write Bytes/sec", "_Total");
                _ = _diskWrite.NextValue();
            }
            catch
            {
                _diskWrite = null;
            }
        }

        private void PrimeNetwork()
        {
            var (bin, bout, pk) = ReadNetworkTotals();
            _lastBytesIn = bin;
            _lastBytesOut = bout;
            _lastPackets = pk;
        }

        private void Tick()
        {
            if (Interlocked.Exchange(ref _tickActive, 1) != 0)
            {
                return;
            }
            try
            {
                int pid;
                lock (_lock) pid = _targetPid;

                if (pid <= 0)
                    return;

                var now = DateTime.UtcNow;
                var wallDelta = now - _lastWall;
                if (wallDelta.TotalMilliseconds <= 0)
                    wallDelta = TimeSpan.FromMilliseconds(1000);

                var sample = new PerformanceSample { TimestampUtc = now, CoreCount = Environment.ProcessorCount };

                _lastWall = now;
                if (!FillProcess(sample, pid, wallDelta))
                    return;

                SampleArrived?.Invoke(this, sample);
            }
            finally
            {
                Interlocked.Exchange(ref _tickActive, 0);
            }
        }

        private void FillSystem(PerformanceSample s, TimeSpan wallDelta)
        {
            if (_cpuTotal != null)
            {
                try
                {
                    s.CpuPercent = Clamp(_cpuTotal.NextValue(), 0, 100);
                }
                catch
                {
                    s.CpuPercent = 0;
                }
            }

            s.CoresUsedPercent = s.CpuPercent;

            if (_diskRead != null)
            {
                try
                {
                    s.DiskReadBytesPerSec = Math.Max(0, _diskRead.NextValue());
                }
                catch
                {
                }
            }
            if (_diskWrite != null)
            {
                try
                {
                    s.DiskWriteBytesPerSec = Math.Max(0, _diskWrite.NextValue());
                }
                catch
                {
                }
            }

            try
            {
                s.PrivateBytes = GC.GetTotalMemory(false);
                s.ReservedBytes = s.PrivateBytes * 2;
            }
            catch
            {
            }

            var (bin, bout, pk) = ReadNetworkTotals();
            var sec = Math.Max(0.25, wallDelta.TotalSeconds);

            s.NetInBytesPerSec = Math.Max(0, (bin - _lastBytesIn) / sec);
            s.NetOutBytesPerSec = Math.Max(0, (bout - _lastBytesOut) / sec);
            s.NetPacketsPerSec = Math.Max(0, (pk - _lastPackets) / sec);

            _lastBytesIn = bin;
            _lastBytesOut = bout;
            _lastPackets = pk;

            FillTopThreadsForProcess(s, Process.GetCurrentProcess(), wallDelta);
        }

        private bool FillProcess(PerformanceSample s, int pid, TimeSpan wallDelta)
        {
            Process? p = null;
            try
            {
                p = Process.GetProcessById(pid);
            }
            catch
            {
                return false;
            }

            try
            {
                var procCpu = p.TotalProcessorTime;

                if (_lastProcCpu == TimeSpan.Zero)
                    _lastProcCpu = procCpu;

                var cpuDelta = procCpu - _lastProcCpu;
                _lastProcCpu = procCpu;

                var sec = Math.Max(0.25, wallDelta.TotalSeconds);
                var cpuPct = (cpuDelta.TotalSeconds / sec) / Environment.ProcessorCount * 100.0;
                s.CpuPercent = Clamp(cpuPct, 0, 100);

                s.CoresUsedPercent = s.CpuPercent;

                s.PrivateBytes = p.PrivateMemorySize64;
                s.ReservedBytes = p.VirtualMemorySize64;

                var sec2 = Math.Max(0.25, wallDelta.TotalSeconds);
                if (TryReadIoCounters(p, out var io))
                {
                    if (!_lastIoValid || _lastIoPid != pid)
                    {
                        _lastIoRead = io.ReadTransferCount;
                        _lastIoWrite = io.WriteTransferCount;
                        _lastIoOther = io.OtherTransferCount;
                        _lastIoPid = pid;
                        _lastIoValid = true;
                    }
                    else
                    {
                        var readDelta = io.ReadTransferCount - _lastIoRead;
                        var writeDelta = io.WriteTransferCount - _lastIoWrite;
                        s.DiskReadBytesPerSec = Math.Max(0, readDelta / sec2);
                        s.DiskWriteBytesPerSec = Math.Max(0, writeDelta / sec2);
                        s.NetInBytesPerSec = 0;
                        s.NetOutBytesPerSec = 0;
                        s.NetPacketsPerSec = 0;

                        _lastIoRead = io.ReadTransferCount;
                        _lastIoWrite = io.WriteTransferCount;
                        _lastIoOther = io.OtherTransferCount;
                    }
                }

                FillTopThreadsForProcess(s, p, wallDelta);
                FillMemorySnapshot(s, p, s.TimestampUtc == default ? DateTime.UtcNow : s.TimestampUtc);
                return true;
            }
            catch
            {
                return false;
            }
            finally
            {
                try
                {
                    p?.Dispose();
                }
                catch
                {
                }
            }
        }

        private void FillTopThreadsForProcess(PerformanceSample s, Process p, TimeSpan wallDelta)
        {
            var list = new List<ThreadUsageSample>();
            try
            {
                foreach (ProcessThread t in p.Threads)
                {
                    TimeSpan cpu;
                    try
                    {
                        cpu = t.TotalProcessorTime;
                    }
                    catch
                    {
                        continue;
                    }

                    string state = t.ThreadState.ToString();
                    string waitReason = "";
                    if (t.ThreadState == System.Diagnostics.ThreadState.Wait)
                    {
                        try
                        {
                            waitReason = t.WaitReason.ToString();
                        }
                        catch
                        {
                            waitReason = "";
                        }
                    }

                    double deltaMs = 0;
                    if (_threadCpuBaseline.TryGetValue(t.Id, out var prev))
                    {
                        deltaMs = (cpu - prev).TotalMilliseconds;
                        _threadCpuBaseline[t.Id] = cpu;
                    }
                    else
                    {
                        _threadCpuBaseline[t.Id] = cpu;
                        deltaMs = 0;
                    }

                    list.Add(new ThreadUsageSample { Tid = t.Id, CpuMsDelta = Math.Max(0, deltaMs), State = state,
                                                     WaitReason = waitReason, Kind = InferThreadRole(state, waitReason),
                                                     StartTimeUtc = SafeThreadStart(t), TargetSuspended = false });
                }
            }
            catch
            {
            }

            NormalizeThreadKinds(list);
            s.CoreUsage = BuildCoreUsage(list, Math.Max(1, s.CoreCount), wallDelta);
            s.TopThreads = list.OrderByDescending(x => x.CpuMsDelta).Take(20).ToList();
        }

        private static List<CoreUsageSample> BuildCoreUsage(IReadOnlyList<ThreadUsageSample> threads, int coreCount,
                                                            TimeSpan wallDelta)
        {
            var cores = new List<CoreUsageSample>(coreCount);
            var buckets = new List<ThreadUsageSample>[coreCount];
            for (int i = 0; i < coreCount; i += 1)
            {
                buckets[i] = new List<ThreadUsageSample>();
            }

            foreach (ThreadUsageSample thread in threads)
            {
                uint tidHash = unchecked((uint)thread.Tid);
                int core = (int)(tidHash % (uint)coreCount);
                buckets[core].Add(thread);
            }

            double intervalMs = Math.Max(250.0, wallDelta.TotalMilliseconds);
            for (int i = 0; i < coreCount; i += 1)
            {
                List<ThreadUsageSample> bucket = buckets[i];
                double totalMs = bucket.Sum(x => Math.Max(0.0, x.CpuMsDelta));
                ThreadUsageSample? dominant = bucket.OrderByDescending(x => x.CpuMsDelta).FirstOrDefault();

                cores.Add(new CoreUsageSample {
                    CoreIndex = i, BusyPercent = Clamp((totalMs / intervalMs) * 100.0, 0, 100),
                    DominantTid = dominant?.Tid ?? 0, DominantThreadKind = dominant?.Kind ?? string.Empty,
                    DominantThreadCpuMs = dominant?.CpuMsDelta ?? 0.0, ThreadCount = bucket.Count
                });
            }

            return cores;
        }

        private void FillMemorySnapshot(PerformanceSample s, Process process, DateTime nowUtc)
        {
            bool refresh = _cachedMemoryMetrics.Count == 0 || _cachedMemoryPages.Count == 0 ||
                           (nowUtc - _lastMemorySnapshotUtc).TotalSeconds >= 3.0;
            if (refresh)
            {
                var metrics = BuildMemoryMetricSnapshot(process);
                var pages = CaptureMemoryPages(process);

                _cachedMemoryMetrics.Clear();
                _cachedMemoryMetrics.AddRange(metrics.Select(CloneMetric));
                _cachedMemoryPages.Clear();
                _cachedMemoryPages.AddRange(pages.Select(ClonePage));
                _lastMemorySnapshotUtc = nowUtc;
            }

            s.MemoryMetrics = _cachedMemoryMetrics.Select(CloneMetric).ToList();
            s.MemoryPages = _cachedMemoryPages.Select(ClonePage).ToList();
            PopulateMemoryBreakdown(s, _cachedMemoryPages);
        }

        private static void PopulateMemoryBreakdown(PerformanceSample sample, IReadOnlyList<MemoryPageSample> pages)
        {
            ulong commit = 0;
            ulong image = 0;
            ulong mapped = 0;
            ulong privateVad = 0;

            for (int i = 0; i < pages.Count; i += 1)
            {
                MemoryPageSample page = pages[i];
                commit += page.RegionSize;
                switch (page.Type)
                {
                case 0x1000000:
                    image += page.RegionSize;
                    break;
                case 0x40000:
                    mapped += page.RegionSize;
                    break;
                case 0x20000:
                    privateVad += page.RegionSize;
                    break;
                }
            }

            sample.CommitBytes = commit;
            sample.ImageBytes = image;
            sample.MappedBytes = mapped;
            sample.PrivateVadBytes = privateVad;
        }

        private static List<MemoryMetricSample> BuildMemoryMetricSnapshot(Process process)
        {
            var rows = new List<MemoryMetricSample> {
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
                        BytesValue = process.PagedSystemMemorySize64 }
            };

            try
            {
                rows.Add(new MemoryMetricSample { Metric = "Handle Count", Value = process.HandleCount.ToString(),
                                                  BytesValue = null });
            }
            catch
            {
            }

            try
            {
                rows.Add(new MemoryMetricSample { Metric = "Thread Count", Value = process.Threads.Count.ToString(),
                                                  BytesValue = null });
            }
            catch
            {
            }

            return rows;
        }

        private static List<MemoryPageSample> CaptureMemoryPages(Process process)
        {
            const uint processQuery = 0x0400;
            const uint processVmRead = 0x0010;
            const uint processQueryLimited = 0x1000;
            const uint memCommit = 0x1000;

            _ = Kernel32Native.EnableDebugPrivilege(out _);

            var rows = new List<MemoryPageSample>(768);
            List<MemoryModuleMapEntry> modules = CaptureModuleMap(process);
            IntPtr handle = Kernel32Native.OpenProcess(processQuery | processVmRead | processQueryLimited, false,
                                                       unchecked((uint)process.Id));
            if (handle == IntPtr.Zero)
            {
                DiagnosticsState.SetValue("Target Memory",
                                          $"OpenProcess VM_READ failed win32={Marshal.GetLastWin32Error()}");
                return rows;
            }

            List<MemoryAnchor> anchors = CaptureMemoryAnchors(process, handle);
            try
            {
                ulong address = 0;
                ulong maxAddress = Environment.Is64BitProcess ? 0x00007FFF_FFFFFFFFul : uint.MaxValue;
                nuint infoSize = (nuint)Marshal.SizeOf<MEMORY_BASIC_INFORMATION>();
                var mappedPathCache = new Dictionary<ulong, string>();

                while (address < maxAddress && rows.Count < 1536)
                {
                    nuint result = VirtualQueryEx(handle, (nint)address, out MEMORY_BASIC_INFORMATION info, infoSize);
                    if (result == 0)
                    {
                        break;
                    }

                    ulong regionSize = (ulong)info.RegionSize;
                    if (regionSize == 0)
                    {
                        break;
                    }

                    if (info.State == memCommit)
                    {
                        string stateLabel = EventDetailFormatting.DescribeMemoryState(info.State);
                        string protectLabel = EventDetailFormatting.DescribeMemoryProtection(info.Protect);
                        string typeLabel = EventDetailFormatting.DescribeMemoryType(info.Type);
                        ulong baseAddress = (ulong)info.BaseAddress;
                        ulong allocationBase = (ulong)info.AllocationBase;
                        string modulePath = ResolveMappedModulePath(modules, baseAddress, allocationBase, regionSize);
                        string backingPath =
                            ResolveMappedBackingPath(handle, baseAddress, allocationBase, mappedPathCache);
                        rows.Add(new MemoryPageSample {
                            BaseAddress = baseAddress, AllocationBase = allocationBase, RegionSize = regionSize,
                            State = info.State, Protect = info.Protect, AllocationProtect = info.AllocationProtect,
                            Type = info.Type, StateLabel = stateLabel, ProtectLabel = protectLabel,
                            TypeLabel = typeLabel,
                            SpecialUse = ResolveSpecialUseLabel(baseAddress, regionSize, anchors),
                            BackingPath = backingPath, ModulePath = modulePath
                        });
                        rows[^1].Sr71Owned = LooksLikeSr71ImagePath(modulePath) || LooksLikeSr71ImagePath(backingPath);
                        if (rows[^1].Sr71Owned)
                        {
                            rows[^1].Sr71OwnerTag = "SR71 Instrumentation";
                        }
                        ApplyWorkingSetAttributes(handle, rows[^1]);
                        rows[^1].Category = BuildPageCategory(rows[^1]);
                    }

                    ulong next = (ulong)info.BaseAddress + regionSize;
                    if (next <= address)
                    {
                        break;
                    }

                    address = next;
                }
            }
            catch
            {
                return new List<MemoryPageSample>();
            }
            finally
            {
                _ = Kernel32Native.CloseHandle(handle);
            }

            return rows.OrderByDescending(x => x.RegionSize).ThenBy(x => x.BaseAddress).Take(768).ToList();
        }

        private static string BuildPageCategory(MemoryPageSample page)
        {
            string specialUse = page.SpecialUse;
            if (!string.IsNullOrWhiteSpace(specialUse))
            {
                return specialUse;
            }
            if (page.Sr71Owned || LooksLikeSr71ImagePath(page.ModulePath) || LooksLikeSr71ImagePath(page.BackingPath))
            {
                return "SR71 Instrumentation";
            }

            uint baseProtect = page.Protect & 0xFFu;
            bool executable = baseProtect == 0x10 || baseProtect == 0x20 || baseProtect == 0x40 || baseProtect == 0x80;
            bool writable = baseProtect == 0x04 || baseProtect == 0x08 || baseProtect == 0x40 || baseProtect == 0x80;

            string typeLabel = page.Type switch {
                0x20000 => "Private",
                0x40000 => "Mapped",
                0x1000000 => "Image",
                _ => "Unknown"
            };

            if (page.WorkingSetValid && !page.WorkingSetShared && (page.Type == 0x40000 || page.Type == 0x1000000))
            {
                typeLabel += " Private Copy";
            }

            if (executable && writable)
            {
                return $"{typeLabel} RWX";
            }
            if (executable)
            {
                return $"{typeLabel} RX";
            }
            if (writable)
            {
                return $"{typeLabel} RW";
            }

            return typeLabel;
        }

        private static string ResolveSpecialUseLabel(ulong baseAddress, ulong regionSize,
                                                     IReadOnlyList<MemoryAnchor> anchors)
        {
            ulong regionEnd = baseAddress + Math.Max(regionSize, 0x1000UL);
            if (regionEnd <= baseAddress)
            {
                regionEnd = ulong.MaxValue;
            }

            MemoryAnchor? best = null;
            foreach (MemoryAnchor anchor in anchors)
            {
                ulong anchorEnd = anchor.Address + Math.Max(anchor.Size, 1UL);
                if (anchorEnd <= anchor.Address)
                {
                    anchorEnd = ulong.MaxValue;
                }

                if (baseAddress >= anchorEnd || anchor.Address >= regionEnd)
                {
                    continue;
                }

                if (best == null || anchor.Priority < best.Value.Priority)
                {
                    best = anchor;
                }
            }

            return best?.Label ?? string.Empty;
        }

        private static bool LooksLikeSr71ImagePath(string? path) =>
            EventDetailFormatting.IsSr71Module(EventDetailFormatting.ModuleNameFromPath(path ?? string.Empty));

        private static void ApplyWorkingSetAttributes(IntPtr processHandle, MemoryPageSample page)
        {
            if (processHandle == IntPtr.Zero || page.BaseAddress == 0)
            {
                return;
            }

            var entries =
                new[] { new PSAPI_WORKING_SET_EX_INFORMATION { VirtualAddress = unchecked((IntPtr)page.BaseAddress) } };

            int size = Marshal.SizeOf<PSAPI_WORKING_SET_EX_INFORMATION>();
            if (!QueryWorkingSetEx(processHandle, entries, size))
            {
                return;
            }

            ulong flags = entries[0].VirtualAttributes.ToUInt64();
            page.WorkingSetValid = (flags & 0x1UL) != 0;
            page.WorkingSetShareCount = (uint)((flags >> 1) & 0x7UL);
            page.WorkingSetShared = ((flags >> 15) & 0x1UL) != 0;
            page.WorkingSetLocked = ((flags >> 22) & 0x1UL) != 0;
            page.WorkingSetLargePage = ((flags >> 23) & 0x1UL) != 0;
        }

        // Offsets/field names are derived from Kernel/include/ntpebteb.h.
        private static List<MemoryAnchor> CaptureMemoryAnchors(Process process, IntPtr processHandle)
        {
            var anchors = new List<MemoryAnchor>(96);
            if (processHandle == IntPtr.Zero || IntPtr.Size != 8)
            {
                return anchors;
            }

            if (!TryGetPebAddress(processHandle, out ulong pebAddress) || pebAddress == 0)
            {
                AppendThreadAnchors(process, processHandle, anchors);
                return anchors;
            }

            anchors.Add(new MemoryAnchor("PEB", pebAddress, 0x1000, 0));

            const ulong PebProcessParameters = 0x20;
            const ulong PebProcessHeap = 0x30;
            const ulong PebUserSharedInfoPtr = 0x58;
            const ulong PebApiSetMap = 0x68;
            const ulong PebTlsBitmap = 0x78;
            const ulong PebReadOnlySharedMemoryBase = 0x88;
            const ulong PebSharedData = 0x90;
            const ulong PebReadOnlyStaticServerData = 0x98;
            const ulong PebAnsiCodePageData = 0xA0;
            const ulong PebOemCodePageData = 0xA8;
            const ulong PebUnicodeCaseTableData = 0xB0;
            const ulong PebNumberOfHeaps = 0xE8;
            const ulong PebProcessHeaps = 0xF0;
            const ulong PebGdiSharedHandleTable = 0xF8;
            const ulong PebProcessStarterHelper = 0x100;
            const ulong PebLoaderLock = 0x110;
            const ulong PebShimData = 0x2D8;
            const ulong PebAppCompatInfo = 0x2E0;
            const ulong PebActivationContextData = 0x2F8;
            const ulong PebProcessAssemblyStorageMap = 0x300;
            const ulong PebSystemDefaultActivationContextData = 0x308;
            const ulong PebSystemAssemblyStorageMap = 0x310;
            const ulong PebPatchLoaderData = 0x330;
            const ulong PebChpeV2ProcessInfo = 0x338;
            const ulong PebWerRegistrationData = 0x358;
            const ulong PebWerShipAssertPtr = 0x360;
            const ulong PebEcCodeBitMap = 0x368;
            const ulong PebImageHeaderHash = 0x370;
            const ulong PebCsrServerReadOnlySharedMemoryBase = 0x380;
            const ulong PebTelemetryCoverageHeader = 0x7A0;
            const ulong PebLeapSecondData = 0x7B8;

            AddPebPointerAnchor(processHandle, anchors, pebAddress + PebProcessParameters, "Process Parameters", 1);
            ulong processHeap =
                AddPebPointerAnchor(processHandle, anchors, pebAddress + PebProcessHeap, "Process Heap", 2);
            AddPebPointerAnchor(processHandle, anchors, pebAddress + PebUserSharedInfoPtr, "USER32 Shared Info", 5);
            AddPebPointerAnchor(processHandle, anchors, pebAddress + PebApiSetMap, "ApiSetMap", 3);
            AddPebPointerAnchor(processHandle, anchors, pebAddress + PebTlsBitmap, "TLS Bitmap", 6);
            AddPebPointerAnchor(processHandle, anchors, pebAddress + PebReadOnlySharedMemoryBase,
                                "CSRSS ReadOnly Shared Memory", 3);
            AddPebPointerAnchor(processHandle, anchors, pebAddress + PebSharedData, "Silo Shared Data", 2);
            AddPebPointerAnchor(processHandle, anchors, pebAddress + PebReadOnlyStaticServerData,
                                "CSRSS Static Server Data", 4);
            AddPebPointerAnchor(processHandle, anchors, pebAddress + PebAnsiCodePageData, "CodePage Data", 4);
            AddPebPointerAnchor(processHandle, anchors, pebAddress + PebOemCodePageData, "CodePage Data", 4);
            AddPebPointerAnchor(processHandle, anchors, pebAddress + PebUnicodeCaseTableData, "CodePage Data", 4);
            AddPebPointerAnchor(processHandle, anchors, pebAddress + PebGdiSharedHandleTable, "GDI Shared Handle Table",
                                3);
            AddPebPointerAnchor(processHandle, anchors, pebAddress + PebProcessStarterHelper, "Process Starter Helper",
                                6);
            AddPebPointerAnchor(processHandle, anchors, pebAddress + PebLoaderLock, "Loader Lock", 6);
            AddPebPointerAnchor(processHandle, anchors, pebAddress + PebShimData, "Shim Data", 3);
            AddPebPointerAnchor(processHandle, anchors, pebAddress + PebAppCompatInfo, "AppCompat Data", 4);
            AddPebPointerAnchor(processHandle, anchors, pebAddress + PebActivationContextData,
                                "Activation Context Data", 3);
            AddPebPointerAnchor(processHandle, anchors, pebAddress + PebProcessAssemblyStorageMap,
                                "Process Assembly Storage Map", 4);
            AddPebPointerAnchor(processHandle, anchors, pebAddress + PebSystemDefaultActivationContextData,
                                "System Activation Context Data", 4);
            AddPebPointerAnchor(processHandle, anchors, pebAddress + PebSystemAssemblyStorageMap,
                                "System Assembly Storage Map", 4);
            AddPebPointerAnchor(processHandle, anchors, pebAddress + PebPatchLoaderData, "Patch Loader Data", 5);
            AddPebPointerAnchor(processHandle, anchors, pebAddress + PebChpeV2ProcessInfo, "CHPEV2 Process Info", 5);
            AddPebPointerAnchor(processHandle, anchors, pebAddress + PebWerRegistrationData, "WER Registration Data",
                                6);
            AddPebPointerAnchor(processHandle, anchors, pebAddress + PebWerShipAssertPtr, "WER Assert Data", 6);
            AddPebPointerAnchor(processHandle, anchors, pebAddress + PebEcCodeBitMap, "EC Code Bitmap", 6);
            AddPebPointerAnchor(processHandle, anchors, pebAddress + PebImageHeaderHash, "Image Header Hash", 6);
            AddPebPointerAnchor(processHandle, anchors, pebAddress + PebCsrServerReadOnlySharedMemoryBase,
                                "CSR Server Shared Memory", 3);
            AddPebPointerAnchor(processHandle, anchors, pebAddress + PebTelemetryCoverageHeader, "Telemetry Coverage",
                                4);
            AddPebPointerAnchor(processHandle, anchors, pebAddress + PebLeapSecondData, "Leap Second Data", 3);

            if (TryReadUInt32(processHandle, pebAddress + PebNumberOfHeaps, out uint heapCount) &&
                TryReadPointer(processHandle, pebAddress + PebProcessHeaps, out ulong heapsArray) && heapCount > 0 &&
                heapCount <= 1024 && heapsArray != 0)
            {
                anchors.Add(
                    new MemoryAnchor("Process Heaps Array", heapsArray, (ulong)heapCount * (ulong)IntPtr.Size, 4));
                foreach (ulong heap in ReadPointerArray(processHandle, heapsArray, (int)heapCount))
                {
                    if (heap == 0)
                    {
                        continue;
                    }

                    anchors.Add(new MemoryAnchor(heap == processHeap ? "Process Heap" : "Heap", heap, 0x1000,
                                                 heap == processHeap ? 2 : 5));
                }
            }

            AppendThreadAnchors(process, processHandle, anchors);
            return anchors;
        }

        private static void AppendThreadAnchors(Process process, IntPtr processHandle, List<MemoryAnchor> anchors)
        {
            try
            {
                foreach (ProcessThread thread in process.Threads)
                {
                    IntPtr threadHandle = OpenThread(ThreadQueryInformation | ThreadQueryLimitedInformation, false,
                                                     unchecked((uint)thread.Id));
                    if (threadHandle == IntPtr.Zero)
                    {
                        continue;
                    }

                    try
                    {
                        if (!TryGetThreadMemoryRange(processHandle, threadHandle, out ulong tebAddress,
                                                     out ulong stackBase, out ulong stackLimit))
                        {
                            continue;
                        }

                        if (tebAddress != 0)
                        {
                            anchors.Add(new MemoryAnchor("TEB", tebAddress, 0x2000, 2));
                        }
                        if (stackLimit != 0 && stackBase > stackLimit)
                        {
                            anchors.Add(new MemoryAnchor("Thread Stack", stackLimit, stackBase - stackLimit, 1));
                        }
                    }
                    finally
                    {
                        _ = CloseHandle(threadHandle);
                    }
                }
            }
            catch
            {
            }
        }

        private static ulong AddPebPointerAnchor(IntPtr processHandle, List<MemoryAnchor> anchors, ulong pointerAddress,
                                                 string label, int priority)
        {
            if (!TryReadPointer(processHandle, pointerAddress, out ulong value) || value == 0)
            {
                return 0;
            }

            anchors.Add(new MemoryAnchor(label, value, 0x1000, priority));
            return value;
        }

        private static bool TryGetPebAddress(IntPtr processHandle, out ulong pebAddress)
        {
            pebAddress = 0;
            int status = NtQueryInformationProcess(processHandle, 0, out PROCESS_BASIC_INFORMATION pbi,
                                                   Marshal.SizeOf<PROCESS_BASIC_INFORMATION>(), out _);
            if (status != 0 || pbi.PebBaseAddress == IntPtr.Zero)
            {
                return false;
            }

            pebAddress = unchecked((ulong)pbi.PebBaseAddress.ToInt64());
            return pebAddress != 0;
        }

        private static bool TryReadPointer(IntPtr processHandle, ulong address, out ulong value)
        {
            value = 0;
            byte[] buffer = new byte[IntPtr.Size];
            if (!ReadProcessMemory(processHandle, unchecked((IntPtr)address), buffer, buffer.Length,
                                   out IntPtr bytesRead) ||
                bytesRead.ToInt64() != buffer.Length)
            {
                return false;
            }

            value = BitConverter.ToUInt64(buffer, 0);
            return true;
        }

        private static bool TryReadUInt32(IntPtr processHandle, ulong address, out uint value)
        {
            value = 0;
            byte[] buffer = new byte[sizeof(uint)];
            if (!ReadProcessMemory(processHandle, unchecked((IntPtr)address), buffer, buffer.Length,
                                   out IntPtr bytesRead) ||
                bytesRead.ToInt64() != buffer.Length)
            {
                return false;
            }

            value = BitConverter.ToUInt32(buffer, 0);
            return true;
        }

        private static IEnumerable<ulong> ReadPointerArray(IntPtr processHandle, ulong address, int count)
        {
            int bytes = checked(count * IntPtr.Size);
            byte[] buffer = new byte[bytes];
            if (!ReadProcessMemory(processHandle, unchecked((IntPtr)address), buffer, bytes, out IntPtr bytesRead))
            {
                yield break;
            }

            int entries = (int)(bytesRead.ToInt64() / IntPtr.Size);
            for (int i = 0; i < entries; i += 1)
            {
                yield return BitConverter.ToUInt64(buffer, i * IntPtr.Size);
            }
        }

        private static bool TryGetThreadMemoryRange(IntPtr processHandle, IntPtr threadHandle, out ulong tebAddress,
                                                    out ulong stackBase, out ulong stackLimit)
        {
            tebAddress = 0;
            stackBase = 0;
            stackLimit = 0;

            int status = NtQueryInformationThread(threadHandle, 0, out THREAD_BASIC_INFORMATION tbi,
                                                  Marshal.SizeOf<THREAD_BASIC_INFORMATION>(), out _);
            if (status != 0 || tbi.TebBaseAddress == IntPtr.Zero)
            {
                return false;
            }

            tebAddress = unchecked((ulong)tbi.TebBaseAddress.ToInt64());
            byte[] tibBuffer = new byte[Marshal.SizeOf<NT_TIB64>()];
            if (!ReadProcessMemory(processHandle, tbi.TebBaseAddress, tibBuffer, tibBuffer.Length,
                                   out IntPtr bytesRead) ||
                bytesRead.ToInt64() < tibBuffer.Length)
            {
                return tebAddress != 0;
            }

            GCHandle handle = GCHandle.Alloc(tibBuffer, GCHandleType.Pinned);
            try
            {
                NT_TIB64 tib = Marshal.PtrToStructure<NT_TIB64>(handle.AddrOfPinnedObject());
                stackBase = tib.StackBase;
                stackLimit = tib.StackLimit;
            }
            finally
            {
                handle.Free();
            }

            return true;
        }

        private static List<MemoryModuleMapEntry> CaptureModuleMap(Process process)
        {
            var rows = new List<MemoryModuleMapEntry>(128);
            try
            {
                foreach (ProcessModule module in process.Modules)
                {
                    ulong baseAddress = unchecked((ulong)module.BaseAddress.ToInt64());
                    ulong size = (ulong)Math.Max(module.ModuleMemorySize, 0);
                    if (baseAddress == 0 || size == 0)
                    {
                        continue;
                    }

                    rows.Add(new MemoryModuleMapEntry(baseAddress, baseAddress + size,
                                                      module.ModuleName ?? string.Empty,
                                                      module.FileName ?? string.Empty));
                }
            }
            catch
            {
            }

            rows.Sort((left, right) => left.BaseAddress.CompareTo(right.BaseAddress));
            return rows;
        }

        private static string ResolveMappedModulePath(IReadOnlyList<MemoryModuleMapEntry> modules, ulong baseAddress,
                                                      ulong allocationBase, ulong regionSize)
        {
            ulong regionEnd = baseAddress + regionSize;
            if (regionEnd <= baseAddress)
            {
                regionEnd = ulong.MaxValue;
            }

            for (int i = 0; i < modules.Count; i += 1)
            {
                MemoryModuleMapEntry module = modules[i];
                if ((allocationBase != 0 && allocationBase == module.BaseAddress) ||
                    (baseAddress >= module.BaseAddress && baseAddress < module.EndAddress) ||
                    (module.BaseAddress >= baseAddress && module.BaseAddress < regionEnd))
                {
                    return module.Path;
                }
            }

            return string.Empty;
        }

        private static string ResolveMappedBackingPath(IntPtr processHandle, ulong baseAddress, ulong allocationBase,
                                                       Dictionary<ulong, string> cache)
        {
            ulong key = allocationBase != 0 ? allocationBase : baseAddress;
            if (key == 0)
            {
                return string.Empty;
            }

            if (cache.TryGetValue(key, out string? existing))
            {
                return existing;
            }

            string mappedPath = QueryMappedFilename(processHandle, key);
            cache[key] = mappedPath;
            return mappedPath;
        }

        private static string QueryMappedFilename(IntPtr processHandle, ulong address)
        {
            const int memoryMappedFilenameInformation = 2;
            const int bufferBytes = 32768;

            if (processHandle == IntPtr.Zero || address == 0)
            {
                return string.Empty;
            }

            IntPtr buffer = Marshal.AllocHGlobal(bufferBytes);
            try
            {
                int status =
                    NtQueryVirtualMemory(processHandle, unchecked((nint)address), memoryMappedFilenameInformation,
                                         buffer, (uint)bufferBytes, out uint _);
                if (status < 0)
                {
                    return string.Empty;
                }

                UNICODE_STRING text = Marshal.PtrToStructure<UNICODE_STRING>(buffer);
                if (text.Buffer == IntPtr.Zero || text.Length == 0)
                {
                    return string.Empty;
                }

                return Marshal.PtrToStringUni(text.Buffer, text.Length / 2) ?? string.Empty;
            }
            catch
            {
                return string.Empty;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        private static MemoryMetricSample CloneMetric(MemoryMetricSample src)
        {
            return new MemoryMetricSample { Metric = src.Metric, Value = src.Value, BytesValue = src.BytesValue };
        }

        private static MemoryPageSample ClonePage(MemoryPageSample src)
        {
            return new MemoryPageSample { BaseAddress = src.BaseAddress,
                                          AllocationBase = src.AllocationBase,
                                          RegionSize = src.RegionSize,
                                          State = src.State,
                                          Protect = src.Protect,
                                          AllocationProtect = src.AllocationProtect,
                                          Type = src.Type,
                                          StateLabel = src.StateLabel,
                                          ProtectLabel = src.ProtectLabel,
                                          TypeLabel = src.TypeLabel,
                                          Category = src.Category,
                                          SpecialUse = src.SpecialUse,
                                          BackingPath = src.BackingPath,
                                          ModulePath = src.ModulePath,
                                          Sr71Owned = src.Sr71Owned,
                                          Sr71OwnerTag = src.Sr71OwnerTag,
                                          WorkingSetValid = src.WorkingSetValid,
                                          WorkingSetShared = src.WorkingSetShared,
                                          WorkingSetShareCount = src.WorkingSetShareCount,
                                          WorkingSetLocked = src.WorkingSetLocked,
                                          WorkingSetLargePage = src.WorkingSetLargePage };
        }

        private static string FormatBytes(long bytes)
        {
            if (bytes >= 1024L * 1024 * 1024)
                return $"{bytes / (1024d * 1024 * 1024):0.##} GB";
            if (bytes >= 1024L * 1024)
                return $"{bytes / (1024d * 1024):0.##} MB";
            if (bytes >= 1024)
                return $"{bytes / 1024d:0.##} KB";
            return $"{bytes} B";
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

                thread.Kind = InferThreadRole(thread.State, thread.WaitReason);
            }
        }

        private static string InferThreadRole(string state, string waitReason)
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

        private static DateTime? SafeThreadStart(ProcessThread t)
        {
            try
            {
                return t.StartTime.ToUniversalTime();
            }
            catch
            {
                return null;
            }
        }

        private static (long bytesIn, long bytesOut, long packets) ReadNetworkTotals()
        {
            long bin = 0, bout = 0, pk = 0;

            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                try
                {
                    if (nic.OperationalStatus != OperationalStatus.Up)
                        continue;
                    if (nic.NetworkInterfaceType == NetworkInterfaceType.Loopback)
                        continue;

                    var stats = nic.GetIPv4Statistics();
                    bin += stats.BytesReceived;
                    bout += stats.BytesSent;
                    pk += stats.UnicastPacketsReceived + stats.UnicastPacketsSent;
                }
                catch
                {
                }
            }

            return (bin, bout, pk);
        }

        private static double Clamp(double v, double min, double max) => v < min ? min : (v > max ? max : v);

        private static bool TryReadIoCounters(Process p, out IO_COUNTERS io)
        {
            io = default;
            try
            {
                return GetProcessIoCounters(p.Handle, out io);
            }
            catch
            {
                return false;
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct IO_COUNTERS
        {
            public ulong ReadOperationCount;
            public ulong WriteOperationCount;
            public ulong OtherOperationCount;
            public ulong ReadTransferCount;
            public ulong WriteTransferCount;
            public ulong OtherTransferCount;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetProcessIoCounters(IntPtr hProcess, out IO_COUNTERS lpIoCounters);

        [StructLayout(LayoutKind.Sequential)]
        private struct MEMORY_BASIC_INFORMATION
        {
            public nint BaseAddress;
            public nint AllocationBase;
            public uint AllocationProtect;
            public ushort PartitionId;
            public nuint RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct UNICODE_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr Reserved1;
            public IntPtr PebBaseAddress;
            public IntPtr Reserved2_0;
            public IntPtr Reserved2_1;
            public IntPtr UniqueProcessId;
            public IntPtr Reserved3;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct THREAD_BASIC_INFORMATION
        {
            public int ExitStatus;
            public IntPtr TebBaseAddress;
            public IntPtr ClientIdUniqueProcess;
            public IntPtr ClientIdUniqueThread;
            public UIntPtr AffinityMask;
            public int Priority;
            public int BasePriority;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct NT_TIB64
        {
            public ulong ExceptionList;
            public ulong StackBase;
            public ulong StackLimit;
            public ulong SubSystemTib;
            public ulong FiberData;
            public ulong ArbitraryUserPointer;
            public ulong Self;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PSAPI_WORKING_SET_EX_INFORMATION
        {
            public IntPtr VirtualAddress;
            public UIntPtr VirtualAttributes;
        }

        private readonly record struct MemoryModuleMapEntry(ulong BaseAddress, ulong EndAddress, string Name,
                                                            string Path);

        private readonly record struct MemoryAnchor(string Label, ulong Address, ulong Size, int Priority);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern nuint VirtualQueryEx(IntPtr hProcess, nint lpAddress,
                                                   out MEMORY_BASIC_INFORMATION lpBuffer, nuint dwLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer,
                                                     int nSize, out IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenThread(uint desiredAccess, bool inheritHandle, uint threadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("ntdll.dll")]
        private static extern int NtQueryVirtualMemory(IntPtr processHandle, nint baseAddress,
                                                       int memoryInformationClass, IntPtr memoryInformation,
                                                       uint memoryInformationLength, out uint returnLength);

        [DllImport("ntdll.dll")]
        private static extern int NtQueryInformationProcess(IntPtr processHandle, int processInformationClass,
                                                            out PROCESS_BASIC_INFORMATION processInformation,
                                                            int processInformationLength, out int returnLength);

        [DllImport("ntdll.dll")]
        private static extern int NtQueryInformationThread(IntPtr threadHandle, int threadInformationClass,
                                                           out THREAD_BASIC_INFORMATION threadInformation,
                                                           int threadInformationLength, out int returnLength);

        [DllImport("psapi.dll", SetLastError = true)]
        private static extern bool QueryWorkingSetEx(IntPtr hProcess, [In, Out] PSAPI_WORKING_SET_EX_INFORMATION[] pv,
                                                     int cb);

        private const uint ThreadQueryInformation = 0x0040;
        private const uint ThreadQueryLimitedInformation = 0x0800;
    }
}
