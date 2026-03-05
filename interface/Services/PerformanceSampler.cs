using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Threading;

namespace SleepwalkerInterface
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

        public PerformanceSampler()
        {
            TryInitCounters();
        }

        public void Start()
        {
            _lastWall = DateTime.UtcNow;
            _lastProcCpu = TimeSpan.Zero;
            PrimeNetwork();
            lock (_lock)
            {
                _timer?.Dispose();
                _timer = new Timer(_ => Tick(), null, TimeSpan.Zero, TimeSpan.FromSeconds(1));
            }
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
            }
        }

        private void TryInitCounters()
        {
            try { _cpuTotal = new PerformanceCounter("Processor", "% Processor Time", "_Total"); _ = _cpuTotal.NextValue(); } catch { _cpuTotal = null; }
            try { _diskRead = new PerformanceCounter("PhysicalDisk", "Disk Read Bytes/sec", "_Total"); _ = _diskRead.NextValue(); } catch { _diskRead = null; }
            try { _diskWrite = new PerformanceCounter("PhysicalDisk", "Disk Write Bytes/sec", "_Total"); _ = _diskWrite.NextValue(); } catch { _diskWrite = null; }
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
            if (wallDelta.TotalMilliseconds <= 0) wallDelta = TimeSpan.FromMilliseconds(1000);

            var sample = new PerformanceSample
            {
                TimestampUtc = now,
                CoreCount = Environment.ProcessorCount
            };

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
                try { s.CpuPercent = Clamp(_cpuTotal.NextValue(), 0, 100); }
                catch { s.CpuPercent = 0; }
            }

            s.CoresUsedPercent = s.CpuPercent;

            if (_diskRead != null)
            {
                try { s.DiskReadBytesPerSec = Math.Max(0, _diskRead.NextValue()); } catch { }
            }
            if (_diskWrite != null)
            {
                try { s.DiskWriteBytesPerSec = Math.Max(0, _diskWrite.NextValue()); } catch { }
            }

            try
            {
                s.PrivateBytes = GC.GetTotalMemory(false);
                s.ReservedBytes = s.PrivateBytes * 2;
            }
            catch { }

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
            try { p = Process.GetProcessById(pid); }
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
                        var otherDelta = io.OtherTransferCount - _lastIoOther;

                        s.DiskReadBytesPerSec = Math.Max(0, readDelta / sec2);
                        s.DiskWriteBytesPerSec = Math.Max(0, writeDelta / sec2);

                        var otherPerSec = Math.Max(0, otherDelta / sec2);
                        s.NetInBytesPerSec = otherPerSec * 0.5;
                        s.NetOutBytesPerSec = otherPerSec * 0.5;
                        s.NetPacketsPerSec = otherPerSec / 512.0;

                        _lastIoRead = io.ReadTransferCount;
                        _lastIoWrite = io.WriteTransferCount;
                        _lastIoOther = io.OtherTransferCount;
                    }
                }

                FillTopThreadsForProcess(s, p, wallDelta);
                return true;
            }
            catch
            {
                return false;
            }
            finally
            {
                try { p?.Dispose(); } catch { }
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
                    try { cpu = t.TotalProcessorTime; }
                    catch { continue; }

                    string state = t.ThreadState.ToString();
                    string waitReason = "";
                    if (t.ThreadState == System.Diagnostics.ThreadState.Wait)
                    {
                        try { waitReason = t.WaitReason.ToString(); } catch { waitReason = ""; }
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

                    list.Add(new ThreadUsageSample
                    {
                        Tid = t.Id,
                        CpuMsDelta = Math.Max(0, deltaMs),
                        State = state,
                        WaitReason = waitReason,
                        Kind = InferThreadKind(state, waitReason),
                        StartTimeUtc = SafeThreadStart(t)
                    });
                }
            }
            catch
            {
            }

            s.TopThreads = list.OrderByDescending(x => x.CpuMsDelta).Take(20).ToList();
        }

        private static string InferThreadKind(string state, string waitReason)
        {
            if (!string.IsNullOrWhiteSpace(waitReason))
            {
                if (waitReason.Equals("Suspended", StringComparison.OrdinalIgnoreCase) ||
                    waitReason.Equals("UserRequest", StringComparison.OrdinalIgnoreCase))
                {
                    return "Normal";
                }

                if (waitReason.Equals("ExecutionDelay", StringComparison.OrdinalIgnoreCase) ||
                    waitReason.Equals("WrQueue", StringComparison.OrdinalIgnoreCase) ||
                    waitReason.Equals("WrLpcReceive", StringComparison.OrdinalIgnoreCase) ||
                    waitReason.Equals("WrLpcReply", StringComparison.OrdinalIgnoreCase) ||
                    waitReason.Equals("WrExecutive", StringComparison.OrdinalIgnoreCase))
                {
                    return "ThreadPool/System";
                }
            }

            if (state.Equals("Wait", StringComparison.OrdinalIgnoreCase) ||
                state.Equals("Transition", StringComparison.OrdinalIgnoreCase))
            {
                return "System/Runtime";
            }

            return "Normal";
        }

        private static DateTime? SafeThreadStart(ProcessThread t)
        {
            try
            {
                return t.StartTime.ToUniversalTime();
            }
            catch { return null; }
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
                catch { }
            }

            return (bin, bout, pk);
        }

        private static double Clamp(double v, double min, double max)
            => v < min ? min : (v > max ? max : v);

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
    }
}
