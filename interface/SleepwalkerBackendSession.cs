using System;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace SleepwalkerInterface
{
    internal sealed class SleepwalkerBackendSession : IDisposable
    {
        private readonly int _targetPid;
        private readonly uint _streamMask;
        private readonly CancellationTokenSource _cts = new();

        private Task? _ioctlTask;
        private Task? _etwTask;
        private Task? _statsTask;
        private IntPtr _ioctlHandle;
        private IntPtr _etwHandle;

        public event Action<IoctlParsedEvent>? IoctlEvent;
        public event Action<SleepwalkerNative.SwIpcEtwEvent>? EtwEvent;
        public event Action<BackendStatsView>? Stats;
        public event Action<string>? Status;

        public int TargetPid => _targetPid;

        private SleepwalkerBackendSession(int targetPid, uint streamMask)
        {
            _targetPid = targetPid;
            _streamMask = streamMask;
        }

        public static SleepwalkerBackendSession Start(int targetPid, uint streamMask)
        {
            if (targetPid <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(targetPid));
            }

            var session = new SleepwalkerBackendSession(targetPid, streamMask);
            session.StartInternal();
            return session;
        }

        private void StartInternal()
        {
            try
            {
                if (!SleepwalkerNative.UseClientProtocol(null, 1500))
                {
                    throw SleepwalkerNative.LastError("UseClientProtocol failed");
                }

                _ioctlHandle = SleepwalkerNative.OpenControlDevice();
                if (_ioctlHandle == IntPtr.Zero || _ioctlHandle == new IntPtr(-1))
                {
                    throw SleepwalkerNative.LastError("OpenControlDevice(ioctl) failed");
                }

                _etwHandle = SleepwalkerNative.OpenControlDevice();
                if (_etwHandle == IntPtr.Zero || _etwHandle == new IntPtr(-1))
                {
                    throw SleepwalkerNative.LastError("OpenControlDevice(etw) failed");
                }

                var pids = new[] { (uint)_targetPid };
                if (!SleepwalkerNative.SetPids(_ioctlHandle, pids, 1, _streamMask))
                {
                    throw SleepwalkerNative.LastError("SetPids(ioctl) failed");
                }

                if (!SleepwalkerNative.SetPids(_etwHandle, pids, 1, _streamMask))
                {
                    throw SleepwalkerNative.LastError("SetPids(etw) failed");
                }

                Status?.Invoke($"Session started for PID {_targetPid}");
                DiagnosticsState.SetValue("Session", $"pid={_targetPid} stream=0x{_streamMask:X8}");

                _ioctlTask = Task.Run(() => IoctlPump(_cts.Token));
                _etwTask = Task.Run(() => EtwPump(_cts.Token));
                _statsTask = Task.Run(() => StatsPump(_cts.Token));
            }
            catch
            {
                CleanupHandles();
                throw;
            }
        }

        private void IoctlPump(CancellationToken ct)
        {
            IntPtr buffer = Marshal.AllocHGlobal(SleepwalkerNative.EventReadBufferBytes);
            byte[] managed = new byte[SleepwalkerNative.EventReadBufferBytes];
            try
            {
                while (!ct.IsCancellationRequested)
                {
                    bool ok = SleepwalkerNative.GetEventRaw(_ioctlHandle, buffer, out uint bytes);
                    if (ok)
                    {
                        int len = (int)Math.Min(bytes, (uint)managed.Length);
                        if (len <= 0)
                        {
                            ct.WaitHandle.WaitOne(2);
                            continue;
                        }

                        Marshal.Copy(buffer, managed, 0, len);
                        if (SleepwalkerNative.TryParseIoctlEvent(managed, len, out var parsed))
                        {
                            DiagnosticsState.Increment("IOCTL Events");
                            IoctlEvent?.Invoke(parsed);
                        }

                        continue;
                    }

                    int err = Marshal.GetLastWin32Error();
                    if (err == SleepwalkerNative.ErrorNoMoreEntries)
                    {
                        ct.WaitHandle.WaitOne(8);
                        continue;
                    }

                    if (err == SleepwalkerNative.ErrorOperationAborted || err == SleepwalkerNative.ErrorNotReady ||
                        err == SleepwalkerNative.ErrorDeviceNotConnected || err == SleepwalkerNative.ErrorBrokenPipe)
                    {
                        Status?.Invoke($"IOCTL pump stopped (err={err})");
                        DiagnosticsState.SetValue("IOCTL Pump", $"Stopped err={err}");
                        break;
                    }

                    DiagnosticsState.Increment("IOCTL Errors");
                    DiagnosticsState.SetValue("IOCTL LastError", err.ToString());
                    ct.WaitHandle.WaitOne(40);
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        private void EtwPump(CancellationToken ct)
        {
            while (!ct.IsCancellationRequested)
            {
                bool ok = SleepwalkerNative.GetEtwEvent(_etwHandle, out var etw, 500);
                if (ok)
                {
                    DiagnosticsState.Increment("ETW Events");
                    if (etw.Source == SleepwalkerNative.IpcEtwSourceThreatIntel)
                    {
                        DiagnosticsState.Increment("ETW-TI Events");
                    }
                    EtwEvent?.Invoke(etw);
                    continue;
                }

                int err = Marshal.GetLastWin32Error();
                if (err == SleepwalkerNative.ErrorNoMoreItems)
                {
                    continue;
                }

                if (err == SleepwalkerNative.ErrorOperationAborted || err == SleepwalkerNative.ErrorNotReady ||
                    err == SleepwalkerNative.ErrorDeviceNotConnected || err == SleepwalkerNative.ErrorBrokenPipe)
                {
                    Status?.Invoke($"ETW pump stopped (err={err})");
                    DiagnosticsState.SetValue("ETW Pump", $"Stopped err={err}");
                    return;
                }

                if (err == SleepwalkerNative.ErrorNotSupported || err == SleepwalkerNative.ErrorInvalidFunction)
                {
                    Status?.Invoke("ETW uplink unsupported by active controller build");
                    DiagnosticsState.SetValue("ETW Pump", "Unsupported");
                    return;
                }

                DiagnosticsState.Increment("ETW Errors");
                DiagnosticsState.SetValue("ETW LastError", err.ToString());
                ct.WaitHandle.WaitOne(40);
            }
        }

        private void StatsPump(CancellationToken ct)
        {
            while (!ct.IsCancellationRequested)
            {
                if (SleepwalkerNative.GetStats(_ioctlHandle, out var stats, out _))
                {
                    Stats?.Invoke(new BackendStatsView
                    {
                        TimestampUtc = DateTime.UtcNow,
                        SubscriptionCount = stats.SubscriptionCount,
                        QueueDepth = stats.QueueDepth,
                        DroppedEvents = stats.DroppedEvents
                    });

                    DiagnosticsState.SetValue(
                        "Driver Queue",
                        $"subs={stats.SubscriptionCount} depth={stats.QueueDepth} dropped={stats.DroppedEvents}");
                }

                ct.WaitHandle.WaitOne(2000);
            }
        }

        public void Dispose()
        {
            _cts.Cancel();

            try
            {
                _ioctlTask?.Wait(1200);
            }
            catch
            {
            }

            try
            {
                _etwTask?.Wait(1200);
            }
            catch
            {
            }

            try
            {
                _statsTask?.Wait(1200);
            }
            catch
            {
            }

            CleanupHandles();

            _cts.Dispose();
            Status?.Invoke("Session disposed");
        }

        private void CleanupHandles()
        {
            if (_ioctlHandle != IntPtr.Zero && _ioctlHandle != new IntPtr(-1))
            {
                _ = SleepwalkerNative.CloseHandle(_ioctlHandle);
                _ioctlHandle = IntPtr.Zero;
            }

            if (_etwHandle != IntPtr.Zero && _etwHandle != new IntPtr(-1))
            {
                _ = SleepwalkerNative.CloseHandle(_etwHandle);
                _etwHandle = IntPtr.Zero;
            }
        }
    }
}
