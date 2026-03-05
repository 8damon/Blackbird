using System;
using System.ComponentModel;
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
        private uint _brokerCapabilities;
        private bool _sharedRingEnabled;
        private uint _sharedRingError;
        private long _ioctlEvents;
        private long _etwEvents;
        private long _ioctlErrors;
        private long _etwErrors;
        private long _ioctlEmptyPolls;
        private long _etwEmptyPolls;
        private DateTime _lastStatsSnapshotUtc = DateTime.UtcNow;
        private long _lastStatsIoctlEvents;
        private long _lastStatsEtwEvents;

        public event Action<IoctlParsedEvent>? IoctlEvent;
        public event Action<SleepwalkerNative.SwIpcEtwEvent>? EtwEvent;
        public event Action<BackendStatsView>? Stats;
        public event Action<BackendIpcDiagnosticsView>? IpcDiagnostics;
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

                if (SleepwalkerNative.GetBrokerInfo(out uint capabilities, out _))
                {
                    _brokerCapabilities = capabilities;
                }
                _sharedRingError = SleepwalkerNative.GetLastSharedRingError();

                bool hasIoctlRing = false;
                bool hasEtwRing = false;
                if (SleepwalkerNative.HasSharedChannel(_ioctlHandle, out bool ioctlIoctlReady, out _))
                {
                    hasIoctlRing = ioctlIoctlReady;
                }
                if (SleepwalkerNative.HasSharedChannel(_etwHandle, out _, out bool etwEtwReady))
                {
                    hasEtwRing = etwEtwReady;
                }

                _sharedRingEnabled = hasIoctlRing && hasEtwRing;
                if (_sharedRingEnabled)
                {
                    _brokerCapabilities |= SleepwalkerNative.IpcCapSharedRing;
                    _sharedRingError = 0;
                }
                else
                {
                    _brokerCapabilities &= ~SleepwalkerNative.IpcCapSharedRing;
                }

                if (!_sharedRingEnabled)
                {
                    int err = _sharedRingError == 0 ? SleepwalkerNative.ErrorNotSupported : unchecked((int)_sharedRingError);
                    throw new Win32Exception(err, $"Shared-ring IPC required but unavailable (err={_sharedRingError})");
                }

                Status?.Invoke($"Session started for PID {_targetPid}");
                DiagnosticsState.SetValue("Session", $"pid={_targetPid} stream=0x{_streamMask:X8}");
                DiagnosticsState.SetValue("IPC Mode", "SharedRing+Event");
                DiagnosticsState.SetValue("IPC Shared Ring",
                    $"enabled={_sharedRingEnabled} ioctl={hasIoctlRing} etw={hasEtwRing} err={_sharedRingError}");

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
            int idleBackoffMs = _sharedRingEnabled ? 2 : 12;
            int idleBackoffMaxMs = _sharedRingEnabled ? 24 : 80;
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
                            ct.WaitHandle.WaitOne(idleBackoffMs);
                            idleBackoffMs = Math.Min(idleBackoffMaxMs, idleBackoffMs + 2);
                            continue;
                        }

                        Marshal.Copy(buffer, managed, 0, len);
                        if (SleepwalkerNative.TryParseIoctlEvent(managed, len, out var parsed))
                        {
                            Interlocked.Increment(ref _ioctlEvents);
                            DiagnosticsState.Increment("IOCTL Events");
                            IoctlEvent?.Invoke(parsed);
                        }
                        idleBackoffMs = _sharedRingEnabled ? 2 : 12;

                        continue;
                    }

                    int err = Marshal.GetLastWin32Error();
                    if (err == SleepwalkerNative.ErrorNoMoreEntries)
                    {
                        Interlocked.Increment(ref _ioctlEmptyPolls);
                        ct.WaitHandle.WaitOne(idleBackoffMs);
                        idleBackoffMs = Math.Min(idleBackoffMaxMs, idleBackoffMs + 4);
                        continue;
                    }

                    if (err == SleepwalkerNative.ErrorOperationAborted || err == SleepwalkerNative.ErrorNotReady ||
                        err == SleepwalkerNative.ErrorDeviceNotConnected || err == SleepwalkerNative.ErrorBrokenPipe)
                    {
                        Status?.Invoke($"IOCTL pump stopped (err={err})");
                        DiagnosticsState.SetValue("IOCTL Pump", $"Stopped err={err}");
                        break;
                    }

                    Interlocked.Increment(ref _ioctlErrors);
                    DiagnosticsState.Increment("IOCTL Errors");
                    DiagnosticsState.SetValue("IOCTL LastError", err.ToString());
                    ct.WaitHandle.WaitOne(40);
                    idleBackoffMs = _sharedRingEnabled ? 2 : 12;
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
                    Interlocked.Increment(ref _etwEvents);
                    DiagnosticsState.Increment("ETW Events");
                    if (etw.Source == SleepwalkerNative.IpcEtwSourceThreatIntel)
                    {
                        DiagnosticsState.Increment("ETW ThreatIntel Events");
                    }
                    EtwEvent?.Invoke(etw);
                    continue;
                }

                int err = Marshal.GetLastWin32Error();
                if (err == SleepwalkerNative.ErrorNoMoreItems)
                {
                    Interlocked.Increment(ref _etwEmptyPolls);
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

                Interlocked.Increment(ref _etwErrors);
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
                    DateTime now = DateTime.UtcNow;
                    double elapsed = (now - _lastStatsSnapshotUtc).TotalSeconds;
                    if (elapsed <= 0)
                    {
                        elapsed = 0.001;
                    }

                    long ioctlTotal = Interlocked.Read(ref _ioctlEvents);
                    long etwTotal = Interlocked.Read(ref _etwEvents);
                    long ioctlDelta = Math.Max(0, ioctlTotal - _lastStatsIoctlEvents);
                    long etwDelta = Math.Max(0, etwTotal - _lastStatsEtwEvents);

                    Stats?.Invoke(new BackendStatsView
                    {
                        TimestampUtc = now,
                        SubscriptionCount = stats.SubscriptionCount,
                        QueueDepth = stats.QueueDepth,
                        DroppedEvents = stats.DroppedEvents
                    });

                    IpcDiagnostics?.Invoke(new BackendIpcDiagnosticsView
                    {
                        TimestampUtc = now,
                        BrokerCapabilities = _brokerCapabilities,
                        SharedRingEnabled = _sharedRingEnabled,
                        SharedRingError = _sharedRingError,
                        IoctlReadBufferBytes = SleepwalkerNative.EventReadBufferBytes,
                        SubscriptionCount = stats.SubscriptionCount,
                        DriverQueueDepth = stats.QueueDepth,
                        DriverDroppedEvents = stats.DroppedEvents,
                        IoctlEventsTotal = ioctlTotal,
                        EtwEventsTotal = etwTotal,
                        IoctlErrorsTotal = Interlocked.Read(ref _ioctlErrors),
                        EtwErrorsTotal = Interlocked.Read(ref _etwErrors),
                        IoctlEmptyPolls = Interlocked.Read(ref _ioctlEmptyPolls),
                        EtwEmptyPolls = Interlocked.Read(ref _etwEmptyPolls),
                        IoctlEventsPerSec = ioctlDelta / elapsed,
                        EtwEventsPerSec = etwDelta / elapsed
                    });

                    _lastStatsSnapshotUtc = now;
                    _lastStatsIoctlEvents = ioctlTotal;
                    _lastStatsEtwEvents = etwTotal;

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
                _ = SleepwalkerNative.CloseControlDevice(_ioctlHandle);
                _ioctlHandle = IntPtr.Zero;
            }

            if (_etwHandle != IntPtr.Zero && _etwHandle != new IntPtr(-1))
            {
                _ = SleepwalkerNative.CloseControlDevice(_etwHandle);
                _etwHandle = IntPtr.Zero;
            }
        }
    }
}
