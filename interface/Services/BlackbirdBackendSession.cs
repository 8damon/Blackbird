using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace BlackbirdInterface
{
    internal sealed class BlackbirdBackendSession : IDisposable
    {
        private readonly int _targetPid;
        private readonly uint _streamMask;
        private readonly bool _useUsermodeHooks;
        private readonly IntPtr _seedIoctlHandle;
        private readonly IntPtr _seedEtwHandle;
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
        public event Action<BlackbirdNative.BkIpcEtwEvent>? EtwEvent;
        public event Action<BackendStatsView>? Stats;
        public event Action<BackendIpcDiagnosticsView>? IpcDiagnostics;
        public event Action<string>? Status;

        public int TargetPid => _targetPid;

        private BlackbirdBackendSession(int targetPid, uint streamMask, bool useUsermodeHooks,
            IntPtr seedIoctlHandle = default, IntPtr seedEtwHandle = default)
        {
            _targetPid = targetPid;
            _streamMask = streamMask;
            _useUsermodeHooks = useUsermodeHooks;
            _seedIoctlHandle = seedIoctlHandle;
            _seedEtwHandle = seedEtwHandle;
        }

        public static BlackbirdBackendSession Start(int targetPid, uint streamMask, bool useUsermodeHooks)
        {
            if (targetPid <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(targetPid));
            }

            var session = new BlackbirdBackendSession(targetPid, streamMask, useUsermodeHooks);
            session.StartInternal();
            return session;
        }

        public static BlackbirdBackendSession StartFromHandles(
            int targetPid,
            uint streamMask,
            bool useUsermodeHooks,
            IntPtr ioctlHandle,
            IntPtr etwHandle)
        {
            if (targetPid <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(targetPid));
            }
            if (ioctlHandle == IntPtr.Zero || ioctlHandle == new IntPtr(-1))
            {
                throw new ArgumentException("Invalid ioctl handle.", nameof(ioctlHandle));
            }
            if (etwHandle == IntPtr.Zero || etwHandle == new IntPtr(-1))
            {
                throw new ArgumentException("Invalid etw handle.", nameof(etwHandle));
            }

            var session = new BlackbirdBackendSession(targetPid, streamMask, useUsermodeHooks, ioctlHandle, etwHandle);
            session.StartInternal();
            return session;
        }

        private void StartInternal()
        {
            try
            {
                if (!BlackbirdNative.UseClientProtocol(null, 1500))
                {
                    throw BlackbirdNative.LastError("UseClientProtocol failed");
                }

                if (_seedIoctlHandle != IntPtr.Zero && _seedIoctlHandle != new IntPtr(-1))
                {
                    _ioctlHandle = _seedIoctlHandle;
                }
                else
                {
                    _ioctlHandle = BlackbirdNative.OpenControlDevice();
                    if (_ioctlHandle == IntPtr.Zero || _ioctlHandle == new IntPtr(-1))
                    {
                        throw BlackbirdNative.LastError("OpenControlDevice(ioctl) failed");
                    }
                }

                if (_seedEtwHandle != IntPtr.Zero && _seedEtwHandle != new IntPtr(-1))
                {
                    _etwHandle = _seedEtwHandle;
                }
                else
                {
                    _etwHandle = BlackbirdNative.OpenControlDevice();
                    if (_etwHandle == IntPtr.Zero || _etwHandle == new IntPtr(-1))
                    {
                        throw BlackbirdNative.LastError("OpenControlDevice(etw) failed");
                    }
                }

                var pids = new[] { (uint)_targetPid };
                if (!BlackbirdNative.SetPids(_ioctlHandle, pids, 1, _streamMask))
                {
                    throw BlackbirdNative.LastError("SetPids(ioctl) failed");
                }

                if (!BlackbirdNative.SetPids(_etwHandle, pids, 1, _streamMask))
                {
                    throw BlackbirdNative.LastError("SetPids(etw) failed");
                }

                if (BlackbirdNative.GetBrokerInfo(out uint capabilities, out _))
                {
                    _brokerCapabilities = capabilities;
                }
                _sharedRingError = BlackbirdNative.GetLastSharedRingError();

                bool hasIoctlRing = false;
                bool hasEtwRing = false;
                if (BlackbirdNative.HasSharedChannel(_ioctlHandle, out bool ioctlIoctlReady, out _))
                {
                    hasIoctlRing = ioctlIoctlReady;
                }
                if (BlackbirdNative.HasSharedChannel(_etwHandle, out _, out bool etwEtwReady))
                {
                    hasEtwRing = etwEtwReady;
                }

                _sharedRingEnabled = hasIoctlRing && hasEtwRing;
                if (_sharedRingEnabled)
                {
                    _brokerCapabilities |= BlackbirdNative.IpcCapSharedRing;
                    _sharedRingError = 0;
                }
                else
                {
                    _brokerCapabilities &= ~BlackbirdNative.IpcCapSharedRing;
                }

                if (!_sharedRingEnabled)
                {
                    int err = _sharedRingError == 0 ? BlackbirdNative.ErrorNotSupported : unchecked((int)_sharedRingError);
                    throw new Win32Exception(err, $"Shared-ring IPC required but unavailable (err={_sharedRingError})");
                }

                Status?.Invoke($"Session started for PID {_targetPid}");
                if (_useUsermodeHooks)
                {
                    Status?.Invoke("Usermode hooks enabled: waiting for hook publisher events.");
                }
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
            IntPtr buffer = Marshal.AllocHGlobal(BlackbirdNative.EventReadBufferBytes);
            byte[] managed = new byte[BlackbirdNative.EventReadBufferBytes];
            int idleBackoffMs = _sharedRingEnabled ? 2 : 12;
            int idleBackoffMaxMs = _sharedRingEnabled ? 24 : 80;
            try
            {
                while (!ct.IsCancellationRequested)
                {
                    bool ok = BlackbirdNative.GetEventRaw(_ioctlHandle, buffer, out uint bytes);
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
                        if (BlackbirdNative.TryParseIoctlEvent(managed, len, out var parsed))
                        {
                            Interlocked.Increment(ref _ioctlEvents);
                            DiagnosticsState.Increment("IOCTL Events");
                            IoctlEvent?.Invoke(parsed);
                        }
                        idleBackoffMs = _sharedRingEnabled ? 2 : 12;

                        continue;
                    }

                    int err = Marshal.GetLastWin32Error();
                    if (err == BlackbirdNative.ErrorNoMoreEntries)
                    {
                        Interlocked.Increment(ref _ioctlEmptyPolls);
                        ct.WaitHandle.WaitOne(idleBackoffMs);
                        idleBackoffMs = Math.Min(idleBackoffMaxMs, idleBackoffMs + 4);
                        continue;
                    }

                    if (err == BlackbirdNative.ErrorOperationAborted || err == BlackbirdNative.ErrorNotReady ||
                        err == BlackbirdNative.ErrorDeviceNotConnected || err == BlackbirdNative.ErrorBrokenPipe)
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
                bool ok = BlackbirdNative.GetEtwEvent(_etwHandle, out var etw, 500);
                if (ok)
                {
                    Interlocked.Increment(ref _etwEvents);
                    DiagnosticsState.Increment("ETW Events");
                    if (etw.Source == BlackbirdNative.IpcEtwSourceThreatIntel)
                    {
                        DiagnosticsState.Increment("ETW ThreatIntel Events");
                    }
                    EtwEvent?.Invoke(etw);
                    continue;
                }

                int err = Marshal.GetLastWin32Error();
                if (err == BlackbirdNative.ErrorNoMoreItems)
                {
                    Interlocked.Increment(ref _etwEmptyPolls);
                    continue;
                }

                if (err == BlackbirdNative.ErrorOperationAborted || err == BlackbirdNative.ErrorNotReady ||
                    err == BlackbirdNative.ErrorDeviceNotConnected || err == BlackbirdNative.ErrorBrokenPipe)
                {
                    Status?.Invoke($"ETW pump stopped (err={err})");
                    DiagnosticsState.SetValue("ETW Pump", $"Stopped err={err}");
                    return;
                }

                if (err == BlackbirdNative.ErrorNotSupported || err == BlackbirdNative.ErrorInvalidFunction)
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
                if (BlackbirdNative.GetStats(_ioctlHandle, out var stats, out _))
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
                        IoctlReadBufferBytes = BlackbirdNative.EventReadBufferBytes,
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
                _ = BlackbirdNative.CloseControlDevice(_ioctlHandle);
                _ioctlHandle = IntPtr.Zero;
            }

            if (_etwHandle != IntPtr.Zero && _etwHandle != new IntPtr(-1))
            {
                _ = BlackbirdNative.CloseControlDevice(_etwHandle);
                _etwHandle = IntPtr.Zero;
            }
        }
    }
}
