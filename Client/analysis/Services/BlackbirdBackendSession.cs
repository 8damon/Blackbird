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
        private readonly IntPtr _seedHandle;
        private readonly CancellationTokenSource _cts = new();

        private Task? _ioctlTask;
        private Task? _etwTask;
        private Task? _statsTask;
        private IntPtr _controlHandle;
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
        private string _lastTempusSummary = string.Empty;

        public event Action<IoctlParsedEvent>? IoctlEvent;
        public event Action<BlackbirdNative.BkIpcEtwEvent>? EtwEvent;
        public event Action<BackendStatsView>? Stats;
        public event Action<BackendIpcDiagnosticsView>? IpcDiagnostics;
        public event Action<string>? Status;

        public int TargetPid => _targetPid;

        public bool ControlProcessExecution(uint processId, bool suspend)
        {
            IntPtr handle = _controlHandle;
            if (handle == IntPtr.Zero || handle == new IntPtr(-1))
            {
                return false;
            }
            return BlackbirdNative.ControlProcessExecution(handle, processId, suspend);
        }

        private BlackbirdBackendSession(int targetPid, uint streamMask, bool useUsermodeHooks, IntPtr seedHandle = default)
        {
            _targetPid = targetPid;
            _streamMask = streamMask;
            _useUsermodeHooks = useUsermodeHooks;
            _seedHandle = seedHandle;
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

        public static BlackbirdBackendSession StartFromHandle(int targetPid, uint streamMask, bool useUsermodeHooks, IntPtr controlHandle)
        {
            if (targetPid <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(targetPid));
            }
            if (controlHandle == IntPtr.Zero || controlHandle == new IntPtr(-1))
            {
                throw new ArgumentException("Invalid control handle.", nameof(controlHandle));
            }

            var session = new BlackbirdBackendSession(targetPid, streamMask, useUsermodeHooks, controlHandle);
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

                if (_seedHandle != IntPtr.Zero && _seedHandle != new IntPtr(-1))
                {
                    _controlHandle = _seedHandle;
                }
                else
                {
                    if (!BlackbirdControlDeviceSession.TryOpen(out var control, out string error, ensureClientProtocol: false))
                    {
                        throw new InvalidOperationException(error);
                    }

                    using (control)
                    {
                        _controlHandle = control.DetachHandle();
                    }
                }

                var pids = new[] { (uint)_targetPid };
                if (!BlackbirdNative.SetPids(_controlHandle, pids, 1, _streamMask))
                {
                    throw BlackbirdNative.LastError("SetPids failed");
                }

                if (BlackbirdNative.GetBrokerInfo(out uint capabilities, out _))
                {
                    _brokerCapabilities = capabilities;
                }
                _sharedRingError = BlackbirdNative.GetLastSharedRingError();

                bool hasIoctlRing = false;
                bool hasEtwRing = false;
                if (BlackbirdNative.HasSharedChannel(_controlHandle, out bool ioctlReady, out bool etwReady))
                {
                    hasIoctlRing = ioctlReady;
                    hasEtwRing = etwReady;
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
                DiagnosticsState.SetValue("IPC Shared Ring", $"enabled={_sharedRingEnabled} ioctl={hasIoctlRing} etw={hasEtwRing} err={_sharedRingError}");
                DiagnosticsState.SetValue("Interface->Controller IPC", _sharedRingEnabled ? "Ready (shared ring + events)" : $"Degraded err={_sharedRingError}");
                DiagnosticsState.SetValue("Controller<->Driver Comms", "Ready");
                Console.WriteLine($"[Session] Started  pid={_targetPid} stream=0x{_streamMask:X8} caps=0x{_brokerCapabilities:X8} sharedRing={_sharedRingEnabled} hooks={_useUsermodeHooks}");

                _ioctlTask = Task.Run(() => IoctlPump(_cts.Token));
                _etwTask = Task.Run(() => EtwPump(_cts.Token));
                _statsTask = Task.Run(() => StatsPump(_cts.Token));
            }
            catch
            {
                CleanupHandle();
                throw;
            }
        }

        private void IoctlPump(CancellationToken ct)
        {
            IntPtr buffer = Marshal.AllocHGlobal(BlackbirdNative.EventReadBufferBytes);
            byte[] managed = new byte[BlackbirdNative.EventReadBufferBytes];
            try
            {
                while (!ct.IsCancellationRequested)
                {
                    // Block up to 100ms for data on the shared ring event handle.
                    bool ok = BlackbirdNative.GetEventWait(_controlHandle, buffer, out uint bytes, 100);
                    if (ok)
                    {
                        // Process this record, then drain any additional records without waiting.
                        do
                        {
                            int len = (int)Math.Min(bytes, (uint)managed.Length);
                            if (len > 0)
                            {
                                Marshal.Copy(buffer, managed, 0, len);
                                if (BlackbirdNative.TryParseIoctlEvent(managed, len, out var parsed))
                                {
                                    Interlocked.Increment(ref _ioctlEvents);
                                    DiagnosticsState.Increment("IOCTL Events");
                                    IoctlEvent?.Invoke(parsed);
                                }
                            }
                            ok = BlackbirdNative.GetEventRaw(_controlHandle, buffer, out bytes);
                        }
                        while (ok && !ct.IsCancellationRequested);

                        int drainErr = Marshal.GetLastWin32Error();
                        if (drainErr != BlackbirdNative.ErrorNoMoreEntries &&
                            drainErr != BlackbirdNative.ErrorNoMoreItems &&
                            (drainErr == BlackbirdNative.ErrorOperationAborted ||
                             drainErr == BlackbirdNative.ErrorNotReady ||
                             drainErr == BlackbirdNative.ErrorDeviceNotConnected ||
                             drainErr == BlackbirdNative.ErrorBrokenPipe))
                        {
                            Status?.Invoke($"IOCTL pump stopped (err={drainErr})");
                            DiagnosticsState.SetValue("IOCTL Pump", $"Stopped err={drainErr}");
                            DiagnosticsState.SetValue("Controller<->Driver Comms", $"Stopped err={drainErr}");
                            Console.WriteLine($"[Session] IOCTL pump stopped  pid={_targetPid} err={drainErr}");
                            break;
                        }
                        continue;
                    }

                    int err = Marshal.GetLastWin32Error();
                    if (err == BlackbirdNative.ErrorNoMoreEntries || err == BlackbirdNative.ErrorNoMoreItems)
                    {
                        // Timeout — no data in 100ms window; loop back to wait again.
                        Interlocked.Increment(ref _ioctlEmptyPolls);
                        continue;
                    }

                    if (err == BlackbirdNative.ErrorOperationAborted || err == BlackbirdNative.ErrorNotReady ||
                        err == BlackbirdNative.ErrorDeviceNotConnected || err == BlackbirdNative.ErrorBrokenPipe)
                    {
                        Status?.Invoke($"IOCTL pump stopped (err={err})");
                        DiagnosticsState.SetValue("IOCTL Pump", $"Stopped err={err}");
                        DiagnosticsState.SetValue("Controller<->Driver Comms", $"Stopped err={err}");
                        Console.WriteLine($"[Session] IOCTL pump stopped  pid={_targetPid} err={err}");
                        break;
                    }

                    Interlocked.Increment(ref _ioctlErrors);
                    DiagnosticsState.Increment("IOCTL Errors");
                    DiagnosticsState.SetValue("IOCTL LastError", err.ToString());
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
                bool ok = BlackbirdNative.GetEtwEvent(_controlHandle, out var etw, 500);
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
                    DiagnosticsState.SetValue("ETW Status", $"Stopped err={err}");
                    Console.WriteLine($"[Session] ETW pump stopped  pid={_targetPid} err={err}");
                    return;
                }

                if (err == BlackbirdNative.ErrorNotSupported || err == BlackbirdNative.ErrorInvalidFunction)
                {
                    Status?.Invoke("ETW uplink unsupported by active controller build");
                    DiagnosticsState.SetValue("ETW Pump", "Unsupported");
                    DiagnosticsState.SetValue("ETW Status", "Unsupported");
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
                if (BlackbirdNative.GetStats(_controlHandle, out var stats, out _))
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

                    DiagnosticsState.SetValue("Driver Queue", $"subs={stats.SubscriptionCount} depth={stats.QueueDepth} dropped={stats.DroppedEvents}");
                    DiagnosticsState.SetValue("Controller<->Driver Comms", $"OK depth={stats.QueueDepth} dropped={stats.DroppedEvents}");
                    string tempusSummary = BuildTempusSummary(stats);
                    if (!string.IsNullOrWhiteSpace(tempusSummary))
                    {
                        DiagnosticsState.SetValue("Tempus", tempusSummary);
                        if (!string.Equals(_lastTempusSummary, tempusSummary, StringComparison.Ordinal))
                        {
                            _lastTempusSummary = tempusSummary;
                            Console.WriteLine($"[Tempus] {tempusSummary}");
                        }
                    }
                }

                ct.WaitHandle.WaitOne(2000);
            }
        }

        public void Dispose()
        {
            _cts.Cancel();

            // Wait for pump tasks to observe cancellation before closing the handle.
            // The event-driven IOCTL pump blocks in WaitForSingleObject with a 100ms timeout,
            // so it will exit within one timeout interval after cancellation is set.
            try
            {
                _ioctlTask?.Wait(500);
            }
            catch
            {
            }

            try
            {
                _etwTask?.Wait(500);
            }
            catch
            {
            }

            try
            {
                _statsTask?.Wait(500);
            }
            catch
            {
            }

            CleanupHandle();
            _cts.Dispose();
            Status?.Invoke("Session disposed");
            Console.WriteLine($"[Session] Disposed  pid={_targetPid} ioctlEvents={Interlocked.Read(ref _ioctlEvents)} etwEvents={Interlocked.Read(ref _etwEvents)} ioctlErrors={Interlocked.Read(ref _ioctlErrors)} etwErrors={Interlocked.Read(ref _etwErrors)}");
        }

        private void CleanupHandle()
        {
            if (_controlHandle != IntPtr.Zero && _controlHandle != new IntPtr(-1))
            {
                _ = BlackbirdNative.CloseControlDevice(_controlHandle);
                _controlHandle = IntPtr.Zero;
            }
        }

        private static string BuildTempusSummary(BlackbirdNative.BkStatsResponse stats)
        {
            if (stats.TempusEnabled == 0 || stats.Tempus is null || stats.Tempus.Length == 0 || stats.TempusQpcFrequency == 0)
            {
                return string.Empty;
            }

            int count = (int)Math.Min(stats.TempusSubsystemCount, (uint)stats.Tempus.Length);
            ulong bestTotal = 0;
            ulong bestAvg = 0;
            ulong bestMax = 0;
            ulong bestSamples = 0;
            int bestIndex = -1;

            for (int i = 0; i < count; i += 1)
            {
                BlackbirdNative.BkTempusBucket bucket = stats.Tempus[i];
                if (bucket.SampleCount == 0 || bucket.TotalQpc == 0)
                {
                    continue;
                }

                ulong avg = bucket.TotalQpc / bucket.SampleCount;
                if (bucket.TotalQpc > bestTotal)
                {
                    bestTotal = bucket.TotalQpc;
                    bestAvg = avg;
                    bestMax = bucket.MaxQpc;
                    bestSamples = bucket.SampleCount;
                    bestIndex = i;
                }
            }

            if (bestIndex < 0)
            {
                return string.Empty;
            }

            double avgMs = bestAvg * 1000.0 / stats.TempusQpcFrequency;
            double maxMs = bestMax * 1000.0 / stats.TempusQpcFrequency;
            return $"{TempusName(bestIndex)} avg={avgMs:0.###}ms max={maxMs:0.###}ms samples={bestSamples}";
        }

        private static string TempusName(int index)
        {
            return index switch
            {
                0 => "driver",
                1 => "control",
                2 => "etw",
                3 => "handle",
                4 => "thread",
                5 => "process",
                6 => "image",
                7 => "registry",
                8 => "filesystem",
                9 => "apc",
                10 => "correlation",
                11 => "hollowing",
                12 => "ntapi",
                13 => "anti-tamper",
                _ => $"bucket-{index}"
            };
        }
    }
}
