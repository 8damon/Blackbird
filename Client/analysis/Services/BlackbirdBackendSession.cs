using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace BlackbirdInterface
{
    internal sealed class BlackbirdBackendSession : IDisposable
    {
        private const uint ControllerSubscriptionSoftLimit = 4096;
        private readonly int _targetPid;
        private readonly uint _streamMask;
        private readonly bool _useUsermodeHooks;
        private readonly bool _useKernelDriver;
        private readonly IntPtr _seedHandle;
        private readonly CancellationTokenSource _cts = new();

        private Task? _ioctlTask;
        private Task? _etwTask;
        private Task? _statsTask;
        private readonly object _commandLock = new();
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
        private ulong _lastDriverDiagSequence;
        private int _disposed;
        private int _cleanupFinalized;

        public event Action<IoctlParsedEvent>? IoctlEvent;
        public event Action<BlackbirdNative.BkIpcEtwEvent>? EtwEvent;
        public event Action<BackendStatsView>? Stats;
        public event Action<BackendIpcDiagnosticsView>? IpcDiagnostics;
        public event Action<string>? Status;

        public int TargetPid => _targetPid;

        public bool ControlProcessExecution(uint processId, bool suspend)
        {
            lock (_commandLock)
            {
                IntPtr handle = _controlHandle;
                if (handle == IntPtr.Zero || handle == new IntPtr(-1))
                {
                    return false;
                }
                if (_useKernelDriver && BlackbirdNative.ControlProcessExecution(handle, processId, suspend))
                {
                    return true;
                }
                if (_useKernelDriver && !IsDriverUnavailableError(Marshal.GetLastWin32Error()))
                {
                    return false;
                }
            }

            return TryControlProcessExecutionUserMode(processId, suspend);
        }

        internal static bool TryControlProcessExecutionUserMode(uint processId, bool suspend)
        {
            const uint ProcessSuspendResume = 0x0800;
            const uint ProcessQueryLimitedInformation = 0x1000;

            if (processId == 0)
            {
                return false;
            }

            IntPtr processHandle =
                Kernel32Native.OpenProcess(ProcessSuspendResume | ProcessQueryLimitedInformation, false, processId);
            if (processHandle == IntPtr.Zero || processHandle == new IntPtr(-1))
            {
                int err = Marshal.GetLastWin32Error();
                DiagnosticsState.SetValue(
                    "Process Control",
                    $"UserAPI failed pid={processId} action={(suspend ? "suspend" : "resume")} err={err}");
                return false;
            }

            try
            {
                int status = suspend ? Kernel32Native.NtSuspendProcess(processHandle)
                                     : Kernel32Native.NtResumeProcess(processHandle);
                if (status >= 0)
                {
                    DiagnosticsState.SetValue("Process Control",
                                              $"UserAPI ok pid={processId} action={(suspend ? "suspend" : "resume")}");
                    return true;
                }

                DiagnosticsState.SetValue(
                    "Process Control",
                    $"UserAPI failed pid={processId} action={(suspend ? "suspend" : "resume")} ntstatus=0x{unchecked((uint)status):X8}");
                return false;
            }
            finally
            {
                _ = Kernel32Native.CloseHandle(processHandle);
            }
        }

        private static bool IsDriverUnavailableError(int win32)
        {
            return win32 == BlackbirdNative.ErrorDeviceNotConnected || win32 == BlackbirdNative.ErrorNotSupported ||
                   win32 == BlackbirdNative.ErrorInvalidFunction || win32 == BlackbirdNative.ErrorBrokenPipe ||
                   win32 == BlackbirdNative.ErrorOperationAborted || win32 == BlackbirdNative.ErrorNotReady;
        }

        private BlackbirdBackendSession(int targetPid, uint streamMask, bool useUsermodeHooks, bool useKernelDriver,
                                        IntPtr seedHandle = default)
        {
            _targetPid = targetPid;
            _streamMask = useKernelDriver ? streamMask : streamMask | BlackbirdNative.StreamUsermodeOnly;
            _useUsermodeHooks = useUsermodeHooks;
            _useKernelDriver = useKernelDriver;
            _seedHandle = seedHandle;
        }

        public static BlackbirdBackendSession Start(int targetPid, uint streamMask, bool useUsermodeHooks,
                                                    bool useKernelDriver = true)
        {
            if (targetPid <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(targetPid));
            }

            var session = new BlackbirdBackendSession(targetPid, streamMask, useUsermodeHooks, useKernelDriver);
            session.StartInternal();
            return session;
        }

        public static BlackbirdBackendSession StartFromHandle(int targetPid, uint streamMask, bool useUsermodeHooks,
                                                              IntPtr controlHandle, bool useKernelDriver = true)
        {
            if (targetPid <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(targetPid));
            }
            if (controlHandle == IntPtr.Zero || controlHandle == new IntPtr(-1))
            {
                throw new ArgumentException("Invalid control handle.", nameof(controlHandle));
            }

            var session =
                new BlackbirdBackendSession(targetPid, streamMask, useUsermodeHooks, useKernelDriver, controlHandle);
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
                    if (!BkctlDeviceSession.TryOpen(out var control, out string error, ensureClientProtocol: false))
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
                }

                bool driverAvailable = (_brokerCapabilities & BlackbirdNative.IpcCapDriverProxy) != 0;
                Status?.Invoke(_useKernelDriver && driverAvailable
                                   ? $"Session started for PID {_targetPid}"
                                   : $"Driverless session started for PID {_targetPid}");
                if (_useUsermodeHooks)
                {
                    Status?.Invoke("Usermode hooks enabled: waiting for hook publisher events.");
                }
                if (!_useKernelDriver || !driverAvailable)
                {
                    Status?.Invoke("KM driver telemetry unavailable; using SR71, ETW, and user-mode API fallbacks.");
                }
                DiagnosticsState.SetValue("Session", $"pid={_targetPid} stream=0x{_streamMask:X8}");
                DiagnosticsState.SetValue("IPC Mode", _sharedRingEnabled ? "SharedRing+Event" : "Pipe+Event");
                DiagnosticsState.SetValue(
                    "IPC Shared Ring",
                    $"enabled={_sharedRingEnabled} ioctl={hasIoctlRing} etw={hasEtwRing} err={_sharedRingError}");
                DiagnosticsState.SetValue("Interface->Controller IPC", _sharedRingEnabled
                                                                           ? "Ready (shared ring + events)"
                                                                           : "Ready (pipe + events)");
                DiagnosticsState.SetValue("Controller<->Driver Comms",
                                          _useKernelDriver && driverAvailable ? "Ready" : "Driverless mode");
                DiagnosticsState.SetValue(
                    "KM Driver", _useKernelDriver ? (driverAvailable ? "Enabled" : "Unavailable; driverless fallback")
                                                  : "Driverless mode");
                Console.WriteLine(
                    $"[Session] Started  pid={_targetPid} stream=0x{_streamMask:X8} caps=0x{_brokerCapabilities:X8} sharedRing={_sharedRingEnabled} hooks={_useUsermodeHooks} kernelDriver={_useKernelDriver} driverAvailable={driverAvailable}");

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
                    bool ok = BlackbirdNative.GetEventWait(_controlHandle, buffer, out uint bytes, 100);
                    if (ok)
                    {
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
                        } while (ok && !ct.IsCancellationRequested);

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

        private bool TryGetStatsSnapshot(out BlackbirdNative.BkStatsResponse stats, bool skipIfBusy)
        {
            stats = default;
            bool entered;
            if (skipIfBusy)
            {
                entered = Monitor.TryEnter(_commandLock);
                if (!entered)
                {
                    return false;
                }
            }
            else
            {
                Monitor.Enter(_commandLock);
                entered = true;
            }

            try
            {
                IntPtr handle = _controlHandle;
                if (handle == IntPtr.Zero || handle == new IntPtr(-1))
                {
                    return false;
                }
                return BlackbirdNative.GetStats(handle, out stats, out _);
            }
            finally
            {
                if (entered)
                {
                    Monitor.Exit(_commandLock);
                }
            }
        }

        private bool TryGetHealthSnapshot(out BlackbirdNative.BkHealthResponse health)
        {
            health = default;
            lock (_commandLock)
            {
                IntPtr handle = _controlHandle;
                if (handle == IntPtr.Zero || handle == new IntPtr(-1))
                {
                    return false;
                }
                return BlackbirdNative.GetHealth(handle, out health, out _);
            }
        }

        private bool TryGetDiagnosticsSnapshot(out BlackbirdNative.BkDiagnosticsResponse diagnostics)
        {
            diagnostics = default;
            lock (_commandLock)
            {
                IntPtr handle = _controlHandle;
                if (handle == IntPtr.Zero || handle == new IntPtr(-1))
                {
                    return false;
                }
                return BlackbirdNative.GetDiagnostics(handle, out diagnostics, out _);
            }
        }

        private void StatsPump(CancellationToken ct)
        {
            while (!ct.IsCancellationRequested)
            {
                if (TryGetStatsSnapshot(out var stats, skipIfBusy: true))
                {
                    if (BlackbirdNative.GetBrokerInfo(out uint refreshedCapabilities, out _))
                    {
                        _brokerCapabilities = refreshedCapabilities;
                        if (_sharedRingEnabled)
                        {
                            _brokerCapabilities |= BlackbirdNative.IpcCapSharedRing;
                        }
                    }
                    bool driverAvailable =
                        _useKernelDriver && (_brokerCapabilities & BlackbirdNative.IpcCapDriverProxy) != 0;
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

                    Stats?.Invoke(
                        new BackendStatsView { TimestampUtc = now, SubscriptionCount = stats.SubscriptionCount,
                                               QueueDepth = stats.QueueDepth, DroppedEvents = stats.DroppedEvents });

                    IpcDiagnostics?.Invoke(new BackendIpcDiagnosticsView {
                        TimestampUtc = now, BrokerCapabilities = _brokerCapabilities,
                        SharedRingEnabled = _sharedRingEnabled, SharedRingError = _sharedRingError,
                        IoctlReadBufferBytes = BlackbirdNative.EventReadBufferBytes,
                        SubscriptionCount = stats.SubscriptionCount, DriverQueueDepth = stats.QueueDepth,
                        DriverDroppedEvents = stats.DroppedEvents, IoctlEventsTotal = ioctlTotal,
                        EtwEventsTotal = etwTotal, IoctlErrorsTotal = Interlocked.Read(ref _ioctlErrors),
                        EtwErrorsTotal = Interlocked.Read(ref _etwErrors),
                        IoctlEmptyPolls = Interlocked.Read(ref _ioctlEmptyPolls),
                        EtwEmptyPolls = Interlocked.Read(ref _etwEmptyPolls), IoctlEventsPerSec = ioctlDelta / elapsed,
                        EtwEventsPerSec = etwDelta / elapsed
                    });

                    _lastStatsSnapshotUtc = now;
                    _lastStatsIoctlEvents = ioctlTotal;
                    _lastStatsEtwEvents = etwTotal;

                    string pidCoverage = BuildPidCoverageSummary(stats.SubscriptionCount);
                    string queueSummary =
                        BuildQueueSummary(stats.SubscriptionCount, stats.QueueDepth, stats.DroppedEvents);
                    DiagnosticsState.SetValue("PID Coverage", pidCoverage);
                    DiagnosticsState.SetValue("Driver Queue", driverAvailable ? queueSummary : "Driverless mode");
                    DiagnosticsState.SetValue("SR71 Hook Ready",
                                              BuildHookReadySummary(stats.HookReadyMask, stats.HookReadyRequiredMask));
                    DiagnosticsState.SetValue(
                        "SR71 Instrumentation",
                        BuildInstrumentationSummary(stats.InstrumentationRangeCount, stats.HookPatchCount,
                                                    stats.HookPatchOverlayCount, stats.InstrumentationReadDenyCount,
                                                    stats.HookReadyMask, stats.HookReadyRequiredMask));
                    DiagnosticsState.SetValue("Ntdll Mirror",
                                              BuildNtdllMirrorSummary(stats.DuplicateNtdllMirrorCount,
                                                                      stats.DuplicateNtdllMirrorFailureCount));
                    DiagnosticsState.SetValue(
                        "Controller<->Driver Comms",
                        driverAvailable ? (stats.DroppedEvents != 0
                                               ? $"DEGRADED depth={stats.QueueDepth} dropped={stats.DroppedEvents}"
                                               : $"OK depth={stats.QueueDepth} dropped={stats.DroppedEvents}")
                                        : "Driverless mode");
                    if (ct.IsCancellationRequested)
                    {
                        break;
                    }
                    if (!driverAvailable)
                    {
                        DiagnosticsState.SetValue("Driver Health", "Unavailable (driverless mode)");
                        DiagnosticsState.SetValue("Driver Diagnostics", "Unavailable (driverless mode)");
                    }
                    else if (TryGetHealthSnapshot(out var health))
                    {
                        DiagnosticsState.SetValue("Driver Health", BuildDriverHealthSummary(health.HealthMask));
                        DiagnosticsState.SetValue("Driver Tamper", health.TamperMask == 0
                                                                       ? "OK mask=0x00000000"
                                                                       : $"DEGRADED mask=0x{health.TamperMask:X8}");
                    }
                    else
                    {
                        DiagnosticsState.SetValue("Driver Health", $"Unavailable err={Marshal.GetLastWin32Error()}");
                    }
                    if (ct.IsCancellationRequested)
                    {
                        break;
                    }
                    if (driverAvailable && TryGetDiagnosticsSnapshot(out var diagnostics))
                    {
                        ProcessDriverDiagnostics(diagnostics);
                    }
                    else if (driverAvailable)
                    {
                        DiagnosticsState.SetValue("Driver Diagnostics",
                                                  $"Unavailable err={Marshal.GetLastWin32Error()}");
                    }
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
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
            {
                return;
            }

            _cts.Cancel();
            Task[] pumpTasks = SnapshotPumpTasks();
            if (!WaitForPumpTasks(pumpTasks, 6500))
            {
                DiagnosticsState.SetValue("Session Dispose", "Deferred waiting for pump tasks");
                Console.WriteLine(
                    $"[Session] Dispose deferred pid={_targetPid} reason=pump-active ioctlDone={_ioctlTask?.IsCompleted ?? true} etwDone={_etwTask?.IsCompleted ?? true} statsDone={_statsTask?.IsCompleted ?? true}");
                _ = Task.WhenAll(pumpTasks).ContinueWith(
                    _ => FinalizeCleanup("deferred"), CancellationToken.None,
                    TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
                return;
            }

            FinalizeCleanup("disposed");
        }

        private Task[] SnapshotPumpTasks()
        {
            var tasks = new List<Task>(3);
            if (_ioctlTask != null)
            {
                tasks.Add(_ioctlTask);
            }
            if (_etwTask != null)
            {
                tasks.Add(_etwTask);
            }
            if (_statsTask != null)
            {
                tasks.Add(_statsTask);
            }
            return tasks.ToArray();
        }

        private static bool WaitForPumpTasks(Task[] tasks, int timeoutMs)
        {
            if (tasks.Length == 0)
            {
                return true;
            }

            try
            {
                return Task.WaitAll(tasks, timeoutMs);
            }
            catch
            {
                foreach (Task task in tasks)
                {
                    if (!task.IsCompleted)
                    {
                        return false;
                    }
                }
                return true;
            }
        }

        private void FinalizeCleanup(string mode)
        {
            if (Interlocked.Exchange(ref _cleanupFinalized, 1) != 0)
            {
                return;
            }
            CleanupHandle();
            _cts.Dispose();
            DiagnosticsState.SetValue("Session Dispose", mode);
            Console.WriteLine(
                $"[Session] Disposed  pid={_targetPid} mode={mode} ioctlEvents={Interlocked.Read(ref _ioctlEvents)} etwEvents={Interlocked.Read(ref _etwEvents)} ioctlErrors={Interlocked.Read(ref _ioctlErrors)} etwErrors={Interlocked.Read(ref _etwErrors)}");
        }

        private void CleanupHandle()
        {
            lock (_commandLock)
            {
                if (_controlHandle != IntPtr.Zero && _controlHandle != new IntPtr(-1))
                {
                    uint[] emptyPids = Array.Empty<uint>();
                    if (!BlackbirdNative.SetPids(_controlHandle, emptyPids, 0, _streamMask))
                    {
                        Console.WriteLine(
                            $"[Session] Clear subscriptions before close failed pid={_targetPid} err={Marshal.GetLastWin32Error()}");
                    }
                    _ = BlackbirdNative.CloseControlDevice(_controlHandle);
                    _controlHandle = IntPtr.Zero;
                }
            }
        }

        private void ProcessDriverDiagnostics(BlackbirdNative.BkDiagnosticsResponse diagnostics)
        {
            PublishDriverComponentDiagnostics(diagnostics);

            if (diagnostics.Events is null || diagnostics.EventCount == 0)
            {
                DiagnosticsState.SetValue("Driver Diagnostics", "OK no events");
                return;
            }

            if (_lastDriverDiagSequence != 0 && diagnostics.OldestSequence > _lastDriverDiagSequence + 1)
            {
                DiagnosticsState.SetValue(
                    "Driver Diagnostics",
                    $"DEGRADED missed events last={_lastDriverDiagSequence} oldest={diagnostics.OldestSequence} dropped={diagnostics.DroppedCount}");
            }

            int count = (int)Math.Min(diagnostics.EventCount, (uint)diagnostics.Events.Length);
            for (int i = 0; i < count; i += 1)
            {
                BlackbirdNative.BkDiagnosticEvent diag = diagnostics.Events[i];
                if (diag.Sequence == 0 || diag.Sequence <= _lastDriverDiagSequence)
                {
                    continue;
                }

                string summary = BuildDriverDiagnosticSummary(diag, diagnostics.QpcFrequency);
                Console.WriteLine($"[DriverDiag] {summary}");
                DiagnosticsState.SetValue($"Driver:{DriverDiagnosticSubsystemName(diag.SubsystemId)}", summary);
                DiagnosticsState.SetValue(
                    "Driver Diagnostics",
                    $"{DriverDiagnosticState(diag)} lastSeq={diag.Sequence} dropped={diagnostics.DroppedCount}");
                _lastDriverDiagSequence = Math.Max(_lastDriverDiagSequence, diag.Sequence);
            }
        }

        private static void PublishDriverComponentDiagnostics(BlackbirdNative.BkDiagnosticsResponse diagnostics)
        {
            if (diagnostics.Components is null || diagnostics.ComponentStateCount == 0)
            {
                return;
            }

            int count = (int)Math.Min(diagnostics.ComponentStateCount, (uint)diagnostics.Components.Length);
            int degraded = 0;
            for (int i = 0; i < count; i += 1)
            {
                BlackbirdNative.BkDiagnosticComponentState state = diagnostics.Components[i];
                string name = DriverDiagnosticComponentName(state.ComponentId);
                if (string.IsNullOrWhiteSpace(name))
                {
                    name = $"component-{state.ComponentId}";
                }

                string status = DriverComponentStateLabel(state);
                if (!status.Equals("OK", StringComparison.OrdinalIgnoreCase) &&
                    !status.Equals("Disabled", StringComparison.OrdinalIgnoreCase))
                {
                    degraded += 1;
                }

                DiagnosticsState.SetValue(
                    $"Driver Component:{name}",
                    $"{status} subsystem={DriverDiagnosticSubsystemName(state.SubsystemId)} component={name} flags=0x{state.Flags:X8} flagsText={BuildComponentFlagText(state.Flags)} status=0x{unchecked((uint)state.Status):X8} detail0=0x{state.Detail0:X} detail1=0x{state.Detail1:X}");
            }

            DiagnosticsState.SetValue(
                "Driver Components",
                degraded == 0 ? $"OK components={count}" : $"DEGRADED components={count} degraded={degraded}");
        }

        private static string DriverComponentStateLabel(BlackbirdNative.BkDiagnosticComponentState state)
        {
            if ((state.Flags & BlackbirdNative.DiagStatePolicyDisabled) != 0)
            {
                return "Disabled";
            }
            if ((state.Flags & BlackbirdNative.DiagStateDegraded) != 0 || state.Status < 0)
            {
                return "DEGRADED";
            }
            return (state.Flags & BlackbirdNative.DiagStateOnline) != 0 ? "OK" : "Awaiting";
        }

        private static string BuildComponentFlagText(uint flags)
        {
            var names = new List<string>(8);
            AddComponentFlag(names, flags, BlackbirdNative.DiagStateOnline, "online");
            AddComponentFlag(names, flags, BlackbirdNative.DiagStateRegistered, "registered");
            AddComponentFlag(names, flags, BlackbirdNative.DiagStateArmed, "armed");
            AddComponentFlag(names, flags, BlackbirdNative.DiagStateCallback, "callback");
            AddComponentFlag(names, flags, BlackbirdNative.DiagStateHook, "hook");
            AddComponentFlag(names, flags, BlackbirdNative.DiagStateRequired, "required");
            AddComponentFlag(names, flags, BlackbirdNative.DiagStateOptional, "optional");
            AddComponentFlag(names, flags, BlackbirdNative.DiagStateInstalled, "installed");
            AddComponentFlag(names, flags, BlackbirdNative.DiagStateResolved, "resolved");
            AddComponentFlag(names, flags, BlackbirdNative.DiagStatePolicyDisabled, "policy-disabled");
            AddComponentFlag(names, flags, BlackbirdNative.DiagStateDegraded, "degraded");
            AddComponentFlag(names, flags, BlackbirdNative.DiagStateSanitizes, "sanitizes");
            AddComponentFlag(names, flags, BlackbirdNative.DiagStateTelemetry, "telemetry");
            AddComponentFlag(names, flags, BlackbirdNative.DiagStateTamperActive, "tamper-active");
            AddComponentFlag(names, flags, BlackbirdNative.DiagStateFastPath, "fast-path");
            return names.Count == 0 ? "none" : string.Join("|", names);
        }

        private static void AddComponentFlag(ICollection<string> names, uint flags, uint bit, string name)
        {
            if ((flags & bit) != 0)
            {
                names.Add(name);
            }
        }

        private static string BuildDriverDiagnosticSummary(BlackbirdNative.BkDiagnosticEvent diag, ulong qpcFrequency)
        {
            string subsystem = DriverDiagnosticSubsystemName(diag.SubsystemId);
            string eventName = DriverDiagnosticEventName(diag.EventType);
            string component = DriverDiagnosticComponentName(diag.ComponentId);
            string elapsed = FormatDiagnosticElapsed(diag.ElapsedQpc, qpcFrequency);
            string state = DriverDiagnosticState(diag);
            uint status = unchecked((uint)diag.Status);

            var parts = new List<string>(8) { $"{state} seq={diag.Sequence}", $"{subsystem} {eventName}",
                                              $"status=0x{status:X8}" };
            if (!string.IsNullOrWhiteSpace(elapsed))
            {
                parts.Add($"elapsed={elapsed}");
            }
            if (diag.Flags != 0)
            {
                parts.Add($"flags=0x{diag.Flags:X8}");
            }
            if (diag.DetailCode != 0)
            {
                parts.Add($"detail=0x{diag.DetailCode:X8}");
            }
            if (!string.IsNullOrWhiteSpace(component))
            {
                parts.Add(component);
            }

            return string.Join(" ", parts);
        }

        private static string DriverDiagnosticState(BlackbirdNative.BkDiagnosticEvent diag)
        {
            if ((diag.Flags & BlackbirdNative.DiagFlagFailure) != 0 ||
                diag.EventType == BlackbirdNative.DiagEventInitFailed ||
                diag.EventType == BlackbirdNative.DiagEventSelfCheckFailed)
            {
                return "ERROR";
            }
            if (diag.EventType == BlackbirdNative.DiagEventDisabledByPolicy)
            {
                return (diag.Flags & BlackbirdNative.DiagFlagOptional) != 0 ? "OK" : "Disabled";
            }
            if (diag.EventType == BlackbirdNative.DiagEventOptionalMissingContinuing ||
                diag.EventType == BlackbirdNative.DiagEventDegradedContinuing)
            {
                return "DEGRADED";
            }

            return "OK";
        }

        private static string DriverDiagnosticEventName(uint eventType)
        {
            return eventType switch { BlackbirdNative.DiagEventInitBegin => "init-begin",
                                      BlackbirdNative.DiagEventInitOk => "init-ok",
                                      BlackbirdNative.DiagEventInitFailed => "init-failed",
                                      BlackbirdNative.DiagEventOnline => "online",
                                      BlackbirdNative.DiagEventConfirmedOnline => "confirmed-online",
                                      BlackbirdNative.DiagEventDisabledByPolicy => "disabled-by-policy",
                                      BlackbirdNative.DiagEventOptionalMissingContinuing =>
                                          "optional-missing-continuing",
                                      BlackbirdNative.DiagEventDisarmed => "disarmed",
                                      BlackbirdNative.DiagEventArmed => "armed",
                                      BlackbirdNative.DiagEventShutdownBegin => "shutdown-begin",
                                      BlackbirdNative.DiagEventShutdownOk => "shutdown-ok",
                                      BlackbirdNative.DiagEventSelfCheckFailed => "self-check-failed",
                                      BlackbirdNative.DiagEventDegradedContinuing => "degraded-continuing",
                                      _ => $"event-{eventType}" };
        }

        private static string DriverDiagnosticSubsystemName(uint subsystemId)
        {
            return TempusName((int)subsystemId);
        }

        private static string DriverDiagnosticComponentName(uint componentId)
        {
            return componentId switch { BlackbirdNative.DiagComponentDriverEntry => "driver-entry",
                                        BlackbirdNative.DiagComponentRuntimeConfig => "runtime-config",
                                        BlackbirdNative.DiagComponentEtw => "etw",
                                        BlackbirdNative.DiagComponentControl => "control",
                                        BlackbirdNative.DiagComponentCorrelation => "correlation",
                                        BlackbirdNative.DiagComponentHollowingEngine => "hollowing-engine",
                                        BlackbirdNative.DiagComponentApcMonitor => "apc-monitor",
                                        BlackbirdNative.DiagComponentProcessMonitor => "process-monitor",
                                        BlackbirdNative.DiagComponentImageMonitor => "image-monitor",
                                        BlackbirdNative.DiagComponentRegistryMonitor => "registry-monitor",
                                        BlackbirdNative.DiagComponentThreadMonitor => "thread-monitor",
                                        BlackbirdNative.DiagComponentFilesystemMonitor => "filesystem-monitor",
                                        BlackbirdNative.DiagComponentHandleMonitor => "handle-monitor",
                                        BlackbirdNative.DiagComponentNtApiMonitor => "ntapi-monitor",
                                        BlackbirdNative.DiagComponentAntiTamper => "anti-tamper",
                                        BlackbirdNative.DiagComponentDiagnostics => "diagnostics",
                                        0 => string.Empty,
                                        _ => $"component-{componentId}" };
        }

        private static string FormatDiagnosticElapsed(ulong elapsedQpc, ulong qpcFrequency)
        {
            if (elapsedQpc == 0 || qpcFrequency == 0)
            {
                return string.Empty;
            }

            double us = elapsedQpc * 1000000.0 / qpcFrequency;
            if (us < 1000.0)
            {
                return $"{us:0.#}us";
            }

            return $"{us / 1000.0:0.###}ms";
        }

        private static string BuildTempusSummary(BlackbirdNative.BkStatsResponse stats)
        {
            if (stats.TempusEnabled == 0 || stats.Tempus is null || stats.Tempus.Length == 0 ||
                stats.TempusQpcFrequency == 0)
            {
                return string.Empty;
            }

            int count = (int)Math.Min(stats.TempusSubsystemCount, (uint)stats.Tempus.Length);
            var top = new List<(int Index, ulong Total, ulong Avg, ulong Max, ulong Samples)>(3);

            for (int i = 0; i < count; i += 1)
            {
                BlackbirdNative.BkTempusBucket bucket = stats.Tempus[i];
                if (bucket.SampleCount == 0 || bucket.TotalQpc == 0)
                {
                    continue;
                }

                ulong avg = bucket.TotalQpc / bucket.SampleCount;
                int insertAt = top.Count;
                for (int slot = 0; slot < top.Count; slot += 1)
                {
                    if (bucket.TotalQpc > top[slot].Total)
                    {
                        insertAt = slot;
                        break;
                    }
                }

                if (insertAt < 3)
                {
                    top.Insert(insertAt, (i, bucket.TotalQpc, avg, bucket.MaxQpc, bucket.SampleCount));
                    if (top.Count > 3)
                    {
                        top.RemoveAt(top.Count - 1);
                    }
                }
            }

            if (top.Count == 0)
            {
                return string.Empty;
            }

            var parts = new List<string>(top.Count);
            foreach (var item in top)
            {
                double avgMs = item.Avg * 1000.0 / stats.TempusQpcFrequency;
                double maxMs = item.Max * 1000.0 / stats.TempusQpcFrequency;
                parts.Add($"{TempusName(item.Index)} avg={avgMs:0.###}ms max={maxMs:0.###}ms samples={item.Samples}");
            }

            return string.Join(" | ", parts);
        }

        private static string BuildPidCoverageSummary(uint subscriptionCount)
        {
            if (subscriptionCount >= ControllerSubscriptionSoftLimit)
            {
                return $"ERROR saturated subs={subscriptionCount} cap={ControllerSubscriptionSoftLimit}";
            }

            if (subscriptionCount >= (ControllerSubscriptionSoftLimit * 3u) / 4u)
            {
                return $"DEGRADED expanding subs={subscriptionCount} cap={ControllerSubscriptionSoftLimit}";
            }

            return $"OK subs={subscriptionCount} cap={ControllerSubscriptionSoftLimit}";
        }

        private static string BuildQueueSummary(uint subscriptionCount, uint queueDepth, uint droppedEvents)
        {
            if (droppedEvents != 0 || queueDepth >= 2048)
            {
                return $"DEGRADED subs={subscriptionCount} depth={queueDepth} dropped={droppedEvents}";
            }

            return $"OK subs={subscriptionCount} depth={queueDepth} dropped={droppedEvents}";
        }

        internal static string BuildHookReadySummary(uint observedMask, uint requiredMask)
        {
            if (requiredMask == 0)
            {
                string observedNames = FormatMaskNames(BuildHookReadyMaskLabels(observedMask));
                return observedMask == 0
                           ? "Awaiting target resume mask=0x00000000 required=0x00000000 missing=0x00000000"
                           : $"Active mask=0x{observedMask:X8} required=0x00000000 missing=0x00000000 present={observedNames}";
            }

            uint missing = requiredMask & ~observedMask;
            string presentNames = FormatMaskNames(BuildHookReadyMaskLabels(observedMask & requiredMask));
            string missingNames = FormatMaskNames(BuildHookReadyMaskLabels(missing));
            if (missing == 0)
            {
                return $"OK mask=0x{observedMask:X8} required=0x{requiredMask:X8} missing=0x00000000 present={presentNames}";
            }

            string state = observedMask == 0 ? "Awaiting target resume" : "Awaiting hook-ready";
            return $"{state} mask=0x{observedMask:X8} required=0x{requiredMask:X8} missing=0x{missing:X8} missingNames={missingNames} present={presentNames}";
        }

        internal static string BuildInstrumentationSummary(uint ranges, uint patches, ulong overlays, ulong deniedReads,
                                                           uint hookReadyMask = 0, uint hookReadyRequiredMask = 0)
        {
            bool hookReady =
                hookReadyRequiredMask != 0 && (hookReadyMask & hookReadyRequiredMask) == hookReadyRequiredMask;
            bool observedInstrumentation = ranges != 0 || patches != 0 || overlays != 0;
            string state = observedInstrumentation || hookReady
                               ? "OK"
                               : hookReadyMask == 0 ? "Awaiting target resume" : "Awaiting hook-ready";
            return
                $"{state} ranges={ranges} patches={patches} overlays={overlays} deniedReads={deniedReads} hookMask=0x{hookReadyMask:X8} required=0x{hookReadyRequiredMask:X8}";
        }

        private static string BuildNtdllMirrorSummary(ulong mirrored, ulong failed)
        {
            string state = failed == 0 ? "OK" : "DEGRADED";
            return $"{state} mirrored={mirrored} failures={failed}";
        }

        internal static string BuildDriverHealthSummary(uint mask)
        {
            const uint required = BlackbirdNative.HealthControlReady | BlackbirdNative.HealthEtwReady |
                                  BlackbirdNative.HealthHandleMonitorReady | BlackbirdNative.HealthThreadMonitorReady |
                                  BlackbirdNative.HealthProcessMonitorReady | BlackbirdNative.HealthImageMonitorReady |
                                  BlackbirdNative.HealthRegistryMonitorReady | BlackbirdNative.HealthApcMonitorReady |
                                  BlackbirdNative.HealthFileSystemMonitorReady |
                                  BlackbirdNative.HealthCorrelationReady | BlackbirdNative.HealthHollowingEngineReady |
                                  BlackbirdNative.HealthNtApiMonitorReady | BlackbirdNative.HealthAntiTamperReady |
                                  BlackbirdNative.HealthDiagnosticsReady;

            uint missing = required & ~mask;
            string presentNames = FormatMaskNames(BuildDriverHealthMaskLabels(mask & required));
            string missingNames = FormatMaskNames(BuildDriverHealthMaskLabels(missing));
            return missing == 0
                       ? $"OK mask=0x{mask:X8} required=0x{required:X8} missing=0x00000000 present={presentNames}"
                       : $"DEGRADED mask=0x{mask:X8} required=0x{required:X8} missing=0x{missing:X8} missingNames={missingNames} present={presentNames}";
        }

        private static IReadOnlyList<string> BuildHookReadyMaskLabels(uint mask)
        {
            var labels = new List<string>(5);
            AddMaskLabel(labels, mask, BlackbirdNative.HookReadyIpcConnected, "ipc");
            AddMaskLabel(labels, mask, BlackbirdNative.HookReadyWinsock, "winsock");
            AddMaskLabel(labels, mask, BlackbirdNative.HookReadyNt, "nt");
            AddMaskLabel(labels, mask, BlackbirdNative.HookReadyKi, "ki");
            AddMaskLabel(labels, mask, BlackbirdNative.HookReadyModule, "module");
            return labels;
        }

        private static IReadOnlyList<string> BuildDriverHealthMaskLabels(uint mask)
        {
            var labels = new List<string>(14);
            AddMaskLabel(labels, mask, BlackbirdNative.HealthControlReady, "control");
            AddMaskLabel(labels, mask, BlackbirdNative.HealthEtwReady, "etw");
            AddMaskLabel(labels, mask, BlackbirdNative.HealthHandleMonitorReady, "handle");
            AddMaskLabel(labels, mask, BlackbirdNative.HealthThreadMonitorReady, "thread");
            AddMaskLabel(labels, mask, BlackbirdNative.HealthProcessMonitorReady, "process");
            AddMaskLabel(labels, mask, BlackbirdNative.HealthImageMonitorReady, "image");
            AddMaskLabel(labels, mask, BlackbirdNative.HealthRegistryMonitorReady, "registry");
            AddMaskLabel(labels, mask, BlackbirdNative.HealthApcMonitorReady, "apc");
            AddMaskLabel(labels, mask, BlackbirdNative.HealthFileSystemMonitorReady, "filesystem");
            AddMaskLabel(labels, mask, BlackbirdNative.HealthCorrelationReady, "correlation");
            AddMaskLabel(labels, mask, BlackbirdNative.HealthHollowingEngineReady, "hollowing");
            AddMaskLabel(labels, mask, BlackbirdNative.HealthNtApiMonitorReady, "ntapi");
            AddMaskLabel(labels, mask, BlackbirdNative.HealthAntiTamperReady, "anti-tamper");
            AddMaskLabel(labels, mask, BlackbirdNative.HealthDiagnosticsReady, "diagnostics");
            return labels;
        }

        private static void AddMaskLabel(ICollection<string> labels, uint mask, uint bit, string label)
        {
            if ((mask & bit) != 0)
            {
                labels.Add(label);
            }
        }

        private static string FormatMaskNames(IReadOnlyList<string> labels) =>
            labels.Count == 0 ? "none" : string.Join("|", labels);

        private static string TempusName(int index)
        {
            return index switch {
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
