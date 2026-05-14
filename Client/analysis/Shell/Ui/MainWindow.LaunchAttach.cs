using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Input;
using System.Windows.Threading;

namespace BlackbirdInterface
{
    public partial class MainWindow
    {
        private async void FindProcess_Click(object sender, RoutedEventArgs e) =>
            await OpenProcessPickerAndConnectAsync(showLaunchOptions: true);

        private async void NewProcessTab_Click(object sender, RoutedEventArgs e) =>
            await OpenProcessPickerAndConnectAsync(showLaunchOptions: true);

        private void CloseProcessTab_Click(object sender, RoutedEventArgs e)
        {
            if ((sender as FrameworkElement)?.Tag is not ProcessSessionTab tab)
                return;

            if (_processTabs.Count <= 1)
                return;

            bool wasSelected = ReferenceEquals(ProcessTabs.SelectedItem, tab);
            if (ReferenceEquals(_currentSession, tab))
                SaveCurrentSessionState();

            _processTabs.Remove(tab);

            if (_processTabs.Count == 0)
            {
                _currentSession = null;
                PerformancePaneHost.SetProcessLiveDataAvailable(false);
                PerformancePaneHost.SetTargetSuspended(false);
                StatusBlock.Text = "NO TARGET SELECTED";
                RefreshProcessStateBadge();
                return;
            }

            if (wasSelected)
            {
                _currentSession = null;
                ProcessTabs.SelectedItem = _processTabs[0];
            }
        }

        private void ProcessTabs_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (_suppressTabSelectionChange)
                return;

            if (ProcessTabs.SelectedItem is not ProcessSessionTab tab)
                return;

            _queuedSessionSwitchTab = tab;
            if (_sessionSwitchQueued)
            {
                return;
            }

            _sessionSwitchQueued = true;
            Dispatcher.BeginInvoke(new Action(() =>
                                              {
                                                  _sessionSwitchQueued = false;
                                                  ProcessSessionTab? pending = _queuedSessionSwitchTab;
                                                  _queuedSessionSwitchTab = null;
                                                  if (pending == null ||
                                                      !ReferenceEquals(ProcessTabs.SelectedItem, pending) ||
                                                      _isMainWindowShuttingDown)
                                                  {
                                                      return;
                                                  }

                                                  SwitchToSession(pending);
                                                  RefreshProcessStateBadge();
                                              }),
                                   DispatcherPriority.Background);
        }

        private DateTime GetCurrentObservedUtc()
        {
            if (EventsPaneHost?.Timeline == null)
            {
                return DateTime.UtcNow;
            }

            return _captureStartUtc + TimeSpan.FromSeconds(EventsPaneHost.Timeline.ViewStartSeconds +
                                                           EventsPaneHost.Timeline.ViewDurationSeconds);
        }

        private static string ResolveHookDllPathFromInterfaceDirectory()
        {
            return BlackbirdPackageResolver.ResolveRuntimeFile("SR71.dll");
        }

        private static string ResolveDllHostPathFromInterfaceDirectory()
        {
            return BlackbirdPackageResolver.ResolveRuntimeFile("BlackbirdDllHost.exe");
        }

        private static string QuoteCommandLineArgument(string value)
        {
            if (string.IsNullOrEmpty(value))
            {
                return "\"\"";
            }

            var builder = new System.Text.StringBuilder();
            builder.Append('"');
            int backslashes = 0;
            foreach (char ch in value)
            {
                if (ch == '\\')
                {
                    backslashes += 1;
                    continue;
                }

                if (ch == '"')
                {
                    builder.Append('\\', backslashes * 2 + 1);
                    builder.Append('"');
                    backslashes = 0;
                    continue;
                }

                if (backslashes > 0)
                {
                    builder.Append('\\', backslashes);
                    backslashes = 0;
                }
                builder.Append(ch);
            }

            if (backslashes > 0)
            {
                builder.Append('\\', backslashes * 2);
            }
            builder.Append('"');
            return builder.ToString();
        }

        private static string BuildDllHostCommandLineArguments(LaunchProfile launchProfile)
        {
            var args = new List<string> {
                "--dll",
                QuoteCommandLineArgument(launchProfile.AnalysisSubjectPath),
                "--mode",
                launchProfile.DllMode switch { DllLaunchMode.Export => "export", DllLaunchMode.Rundll => "rundll",
                                               DllLaunchMode.Register => "register",
                                               DllLaunchMode.Unregister => "unregister",
                                               DllLaunchMode.Install => "install",
                                               _ => "load" },
                "--wait-ms",
                launchProfile.DllWaitMilliseconds.ToString(System.Globalization.CultureInfo.InvariantCulture)
            };

            if (launchProfile.HasDllExportName)
            {
                args.Add("--export");
                args.Add(QuoteCommandLineArgument(launchProfile.DllExportName));
            }
            if (launchProfile.HasDllExportOrdinal)
            {
                args.Add("--ordinal");
                args.Add(launchProfile.DllExportOrdinal.ToString(System.Globalization.CultureInfo.InvariantCulture));
            }
            if (launchProfile.HasDllArgument)
            {
                args.Add("--arg");
                args.Add(QuoteCommandLineArgument(launchProfile.DllArgument));
            }
            if (launchProfile.HasDllLoadFlags)
            {
                args.Add("--load-flags");
                args.Add("0x" +
                         launchProfile.DllLoadFlags.ToString("X", System.Globalization.CultureInfo.InvariantCulture));
            }
            if (launchProfile.DllFreeOnExit)
            {
                args.Add("--free-on-exit");
            }
            if (launchProfile.DllInstallDisable)
            {
                args.Add("--install-disable");
            }

            return string.Join(" ", args);
        }

        private bool TrySendUserHookRequest(uint mode, uint processId, uint flags, string? imagePath,
                                            out BlackbirdNative.BkSetUserHookTargetResponse response, out string error)
        {
            response = default;
            error = string.Empty;

            if (!BkctlDeviceSession.TryOpen(out var control, out error))
            {
                return false;
            }

            using (control)
            {
                string hookPath = ResolveHookDllPathFromInterfaceDirectory();
                if (!File.Exists(hookPath))
                {
                    error = $"SetUserHookTarget failed because the hook DLL is missing: '{hookPath}'.";
                    return false;
                }

                if (!BlackbirdNative.SetUserHookTarget(control.Handle, mode, processId, flags, imagePath,
                                                       BlackbirdNative.AnalysisSubjectKindProcess, null, hookPath, null,
                                                       null, null, 0, 0, 0, false,
                                                       BlackbirdNative.LaunchIntegrityDefault, out response))
                {
                    error = BkctlDeviceSession.FormatUserHookOperationError(
                        "SetUserHookTarget", BlackbirdNative.LastError("SetUserHookTarget failed"), hookPath);
                    return false;
                }

                return true;
            }
        }

        private bool TryAttachUsermodeHooks(int pid, out string error)
        {
            error = string.Empty;
            if (pid <= 0)
            {
                error = "Invalid PID for hook attach.";
                return false;
            }

            if (!TrySendUserHookRequest(BlackbirdNative.IpcUserHookTargetAttach, unchecked((uint)pid), 0, null, out _,
                                        out error))
            {
                return false;
            }

            OutputCapture.AppendLine($"Hook attached via controller: PID {pid}");
            return true;
        }

        private bool EnsureNoHookControllerCallInFlight(string operation)
        {
            if (!_hookControllerCallInFlight)
            {
                return true;
            }

            string message = "A hook launch or attach request is still waiting for the controller to return. " +
                             "Blackbird will not start another hook operation until that call unwinds.";
            StatusBlock.Text = "HOOK CONTROLLER REQUEST STILL IN PROGRESS";
            OutputCapture.AppendLine($"Blocked overlapping hook operation ({operation}): previous request in-flight.");
            ThemedMessageBox.Show(this, message, "Hook Operation In Progress", MessageBoxButton.OK,
                                  MessageBoxImage.Warning);
            return false;
        }

        private AnalysisOperationGuard BeginAnalysisOperation(string operation)
        {
            var guard = new AnalysisOperationGuard(this, operation);
            _activeAnalysisOperation = guard;
            return guard;
        }

        private void CancelActiveAnalysisOperationForShutdown()
        {
            AnalysisOperationGuard? guard = _activeAnalysisOperation;
            if (guard != null)
            {
                guard.Cancel();
                guard.CleanupAfterAbort();
            }

            CompleteHookControllerCall();
            _openingProcessPicker = false;
            _connectInProgress = false;
        }

        private void CleanupAbortedAnalysisOperation(AnalysisOperationGuard guard)
        {
            DisposePreparedLaunchBackendSession();
            ClearPendingLaunchOptions();

            if (guard.SessionStartAttempted || _isMainWindowShuttingDown)
            {
                StopLiveAnalysisSession(LiveAnalysisStopReason.OperationAbort, preserveApiGraphSnapshot: true,
                                        fastTeardown: true, stopPerformance: true);
            }

            if (guard.LaunchOwnedPid > 0)
            {
                if (TryTerminateTargetProcess(guard.LaunchOwnedPid, out string terminateError))
                {
                    AppendOutputFromAnyThread(
                        $"Analysis operation cleanup terminated launch-owned target: PID {guard.LaunchOwnedPid}");
                }
                else
                {
                    AppendOutputFromAnyThread(
                        $"Analysis operation cleanup could not terminate PID {guard.LaunchOwnedPid}: {terminateError}");
                }
            }
        }

        private void CompleteHookControllerCall()
        {
            _hookControllerCallInFlight = false;
        }

        private void TrackLiveAnalysisSession(int pid, ProcessSessionTab? tab)
        {
            _liveAnalysisSession = new LiveAnalysisSessionLease(pid, tab, tab?.LaunchOwnedByInterface == true);
        }

        private void StopLiveAnalysisSession(LiveAnalysisStopReason reason, bool preserveApiGraphSnapshot = false,
                                             bool fastTeardown = false, bool stopPerformance = false)
        {
            LiveAnalysisSessionLease? lease = _liveAnalysisSession;
            if (lease != null && !lease.TryBeginTeardown())
            {
                lease = null;
            }
            _liveAnalysisSession = null;

            StopTargetExitWatcher();
            StopBackendSession(preserveApiGraphSnapshot, fastTeardown);

            if (stopPerformance)
            {
                _perf?.Stop();
                _samplerPid = 0;
                if (PerformancePaneHost != null)
                {
                    PerformancePaneHost.SetProcessLiveDataAvailable(false);
                    PerformancePaneHost.SetTargetSuspended(false);
                }
                _targetExecutionSuspended = false;
            }

            string reasonText = reason switch { LiveAnalysisStopReason.Shutdown => "shutdown",
                                                LiveAnalysisStopReason.TargetExited => "target-exit",
                                                LiveAnalysisStopReason.OperationAbort => "operation-abort",
                                                LiveAnalysisStopReason.SessionSwitch => "session-switch",
                                                _ => "teardown" };
            if (lease != null)
            {
                string targetExitDetail = reason == LiveAnalysisStopReason.TargetExited &&
                                                  !string.IsNullOrWhiteSpace(lease.Tab?.TargetExitReason)
                                              ? $" targetExit=\"{lease.Tab.TargetExitReason}\""
                                              : string.Empty;
                AppendOutputFromAnyThread(
                    $"Live analysis session detached pid={lease.Pid} reason={reasonText} launchOwned={lease.LaunchOwnedByInterface}{targetExitDetail}");
            }
        }

        private enum LiveAnalysisStopReason
        {
            SessionSwitch,
            TargetExited,
            OperationAbort,
            Shutdown
        }

        private sealed class LiveAnalysisSessionLease
        {
            private int _teardownStarted;

            internal LiveAnalysisSessionLease(int pid, ProcessSessionTab? tab, bool launchOwnedByInterface)
            {
                Pid = pid;
                Tab = tab;
                LaunchOwnedByInterface = launchOwnedByInterface;
            }

            internal int Pid { get; }
            internal ProcessSessionTab? Tab { get; }
            internal bool LaunchOwnedByInterface { get; }

            internal bool TryBeginTeardown()
            {
                return Interlocked.Exchange(ref _teardownStarted, 1) == 0;
            }
        }

        private sealed class AnalysisOperationGuard : IDisposable
        {
            private readonly MainWindow _owner;
            private int _disposed;
            private int _cleanupStarted;
            private bool _completed;

            internal AnalysisOperationGuard(MainWindow owner, string operation)
            {
                _owner = owner;
                Operation = operation;
                Cancellation = new CancellationTokenSource();
            }

            internal string Operation { get; }
            internal CancellationTokenSource Cancellation { get; }
            internal CancellationToken Token => Cancellation.Token;
            internal int LaunchOwnedPid { get; private set; }
            internal bool SessionStartAttempted { get; private set; }

            internal void TrackLaunchOwnedPid(int pid)
            {
                if (pid > 0)
                {
                    LaunchOwnedPid = pid;
                }
            }

            internal void MarkSessionStartAttempted()
            {
                SessionStartAttempted = true;
            }

            internal void Complete()
            {
                _completed = true;
            }

            internal void Cancel()
            {
                try
                {
                    Cancellation.Cancel();
                }
                catch
                {
                }
            }

            internal void CleanupAfterAbort()
            {
                if (_completed || Interlocked.Exchange(ref _cleanupStarted, 1) != 0)
                {
                    return;
                }

                _owner.CleanupAbortedAnalysisOperation(this);
            }

            public void Dispose()
            {
                if (Interlocked.Exchange(ref _disposed, 1) != 0)
                {
                    return;
                }

                if (ReferenceEquals(_owner._activeAnalysisOperation, this))
                {
                    _owner._activeAnalysisOperation = null;
                }

                CleanupAfterAbort();
                Cancellation.Dispose();
            }
        }

        private void AppendOutputFromAnyThread(string message)
        {
            if (Dispatcher.HasShutdownStarted || Dispatcher.HasShutdownFinished)
            {
                return;
            }

            if (Dispatcher.CheckAccess())
            {
                OutputCapture.AppendLine(message);
                return;
            }

            Dispatcher.BeginInvoke(new Action(() => OutputCapture.AppendLine(message)), DispatcherPriority.Background);
        }

        private void CompleteHookControllerCallFromWorker<T>(Task<T> task, Action<T>? lateResultCleanup)
        {
            Exception? cleanupError = null;
            if (task.Status == TaskStatus.RanToCompletion)
            {
                try
                {
                    lateResultCleanup?.Invoke(task.Result);
                }
                catch (Exception ex)
                {
                    cleanupError = ex;
                }
            }
            else if (task.IsFaulted)
            {
                _ = task.Exception;
            }

            if (cleanupError != null)
            {
                AppendOutputFromAnyThread($"Late hook controller cleanup failed: {cleanupError.Message}");
            }
            if (Dispatcher.HasShutdownStarted || Dispatcher.HasShutdownFinished)
            {
                return;
            }

            Dispatcher.BeginInvoke(new Action(CompleteHookControllerCall), DispatcherPriority.Background);
        }

        private async Task<(bool Completed, T Result)>
        RunHookControllerCallWithTimeoutAsync<T>(Func<T> operation, LoadingWindow loading, string timeoutStatus,
                                                 string timeoutDetail, Action<T>? lateResultCleanup = null,
                                                 CancellationToken cancellationToken = default)
        {
            _hookControllerCallInFlight = true;
            Task<T> operationTask = Task.Run(operation);
            loading.StartTimeout(HookControllerCallTimeout);

            Task delayTask = Task.Delay(HookControllerCallTimeout, cancellationToken);
            Task completed = await Task.WhenAny(operationTask, delayTask);
            if (!ReferenceEquals(completed, operationTask))
            {
                if (!cancellationToken.IsCancellationRequested && !_isMainWindowShuttingDown)
                {
                    loading.SetTimedOut(timeoutStatus, timeoutDetail, HookControllerCallTimeout);
                    OutputCapture.AppendLine(
                        $"Hook controller request timed out after {HookControllerCallTimeoutSeconds}s; waiting for native IPC unwind.");
                }
                else
                {
                    AppendOutputFromAnyThread("Hook controller request cancelled during interface teardown.");
                }
                _ = operationTask.ContinueWith(task => CompleteHookControllerCallFromWorker(task, lateResultCleanup),
                                               CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously,
                                               TaskScheduler.Default);
                if (!cancellationToken.IsCancellationRequested && !_isMainWindowShuttingDown)
                {
                    await Task.Delay(700);
                }
                return (false, default!);
            }

            try
            {
                T result = await operationTask;
                return (true, result);
            }
            finally
            {
                loading.StopTimeout();
                CompleteHookControllerCall();
            }
        }

        private bool TryLaunchWithUsermodeHooksAndPrepareSession(string imagePath, bool useEarlyBirdApc,
                                                                 LaunchProfile launchProfile, out int pid,
                                                                 out BlackbirdBackendSession? preparedSession,
                                                                 out string error)
        {
            pid = 0;
            preparedSession = null;
            error = string.Empty;
            if (string.IsNullOrWhiteSpace(imagePath))
            {
                error = "Launch path is empty.";
                return false;
            }
            if (launchProfile.HasCommandLineArguments &&
                launchProfile.CommandLineArguments.Length >= MaxControllerLaunchArgumentChars)
            {
                error =
                    $"Launch arguments are too long for the controller IPC limit ({MaxControllerLaunchArgumentChars - 1} characters).";
                return false;
            }

            uint flags = useEarlyBirdApc ? BlackbirdNative.IpcUserHookFlagLaunchEarlybirdApc : 0;
            if (launchProfile.LeaveSuspendedAfterReady)
            {
                flags |= BlackbirdNative.IpcUserHookFlagDeferredLaunchGateRelease;
            }
            if (!_useKernelDriver)
            {
                flags |= BlackbirdNative.IpcUserHookFlagUsermodeOnly;
            }

            try
            {
                if (!BkctlDeviceSession.TryOpen(out var control, out error))
                {
                    return false;
                }

                using (control)
                {
                    string hookPath = ResolveHookDllPathFromInterfaceDirectory();
                    if (!File.Exists(hookPath))
                    {
                        error = $"Hook launch failed because the hook DLL is missing: '{hookPath}'.";
                        return false;
                    }
                    if (!BlackbirdPreflight.ProbeHookIngestPipe(TimeSpan.FromSeconds(2), out string hookPipeMessage))
                    {
                        error =
                            $"Hook launch blocked because the controller hook-ingest pipe is unavailable: {hookPipeMessage}. Restart BlackbirdController and rerun preflight.";
                        return false;
                    }

                    string environmentOverrides = launchProfile.ToIpcEnvironmentOverrideBlock();
                    if (!BlackbirdNative.SetUserHookTarget(
                            control.Handle, BlackbirdNative.IpcUserHookTargetLaunch, 0, flags, imagePath,
                            launchProfile.HasAnalysisSubject ? BlackbirdNative.AnalysisSubjectKindDll
                                                             : BlackbirdNative.AnalysisSubjectKindProcess,
                            launchProfile.HasAnalysisSubject ? launchProfile.AnalysisSubjectPath : null, hookPath,
                            launchProfile.HasWorkingDirectory ? launchProfile.WorkingDirectory : null,
                            string.IsNullOrWhiteSpace(environmentOverrides) ? null : environmentOverrides,
                            launchProfile.HasCommandLineArguments ? launchProfile.CommandLineArguments : null,
                            launchProfile.ParentProcessId, MapLaunchPriorityClass(launchProfile.Priority),
                            launchProfile.AffinityMask, launchProfile.InheritHandles,
                            (uint)launchProfile.IntegrityLevel,
                            out BlackbirdNative.BkSetUserHookTargetResponse response))
                    {
                        error = BkctlDeviceSession.FormatUserHookOperationError(
                            "SetUserHookTarget(launch)", BlackbirdNative.LastError("SetUserHookTarget(launch) failed"),
                            hookPath);
                        return false;
                    }

                    if (response.ProcessId == 0)
                    {
                        error = "Controller launch returned no PID.";
                        return false;
                    }

                    pid = unchecked((int)response.ProcessId);
                    preparedSession =
                        BlackbirdBackendSession.StartFromHandle(pid, BlackbirdNative.StreamAll, useUsermodeHooks: true,
                                                                control.Handle, useKernelDriver: _useKernelDriver);
                    _ = control.DetachHandle();

                    OutputCapture.AppendLine(
                        launchProfile.HasAnalysisSubject
                            ? $"Hook launch via controller (earlybird-apc): host={imagePath} subject={launchProfile.AnalysisSubjectPath} \u2192 PID {pid} (pre-armed session)"
                            : $"Hook launch via controller (earlybird-apc): {imagePath} \u2192 PID {pid} (pre-armed session)");
                    return true;
                }
            }
            catch (Exception ex)
            {
                if (preparedSession != null)
                {
                    preparedSession.Dispose();
                    preparedSession = null;
                }
                if (string.IsNullOrWhiteSpace(error))
                {
                    error = ex.Message;
                }
                return false;
            }
        }

        private async void Connect_Click(object sender, RoutedEventArgs e)
        {
            using AnalysisOperationGuard operation = BeginAnalysisOperation("attach/analyze");
            await ConnectToCurrentPidAsync(operation.Token, operation);
            if (operation.SessionStartAttempted && !operation.Token.IsCancellationRequested &&
                !_isMainWindowShuttingDown)
            {
                operation.Complete();
            }
        }

        private async Task ConnectToCurrentPidAsync(CancellationToken cancellationToken,
                                                    AnalysisOperationGuard? operationGuard = null)
        {
            if (_connectInProgress || cancellationToken.IsCancellationRequested || _isMainWindowShuttingDown)
            {
                return;
            }

            _connectInProgress = true;
            try
            {
                int pid = TryGetPid();
                if (pid <= 0)
                {
                    DisposePreparedLaunchBackendSession();
                    ClearPendingLaunchOptions();
                    StatusBlock.Text = "ENTER A VALID PID";
                    RefreshProcessStateBadge();
                    return;
                }

                bool hookPreconfigured = _pendingHookPreconfigured;
                bool allowPreparedLaunchAttach =
                    hookPreconfigured && _preparedLaunchBackendSession != null && _preparedLaunchBackendPid == pid;
                if (_pendingLaunchOwnedByInterface)
                {
                    operationGuard?.TrackLaunchOwnedPid(pid);
                }

                if (!TryOpenTargetProcess(pid, out var processName, out var failure, out var accessDenied))
                {
                    if (!allowPreparedLaunchAttach)
                    {
                        DisposePreparedLaunchBackendSession();
                        ClearPendingLaunchOptions();
                        StatusBlock.Text = failure;
                        if (accessDenied)
                        {
                            ThemedMessageBox.Show(
                                this,
                                $"Access denied while opening PID {pid}. The process handle could not be opened with required access rights.",
                                "Target Attach Failed", MessageBoxButton.OK, MessageBoxImage.Warning);
                        }

                        RefreshProcessStateBadge();
                        return;
                    }

                    processName = $"PID {pid}";
                    StatusBlock.Text = $"CONNECTED TO PROTECTED TARGET ({pid})";
                    OutputCapture.AppendLine(
                        $"Protected launch attach accepted via prepared controller session: PID {pid}");
                }
                else
                {
                    StatusBlock.Text = $"CONNECTED TO {processName} ({pid})";
                }

                var tab = AddOrSelectProcessTab(pid, $"{processName} ({pid})", select: true);
                if (_pendingLaunchOptions)
                {
                    tab.LaunchOwnedByInterface = _pendingLaunchOwnedByInterface;
                }
                if (_pendingAnalysisSubjectKind == LaunchTargetKind.Dll &&
                    !string.IsNullOrWhiteSpace(_pendingAnalysisSubjectPath))
                {
                    tab.AnalysisSubjectKind = LaunchTargetKind.Dll;
                    tab.AnalysisSubjectPath = _pendingAnalysisSubjectPath;
                    tab.AnalysisHostPath = _pendingAnalysisHostPath;
                    string subjectName = Path.GetFileName(_pendingAnalysisSubjectPath);
                    tab.Title = NormalizeSessionTitle(
                        $"{(string.IsNullOrWhiteSpace(subjectName) ? "DLL" : subjectName)} via BlackbirdDllHost ({pid})");
                    DiagnosticsState.SetValue("Analysis Subject", tab.AnalysisSubjectPath);
                }
                bool launchStartsSuspended = _pendingLaunchStartsSuspended;
                bool leaveSuspendedAfterReady = _pendingLeaveSuspendedAfterReady;
                if (hookPreconfigured)
                {
                    OutputCapture.AppendLine(
                        $"Protected launch attach state: pid={pid} backendPrepared={allowPreparedLaunchAttach} leaveSuspended={leaveSuspendedAfterReady} uiStartsSuspended={launchStartsSuspended}");
                }
                if (_pendingLaunchOptions)
                {
                    tab.UseUsermodeHooks = _pendingUseUsermodeHooks;
                    tab.AutoOpenApiGraphOnNextStart = _pendingAutoOpenApiGraph;
                }
                tab.LaunchStartsSuspendedPending = launchStartsSuspended;
                tab.DeferredLaunchGateResumePending = false;
                ClearPendingLaunchOptions();

                if (tab.UseUsermodeHooks && !hookPreconfigured)
                {
                    LoadingWindow? hookLoading = null;
                    try
                    {
                        if (cancellationToken.IsCancellationRequested || _isMainWindowShuttingDown)
                        {
                            DisposePreparedLaunchBackendSession();
                            return;
                        }
                        if (!EnsureNoHookControllerCallInFlight("attach usermode hooks"))
                        {
                            DisposePreparedLaunchBackendSession();
                            return;
                        }

                        hookLoading = new LoadingWindow { Owner = this };
                        hookLoading.SetProgress(
                            38, "Attaching usermode hooks...",
                            $"Injecting SR71.dll into PID {pid}. UI timeout is {HookControllerCallTimeoutSeconds}s.");
                        hookLoading.Show();
                        await Dispatcher.InvokeAsync(() =>
                                                     {},
                                                     DispatcherPriority.Render);

                        var hookWait = await RunHookControllerCallWithTimeoutAsync(
                            () =>
                            {
                                bool ok = TryAttachUsermodeHooks(pid, out string err);
                                return (ok, err);
                            },
                            hookLoading, "Hook attach timed out",
                            $"The controller did not complete SR71 attach for PID {pid} within {HookControllerCallTimeoutSeconds}s.",
                            cancellationToken: cancellationToken);

                        if (!hookWait.Completed)
                        {
                            DisposePreparedLaunchBackendSession();
                            if (cancellationToken.IsCancellationRequested || _isMainWindowShuttingDown)
                            {
                                return;
                            }
                            StatusBlock.Text = $"HOOK ATTACH TIMED OUT FOR PID {pid}";
                            ThemedMessageBox.Show(
                                this,
                                $"Timed out attaching usermode hooks to PID {pid}. The controller IPC call is still being allowed to unwind, and overlapping hook operations are blocked until it returns.",
                                "Hook Attach Timed Out", MessageBoxButton.OK, MessageBoxImage.Error);
                            RefreshProcessStateBadge();
                            return;
                        }

                        var hookResult = hookWait.Result;

                        if (!hookResult.ok)
                        {
                            DisposePreparedLaunchBackendSession();
                            StatusBlock.Text = $"HOOK ATTACH FAILED FOR PID {pid}";
                            ThemedMessageBox.Show(this,
                                                  $"Failed to attach usermode hooks for PID {pid}.\n\n{hookResult.err}",
                                                  "Hook Attach Failed", MessageBoxButton.OK, MessageBoxImage.Error);
                            RefreshProcessStateBadge();
                            return;
                        }
                    }
                    finally
                    {
                        if (hookLoading != null && hookLoading.IsVisible)
                        {
                            hookLoading.Close();
                        }
                    }

                    if (!IsLoaded)
                    {
                        DisposePreparedLaunchBackendSession();
                        return;
                    }
                }

                if (cancellationToken.IsCancellationRequested || _isMainWindowShuttingDown)
                {
                    DisposePreparedLaunchBackendSession();
                    return;
                }

                tab.TargetExited = false;
                tab.TargetExitReason = string.Empty;
                tab.OfflineSnapshot = false;
                if (!ReferenceEquals(_currentSession, tab))
                {
                    operationGuard?.MarkSessionStartAttempted();
                    SwitchToSession(tab);
                }
                else
                {
                    operationGuard?.MarkSessionStartAttempted();
                    StartLiveCaptureForPid(pid, tab.UseUsermodeHooks, launchStartsSuspended);
                }

                if (hookPreconfigured && !leaveSuspendedAfterReady)
                {
                    OutputCapture.AppendLine($"Protected launch auto-resume requested: PID {pid}");
                    if (!TryControlTargetExecution(suspend: false, out string resumeError))
                    {
                        OutputCapture.AppendLine($"Protected launch auto-resume failed: PID {pid} error={resumeError}");
                        _targetExecutionSuspended = true;
                        PerformancePaneHost.SetTargetSuspended(true);
                        StatusBlock.Text = $"SESSION READY, TARGET STILL SUSPENDED: PID {pid}";
                        ThemedMessageBox.Show(
                            this,
                            $"Blackbird attached successfully, but the target could not be resumed automatically.\n\n{resumeError}",
                            "Launch Resume Failed", MessageBoxButton.OK, MessageBoxImage.Warning);
                        RefreshProcessStateBadge();
                        RefreshToolbarCommandState();
                        return;
                    }

                    MarkSr71PreResumeGateReleased(DateTime.UtcNow);
                    _targetExecutionSuspended = false;
                    PerformancePaneHost.SetTargetSuspended(false);
                    StatusBlock.Text =
                        $"LIVE CAPTURE READY: {NormalizeSessionTitle(_currentSession?.Title ?? $"PID {pid}")}";
                    OutputCapture.AppendLine($"Protected launch auto-resume completed: PID {pid}");
                }
                else if (launchStartsSuspended)
                {
                    if (hookPreconfigured)
                    {
                        OutputCapture.AppendLine($"Protected launch left suspended by operator option: PID {pid}");
                    }
                    _targetExecutionSuspended = true;
                    PerformancePaneHost.SetTargetSuspended(true);
                    StatusBlock.Text =
                        $"LIVE CAPTURE READY, TARGET SUSPENDED: {NormalizeSessionTitle(_currentSession?.Title ?? $"PID {pid}")}";
                }

                _ = RunPreflightAsync(pid);
                RefreshProcessStateBadge();
            }
            finally
            {
                _connectInProgress = false;
            }
        }

        private async void Launch_Click(object sender, RoutedEventArgs e) =>
            await OpenProcessPickerAndConnectAsync(showLaunchOptions: true);

        private async Task OpenProcessPickerAndConnectAsync(bool showLaunchOptions)
        {
            if (_openingProcessPicker)
                return;

            DisposePreparedLaunchBackendSession();
            ClearPendingLaunchOptions();
            _openingProcessPicker = true;
            LoadingWindow? loading = null;

            try
            {
                loading = new LoadingWindow { Owner = this };
                loading.SetProgress(14, "Preparing process picker...", "Initializing process view shell.");
                loading.Show();
                await Dispatcher.InvokeAsync(() =>
                                             {},
                                             System.Windows.Threading.DispatcherPriority.Render);

                var picker = new ProcessPickerWindow { Owner = this, ShowLaunchOptions = showLaunchOptions };

                loading.SetProgress(62, "Preparing process list...",
                                    "Enumerating launch targets before showing picker.");
                await Dispatcher.InvokeAsync(() =>
                                             {},
                                             DispatcherPriority.Render);
                picker.PrimeForFirstShow();
                loading.SetProgress(100, "Opening picker...", "Process picker is ready.");
                await Dispatcher.InvokeAsync(() =>
                                             {},
                                             DispatcherPriority.Render);
                loading.Close();
                loading = null;

                bool? result = picker.ShowDialog();
                if (result != true)
                    return;

                int selectedPid = picker.SelectedPid;
                bool hookPreconfigured = false;
                bool useUsermodeHooks = false;
                bool autoOpenApiGraph = false;
                bool useEarlyBirdApcLaunch = false;
                LaunchTargetKind launchTargetKind =
                    picker.LaunchSelectedImage ? picker.SelectedLaunchTargetKind : LaunchTargetKind.Executable;
                LaunchProfile launchProfile = new();
                if (showLaunchOptions && (picker.LaunchSelectedImage || selectedPid > 0))
                {
                    var parametersWindow = new LaunchParametersWindow(
                        isLaunchTarget: picker.LaunchSelectedImage, targetKind: launchTargetKind,
                        defaultUseUsermodeHooks: _startupDefaultUseUsermodeHooks,
                        defaultUseKernelDriver: _useKernelDriver, defaultRuntimeFlags: _effectiveRuntimeFlags,
                        defaultSignatureIntel: _signatureIntelEnabled,
                        defaultSignatureIntelMemoryScan: _signatureIntelMemoryScanEnabled,
                        defaultSignatureIntelPageScan: _signatureIntelPageScanEnabled) { Owner = this };
                    bool? parametersAccepted = parametersWindow.ShowDialog();
                    if (parametersAccepted != true)
                    {
                        return;
                    }

                    useUsermodeHooks = parametersWindow.UseUsermodeHooks;
                    _useKernelDriver = parametersWindow.UseKernelDriver;
                    DiagnosticsState.SetValue("KM Driver", _useKernelDriver ? "Enabled" : "Driverless mode");
                    if (!_useKernelDriver)
                    {
                        SetKernelHooksArmed(false);
                    }
                    useEarlyBirdApcLaunch = parametersWindow.UseEarlyBirdApcLaunch;
                    autoOpenApiGraph = useUsermodeHooks && ShouldAutoSwitchToApiViewForHookCapture();
                    launchProfile = parametersWindow.LaunchProfile;
                    launchProfile.TargetKind = launchTargetKind;
                    ConfigureStartupSignatureIntel(parametersWindow.EnableSignatureIntel,
                                                   parametersWindow.EnableSignatureIntelMemoryScan,
                                                   parametersWindow.EnableSignatureIntelPageScan);
                    if (_useKernelDriver)
                    {
                        if (!ApplySelectedRuntimeConfig(launchProfile, out string runtimeError))
                        {
                            ThemedMessageBox.Show(
                                this, $"Failed to apply launch runtime configuration.\n\n{runtimeError}",
                                "Launch Runtime Configuration", MessageBoxButton.OK, MessageBoxImage.Error);
                            return;
                        }
                    }
                    else
                    {
                        DiagnosticsState.SetValue("RuntimeConfig", "Skipped (driverless mode)");
                    }
                }

                using AnalysisOperationGuard operation = BeginAnalysisOperation(
                    showLaunchOptions && picker.LaunchSelectedImage ? "launch/analyze" : "attach/analyze");

                if (showLaunchOptions && picker.LaunchSelectedImage)
                {
                    string selectedImagePath = picker.LaunchImagePath?.Trim() ?? string.Empty;
                    if (string.IsNullOrWhiteSpace(selectedImagePath))
                    {
                        ThemedMessageBox.Show(this, "Launch path is empty.", "Launch failed", MessageBoxButton.OK,
                                              MessageBoxImage.Error);
                        return;
                    }

                    string launchImagePath = selectedImagePath;
                    if (launchTargetKind == LaunchTargetKind.Dll)
                    {
                        string dllHostPath = ResolveDllHostPathFromInterfaceDirectory();
                        if (!File.Exists(dllHostPath))
                        {
                            ThemedMessageBox.Show(
                                this, $"DLL launch failed because the DLL host is missing: '{dllHostPath}'.",
                                "DLL launch failed", MessageBoxButton.OK, MessageBoxImage.Error);
                            return;
                        }

                        launchProfile.TargetKind = LaunchTargetKind.Dll;
                        launchProfile.AnalysisSubjectPath = selectedImagePath;
                        launchProfile.AnalysisHostPath = dllHostPath;
                        launchProfile.CommandLineArguments = BuildDllHostCommandLineArguments(launchProfile);
                        if (!launchProfile.HasWorkingDirectory)
                        {
                            launchProfile.WorkingDirectory = Path.GetDirectoryName(selectedImagePath) ?? string.Empty;
                        }
                        launchImagePath = dllHostPath;
                        useUsermodeHooks = true;
                        useEarlyBirdApcLaunch = true;
                    }

                    if (useUsermodeHooks)
                    {
                        LoadingWindow? launchLoading = null;
                        bool launchOk;
                        int launchedPid = 0;
                        BlackbirdBackendSession? preparedSession = null;
                        string launchError = string.Empty;
                        try
                        {
                            if (!EnsureNoHookControllerCallInFlight("launch target with hooks"))
                            {
                                return;
                            }

                            launchLoading = new LoadingWindow { Owner = this };
                            launchLoading.SetProgress(42, "Launching target with hooks...",
                                                      "Submitting launch + SR71 staging request. UI timeout is " +
                                                          HookControllerCallTimeoutSeconds + "s.");
                            launchLoading.Show();
                            await Dispatcher.InvokeAsync(() =>
                                                         {},
                                                         DispatcherPriority.Render);

                            var launchWait = await RunHookControllerCallWithTimeoutAsync(
                                () =>
                                {
                                                     bool ok = TryLaunchWithUsermodeHooksAndPrepareSession(
                                                         launchImagePath, useEarlyBirdApcLaunch, launchProfile,
                                                         out int taskPid, out BlackbirdBackendSession? taskSession,
                                                         out string taskError);
                                                     return (ok, taskPid, taskSession, taskError);
                                },
                                launchLoading, "Hook launch timed out",
                                "The controller did not return from target launch and SR71 readiness " +
                                    $"within {HookControllerCallTimeoutSeconds}s.",
                                lateResult =>
                                {
                                    lateResult.taskSession?.Dispose();
                                    if (lateResult.taskPid > 0)
                                    {
                                        if (TryTerminateTargetProcess(lateResult.taskPid, out string terminateError))
                                        {
                                            AppendOutputFromAnyThread(
                                                $"Late hook launch result was terminated fail-closed: PID {lateResult.taskPid}");
                                        }
                                        else
                                        {
                                            AppendOutputFromAnyThread(
                                                $"Late hook launch result cleanup could not terminate PID {lateResult.taskPid}: {terminateError}");
                                        }
                                    }
                                },
                                cancellationToken: operation.Token);

                            if (!launchWait.Completed)
                            {
                                launchOk = false;
                                launchError =
                                    $"Controller hook launch did not return within {HookControllerCallTimeoutSeconds} seconds. " +
                                    "Blackbird has blocked overlapping hook launches until the native IPC call unwinds.";
                            }
                            else
                            {
                                launchOk = launchWait.Result.ok;
                                launchedPid = launchWait.Result.taskPid;
                                preparedSession = launchWait.Result.taskSession;
                                launchError = launchWait.Result.taskError;
                                if (launchedPid > 0)
                                {
                                    operation.TrackLaunchOwnedPid(launchedPid);
                                }
                            }
                        }
                        finally
                        {
                            if (launchLoading != null && launchLoading.IsVisible)
                            {
                                launchLoading.Close();
                            }
                        }

                        if (!launchOk)
                        {
                            if (preparedSession != null)
                            {
                                try
                                {
                                    preparedSession.Dispose();
                                }
                                catch
                                {
                                }
                            }

                            if (operation.Token.IsCancellationRequested || _isMainWindowShuttingDown)
                            {
                                return;
                            }

                            ThemedMessageBox.Show(this, launchError, "Hook launch failed", MessageBoxButton.OK,
                                                  MessageBoxImage.Error);
                            return;
                        }

                        selectedPid = launchedPid;
                        operation.TrackLaunchOwnedPid(selectedPid);
                        _preparedLaunchBackendSession = preparedSession;
                        _preparedLaunchBackendPid = selectedPid;
                        hookPreconfigured = true;
                    }
                    else
                    {
                        if (!BlackbirdNative.TryLaunchProcess(launchImagePath, launchProfile, out selectedPid,
                                                              out string launchError))
                        {
                            ThemedMessageBox.Show(this, launchError, "Launch failed", MessageBoxButton.OK,
                                                  MessageBoxImage.Error);
                            return;
                        }

                        operation.TrackLaunchOwnedPid(selectedPid);
                    }
                }

                if (selectedPid <= 0)
                {
                    return;
                }

                _pendingLaunchOptions = showLaunchOptions;
                _pendingUseUsermodeHooks = showLaunchOptions && useUsermodeHooks;
                _pendingAutoOpenApiGraph = showLaunchOptions && autoOpenApiGraph;
                _pendingHookPreconfigured = hookPreconfigured;
                _pendingLaunchStartsSuspended =
                    showLaunchOptions && picker.LaunchSelectedImage && launchProfile.LeaveSuspendedAfterReady;
                _pendingLeaveSuspendedAfterReady =
                    showLaunchOptions && picker.LaunchSelectedImage && launchProfile.LeaveSuspendedAfterReady;
                _pendingLaunchOwnedByInterface = showLaunchOptions && picker.LaunchSelectedImage;
                _pendingAnalysisSubjectKind = launchProfile.TargetKind;
                _pendingAnalysisSubjectPath =
                    launchProfile.HasAnalysisSubject ? launchProfile.AnalysisSubjectPath : string.Empty;
                _pendingAnalysisHostPath =
                    !string.IsNullOrWhiteSpace(launchProfile.AnalysisHostPath)
                        ? launchProfile.AnalysisHostPath
                        : (launchProfile.HasAnalysisSubject ? ResolveDllHostPathFromInterfaceDirectory()
                                                            : string.Empty);
                PidBox.Text = selectedPid.ToString();
                await ConnectToCurrentPidAsync(operation.Token, operation);
                if (operation.SessionStartAttempted && !operation.Token.IsCancellationRequested &&
                    !_isMainWindowShuttingDown)
                {
                    operation.Complete();
                }
            }
            finally
            {
                if (loading != null && loading.IsVisible)
                {
                    loading.Close();
                }

                _openingProcessPicker = false;
            }
        }

        internal void ConnectToStartupPid(int pid)
        {
            if (pid <= 0)
            {
                return;
            }

            PidBox.Text = pid.ToString();
            Connect_Click(this, new RoutedEventArgs());
        }

        internal async Task BeginStartupLaunchFlowAsync()
        {
            await OpenProcessPickerAndConnectAsync(showLaunchOptions: true);
        }

        private void ApplyPausedTimelineRanges()
        {
            if (EventsPaneHost?.Timeline == null)
            {
                return;
            }

            if (_currentSession == null)
            {
                EventsPaneHost.Timeline.SetPauseRanges(null);
                return;
            }

            var ranges = _currentSession.PausedTimelineSpans
                             .Select(x => new TimelinePauseRange { StartUtc = x.StartUtc, EndUtc = x.EndUtc })
                             .ToList();

            if (_currentSession.ActivePauseStartUtc.HasValue)
            {
                ranges.Add(new TimelinePauseRange { StartUtc = _currentSession.ActivePauseStartUtc.Value,
                                                    EndUtc = DateTime.UtcNow });
            }

            EventsPaneHost.Timeline.SetPauseRanges(ranges);
        }

        private void DisposePreparedLaunchBackendSession()
        {
            if (_preparedLaunchBackendSession != null)
            {
                try
                {
                    _preparedLaunchBackendSession.Dispose();
                }
                catch
                {
                }
            }

            _preparedLaunchBackendSession = null;
            _preparedLaunchBackendPid = 0;
        }

        private void ClearPendingLaunchOptions()
        {
            _pendingLaunchOptions = false;
            _pendingUseUsermodeHooks = false;
            _pendingAutoOpenApiGraph = false;
            _pendingHookPreconfigured = false;
            _pendingLaunchStartsSuspended = false;
            _pendingLeaveSuspendedAfterReady = false;
            _pendingLaunchOwnedByInterface = false;
            _pendingAnalysisSubjectKind = LaunchTargetKind.Executable;
            _pendingAnalysisSubjectPath = string.Empty;
            _pendingAnalysisHostPath = string.Empty;
        }

        private static uint MapLaunchPriorityClass(LaunchPriorityPreset priority) => priority switch {
            LaunchPriorityPreset.Idle => 0x00000040,
            LaunchPriorityPreset.BelowNormal => 0x00004000,
            LaunchPriorityPreset.Normal => 0x00000020,
            LaunchPriorityPreset.AboveNormal => 0x00008000,
            LaunchPriorityPreset.High => 0x00000080,
            LaunchPriorityPreset.Realtime => 0x00000100,
            _ => 0u
        };

        internal async Task<string> TryOpenSessionFromStartupPathAsync(string path)
        {
            return await TryOpenSessionArchivePathAsync(path, merge: false);
        }
    }
}
