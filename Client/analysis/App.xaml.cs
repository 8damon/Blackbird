using System;
using Microsoft.Win32;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using System.Windows.Media;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Threading;

namespace BlackbirdInterface
{
    public enum UiThemeMode
    {
        Auto,
        Dark,
        Light
    }

    public partial class App : Application
    {
        private const string GettingStartedUrl = "https://titansoftwork.com/docs/blackbird/#intro";
        private static Mutex? _singleInstanceMutex;
        internal static bool IsDarkTheme { get; private set; } = true;
        internal static UiThemeMode CurrentThemeMode { get; private set; } = UiThemeMode.Dark;
        internal static event Action<bool>? ThemeChanged;

        private static int _faultHandlerDepth;
        private static int _edrWarningShown;
        private static int _vmSafetyWarningShown;

        private sealed class StartupIntent
        {
            public bool StartLaunchFlow { get; init; }
            public string? SessionPath { get; init; }
            public bool EnableKernelDriver { get; set; } = true;
            public bool EnableKernelHooks { get; init; } = true;
            public bool EnableUsermodeHooks { get; init; } = true;
            public bool EnableAntiVirtualizationMasking { get; init; }
            public bool EnableQpcTimingCompensation { get; init; } = true;
            public bool EnableControllerConcealment { get; init; }
            public bool EnableInterfaceProtectedAccess { get; init; }
            public bool EnableControllerProtectedAccess { get; init; }
            public bool EnableSignatureIntel { get; init; }
            public bool EnableSignatureIntelMemoryScan { get; init; }
            public bool EnableSignatureIntelPageScan { get; init; }
        }

        private sealed class StartupOptions
        {
            public bool DebugConsole { get; init; }
        }

        protected override void OnStartup(StartupEventArgs e)
        {
            // Wire global exception handlers before any other work so the interface
            // survives unhandled exceptions — particularly important when protect-handles
            // is active and the process cannot be externally terminated.
            AppDomain.CurrentDomain.UnhandledException += OnDomainUnhandledException;
            DispatcherUnhandledException += OnDispatcherUnhandledException;
            TaskScheduler.UnobservedTaskException += OnUnobservedTaskException;

            ShutdownMode = ShutdownMode.OnExplicitShutdown;

            base.OnStartup(e);
            if (!VerifyAdministratorTokenOrExit())
            {
                return;
            }

            EnsureBackgroundThreadPoolFloor();
            StartupOptions options = ParseStartupOptions(e.Args);
            DebugConsoleService.Start(options.DebugConsole);
            if (options.DebugConsole)
            {
                DebugConsoleService.WriteLocal($"startup args: {string.Join(" ", e.Args)}");
            }
            EnforceSingleInstance();
            ApplyTheme(AnalystSettingsStore.LoadThemeMode());
            ContinueStartupSafe();
        }

        private bool VerifyAdministratorTokenOrExit()
        {
            bool elevated = false;
            try
            {
                using WindowsIdentity identity = WindowsIdentity.GetCurrent();
                var principal = new WindowsPrincipal(identity);
                elevated = principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch
            {
                elevated = false;
            }

            bool debugPrivilegeEnabled = Kernel32Native.EnableDebugPrivilege(out int debugPrivilegeError);
            if (elevated && debugPrivilegeEnabled)
            {
                return true;
            }

            string detail =
                !elevated ? "BlackbirdInterface is not running with an administrator token."
                          : $"BlackbirdInterface could not enable SeDebugPrivilege (win32={debugPrivilegeError}).";
            MessageBox.Show(
                $"{detail}\n\nStart BlackbirdInterface as administrator. Direct target inspection, module enumeration, memory sampling, and thread stack walking require an elevated token with SeDebugPrivilege.",
                "Blackbird Requires Administrator", MessageBoxButton.OK, MessageBoxImage.Error);
            Shutdown();
            return false;
        }

        protected override void OnExit(ExitEventArgs e)
        {
            try
            {
                _singleInstanceMutex?.ReleaseMutex();
            }
            catch
            {
            }
            finally
            {
                _singleInstanceMutex?.Dispose();
                _singleInstanceMutex = null;
            }

            DebugConsoleService.Stop();

            base.OnExit(e);
        }

        private static void EnsureBackgroundThreadPoolFloor()
        {
            ThreadPool.GetMinThreads(out int workerThreads, out int completionPortThreads);

            int workerFloor = Math.Max(8, Environment.ProcessorCount * 2);
            int ioFloor = Math.Max(8, Environment.ProcessorCount);
            if (workerThreads >= workerFloor && completionPortThreads >= ioFloor)
            {
                return;
            }

            ThreadPool.SetMinThreads(Math.Max(workerThreads, workerFloor), Math.Max(completionPortThreads, ioFloor));
        }

        private async void ContinueStartupSafe()
        {
            try
            {
                await ContinueStartupAsync();
            }
            catch (Exception ex)
            {
                HandleStartupFailure(ex);
            }
        }

        private async Task ContinueStartupAsync()
        {
            var bootLoading = new LoadingWindow();
            bootLoading.SetProgress(4, "Launching Blackbird...", "Loading interface resources.");
            bootLoading.Show();
            await YieldForUiFrameAsync();
            await Task.Delay(275);
            bootLoading.SetProgress(100, "Startup ready", "Opening startup options.");
            bootLoading.Close();

            StartupIntent? intent = ResolveStartupIntent();
            if (intent == null)
            {
                Shutdown();
                return;
            }

            bool openingSession = !string.IsNullOrWhiteSpace(intent.SessionPath);
            var loading = new LoadingWindow();
            loading.SetProgress(6, "Preparing startup...",
                                openingSession ? "Preparing offline capture session."
                                               : "Starting Blackbird preflight.");
            loading.Show();
            var loadingShownAtUtc = DateTime.UtcNow;

            if (!openingSession && !await EnsureStartupSystemsReadyAsync(loading, intent))
            {
                loading.Close();
                Shutdown();
                return;
            }
            if (openingSession)
            {
                loading.SetProgress(16, "Opening session...",
                                    "Skipping Blackbird component preflight for offline capture analysis.");
                await YieldForUiFrameAsync();
            }
            EnsureStartMenuShortcut();

            loading.SetProgress(18, "Initializing startup...", "Preparing main interface.");

            loading.SetProgress(28, "Applying theme resources...", "Active theme resolved.");
            await YieldForUiFrameAsync();

            loading.SetProgress(40, "Initializing diagnostics...", "Starting output capture and runtime logging.");
            try
            {
                OutputCapture.Initialize();
            }
            catch (Exception ex)
            {
                loading.SetProgress(44, "Diagnostics degraded", "Continuing startup without output capture.");
                Debug.WriteLine($"OutputCapture.Initialize failed: {ex}");
            }
            await YieldForUiFrameAsync();

            loading.SetProgress(58, "Building interface resources...",
                                "Constructing the main window and control tree.");
            var main = new MainWindow { ShowInTaskbar = false, Opacity = 0 };
            main.WindowStartupLocation = WindowStartupLocation.Manual;
            main.WindowState = WindowState.Normal;
            main.Left = -32000;
            main.Top = -32000;
            await YieldForUiFrameAsync();

            loading.SetProgress(76, "Preparing final shell...", "Pre-rendering main window offscreen.");
            MainWindow = main;
            Task firstRenderTask = WaitForFirstRenderAsync(main);
            main.Show();
            await Task.WhenAny(firstRenderTask, Task.Delay(2500));
            await YieldForUiFrameAsync();

            loading.SetProgress(90, "Preparing final shell...", "Synchronizing final visual state.");

            const int minimumLoadingMs = 1150;
            int elapsedMs = (int)(DateTime.UtcNow - loadingShownAtUtc).TotalMilliseconds;
            if (elapsedMs < minimumLoadingMs)
            {
                await Task.Delay(minimumLoadingMs - elapsedMs);
            }

            loading.SetProgress(100, "Launching interface...", "Startup complete. Opening main window.");
            main.Left = 0;
            main.Top = 0;
            main.WindowState = WindowState.Maximized;
            main.ShowInTaskbar = true;
            main.Opacity = 1;
            main.Activate();
            await YieldForUiFrameAsync();
            loading.Close();
            _ = ShowStartupEnvironmentWarningsAsync();

            if (!openingSession)
            {
                main.ConfigureStartupDriverMode(intent.EnableKernelDriver, intent.EnableUsermodeHooks);

                if (intent.EnableKernelDriver &&
                    !main.ApplyStartupRuntimeSelections(
                        intent.EnableKernelHooks, intent.EnableAntiVirtualizationMasking,
                        intent.EnableQpcTimingCompensation, intent.EnableControllerConcealment,
                        intent.EnableInterfaceProtectedAccess, intent.EnableControllerProtectedAccess,
                        out string startupRuntimeError))
                {
                    MessageBoxResult runtimeChoice = ThemedMessageBox.Show(
                        main,
                        $"Failed to apply KM driver runtime configuration after shell startup.\n\n{startupRuntimeError}\n\nContinue in driverless mode?",
                        "Runtime Configuration", MessageBoxButton.YesNo, MessageBoxImage.Warning);
                    if (runtimeChoice == MessageBoxResult.Yes)
                    {
                        intent.EnableKernelDriver = false;
                        main.ConfigureStartupDriverMode(false, intent.EnableUsermodeHooks);
                        DiagnosticsState.SetValue("RuntimeConfig", "Skipped after driver fallback");
                    }
                    else
                    {
                        ThemedMessageBox.Show(main,
                                              $"Runtime configuration remains unavailable.\n\n{startupRuntimeError}",
                                              "Runtime Configuration", MessageBoxButton.OK, MessageBoxImage.Error);
                    }
                }
                else if (!intent.EnableKernelDriver)
                {
                    DiagnosticsState.SetValue("KM Driver", "Driverless mode");
                    DiagnosticsState.SetValue("Controller<->Driver Comms", "Driverless mode");
                    DiagnosticsState.SetValue("RuntimeConfig", "Skipped (driverless mode)");
                }

                main.ConfigureStartupSignatureIntel(intent.EnableSignatureIntel, intent.EnableSignatureIntelMemoryScan,
                                                    intent.EnableSignatureIntelPageScan);

                await ShowVirtualizationPreflightAsync(intent.EnableKernelDriver &&
                                                       intent.EnableAntiVirtualizationMasking);
            }

            if (intent.StartLaunchFlow)
            {
                await main.BeginStartupLaunchFlowAsync();
            }
            else if (!string.IsNullOrWhiteSpace(intent.SessionPath))
            {
                string openError = await main.TryOpenSessionFromStartupPathAsync(intent.SessionPath);
                if (!string.IsNullOrEmpty(openError))
                {
                    ThemedMessageBox.Show(main, $"Failed to open session.\n\n{openError}", "Open Session",
                                          MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }

            ShutdownMode = ShutdownMode.OnMainWindowClose;
        }

        private static async Task ShowVirtualizationPreflightAsync(bool antiVirtualizationMaskingEnabled)
        {
            VirtualizationProbeReport report = await Task.Run(VirtualizationProbe.Run);
            MessageBoxImage icon = report.VmLikely ? MessageBoxImage.Information : MessageBoxImage.Warning;
            string message = report.BuildOperatorMessage();

            if (antiVirtualizationMaskingEnabled)
            {
                message +=
                    "\n\nDriver anti-virtualization masking is enabled for this session. " +
                    "The host may still look virtualized here because this preflight reports the raw environment signals.";
            }

            ThemedMessageBox.Show(Current?.MainWindow, message, "Environment Preflight", MessageBoxButton.OK, icon);
        }

        private static async Task<bool> EnsureStartupSystemsReadyAsync(LoadingWindow loading, StartupIntent intent)
        {
            int attempt = 0;
            for (;;)
            {
                attempt++;
                loading.SetProgress(10, "Running startup preflight...",
                                    intent.EnableKernelDriver
                                        ? $"Attempt {attempt}: checking driver, controller, SR71, and broker link."
                                        : $"Attempt {attempt}: checking controller, SR71, and broker link.");
                await YieldForUiFrameAsync();

                BlackbirdPreflightReport report = await Task.Run(
                    () => BlackbirdPreflight.Run(0, ensureServicesRunning: true, requireDriverProxy: false,
                                                 enableKernelDriver: intent.EnableKernelDriver,
                                                 progress: (percent, status, detail) =>
                                                 {
                                                     double scaledPercent = 10 + (Math.Clamp(percent, 0, 100) * 0.18);
                                                     if (loading.Dispatcher.CheckAccess())
                                                     {
                                                         loading.SetProgress(scaledPercent, status, detail);
                                                         return;
                                                     }

                                                     loading.Dispatcher.Invoke(
                                                         () => loading.SetProgress(scaledPercent, status, detail));
                                                 }));
                DebugConsoleService.WriteLocal($"startup preflight ready={report.StartupReady}");
                if (report.StartupReady)
                {
                    loading.SetProgress(16, "Startup preflight ready", report.Summary);
                    await YieldForUiFrameAsync();
                    return true;
                }

                loading.SetProgress(16, "Startup preflight blocked", report.Summary);
                await YieldForUiFrameAsync();
                string fallbackPrompt =
                    intent.EnableKernelDriver && report.CanContinueDriverless
                        ? "\nChoose Yes to retry, No to continue in driverless mode, or Cancel to exit."
                        : "\nRetry startup preflight?";
                MessageBoxButton buttons = intent.EnableKernelDriver && report.CanContinueDriverless
                                               ? MessageBoxButton.YesNoCancel
                                               : MessageBoxButton.YesNo;
                MessageBoxResult choice =
                    ThemedMessageBox.Show(Current?.MainWindow, report.BuildStartupFailureMessage() + fallbackPrompt,
                                          "Startup System Preflight", buttons, MessageBoxImage.Error);
                if (choice == MessageBoxResult.No && intent.EnableKernelDriver && report.CanContinueDriverless)
                {
                    intent.EnableKernelDriver = false;
                    DiagnosticsState.SetValue("KM Driver", "Driverless mode selected after preflight failure");
                    loading.SetProgress(16, "Driverless mode selected",
                                        "Continuing with controller, SR71, and user-mode telemetry only.");
                    await YieldForUiFrameAsync();
                    return true;
                }
                if (choice != MessageBoxResult.Yes)
                {
                    return false;
                }
            }
        }

        private void OnDispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
        {
            // Mark handled first — this keeps the WPF message pump alive regardless.
            e.Handled = true;
            HandleFault(e.Exception, "UI thread");
        }

        private static void OnDomainUnhandledException(object sender, UnhandledExceptionEventArgs e)
        {
            // CLR background-thread fault. IsTerminating=true means the runtime will exit
            // after all handlers run — we cannot prevent it, but we can log and attempt to
            // show a blocking dialog so the analyst has a chance to read the message.
            Exception? ex = e.ExceptionObject as Exception;
            string source = e.IsTerminating ? "background thread (FATAL)" : "background thread";
            try
            {
                DebugConsoleService.WriteLocal($"[FAULT/{source}] {ex}");
            }
            catch
            {
            }
            DiagnosticsState.SetValue("Last Fault", $"{ex?.GetType().Name ?? "error"}: {ex?.Message}");

            if (e.IsTerminating)
            {
                try
                {
                    string msg = $"An unhandled exception on a background thread is terminating the interface.\n\n" +
                                 $"{ex?.GetType().Name}: {ex?.Message}\n\n{ex?.StackTrace}";
                    MessageBox.Show(msg, "Blackbird — Fatal Fault", MessageBoxButton.OK, MessageBoxImage.Error);
                }
                catch
                {
                }
            }
            else
            {
                Current?.Dispatcher.BeginInvoke(new Action(() => ShowFaultWindow(source, ex)),
                                                DispatcherPriority.ApplicationIdle);
            }
        }

        private static void OnUnobservedTaskException(object? sender, UnobservedTaskExceptionEventArgs e)
        {
            e.SetObserved();
            HandleFault(e.Exception, "async task");
        }

        private static void HandleFault(Exception? ex, string source)
        {
            try
            {
                DebugConsoleService.WriteLocal($"[FAULT/{source}] {ex}");
            }
            catch
            {
            }
            DiagnosticsState.SetValue("Last Fault", $"{ex?.GetType().Name ?? "error"}: {ex?.Message}");

            Application app = Current;
            if (app == null)
                return;

            app.Dispatcher.BeginInvoke(new Action(() => ShowFaultWindow(source, ex)),
                                       DispatcherPriority.ApplicationIdle);
        }

        private static void ShowFaultWindow(string source, Exception? ex)
        {
            // Re-entry guard: if building the fault window itself throws, don't recurse.
            if (System.Threading.Interlocked.CompareExchange(ref _faultHandlerDepth, 1, 0) != 0)
                return;
            try
            {
                var window = new FaultNotificationWindow(source, ex);
                window.Show();
            }
            catch
            {
            }
            finally
            {
                System.Threading.Interlocked.Exchange(ref _faultHandlerDepth, 0);
            }
        }

        private static async Task ShowStartupEnvironmentWarningsAsync()
        {
            await ShowSecurityProductWarningAsync();
            await Task.Delay(850);
            await ShowVmSafetyWarningAsync();
        }

        private static async Task ShowSecurityProductWarningAsync()
        {
            if (Interlocked.Exchange(ref _edrWarningShown, 1) != 0)
            {
                return;
            }

            SecurityProductProbeReport report;
            try
            {
                report = await Task.Run(SecurityProductProbe.Run);
            }
            catch
            {
                return;
            }

            if (!report.Detected)
            {
                DiagnosticsState.SetValue("Security Product Presence", "None detected");
                return;
            }

            DiagnosticsState.SetValue("Security Product Presence", report.Summary);
            DebugConsoleService.WriteLocal($"security products detected: {report.Summary}");
            try
            {
                var window = FaultNotificationWindow.CreateWarning(
                    "Security product detected",
                    "Another EDR/AV product appears to be active",
                    "Blackbird may be unstable, partially blocked, or unable to collect some telemetry correctly while another endpoint security product is present.",
                    report.BuildDetails());
                window.Show();
            }
            catch
            {
            }
        }

        private static async Task ShowVmSafetyWarningAsync()
        {
            if (Interlocked.Exchange(ref _vmSafetyWarningShown, 1) != 0)
            {
                return;
            }

            VmSafetyProbeReport report;
            try
            {
                report = await Task.Run(VmSafetyProbe.Run);
            }
            catch (Exception ex)
            {
                DiagnosticsState.SetValue("VM Safety", $"Probe failed: {ex.Message}");
                DebugConsoleService.WriteLocal($"vm safety probe failed: {ex}");
                OutputCapture.AppendLine($"VM safety probe failed: {ex.Message}");
                return;
            }

            DiagnosticsState.SetValue("VM Safety", report.Summary);
            DiagnosticsState.SetValue("VM Safety Findings",
                                      report.Findings.Count == 0
                                          ? "none"
                                          : string.Join("; ", report.Findings.Take(8)
                                                              .Select(static x =>
                                                                          $"[{x.Severity}] {x.Category}: {x.Summary}")));
            DebugConsoleService.WriteLocal($"vm safety preflight: {report.Summary}");
            OutputCapture.AppendLine($"VM safety preflight: {report.Summary}");
            foreach (VmSafetyFinding finding in report.Findings.OrderByDescending(static x => x.Severity).Take(12))
            {
                string line = $"VM safety [{finding.Severity}] {finding.Category}: {finding.Summary} ({finding.Evidence})";
                DebugConsoleService.WriteLocal(line);
                OutputCapture.AppendLine(line);
            }

            if (!report.ShouldWarn)
            {
                return;
            }

            if (AnalystSettingsStore.IsVmSafetyWarningIgnored())
            {
                DiagnosticsState.SetValue("VM Safety Warning", "Ignored by operator preference");
                DebugConsoleService.WriteLocal("vm safety warning suppressed by operator preference");
                OutputCapture.AppendLine("VM safety warning suppressed by operator preference");
                return;
            }

            try
            {
                var window = FaultNotificationWindow.CreateWarning(
                    "VM safety warning",
                    "VM isolation risks detected",
                    report.BuildToastMessage(),
                    report.BuildDetails(),
                    () =>
                    {
                        AnalystSettingsStore.SetVmSafetyWarningIgnored(true);
                        DiagnosticsState.SetValue("VM Safety Warning", "Ignored by operator preference");
                        DebugConsoleService.WriteLocal("vm safety warning ignored by operator");
                        OutputCapture.AppendLine("VM safety warning ignored by operator");
                    });
                window.Show();
            }
            catch
            {
            }
        }

        private static void HandleStartupFailure(Exception ex)
        {
            Exception root = ex;
            while (root.InnerException != null)
            {
                root = root.InnerException;
            }

            string message = $"Startup failed.\n\n" + $"Top: {ex.GetType().Name}: {ex.Message}\n\n" +
                             $"Root: {root.GetType().Name}: {root.Message}\n\n" + $"Top Stack:\n{ex.StackTrace}\n\n" +
                             $"Root Stack:\n{root.StackTrace}";
            try
            {
                DebugConsoleService.WriteLocal($"startup failure: {ex}");
                ThemedMessageBox.Show(Current?.MainWindow, message, "Blackbird Startup Failure", MessageBoxButton.OK,
                                      MessageBoxImage.Error);
            }
            catch
            {
            }

            if (Current != null)
            {
                Current.Shutdown();
            }
        }

        private static StartupOptions ParseStartupOptions(string[] args)
        {
            bool debugConsole =
#if TEMPUS_DEBUG
                true;
#else
                false;
#endif

            foreach (string arg in args)
            {
                if (string.Equals(arg, "--debug", StringComparison.OrdinalIgnoreCase))
                {
                    debugConsole = true;
                }
            }

            return new StartupOptions { DebugConsole = debugConsole };
        }

        private static void EnforceSingleInstance()
        {
            string mutexName = $@"Local\BlackbirdInterface.{Environment.UserName}";
            bool createdNew = false;
            _singleInstanceMutex = new Mutex(initiallyOwned: true, mutexName, out createdNew);
            if (createdNew)
            {
                return;
            }

            TerminatePreviousInstances();
        }

        private static void TerminatePreviousInstances()
        {
            Process current = Process.GetCurrentProcess();
            string? currentPath = ResolveCurrentExecutablePath();
            Process[] candidates = Process.GetProcessesByName(current.ProcessName);

            foreach (Process candidate in candidates)
            {
                try
                {
                    if (candidate.Id == current.Id)
                    {
                        continue;
                    }

                    string? candidatePath = null;
                    try
                    {
                        candidatePath = candidate.MainModule?.FileName;
                    }
                    catch
                    {
                    }

                    if (!string.IsNullOrWhiteSpace(currentPath) && !string.IsNullOrWhiteSpace(candidatePath) &&
                        !string.Equals(candidatePath, currentPath, StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    if (!candidate.HasExited)
                    {
                        candidate.Kill(entireProcessTree: true);
                        candidate.WaitForExit(3000);
                    }
                }
                catch
                {
                }
                finally
                {
                    candidate.Dispose();
                }
            }
        }

        private static uint GetPersistentRuntimeFlags()
        {
            const string parametersPath = @"SYSTEM\CurrentControlSet\Services\BK\Parameters";
            uint flags = 0;

            try
            {
                using RegistryKey? key = Registry.LocalMachine.OpenSubKey(parametersPath);
                if (key == null)
                {
                    return 0;
                }

                object? antiVirtualizationValue = key.GetValue("EnableAntiVirtualization");
                if (antiVirtualizationValue is int antiVirtualizationInt && antiVirtualizationInt != 0)
                {
                    flags |= BlackbirdNative.RuntimeFlagAntiVirtualization;
                }
                else if (antiVirtualizationValue is long antiVirtualizationLong && antiVirtualizationLong != 0)
                {
                    flags |= BlackbirdNative.RuntimeFlagAntiVirtualization;
                }

                object? selfHideValue = key.GetValue("EnableSelfHide");
                if (selfHideValue is int selfHideInt && selfHideInt != 0)
                {
                    flags |= BlackbirdNative.RuntimeFlagSelfHide;
                }
                else if (selfHideValue is long selfHideLong && selfHideLong != 0)
                {
                    flags |= BlackbirdNative.RuntimeFlagSelfHide;
                }

                object? interfaceProtectedAccessValue = key.GetValue("EnableInterfaceProtectedAccess");
                if (interfaceProtectedAccessValue is int interfaceProtectedAccessInt &&
                    interfaceProtectedAccessInt != 0)
                {
                    flags |= BlackbirdNative.RuntimeFlagInterfaceProtectedAccess;
                }
                else if (interfaceProtectedAccessValue is long interfaceProtectedAccessLong &&
                         interfaceProtectedAccessLong != 0)
                {
                    flags |= BlackbirdNative.RuntimeFlagInterfaceProtectedAccess;
                }

                object? controllerProtectedAccessValue = key.GetValue("EnableControllerProtectedAccess");
                if (controllerProtectedAccessValue is int controllerProtectedAccessInt &&
                    controllerProtectedAccessInt != 0)
                {
                    flags |= BlackbirdNative.RuntimeFlagControllerProtectedAccess;
                }
                else if (controllerProtectedAccessValue is long controllerProtectedAccessLong &&
                         controllerProtectedAccessLong != 0)
                {
                    flags |= BlackbirdNative.RuntimeFlagControllerProtectedAccess;
                }

                object? qpcTimingDisabledValue = key.GetValue("DisableQpcTimingCompensation");
                if (qpcTimingDisabledValue is int qpcTimingDisabledInt && qpcTimingDisabledInt != 0)
                {
                    flags |= BlackbirdNative.RuntimeFlagQpcTimingDisabled;
                }
                else if (qpcTimingDisabledValue is long qpcTimingDisabledLong && qpcTimingDisabledLong != 0)
                {
                    flags |= BlackbirdNative.RuntimeFlagQpcTimingDisabled;
                }
            }
            catch
            {
            }

            return flags;
        }

        private StartupIntent? ResolveStartupIntent()
        {
            while (true)
            {
                uint persistentRuntimeFlags = GetPersistentRuntimeFlags();
                var welcome = new StartupWelcomeWindow(
                    persistentRuntimeFlags) { WindowStartupLocation = WindowStartupLocation.CenterScreen };
                welcome.ShowInTaskbar = true;
                welcome.Topmost = true;
                welcome.Activate();
                welcome.Topmost = false;

                bool? result = welcome.ShowDialog();
                if (result != true)
                {
                    return null;
                }

                switch (welcome.SelectedAction)
                {
                case StartupWelcomeAction.Launch:
                    return new StartupIntent { StartLaunchFlow = true,
                                               EnableKernelDriver = welcome.EnableKernelDriver,
                                               EnableKernelHooks = welcome.EnableKernelHooks,
                                               EnableUsermodeHooks = welcome.EnableUsermodeHooks,
                                               EnableAntiVirtualizationMasking =
                                                   welcome.EnableAntiVirtualizationMasking,
                                               EnableQpcTimingCompensation = welcome.EnableQpcTimingCompensation,
                                               EnableControllerConcealment = welcome.EnableControllerConcealment,
                                               EnableInterfaceProtectedAccess = welcome.EnableInterfaceProtectedAccess,
                                               EnableControllerProtectedAccess =
                                                   welcome.EnableControllerProtectedAccess,
                                               EnableSignatureIntel = welcome.EnableSignatureIntel,
                                               EnableSignatureIntelMemoryScan = welcome.EnableSignatureIntelMemoryScan,
                                               EnableSignatureIntelPageScan = welcome.EnableSignatureIntelPageScan };
                case StartupWelcomeAction.OpenFile:
                {
                    string? sessionPath = PromptForSessionFile();
                    if (!string.IsNullOrWhiteSpace(sessionPath))
                    {
                        return new StartupIntent {
                            SessionPath = sessionPath,
                            EnableKernelDriver = welcome.EnableKernelDriver,
                            EnableKernelHooks = welcome.EnableKernelHooks,
                            EnableUsermodeHooks = welcome.EnableUsermodeHooks,
                            EnableAntiVirtualizationMasking = welcome.EnableAntiVirtualizationMasking,
                            EnableQpcTimingCompensation = welcome.EnableQpcTimingCompensation,
                            EnableControllerConcealment = welcome.EnableControllerConcealment,
                            EnableInterfaceProtectedAccess = welcome.EnableInterfaceProtectedAccess,
                            EnableControllerProtectedAccess = welcome.EnableControllerProtectedAccess,
                            EnableSignatureIntel = welcome.EnableSignatureIntel,
                            EnableSignatureIntelMemoryScan = welcome.EnableSignatureIntelMemoryScan,
                            EnableSignatureIntelPageScan = welcome.EnableSignatureIntelPageScan
                        };
                    }
                    break;
                }
                case StartupWelcomeAction.GettingStarted:
                    OpenGettingStartedLink(welcome);
                    break;
                }
            }
        }

        private static void OpenGettingStartedLink(Window owner)
        {
            try
            {
                Process.Start(new ProcessStartInfo { FileName = GettingStartedUrl, UseShellExecute = true });
            }
            catch (Exception ex)
            {
                ThemedMessageBox.Show(owner,
                                      $"Failed to open Getting Started.\n\n{ex.Message}\n\nURL: {GettingStartedUrl}",
                                      "Getting Started", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private static string? PromptForSessionFile()
        {
            var dialog = new OpenFileDialog {
                Filter =
                    "Blackbird Capture Archive (*.bkcap)|*.bkcap|Legacy Blackbird Session Archive (*.swlkr;*.blackbird)|*.swlkr;*.blackbird|All files (*.*)|*.*",
                CheckFileExists = true, Multiselect = false
            };

            return dialog.ShowDialog() == true ? dialog.FileName : null;
        }

        private static Task WaitForFirstRenderAsync(Window window)
        {
            var tcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            void OnContentRendered(object? sender, EventArgs e)
            {
                window.ContentRendered -= OnContentRendered;
                tcs.TrySetResult(true);
            }

            window.ContentRendered += OnContentRendered;
            return tcs.Task;
        }

        private static async Task YieldForUiFrameAsync()
        {
            await Application.Current.Dispatcher.InvokeAsync(() =>
                                                             {},
                                                             DispatcherPriority.Render);
        }

        private static void EnsureStartMenuShortcut()
        {
            try
            {
                string? exePath = ResolveCurrentExecutablePath();
                if (string.IsNullOrWhiteSpace(exePath) || !File.Exists(exePath))
                {
                    return;
                }

                string programsDirectory =
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.StartMenu), "Programs");
                Directory.CreateDirectory(programsDirectory);

                string shortcutPath = Path.Combine(programsDirectory, "Blackbird.lnk");

                Type? shellType = Type.GetTypeFromProgID("WScript.Shell");
                if (shellType == null)
                {
                    return;
                }

                object? shell = null;
                object? shortcut = null;
                try
                {
                    shell = Activator.CreateInstance(shellType);
                    if (shell == null)
                    {
                        return;
                    }

                    shortcut = shellType.InvokeMember("CreateShortcut", BindingFlags.InvokeMethod, binder: null,
                                                      target: shell, args: new object[] { shortcutPath });
                    if (shortcut == null)
                    {
                        return;
                    }

                    Type shortcutType = shortcut.GetType();
                    shortcutType.InvokeMember("TargetPath", BindingFlags.SetProperty, null, shortcut,
                                              new object[] { exePath });
                    shortcutType.InvokeMember("WorkingDirectory", BindingFlags.SetProperty, null, shortcut,
                                              new object[] { Path.GetDirectoryName(exePath) ?? string.Empty });
                    shortcutType.InvokeMember("Description", BindingFlags.SetProperty, null, shortcut,
                                              new object[] { ProductEdition.DisplayName });
                    shortcutType.InvokeMember("IconLocation", BindingFlags.SetProperty, null, shortcut,
                                              new object[] { $"{exePath},0" });
                    shortcutType.InvokeMember("Save", BindingFlags.InvokeMethod, null, shortcut, Array.Empty<object>());
                }
                finally
                {
                    if (shortcut != null)
                    {
                        Marshal.FinalReleaseComObject(shortcut);
                    }
                    if (shell != null)
                    {
                        Marshal.FinalReleaseComObject(shell);
                    }
                }
            }
            catch
            {
            }
        }

        private static string? ResolveCurrentExecutablePath()
        {
            string? processPath = Environment.ProcessPath;
            if (!string.IsNullOrWhiteSpace(processPath) &&
                string.Equals(Path.GetExtension(processPath), ".exe", StringComparison.OrdinalIgnoreCase))
            {
                return processPath;
            }

            using Process current = Process.GetCurrentProcess();
            string? mainModulePath = current.MainModule?.FileName;
            if (!string.IsNullOrWhiteSpace(mainModulePath) &&
                string.Equals(Path.GetExtension(mainModulePath), ".exe", StringComparison.OrdinalIgnoreCase))
            {
                return mainModulePath;
            }

            string? entryAssemblyName = Assembly.GetEntryAssembly()?.GetName().Name;
            if (!string.IsNullOrWhiteSpace(entryAssemblyName))
            {
                string entryAssemblyPath = Path.Combine(AppContext.BaseDirectory, entryAssemblyName + ".exe");
                if (File.Exists(entryAssemblyPath))
                {
                    return entryAssemblyPath;
                }
            }

            return null;
        }

        internal static void SetThemeMode(UiThemeMode mode)
        {
            if (Current is App app)
            {
                AnalystSettingsStore.SaveThemeMode(mode);
                app.ApplyTheme(mode);
            }
        }

        private void ApplyTheme(UiThemeMode mode)
        {
            CurrentThemeMode = mode;
            bool effectiveDark = ResolveEffectiveDarkMode(mode);

            Resources.MergedDictionaries.Clear();
            try
            {
                Resources.MergedDictionaries.Add(
                    new ResourceDictionary { Source = new Uri("Themes/DarkTheme.xaml", UriKind.Relative) });

                if (!effectiveDark)
                {
                    Resources.MergedDictionaries.Add(
                        new ResourceDictionary { Source = new Uri("Themes/LightTheme.xaml", UriKind.Relative) });
                }
            }
            catch
            {
                effectiveDark = true;
                Resources.MergedDictionaries.Clear();
                Resources.MergedDictionaries.Add(
                    new ResourceDictionary { Source = new Uri("Themes/DarkTheme.xaml", UriKind.Relative) });
            }

            IsDarkTheme = effectiveDark;
            Resources["IsDarkTheme"] = IsDarkTheme;

            foreach (Window window in Windows)
            {
                WindowThemeHelper.ApplyTitleBarTheme(window, IsDarkTheme);
                RebindThemedControlStyles(window);
            }

            ThemeChanged?.Invoke(IsDarkTheme);
        }

        private static bool ResolveEffectiveDarkMode(UiThemeMode mode)
        {
            switch (mode)
            {
            case UiThemeMode.Dark:
                return true;
            case UiThemeMode.Light:
                return false;
            case UiThemeMode.Auto:
            default:
                return !IsWindowsAppsLightThemeEnabled();
            }
        }

        private static bool IsWindowsAppsLightThemeEnabled()
        {
            try
            {
                using RegistryKey? key =
                    Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize");
                object? raw = key?.GetValue("AppsUseLightTheme");
                if (raw is int intValue)
                {
                    return intValue != 0;
                }

                if (raw is long longValue)
                {
                    return longValue != 0;
                }
            }
            catch
            {
            }

            return false;
        }

        private void RebindThemedControlStyles(Window window)
        {
            foreach (var element in EnumerateVisualTree(window))
            {
                if (element is DataGrid grid)
                {
                    if (grid.ReadLocalValue(FrameworkElement.StyleProperty) == DependencyProperty.UnsetValue)
                    {
                        grid.SetResourceReference(FrameworkElement.StyleProperty, "AppDataGridStyle");
                    }

                    if (grid.ReadLocalValue(DataGrid.RowStyleProperty) == DependencyProperty.UnsetValue)
                    {
                        grid.SetResourceReference(DataGrid.RowStyleProperty, "AppDataGridRowStyle");
                    }

                    if (grid.ReadLocalValue(DataGrid.CellStyleProperty) == DependencyProperty.UnsetValue)
                    {
                        grid.SetResourceReference(DataGrid.CellStyleProperty, "AppDataGridCellStyle");
                    }

                    if (grid.ReadLocalValue(DataGrid.ColumnHeaderStyleProperty) == DependencyProperty.UnsetValue)
                    {
                        grid.SetResourceReference(DataGrid.ColumnHeaderStyleProperty, "AppDataGridColumnHeaderStyle");
                    }

                    continue;
                }

                if (element is ListBox list && string.Equals(list.Name, "GraphExplorer", StringComparison.Ordinal))
                {
                    list.SetResourceReference(FrameworkElement.StyleProperty, "ExplorerListStyle");
                    list.SetResourceReference(ItemsControl.ItemContainerStyleProperty, "ExplorerItemStyle");
                    list.SetResourceReference(Control.BackgroundProperty, "WinPanelBrush");
                }
            }
        }

        private static IEnumerable<DependencyObject> EnumerateVisualTree(DependencyObject root)
        {
            var queue = new Queue<DependencyObject>();
            queue.Enqueue(root);
            while (queue.Count > 0)
            {
                var current = queue.Dequeue();
                yield return current;

                int count = VisualTreeHelper.GetChildrenCount(current);
                for (int i = 0; i < count; i += 1)
                {
                    queue.Enqueue(VisualTreeHelper.GetChild(current, i));
                }
            }
        }
    }
}
