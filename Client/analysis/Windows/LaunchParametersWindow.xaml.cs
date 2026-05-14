using System;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;

namespace BlackbirdInterface
{
    public partial class LaunchParametersWindow : Window
    {
        private readonly bool _isLaunchTarget;
        private readonly LaunchTargetKind _targetKind;
        private readonly bool _isDllTarget;

        public bool UseUsermodeHooks { get; private set; } = true;
        public bool UseKernelDriver { get; private set; } = true;
        public bool UseEarlyBirdApcLaunch { get; private set; }
        public bool EnableSignatureIntel { get; private set; } = true;
        public bool EnableSignatureIntelMemoryScan { get; private set; } = true;
        public bool EnableSignatureIntelPageScan { get; private set; } = true;
        public LaunchProfile LaunchProfile { get; } = new();

        public LaunchParametersWindow(bool isLaunchTarget, LaunchTargetKind targetKind = LaunchTargetKind.Executable,
                                      bool defaultUseUsermodeHooks = true, bool defaultUseKernelDriver = true,
                                      uint defaultRuntimeFlags = 0, bool defaultSignatureIntel = true,
                                      bool defaultSignatureIntelMemoryScan = true,
                                      bool defaultSignatureIntelPageScan = true)
        {
            _isLaunchTarget = isLaunchTarget;
            _targetKind = isLaunchTarget ? targetKind : LaunchTargetKind.Executable;
            _isDllTarget = _isLaunchTarget && _targetKind == LaunchTargetKind.Dll;

            InitializeComponent();
            WindowThemeHelper.WireThemeAwareTitleBar(this);
            if (UseKernelDriverCheckBox != null)
            {
                UseKernelDriverCheckBox.IsChecked = defaultUseKernelDriver;
            }
            if (EnableKernelHooksCheckBox != null)
            {
                EnableKernelHooksCheckBox.IsChecked =
                    defaultUseKernelDriver &&
                    (defaultRuntimeFlags & BlackbirdNative.RuntimeFlagNtApiHooksDisarmed) == 0;
            }
            if (UseUsermodeHooksCheckBox != null)
            {
                UseUsermodeHooksCheckBox.IsChecked = defaultUseUsermodeHooks;
            }
            if (EnableAntiVirtualizationMaskingCheckBox != null)
            {
                EnableAntiVirtualizationMaskingCheckBox.IsChecked =
                    defaultUseKernelDriver &&
                    (defaultRuntimeFlags & BlackbirdNative.RuntimeFlagAntiVirtualization) != 0;
            }
            if (EnableQpcTimingCompensationCheckBox != null)
            {
                EnableQpcTimingCompensationCheckBox.IsChecked =
                    (defaultRuntimeFlags & BlackbirdNative.RuntimeFlagAntiVirtualization) != 0 &&
                    (defaultRuntimeFlags & BlackbirdNative.RuntimeFlagQpcTimingDisabled) == 0;
            }
            if (EnableControllerConcealmentCheckBox != null)
            {
                EnableControllerConcealmentCheckBox.IsChecked =
                    defaultUseKernelDriver && (defaultRuntimeFlags & BlackbirdNative.RuntimeFlagSelfHide) != 0;
            }
            if (EnableInterfaceProtectedAccessCheckBox != null)
            {
                EnableInterfaceProtectedAccessCheckBox.IsChecked =
                    defaultUseKernelDriver &&
                    (defaultRuntimeFlags & BlackbirdNative.RuntimeFlagInterfaceProtectedAccess) != 0;
            }
            if (EnableSignatureIntelCheckBox != null)
            {
                EnableSignatureIntelCheckBox.IsChecked = defaultSignatureIntel;
            }
            if (EnableSignatureIntelMemoryScanCheckBox != null)
            {
                EnableSignatureIntelMemoryScanCheckBox.IsChecked = defaultSignatureIntelMemoryScan;
            }
            if (EnableSignatureIntelPageScanCheckBox != null)
            {
                EnableSignatureIntelPageScanCheckBox.IsChecked = defaultSignatureIntelPageScan;
            }
            InitializeDefaultParentPid();
            UpdateUi();
        }

        [DllImport("user32.dll")]
        private static extern IntPtr GetShellWindow();

        [DllImport("user32.dll")]
        private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint processId);

        private void UpdateUi()
        {
            if (UseUsermodeHooksCheckBox != null)
            {
                UseUsermodeHooksCheckBox.IsEnabled = !_isDllTarget;
                if (_isDllTarget)
                {
                    UseUsermodeHooksCheckBox.IsChecked = true;
                }
            }

            bool hooksEnabled = UseUsermodeHooksCheckBox?.IsChecked == true;
            bool driverEnabled = UseKernelDriverCheckBox?.IsChecked == true;
            bool kernelHooksEnabled = driverEnabled && EnableKernelHooksCheckBox?.IsChecked == true;
            bool canUseEarlyBird = hooksEnabled && _isLaunchTarget;
            bool launchControlsEnabled = _isLaunchTarget;

            if (EnableKernelHooksCheckBox != null)
            {
                EnableKernelHooksCheckBox.IsEnabled = driverEnabled;
                if (!driverEnabled)
                {
                    EnableKernelHooksCheckBox.IsChecked = false;
                }
            }

            if (ModeTitleBlock != null)
            {
                ModeTitleBlock.Text = _isDllTarget
                                          ? "Launch DLL Analysis Host"
                                          : (_isLaunchTarget ? "Launch New Process" : "Attach to Running Process");
            }

            if (ModeDescriptionBlock != null)
            {
                ModeDescriptionBlock.Text =
                    _isLaunchTarget
                        ? (_isDllTarget
                               ? "Blackbird will stage the DLL through BlackbirdDllHost.exe and bind the analysis subject to the DLL image path."
                               : "Phase 1 extends the existing launch path with execution context controls while keeping the ready-to-resume gate intact.")
                        : "Attach mode keeps the instrumentation controls, but launch-only options stay disabled because the process already exists.";
            }

            if (EarlyBirdApcCheckBox != null)
            {
                EarlyBirdApcCheckBox.IsEnabled = false;
                EarlyBirdApcCheckBox.IsChecked = canUseEarlyBird;
            }

            if (ConcealHookPresenceCheckBox != null)
            {
                ConcealHookPresenceCheckBox.IsEnabled = canUseEarlyBird;
                if (!canUseEarlyBird)
                {
                    ConcealHookPresenceCheckBox.IsChecked = false;
                }
            }

            if (EnableAntiVirtualizationMaskingCheckBox != null)
            {
                EnableAntiVirtualizationMaskingCheckBox.IsEnabled = kernelHooksEnabled;
                if (!kernelHooksEnabled)
                {
                    EnableAntiVirtualizationMaskingCheckBox.IsChecked = false;
                }
            }

            bool antiVirtualizationEnabled =
                kernelHooksEnabled && EnableAntiVirtualizationMaskingCheckBox?.IsChecked == true;
            if (EnableQpcTimingCompensationCheckBox != null)
            {
                EnableQpcTimingCompensationCheckBox.IsEnabled = antiVirtualizationEnabled;
                if (!antiVirtualizationEnabled)
                {
                    EnableQpcTimingCompensationCheckBox.IsChecked = false;
                }
            }

            if (EnableControllerConcealmentCheckBox != null)
            {
                EnableControllerConcealmentCheckBox.IsEnabled = driverEnabled;
                if (!driverEnabled)
                {
                    EnableControllerConcealmentCheckBox.IsChecked = false;
                }
            }

            if (EnableInterfaceProtectedAccessCheckBox != null)
            {
                EnableInterfaceProtectedAccessCheckBox.IsEnabled = driverEnabled;
                if (!driverEnabled)
                {
                    EnableInterfaceProtectedAccessCheckBox.IsChecked = false;
                }
            }

            bool signatureIntelEnabled = EnableSignatureIntelCheckBox?.IsChecked == true;
            if (EnableSignatureIntelMemoryScanCheckBox != null)
            {
                EnableSignatureIntelMemoryScanCheckBox.IsEnabled = signatureIntelEnabled;
                if (!signatureIntelEnabled)
                {
                    EnableSignatureIntelMemoryScanCheckBox.IsChecked = false;
                }
            }

            if (EnableSignatureIntelPageScanCheckBox != null)
            {
                EnableSignatureIntelPageScanCheckBox.IsEnabled = signatureIntelEnabled;
                if (!signatureIntelEnabled)
                {
                    EnableSignatureIntelPageScanCheckBox.IsChecked = false;
                }
            }

            if (LaunchPhaseOnePanel != null)
            {
                LaunchPhaseOnePanel.IsEnabled = launchControlsEnabled;
                LaunchPhaseOnePanel.Opacity = launchControlsEnabled ? 1.0 : 0.55;
            }

            if (LeaveSuspendedCheckBox != null)
            {
                LeaveSuspendedCheckBox.IsEnabled = launchControlsEnabled && hooksEnabled;
                LeaveSuspendedCheckBox.ToolTip =
                    hooksEnabled ? "Keep the target suspended after SR71 reaches the ready-to-resume gate."
                                 : "Requires SR71 usermode hooks; disabled because SR71 is off for this launch.";
                if (!hooksEnabled)
                {
                    LeaveSuspendedCheckBox.IsChecked = false;
                }
            }

            if (CommandLineArgumentsTextBox != null)
            {
                CommandLineArgumentsTextBox.IsEnabled = launchControlsEnabled && !_isDllTarget;
                CommandLineArgumentsTextBox.ToolTip =
                    _isDllTarget
                        ? "DLL host arguments are generated from the DLL Analysis controls below."
                        : "Arguments passed after the executable path. Preserve your own quoting, for example: --profile \"lab one\"";
                if (_isDllTarget)
                {
                    CommandLineArgumentsTextBox.Text = string.Empty;
                }
            }

            if (DllAnalysisPanel != null)
            {
                DllAnalysisPanel.Visibility = _isDllTarget ? Visibility.Visible : Visibility.Collapsed;
            }
            UpdateDllModeUi();

            if (IntegrityLevelComboBox != null)
            {
                IntegrityLevelComboBox.IsEnabled = launchControlsEnabled;
                if (!launchControlsEnabled)
                {
                    IntegrityLevelComboBox.SelectedIndex = 0;
                }
            }

            if (CompatibilityNoteBlock != null)
            {
                CompatibilityNoteBlock.Text =
                    !driverEnabled
                        ? "Driverless mode keeps SR71/user-mode telemetry available but disables kernel-only filesystem, registry, handle, and driver health visibility for this session."
                    : _isDllTarget
                        ? "DLL analysis requires the staged hook launch so Blackbird can bind kernel and hook attribution to the DLL rather than the host image."
                        : (_isLaunchTarget
                               ? "Spoof parent PID defaults to the interactive shell so the target does not obviously appear controller-launched. Override it for a specific launcher."
                               : "Launch-only controls are disabled for attach mode. APC launch only applies when creating a new process.");
            }
        }

        private void UpdateDllModeUi()
        {
            if (!_isDllTarget)
            {
                return;
            }

            DllLaunchMode mode = DllModeComboBox?.SelectedIndex switch
            {
                1 => DllLaunchMode.Export,
                2 => DllLaunchMode.Rundll,
                3 => DllLaunchMode.Register,
                4 => DllLaunchMode.Unregister,
                5 => DllLaunchMode.Install,
                _ => DllLaunchMode.Load
            };
            bool needsExport = mode is DllLaunchMode.Export or DllLaunchMode.Rundll;
            bool usesArgument = mode is DllLaunchMode.Rundll or DllLaunchMode.Install;
            bool isInstall = mode == DllLaunchMode.Install;

            if (DllExportTextBox != null)
            {
                DllExportTextBox.IsEnabled = needsExport;
            }
            if (DllOrdinalTextBox != null)
            {
                DllOrdinalTextBox.IsEnabled = needsExport;
            }
            if (DllArgumentTextBox != null)
            {
                DllArgumentTextBox.IsEnabled = usesArgument;
            }
            if (DllInstallDisableCheckBox != null)
            {
                DllInstallDisableCheckBox.IsEnabled = isInstall;
                if (!isInstall)
                {
                    DllInstallDisableCheckBox.IsChecked = false;
                }
            }
        }

        private void InitializeDefaultParentPid()
        {
            if (!_isLaunchTarget)
            {
                return;
            }

            uint defaultShellParentPid = ResolveInteractiveShellPid();
            if (defaultShellParentPid != 0 && ParentPidTextBox != null)
            {
                ParentPidTextBox.Text = defaultShellParentPid.ToString();
                ParentPidTextBox.ToolTip = $"Default PPID spoof target: {DescribeProcess(defaultShellParentPid)}";
            }
        }

        private static uint ResolveInteractiveShellPid()
        {
            try
            {
                IntPtr shellWindow = GetShellWindow();
                if (shellWindow != IntPtr.Zero)
                {
                    _ = GetWindowThreadProcessId(shellWindow, out uint shellPid);
                    if (shellPid != 0)
                    {
                        return shellPid;
                    }
                }
            }
            catch
            {
            }

            try
            {
                Process? explorer = Process.GetProcessesByName("explorer")
                                        .Where(static p => p.MainWindowHandle != IntPtr.Zero)
                                        .OrderBy(static p => p.StartTime)
                                        .FirstOrDefault();
                return explorer == null ? 0u : unchecked((uint)explorer.Id);
            }
            catch
            {
                return 0;
            }
        }

        private static string DescribeProcess(uint pid)
        {
            try
            {
                using Process process = Process.GetProcessById(unchecked((int)pid));
                return $"{process.ProcessName} ({pid})";
            }
            catch
            {
                return pid.ToString();
            }
        }

        private void UseUsermodeHooksCheckBox_Changed(object sender, RoutedEventArgs e)
        {
            UpdateUi();
        }

        private void Apply_Click(object sender, RoutedEventArgs e)
        {
            if (!TryPopulateLaunchProfile(out string error))
            {
                ThemedMessageBox.Show(this, error, "Invalid launch options", MessageBoxButton.OK,
                                      MessageBoxImage.Warning);
                return;
            }

            ApplyLaunchHookOptions();
            DialogResult = true;
            Close();
        }

        private bool TryPopulateLaunchProfile(out string error)
        {
            error = string.Empty;

            LaunchProfile.TargetKind = _targetKind;
            LaunchProfile.WorkingDirectory =
                _isLaunchTarget ? (WorkingDirectoryTextBox?.Text?.Trim() ?? string.Empty) : string.Empty;
            LaunchProfile.CommandLineArguments = _isLaunchTarget && !_isDllTarget
                                                     ? (CommandLineArgumentsTextBox?.Text?.Trim() ?? string.Empty)
                                                     : string.Empty;
            LaunchProfile.EnvironmentOverridesText =
                _isLaunchTarget ? (EnvironmentOverridesTextBox?.Text ?? string.Empty) : string.Empty;
            bool driverEnabled = UseKernelDriverCheckBox?.IsChecked == true;
            bool hooksEnabled = UseUsermodeHooksCheckBox?.IsChecked == true;
            bool kernelHooksEnabled = driverEnabled && EnableKernelHooksCheckBox?.IsChecked == true;
            bool antiVirtualizationEnabled =
                kernelHooksEnabled && EnableAntiVirtualizationMaskingCheckBox?.IsChecked == true;
            LaunchProfile.EnableKernelHooks = kernelHooksEnabled;
            LaunchProfile.EnableAntiVirtualizationMasking = antiVirtualizationEnabled;
            LaunchProfile.EnableQpcTimingCompensation =
                antiVirtualizationEnabled && EnableQpcTimingCompensationCheckBox?.IsChecked == true;
            LaunchProfile.EnableControllerConcealment =
                driverEnabled && EnableControllerConcealmentCheckBox?.IsChecked == true;
            LaunchProfile.EnableInterfaceProtectedAccess =
                driverEnabled && EnableInterfaceProtectedAccessCheckBox?.IsChecked == true;
            LaunchProfile.EnableControllerProtectedAccess = driverEnabled;
            LaunchProfile.LeaveSuspendedAfterReady =
                _isLaunchTarget && hooksEnabled && (LeaveSuspendedCheckBox?.IsChecked == true);
            LaunchProfile.ConcealHookPresence = _isLaunchTarget && (ConcealHookPresenceCheckBox?.IsChecked == true);
            LaunchProfile.InheritHandles = _isLaunchTarget && (InheritHandlesCheckBox?.IsChecked == true);
            LaunchProfile.ParentProcessId = 0;
            LaunchProfile.AffinityMask = 0;
            LaunchProfile.Priority = PriorityComboBox?.SelectedIndex switch
            {
                1 => LaunchPriorityPreset.Idle,
                2 => LaunchPriorityPreset.BelowNormal,
                3 => LaunchPriorityPreset.Normal,
                4 => LaunchPriorityPreset.AboveNormal,
                5 => LaunchPriorityPreset.High,
                6 => LaunchPriorityPreset.Realtime,
                _ => LaunchPriorityPreset.Inherit
            };

            LaunchProfile.IntegrityLevel = _isLaunchTarget ? IntegrityLevelComboBox?.SelectedIndex switch
            {
                1 => LaunchIntegrityLevel.Untrusted,
                2 => LaunchIntegrityLevel.Low,
                3 => LaunchIntegrityLevel.Medium,
                4 => LaunchIntegrityLevel.High,
                5 => LaunchIntegrityLevel.System,
                _ => LaunchIntegrityLevel.Default
            } : LaunchIntegrityLevel.Default;

            if (!_isLaunchTarget)
            {
                return true;
            }

            if (!_isDllTarget && LaunchProfile.CommandLineArguments.IndexOf('\0') >= 0)
            {
                error = "Command-line arguments cannot contain NUL characters.";
                return false;
            }

            if (_isDllTarget && !TryPopulateDllOptions(out error))
            {
                return false;
            }

            string parentPidText = ParentPidTextBox?.Text?.Trim() ?? string.Empty;
            if (parentPidText.Length > 0 && (!uint.TryParse(parentPidText, out uint parentPid) || parentPid == 0))
            {
                error = "Parent process PID must be a valid positive integer.";
                return false;
            }
            LaunchProfile.ParentProcessId = parentPidText.Length == 0 ? 0u : uint.Parse(parentPidText);

            string affinityText = AffinityMaskTextBox?.Text?.Trim() ?? string.Empty;
            if (!LaunchProfile.TryParseAffinityMask(affinityText, out ulong affinityMask))
            {
                error = "Affinity mask must be decimal or hex, for example 15 or 0x0F.";
                return false;
            }
            LaunchProfile.AffinityMask = affinityMask;

            if (!LaunchProfile.TryParseEnvironmentOverrides(out _, out string envError))
            {
                error = envError;
                return false;
            }

            return true;
        }

        private bool TryPopulateDllOptions(out string error)
        {
            error = string.Empty;
            LaunchProfile.DllMode = DllModeComboBox?.SelectedIndex switch
            {
                1 => DllLaunchMode.Export,
                2 => DllLaunchMode.Rundll,
                3 => DllLaunchMode.Register,
                4 => DllLaunchMode.Unregister,
                5 => DllLaunchMode.Install,
                _ => DllLaunchMode.Load
            };
            LaunchProfile.DllExportName = DllExportTextBox?.Text?.Trim() ?? string.Empty;
            LaunchProfile.DllArgument = DllArgumentTextBox?.Text ?? string.Empty;
            LaunchProfile.DllFreeOnExit = DllFreeOnExitCheckBox?.IsChecked == true;
            LaunchProfile.DllInstallDisable =
                LaunchProfile.DllMode == DllLaunchMode.Install && DllInstallDisableCheckBox?.IsChecked == true;

            if (LaunchProfile.DllExportName.IndexOf('\0') >= 0 || LaunchProfile.DllArgument.IndexOf('\0') >= 0)
            {
                error = "DLL analysis fields cannot contain NUL characters.";
                return false;
            }

            if (!TryParseUInt32Text(DllOrdinalTextBox?.Text, "Export ordinal", allowEmpty: true, out uint ordinal,
                                    out error))
            {
                return false;
            }
            LaunchProfile.DllExportOrdinal = ordinal;

            if (!TryParseUInt32Text(DllLoadFlagsTextBox?.Text, "Load flags", allowEmpty: true, out uint loadFlags,
                                    out error))
            {
                return false;
            }
            LaunchProfile.DllLoadFlags = loadFlags;

            if (!TryParseUInt32Text(DllWaitMsTextBox?.Text, "Hold time", allowEmpty: true, out uint waitMs, out error))
            {
                return false;
            }
            LaunchProfile.DllWaitMilliseconds =
                waitMs == 0 && string.IsNullOrWhiteSpace(DllWaitMsTextBox?.Text) ? 60000u : waitMs;

            if (LaunchProfile.DllMode is DllLaunchMode.Export or DllLaunchMode.Rundll &&
                !LaunchProfile.HasDllExportName && !LaunchProfile.HasDllExportOrdinal)
            {
                error = "DLL export mode requires an export name or ordinal.";
                return false;
            }

            return true;
        }

        private static bool TryParseUInt32Text(string? text, string label, bool allowEmpty, out uint value,
                                               out string error)
        {
            value = 0;
            error = string.Empty;
            string trimmed = (text ?? string.Empty).Trim();
            if (trimmed.Length == 0)
            {
                if (allowEmpty)
                {
                    return true;
                }

                error = $"{label} is required.";
                return false;
            }

            bool parsed =
                trimmed.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
                    ? uint.TryParse(trimmed.AsSpan(2), System.Globalization.NumberStyles.HexNumber, null, out value)
                    : uint.TryParse(trimmed, out value);
            if (!parsed)
            {
                error = $"{label} must be a decimal or hex integer.";
                return false;
            }

            return true;
        }

        private void DllModeComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            UpdateDllModeUi();
        }

        private void UseShellParent_Click(object sender, RoutedEventArgs e)
        {
            uint shellPid = ResolveInteractiveShellPid();
            if (shellPid == 0)
            {
                ThemedMessageBox.Show(this, "Could not resolve the interactive shell process.", "Parent PID",
                                      MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            ParentPidTextBox.Text = shellPid.ToString();
            ParentPidTextBox.ToolTip = $"Default PPID spoof target: {DescribeProcess(shellPid)}";
        }

        private void Cancel_Click(object sender, RoutedEventArgs e)
        {
            DialogResult = false;
            Close();
        }

        private void ApplyLaunchHookOptions()
        {
            LaunchHookOptions state = LaunchHookOptions.Capture(UseUsermodeHooksCheckBox?.IsChecked,
                                                                EarlyBirdApcCheckBox?.IsChecked, _isLaunchTarget);

            UseUsermodeHooks = state.UseUsermodeHooks;
            UseKernelDriver = UseKernelDriverCheckBox?.IsChecked == true;
            UseEarlyBirdApcLaunch = state.UseEarlyBirdApcLaunch;
            EnableSignatureIntel = EnableSignatureIntelCheckBox?.IsChecked == true;
            EnableSignatureIntelMemoryScan =
                EnableSignatureIntel && EnableSignatureIntelMemoryScanCheckBox?.IsChecked == true;
            EnableSignatureIntelPageScan =
                EnableSignatureIntel && EnableSignatureIntelPageScanCheckBox?.IsChecked == true;
            if (_isDllTarget)
            {
                UseUsermodeHooks = true;
                UseEarlyBirdApcLaunch = true;
            }
        }

        private void Root_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
        {
            WindowChromeBehavior.HandleRootDragMove(this, e);
        }
    }
}
