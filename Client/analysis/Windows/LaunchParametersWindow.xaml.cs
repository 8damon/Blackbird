using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;

namespace BlackbirdInterface
{
    public partial class LaunchParametersWindow : Window
    {
        private readonly bool _isLaunchTarget;

        public bool UseUsermodeHooks { get; private set; } = true;
        public bool AutoOpenApiGraphWindow { get; private set; } = true;
        public bool UseEarlyBirdApcLaunch { get; private set; }
        public LaunchProfile LaunchProfile { get; } = new();

        public LaunchParametersWindow(bool isLaunchTarget)
        {
            _isLaunchTarget = isLaunchTarget;

            InitializeComponent();
            WindowThemeHelper.ApplyTitleBarTheme(this, App.IsDarkTheme);
            UpdateUi();
        }

        private void UpdateUi()
        {
            bool hooksEnabled = UseUsermodeHooksCheckBox?.IsChecked == true;
            bool canUseEarlyBird = hooksEnabled && _isLaunchTarget;
            bool launchControlsEnabled = _isLaunchTarget;

            if (ModeTitleBlock != null)
            {
                ModeTitleBlock.Text = _isLaunchTarget ? "Launch New Process" : "Attach to Running Process";
            }

            if (ModeDescriptionBlock != null)
            {
                ModeDescriptionBlock.Text = _isLaunchTarget
                    ? "Phase 1 extends the existing launch path with execution context controls while keeping the ready-to-resume gate intact."
                    : "Attach mode keeps the instrumentation controls, but launch-only options stay disabled because the process already exists.";
            }

            if (AutoOpenApiGraphCheckBox != null)
            {
                AutoOpenApiGraphCheckBox.IsEnabled = hooksEnabled;
                if (!hooksEnabled)
                {
                    AutoOpenApiGraphCheckBox.IsChecked = false;
                }
            }

            if (EarlyBirdApcCheckBox != null)
            {
                EarlyBirdApcCheckBox.IsEnabled = canUseEarlyBird;
                if (!canUseEarlyBird)
                {
                    EarlyBirdApcCheckBox.IsChecked = false;
                }
            }

            if (LaunchPhaseOnePanel != null)
            {
                LaunchPhaseOnePanel.IsEnabled = launchControlsEnabled;
                LaunchPhaseOnePanel.Opacity = launchControlsEnabled ? 1.0 : 0.55;
            }

            if (CompatibilityNoteBlock != null)
            {
                CompatibilityNoteBlock.Text = _isLaunchTarget
                    ? "Parent PID and inherited handles only apply when creating a new process."
                    : "Launch-only controls are disabled for attach mode. EarlyBird APC is also unavailable because the process is already running.";
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
                ThemedMessageBox.Show(this, error, "Invalid launch options", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            ApplyLaunchHookOptions();
            DialogResult = true;
            Close();
        }

        private bool TryPopulateLaunchProfile(out string error)
        {
            error = string.Empty;

            LaunchProfile.WorkingDirectory = _isLaunchTarget ? (WorkingDirectoryTextBox?.Text?.Trim() ?? string.Empty) : string.Empty;
            LaunchProfile.EnvironmentOverridesText = _isLaunchTarget ? (EnvironmentOverridesTextBox?.Text ?? string.Empty) : string.Empty;
            LaunchProfile.LeaveSuspendedAfterReady = _isLaunchTarget && (LeaveSuspendedCheckBox?.IsChecked == true);
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

            if (!_isLaunchTarget)
            {
                return true;
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

        private void Cancel_Click(object sender, RoutedEventArgs e)
        {
            DialogResult = false;
            Close();
        }

        private void ApplyLaunchHookOptions()
        {
            LaunchHookOptions state = LaunchHookOptions.Capture(
                UseUsermodeHooksCheckBox?.IsChecked,
                AutoOpenApiGraphCheckBox?.IsChecked,
                EarlyBirdApcCheckBox?.IsChecked,
                _isLaunchTarget);

            UseUsermodeHooks = state.UseUsermodeHooks;
            AutoOpenApiGraphWindow = state.AutoOpenApiGraphWindow;
            UseEarlyBirdApcLaunch = state.UseEarlyBirdApcLaunch;
        }

        private void Root_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
        {
            WindowChromeBehavior.HandleRootDragMove(this, e);
        }
    }
}
