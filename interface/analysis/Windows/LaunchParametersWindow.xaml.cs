using System.Windows;
using System.Windows.Input;

namespace BlackbirdInterface
{
    public partial class LaunchParametersWindow : Window
    {
        private readonly bool _isLaunchTarget;

        public bool UseUsermodeHooks { get; private set; } = true;
        public bool AutoOpenApiGraphWindow { get; private set; } = true;
        public bool UseEarlyBirdApcLaunch { get; private set; }

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

            if (ModeTitleBlock != null)
            {
                ModeTitleBlock.Text = _isLaunchTarget ? "Launch New Process" : "Attach to Running Process";
            }

            if (ModeDescriptionBlock != null)
            {
                ModeDescriptionBlock.Text = _isLaunchTarget
                    ? "Choose launch-time instrumentation and whether the interface should switch into API graph mode after hook start."
                    : "Choose attach-time instrumentation for the running target. EarlyBird APC is unavailable for this mode.";
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

            if (CompatibilityNoteBlock != null)
            {
                CompatibilityNoteBlock.Text = _isLaunchTarget
                    ? "EarlyBird APC is only used when launching a new process with usermode hooks enabled. If hooks are disabled, launch falls back to normal process start."
                    : "Attaching to a running process cannot use EarlyBird APC. That option is disabled automatically for attach mode.";
            }
        }

        private void UseUsermodeHooksCheckBox_Changed(object sender, RoutedEventArgs e)
        {
            UpdateUi();
        }

        private void Apply_Click(object sender, RoutedEventArgs e)
        {
            UseUsermodeHooks = UseUsermodeHooksCheckBox?.IsChecked == true;
            AutoOpenApiGraphWindow = UseUsermodeHooks && (AutoOpenApiGraphCheckBox?.IsChecked != false);
            UseEarlyBirdApcLaunch = UseUsermodeHooks && _isLaunchTarget && (EarlyBirdApcCheckBox?.IsChecked == true);
            DialogResult = true;
            Close();
        }

        private void Cancel_Click(object sender, RoutedEventArgs e)
        {
            DialogResult = false;
            Close();
        }

        private void Root_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
        {
            WindowChromeBehavior.HandleRootDragMove(this, e);
        }
    }
}

