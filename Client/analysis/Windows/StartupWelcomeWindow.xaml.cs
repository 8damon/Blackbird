using System.Collections.Generic;
using System.Windows;
using System.Windows.Input;

namespace BlackbirdInterface
{
    internal enum StartupWelcomeAction
    {
        None,
        Launch,
        OpenFile,
        GettingStarted
    }

    public partial class StartupWelcomeWindow : Window
    {
        private readonly bool _forceAntiVirtualizationMasking;
        private readonly bool _forceQpcTimingDisabled;
        private readonly bool _forceControllerConcealment;
        private readonly bool _forceInterfaceProtectedAccess;

        internal StartupWelcomeAction SelectedAction { get; private set; }
        internal bool EnableKernelHooks => EnableKernelHooksCheckBox?.IsChecked == true;
        internal bool EnableAntiVirtualizationMasking =>
            EnableKernelHooks &&
            (_forceAntiVirtualizationMasking || (EnableAntiVirtualizationMaskingCheckBox?.IsChecked == true));
        internal bool EnableQpcTimingCompensation => EnableAntiVirtualizationMasking && !_forceQpcTimingDisabled &&
                                                     (EnableQpcTimingCompensationCheckBox?.IsChecked == true);
        internal bool EnableControllerConcealment =>
            _forceControllerConcealment || (EnableControllerConcealmentCheckBox?.IsChecked == true);
        internal bool EnableInterfaceProtectedAccess =>
            _forceInterfaceProtectedAccess || (EnableInterfaceProtectedAccessCheckBox?.IsChecked == true);
        internal bool EnableControllerProtectedAccess => true;
        internal bool EnableSignatureIntel => EnableSignatureIntelCheckBox?.IsChecked == true;
        internal bool EnableSignatureIntelMemoryScan => EnableSignatureIntelMemoryScanCheckBox?.IsChecked == true;
        internal bool EnableSignatureIntelPageScan => EnableSignatureIntelPageScanCheckBox?.IsChecked == true;

        public StartupWelcomeWindow(uint persistentRuntimeFlags = 0)
        {
            _forceAntiVirtualizationMasking =
                (persistentRuntimeFlags & BlackbirdNative.RuntimeFlagAntiVirtualization) != 0;
            _forceQpcTimingDisabled = (persistentRuntimeFlags & BlackbirdNative.RuntimeFlagQpcTimingDisabled) != 0;
            _forceControllerConcealment = (persistentRuntimeFlags & BlackbirdNative.RuntimeFlagSelfHide) != 0;
            _forceInterfaceProtectedAccess =
                (persistentRuntimeFlags & BlackbirdNative.RuntimeFlagInterfaceProtectedAccess) != 0;

            InitializeComponent();
            WindowThemeHelper.WireThemeAwareTitleBar(this);
            ApplyRuntimeConfigUi();
        }

        private void KernelHooksCheckBox_Changed(object sender, RoutedEventArgs e)
        {
            bool hooksEnabled = EnableKernelHooksCheckBox?.IsChecked == true;
            if (EnableAntiVirtualizationMaskingCheckBox != null)
            {
                EnableAntiVirtualizationMaskingCheckBox.IsEnabled = hooksEnabled && !_forceAntiVirtualizationMasking;
                if (!hooksEnabled)
                {
                    EnableAntiVirtualizationMaskingCheckBox.IsChecked = false;
                }
            }

            UpdateSubsystemOptionUi();
        }

        private void SubsystemOptions_Changed(object sender, RoutedEventArgs e)
        {
            if (ReferenceEquals(sender, EnableAntiVirtualizationMaskingCheckBox) &&
                EnableAntiVirtualizationMaskingCheckBox?.IsChecked == true &&
                EnableQpcTimingCompensationCheckBox != null && !_forceQpcTimingDisabled)
            {
                EnableQpcTimingCompensationCheckBox.IsChecked = true;
            }

            UpdateSubsystemOptionUi();
        }

        private void ApplyRuntimeConfigUi()
        {
            if (EnableAntiVirtualizationMaskingCheckBox != null)
            {
                EnableAntiVirtualizationMaskingCheckBox.IsChecked = _forceAntiVirtualizationMasking;
                EnableAntiVirtualizationMaskingCheckBox.IsEnabled = !_forceAntiVirtualizationMasking;
            }

            if (EnableControllerConcealmentCheckBox != null)
            {
                EnableControllerConcealmentCheckBox.IsChecked = _forceControllerConcealment;
                EnableControllerConcealmentCheckBox.IsEnabled = !_forceControllerConcealment;
            }

            if (EnableQpcTimingCompensationCheckBox != null)
            {
                EnableQpcTimingCompensationCheckBox.IsChecked = !_forceQpcTimingDisabled;
                EnableQpcTimingCompensationCheckBox.IsEnabled = !_forceQpcTimingDisabled;
            }

            if (EnableInterfaceProtectedAccessCheckBox != null)
            {
                EnableInterfaceProtectedAccessCheckBox.IsChecked = _forceInterfaceProtectedAccess;
                EnableInterfaceProtectedAccessCheckBox.IsEnabled = !_forceInterfaceProtectedAccess;
            }

            if (RuntimeConfigNoteBlock != null)
            {
                if (EnableSignatureIntelCheckBox != null)
                {
                    EnableSignatureIntelCheckBox.IsChecked = true;
                }

                var forcedItems = new List<string>();
                if (_forceAntiVirtualizationMasking)
                {
                    forcedItems.Add("anti-virtualization masking");
                }
                if (_forceControllerConcealment)
                {
                    forcedItems.Add("controller concealment");
                }
                if (_forceInterfaceProtectedAccess)
                {
                    forcedItems.Add("interface protection");
                }

                if (forcedItems.Count != 0)
                {
                    RuntimeConfigNoteBlock.Text =
                        $"Installed driver defaults keep {string.Join(" and ", forcedItems)} enabled.";
                    RuntimeConfigNoteBlock.Visibility = Visibility.Visible;
                }
                else
                {
                    RuntimeConfigNoteBlock.Text = string.Empty;
                    RuntimeConfigNoteBlock.Visibility = Visibility.Collapsed;
                }
            }

            UpdateSubsystemOptionUi();
        }

        private void UpdateSubsystemOptionUi()
        {
            bool signatureIntelEnabled = EnableSignatureIntelCheckBox?.IsChecked == true;
            bool qpcTimingAvailable = EnableAntiVirtualizationMasking && !_forceQpcTimingDisabled;
            if (EnableQpcTimingCompensationCheckBox != null)
            {
                EnableQpcTimingCompensationCheckBox.IsEnabled = qpcTimingAvailable;
                if (!qpcTimingAvailable)
                {
                    EnableQpcTimingCompensationCheckBox.IsChecked = false;
                }
            }

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
        }

        private void OpenTraceFile_Click(object sender, RoutedEventArgs e)
        {
            SelectedAction = StartupWelcomeAction.OpenFile;
            DialogResult = true;
            Close();
        }

        private void Launch_Click(object sender, RoutedEventArgs e)
        {
            SelectedAction = StartupWelcomeAction.Launch;
            DialogResult = true;
            Close();
        }

        private void GettingStarted_Click(object sender, RoutedEventArgs e)
        {
            SelectedAction = StartupWelcomeAction.GettingStarted;
            DialogResult = true;
            Close();
        }

        private void Close_Click(object sender, RoutedEventArgs e)
        {
            SelectedAction = StartupWelcomeAction.None;
            DialogResult = false;
            Close();
        }

        private void Root_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
        {
            WindowChromeBehavior.HandleRootDragMove(this, e);
        }
    }
}
