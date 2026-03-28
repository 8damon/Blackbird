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
        private readonly bool _forceControllerConcealment;
        private readonly bool _forceInterfaceProtectedAccess;
        private readonly bool _forceControllerProtectedAccess;

        internal StartupWelcomeAction SelectedAction { get; private set; }
        internal bool EnableAntiVirtualizationMasking => _forceAntiVirtualizationMasking || (EnableAntiVirtualizationMaskingCheckBox?.IsChecked == true);
        internal bool EnableControllerConcealment => _forceControllerConcealment || (EnableControllerConcealmentCheckBox?.IsChecked == true);
        internal bool EnableInterfaceProtectedAccess => _forceInterfaceProtectedAccess || (EnableInterfaceProtectedAccessCheckBox?.IsChecked == true);
        internal bool EnableControllerProtectedAccess => _forceControllerProtectedAccess || (EnableControllerProtectedAccessCheckBox?.IsChecked == true);

        public StartupWelcomeWindow(uint persistentRuntimeFlags = 0)
        {
            _forceAntiVirtualizationMasking = (persistentRuntimeFlags & BlackbirdNative.RuntimeFlagAntiVirtualization) != 0;
            _forceControllerConcealment = (persistentRuntimeFlags & BlackbirdNative.RuntimeFlagSelfHide) != 0;
            _forceInterfaceProtectedAccess = (persistentRuntimeFlags & BlackbirdNative.RuntimeFlagInterfaceProtectedAccess) != 0;
            _forceControllerProtectedAccess = (persistentRuntimeFlags & BlackbirdNative.RuntimeFlagControllerProtectedAccess) != 0;

            InitializeComponent();
            ApplyRuntimeConfigUi();
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

            if (EnableInterfaceProtectedAccessCheckBox != null)
            {
                EnableInterfaceProtectedAccessCheckBox.IsChecked = _forceInterfaceProtectedAccess;
                EnableInterfaceProtectedAccessCheckBox.IsEnabled = !_forceInterfaceProtectedAccess;
            }

            if (EnableControllerProtectedAccessCheckBox != null)
            {
                EnableControllerProtectedAccessCheckBox.IsChecked = _forceControllerProtectedAccess;
                EnableControllerProtectedAccessCheckBox.IsEnabled = !_forceControllerProtectedAccess;
            }

            if (RuntimeConfigNoteBlock != null)
            {
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
                if (_forceControllerProtectedAccess)
                {
                    forcedItems.Add("controller protection");
                }

                if (forcedItems.Count != 0)
                {
                    RuntimeConfigNoteBlock.Text = $"Installed driver defaults keep {string.Join(" and ", forcedItems)} enabled.";
                    RuntimeConfigNoteBlock.Visibility = Visibility.Visible;
                }
                else
                {
                    RuntimeConfigNoteBlock.Text = string.Empty;
                    RuntimeConfigNoteBlock.Visibility = Visibility.Collapsed;
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
