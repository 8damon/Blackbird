using System.Windows;
using System.Windows.Media;

namespace BlackbirdInterface
{
    public partial class MainWindow
    {
        private bool _kernelHooksArmed = true;

        private static readonly Brush HooksArmedBackground = new SolidColorBrush(Color.FromRgb(0x14, 0x2C, 0x1E));
        private static readonly Brush HooksArmedBorder = new SolidColorBrush(Color.FromRgb(0x3A, 0x8C, 0x52));
        private static readonly Brush HooksArmedForeground = new SolidColorBrush(Color.FromRgb(0x7E, 0xD6, 0x9A));
        private static readonly Brush HooksDisarmedBackground = new SolidColorBrush(Color.FromRgb(0x3B, 0x24, 0x11));
        private static readonly Brush HooksDisarmedBorder = new SolidColorBrush(Color.FromRgb(0xE1, 0x92, 0x2C));
        private static readonly Brush HooksDisarmedForeground = new SolidColorBrush(Color.FromRgb(0xF0, 0xAB, 0x4B));

        private void KernelHooks_Click(object sender, RoutedEventArgs e)
        {
            ToggleKernelHooksArmed();
        }

        private void ToggleKernelHooksArmed()
        {
            bool newArmed = !_kernelHooksArmed;

            uint flags = newArmed ? 0u : BlackbirdNative.RuntimeFlagNtApiHooksDisarmed;
            uint mask = BlackbirdNative.RuntimeFlagNtApiHooksDisarmed;

            // Disarming hooks forces anti-virtualization off
            if (!newArmed)
            {
                mask |= BlackbirdNative.RuntimeFlagAntiVirtualization;
            }

            if (!TryApplyRuntimeConfig(flags, mask, out _, out string error))
            {
                OutputCapture.AppendLine($"Failed to toggle kernel hooks: {error}");
                return;
            }

            SetKernelHooksArmed(newArmed);
        }

        internal void SetKernelHooksArmed(bool armed)
        {
            _kernelHooksArmed = armed;
            RefreshHooksButtonState();
        }

        private void RefreshHooksButtonState()
        {
            if (KernelHooksToggleButton == null)
            {
                return;
            }

            if (_kernelHooksArmed)
            {
                KernelHooksToggleButton.Background = HooksArmedBackground;
                KernelHooksToggleButton.BorderBrush = HooksArmedBorder;
                KernelHooksToggleButton.Foreground = HooksArmedForeground;
                if (KernelHooksToggleLabel != null)
                {
                    KernelHooksToggleLabel.Text = "Hooks ARMED";
                }
            }
            else
            {
                KernelHooksToggleButton.Background = HooksDisarmedBackground;
                KernelHooksToggleButton.BorderBrush = HooksDisarmedBorder;
                KernelHooksToggleButton.Foreground = HooksDisarmedForeground;
                if (KernelHooksToggleLabel != null)
                {
                    KernelHooksToggleLabel.Text = "Hooks DISARMED";
                }
            }
        }
    }
}
