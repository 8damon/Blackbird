using System.Windows;
using System.Windows.Input;
using BlackbirdOperator.Models;

namespace BlackbirdOperator;

public partial class OperatorStartupWindow : Window
{
    public OperatorDiscoveryOptions? SelectedOptions { get; private set; }

    public OperatorStartupWindow(IReadOnlyList<OperatorAdapterOption> adapters, OperatorDiscoveryOptions defaults)
    {
        InitializeComponent();
        AdapterCombo.ItemsSource = adapters;

        int selectedIndex = 0;
        if (!string.IsNullOrWhiteSpace(defaults.PreferredInterfaceId))
        {
            int matchIndex = adapters.ToList().FindIndex(item =>
                string.Equals(item.InterfaceId, defaults.PreferredInterfaceId, StringComparison.OrdinalIgnoreCase));
            if (matchIndex >= 0)
            {
                selectedIndex = matchIndex;
            }
        }

        if (adapters.Count > 0)
        {
            AdapterCombo.SelectedIndex = selectedIndex;
        }

        PassiveDiscoveryCheckBox.IsChecked = defaults.EnablePassiveDiscovery;
        ActiveProbeCheckBox.IsChecked = defaults.EnableActiveSubnetProbe;
    }

    private void Root_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (e.ChangedButton != MouseButton.Left || e.ClickCount != 1)
        {
            return;
        }

        try
        {
            DragMove();
        }
        catch
        {
        }
    }

    private void Start_Click(object sender, RoutedEventArgs e)
    {
        SelectedOptions = new OperatorDiscoveryOptions
        {
            EnablePassiveDiscovery = PassiveDiscoveryCheckBox.IsChecked != false,
            EnableActiveSubnetProbe = ActiveProbeCheckBox.IsChecked == true,
            PreferredInterfaceId = (AdapterCombo.SelectedItem as OperatorAdapterOption)?.InterfaceId,
            MaxProbeHosts = 256
        };

        DialogResult = true;
        Close();
    }

    private void Cancel_Click(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
        Close();
    }
}
