using System;
using System.Linq;
using System.Windows;
using System.Windows.Input;

namespace BlackbirdInterface
{
    public partial class OperatorCaseWindow : Window
    {
        private OperatorCaseReport _report = new();

        private OperatorCaseWindow(OperatorCaseReport report)
        {
            InitializeComponent();
            WindowThemeHelper.WireThemeAwareTitleBar(this);
            LoadReport(report);
        }

        internal static void ShowForReport(Window? owner, OperatorCaseReport report)
        {
            OperatorCaseWindow? existing =
                Application.Current.Windows.OfType<OperatorCaseWindow>().FirstOrDefault(static x => x.IsVisible);

            if (existing != null)
            {
                existing.LoadReport(report);
                existing.Activate();
                return;
            }

            var window = new OperatorCaseWindow(report);
            if (owner != null && !ReferenceEquals(owner, window))
            {
                window.Owner = owner;
            }

            window.Show();
            window.Activate();
        }

        private void LoadReport(OperatorCaseReport report)
        {
            _report = report ?? new OperatorCaseReport();
            DataContext = _report;
            Title = "Operator Case";

            if (EvidenceGrid != null && EvidenceGrid.Items.Count > 0)
            {
                EvidenceGrid.SelectedIndex = 0;
            }
        }

        private void CopyReport_Click(object sender, RoutedEventArgs e)
        {
            _ = sender;
            _ = e;
            CopyToClipboard(_report.ReportText);
        }

        private void CopyIocs_Click(object sender, RoutedEventArgs e)
        {
            _ = sender;
            _ = e;
            CopyToClipboard(_report.IocText);
        }

        private static void CopyToClipboard(string text)
        {
            if (string.IsNullOrWhiteSpace(text))
            {
                return;
            }

            try
            {
                Clipboard.SetText(text);
            }
            catch (Exception)
            {
                // Clipboard may be locked by another process; the case window remains usable.
            }
        }

        private void Root_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
        {
            _ = sender;
            WindowChromeBehavior.HandleRootDragMove(this, e);
        }

        private void WindowMinimize_Click(object sender, RoutedEventArgs e)
        {
            _ = sender;
            _ = e;
            WindowChromeBehavior.Minimize(this);
        }

        private void WindowMaximize_Click(object sender, RoutedEventArgs e)
        {
            _ = sender;
            _ = e;
            WindowChromeBehavior.ToggleMaximize(this);
        }

        private void Close_Click(object sender, RoutedEventArgs e)
        {
            _ = sender;
            _ = e;
            WindowChromeBehavior.Close(this);
        }
    }
}
