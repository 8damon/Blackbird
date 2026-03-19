using System;
using System.Collections.Generic;
using System.Windows;
using System.Windows.Input;

namespace BlackbirdInterface
{
    public partial class ChildProcessGraphWindow : Window
    {
        public ChildProcessGraphWindow(int pid)
        {
            InitializeComponent();
            WindowThemeHelper.ApplyDarkTitleBar(this);
            SetTargetPid(pid);
            UpdateGraph(Array.Empty<GroupedEventRow>(), pid);
        }

        public void SetTargetPid(int pid)
        {
            TargetBlock.Text = pid > 0 ? $"PID {pid}" : "No target selected";
        }

        internal void UpdateGraph(IReadOnlyList<GroupedEventRow> rows, int rootPid)
        {
            var snapshot = ProcessGraphProjectionBuilder.Build(rows ?? Array.Empty<GroupedEventRow>(), rootPid > 0 ? (uint)rootPid : 0);
            RelationsTree.ItemsSource = snapshot.Roots;
            SummaryBlock.Text = snapshot.SummaryText;
            SetTargetPid(rootPid);
            NoDataOverlay.Visibility = snapshot.Roots.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        }

        private void Root_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
        {
            WindowChromeBehavior.HandleRootDragMove(this, e);
        }

        private void Close_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }
    }
}
