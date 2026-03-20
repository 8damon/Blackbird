using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows;
using System.Windows.Input;

namespace BlackbirdInterface
{
    public partial class ChildProcessGraphWindow : Window
    {
        private readonly HashSet<string> _expandedKeys = new(StringComparer.Ordinal);
        private bool _preferInjectedExpansionState;

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
            if (_preferInjectedExpansionState)
            {
                _preferInjectedExpansionState = false;
            }
            else
            {
                CaptureExpandedState(RelationsTree.ItemsSource as IEnumerable<ProcessGraphNodeView>);
            }

            var snapshot = ProcessGraphProjectionBuilder.Build(rows ?? Array.Empty<GroupedEventRow>(), rootPid > 0 ? (uint)rootPid : 0);
            ApplyExpandedState(snapshot.Roots, isRoot: true);
            RelationsTree.ItemsSource = snapshot.Roots;
            InboundHandlesList.ItemsSource = snapshot.InboundHandles;
            OutboundHandlesList.ItemsSource = snapshot.OutboundHandles;
            SummaryBlock.Text = snapshot.SummaryText;
            SetTargetPid(rootPid);
            LaunchCountBlock.Text = snapshot.LaunchEdges.ToString();
            PivotCountBlock.Text = snapshot.ActionEdges.ToString();
            ScopeBlock.Text = snapshot.RootPid != 0
                ? $"Root PID {snapshot.RootPid} with {snapshot.ProcessCount} tracked process node(s), {snapshot.InboundHandles.Count} inbound handle row(s), {snapshot.OutboundHandles.Count} outbound handle row(s)"
                : "Live descendant and pivot graph";
            NoDataOverlay.Visibility = snapshot.Roots.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
            InboundHandlesEmptyBlock.Visibility = snapshot.InboundHandles.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
            OutboundHandlesEmptyBlock.Visibility = snapshot.OutboundHandles.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        }

        internal IReadOnlyCollection<string> GetExpandedKeysSnapshot()
        {
            CaptureExpandedState(RelationsTree.ItemsSource as IEnumerable<ProcessGraphNodeView>);
            return _expandedKeys.ToArray();
        }

        internal void SetExpandedKeys(IEnumerable<string>? keys)
        {
            _expandedKeys.Clear();
            if (keys != null)
            {
                foreach (string key in keys)
                {
                    if (!string.IsNullOrWhiteSpace(key))
                    {
                        _expandedKeys.Add(key);
                    }
                }
            }

            _preferInjectedExpansionState = true;
        }

        private void CaptureExpandedState(IEnumerable<ProcessGraphNodeView>? nodes)
        {
            _expandedKeys.Clear();
            if (nodes == null)
            {
                return;
            }

            foreach (ProcessGraphNodeView node in Flatten(nodes))
            {
                if (node.IsExpanded && !string.IsNullOrWhiteSpace(node.Key))
                {
                    _expandedKeys.Add(node.Key);
                }
            }
        }

        private void ApplyExpandedState(IEnumerable<ProcessGraphNodeView> nodes, bool isRoot)
        {
            foreach (ProcessGraphNodeView node in nodes)
            {
                node.IsExpanded = _expandedKeys.Contains(node.Key) || (isRoot && node.IsProcess);
                ApplyExpandedState(node.Children, isRoot: false);
            }
        }

        private static IEnumerable<ProcessGraphNodeView> Flatten(IEnumerable<ProcessGraphNodeView> nodes)
        {
            foreach (ProcessGraphNodeView node in nodes)
            {
                yield return node;
                foreach (ProcessGraphNodeView child in Flatten(node.Children))
                {
                    yield return child;
                }
            }
        }

        private void Root_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
        {
            WindowChromeBehavior.HandleRootDragMove(this, e);
        }

        private void WindowMinimize_Click(object sender, RoutedEventArgs e)
        {
            _ = sender;
            _ = e;
            WindowState = WindowState.Minimized;
        }

        private void WindowMaximize_Click(object sender, RoutedEventArgs e)
        {
            _ = sender;
            _ = e;
            WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;
        }

        private void Close_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }
    }
}
