using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Windows;
using System.Windows.Input;

namespace BlackbirdInterface
{
    public partial class ApiCallGraphWindow : Window
    {
        private readonly ObservableCollection<ApiCallGraphRowView> _rows = new();

        public ApiCallGraphWindow()
        {
            InitializeComponent();
            WindowThemeHelper.ApplyDarkTitleBar(this);
            ApiGrid.ItemsSource = _rows;
        }

        internal void UpdateSnapshot(IReadOnlyList<ApiCallGraphRowSnapshot> rows, string dotGraph)
        {
            rows ??= Array.Empty<ApiCallGraphRowSnapshot>();

            int maxHits = Math.Max(1, rows.Count == 0 ? 1 : rows.Max(x => Math.Max(1, x.Hits)));
            _rows.Clear();
            foreach (ApiCallGraphRowSnapshot row in rows.OrderByDescending(x => x.Hits).ThenByDescending(x => x.LastSeenUtc))
            {
                uint target = row.TargetPid != 0 ? row.TargetPid : row.SourcePid;
                int flameWidth = Math.Clamp((int)Math.Round((row.Hits / (double)maxHits) * 24.0), 1, 24);
                _rows.Add(new ApiCallGraphRowView
                {
                    ApiName = string.IsNullOrWhiteSpace(row.ApiName) ? "unknown" : row.ApiName,
                    PathLabel = $"{row.SourcePid} -> {target}",
                    ThreadLabel = row.ThreadId == 0 ? "-" : row.ThreadId.ToString(),
                    Hits = Math.Max(1, row.Hits),
                    FlameBar = new string('|', flameWidth)
                });
            }

            SummaryBlock.Text = rows.Count == 0
                ? "No API hook data yet"
                : $"Patterns: {_rows.Count} / Calls: {_rows.Sum(x => x.Hits)}";
            SubSummaryBlock.Text = rows.Count == 0
                ? "dot graph updates live"
                : $"last update: {rows.Max(x => x.LastSeenUtc):HH:mm:ss.fff}Z";
            DotGraphTextBox.Text = string.IsNullOrWhiteSpace(dotGraph) ? "digraph ApiCalls {\n}" : dotGraph;
        }

        private void Root_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
        {
            WindowChromeBehavior.HandleRootDragMove(this, e);
        }

        private void TopClose_Click(object sender, RoutedEventArgs e) => Close();

        private sealed class ApiCallGraphRowView
        {
            public string ApiName { get; set; } = "";
            public string PathLabel { get; set; } = "";
            public string ThreadLabel { get; set; } = "";
            public int Hits { get; set; }
            public string FlameBar { get; set; } = "";
        }
    }
}

