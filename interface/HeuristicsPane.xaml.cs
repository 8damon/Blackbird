using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Windows;
using System.Windows.Controls;

namespace SleepwalkerInterface
{
    public partial class HeuristicsPane : UserControl
    {
        public event RoutedEventHandler? ReorderRequested;
        public event RoutedEventHandler? FloatRequested;
        public event RoutedEventHandler? CloseRequested;

        private readonly ObservableCollection<HeuristicEventView> _items = new();
        private int _lowCount;
        private int _mediumCount;
        private int _highCount;
        private int _criticalCount;
        internal int ItemCount => _items.Count;

        public HeuristicsPane()
        {
            InitializeComponent();
            HeuristicsGrid.ItemsSource = _items;
            UpdateNoDataOverlay();
        }

        internal void PushHeuristic(HeuristicEventView item)
        {
            _items.Add(item);
            UpdateSeverityCounts(item.Severity, +1);
            while (_items.Count > 2000)
            {
                UpdateSeverityCounts(_items[0].Severity, -1);
                _items.RemoveAt(0);
            }

            UpdateSummary();
            UpdateNoDataOverlay();
        }

        private void RecomputeSummary()
        {
            _lowCount = 0;
            _mediumCount = 0;
            _highCount = 0;
            _criticalCount = 0;

            foreach (var entry in _items)
            {
                UpdateSeverityCounts(entry.Severity, +1);
            }

            UpdateSummary();
        }

        private void UpdateSummary()
        {
            CountLowBlock.Text = $"Low: {_lowCount}";
            CountMediumBlock.Text = $"Medium: {_mediumCount}";
            CountHighBlock.Text = $"High: {_highCount}";
            CountCriticalBlock.Text = $"Critical: {_criticalCount}";
            SummaryBlock.Text = $"Total detections: {_items.Count}";
        }

        private void UpdateSeverityCounts(uint severity, int delta)
        {
            if (severity >= 8)
            {
                _criticalCount += delta;
            }
            else if (severity >= 6)
            {
                _highCount += delta;
            }
            else if (severity >= 4)
            {
                _mediumCount += delta;
            }
            else
            {
                _lowCount += delta;
            }
        }

        internal IReadOnlyList<HeuristicEventView> SnapshotItems()
            => _items.Select(x => x.Clone()).ToList();

        internal void LoadHistory(IEnumerable<HeuristicEventView> items)
        {
            _items.Clear();
            foreach (var item in items)
            {
                _items.Add(item.Clone());
            }
            RecomputeSummary();
            UpdateNoDataOverlay();
        }

        public void ClearAll()
        {
            _items.Clear();
            RecomputeSummary();
            SummaryBlock.Text = "No detections yet";
            UpdateNoDataOverlay();
        }

        private void HeurBtnReorder_Click(object sender, RoutedEventArgs e) => ReorderRequested?.Invoke(this, e);
        private void HeurBtnFloat_Click(object sender, RoutedEventArgs e) => FloatRequested?.Invoke(this, e);
        private void HeurBtnClose_Click(object sender, RoutedEventArgs e) => CloseRequested?.Invoke(this, e);

        private void UpdateNoDataOverlay()
        {
            HeuristicsNoDataOverlay.Visibility = _items.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        }
    }
}
