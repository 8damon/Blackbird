using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Windows;
using System.Windows.Controls;

namespace SleepwalkerInterface
{
    public partial class EtwPane : UserControl
    {
        public event RoutedEventHandler? ReorderRequested;
        public event RoutedEventHandler? FloatRequested;
        public event RoutedEventHandler? CloseRequested;

        private readonly ObservableCollection<BrokerEtwEventView> _sleepwalkerEvents = new();
        private readonly ObservableCollection<BrokerEtwEventView> _tiEvents = new();
        private readonly ObservableCollection<TiTaskCountView> _taskCounts = new();
        private readonly Dictionary<ushort, int> _taskCounterMap = new();
        private DateTime _lastTaskBarsRebuildUtc;
        private bool _taskBarsDirty;

        public EtwPane()
        {
            InitializeComponent();
            SleepwalkerGrid.ItemsSource = _sleepwalkerEvents;
            TiGrid.ItemsSource = _tiEvents;
            TaskBars.ItemsSource = _taskCounts;
            SetSectionsVisible(showSleepwalker: true, showTi: true);
            UpdateNoDataOverlays();
        }

        internal int SleepwalkerCount => _sleepwalkerEvents.Count;
        internal int TiCount => _tiEvents.Count;

        internal void PushEvent(BrokerEtwEventView entry)
        {
            if (entry.Source.Equals("ThreatIntel", StringComparison.OrdinalIgnoreCase))
            {
                _tiEvents.Add(entry);
                while (_tiEvents.Count > 1200)
                {
                    _tiEvents.RemoveAt(0);
                }

                if (_taskCounterMap.TryGetValue(entry.Task, out int current))
                {
                    _taskCounterMap[entry.Task] = current + 1;
                }
                else
                {
                    _taskCounterMap[entry.Task] = 1;
                }

                TryRebuildTaskBars();
            }
            else
            {
                _sleepwalkerEvents.Add(entry);
                while (_sleepwalkerEvents.Count > 1200)
                {
                    _sleepwalkerEvents.RemoveAt(0);
                }
            }

            if (_taskBarsDirty)
            {
                TryRebuildTaskBars();
            }

            SummaryBlock.Text = $"Sleepwalker={_sleepwalkerEvents.Count} TI={_tiEvents.Count} taskKinds={_taskCounterMap.Count}";
            UpdateNoDataOverlays();
        }

        private void TryRebuildTaskBars(bool force = false)
        {
            if (!force && (DateTime.UtcNow - _lastTaskBarsRebuildUtc).TotalMilliseconds < 200)
            {
                _taskBarsDirty = true;
                return;
            }

            _taskBarsDirty = false;
            _lastTaskBarsRebuildUtc = DateTime.UtcNow;
            RebuildTaskBars();
        }

        private void RebuildTaskBars()
        {
            _taskCounts.Clear();
            int max = Math.Max(1, _taskCounterMap.Values.DefaultIfEmpty(1).Max());
            foreach (var item in _taskCounterMap.OrderByDescending(x => x.Value).Take(10))
            {
                _taskCounts.Add(new TiTaskCountView
                {
                    Task = item.Key,
                    Count = item.Value,
                    MaxCount = max
                });
            }
        }

        internal IReadOnlyList<BrokerEtwEventView> SnapshotSleepwalkerEvents()
            => _sleepwalkerEvents.Select(x => x.Clone()).ToList();

        internal IReadOnlyList<BrokerEtwEventView> SnapshotTiEvents()
            => _tiEvents.Select(x => x.Clone()).ToList();

        internal void LoadHistory(IEnumerable<BrokerEtwEventView> sleepwalkerEvents, IEnumerable<BrokerEtwEventView> tiEvents)
        {
            _sleepwalkerEvents.Clear();
            _tiEvents.Clear();
            _taskCounterMap.Clear();

            foreach (var e in sleepwalkerEvents)
            {
                _sleepwalkerEvents.Add(e.Clone());
            }

            foreach (var e in tiEvents)
            {
                _tiEvents.Add(e.Clone());
                if (_taskCounterMap.TryGetValue(e.Task, out int current))
                {
                    _taskCounterMap[e.Task] = current + 1;
                }
                else
                {
                    _taskCounterMap[e.Task] = 1;
                }
            }

            TryRebuildTaskBars(force: true);
            SummaryBlock.Text = $"Sleepwalker={_sleepwalkerEvents.Count} TI={_tiEvents.Count} taskKinds={_taskCounterMap.Count}";
            UpdateNoDataOverlays();
        }

        public void ClearAll()
        {
            _sleepwalkerEvents.Clear();
            _tiEvents.Clear();
            _taskCounts.Clear();
            _taskCounterMap.Clear();
            _taskBarsDirty = false;
            _lastTaskBarsRebuildUtc = DateTime.MinValue;
            SummaryBlock.Text = "No ETW events yet";
            UpdateNoDataOverlays();
        }

        internal void SetSectionsVisible(bool showSleepwalker, bool showTi)
        {
            SleepwalkerSectionBorder.Visibility = showSleepwalker ? Visibility.Visible : Visibility.Collapsed;
            TiSectionBorder.Visibility = showTi ? Visibility.Visible : Visibility.Collapsed;
            SectionSplitter.Visibility = (showSleepwalker && showTi) ? Visibility.Visible : Visibility.Collapsed;
        }

        private void EtwBtnReorder_Click(object sender, RoutedEventArgs e) => ReorderRequested?.Invoke(this, e);
        private void EtwBtnFloat_Click(object sender, RoutedEventArgs e) => FloatRequested?.Invoke(this, e);
        private void EtwBtnClose_Click(object sender, RoutedEventArgs e) => CloseRequested?.Invoke(this, e);

        private void UpdateNoDataOverlays()
        {
            SleepwalkerNoDataOverlay.Visibility = _sleepwalkerEvents.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
            TiNoDataOverlay.Visibility = _tiEvents.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        }
    }
}
