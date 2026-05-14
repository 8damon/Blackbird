using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;

namespace BlackbirdInterface
{
    public partial class PerformancePane
    {
        public void LoadHistory(IEnumerable<PerformanceSample> samples)
        {
            var list = samples.Select(CloneSample).OrderBy(x => x.TimestampUtc).ToList();
            _historySamples.Clear();
            _historySamples.AddRange(list);
            _selectedSampleIndex = _historySamples.Count - 1;

            CpuChart?.SetSamples(list);
            DiskChart?.SetSamples(list);
            RamChart?.SetSamples(list);
            NetChart?.SetSamples(list);

            if (list.Count > 0)
            {
                _lastSample = list[^1];
            }
            else
            {
                _lastSample = null;
            }

            RebuildTimeTravelSliderBounds();
            if (_historySamples.Count > 0)
            {
                int index = _timeTravelEnabled ? ResolveSampleIndexForCurrentView() : _historySamples.Count - 1;
                ApplySampleIndex(index, updateSlider: true);
            }
            else
            {
                TopThreads.Clear();
                CoreUsageRows.Clear();
                MemoryMetrics.Clear();
                MemoryAttributionRows.Clear();
                UpdateMemoryTreemap();
            }

            RefreshProcessDetails();
            UpdateSubtitle();
            UpdateLiveDataOverlays();
        }

        public void PushMemoryRegionAttributions(IEnumerable<MemoryRegionAttributionSample> samples)
        {
            bool appended = false;
            foreach (MemoryRegionAttributionSample sample in samples)
            {
                _memoryRegionAttributionHistory.Add(CloneMemoryRegionAttributionSample(sample));
                appended = true;
            }

            if (!appended)
            {
                return;
            }

            if (_memoryRegionAttributionHistory.Count > 40_000)
            {
                _memoryRegionAttributionHistory.RemoveRange(0, _memoryRegionAttributionHistory.Count - 40_000);
            }

            ScheduleMemoryAttributionRowsRefresh();

            UpdateLiveDataOverlays();
        }

        public void PushObservedModules(IEnumerable<ModuleInfoRow> modules)
        {
            var incoming = modules
                               .Where(static module => !string.IsNullOrWhiteSpace(module.Name) ||
                                                       !string.IsNullOrWhiteSpace(module.Path))
                               .ToList();
            if (incoming.Count == 0)
            {
                return;
            }

            var byKey = new Dictionary<string, ModuleInfoRow>(StringComparer.OrdinalIgnoreCase);
            foreach (ModuleInfoRow module in Modules)
            {
                byKey[BuildModuleKey(module)] = module;
            }

            foreach (ModuleInfoRow module in incoming)
            {
                byKey[BuildModuleKey(module)] = module;
            }

            Modules.Clear();
            foreach (ModuleInfoRow module in byKey.Values
                         .OrderBy(static module => module.Name, StringComparer.OrdinalIgnoreCase)
                         .Take(1024))
            {
                Modules.Add(module);
            }

            UpdateLiveDataOverlays();
        }

        public void LoadMemoryRegionAttributionHistory(IEnumerable<MemoryRegionAttributionSample> history)
        {
            _memoryRegionAttributionHistory.Clear();
            _memoryRegionAttributionHistory.AddRange(
                history.Select(CloneMemoryRegionAttributionSample).OrderBy(x => x.TimestampUtc));

            RefreshMemoryAttributionRowsForCurrentView();
        }

        public void PushThreadLifecycle(ThreadLifecycleEventSample sample)
        {
            PushThreadLifecycles(new[] { sample });
        }

        public void PushThreadLifecycles(IEnumerable<ThreadLifecycleEventSample> samples)
        {
            bool appended = false;
            foreach (ThreadLifecycleEventSample sample in samples)
            {
                _threadLifecycleHistory.Add(CloneThreadLifecycleEvent(sample));
                appended = true;
            }

            if (!appended)
            {
                return;
            }

            if (_threadLifecycleHistory.Count > 40_000)
            {
                _threadLifecycleHistory.RemoveRange(0, _threadLifecycleHistory.Count - 40_000);
            }

            if (!_timeTravelEnabled)
            {
                RebuildThreadLifecycleRows(DateTime.UtcNow);
            }

            ScheduleMemoryAttributionRowsRefresh();
            UpdateLiveDataOverlays();
        }

        public void LoadThreadLifecycleHistory(IEnumerable<ThreadLifecycleEventSample> history)
        {
            _threadLifecycleHistory.Clear();
            _threadLifecycleHistory.AddRange(history.Select(CloneThreadLifecycleEvent).OrderBy(x => x.TimestampUtc));

            DateTime cutoff =
                _historySamples.Count > 0 && _selectedSampleIndex >= 0 && _selectedSampleIndex < _historySamples.Count
                    ? _historySamples[_selectedSampleIndex].TimestampUtc
                    : DateTime.UtcNow;
            RebuildThreadLifecycleRows(cutoff);
            RefreshMemoryAttributionRowsForCurrentView();
            UpdateLiveDataOverlays();
        }

        public void LoadThreadStackHistory(IEnumerable<ThreadStackHistoryArchiveEntry> history)
        {
            _threadStackHistories.Clear();
            _threadStackHistories.AddRange(history.Select(x => x.Clone()));

            RefreshMemoryAttributionRowsForCurrentView();
            UpdateLiveDataOverlays();
        }

        private void RefreshMemoryAttributionRowsForCurrentView()
        {
            _memoryAttributionRefreshPending = false;
            if (_memoryAttributionRefreshTimer.IsEnabled)
            {
                _memoryAttributionRefreshTimer.Stop();
            }

            if (_selectedSampleIndex >= 0 && _selectedSampleIndex < _historySamples.Count)
            {
                RebuildMemoryAttributionRows(_historySamples[_selectedSampleIndex].MemoryPages,
                                             _historySamples[_selectedSampleIndex].TimestampUtc);
            }
            else if (_lastSample != null)
            {
                RebuildMemoryAttributionRows(_lastSample.MemoryPages, _lastSample.TimestampUtc);
            }
            else
            {
                RebuildMemoryAttributionRowsFromAttributions(DateTime.UtcNow);
            }

            _lastMemoryAttributionRefreshUtc = DateTime.UtcNow;
        }

        private void ScheduleMemoryAttributionRowsRefresh()
        {
            if (!Dispatcher.CheckAccess())
            {
                Dispatcher.BeginInvoke(new Action(ScheduleMemoryAttributionRowsRefresh), DispatcherPriority.Background);
                return;
            }

            _memoryAttributionRefreshPending = true;
            if (_memoryAttributionRefreshTimer.IsEnabled)
            {
                return;
            }

            TimeSpan elapsed = DateTime.UtcNow - _lastMemoryAttributionRefreshUtc;
            TimeSpan delay = elapsed >= MemoryAttributionRefreshCoalesceInterval
                                 ? MemoryAttributionRefreshMinimumDelay
                                 : MemoryAttributionRefreshCoalesceInterval - elapsed;
            if (delay < MemoryAttributionRefreshMinimumDelay)
            {
                delay = MemoryAttributionRefreshMinimumDelay;
            }

            _memoryAttributionRefreshTimer.Interval = delay;
            _memoryAttributionRefreshTimer.Start();
        }

        private void FlushScheduledMemoryAttributionRefresh()
        {
            _memoryAttributionRefreshTimer.Stop();
            if (!_memoryAttributionRefreshPending)
            {
                return;
            }

            RefreshMemoryAttributionRowsForCurrentView();
        }

        private void RebuildTimeTravelSliderBounds()
        {
            if (TimeTravelSlider == null)
            {
                return;
            }

            _timeTravelSliderProgrammatic = true;
            TimeTravelSlider.Minimum = 0;
            TimeTravelSlider.Maximum = Math.Max(0, _historySamples.Count - 1);
            TimeTravelSlider.IsEnabled = _historySamples.Count > 1 && _timeTravelEnabled;
            if (_historySamples.Count == 0)
            {
                TimeTravelSlider.Value = 0;
                _selectedSampleIndex = -1;
            }
            else if (_selectedSampleIndex < 0 || _selectedSampleIndex >= _historySamples.Count)
            {
                _selectedSampleIndex = _historySamples.Count - 1;
                TimeTravelSlider.Value = _selectedSampleIndex;
            }
            _timeTravelSliderProgrammatic = false;
        }

        private int FindSampleIndexForTimestamp(DateTime timestampUtc)
        {
            if (_historySamples.Count == 0)
            {
                return -1;
            }

            DateTime target = timestampUtc == default ? _historySamples[^1].TimestampUtc : timestampUtc;
            int lo = 0;
            int hi = _historySamples.Count - 1;
            while (lo < hi)
            {
                int mid = lo + ((hi - lo + 1) / 2);
                if (_historySamples[mid].TimestampUtc <= target)
                {
                    lo = mid;
                }
                else
                {
                    hi = mid - 1;
                }
            }

            return lo;
        }

        private void ApplySampleIndex(int index, bool updateSlider)
        {
            if (_historySamples.Count == 0 || index < 0 || index >= _historySamples.Count)
            {
                _selectedSampleIndex = -1;
                TopThreads.Clear();
                CoreUsageRows.Clear();
                ThreadLifecycleRows.Clear();
                MemoryMetrics.Clear();
                MemoryAttributionRows.Clear();
                NetworkPeers.Clear();
                if (TimeTravelStampBlock != null)
                {
                    TimeTravelStampBlock.Text = "LIVE";
                }
                UpdateSubtitle();
                UpdateMemoryTreemap();
                UpdateLiveDataOverlays();
                return;
            }

            _selectedSampleIndex = index;
            PerformanceSample sample = _historySamples[index];
            _lastSample = sample;

            int selectedThreadTid = 0;
            int selectedThreadIndex = -1;
            if (ThreadsGrid?.SelectedItem is ThreadUsageRow selectedThread)
            {
                selectedThreadTid = selectedThread.Tid;
                selectedThreadIndex = ThreadsGrid.SelectedIndex;
            }

            var rebuiltThreads = BuildUnifiedThreadRows(sample.TopThreads, sample.TimestampUtc);
            if (selectedThreadTid > 0 && selectedThreadIndex >= 0 && selectedThreadIndex < rebuiltThreads.Count)
            {
                int selectedIndexInNew = rebuiltThreads.FindIndex(x => x.Tid == selectedThreadTid);
                if (selectedIndexInNew >= 0 && selectedIndexInNew != selectedThreadIndex)
                {
                    ThreadUsageRow pinned = rebuiltThreads[selectedIndexInNew];
                    rebuiltThreads.RemoveAt(selectedIndexInNew);
                    rebuiltThreads.Insert(selectedThreadIndex, pinned);
                }
            }

            ApplyUnifiedThreadRows(rebuiltThreads);
            ApplyCoreUsageRows(sample.CoreUsage, sample.CoreCount);
            if (selectedThreadTid > 0 && ThreadsGrid != null)
            {
                ThreadUsageRow? selectedAfter = TopThreads.FirstOrDefault(x => x.Tid == selectedThreadTid);
                if (selectedAfter != null)
                {
                    ThreadsGrid.SelectedItem = selectedAfter;
                }
            }

            MemoryMetrics.Clear();
            foreach (MemoryMetricSample metric in sample.MemoryMetrics)
            {
                MemoryMetrics.Add(new MemoryMetricRow { Metric = metric.Metric, Value = metric.Value,
                                                        BytesValue = metric.BytesValue });
            }
            RebuildMemoryAttributionRows(sample.MemoryPages, sample.TimestampUtc);
            RebuildThreadLifecycleRows(sample.TimestampUtc);

            if (TimeTravelStampBlock != null)
            {
                string mode = _timeTravelEnabled ? "T" : "LIVE";
                TimeTravelStampBlock.Text = $"{mode} {sample.TimestampUtc:HH:mm:ss}";
            }

            if (updateSlider && TimeTravelSlider != null)
            {
                _timeTravelSliderProgrammatic = true;
                TimeTravelSlider.Value = _selectedSampleIndex;
                _timeTravelSliderProgrammatic = false;
            }

            UpdateMemorySummaryMode();
            UpdateMemoryTreemap();
            UpdateSubtitle();
            UpdateLiveDataOverlays();
        }
    }
}
