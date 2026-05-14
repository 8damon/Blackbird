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
        private void NetworkViewSwitchButton_Click(object sender, RoutedEventArgs e)
        {
            _showNetworkPeers = !_showNetworkPeers;
            UpdateNetworkPaneView();
        }

        private void UpdateNetworkPaneView()
        {
            if (NetChart == null || NetworkPeersGrid == null || NetworkPaneTitle == null ||
                NetworkViewSwitchButton == null)
                return;

            if (_showNetworkPeers)
            {
                NetChart.Visibility = Visibility.Collapsed;
                NetworkPeersGrid.Visibility = Visibility.Visible;
                NetworkPaneTitle.Text = "Network Peers";
                NetworkViewSwitchButton.Content = "Traffic";
                return;
            }

            NetChart.Visibility = Visibility.Visible;
            NetworkPeersGrid.Visibility = Visibility.Collapsed;
            NetworkPaneTitle.Text = "Network Traffic";
            NetworkViewSwitchButton.Content = "Peers";
        }

        private static SolidColorBrush Brush(byte r, byte g, byte b)
        {
            var brush = new SolidColorBrush(Color.FromRgb(r, g, b));
            brush.Freeze();
            return brush;
        }

        private void ConfigureCharts()
        {
            if (CpuChart != null)
            {
                CpuChart.SetSeries(new[] {
                    new ChartSeries("CPU %", Brush(0x35, 0xA8, 0xFF), SeriesScale.Percent, p => p.CpuPercent,
                                    ChartValueFormat.Percent),
                    new ChartSeries("Cores used %", Brush(0x7C, 0xD5, 0xFF), SeriesScale.Percent,
                                    p => p.CoresUsedPercent, ChartValueFormat.Percent),
                });
            }

            if (DiskChart != null)
            {
                DiskChart.SetSeries(new[] {
                    new ChartSeries("Read B/s", Brush(0xFF9A21), SeriesScale.AutoToViewMax, p => p.DiskReadBytesPerSec,
                                    ChartValueFormat.BytesPerSecond),
                    new ChartSeries("Write B/s", Brush(0xFF4545), SeriesScale.AutoToViewMax,
                                    p => p.DiskWriteBytesPerSec, ChartValueFormat.BytesPerSecond),
                });
            }

            if (RamChart != null)
            {
                RamChart.SetSeries(new[] {
                    new ChartSeries("Private bytes", Brush(0x43, 0xF2, 0x72), SeriesScale.AutoToViewMax,
                                    p => p.PrivateBytes, ChartValueFormat.Bytes),
                    new ChartSeries("Commit", Brush(0x66, 0xD9, 0xEF), SeriesScale.AutoToViewMax, p => p.CommitBytes,
                                    ChartValueFormat.Bytes),
                    new ChartSeries("MEM_IMAGE", Brush(0xFF, 0xC8, 0x57), SeriesScale.AutoToViewMax, p => p.ImageBytes,
                                    ChartValueFormat.Bytes),
                    new ChartSeries("MEM_MAPPED", Brush(0xB2, 0x8D, 0xFF), SeriesScale.AutoToViewMax,
                                    p => p.MappedBytes, ChartValueFormat.Bytes),
                });
            }

            if (NetChart != null)
            {
                NetChart.SetSeries(new[] {
                    new ChartSeries("Inbound B/s", Brush(0xA0, 0x5B, 0xFF), SeriesScale.AutoToViewMax,
                                    p => p.NetInBytesPerSec, ChartValueFormat.BytesPerSecond),
                    new ChartSeries("Outbound B/s", Brush(0xC0, 0x86, 0xFF), SeriesScale.AutoToViewMax,
                                    p => p.NetOutBytesPerSec, ChartValueFormat.BytesPerSecond),
                });
            }
        }

        private static SolidColorBrush Brush(uint rgb)
        {
            var r = (byte)((rgb >> 16) & 0xFF);
            var g = (byte)((rgb >> 8) & 0xFF);
            var b = (byte)(rgb & 0xFF);
            return Brush(r, g, b);
        }

        public void SetCaptureStart(DateTime captureStartUtc)
        {
            _captureStartUtc = captureStartUtc;
        }

        private DateTime GetObservedTimestampUtc()
        {
            if (_viewEndUtc != default)
            {
                return _viewEndUtc;
            }

            if (_historySamples.Count > 0)
            {
                return _historySamples[^1].TimestampUtc;
            }

            return DateTime.UtcNow;
        }

        private int ResolveSampleIndexForTimestamp(DateTime timestampUtc)
        {
            if (_historySamples.Count == 0)
            {
                return -1;
            }

            DateTime first = _historySamples[0].TimestampUtc;
            DateTime last = _historySamples[^1].TimestampUtc;
            DateTime target = timestampUtc == default ? last : timestampUtc;

            if (target < first)
            {
                return -1;
            }

            if (!_processLiveDataAvailable && target > last)
            {
                return -1;
            }

            return FindSampleIndexForTimestamp(target);
        }

        private int ResolveSampleIndexForCurrentView() => ResolveSampleIndexForTimestamp(GetObservedTimestampUtc());

        private bool HasHistoricalDataForObservedTime() => ResolveSampleIndexForCurrentView() >= 0;

        public void SetPid(int pid)
        {
            if (_pid != pid)
            {
                _historySamples.Clear();
                _threadLifecycleHistory.Clear();
                _selectedSampleIndex = -1;
                TopThreads.Clear();
                CoreUsageRows.Clear();
                ThreadLifecycleRows.Clear();
                MemoryMetrics.Clear();
                MemoryAttributionRows.Clear();
                _memoryRegionAttributionHistory.Clear();
                RebuildTimeTravelSliderBounds();
                if (TimeTravelStampBlock != null)
                {
                    TimeTravelStampBlock.Text = "LIVE";
                }
            }
            _pid = pid;
        }

        public void SetAnalysisSubject(string? subjectPath, string? hostPath)
        {
            _analysisSubjectPath = subjectPath?.Trim() ?? string.Empty;
            _analysisHostPath = hostPath?.Trim() ?? string.Empty;
        }

        public void RefreshLiveProcessDetails()
        {
            RefreshProcessDetails();
        }

        public bool IsTargetSuspended => _targetSuspended;

        public void SetProcessLiveDataAvailable(bool available)
        {
            _processLiveDataAvailable = available;
            if (!available)
            {
                if (_targetSuspended)
                {
                    PreserveSuspendedThreadState();
                }
                else if (_historySamples.Count == 0)
                {
                    TopThreads.Clear();
                    CoreUsageRows.Clear();
                    ThreadLifecycleRows.Clear();
                    MemoryMetrics.Clear();
                    MemoryAttributionRows.Clear();
                    NetworkPeers.Clear();
                    UpdateMemoryTreemap();
                }
                else if (_selectedSampleIndex >= 0 && _selectedSampleIndex < _historySamples.Count)
                {
                    ApplySampleIndex(ResolveSampleIndexForCurrentView(), updateSlider: true);
                }
                else
                {
                    ApplySampleIndex(ResolveSampleIndexForCurrentView(), updateSlider: true);
                }
            }

            UpdateLiveDataOverlays();
        }

        public void SetTargetSuspended(bool suspended)
        {
            _targetSuspended = suspended;
            if (_selectedSampleIndex >= 0 && _selectedSampleIndex < _historySamples.Count)
            {
                ApplySampleIndex(_selectedSampleIndex, updateSlider: false);
            }
            else if (_historySamples.Count > 0)
            {
                ApplySampleIndex(_historySamples.Count - 1, updateSlider: false);
            }
            else if (suspended)
            {
                PreserveSuspendedThreadState();
                UpdateSubtitle();
                UpdateLiveDataOverlays();
            }
            else
            {
                UpdateLiveDataOverlays();
            }
        }

        private void PreserveSuspendedThreadState()
        {
            List<ThreadUsageSample> suspendedThreads = BuildSuspendedThreadSnapshot();
            if (suspendedThreads.Count == 0)
            {
                return;
            }

            ApplyUnifiedThreadRows(BuildUnifiedThreadRows(suspendedThreads, DateTime.UtcNow));
            if (_threadLifecycleHistory.Count > 0)
            {
                RebuildThreadLifecycleRows(DateTime.UtcNow);
            }
        }

        private List<ThreadUsageSample> BuildSuspendedThreadSnapshot()
        {
            if (_lastSample?.TopThreads.Count > 0)
            {
                return _lastSample.TopThreads.Select(CloneThreadUsageForSuspension)
                    .OrderByDescending(x => x.CpuMsDelta)
                    .Take(14)
                    .ToList();
            }

            if (TopThreads.Count > 0)
            {
                return TopThreads
                    .Select(row => new ThreadUsageSample { Tid = row.Tid, CpuMsDelta = row.CpuMs, State = row.State,
                                                           WaitReason = row.IsSuspended ? "Suspended" : string.Empty,
                                                           Kind = row.ThreadKind, StartTimeUtc = row.StartTimeUtc,
                                                           TargetSuspended = true })
                    .Take(14)
                    .ToList();
            }

            if (_threadLifecycleHistory.Count == 0)
            {
                return new List<ThreadUsageSample>();
            }

            var activeThreads = new Dictionary<uint, ThreadLifecycleEventSample>();
            for (int i = 0; i < _threadLifecycleHistory.Count; i += 1)
            {
                ThreadLifecycleEventSample sample = _threadLifecycleHistory[i];
                if (!sample.EventKind.Equals("Exit", StringComparison.OrdinalIgnoreCase))
                {
                    activeThreads[sample.ThreadId] = sample;
                }
                else
                {
                    activeThreads.Remove(sample.ThreadId);
                }
            }

            return activeThreads.Values.OrderByDescending(x => x.TimestampUtc)
                .Take(14)
                .Select(sample => new ThreadUsageSample { Tid = unchecked((int)sample.ThreadId), CpuMsDelta = 0,
                                                          State = "Suspended", WaitReason = "Suspended",
                                                          Kind = string.IsNullOrWhiteSpace(sample.EventKind)
                                                                     ? "Thread"
                                                                     : sample.EventKind,
                                                          StartTimeUtc = sample.TimestampUtc, TargetSuspended = true })
                .ToList();
        }

        private static ThreadUsageSample CloneThreadUsage(ThreadUsageSample sample)
        {
            return new ThreadUsageSample { Tid = sample.Tid,
                                           CpuMsDelta = sample.CpuMsDelta,
                                           State = sample.State,
                                           WaitReason = sample.WaitReason,
                                           Kind = sample.Kind,
                                           StartTimeUtc = sample.StartTimeUtc,
                                           TargetSuspended = sample.TargetSuspended };
        }

        private static ThreadUsageSample CloneThreadUsageForSuspension(ThreadUsageSample sample)
        {
            return new ThreadUsageSample { Tid = sample.Tid,      CpuMsDelta = sample.CpuMsDelta,
                                           State = sample.State,  WaitReason = "Suspended",
                                           Kind = sample.Kind,    StartTimeUtc = sample.StartTimeUtc,
                                           TargetSuspended = true };
        }

        public IReadOnlyList<ThreadUsageRow> SnapshotTopThreads() =>
            TopThreads
                .Select(row => new ThreadUsageRow(new ThreadUsageSample {
                            Tid = row.Tid, CpuMsDelta = row.CpuMs, State = row.State,
                            WaitReason = row.IsSuspended ? "Suspended" : string.Empty, Kind = row.ThreadKind,
                            StartTimeUtc = row.StartTimeUtc, TargetSuspended = row.IsSuspended
                        }))
                .ToList();

        public void SetViewWindow(DateTime viewStartUtc, DateTime viewEndUtc)
        {
            _viewStartUtc = viewStartUtc;
            _viewEndUtc = viewEndUtc;

            CpuChart?.SetView(_viewStartUtc, _viewEndUtc);
            DiskChart?.SetView(_viewStartUtc, _viewEndUtc);
            RamChart?.SetView(_viewStartUtc, _viewEndUtc);
            NetChart?.SetView(_viewStartUtc, _viewEndUtc);

            if (_timeTravelEnabled && _historySamples.Count > 0)
            {
                int index = ResolveSampleIndexForCurrentView();
                ApplySampleIndex(index, updateSlider: true);
            }

            UpdateSubtitle();
        }

        public void PushSample(PerformanceSample s)
        {
            _processLiveDataAvailable = true;
            _lastSample = CloneSample(s);
            _historySamples.Add(CloneSample(s));
            if (_historySamples.Count > 4000)
            {
                _historySamples.RemoveRange(0, _historySamples.Count - 4000);
            }
            RebuildTimeTravelSliderBounds();

            _cpu.Add(s.TimestampUtc, s.CpuPercent);
            _diskRead.Add(s.TimestampUtc, s.DiskReadBytesPerSec);
            _diskWrite.Add(s.TimestampUtc, s.DiskWriteBytesPerSec);
            _ramPrivate.Add(s.TimestampUtc, s.PrivateBytes);
            _netIn.Add(s.TimestampUtc, s.NetInBytesPerSec);
            _netOut.Add(s.TimestampUtc, s.NetOutBytesPerSec);

            CpuChart?.PushSample(s);
            DiskChart?.PushSample(s);
            RamChart?.PushSample(s);
            NetChart?.PushSample(s);

            if (!_timeTravelEnabled)
            {
                ApplySampleIndex(_historySamples.Count - 1, updateSlider: true);
            }

            if (!_timeTravelEnabled && (DateTime.UtcNow - _lastDetailsRefreshUtc).TotalSeconds >= 5.0)
            {
                RefreshProcessDetails();
                _lastDetailsRefreshUtc = DateTime.UtcNow;
            }

            UpdateSubtitle();
            UpdateLiveDataOverlays();
        }
    }
}
