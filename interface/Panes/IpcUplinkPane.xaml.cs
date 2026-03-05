using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace SleepwalkerInterface
{
    public partial class IpcUplinkPane : UserControl
    {
        public event RoutedEventHandler? CloseRequested;

        private readonly ObservableCollection<IpcMetricRow> _rows = new();
        private readonly Dictionary<string, IpcMetricRow> _index = new(StringComparer.OrdinalIgnoreCase);
        private long _lastIoctlErrorsTotal;
        private long _lastEtwErrorsTotal;
        private DateTime _lastErrorSeenUtc;
        private bool _hasErrorBaseline;
        public ObservableCollection<IpcMetricRow> MetricRows => _rows;

        public IpcUplinkPane()
        {
            InitializeComponent();
            UpdateOverlay();
        }

        internal void SetInactive(string primary, string secondary)
        {
            SummaryPrimaryBlock.Text = string.IsNullOrWhiteSpace(primary) ? "No IPC diagnostics yet" : primary;
            SummarySecondaryBlock.Text = string.IsNullOrWhiteSpace(secondary) ? "Enable uplink and wait for stats sample." : secondary;
            _rows.Clear();
            _index.Clear();
            _lastIoctlErrorsTotal = 0;
            _lastEtwErrorsTotal = 0;
            _lastErrorSeenUtc = default;
            _hasErrorBaseline = false;
            TransportModeBlock.Text = "SHARED-RING";
            TimestampBlock.Text = "--:--:--.---";
            SetHealthVisual("STANDBY", "WinHeaderBrush", 1.0);
            IoctlRateValue.Text = "-";
            EtwRateValue.Text = "-";
            ErrorsValue.Text = "-";
            DriverQueueValue.Text = "-";
            BufferSizeValue.Text = "-";
            UiBacklogValue.Text = "-";
            UpdateOverlay();
        }

        internal void UpdateDiagnostics(BackendIpcDiagnosticsView d)
        {
            string transport = "shared-ring+event";
            SummaryPrimaryBlock.Text = $"{transport} | caps=0x{d.BrokerCapabilities:X8}";
            SummarySecondaryBlock.Text = $"driverQ={d.DriverQueueDepth} dropped={d.DriverDroppedEvents} | ioctl={d.IoctlEventsPerSec:0} ev/s etw={d.EtwEventsPerSec:0} ev/s";
            TransportModeBlock.Text = transport.ToUpperInvariant();
            TimestampBlock.Text = d.TimestampUtc.ToString("HH:mm:ss.fff");

            long errorsTotal = d.IoctlErrorsTotal + d.EtwErrorsTotal;
            int uiBacklog = Math.Max(0, d.PendingIoctlUiQueue + d.PendingEtwUiQueue + d.PendingStatusUiQueue);
            double bufferKb = d.IoctlReadBufferBytes / 1024.0;
            IoctlRateValue.Text = $"{d.IoctlEventsPerSec:0.0}/s";
            EtwRateValue.Text = $"{d.EtwEventsPerSec:0.0}/s";
            ErrorsValue.Text = errorsTotal.ToString();
            DriverQueueValue.Text = d.DriverQueueDepth.ToString();
            BufferSizeValue.Text = $"{bufferKb:0.0} KB";
            UiBacklogValue.Text = uiBacklog.ToString();

            long ioctlErrorDelta = 0;
            long etwErrorDelta = 0;
            if (_hasErrorBaseline)
            {
                ioctlErrorDelta = Math.Max(0, d.IoctlErrorsTotal - _lastIoctlErrorsTotal);
                etwErrorDelta = Math.Max(0, d.EtwErrorsTotal - _lastEtwErrorsTotal);
            }
            _lastIoctlErrorsTotal = d.IoctlErrorsTotal;
            _lastEtwErrorsTotal = d.EtwErrorsTotal;
            _hasErrorBaseline = true;

            if ((ioctlErrorDelta + etwErrorDelta) > 0)
            {
                _lastErrorSeenUtc = d.TimestampUtc;
            }

            bool recentError = _lastErrorSeenUtc != default && (d.TimestampUtc - _lastErrorSeenUtc).TotalSeconds <= 12;
            UpdateHealthState(recentError, d.DriverQueueDepth, uiBacklog, d.SharedRingEnabled);

            SetMetric("Timestamp (UTC)", d.TimestampUtc.ToString("HH:mm:ss.fff"));
            SetMetric("Transport", transport);
            SetMetric("Shared Ring Error", d.SharedRingError.ToString());
            SetMetric("IOCTL Read Buffer", FormatBytes(d.IoctlReadBufferBytes));
            SetMetric("Subscriptions", d.SubscriptionCount.ToString());
            SetMetric("Driver Queue Depth", d.DriverQueueDepth.ToString());
            SetMetric("Driver Dropped", d.DriverDroppedEvents.ToString());
            SetMetric("IOCTL Event Rate", $"{d.IoctlEventsPerSec:0.00} /s");
            SetMetric("ETW Event Rate", $"{d.EtwEventsPerSec:0.00} /s");
            SetMetric("IOCTL Events Total", d.IoctlEventsTotal.ToString());
            SetMetric("ETW Events Total", d.EtwEventsTotal.ToString());
            SetMetric("IOCTL Empty Polls", d.IoctlEmptyPolls.ToString());
            SetMetric("ETW Empty Polls", d.EtwEmptyPolls.ToString());
            SetMetric("IOCTL Errors", d.IoctlErrorsTotal.ToString());
            SetMetric("ETW Errors", d.EtwErrorsTotal.ToString());
            SetMetric("UI Pending IOCTL", d.PendingIoctlUiQueue.ToString());
            SetMetric("UI Pending ETW", d.PendingEtwUiQueue.ToString());
            SetMetric("UI Pending Status", d.PendingStatusUiQueue.ToString());
            UpdateOverlay();
        }

        private void SetMetric(string name, string value)
        {
            if (_index.TryGetValue(name, out var row))
            {
                row.Value = value;
                return;
            }

            var created = new IpcMetricRow { Name = name, Value = value };
            _index[name] = created;
            _rows.Add(created);
        }

        private void IpcBtnClose_Click(object sender, RoutedEventArgs e) => CloseRequested?.Invoke(this, e);

        private void UpdateOverlay()
        {
            NoDataOverlay.Visibility = _rows.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        }

        private void UpdateHealthState(bool recentError, uint driverQueueDepth, int uiBacklog, bool sharedRingEnabled)
        {
            if (recentError)
            {
                SetHealthVisual("FAULT", "HeuristicsHeaderBrush", 0.9);
                return;
            }

            if (!sharedRingEnabled)
            {
                SetHealthVisual("RING-REQ", "StatusFailedBrush", 0.88);
                return;
            }

            if (driverQueueDepth > 0 || uiBacklog > 0)
            {
                SetHealthVisual("DEGRADED", "StatusFailedBrush", 0.85);
                return;
            }

            SetHealthVisual("NOMINAL", "StatusConnectedBrush", 0.82);
        }

        private void SetHealthVisual(string text, string brushKey, double opacity)
        {
            HealthStateBlock.Text = text;
            HealthBadge.Opacity = opacity;
            if (Application.Current?.TryFindResource(brushKey) is Brush)
            {
                HealthBadge.SetResourceReference(Border.BackgroundProperty, brushKey);
                return;
            }

            HealthBadge.Background = new SolidColorBrush(Color.FromRgb(0x4C, 0x8F, 0xD2));
        }

        private static string FormatBytes(int bytes)
        {
            if (bytes < 1024)
            {
                return $"{bytes} B";
            }

            if (bytes < 1024 * 1024)
            {
                return $"{(bytes / 1024.0):0.0} KB";
            }

            return $"{(bytes / (1024.0 * 1024.0)):0.00} MB";
        }
    }

    public sealed class IpcMetricRow : INotifyPropertyChanged
    {
        private string _name = string.Empty;
        private string _value = string.Empty;

        public string Name
        {
            get => _name;
            set
            {
                if (string.Equals(_name, value, StringComparison.Ordinal))
                {
                    return;
                }

                _name = value;
                OnPropertyChanged();
            }
        }

        public string Value
        {
            get => _value;
            set
            {
                if (string.Equals(_value, value, StringComparison.Ordinal))
                {
                    return;
                }

                _value = value;
                OnPropertyChanged();
            }
        }

        public event PropertyChangedEventHandler? PropertyChanged;

        private void OnPropertyChanged([CallerMemberName] string? propertyName = null)
            => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}
