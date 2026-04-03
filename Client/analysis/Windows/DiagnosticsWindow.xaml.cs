using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Text;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;

namespace BlackbirdInterface
{
    public partial class DiagnosticsWindow : Window
    {
        private static readonly string ControllerLogPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "Blackbird", "Node", "logs", "controller.log");

        private readonly int _targetPid;
        private readonly DispatcherTimer _stateTimer;
        private readonly DispatcherTimer _controllerLogTimer;
        private readonly ObservableCollection<DiagnosticsEntryView> _problemEntries = new();
        private readonly ObservableCollection<DiagnosticsEntryView> _disabledEntries = new();
        private readonly ObservableCollection<DiagnosticsEntryView> _waitingEntries = new();
        private readonly ObservableCollection<DiagnosticsEntryView> _healthyEntries = new();
        private long _controllerLogOffset;

        public DiagnosticsWindow(int pid)
        {
            InitializeComponent();
            WindowThemeHelper.ApplyDarkTitleBar(this);

            _targetPid = pid > 0 ? pid : Environment.ProcessId;
            TargetBlock.Text = $"PID {_targetPid}";
            ProblemItemsControl.ItemsSource = _problemEntries;
            DisabledItemsControl.ItemsSource = _disabledEntries;
            WaitingItemsControl.ItemsSource = _waitingEntries;
            HealthyItemsControl.ItemsSource = _healthyEntries;

            LoadSnapshot();
            RefreshState();

            _stateTimer = new DispatcherTimer
            {
                Interval = TimeSpan.FromSeconds(1)
            };
            _stateTimer.Tick += (_, __) => RefreshState();
            _stateTimer.Start();

            ControllerLogPathBlock.Text = ControllerLogPath;
            LoadControllerLogInitial();
            _controllerLogTimer = new DispatcherTimer
            {
                Interval = TimeSpan.FromSeconds(2)
            };
            _controllerLogTimer.Tick += (_, __) => TailControllerLog();
            _controllerLogTimer.Start();

            OutputCapture.LineReceived += OutputCapture_LineReceived;
            Closed += (_, __) =>
            {
                OutputCapture.LineReceived -= OutputCapture_LineReceived;
                _stateTimer.Stop();
                _controllerLogTimer.Stop();
            };
        }

        private void LoadSnapshot()
        {
            IReadOnlyList<string> lines = OutputCapture.Snapshot();
            OutputBox.Text = string.Join(Environment.NewLine, lines);
            OutputBox.ScrollToEnd();
        }

        private void RefreshState()
        {
            List<DiagnosticsStateEntry> entries = DiagnosticsState.SnapshotEntries().ToList();
            EnsureSyntheticEntries(entries);

            List<DiagnosticsEntryView> views = entries
                .Select(DiagnosticsEntryView.From)
                .OrderBy(x => StateSortKey(x.StateGroup))
                .ThenBy(x => x.SortOrder)
                .ThenBy(x => x.Key, StringComparer.OrdinalIgnoreCase)
                .ToList();

            ReplaceCollection(_problemEntries, views.Where(x => x.StateGroup == DiagnosticsStateGroup.Problem));
            ReplaceCollection(_disabledEntries, views.Where(x => x.StateGroup == DiagnosticsStateGroup.Disabled));
            ReplaceCollection(_waitingEntries, views.Where(x => x.StateGroup == DiagnosticsStateGroup.Waiting));
            ReplaceCollection(_healthyEntries, views.Where(x => x.StateGroup == DiagnosticsStateGroup.Healthy));

            SummaryBlock.Text =
                $"Problems {_problemEntries.Count}  |  Disabled {_disabledEntries.Count}  |  Waiting {_waitingEntries.Count}  |  Healthy {_healthyEntries.Count}";
            UpdatedBlock.Text = $"Updated {DateTime.Now:HH:mm:ss}";
        }

        private static void ReplaceCollection(ObservableCollection<DiagnosticsEntryView> target, IEnumerable<DiagnosticsEntryView> values)
        {
            target.Clear();
            foreach (DiagnosticsEntryView value in values)
            {
                target.Add(value);
            }
        }

        private static void EnsureSyntheticEntries(List<DiagnosticsStateEntry> entries)
        {
            if (!entries.Any(x => string.Equals(x.Key, "Operator Connection Established", StringComparison.OrdinalIgnoreCase)))
            {
                entries.Add(new DiagnosticsStateEntry
                {
                    Key = "Operator Connection Established",
                    Value = "Disabled in analyst interface"
                });
            }
        }

        private void OutputCapture_LineReceived(string line)
        {
            _ = Dispatcher.BeginInvoke(new Action(() =>
            {
                if (OutputBox.LineCount > 5000)
                {
                    OutputBox.Clear();
                }

                if (OutputBox.Text.Length > 0)
                {
                    OutputBox.AppendText(Environment.NewLine);
                }

                OutputBox.AppendText($"[{DateTime.Now:HH:mm:ss}] {line}");
                OutputBox.ScrollToEnd();
            }), DispatcherPriority.Background);
        }

        private void LoadControllerLogInitial()
        {
            if (!File.Exists(ControllerLogPath))
            {
                ControllerLogBox.Text = "(controller log not found)";
                return;
            }

            try
            {
                using var fs = new FileStream(ControllerLogPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                const int tail = 64 * 1024;
                long startPos = Math.Max(0, fs.Length - tail);
                fs.Seek(startPos, SeekOrigin.Begin);
                using var sr = new StreamReader(fs, Encoding.UTF8, detectEncodingFromByteOrderMarks: false);
                string content = sr.ReadToEnd();
                if (startPos > 0)
                {
                    int nl = content.IndexOf('\n');
                    content = nl >= 0 ? content[(nl + 1)..] : content;
                }

                ControllerLogBox.Text = content;
                ControllerLogBox.ScrollToEnd();
                _controllerLogOffset = fs.Length;
            }
            catch
            {
                ControllerLogBox.Text = "(unable to read controller log)";
            }
        }

        private void TailControllerLog()
        {
            if (!File.Exists(ControllerLogPath))
            {
                return;
            }

            try
            {
                using var fs = new FileStream(ControllerLogPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                if (fs.Length < _controllerLogOffset)
                {
                    _controllerLogOffset = 0;
                    ControllerLogBox.Clear();
                }

                if (fs.Length <= _controllerLogOffset)
                {
                    return;
                }

                fs.Seek(_controllerLogOffset, SeekOrigin.Begin);
                using var sr = new StreamReader(fs, Encoding.UTF8, detectEncodingFromByteOrderMarks: false);
                string newText = sr.ReadToEnd();
                _controllerLogOffset = fs.Length;

                if (string.IsNullOrEmpty(newText))
                {
                    return;
                }

                if (ControllerLogBox.LineCount > 5000)
                {
                    ControllerLogBox.Clear();
                }

                bool autoScroll = IsNearBottom(ControllerLogBox);
                ControllerLogBox.AppendText(newText);
                if (autoScroll)
                {
                    ControllerLogBox.ScrollToEnd();
                }
            }
            catch
            {
            }
        }

        private static bool IsNearBottom(System.Windows.Controls.TextBox box)
        {
            double remaining = box.ExtentHeight - (box.VerticalOffset + box.ViewportHeight);
            return remaining <= 4.0;
        }

        private void Clear_Click(object sender, RoutedEventArgs e)
        {
            OutputBox.Clear();
        }

        private void Root_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
        {
            WindowChromeBehavior.HandleRootDragMove(this, e);
        }

        private void Close_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }

        private static int StateSortKey(DiagnosticsStateGroup state)
        {
            return state switch
            {
                DiagnosticsStateGroup.Problem => 0,
                DiagnosticsStateGroup.Disabled => 1,
                DiagnosticsStateGroup.Waiting => 2,
                _ => 3
            };
        }

        private enum DiagnosticsDomain
        {
            Subsystems,
            Integrity,
            Transport,
            Other
        }

        private enum DiagnosticsStateGroup
        {
            Problem,
            Disabled,
            Waiting,
            Healthy
        }

        private enum DiagnosticsStatusKind
        {
            Neutral,
            Disabled,
            Good,
            Warning,
            Bad
        }

        private sealed class DiagnosticsEntryView
        {
            public string Key { get; init; } = string.Empty;
            public string Value { get; init; } = string.Empty;
            public Brush Background { get; init; } = Brushes.Transparent;
            public Brush BorderBrush { get; init; } = Brushes.Transparent;
            public Brush Foreground { get; init; } = Brushes.White;
            public Brush StatusDotBrush { get; init; } = Brushes.Gray;
            public string StatusLabel { get; init; } = string.Empty;
            public string DomainLabel { get; init; } = string.Empty;
            public string Guidance { get; init; } = string.Empty;
            public DiagnosticsStatusKind StatusKind { get; init; }
            public DiagnosticsDomain Domain { get; init; }
            public DiagnosticsStateGroup StateGroup { get; init; }
            public int SortOrder { get; init; }

            internal static DiagnosticsEntryView From(DiagnosticsStateEntry entry)
            {
                DiagnosticsStatusKind kind = Classify(entry.Value);
                DiagnosticsDomain domain = Categorize(entry.Key);
                DiagnosticsStateGroup stateGroup = Group(kind);
                return new DiagnosticsEntryView
                {
                    Key = entry.Key,
                    Value = entry.Value,
                    Domain = domain,
                    StateGroup = stateGroup,
                    SortOrder = Sort(entry.Key),
                    StatusKind = kind,
                    StatusLabel = kind switch
                    {
                        DiagnosticsStatusKind.Good => "Healthy",
                        DiagnosticsStatusKind.Disabled => "Disabled",
                        DiagnosticsStatusKind.Warning => "Waiting / no data",
                        DiagnosticsStatusKind.Bad => "Problem",
                        _ => "Needs review"
                    },
                    DomainLabel = domain switch
                    {
                        DiagnosticsDomain.Subsystems => "Subsystem",
                        DiagnosticsDomain.Integrity => "Integrity",
                        DiagnosticsDomain.Transport => "Transport / capture",
                        _ => "Other"
                    },
                    Guidance = BuildGuidance(kind, domain, entry.Value),
                    Background = kind switch
                    {
                        DiagnosticsStatusKind.Good => new SolidColorBrush(Color.FromArgb(0x56, 0x13, 0x4A, 0x24)),
                        DiagnosticsStatusKind.Disabled => new SolidColorBrush(Color.FromArgb(0x40, 0x22, 0x26, 0x2D)),
                        DiagnosticsStatusKind.Warning => new SolidColorBrush(Color.FromArgb(0x56, 0x5E, 0x49, 0x12)),
                        DiagnosticsStatusKind.Bad => new SolidColorBrush(Color.FromArgb(0x56, 0x5E, 0x1E, 0x1E)),
                        _ => new SolidColorBrush(Color.FromArgb(0x30, 0x20, 0x26, 0x2D))
                    },
                    BorderBrush = kind switch
                    {
                        DiagnosticsStatusKind.Good => new SolidColorBrush(Color.FromRgb(0x4D, 0xC2, 0x74)),
                        DiagnosticsStatusKind.Disabled => new SolidColorBrush(Color.FromRgb(0x7E, 0x87, 0x91)),
                        DiagnosticsStatusKind.Warning => new SolidColorBrush(Color.FromRgb(0xE3, 0xB9, 0x45)),
                        DiagnosticsStatusKind.Bad => new SolidColorBrush(Color.FromRgb(0xDF, 0x63, 0x63)),
                        _ => new SolidColorBrush(Color.FromRgb(0x5C, 0x66, 0x73))
                    },
                    Foreground = kind switch
                    {
                        DiagnosticsStatusKind.Good => new SolidColorBrush(Color.FromRgb(0xBE, 0xF7, 0xCD)),
                        DiagnosticsStatusKind.Disabled => new SolidColorBrush(Color.FromRgb(0xD2, 0xD8, 0xDE)),
                        DiagnosticsStatusKind.Warning => new SolidColorBrush(Color.FromRgb(0xF7, 0xE6, 0xA6)),
                        DiagnosticsStatusKind.Bad => new SolidColorBrush(Color.FromRgb(0xFF, 0xC5, 0xC5)),
                        _ => new SolidColorBrush(Color.FromRgb(0xEC, 0xF0, 0xF3))
                    },
                    StatusDotBrush = kind switch
                    {
                        DiagnosticsStatusKind.Good => new SolidColorBrush(Color.FromRgb(0x4D, 0xC2, 0x74)),
                        DiagnosticsStatusKind.Disabled => new SolidColorBrush(Color.FromRgb(0x7E, 0x87, 0x91)),
                        DiagnosticsStatusKind.Warning => new SolidColorBrush(Color.FromRgb(0xE3, 0xB9, 0x45)),
                        DiagnosticsStatusKind.Bad => new SolidColorBrush(Color.FromRgb(0xDF, 0x63, 0x63)),
                        _ => new SolidColorBrush(Color.FromRgb(0x5C, 0x66, 0x73))
                    }
                };
            }

            private static DiagnosticsStateGroup Group(DiagnosticsStatusKind kind)
            {
                return kind switch
                {
                    DiagnosticsStatusKind.Bad => DiagnosticsStateGroup.Problem,
                    DiagnosticsStatusKind.Disabled => DiagnosticsStateGroup.Disabled,
                    DiagnosticsStatusKind.Warning or DiagnosticsStatusKind.Neutral => DiagnosticsStateGroup.Waiting,
                    _ => DiagnosticsStateGroup.Healthy
                };
            }

            private static string BuildGuidance(DiagnosticsStatusKind kind, DiagnosticsDomain domain, string? value)
            {
                string text = value?.Trim() ?? string.Empty;
                return kind switch
                {
                    DiagnosticsStatusKind.Bad => "Investigate this path first. The component is failing or returning an error state.",
                    DiagnosticsStatusKind.Disabled => "This path is intentionally off or unavailable. It should not be treated as a break unless you expected it to be active.",
                    DiagnosticsStatusKind.Warning when domain == DiagnosticsDomain.Transport =>
                        "The pipeline is up but incomplete. This usually means no samples yet, upstream lag, or unsupported telemetry for the current target.",
                    DiagnosticsStatusKind.Warning => "The component is present, but the interface does not have enough signal yet to mark it healthy.",
                    DiagnosticsStatusKind.Neutral when text.Length == 0 => "No status has been reported yet.",
                    DiagnosticsStatusKind.Neutral => "Status is unclassified. Review the raw value before treating it as healthy or failed.",
                    _ => "Working and reporting data."
                };
            }

            private static DiagnosticsStatusKind Classify(string? value)
            {
                string text = value?.Trim() ?? string.Empty;
                if (text.Length == 0)
                {
                    return DiagnosticsStatusKind.Neutral;
                }

                if (text.Contains("FAILED", StringComparison.OrdinalIgnoreCase) ||
                    text.Contains("TAMPERED", StringComparison.OrdinalIgnoreCase) ||
                    text.Contains("MISSING", StringComparison.OrdinalIgnoreCase) ||
                    text.Contains("UNAVAILABLE", StringComparison.OrdinalIgnoreCase) ||
                    text.Contains("OPEN FAILED", StringComparison.OrdinalIgnoreCase) ||
                    text.Contains("START FAILED", StringComparison.OrdinalIgnoreCase) ||
                    text.Contains("ERROR", StringComparison.OrdinalIgnoreCase))
                {
                    return DiagnosticsStatusKind.Bad;
                }

                if (text.Contains("DISABLED", StringComparison.OrdinalIgnoreCase) ||
                    text.Contains("INACTIVE", StringComparison.OrdinalIgnoreCase) ||
                    text.Contains("CLOSED", StringComparison.OrdinalIgnoreCase))
                {
                    return DiagnosticsStatusKind.Disabled;
                }

                if (text.Contains("WARNING", StringComparison.OrdinalIgnoreCase) ||
                    text.Contains("UNKNOWN", StringComparison.OrdinalIgnoreCase) ||
                    text.Contains("AWAITING", StringComparison.OrdinalIgnoreCase) ||
                    text.Contains("NO DATA", StringComparison.OrdinalIgnoreCase) ||
                    text.Contains("NOT YET", StringComparison.OrdinalIgnoreCase) ||
                    text.Contains("STOPPED", StringComparison.OrdinalIgnoreCase) ||
                    text.Contains("UNSUPPORTED", StringComparison.OrdinalIgnoreCase))
                {
                    return DiagnosticsStatusKind.Warning;
                }

                if (text.Contains("OK", StringComparison.OrdinalIgnoreCase) ||
                    text.Contains("RUNNING", StringComparison.OrdinalIgnoreCase) ||
                    text.Contains("ENABLED", StringComparison.OrdinalIgnoreCase) ||
                    text.Contains("OPEN", StringComparison.OrdinalIgnoreCase) ||
                    text.Contains("FOUND", StringComparison.OrdinalIgnoreCase) ||
                    text.Contains("ACTIVE", StringComparison.OrdinalIgnoreCase) ||
                    text.Contains("CONNECTED", StringComparison.OrdinalIgnoreCase) ||
                    text.Contains("ESTABLISHED", StringComparison.OrdinalIgnoreCase) ||
                    text.Contains("INITIALIZED", StringComparison.OrdinalIgnoreCase) ||
                    text.Contains("READY", StringComparison.OrdinalIgnoreCase))
                {
                    return DiagnosticsStatusKind.Good;
                }

                return DiagnosticsStatusKind.Neutral;
            }

            private static DiagnosticsDomain Categorize(string key)
            {
                return key.Trim() switch
                {
                    "UI" or
                    "Session" or
                    "Kernel Hooks" or
                    "Usermode Hooks" or
                    "Driver Service" or
                    "Controller Service" or
                    "Operator Connection Established" or
                    "Connectivity" => DiagnosticsDomain.Subsystems,

                    "Hook Integrity" or
                    "AMSI Integrity" or
                    "ETW Integrity" or
                    "Hook DLL" or
                    "HookDLL" => DiagnosticsDomain.Integrity,

                    "Capture Store" or
                    "IPC Uplink" or
                    "IPC Mode" or
                    "IPC Shared Ring" or
                    "Driver Queue" or
                    "DriverProxy" or
                    "DriverStats" or
                    "BrokerHandle" or
                    "Broker Caps" or
                    "Broker TI" or
                    "Broker TI Enable Err" or
                    "Session Stats" or
                    "UI Flush" or
                    "IOCTL Pump" or
                    "ETW Pump" => DiagnosticsDomain.Transport,

                    _ => DiagnosticsDomain.Other
                };
            }

            private static int Sort(string key)
            {
                return key.Trim() switch
                {
                    "Session" => 0,
                    "Connectivity" => 1,
                    "Driver Service" => 2,
                    "Controller Service" => 3,
                    "Kernel Hooks" => 4,
                    "Usermode Hooks" => 5,
                    "Operator Connection Established" => 6,
                    "Hook Integrity" => 7,
                    "AMSI Integrity" => 8,
                    "ETW Integrity" => 9,
                    "Capture Store" => 10,
                    "IPC Uplink" => 11,
                    "Driver Queue" => 12,
                    _ => 100
                };
            }
        }
    }
}
