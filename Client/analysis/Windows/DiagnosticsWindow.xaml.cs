using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;
using System.Windows.Documents;

namespace BlackbirdInterface
{
    public partial class DiagnosticsWindow : Window
    {
        private static readonly string ControllerLogPath =
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Blackbird",
                         "Node", "logs", "controller.log");
        private const int MaxFeedEntries = 5000;

        private readonly int _targetPid;
        private readonly DispatcherTimer _stateTimer;
        private readonly DispatcherTimer _controllerLogTimer;
        private readonly ObservableCollection<DiagnosticsEntryView> _problemEntries = new();
        private readonly ObservableCollection<DiagnosticsEntryView> _disabledEntries = new();
        private readonly ObservableCollection<DiagnosticsEntryView> _degradedEntries = new();
        private readonly ObservableCollection<DiagnosticsEntryView> _healthyEntries = new();
        private readonly ObservableCollection<FeedEntryView> _outputFeedEntries = new();
        private readonly ObservableCollection<FeedEntryView> _controllerFeedEntries = new();
        private long _controllerLogOffset;

        public DiagnosticsWindow(int pid)
        {
            InitializeComponent();
            WindowThemeHelper.ApplyDarkTitleBar(this);

            _targetPid = pid > 0 ? pid : Environment.ProcessId;
            TargetBlock.Text = $"PID {_targetPid}";
            ProblemItemsControl.ItemsSource = _problemEntries;
            DisabledItemsControl.ItemsSource = _disabledEntries;
            DegradedItemsControl.ItemsSource = _degradedEntries;
            HealthyItemsControl.ItemsSource = _healthyEntries;
            LoadOutputSnapshot();
            RefreshState();

            _stateTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
            _stateTimer.Tick += (_, __) => RefreshState();
            _stateTimer.Start();

            ControllerLogPathBlock.Text = ControllerLogPath;
            LoadControllerLogInitial();
            _controllerLogTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(2) };
            _controllerLogTimer.Tick += (_, __) => TailControllerLog();
            _controllerLogTimer.Start();

            DebugConsoleService.EntryReceived += DebugConsoleService_EntryReceived;
            Closed += (_, __) =>
            {
                DebugConsoleService.EntryReceived -= DebugConsoleService_EntryReceived;
                _stateTimer.Stop();
                _controllerLogTimer.Stop();
            };
        }

        private void LoadOutputSnapshot()
        {
            _outputFeedEntries.Clear();
            ClearFeedBox(OutputFeedBox);
            foreach (DebugConsoleEntry entry in DebugConsoleService.Snapshot())
            {
                AppendFeedEntry(_outputFeedEntries, FeedEntryView.FromDebugConsole(entry), OutputFeedBox);
            }
        }

        private void RefreshState()
        {
            Dictionary<string, string> values =
                DiagnosticsState.SnapshotEntries()
                    .Where(x => !string.IsNullOrWhiteSpace(x.Key))
                    .GroupBy(x => x.Key, StringComparer.OrdinalIgnoreCase)
                    .ToDictionary(g => g.Key, g => g.Last().Value, StringComparer.OrdinalIgnoreCase);

            List<DiagnosticsEntryView> views = BuildSubsystemEntries(values)
                                                   .Select(DiagnosticsEntryView.From)
                                                   .OrderBy(x => StateSortKey(x.StateGroup))
                                                   .ThenBy(x => x.SortOrder)
                                                   .ThenBy(x => x.Key, StringComparer.OrdinalIgnoreCase)
                                                   .ToList();

            ReplaceCollection(_problemEntries, views.Where(x => x.StateGroup == DiagnosticsStateGroup.Problem));
            ReplaceCollection(_disabledEntries, views.Where(x => x.StateGroup == DiagnosticsStateGroup.Disabled));
            ReplaceCollection(_degradedEntries, views.Where(x => x.StateGroup == DiagnosticsStateGroup.Degraded));
            ReplaceCollection(_healthyEntries, views.Where(x => x.StateGroup == DiagnosticsStateGroup.Healthy));

            SummaryBlock.Text =
                $"Problems {_problemEntries.Count}  |  Disabled {_disabledEntries.Count}  |  Degraded {_degradedEntries.Count}  |  Healthy {_healthyEntries.Count}";
            UpdatedBlock.Text = $"Updated {DateTime.Now:HH:mm:ss}";
        }

        private static List<DiagnosticsStateEntry> BuildSubsystemEntries(IReadOnlyDictionary<string, string> values)
        {
            var projected = new List<DiagnosticsStateEntry>();
            AddProjected(projected, "Interface->Controller IPC",
                         ResolveFirst(values, "Interface->Controller IPC", "Connectivity"));
            AddProjected(projected, "HookDLL->Controller IPC", ResolveHookIpc(values));
            AddProjected(projected, "HookDLL Hooks Set", ResolveFirst(values, "HookDLL Hooks Set", "Usermode Hooks"));
            AddProjected(projected, "DACLs", ResolveDacls(values));
            AddProjected(projected, "Controller<->Driver Comms",
                         ResolveFirst(values, "Controller<->Driver Comms", "DriverProxy"));
            AddProjected(projected, "ETW Status", ResolveEtwStatus(values));
            AddProjected(projected, "Kernel Hooks", ResolveFirst(values, "Kernel Hooks"));
            AddProjected(projected, "Hook Integrity", ResolveIntegrityStatus(values, "Hook Integrity"));
            AddProjected(projected, "AMSI Integrity", ResolveIntegrityStatus(values, "AMSI Integrity"));
            AddProjected(projected, "ETW Integrity", ResolveIntegrityStatus(values, "ETW Integrity"));
            AddProjected(projected, "Signature Intel", ResolveFirst(values, "Signature Intel"));
            AddProjected(projected, "Capture Store", ResolveFirst(values, "Capture Store"));
            AddProjected(projected, "RuntimeConfig", ResolveFirst(values, "RuntimeConfig"));
            AddProjected(projected, "Driver Queue", ResolveFirst(values, "Driver Queue"));
            AddProjected(projected, "Tempus", ResolveFirst(values, "Tempus"));
            AddProjected(projected, "API Graph", ResolveFirst(values, "API Graph"));
            AddProjected(projected, "Driver Service", ResolveFirst(values, "Driver Service"));
            AddProjected(projected, "Controller Service", ResolveFirst(values, "Controller Service"));
            AddProjected(projected, "HookDLL Presence", ResolveHookDllPresence(values));
            return projected;
        }

        private static void AddProjected(List<DiagnosticsStateEntry> entries, string key, string? value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return;
            }

            entries.Add(new DiagnosticsStateEntry { Key = key, Value = value.Trim() });
        }

        private static string? ResolveFirst(IReadOnlyDictionary<string, string> values, params string[] keys)
        {
            foreach (string key in keys)
            {
                if (values.TryGetValue(key, out string? value) && !string.IsNullOrWhiteSpace(value))
                {
                    return value;
                }
            }

            return null;
        }

        private static string? ResolveHookIpc(IReadOnlyDictionary<string, string> values)
        {
            string? explicitValue = ResolveFirst(values, "HookDLL->Controller IPC");
            if (!string.IsNullOrWhiteSpace(explicitValue))
            {
                return explicitValue;
            }

            string? hooks = ResolveFirst(values, "Usermode Hooks");
            if (string.IsNullOrWhiteSpace(hooks))
            {
                return null;
            }

            if (hooks.IndexOf("Active", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return "Ready";
            }

            if (hooks.IndexOf("Awaiting", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return "Awaiting hook-ready";
            }

            if (hooks.IndexOf("Inactive", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return "Inactive";
            }

            return hooks;
        }

        private static string? ResolveDacls(IReadOnlyDictionary<string, string> values)
        {
            string? explicitValue = ResolveFirst(values, "DACLs");
            if (!string.IsNullOrWhiteSpace(explicitValue))
            {
                return explicitValue;
            }

            foreach (string value in values.Values)
            {
                if (value.IndexOf("access denied", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    value.IndexOf("ACL", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    return value;
                }
            }

            if (values.ContainsKey("Interface->Controller IPC") || values.ContainsKey("Controller<->Driver Comms"))
            {
                return "OK";
            }

            return null;
        }

        private static string? ResolveEtwStatus(IReadOnlyDictionary<string, string> values)
        {
            string? explicitValue = ResolveFirst(values, "ETW Status");
            if (!string.IsNullOrWhiteSpace(explicitValue))
            {
                return explicitValue;
            }

            string? pump = ResolveFirst(values, "ETW Pump");
            if (!string.IsNullOrWhiteSpace(pump))
            {
                return pump;
            }

            string? integrity = ResolveFirst(values, "ETW Integrity");
            if (!string.IsNullOrWhiteSpace(integrity) &&
                !string.Equals(integrity, "Unknown", StringComparison.OrdinalIgnoreCase))
            {
                return integrity;
            }

            string? eventCount = ResolveFirst(values, "ETW Events");
            if (!string.IsNullOrWhiteSpace(eventCount) &&
                long.TryParse(eventCount, NumberStyles.Integer, CultureInfo.InvariantCulture, out long count) &&
                count > 0)
            {
                return "Live";
            }

            string? brokerTi = ResolveFirst(values, "Broker TI");
            if (!string.IsNullOrWhiteSpace(brokerTi) &&
                !brokerTi.Contains("Disabled", StringComparison.OrdinalIgnoreCase))
            {
                return "OK";
            }

            return brokerTi;
        }

        private static string? ResolveIntegrityStatus(IReadOnlyDictionary<string, string> values, string key)
        {
            string? explicitValue = ResolveFirst(values, key);
            if (!string.IsNullOrWhiteSpace(explicitValue) &&
                !string.Equals(explicitValue, "Unknown", StringComparison.OrdinalIgnoreCase))
            {
                return explicitValue;
            }

            string? hooks = ResolveFirst(values, "Usermode Hooks");
            if (key.Equals("Hook Integrity", StringComparison.OrdinalIgnoreCase) && !string.IsNullOrWhiteSpace(hooks) &&
                hooks.Contains("Active", StringComparison.OrdinalIgnoreCase))
            {
                return "OK";
            }

            string? etw = ResolveEtwStatus(values);
            if (key.Equals("ETW Integrity", StringComparison.OrdinalIgnoreCase) && !string.IsNullOrWhiteSpace(etw) &&
                !etw.Contains("Stopped", StringComparison.OrdinalIgnoreCase) &&
                !etw.Contains("Unsupported", StringComparison.OrdinalIgnoreCase))
            {
                return "OK";
            }

            if (key.Equals("AMSI Integrity", StringComparison.OrdinalIgnoreCase) && !string.IsNullOrWhiteSpace(hooks) &&
                hooks.Contains("Active", StringComparison.OrdinalIgnoreCase))
            {
                return "OK";
            }

            return explicitValue;
        }

        private static string? ResolveHookDllPresence(IReadOnlyDictionary<string, string> values)
        {
            string? hookState = ResolveFirst(values, "Usermode Hooks");
            if (!string.IsNullOrWhiteSpace(hookState) &&
                hookState.Contains("Active", StringComparison.OrdinalIgnoreCase))
            {
                return "Active";
            }

            return ResolveFirst(values, "HookDLL Presence", "Hook DLL", "HookDLL");
        }

        private static void ReplaceCollection<T>(ObservableCollection<T> target, IEnumerable<T> values)
        {
            target.Clear();
            foreach (T value in values)
            {
                target.Add(value);
            }
        }

        private void DebugConsoleService_EntryReceived(DebugConsoleEntry entry)
        {
            _ = Dispatcher.BeginInvoke(
                new Action(
                    () =>
                    { AppendFeedEntry(_outputFeedEntries, FeedEntryView.FromDebugConsole(entry), OutputFeedBox); }),
                DispatcherPriority.Background);
        }

        private void LoadControllerLogInitial()
        {
            _controllerFeedEntries.Clear();
            if (!File.Exists(ControllerLogPath))
            {
                AppendFeedEntry(_controllerFeedEntries,
                                FeedEntryView.Create(DateTime.Now, FeedLevel.Warning, "CONTROLLER",
                                                     "controller log not found",
                                                     "CONTROLLER|WARNING|controller log not found"),
                                ControllerFeedBox);
                return;
            }

            try
            {
                ClearFeedBox(ControllerFeedBox);
                using var fs = new FileStream(ControllerLogPath, FileMode.Open, FileAccess.Read,
                                              FileShare.ReadWrite | FileShare.Delete);
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

                AppendControllerLines(content);
                _controllerLogOffset = fs.Length;
            }
            catch
            {
                AppendFeedEntry(_controllerFeedEntries,
                                FeedEntryView.Create(DateTime.Now, FeedLevel.Error, "CONTROLLER",
                                                     "unable to read controller log",
                                                     "CONTROLLER|ERROR|unable to read controller log"),
                                ControllerFeedBox);
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
                using var fs = new FileStream(ControllerLogPath, FileMode.Open, FileAccess.Read,
                                              FileShare.ReadWrite | FileShare.Delete);
                if (fs.Length < _controllerLogOffset)
                {
                    _controllerLogOffset = 0;
                    _controllerFeedEntries.Clear();
                }

                if (fs.Length <= _controllerLogOffset)
                {
                    return;
                }

                fs.Seek(_controllerLogOffset, SeekOrigin.Begin);
                using var sr = new StreamReader(fs, Encoding.UTF8, detectEncodingFromByteOrderMarks: false);
                string newText = sr.ReadToEnd();
                _controllerLogOffset = fs.Length;
                AppendControllerLines(newText);
            }
            catch
            {
            }
        }

        private void AppendControllerLines(string content)
        {
            if (string.IsNullOrWhiteSpace(content))
            {
                return;
            }

            foreach (string line in content.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries))
            {
                FeedEntryView? parsed = FeedEntryView.FromControllerLogLine(line);
                if (parsed != null)
                {
                    AppendFeedEntry(_controllerFeedEntries, parsed, ControllerFeedBox);
                }
            }
        }

        private static void AppendFeedEntry(ObservableCollection<FeedEntryView> target, FeedEntryView incoming,
                                            RichTextBox feedBox)
        {
            if (target.Count > 0)
            {
                FeedEntryView previous = target[^1];
                if (string.Equals(previous.DedupKey, incoming.DedupKey, StringComparison.Ordinal))
                {
                    target[^1] = previous.Merge(incoming);
                    RewriteFeedBox(feedBox, target);
                    return;
                }
            }

            if (target.Count >= MaxFeedEntries)
            {
                target.RemoveAt(0);
            }

            target.Add(incoming);
            AppendFeedParagraph(feedBox, incoming);
            feedBox.ScrollToEnd();
        }

        private void Clear_Click(object sender, RoutedEventArgs e)
        {
            _outputFeedEntries.Clear();
            ClearFeedBox(OutputFeedBox);
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
            return state switch { DiagnosticsStateGroup.Problem => 0, DiagnosticsStateGroup.Disabled => 1,
                                  DiagnosticsStateGroup.Degraded => 2,
                                  _ => 3 };
        }

        private enum DiagnosticsDomain
        {
            Ipc,
            Hooks,
            Integrity,
            Services,
            Capture,
            Other
        }

        private enum DiagnosticsStateGroup
        {
            Problem,
            Disabled,
            Degraded,
            Healthy
        }

        private enum DiagnosticsStatusKind
        {
            Neutral,
            Disabled,
            Good,
            Warning,
            Error,
            Critical
        }

        private enum FeedLevel
        {
            Info,
            Warning,
            Error,
            Critical
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
                DiagnosticsStatusKind kind = Classify(entry.Key, entry.Value);
                DiagnosticsDomain domain = Categorize(entry.Key);
                DiagnosticsStateGroup stateGroup = Group(kind);
                return new DiagnosticsEntryView {
                    Key = entry.Key,
                    Value = entry.Value,
                    Domain = domain,
                    StateGroup = stateGroup,
                    SortOrder = Sort(entry.Key),
                    StatusKind = kind,
                    StatusLabel = kind switch { DiagnosticsStatusKind.Good => "Healthy",
                                                DiagnosticsStatusKind.Disabled => "Disabled",
                                                DiagnosticsStatusKind.Warning => "Warning",
                                                DiagnosticsStatusKind.Error => "Error",
                                                DiagnosticsStatusKind.Critical => "Critical",
                                                _ => "Review" },
                    DomainLabel = domain switch { DiagnosticsDomain.Ipc => "IPC / transport",
                                                  DiagnosticsDomain.Hooks => "Hooks / attach",
                                                  DiagnosticsDomain.Integrity => "Integrity",
                                                  DiagnosticsDomain.Services => "Service state",
                                                  DiagnosticsDomain.Capture => "Telemetry path",
                                                  _ => "Other" },
                    Guidance = BuildGuidance(kind, domain),
                    Background = kind switch { DiagnosticsStatusKind.Good =>
                                                   new SolidColorBrush(Color.FromArgb(0x56, 0x13, 0x4A, 0x24)),
                                               DiagnosticsStatusKind.Disabled =>
                                                   new SolidColorBrush(Color.FromArgb(0x40, 0x22, 0x26, 0x2D)),
                                               DiagnosticsStatusKind.Warning =>
                                                   new SolidColorBrush(Color.FromArgb(0x56, 0x5E, 0x49, 0x12)),
                                               DiagnosticsStatusKind.Error =>
                                                   new SolidColorBrush(Color.FromArgb(0x56, 0x5E, 0x1E, 0x1E)),
                                               DiagnosticsStatusKind.Critical =>
                                                   new SolidColorBrush(Color.FromArgb(0x66, 0x55, 0x11, 0x2A)),
                                               _ => new SolidColorBrush(Color.FromArgb(0x30, 0x20, 0x26, 0x2D)) },
                    BorderBrush =
                        kind switch {
                            DiagnosticsStatusKind.Good => new SolidColorBrush(Color.FromRgb(0x4D, 0xC2, 0x74)),
                            DiagnosticsStatusKind.Disabled => new SolidColorBrush(Color.FromRgb(0x7E, 0x87, 0x91)),
                            DiagnosticsStatusKind.Warning => new SolidColorBrush(Color.FromRgb(0xE3, 0xB9, 0x45)),
                            DiagnosticsStatusKind.Error => new SolidColorBrush(Color.FromRgb(0xDF, 0x63, 0x63)),
                            DiagnosticsStatusKind.Critical => new SolidColorBrush(Color.FromRgb(0xFF, 0x66, 0x99)),
                            _ => new SolidColorBrush(Color.FromRgb(0x5C, 0x66, 0x73))
                        },
                    Foreground =
                        kind switch {
                            DiagnosticsStatusKind.Good => new SolidColorBrush(Color.FromRgb(0xBE, 0xF7, 0xCD)),
                            DiagnosticsStatusKind.Disabled => new SolidColorBrush(Color.FromRgb(0xD2, 0xD8, 0xDE)),
                            DiagnosticsStatusKind.Warning => new SolidColorBrush(Color.FromRgb(0xF7, 0xE6, 0xA6)),
                            DiagnosticsStatusKind.Error => new SolidColorBrush(Color.FromRgb(0xFF, 0xC5, 0xC5)),
                            DiagnosticsStatusKind.Critical => new SolidColorBrush(Color.FromRgb(0xFF, 0xC8, 0xDB)),
                            _ => new SolidColorBrush(Color.FromRgb(0xEC, 0xF0, 0xF3))
                        },
                    StatusDotBrush =
                        kind switch {
                            DiagnosticsStatusKind.Good => new SolidColorBrush(Color.FromRgb(0x4D, 0xC2, 0x74)),
                            DiagnosticsStatusKind.Disabled => new SolidColorBrush(Color.FromRgb(0x7E, 0x87, 0x91)),
                            DiagnosticsStatusKind.Warning => new SolidColorBrush(Color.FromRgb(0xE3, 0xB9, 0x45)),
                            DiagnosticsStatusKind.Error => new SolidColorBrush(Color.FromRgb(0xDF, 0x63, 0x63)),
                            DiagnosticsStatusKind.Critical => new SolidColorBrush(Color.FromRgb(0xFF, 0x66, 0x99)),
                            _ => new SolidColorBrush(Color.FromRgb(0x5C, 0x66, 0x73))
                        }
                };
            }

            private static DiagnosticsStateGroup Group(DiagnosticsStatusKind kind)
            {
                return kind switch { DiagnosticsStatusKind.Error or DiagnosticsStatusKind.Critical =>
                                         DiagnosticsStateGroup.Problem,
                                     DiagnosticsStatusKind.Disabled => DiagnosticsStateGroup.Disabled,
                                     DiagnosticsStatusKind.Warning or DiagnosticsStatusKind.Neutral =>
                                         DiagnosticsStateGroup.Degraded,
                                     _ => DiagnosticsStateGroup.Healthy };
            }

            private static string BuildGuidance(DiagnosticsStatusKind kind, DiagnosticsDomain domain)
            {
                return kind switch {
                    DiagnosticsStatusKind.Critical => "Broken or tampered. This path needs immediate attention.",
                    DiagnosticsStatusKind.Error => "Failing or disconnected. Investigate this subsystem first.",
                    DiagnosticsStatusKind.Disabled => "Present but intentionally inactive for this run mode or target.",
                    DiagnosticsStatusKind.Warning when domain == DiagnosticsDomain.Capture =>
                        "Reporting is partial. Telemetry is up, but the path is degraded or incomplete.",
                    DiagnosticsStatusKind.Warning => "The subsystem is reachable, but not in a clean healthy state.",
                    DiagnosticsStatusKind.Neutral => "Status is present but not yet classifiable.",
                    _ => "Healthy and reporting."
                };
            }

            private static DiagnosticsStatusKind Classify(string key, string? value)
            {
                string text = value?.Trim() ?? string.Empty;
                if (text.Length == 0)
                {
                    return DiagnosticsStatusKind.Neutral;
                }

                if (text.Contains("TAMPERED", StringComparison.OrdinalIgnoreCase) ||
                    text.Contains("ACCESS DENIED", StringComparison.OrdinalIgnoreCase))
                {
                    return DiagnosticsStatusKind.Critical;
                }

                if (text.Contains("FAILED", StringComparison.OrdinalIgnoreCase) ||
                    text.Contains("MISSING", StringComparison.OrdinalIgnoreCase) ||
                    text.Contains("OPEN FAILED", StringComparison.OrdinalIgnoreCase) ||
                    text.Contains("TIMED OUT", StringComparison.OrdinalIgnoreCase) ||
                    text.Contains("STOPPED", StringComparison.OrdinalIgnoreCase) ||
                    text.Contains("ERROR", StringComparison.OrdinalIgnoreCase))
                {
                    return DiagnosticsStatusKind.Error;
                }

                if (text.Contains("DISABLED", StringComparison.OrdinalIgnoreCase) ||
                    text.Contains("INACTIVE", StringComparison.OrdinalIgnoreCase) ||
                    text.Contains("DEFERRED", StringComparison.OrdinalIgnoreCase) ||
                    text.Contains("CLOSED", StringComparison.OrdinalIgnoreCase))
                {
                    return DiagnosticsStatusKind.Disabled;
                }

                if (text.Contains("DEGRADED", StringComparison.OrdinalIgnoreCase) ||
                    text.Contains("UNKNOWN", StringComparison.OrdinalIgnoreCase) ||
                    text.Contains("AWAITING", StringComparison.OrdinalIgnoreCase) ||
                    text.Contains("NO DATA", StringComparison.OrdinalIgnoreCase) ||
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

                if (string.Equals(key, "DACLs", StringComparison.OrdinalIgnoreCase))
                {
                    return DiagnosticsStatusKind.Good;
                }

                return DiagnosticsStatusKind.Neutral;
            }

            private static DiagnosticsDomain Categorize(string key)
            {
                return key.Trim() switch {
                    "Interface->Controller IPC" or "HookDLL->Controller IPC" or "Controller<->Driver Comms" =>
                        DiagnosticsDomain.Ipc,

                    "HookDLL Hooks Set" or "Kernel Hooks" or "HookDLL Presence" => DiagnosticsDomain.Hooks,

                    "Hook Integrity" or "AMSI Integrity" or "ETW Integrity" or "DACLs" => DiagnosticsDomain.Integrity,

                    "Driver Service" or "Controller Service" => DiagnosticsDomain.Services,

                    "ETW Status" or "Signature Intel" or "Capture Store" or "RuntimeConfig" or "Driver Queue" or
                    "Tempus" or "API Graph" => DiagnosticsDomain.Capture,

                    _ => DiagnosticsDomain.Other
                };
            }

            private static int Sort(string key)
            {
                return key.Trim() switch { "Interface->Controller IPC" => 0,
                                           "HookDLL->Controller IPC" => 1,
                                           "Controller<->Driver Comms" => 2,
                                           "ETW Status" => 3,
                                           "DACLs" => 4,
                                           "HookDLL Presence" => 5,
                                           "HookDLL Hooks Set" => 6,
                                           "Kernel Hooks" => 7,
                                           "Hook Integrity" => 8,
                                           "AMSI Integrity" => 9,
                                           "ETW Integrity" => 10,
                                           "Signature Intel" => 11,
                                           "Capture Store" => 12,
                                           "RuntimeConfig" => 13,
                                           "Driver Queue" => 14,
                                           "Tempus" => 15,
                                           "API Graph" => 16,
                                           "Driver Service" => 17,
                                           "Controller Service" => 18,
                                           _ => 100 };
            }
        }

        private sealed class FeedEntryView
        {
            public DateTime TimestampLocal { get; init; }
            public string TimestampText { get; init; } = string.Empty;
            public FeedLevel Level { get; init; }
            public string LevelLabel { get; init; } = string.Empty;
            public string Source { get; init; } = string.Empty;
            public string Message { get; init; } = string.Empty;
            public int RepeatCount { get; init; }
            public string RepeatText { get; init; } = string.Empty;
            public string DedupKey { get; init; } = string.Empty;
            public Brush Foreground { get; init; } = Brushes.White;
            public Brush SourceBrush { get; init; } = Brushes.White;
            public Brush BorderBrush { get; init; } = Brushes.White;
            public Brush RowBackground { get; init; } = Brushes.Transparent;
            public Brush LevelBackground { get; init; } = Brushes.Transparent;
            public Brush LevelForeground { get; init; } = Brushes.White;

            public FeedEntryView Merge(FeedEntryView next)
            {
                int repeatCount = Math.Max(1, RepeatCount) + Math.Max(1, next.RepeatCount);
                DateTime timestamp = TimestampLocal > next.TimestampLocal ? TimestampLocal : next.TimestampLocal;
                return Create(timestamp, Level, Source, Message, DedupKey, repeatCount);
            }

            public static FeedEntryView FromDebugConsole(DebugConsoleEntry entry)
            {
                ParsedFeedMessage parsed = ParseFeedMessage(entry.Message, entry.Source, entry.TimestampLocal);
                return Create(parsed.TimestampLocal, parsed.Level, parsed.Source, parsed.Message, parsed.DedupKey);
            }

            public static FeedEntryView? FromControllerLogLine(string line)
            {
                if (string.IsNullOrWhiteSpace(line))
                {
                    return null;
                }

                DateTime timestamp = DateTime.Now;
                string message = line.Trim();
                if (message.Length > 22 && message[0] == '[')
                {
                    int end = message.IndexOf(']');
                    if (end > 0)
                    {
                        string stamp = message.Substring(1, end - 1);
                        if (DateTime.TryParseExact(stamp, "yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture,
                                                   DateTimeStyles.AssumeLocal, out DateTime parsedTimestamp))
                        {
                            timestamp = parsedTimestamp;
                            message = message[(end + 1)..].TrimStart();
                        }
                    }
                }

                ParsedFeedMessage parsed = ParseFeedMessage(message, "CONTROLLER", timestamp);
                return Create(parsed.TimestampLocal, parsed.Level, parsed.Source, parsed.Message, parsed.DedupKey);
            }

            public static FeedEntryView Create(DateTime timestamp, FeedLevel level, string source, string message,
                                               string dedupKey, int repeatCount = 1)
            {
                string normalizedSource =
                    string.IsNullOrWhiteSpace(source) ? "GENERAL" : source.Trim().ToUpperInvariant();
                string cleanMessage = string.IsNullOrWhiteSpace(message) ? "<empty>" : message.Trim();
                Brush accent = BuildFeedAccent(level);
                return new FeedEntryView { TimestampLocal = timestamp,
                                           TimestampText = timestamp.ToString("HH:mm:ss", CultureInfo.InvariantCulture),
                                           Level = level,
                                           LevelLabel =
                                               level switch { FeedLevel.Warning => "WARN", FeedLevel.Error => "ERROR",
                                                              FeedLevel.Critical => "CRIT",
                                                              _ => "INFO" },
                                           Source = normalizedSource,
                                           Message = cleanMessage,
                                           RepeatCount = repeatCount,
                                           RepeatText = repeatCount > 1 ? $"x{repeatCount}" : string.Empty,
                                           DedupKey = dedupKey,
                                           Foreground = BuildFeedForeground(level),
                                           SourceBrush = new SolidColorBrush(Color.FromRgb(0xD7, 0xDE, 0xE8)),
                                           BorderBrush = accent,
                                           RowBackground = BuildFeedBackground(level),
                                           LevelBackground = BuildFeedLevelBackground(level),
                                           LevelForeground = accent };
            }

            private static ParsedFeedMessage ParseFeedMessage(string rawMessage, string defaultSource,
                                                              DateTime timestamp)
            {
                string working = (rawMessage ?? string.Empty).Trim();
                string source = string.IsNullOrWhiteSpace(defaultSource) ? "GENERAL" : defaultSource.Trim();
                FeedLevel level = FeedLevel.Info;

                while (working.StartsWith("[", StringComparison.Ordinal))
                {
                    int end = working.IndexOf(']');
                    if (end <= 1)
                    {
                        break;
                    }

                    string token = working.Substring(1, end - 1).Trim();
                    if (TryParseLevelToken(token, out FeedLevel parsedLevel))
                    {
                        if ((int)parsedLevel > (int)level)
                        {
                            level = parsedLevel;
                        }
                    }
                    else if (!LooksLikeTimestampToken(token))
                    {
                        source = token;
                    }

                    working = working[(end + 1)..].TrimStart();
                }

                if (working.StartsWith("[-]", StringComparison.Ordinal))
                {
                    level = FeedLevel.Error;
                    working = working[3..].TrimStart();
                }
                else if (working.StartsWith("[*]", StringComparison.Ordinal))
                {
                    level = FeedLevel.Info;
                    working = working[3..].TrimStart();
                }

                if (level == FeedLevel.Info)
                {
                    level = InferLevelFromMessage(working);
                }

                string cleanMessage =
                    string.IsNullOrWhiteSpace(working) ? (rawMessage ?? string.Empty).Trim() : working;
                string dedupKey = $"{source.Trim().ToUpperInvariant()}|{level}|{NormalizeForDedup(cleanMessage)}";
                return new ParsedFeedMessage(timestamp, level, source, cleanMessage, dedupKey);
            }

            private static bool LooksLikeTimestampToken(string token)
            {
                return token.Length >= 19 &&
                       DateTime.TryParseExact(token, "yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture,
                                              DateTimeStyles.AssumeLocal, out _);
            }

            private static bool TryParseLevelToken(string token, out FeedLevel level)
            {
                switch (token.Trim().ToUpperInvariant())
                {
                case "WARN":
                case "WARNING":
                    level = FeedLevel.Warning;
                    return true;
                case "ERR":
                case "ERROR":
                    level = FeedLevel.Error;
                    return true;
                case "CRIT":
                case "CRITICAL":
                case "FATAL":
                    level = FeedLevel.Critical;
                    return true;
                case "INFO":
                    level = FeedLevel.Info;
                    return true;
                default:
                    level = FeedLevel.Info;
                    return false;
                }
            }

            private static FeedLevel InferLevelFromMessage(string message)
            {
                string text = message ?? string.Empty;
                if (text.IndexOf("critical", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    text.IndexOf("tampered", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    text.IndexOf("fatal", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    return FeedLevel.Critical;
                }

                if (text.IndexOf("failed", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    text.IndexOf("error", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    text.IndexOf("access denied", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    return FeedLevel.Error;
                }

                if (text.IndexOf("warn", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    text.IndexOf("degraded", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    text.IndexOf("timed out", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    text.IndexOf("unsupported", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    return FeedLevel.Warning;
                }

                return FeedLevel.Info;
            }

            private static string NormalizeForDedup(string text)
            {
                string[] parts = (text ?? string.Empty).Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
                return string.Join(" ", parts).Trim().ToUpperInvariant();
            }
        }

        private readonly struct ParsedFeedMessage
        {
            public ParsedFeedMessage(DateTime timestampLocal, FeedLevel level, string source, string message,
                                     string dedupKey)
            {
                TimestampLocal = timestampLocal;
                Level = level;
                Source = source;
                Message = message;
                DedupKey = dedupKey;
            }

            public DateTime TimestampLocal { get; }
            public FeedLevel Level { get; }
            public string Source { get; }
            public string Message { get; }
            public string DedupKey { get; }
        }

        private static Brush BuildFeedAccent(FeedLevel level)
        {
            return level switch { FeedLevel.Warning => new SolidColorBrush(Color.FromRgb(0xF0, 0xC6, 0x48)),
                                  FeedLevel.Error => new SolidColorBrush(Color.FromRgb(0xF0, 0x71, 0x78)),
                                  FeedLevel.Critical => new SolidColorBrush(Color.FromRgb(0xFF, 0x5B, 0xA6)),
                                  _ => new SolidColorBrush(Color.FromRgb(0x6F, 0xB7, 0xFF)) };
        }

        private static Brush BuildFeedForeground(FeedLevel level)
        {
            return level switch { FeedLevel.Warning => new SolidColorBrush(Color.FromRgb(0xFF, 0xE8, 0xAE)),
                                  FeedLevel.Error => new SolidColorBrush(Color.FromRgb(0xFF, 0xCF, 0xCF)),
                                  FeedLevel.Critical => new SolidColorBrush(Color.FromRgb(0xFF, 0xD4, 0xE4)),
                                  _ => new SolidColorBrush(Color.FromRgb(0xE5, 0xEE, 0xFF)) };
        }

        private static Brush BuildFeedBackground(FeedLevel level)
        {
            return level switch { FeedLevel.Warning => new SolidColorBrush(Color.FromArgb(0x45, 0x5E, 0x49, 0x12)),
                                  FeedLevel.Error => new SolidColorBrush(Color.FromArgb(0x45, 0x5E, 0x1E, 0x1E)),
                                  FeedLevel.Critical => new SolidColorBrush(Color.FromArgb(0x52, 0x55, 0x11, 0x2A)),
                                  _ => new SolidColorBrush(Color.FromArgb(0x38, 0x15, 0x24, 0x36)) };
        }

        private static Brush BuildFeedLevelBackground(FeedLevel level)
        {
            return level switch { FeedLevel.Warning => new SolidColorBrush(Color.FromArgb(0x1E, 0xF0, 0xC6, 0x48)),
                                  FeedLevel.Error => new SolidColorBrush(Color.FromArgb(0x22, 0xF0, 0x71, 0x78)),
                                  FeedLevel.Critical => new SolidColorBrush(Color.FromArgb(0x24, 0xFF, 0x5B, 0xA6)),
                                  _ => new SolidColorBrush(Color.FromArgb(0x20, 0x6F, 0xB7, 0xFF)) };
        }

        private static void ClearFeedBox(RichTextBox? box)
        {
            if (box == null)
            {
                return;
            }

            box.Document = new FlowDocument { PagePadding = new Thickness(0), TextAlignment = TextAlignment.Left };
        }

        private static void RewriteFeedBox(RichTextBox? box, IEnumerable<FeedEntryView> entries)
        {
            ClearFeedBox(box);
            if (box == null)
            {
                return;
            }

            foreach (FeedEntryView entry in entries)
            {
                AppendFeedParagraph(box, entry);
            }

            box.ScrollToEnd();
        }

        private static void AppendFeedParagraph(RichTextBox? box, FeedEntryView entry)
        {
            if (box == null)
            {
                return;
            }

            Paragraph paragraph = new() { Margin = new Thickness(0), LineHeight = 13 };
            paragraph.Inlines.Add(new Run(
                $"[{entry.TimestampText}] ") { Foreground = new SolidColorBrush(Color.FromRgb(0x98, 0xA2, 0xAE)) });
            paragraph.Inlines.Add(new Run($"[{entry.LevelLabel}] ") { Foreground = entry.LevelForeground,
                                                                      FontWeight = FontWeights.SemiBold });
            paragraph.Inlines.Add(new Run($"[{entry.Source}] ") { Foreground = entry.SourceBrush });
            paragraph.Inlines.Add(new Run(entry.Message) { Foreground = entry.Foreground });
            if (entry.RepeatCount > 1)
            {
                paragraph.Inlines.Add(new Run(
                    $"  {entry.RepeatText}") { Foreground = new SolidColorBrush(Color.FromRgb(0xA8, 0xB2, 0xBF)) });
            }
            box.Document.Blocks.Add(paragraph);
        }
    }
}
