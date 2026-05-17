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
        private readonly ObservableCollection<FeedEntryView> _targetFeedEntries = new();
        private readonly ObservableCollection<FeedEntryView> _exceptionFeedEntries = new();
        private readonly ObservableCollection<FeedEntryView> _controllerFeedEntries = new();
        private readonly ObservableCollection<ComponentEntryView> _componentEntries = new();
        private readonly ObservableCollection<ArchitectureLayerView> _architectureLayers = new();
        private long _controllerLogOffset;

        public DiagnosticsWindow(int pid)
        {
            InitializeComponent();
            WindowThemeHelper.WireThemeAwareTitleBar(this);

            _targetPid = pid > 0 ? pid : Environment.ProcessId;
            TargetBlock.Text = _targetPid > 0 ? $"Target {_targetPid}" : "No target";
            ProblemItemsControl.ItemsSource = _problemEntries;
            DisabledItemsControl.ItemsSource = _disabledEntries;
            DegradedItemsControl.ItemsSource = _degradedEntries;
            HealthyItemsControl.ItemsSource = _healthyEntries;
            ComponentItemsControl.ItemsSource = _componentEntries;
            ArchitectureLayersControl.ItemsSource = _architectureLayers;
            LoadOutputSnapshot();
            RefreshState();
            _ = LoadComponentIdentityAsync();

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
            _targetFeedEntries.Clear();
            _exceptionFeedEntries.Clear();
            ClearFeedBox(OutputFeedBox);
            ClearFeedBox(TargetFeedBox);
            ClearFeedBox(ExceptionsFeedBox);
            foreach (DebugConsoleEntry entry in DebugConsoleService.Snapshot())
            {
                AppendDebugConsoleEntry(entry);
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
            ReplaceCollection(_architectureLayers, BuildArchitectureLayers(values));
        }

        private static List<DiagnosticsStateEntry> BuildSubsystemEntries(IReadOnlyDictionary<string, string> values)
        {
            var projected = new List<DiagnosticsStateEntry>();
            AddProjected(projected, "Interface->Controller IPC",
                         ResolveFirst(values, "Interface->Controller IPC", "Connectivity"));
            AddProjected(projected, "HookDLL->Controller IPC", ResolveHookIpc(values));
            AddProjected(projected, "HookDLL Hooks Set", ResolveHookDllHooksSet(values));
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
            AddProjected(projected, "PID Coverage", ResolveFirst(values, "PID Coverage"));
            AddProjected(projected, "Driver Queue", ResolveFirst(values, "Driver Queue"));
            AddProjected(projected, "Driver Health", ResolveFirst(values, "Driver Health"));
            AddProjected(projected, "Driver Components", ResolveFirst(values, "Driver Components"));
            AddProjected(projected, "Driver Tamper", ResolveDriverTamper(values));
            AddProjected(projected, "SR71 Hook Ready", ResolveSr71HookReady(values));
            AddProjected(projected, "SR71 Instrumentation", ResolveSr71Instrumentation(values));
            AddProjected(projected, "Ntdll Mirror", ResolveFirst(values, "Ntdll Mirror"));
            AddProjected(projected, "Tempus", ResolveFirst(values, "Tempus"));
            AddProjected(projected, "API Graph", ResolveFirst(values, "API Graph"));
            AddProjected(projected, "Driver Service", ResolveFirst(values, "Driver Service"));
            AddProjected(projected, "Controller Service", ResolveFirst(values, "Controller Service"));
            AddProjected(projected, "Virtualization", ResolveFirst(values, "Virtualization"));
            AddProjected(projected, "HookDLL Presence", ResolveHookDllPresence(values));
            AddProjected(projected, "Last Fault", ResolveFirst(values, "Last Fault"));
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
            if (IsGoodStatus(explicitValue))
            {
                return explicitValue;
            }

            string? hooks = ResolveFirst(values, "Usermode Hooks");
            string? hookReady = ResolveSr71HookReady(values);
            if (IsGoodStatus(hooks) || IsGoodStatus(hookReady))
            {
                return "Ready";
            }

            if (!string.IsNullOrWhiteSpace(explicitValue) && !IsPendingStatus(explicitValue))
            {
                return explicitValue;
            }

            if (string.IsNullOrWhiteSpace(hooks))
            {
                return explicitValue;
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

        private static string? ResolveHookDllHooksSet(IReadOnlyDictionary<string, string> values)
        {
            string? explicitValue = ResolveFirst(values, "HookDLL Hooks Set");
            if (IsGoodStatus(explicitValue) || IsBadStatus(explicitValue) || IsDisabledStatus(explicitValue))
            {
                return explicitValue;
            }

            string? hooks = ResolveFirst(values, "Usermode Hooks");
            if (IsDisabledStatus(hooks))
            {
                return hooks;
            }

            if (IsGoodStatus(hooks))
            {
                return hooks;
            }

            string? hookReady = ResolveSr71HookReady(values);
            if (IsGoodStatus(hookReady))
            {
                return "OK";
            }

            return explicitValue ?? hooks;
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
            if (IsBadStatus(explicitValue) || IsGoodStatus(explicitValue) || IsDisabledStatus(explicitValue))
            {
                return explicitValue;
            }

            string? hooks = ResolveFirst(values, "Usermode Hooks");
            string? hookReady = ResolveSr71HookReady(values);
            bool hookPathReady =
                IsGoodStatus(hookReady) ||
                (!string.IsNullOrWhiteSpace(hooks) && hooks.Contains("Active", StringComparison.OrdinalIgnoreCase));
            if (key.Equals("Hook Integrity", StringComparison.OrdinalIgnoreCase) && hookPathReady)
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

            if (key.Equals("AMSI Integrity", StringComparison.OrdinalIgnoreCase) && hookPathReady)
            {
                return "OK";
            }

            return explicitValue;
        }

        private static string? ResolveDriverTamper(IReadOnlyDictionary<string, string> values)
        {
            string? value = ResolveFirst(values, "Driver Tamper");
            if (string.IsNullOrWhiteSpace(value))
            {
                return null;
            }

            if (TryReadHexToken(value, "mask", out uint mask))
            {
                return mask == 0 ? "OK mask=0x00000000" : $"DEGRADED mask=0x{mask:X8}";
            }

            return value;
        }

        private static string? ResolveSr71HookReady(IReadOnlyDictionary<string, string> values)
        {
            string? value = ResolveFirst(values, "SR71 Hook Ready");
            string? hooks = ResolveFirst(values, "Usermode Hooks", "HookDLL Hooks Set");
            if (IsDisabledStatus(hooks))
            {
                return hooks;
            }

            if (IsGoodStatus(value) || IsBadStatus(value) || IsDisabledStatus(value))
            {
                return value;
            }

            if (!string.IsNullOrWhiteSpace(value) &&
                (value.Contains("missingNames=", StringComparison.OrdinalIgnoreCase) ||
                 value.Contains("present=", StringComparison.OrdinalIgnoreCase)))
            {
                return value;
            }

            if (IsGoodStatus(hooks))
            {
                return "OK observed via SR71 telemetry";
            }

            if (!string.IsNullOrWhiteSpace(value) && TryReadHexToken(value, "mask", out uint observed) &&
                TryReadHexToken(value, "required", out uint required))
            {
                if (required == 0)
                {
                    return observed == 0 ? "Inactive mask=0x00000000" : $"OK mask=0x{observed:X8}";
                }

                uint missing = required & ~observed;
                return missing == 0 ? $"OK mask=0x{observed:X8}"
                                    : $"Awaiting hook-ready mask=0x{observed:X8} missing=0x{missing:X8}";
            }

            return value;
        }

        private static string? ResolveSr71Instrumentation(IReadOnlyDictionary<string, string> values)
        {
            string? value = ResolveFirst(values, "SR71 Instrumentation");
            string? hooks = ResolveFirst(values, "Usermode Hooks", "HookDLL Hooks Set");
            if (IsDisabledStatus(hooks))
            {
                return hooks;
            }

            if (IsGoodStatus(value) || IsBadStatus(value) || IsDisabledStatus(value))
            {
                return value;
            }

            if (TryReadUIntToken(value, "ranges", out uint ranges) && ranges > 0)
            {
                return value!.Contains("OK", StringComparison.OrdinalIgnoreCase) ? value : $"OK {value}";
            }

            string? hookReady = ResolveSr71HookReady(values);
            if (IsGoodStatus(hookReady) || IsGoodStatus(hooks))
            {
                return "OK observed via SR71 telemetry";
            }

            return value;
        }

        private static string? ResolveHookDllPresence(IReadOnlyDictionary<string, string> values)
        {
            string? hookState = ResolveFirst(values, "Usermode Hooks");
            if (IsDisabledStatus(hookState))
            {
                return hookState;
            }

            if (!string.IsNullOrWhiteSpace(hookState) &&
                hookState.Contains("Active", StringComparison.OrdinalIgnoreCase))
            {
                return "Active";
            }

            return ResolveFirst(values, "HookDLL Presence", "Hook DLL", "HookDLL");
        }

        private static bool IsGoodStatus(string? value)
        {
            if (string.IsNullOrWhiteSpace(value) || IsBadStatus(value) || IsDisabledStatus(value) ||
                IsPendingStatus(value))
            {
                return false;
            }

            return value.Contains("OK", StringComparison.OrdinalIgnoreCase) ||
                   value.Contains("Running", StringComparison.OrdinalIgnoreCase) ||
                   value.Contains("Enabled", StringComparison.OrdinalIgnoreCase) ||
                   value.Contains("Open", StringComparison.OrdinalIgnoreCase) ||
                   value.Contains("Found", StringComparison.OrdinalIgnoreCase) ||
                   value.Contains("Active", StringComparison.OrdinalIgnoreCase) ||
                   value.Contains("Connected", StringComparison.OrdinalIgnoreCase) ||
                   value.Contains("Established", StringComparison.OrdinalIgnoreCase) ||
                   value.Contains("Initialized", StringComparison.OrdinalIgnoreCase) ||
                   value.Contains("Ready", StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsBadStatus(string? value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return false;
            }

            return value.Contains("TAMPERED", StringComparison.OrdinalIgnoreCase) ||
                   value.Contains("FAILED", StringComparison.OrdinalIgnoreCase) ||
                   ContainsStatusWord(value, "MISSING") ||
                   value.Contains("OPEN FAILED", StringComparison.OrdinalIgnoreCase) ||
                   value.Contains("TIMED OUT", StringComparison.OrdinalIgnoreCase) ||
                   value.Contains("STOPPED", StringComparison.OrdinalIgnoreCase) ||
                   value.Contains("ERROR", StringComparison.OrdinalIgnoreCase) ||
                   value.Contains("ACCESS DENIED", StringComparison.OrdinalIgnoreCase);
        }

        private static bool ContainsStatusWord(string value, string word)
        {
            int index = value.IndexOf(word, StringComparison.OrdinalIgnoreCase);
            while (index >= 0)
            {
                bool beforeOk = index == 0 || !char.IsLetterOrDigit(value[index - 1]);
                int after = index + word.Length;
                bool afterOk = after >= value.Length ||
                               (!char.IsLetterOrDigit(value[after]) && value[after] != '=');
                if (beforeOk && afterOk)
                {
                    return true;
                }

                index = value.IndexOf(word, index + word.Length, StringComparison.OrdinalIgnoreCase);
            }

            return false;
        }

        private static bool IsDisabledStatus(string? value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return false;
            }

            return value.Contains("DISABLED", StringComparison.OrdinalIgnoreCase) ||
                   value.Contains("INACTIVE", StringComparison.OrdinalIgnoreCase) ||
                   value.Contains("DEFERRED", StringComparison.OrdinalIgnoreCase) ||
                   value.Contains("CLOSED", StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsPendingStatus(string? value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return false;
            }

            return value.Contains("DEGRADED", StringComparison.OrdinalIgnoreCase) ||
                   value.Contains("UNKNOWN", StringComparison.OrdinalIgnoreCase) ||
                   value.Contains("AWAITING", StringComparison.OrdinalIgnoreCase) ||
                   value.Contains("REVIEW", StringComparison.OrdinalIgnoreCase) ||
                   value.Contains("NO DATA", StringComparison.OrdinalIgnoreCase) ||
                   value.Contains("UNSUPPORTED", StringComparison.OrdinalIgnoreCase);
        }

        private static bool TryReadHexToken(string? value, string token, out uint parsed)
        {
            parsed = 0;
            if (string.IsNullOrWhiteSpace(value))
            {
                return false;
            }

            string prefix = token + "=";
            int start = value.IndexOf(prefix, StringComparison.OrdinalIgnoreCase);
            if (start < 0)
            {
                return false;
            }

            start += prefix.Length;
            if (start + 2 <= value.Length && value.AsSpan(start).StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            {
                start += 2;
            }

            int end = start;
            while (end < value.Length && Uri.IsHexDigit(value[end]))
            {
                end += 1;
            }

            return end > start && uint.TryParse(value.AsSpan(start, end - start), NumberStyles.HexNumber,
                                                CultureInfo.InvariantCulture, out parsed);
        }

        private static bool TryReadUIntToken(string? value, string token, out uint parsed)
        {
            parsed = 0;
            if (string.IsNullOrWhiteSpace(value))
            {
                return false;
            }

            string prefix = token + "=";
            int start = value.IndexOf(prefix, StringComparison.OrdinalIgnoreCase);
            if (start < 0)
            {
                return false;
            }

            start += prefix.Length;
            int end = start;
            while (end < value.Length && char.IsDigit(value[end]))
            {
                end += 1;
            }

            return end > start && uint.TryParse(value.AsSpan(start, end - start), NumberStyles.Integer,
                                                CultureInfo.InvariantCulture, out parsed);
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
            _ = Dispatcher.BeginInvoke(new Action(() =>
                                                  { AppendDebugConsoleEntry(entry); }),
                                       DispatcherPriority.Background);
        }

        private void AppendDebugConsoleEntry(DebugConsoleEntry entry)
        {
            if (DebugConsoleService.ShouldDropPreResumeSr71Entry(entry))
            {
                return;
            }

            FeedEntryView parsed = FeedEntryView.FromDebugConsole(entry);
            AppendFeedEntry(_outputFeedEntries, parsed, OutputFeedBox);

            if (IsTargetFeedEntry(entry))
            {
                AppendFeedEntry(_targetFeedEntries, parsed, TargetFeedBox);
            }

            if (IsVehExceptionEntry(entry))
            {
                AppendFeedEntry(_exceptionFeedEntries, parsed, ExceptionsFeedBox);
            }
        }

        private void LoadControllerLogInitial()
        {
            _controllerFeedEntries.Clear();
            ClearFeedBox(ControllerFeedBox);
            if (!EnsureControllerLogFile(out string prepareError))
            {
                string message = string.IsNullOrWhiteSpace(prepareError)
                                     ? "unable to prepare controller log"
                                     : $"unable to prepare controller log: {prepareError}";
                AppendFeedEntry(_controllerFeedEntries,
                                FeedEntryView.Create(DateTime.Now, FeedLevel.Error, "CONTROLLER", message,
                                                     $"CONTROLLER|ERROR|{message}"),
                                ControllerFeedBox);
                return;
            }

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
            catch (Exception ex)
            {
                bool accessDenied = ex is UnauthorizedAccessException;
                string message =
                    accessDenied ? "controller log is not readable by this session; continuing without controller tail"
                                 : $"unable to read controller log: {ex.Message}";
                AppendFeedEntry(_controllerFeedEntries,
                                FeedEntryView.Create(DateTime.Now, accessDenied ? FeedLevel.Warning : FeedLevel.Error,
                                                     "CONTROLLER", message,
                                                     $"CONTROLLER|{(accessDenied ? "WARNING" : "ERROR")}|{message}"),
                                ControllerFeedBox);
            }
        }

        private void TailControllerLog()
        {
            if (!EnsureControllerLogFile(out _))
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

        private static bool EnsureControllerLogFile(out string error)
        {
            error = string.Empty;
            try
            {
                string? directory = Path.GetDirectoryName(ControllerLogPath);
                if (!string.IsNullOrWhiteSpace(directory) && !Directory.Exists(directory))
                {
                    try
                    {
                        Directory.CreateDirectory(directory);
                    }
                    catch (UnauthorizedAccessException)
                    {
                        return true;
                    }
                }

                if (!File.Exists(ControllerLogPath))
                {
                    try
                    {
                        using FileStream _ =
                            new FileStream(ControllerLogPath, FileMode.OpenOrCreate, FileAccess.ReadWrite,
                                           FileShare.ReadWrite | FileShare.Delete);
                    }
                    catch (UnauthorizedAccessException)
                    {
                        return true;
                    }
                }

                return true;
            }
            catch (Exception ex)
            {
                error = $"{ex.GetType().Name}: {ex.Message}";
                return false;
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
            _targetFeedEntries.Clear();
            _exceptionFeedEntries.Clear();
            ClearFeedBox(OutputFeedBox);
            ClearFeedBox(TargetFeedBox);
            ClearFeedBox(ExceptionsFeedBox);
        }

        private async System.Threading.Tasks.Task LoadComponentIdentityAsync()
        {
            IReadOnlyList<ComponentEntry> entries =
                await System.Threading.Tasks.Task.Run(ComponentIdentityService.GetEntries);
            _componentEntries.Clear();
            foreach (ComponentEntry entry in entries)
                _componentEntries.Add(ComponentEntryView.From(entry));
        }

        private async void RefreshComponents_Click(object sender, RoutedEventArgs e)
        {
            IReadOnlyList<ComponentEntry> entries =
                await System.Threading.Tasks.Task.Run(ComponentIdentityService.Refresh);
            _componentEntries.Clear();
            foreach (ComponentEntry entry in entries)
                _componentEntries.Add(ComponentEntryView.From(entry));
        }

        private void CopyComponents_Click(object sender, RoutedEventArgs e)
        {
            var sb = new StringBuilder();
            sb.AppendLine($"{"Component",-14}  {"Description",-74}  {"Version",-24}  {"SHA-256",-64}  Path");
            sb.AppendLine(new string('-', 230));
            foreach (ComponentEntry entry in ComponentIdentityService.GetEntries())
            {
                string hash = string.IsNullOrEmpty(entry.HashHex) ? "(not found)" : entry.HashHex;
                sb.AppendLine(
                    $"{entry.Name,-14}  {entry.Description,-74}  {entry.Version,-24}  {hash,-64}  {entry.Path}");
            }
            try
            {
                Clipboard.SetText(sb.ToString());
            }
            catch
            {
            }
        }

        private bool IsTargetFeedEntry(DebugConsoleEntry entry)
        {
            if (_targetPid <= 0)
            {
                return false;
            }

            if (entry.ProcessId == _targetPid)
            {
                return true;
            }

            return entry.Source.EndsWith($":{_targetPid}", StringComparison.OrdinalIgnoreCase);
        }

        private bool IsVehExceptionEntry(DebugConsoleEntry entry)
        {
            if (!IsTargetFeedEntry(entry))
            {
                return false;
            }

            return entry.Message.IndexOf("[VEH]", StringComparison.OrdinalIgnoreCase) >= 0 ||
                   entry.Message.IndexOf("veh-exception", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        private void DiagnosticCard_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
        {
            if (e.ClickCount < 2 || (sender as FrameworkElement)?.Tag is not DiagnosticsEntryView view)
            {
                return;
            }

            e.Handled = true;
            Dictionary<string, string> values =
                DiagnosticsState.SnapshotEntries()
                    .Where(x => !string.IsNullOrWhiteSpace(x.Key))
                    .GroupBy(x => x.Key, StringComparer.OrdinalIgnoreCase)
                    .ToDictionary(g => g.Key, g => g.Last().Value, StringComparer.OrdinalIgnoreCase);
            MessageBox.Show(this, BuildDiagnosticDetail(view, values), $"{view.Key} diagnostics",
                            MessageBoxButton.OK, MessageBoxImage.Information);
        }

        private static string BuildDiagnosticDetail(DiagnosticsEntryView view,
                                                    IReadOnlyDictionary<string, string> values)
        {
            var sb = new StringBuilder(1024);
            sb.AppendLine(view.Key);
            sb.AppendLine($"Status: {view.StatusLabel}");
            sb.AppendLine($"Domain: {view.DomainLabel}");
            sb.AppendLine($"Summary: {view.Value}");
            sb.AppendLine($"Guidance: {view.Guidance}");
            AppendEvidenceTokens(sb, view.Value);

            var related = RelatedDiagnostics(view.Key, values).ToList();
            if (related.Count > 0)
            {
                sb.AppendLine();
                sb.AppendLine("Related state:");
                foreach (KeyValuePair<string, string> item in related)
                {
                    sb.AppendLine($"- {item.Key}: {item.Value}");
                }
            }

            if (view.Value.Contains("preArm=true", StringComparison.OrdinalIgnoreCase))
            {
                sb.AppendLine();
                sb.AppendLine("Interpretation: SR71 is injected while the target is still suspended. Integrity verdicts are deferred until the first post-resume user-mode telemetry.");
            }

            return sb.ToString().TrimEnd();
        }

        private static void AppendEvidenceTokens(StringBuilder sb, string value)
        {
            string[] tokens = (value ?? string.Empty).Split(';', StringSplitOptions.RemoveEmptyEntries);
            if (tokens.Length <= 1)
            {
                return;
            }

            sb.AppendLine();
            sb.AppendLine("Evidence:");
            foreach (string token in tokens.Skip(1))
            {
                sb.AppendLine($"- {token.Trim()}");
            }
        }

        private static IEnumerable<KeyValuePair<string, string>> RelatedDiagnostics(
            string key,
            IReadOnlyDictionary<string, string> values)
        {
            string[] relatedKeys =
                key switch {
                    "Driver Health" or "Driver Components" or "Driver Tamper" or "Kernel Hooks" or
                        "Driver Queue" => new[] { "Driver Health", "Driver Components", "Driver Tamper",
                                                  "Kernel Hooks", "Driver Queue", "Controller<->Driver Comms" },
                    "SR71 Hook Ready" or "SR71 Instrumentation" or "HookDLL Hooks Set" or
                        "HookDLL->Controller IPC" => new[] { "SR71 Hook Ready", "SR71 Instrumentation",
                                                              "Usermode Hooks", "HookDLL Hooks Set",
                                                              "HookDLL->Controller IPC", "HookDLL Presence" },
                    "Hook Integrity" or "AMSI Integrity" or "ETW Integrity" => new[] { "Hook Integrity",
                                                                                        "AMSI Integrity",
                                                                                        "ETW Integrity",
                                                                                        "SR71 Hook Ready",
                                                                                        "Usermode Hooks" },
                    _ => new[] { key }
                };

            foreach (string relatedKey in relatedKeys)
            {
                if (values.TryGetValue(relatedKey, out string? value) && !string.IsNullOrWhiteSpace(value))
                {
                    yield return new KeyValuePair<string, string>(relatedKey, value);
                }
            }

            if (key.StartsWith("Driver", StringComparison.OrdinalIgnoreCase) ||
                key.Equals("Kernel Hooks", StringComparison.OrdinalIgnoreCase))
            {
                foreach (KeyValuePair<string, string> item in values
                             .Where(x => x.Key.StartsWith("Driver Component:", StringComparison.OrdinalIgnoreCase))
                             .OrderBy(x => x.Key, StringComparer.OrdinalIgnoreCase))
                {
                    yield return item;
                }
            }
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

        private static IReadOnlyList<ArchitectureLayerView> BuildArchitectureLayers(
            IReadOnlyDictionary<string, string> values)
        {
            return new[] {
                ArchitectureLayerView.From(
                    "Operator Surface",
                    "The WPF analyst interface and local state used to control the current capture.",
                    new[] {
                        Component(values, "Interface", "Interface->Controller IPC", "Connectivity"),
                        Component(values, "Controller", "Controller Service"),
                        Component(values, "Runtime Config", "RuntimeConfig"),
                        Component(values, "Capture Store", "Capture Store")
                    }),
                ArchitectureLayerView.From(
                    "Local Transport",
                    "Named-pipe IPC, hook ingest, driver proxy, and access-control boundary.",
                    new[] {
                        Component(values, "Interface IPC", "Interface->Controller IPC", "Connectivity"),
                        Component(values, "Hook IPC", "HookDLL->Controller IPC"),
                        Component(values, "Driver Proxy", "Controller<->Driver Comms", "DriverProxy"),
                        Component(values, "DACLs", "DACLs")
                    }),
                ArchitectureLayerView.From(
                    "SR71 Target Runtime",
                    "Injected user-mode runtime, hook readiness, integrity verdicts, and ntdll mirror state.",
                    new[] {
                        Component(values, "Hook DLL", "HookDLL Presence", "Hook DLL", "HookDLL"),
                        Component(values, "Ready Mask", "SR71 Hook Ready"),
                        Component(values, "Instrumentation", "SR71 Instrumentation"),
                        Component(values, "Hook Integrity", "Hook Integrity"),
                        Component(values, "AMSI", "AMSI Integrity"),
                        Component(values, "ETW Patch", "ETW Integrity"),
                        Component(values, "Ntdll Mirror", "Ntdll Mirror")
                    }),
                ArchitectureLayerView.From(
                    "Kernel Driver",
                    "Driver service, callback registration, hook surface, queueing, and component diagnostics.",
                    new[] {
                        Component(values, "Driver Service", "Driver Service"),
                        Component(values, "Health Mask", "Driver Health"),
                        Component(values, "Components", "Driver Components"),
                        Component(values, "Tamper Mask", "Driver Tamper"),
                        Component(values, "Kernel Hooks", "Kernel Hooks"),
                        Component(values, "Queue", "Driver Queue")
                    }),
                ArchitectureLayerView.From(
                    "Telemetry And Analysis",
                    "ETW feeds, signature intelligence, graph enrichment, timing, and virtualization context.",
                    new[] {
                        Component(values, "ETW", "ETW Status"),
                        Component(values, "Signature Intel", "Signature Intel"),
                        Component(values, "PID Coverage", "PID Coverage"),
                        Component(values, "API Graph", "API Graph"),
                        Component(values, "Tempus", "Tempus"),
                        Component(values, "Virtualization", "Virtualization", "Hypervisor", "BlackbirdVisor")
                    })
            };
        }

        private static ArchitectureComponentView Component(IReadOnlyDictionary<string, string> values, string name,
                                                           string key, params string[] aliases)
        {
            string? value = ResolveArchitectureValue(values, key, aliases);
            string effectiveValue = string.IsNullOrWhiteSpace(value) ? "No data" : value.Trim();
            DiagnosticsEntryView diagnostic =
                DiagnosticsEntryView.From(new DiagnosticsStateEntry { Key = key, Value = effectiveValue });
            return ArchitectureComponentView.From(name, key, effectiveValue, diagnostic);
        }

        private static string? ResolveArchitectureValue(IReadOnlyDictionary<string, string> values, string key,
                                                        params string[] aliases)
        {
            if (values.TryGetValue(key, out string? value) && !string.IsNullOrWhiteSpace(value))
            {
                return value;
            }

            foreach (string alias in aliases)
            {
                if (values.TryGetValue(alias, out value) && !string.IsNullOrWhiteSpace(value))
                {
                    return value;
                }
            }

            return null;
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

        private sealed class ArchitectureLayerView
        {
            public string Name { get; init; } = string.Empty;
            public string Description { get; init; } = string.Empty;
            public IReadOnlyList<ArchitectureComponentView> Components { get; init; } =
                Array.Empty<ArchitectureComponentView>();
            public string StateLabel { get; init; } = string.Empty;
            public Brush Background { get; init; } = Brushes.Transparent;
            public Brush BorderBrush { get; init; } = Brushes.Transparent;
            public Brush Foreground { get; init; } = Brushes.White;

            internal static ArchitectureLayerView From(string name, string description,
                                                       IReadOnlyList<ArchitectureComponentView> components)
            {
                DiagnosticsStatusKind kind = AggregateKind(components);
                return new ArchitectureLayerView { Name = name,
                                                   Description = description,
                                                   Components = components,
                                                   StateLabel =
                                                       kind switch {
                                                           DiagnosticsStatusKind.Good => "Healthy",
                                                           DiagnosticsStatusKind.Disabled => "Disabled",
                                                           DiagnosticsStatusKind.Error => "Error",
                                                           DiagnosticsStatusKind.Critical => "Critical",
                                                           DiagnosticsStatusKind.Warning => "Review",
                                                           _ => "Unknown"
                                                       },
                                                   Background = BackgroundFor(kind),
                                                   BorderBrush = BorderFor(kind),
                                                   Foreground = ForegroundFor(kind) };
            }

            private static DiagnosticsStatusKind AggregateKind(IReadOnlyList<ArchitectureComponentView> components)
            {
                if (components.Any(x => x.StatusKind == DiagnosticsStatusKind.Critical))
                {
                    return DiagnosticsStatusKind.Critical;
                }
                if (components.Any(x => x.StatusKind == DiagnosticsStatusKind.Error))
                {
                    return DiagnosticsStatusKind.Error;
                }
                if (components.Any(x => x.StatusKind is DiagnosticsStatusKind.Warning or DiagnosticsStatusKind.Neutral))
                {
                    return DiagnosticsStatusKind.Warning;
                }
                if (components.Count > 0 && components.All(x => x.StatusKind == DiagnosticsStatusKind.Disabled))
                {
                    return DiagnosticsStatusKind.Disabled;
                }
                if (components.Any(x => x.StatusKind == DiagnosticsStatusKind.Disabled))
                {
                    return DiagnosticsStatusKind.Warning;
                }

                return DiagnosticsStatusKind.Good;
            }
        }

        private sealed class ArchitectureComponentView
        {
            public string Name { get; init; } = string.Empty;
            public string Key { get; init; } = string.Empty;
            public string Value { get; init; } = string.Empty;
            public string Detail { get; init; } = string.Empty;
            public DiagnosticsStatusKind StatusKind { get; init; }
            public Brush Background { get; init; } = Brushes.Transparent;
            public Brush BorderBrush { get; init; } = Brushes.Transparent;
            public Brush Foreground { get; init; } = Brushes.White;
            public Brush StatusDotBrush { get; init; } = Brushes.Gray;

            internal static ArchitectureComponentView From(string name, string key, string value,
                                                           DiagnosticsEntryView diagnostic)
            {
                return new ArchitectureComponentView { Name = name,
                                                       Key = key,
                                                       Value = CompactArchitectureValue(value),
                                                       Detail = $"{key}: {value}",
                                                       StatusKind = diagnostic.StatusKind,
                                                       Background = BackgroundFor(diagnostic.StatusKind),
                                                       BorderBrush = BorderFor(diagnostic.StatusKind),
                                                       Foreground = ForegroundFor(diagnostic.StatusKind),
                                                       StatusDotBrush = BorderFor(diagnostic.StatusKind) };
            }

            private static string CompactArchitectureValue(string value)
            {
                string text = string.IsNullOrWhiteSpace(value) ? "No data" : value.Trim();
                return text.Length <= 88 ? text : text[..85] + "...";
            }
        }

        private static Brush BackgroundFor(DiagnosticsStatusKind kind)
        {
            return kind == DiagnosticsStatusKind.Neutral
                       ? new SolidColorBrush(Color.FromRgb(0x05, 0x05, 0x05))
                       : new SolidColorBrush(Color.FromRgb(0x00, 0x00, 0x00));
        }

        private static Brush BorderFor(DiagnosticsStatusKind kind)
        {
            return kind switch { DiagnosticsStatusKind.Good => new SolidColorBrush(Color.FromRgb(0x4D, 0xC2, 0x74)),
                                 DiagnosticsStatusKind.Disabled =>
                                     new SolidColorBrush(Color.FromRgb(0x7E, 0x87, 0x91)),
                                 DiagnosticsStatusKind.Warning =>
                                     new SolidColorBrush(Color.FromRgb(0xE3, 0xB9, 0x45)),
                                 DiagnosticsStatusKind.Error =>
                                     new SolidColorBrush(Color.FromRgb(0xDF, 0x63, 0x63)),
                                 DiagnosticsStatusKind.Critical =>
                                     new SolidColorBrush(Color.FromRgb(0xFF, 0x66, 0x99)),
                                 _ => new SolidColorBrush(Color.FromRgb(0x5C, 0x66, 0x73)) };
        }

        private static Brush ForegroundFor(DiagnosticsStatusKind kind)
        {
            return kind switch { DiagnosticsStatusKind.Good => new SolidColorBrush(Color.FromRgb(0xBE, 0xF7, 0xCD)),
                                 DiagnosticsStatusKind.Disabled =>
                                     new SolidColorBrush(Color.FromRgb(0xD2, 0xD8, 0xDE)),
                                 DiagnosticsStatusKind.Warning =>
                                     new SolidColorBrush(Color.FromRgb(0xF7, 0xE6, 0xA6)),
                                 DiagnosticsStatusKind.Error =>
                                     new SolidColorBrush(Color.FromRgb(0xFF, 0xC5, 0xC5)),
                                 DiagnosticsStatusKind.Critical =>
                                     new SolidColorBrush(Color.FromRgb(0xFF, 0xC8, 0xDB)),
                                 _ => new SolidColorBrush(Color.FromRgb(0xEC, 0xF0, 0xF3)) };
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
                    Background = kind == DiagnosticsStatusKind.Neutral
                                     ? new SolidColorBrush(Color.FromRgb(0x05, 0x05, 0x05))
                                     : new SolidColorBrush(Color.FromRgb(0x00, 0x00, 0x00)),
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
                    DiagnosticsWindow.ContainsStatusWord(text, "MISSING") ||
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
                return key.Trim() switch { "Interface->Controller IPC" or "HookDLL->Controller IPC" or
                                           "Controller<->Driver Comms" => DiagnosticsDomain.Ipc,

                                           "HookDLL Hooks Set" or "Kernel Hooks" or "HookDLL Presence" or
                                           "SR71 Hook Ready" or "SR71 Instrumentation" or "Ntdll Mirror" =>
                                               DiagnosticsDomain.Hooks,

                                           "Hook Integrity" or "AMSI Integrity" or "ETW Integrity" or "DACLs" or
                                           "Driver Health" or "Driver Components" or "Driver Tamper" =>
                                               DiagnosticsDomain.Integrity,

                                           "Driver Service" or "Controller Service" => DiagnosticsDomain.Services,

                                           "ETW Status" or "Signature Intel" or "Capture Store" or "RuntimeConfig" or
                                           "PID Coverage" or "Driver Queue" or "Tempus" or "API Graph" or
                                           "Last Fault" => DiagnosticsDomain.Capture,

                                           _ => DiagnosticsDomain.Other };
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
                                           "PID Coverage" => 14,
                                           "Driver Queue" => 15,
                                           "Driver Health" => 16,
                                           "Driver Components" => 17,
                                           "Driver Tamper" => 18,
                                           "SR71 Hook Ready" => 19,
                                           "SR71 Instrumentation" => 20,
                                           "Ntdll Mirror" => 21,
                                           "Tempus" => 22,
                                           "API Graph" => 23,
                                           "Driver Service" => 24,
                                           "Controller Service" => 25,
                                           "Virtualization" => 26,
                                           "Last Fault" => 27,
                                           _ => 100 };
            }
        }

        private sealed class ComponentEntryView
        {
            public string Name { get; init; } = string.Empty;
            public string Description { get; init; } = string.Empty;
            public string Version { get; init; } = string.Empty;
            public string HashShort { get; init; } = string.Empty;
            public string HashFull { get; init; } = string.Empty;
            public string Path { get; init; } = string.Empty;
            public Brush Background { get; init; } = Brushes.Transparent;
            public Brush BorderBrush { get; init; } = Brushes.Transparent;
            public Brush Foreground { get; init; } = Brushes.White;

            internal static ComponentEntryView From(ComponentEntry e)
            {
                string short16 = string.IsNullOrEmpty(e.HashHex) ? "—" : e.HashHex[..Math.Min(16, e.HashHex.Length)];

                return new ComponentEntryView {
                    Name = e.Name,
                    Description = e.Description,
                    Version = e.Version,
                    HashShort = short16,
                    HashFull = string.IsNullOrEmpty(e.HashHex) ? "(no hash)" : e.HashHex,
                    Path = e.Path,
                    Background = e.Found ? new SolidColorBrush(Color.FromArgb(0x38, 0x15, 0x24, 0x36))
                                         : new SolidColorBrush(Color.FromArgb(0x40, 0x3E, 0x16, 0x16)),
                    BorderBrush = e.Found ? new SolidColorBrush(Color.FromRgb(0x2C, 0x38, 0x46))
                                          : new SolidColorBrush(Color.FromRgb(0xDF, 0x63, 0x63)),
                    Foreground = e.Found ? new SolidColorBrush(Color.FromRgb(0xE5, 0xEE, 0xFF))
                                         : new SolidColorBrush(Color.FromRgb(0xFF, 0xC5, 0xC5))
                };
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
                                  _ => new SolidColorBrush(Color.FromRgb(0xE7, 0xE7, 0xE7)) };
        }

        private static Brush BuildFeedBackground(FeedLevel level)
        {
            return level switch { FeedLevel.Warning => new SolidColorBrush(Color.FromArgb(0x45, 0x5E, 0x49, 0x12)),
                                  FeedLevel.Error => new SolidColorBrush(Color.FromArgb(0x45, 0x5E, 0x1E, 0x1E)),
                                  FeedLevel.Critical => new SolidColorBrush(Color.FromArgb(0x52, 0x55, 0x11, 0x2A)),
                                  _ => new SolidColorBrush(Color.FromArgb(0x26, 0x14, 0x14, 0x14)) };
        }

        private static Brush BuildFeedLevelBackground(FeedLevel level)
        {
            return level switch { FeedLevel.Warning => new SolidColorBrush(Color.FromArgb(0x1E, 0xF0, 0xC6, 0x48)),
                                  FeedLevel.Error => new SolidColorBrush(Color.FromArgb(0x22, 0xF0, 0x71, 0x78)),
                                  FeedLevel.Critical => new SolidColorBrush(Color.FromArgb(0x24, 0xFF, 0x5B, 0xA6)),
                                  _ => new SolidColorBrush(Color.FromArgb(0x20, 0x8A, 0x8A, 0x8A)) };
        }

        private static void ClearFeedBox(RichTextBox? box)
        {
            if (box == null)
            {
                return;
            }

            box.Document = new FlowDocument { PagePadding = new Thickness(0), TextAlignment = TextAlignment.Left,
                                              Background = new SolidColorBrush(Color.FromRgb(0x10, 0x10, 0x10)),
                                              Foreground = new SolidColorBrush(Color.FromRgb(0xE7, 0xE7, 0xE7)) };
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
