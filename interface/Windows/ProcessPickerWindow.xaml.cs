using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;

namespace BlackbirdInterface
{
    public partial class ProcessPickerWindow : Window
    {
        private readonly List<ProcessItem> _all = new();
        private readonly ObservableCollection<ProcessItem> _view = new();
        private readonly ObservableCollection<ProcessFilterRule> _rules = new();
        private readonly Dictionary<int, (long cpu100ns, DateTime ts)> _cpuBaseline = new();
        private readonly Dictionary<string, SignatureTrustState> _signatureCache = new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, ProcessPathMetadata> _pathMetadataCache = new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, ImageSource?> _iconCache = new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<int, ProcessEnrichmentSnapshot> _processEnrichmentCache = new();
        private readonly object _cacheLock = new();
        private readonly ImageSource? _defaultProcessIcon;
        private readonly DispatcherTimer _refreshTimer;
        private CancellationTokenSource? _enrichmentCts;
        private int _refreshGeneration;
        private bool _isReady;
        private bool _initialListPrepared;
        private bool _firstRevealComplete;
        private string? _activeSortProperty;
        private ListSortDirection _activeSortDirection = ListSortDirection.Ascending;
        private Brush _rowDefaultForeground = Brushes.Black;
        private Brush _rowUnsignedBackground = Brushes.Transparent;
        private Brush _rowUnsignedBorder = Brushes.Transparent;
        private Brush _rowUnsignedForeground = Brushes.Black;
        private Brush _rowAppContainerBackground = Brushes.Transparent;
        private Brush _rowAppContainerBorder = Brushes.Transparent;
        private Brush _rowAppContainerForeground = Brushes.Black;
        private Brush _rowLowIntegrityBackground = Brushes.Transparent;
        private Brush _rowLowIntegrityBorder = Brushes.Transparent;
        private Brush _rowElevatedBackground = Brushes.Transparent;
        private Brush _rowElevatedBorder = Brushes.Transparent;
        private Brush _rowSystemBackground = Brushes.Transparent;
        private Brush _rowSystemBorder = Brushes.Transparent;
        private Brush _rowSystemForeground = Brushes.Black;
        private bool _showLaunchOptions;

        public int SelectedPid { get; private set; }
        public bool UseUsermodeHooks { get; private set; }
        public bool AutoOpenApiGraphWindow { get; private set; } = true;
        public bool UseEarlyBirdApcLaunch { get; private set; }
        public bool LaunchSelectedImage { get; private set; }
        public string LaunchImagePath { get; private set; } = string.Empty;
        public bool ShowLaunchOptions
        {
            get => _showLaunchOptions;
            set
            {
                _showLaunchOptions = value;
                UpdateLaunchOptionsUi();
            }
        }

        public ProcessPickerWindow()
        {
            InitializeComponent();
            Opacity = 0;
            WindowThemeHelper.ApplyTitleBarTheme(this, App.IsDarkTheme);
            RefreshThemePalette();
            _defaultProcessIcon = GetDefaultProcessIcon();

            ProcessGrid.ItemsSource = _view;
            RulesGrid.ItemsSource = _rules;
            UpdateRulesPanelVisibility();

            _refreshTimer = new DispatcherTimer(DispatcherPriority.Background)
            {
                Interval = TimeSpan.FromSeconds(2)
            };
            _refreshTimer.Tick += (_, __) => RefreshList();

            Loaded += async (_, __) =>
            {
                await RevealAfterFirstRenderAsync();

                await Dispatcher.InvokeAsync(() =>
                {
                    EnsureInitialListPrepared();
                    _refreshTimer.Start();
                }, DispatcherPriority.Background);
            };
            Closed += (_, __) =>
            {
                _refreshTimer.Stop();
                _enrichmentCts?.Cancel();
                _enrichmentCts?.Dispose();
                _enrichmentCts = null;
                App.ThemeChanged -= OnThemeChanged;
            };
            App.ThemeChanged += OnThemeChanged;

            _isReady = true;
            UpdateLaunchOptionsUi();
        }

        private void UpdateLaunchOptionsUi()
        {
            if (LaunchOptionsPanel == null)
            {
                return;
            }

            LaunchOptionsPanel.Visibility = Visibility.Collapsed;
        }

        private void UseUsermodeHooksCheckBox_Changed(object sender, RoutedEventArgs e)
        {
            UpdateLaunchOptionsUi();
        }

        private void Root_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
        {
            WindowChromeBehavior.HandleRootDragMove(this, e);
        }

        public void PrimeForFirstShow()
        {
            EnsureInitialListPrepared();
        }

        private void EnsureInitialListPrepared()
        {
            if (_initialListPrepared)
                return;

            RefreshList();
            _initialListPrepared = true;
        }

        private async Task RevealAfterFirstRenderAsync()
        {
            if (_firstRevealComplete)
                return;

            await Dispatcher.InvokeAsync(() => { }, DispatcherPriority.Render);
            Opacity = 1;
            Activate();
            _firstRevealComplete = true;
        }

        private void Refresh_Click(object sender, RoutedEventArgs e) => RefreshList();

        private void QuickSearchBox_TextChanged(object sender, TextChangedEventArgs e) => ApplyFilter();

        private void FilterValueBox_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key != Key.Enter)
                return;

            AddRule_Click(sender, new RoutedEventArgs());
            e.Handled = true;
        }

        private void AddRule_Click(object sender, RoutedEventArgs e)
        {
            if (!_isReady || FilterColumnBox == null || FilterRelationBox == null || FilterActionBox == null || FilterValueBox == null)
                return;

            string column = (FilterColumnBox.SelectedItem as ComboBoxItem)?.Content?.ToString() ?? "Process Name";
            string relation = (FilterRelationBox.SelectedItem as ComboBoxItem)?.Content?.ToString() ?? "is";
            string action = (FilterActionBox.SelectedItem as ComboBoxItem)?.Content?.ToString() ?? "Include";
            string value = FilterValueBox.Text?.Trim() ?? "";

            if (string.IsNullOrWhiteSpace(value))
                return;

            _rules.Add(new ProcessFilterRule
            {
                Enabled = true,
                Column = column,
                Relation = relation,
                Value = value,
                Action = action
            });

            FilterValueBox.Text = "";
            UpdateRulesPanelVisibility();
            ApplyFilter();
        }

        private void RemoveRule_Click(object sender, RoutedEventArgs e)
        {
            if (RulesGrid.SelectedItem is not ProcessFilterRule rule)
                return;

            _rules.Remove(rule);
            UpdateRulesPanelVisibility();
            ApplyFilter();
        }

        private void RulesGrid_CurrentCellChanged(object? sender, EventArgs e) => ApplyFilter();
        private void RuleEnabled_Click(object sender, RoutedEventArgs e) => ApplyFilter();

        private void MoveRuleUp_Click(object sender, RoutedEventArgs e)
        {
            MoveRule(-1);
        }

        private void MoveRuleDown_Click(object sender, RoutedEventArgs e)
        {
            MoveRule(1);
        }

        private void ResetRules_Click(object sender, RoutedEventArgs e)
        {
            _rules.Clear();
            UpdateRulesPanelVisibility();
            if (QuickSearchBox != null)
                QuickSearchBox.Text = "";
            if (FilterValueBox != null)
                FilterValueBox.Text = "";
            ApplyFilter();
        }

        private void RefreshList()
        {
            int selectedPid = (ProcessGrid.SelectedItem as ProcessItem)?.Pid ?? 0;
            int selectedIndex = ProcessGrid.SelectedIndex;
            var list = new List<ProcessItem>();
            var snapshot = QuerySystemProcessesFast();
            var presentPids = new HashSet<int>(snapshot.Select(s => s.Pid));
            var now = DateTime.UtcNow;

            foreach (var entry in snapshot)
            {
                ProcessEnrichmentSnapshot? cached = null;
                lock (_cacheLock)
                {
                    if (_processEnrichmentCache.TryGetValue(entry.Pid, out var value))
                        cached = value;
                }

                bool isChild = entry.ParentPid > 0;
                double cpuPct = TryGetCpuPercent(entry.Pid, entry.CpuTime100ns, now);
                var row = new ProcessItem
                {
                    Name = entry.Name,
                    AppName = cached?.AppName ?? entry.Name,
                    Company = cached?.Company ?? "",
                    FileName = cached?.FileName ?? "",
                    Icon = cached?.Icon ?? _defaultProcessIcon,
                    Architecture = cached?.Architecture ?? "",
                    Pid = entry.Pid,
                    ParentPid = entry.ParentPid,
                    CpuPercentValue = cpuPct,
                    CpuPercent = cpuPct.ToString("0.0", CultureInfo.InvariantCulture),
                    IntegrityLevel = cached?.IntegrityLevel ?? "",
                    IsAppContainer = cached?.IsAppContainer ?? false,
                    SandboxStatus = cached?.SandboxStatus ?? "",
                    IsSigned = cached?.IsSigned ?? false,
                    IsUnsigned = cached?.IsUnsigned ?? false,
                    SignedStatus = cached?.SignedStatus ?? "",
                    SignatureState = cached?.SignatureState ?? SignatureTrustState.Unknown,
                    IsSystemOrWindows = cached?.IsSystemOrWindows ?? false,
                    Relation = isChild ? "Child" : "Head",
                    Path = cached?.Path ?? ""
                };

                ApplyRowTheme(row);
                list.Add(row);
            }

            foreach (var stale in _cpuBaseline.Keys.Where(k => !presentPids.Contains(k)).ToList())
                _cpuBaseline.Remove(stale);

            lock (_cacheLock)
            {
                foreach (var stale in _processEnrichmentCache.Keys.Where(k => !presentPids.Contains(k)).ToList())
                    _processEnrichmentCache.Remove(stale);
            }

            var byPid = list.ToDictionary(x => x.Pid, x => x.Name);
            foreach (var item in list)
            {
                if (item.ParentPid > 0 && byPid.TryGetValue(item.ParentPid, out var parentName))
                    item.ParentName = $"{parentName} ({item.ParentPid})";
                else
                    item.ParentName = item.ParentPid > 0 ? item.ParentPid.ToString(CultureInfo.InvariantCulture) : "";
            }

            _all.Clear();
            _all.AddRange(list
                .OrderBy(x => x.IsUnsigned ? 0 : 1)
                .ThenBy(x => x.IsAppContainer ? 0 : 1)
                .ThenBy(x => x.IsSystemOrWindows ? 1 : 0)
                .ThenByDescending(x => x.CpuPercentValue)
                .ThenBy(x => x.Name, StringComparer.OrdinalIgnoreCase));

            ApplyFilter(selectedPid, selectedIndex);
            StartDeferredEnrichment(++_refreshGeneration);

            if (selectedPid > 0)
            {
                var selected = _view.FirstOrDefault(x => x.Pid == selectedPid);
                if (selected != null)
                    ProcessGrid.SelectedItem = selected;
            }
        }

        private void RefreshIntervalBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (!_isReady || RefreshIntervalBox.SelectedItem is not ComboBoxItem item)
                return;

            string label = item.Content?.ToString() ?? "2s";
            int sec = label.StartsWith("1", StringComparison.Ordinal) ? 1 :
                      label.StartsWith("5", StringComparison.Ordinal) ? 5 : 2;

            _refreshTimer.Interval = TimeSpan.FromSeconds(sec);
        }

        private void ApplyFilter(int pinnedPid = 0, int pinnedIndex = -1)
        {
            if (!_isReady || ProcessGrid == null)
                return;

            if (pinnedPid <= 0 && ProcessGrid.SelectedItem is ProcessItem selected)
            {
                pinnedPid = selected.Pid;
                pinnedIndex = ProcessGrid.SelectedIndex;
            }

            string q = QuickSearchBox?.Text?.Trim() ?? "";

            IEnumerable<ProcessItem> filtered = _all;

            if (!string.IsNullOrWhiteSpace(q))
            {
                filtered = filtered.Where(x =>
                    x.Name.Contains(q, StringComparison.OrdinalIgnoreCase) ||
                    x.AppName.Contains(q, StringComparison.OrdinalIgnoreCase) ||
                    x.Company.Contains(q, StringComparison.OrdinalIgnoreCase) ||
                    x.FileName.Contains(q, StringComparison.OrdinalIgnoreCase) ||
                    x.Architecture.Contains(q, StringComparison.OrdinalIgnoreCase) ||
                    x.Pid.ToString(CultureInfo.InvariantCulture).Contains(q, StringComparison.OrdinalIgnoreCase) ||
                    x.Path.Contains(q, StringComparison.OrdinalIgnoreCase));
            }

            if (_rules.Count > 0)
                filtered = filtered.Where(PassesRules);

            if (!string.IsNullOrWhiteSpace(_activeSortProperty))
            {
                filtered = ApplyActiveSort(filtered);
            }

            List<ProcessItem> filteredList = filtered.ToList();
            if (pinnedPid > 0 && pinnedIndex >= 0)
            {
                int selectedPos = filteredList.FindIndex(x => x.Pid == pinnedPid);
                if (selectedPos >= 0)
                {
                    ProcessItem pinned = filteredList[selectedPos];
                    filteredList.RemoveAt(selectedPos);
                    int targetIndex = Math.Min(pinnedIndex, filteredList.Count);
                    filteredList.Insert(targetIndex, pinned);
                }
            }

            _view.Clear();
            foreach (var item in filteredList)
                _view.Add(item);

            if (pinnedPid > 0)
            {
                ProcessItem? selectedAfter = _view.FirstOrDefault(x => x.Pid == pinnedPid);
                if (selectedAfter != null)
                {
                    ProcessGrid.SelectedItem = selectedAfter;
                }
            }
        }

        private IEnumerable<ProcessItem> ApplyActiveSort(IEnumerable<ProcessItem> source)
        {
            Func<ProcessItem, object?> selector = _activeSortProperty switch
            {
                nameof(ProcessItem.Name) => x => x.Name,
                nameof(ProcessItem.AppName) => x => x.AppName,
                nameof(ProcessItem.Company) => x => x.Company,
                nameof(ProcessItem.FileName) => x => x.FileName,
                nameof(ProcessItem.Architecture) => x => x.Architecture,
                nameof(ProcessItem.Pid) => x => x.Pid,
                nameof(ProcessItem.CpuPercentValue) => x => x.CpuPercentValue,
                nameof(ProcessItem.IntegrityLevel) => x => x.IntegrityLevel,
                nameof(ProcessItem.SignedStatus) => x => x.SignedStatus,
                nameof(ProcessItem.SandboxStatus) => x => x.SandboxStatus,
                nameof(ProcessItem.Relation) => x => x.Relation,
                nameof(ProcessItem.ParentName) => x => x.ParentName,
                nameof(ProcessItem.Path) => x => x.Path,
                _ => x => x.Name
            };

            return _activeSortDirection == ListSortDirection.Ascending
                ? source.OrderBy(selector).ThenBy(x => x.Name, StringComparer.OrdinalIgnoreCase)
                : source.OrderByDescending(selector).ThenBy(x => x.Name, StringComparer.OrdinalIgnoreCase);
        }

        private bool PassesRules(ProcessItem item)
        {
            var active = _rules.Where(r => r.Enabled).ToList();
            if (active.Count == 0)
                return true;

            bool hasIncludeRules = active.Any(r => r.Action.Equals("Include", StringComparison.OrdinalIgnoreCase));
            bool include = !hasIncludeRules;

            foreach (var rule in active)
            {
                if (!RuleMatches(item, rule))
                    continue;

                include = rule.Action.Equals("Include", StringComparison.OrdinalIgnoreCase);
            }

            return include;
        }

        private void MoveRule(int delta)
        {
            if (RulesGrid.SelectedItem is not ProcessFilterRule rule)
                return;

            int oldIndex = _rules.IndexOf(rule);
            if (oldIndex < 0)
                return;

            int newIndex = oldIndex + delta;
            if (newIndex < 0 || newIndex >= _rules.Count)
                return;

            _rules.Move(oldIndex, newIndex);
            RulesGrid.SelectedItem = rule;
            RulesGrid.ScrollIntoView(rule);
            ApplyFilter();
        }

        private static bool RuleMatches(ProcessItem item, ProcessFilterRule rule)
        {
            string left = GetRuleField(item, rule.Column);
            string right = rule.Value ?? "";
            string relation = rule.Relation?.Trim().ToLowerInvariant() ?? "is";

            return relation switch
            {
                "is" => string.Equals(left, right, StringComparison.OrdinalIgnoreCase),
                "contains" => left.Contains(right, StringComparison.OrdinalIgnoreCase),
                "begins with" => left.StartsWith(right, StringComparison.OrdinalIgnoreCase),
                "ends with" => left.EndsWith(right, StringComparison.OrdinalIgnoreCase),
                "greater than" => TryCompareNumeric(left, right, out var gt) && gt > 0,
                "less than" => TryCompareNumeric(left, right, out var lt) && lt < 0,
                _ => string.Equals(left, right, StringComparison.OrdinalIgnoreCase)
            };
        }

        private static string GetRuleField(ProcessItem item, string column)
        {
            return column switch
            {
                "Architecture" => item.Architecture,
                "Process Name" => item.Name,
                "App Name" => item.AppName,
                "Company" => item.Company,
                "File Name" => item.FileName,
                "PID" => item.Pid.ToString(CultureInfo.InvariantCulture),
                "CPU %" => item.CpuPercent,
                "Integrity" => item.IntegrityLevel,
                "Signed" => item.SignedStatus,
                "Sandbox" => item.SandboxStatus,
                "Relation" => item.Relation,
                "Parent" => item.ParentName,
                "Path" => item.Path,
                _ => item.Name
            };
        }

        private static bool TryCompareNumeric(string left, string right, out int compareResult)
        {
            compareResult = 0;
            if (!double.TryParse(left, NumberStyles.Float, CultureInfo.InvariantCulture, out var a))
                return false;
            if (!double.TryParse(right, NumberStyles.Float, CultureInfo.InvariantCulture, out var b))
                return false;

            compareResult = a.CompareTo(b);
            return true;
        }

        private bool HasCachedEnrichment(int pid)
        {
            lock (_cacheLock)
            {
                return _processEnrichmentCache.ContainsKey(pid);
            }
        }

        private double TryGetCpuPercent(int pid, long cpuNow100ns, DateTime now)
        {
            try
            {
                if (_cpuBaseline.TryGetValue(pid, out var prev))
                {
                    double sec = Math.Max(0.25, (now - prev.ts).TotalSeconds);
                    long delta100ns = cpuNow100ns - prev.cpu100ns;
                    if (delta100ns < 0)
                        delta100ns = 0;

                    double cpuSeconds = delta100ns / 10_000_000.0;
                    double cpuPct = cpuSeconds / sec / Math.Max(1, Environment.ProcessorCount) * 100.0;
                    if (cpuPct < 0)
                        cpuPct = 0;

                    _cpuBaseline[pid] = (cpuNow100ns, now);
                    return cpuPct;
                }

                _cpuBaseline[pid] = (cpuNow100ns, now);
            }
            catch
            {
            }

            return 0;
        }

        private bool TryBuildProcessEnrichment(int pid, string fallbackName, out ProcessEnrichmentSnapshot enrichment)
        {
            enrichment = new ProcessEnrichmentSnapshot
            {
                Path = "",
                FileName = "",
                AppName = fallbackName,
                Company = "",
                Icon = _defaultProcessIcon,
                Architecture = "",
                IntegrityLevel = "",
                IsAppContainer = false,
                SandboxStatus = "",
                IsSigned = false,
                IsUnsigned = false,
                SignedStatus = "",
                SignatureState = SignatureTrustState.Unknown,
                IsSystemOrWindows = false
            };

            string windowsDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);

            try
            {
                using var process = Process.GetProcessById(pid);

                string path = "";
                try
                {
                    path = process.MainModule?.FileName ?? "";
                }
                catch
                {
                }

                string architecture = TryGetArchitecture(process);
                string integrity = "";
                bool isAppContainer = false;
                if (TryGetIntegrityInfo(process, out var integrityLevel, out var appContainer))
                {
                    integrity = integrityLevel;
                    isAppContainer = appContainer;
                }

                bool isSystemOrWindows = process.SessionId == 0 ||
                                         fallbackName.Equals("System", StringComparison.OrdinalIgnoreCase) ||
                                         (!string.IsNullOrWhiteSpace(path) &&
                                          path.StartsWith(windowsDir, StringComparison.OrdinalIgnoreCase));

                string fileName = "";
                string appName = fallbackName;
                string company = "";
                bool isSigned = false;
                bool isUnsigned = false;
                string signedStatus = "";
                SignatureTrustState signatureState = SignatureTrustState.Unknown;
                ImageSource? icon = _defaultProcessIcon;

                if (!string.IsNullOrWhiteSpace(path))
                {
                    var meta = GetPathMetadata(path, fallbackName);
                    fileName = meta.FileName;
                    appName = meta.AppName;
                    company = meta.Company;
                    signatureState = meta.SignatureState;
                    isSigned = signatureState == SignatureTrustState.Trusted;
                    isUnsigned = signatureState == SignatureTrustState.Unsigned ||
                                 signatureState == SignatureTrustState.Invalid ||
                                 signatureState == SignatureTrustState.Expired;
                    signedStatus = signatureState switch
                    {
                        SignatureTrustState.Trusted => "Yes",
                        SignatureTrustState.Unsigned => "Unsigned",
                        SignatureTrustState.Invalid => "Invalid",
                        SignatureTrustState.Expired => "Expired",
                        _ => ""
                    };
                    icon = GetProcessIcon(path);
                }

                enrichment = new ProcessEnrichmentSnapshot
                {
                    Path = path,
                    FileName = fileName,
                    AppName = appName,
                    Company = company,
                    Icon = icon ?? _defaultProcessIcon,
                    Architecture = architecture,
                    IntegrityLevel = integrity,
                    IsAppContainer = isAppContainer,
                    SandboxStatus = isAppContainer ? "AppContainer" : "",
                    IsSigned = isSigned,
                    IsUnsigned = isUnsigned,
                    SignedStatus = signedStatus,
                    SignatureState = signatureState,
                    IsSystemOrWindows = isSystemOrWindows
                };

                return true;
            }
            catch
            {
                return false;
            }
        }

        private static List<SystemProcessSnapshot> QuerySystemProcessesFast()
        {
            const int systemProcessInformation = 5;
            const int statusInfoLengthMismatch = unchecked((int)0xC0000004);

            int length = 1 << 20;
            IntPtr buffer = IntPtr.Zero;

            try
            {
                while (true)
                {
                    buffer = Marshal.AllocHGlobal(length);
                    int status = NtQuerySystemInformation(systemProcessInformation, buffer, length, out int returnLength);
                    if (status == statusInfoLengthMismatch)
                    {
                        Marshal.FreeHGlobal(buffer);
                        buffer = IntPtr.Zero;
                        length = Math.Max(length * 2, returnLength + 65536);
                        continue;
                    }

                    if (status < 0)
                        return new List<SystemProcessSnapshot>();

                    var list = new List<SystemProcessSnapshot>(512);
                    var seenPids = new HashSet<int>();
                    IntPtr current = buffer;

                    while (true)
                    {
                        var spi = Marshal.PtrToStructure<SYSTEM_PROCESS_INFORMATION>(current);
                        long pid64 = spi.UniqueProcessId.ToInt64();
                        long parent64 = spi.InheritedFromUniqueProcessId.ToInt64();

                        if (pid64 > 0 && pid64 <= int.MaxValue)
                        {
                            int pid = (int)pid64;
                            if (!seenPids.Add(pid))
                            {
                                if (spi.NextEntryOffset == 0)
                                    break;

                                current = IntPtr.Add(current, (int)spi.NextEntryOffset);
                                continue;
                            }

                            string name = "";
                            if (spi.ImageName.Buffer != IntPtr.Zero && spi.ImageName.Length > 0)
                            {
                                name = Marshal.PtrToStringUni(spi.ImageName.Buffer, spi.ImageName.Length / 2) ?? "";
                            }

                            if (string.IsNullOrWhiteSpace(name))
                            {
                                name = pid64 == 4 ? "System" : $"pid-{pid64}";
                            }

                            int parentPid = (parent64 > 0 && parent64 <= int.MaxValue) ? (int)parent64 : 0;
                            long cpu100ns = spi.UserTime + spi.KernelTime;
                            if (cpu100ns < 0)
                                cpu100ns = 0;

                            list.Add(new SystemProcessSnapshot(pid, parentPid, name, cpu100ns));
                        }

                        if (spi.NextEntryOffset == 0)
                            break;

                        current = IntPtr.Add(current, (int)spi.NextEntryOffset);
                    }

                    return list;
                }
            }
            finally
            {
                if (buffer != IntPtr.Zero)
                    Marshal.FreeHGlobal(buffer);
            }
        }

        private void UpdateRulesPanelVisibility()
        {
            bool hasRules = _rules.Count > 0;

            RuleActionsBar.Visibility = hasRules ? Visibility.Visible : Visibility.Collapsed;
            RulesGrid.Visibility = hasRules ? Visibility.Visible : Visibility.Collapsed;
            RulesRow.Height = hasRules ? new GridLength(146) : new GridLength(0);
            RulesSpacerRow.Height = hasRules ? new GridLength(8) : new GridLength(0);
        }

        private void StartDeferredEnrichment(int generation)
        {
            _enrichmentCts?.Cancel();
            _enrichmentCts?.Dispose();
            _enrichmentCts = new CancellationTokenSource();
            var token = _enrichmentCts.Token;

            var targets = _all.Where(x => !HasCachedEnrichment(x.Pid)).ToList();
            if (targets.Count == 0)
                return;

            _ = Task.Run(async () =>
            {
                int updates = 0;

                foreach (var target in targets)
                {
                    if (token.IsCancellationRequested || generation != _refreshGeneration)
                        break;

                    if (!TryBuildProcessEnrichment(target.Pid, target.Name, out var enrichment))
                        continue;

                    lock (_cacheLock)
                    {
                        _processEnrichmentCache[target.Pid] = enrichment;
                    }

                    await Dispatcher.InvokeAsync(() =>
                    {
                        if (token.IsCancellationRequested || generation != _refreshGeneration)
                            return;

                        ProcessItem? current = _all.FirstOrDefault(x =>
                            x.Pid == target.Pid &&
                            string.Equals(x.Path, target.Path, StringComparison.OrdinalIgnoreCase));

                        if (current == null)
                            return;

                        current.FileName = enrichment.FileName;
                        current.AppName = enrichment.AppName;
                        current.Company = enrichment.Company;
                        current.Icon = enrichment.Icon ?? _defaultProcessIcon;
                        current.IsSigned = enrichment.IsSigned;
                        current.IsUnsigned = enrichment.IsUnsigned;
                        current.SignedStatus = enrichment.SignedStatus;
                        current.SignatureState = enrichment.SignatureState;
                        current.Architecture = enrichment.Architecture;
                        current.IntegrityLevel = enrichment.IntegrityLevel;
                        current.IsAppContainer = enrichment.IsAppContainer;
                        current.SandboxStatus = enrichment.SandboxStatus;
                        current.IsSystemOrWindows = enrichment.IsSystemOrWindows;
                        current.Path = enrichment.Path;
                        ApplyRowTheme(current);

                        updates++;
                        if ((updates % 8) == 0)
                        {
                            ResortAllForDisplay();
                            ProcessGrid.Items.Refresh();
                            RulesGrid.Items.Refresh();
                        }
                    }, DispatcherPriority.Background);
                }

                await Dispatcher.InvokeAsync(() =>
                {
                    if (generation != _refreshGeneration)
                        return;

                    ResortAllForDisplay();
                    ProcessGrid.Items.Refresh();
                    RulesGrid.Items.Refresh();
                }, DispatcherPriority.Background);
            }, token);
        }

        private void ResortAllForDisplay()
        {
            var sorted = _all
                .OrderBy(x => x.IsUnsigned ? 0 : 1)
                .ThenBy(x => x.IsAppContainer ? 0 : 1)
                .ThenBy(x => x.IsSystemOrWindows ? 1 : 0)
                .ThenByDescending(x => x.CpuPercentValue)
                .ThenBy(x => x.Name, StringComparer.OrdinalIgnoreCase)
                .ToList();

            _all.Clear();
            _all.AddRange(sorted);
            ApplyFilter();
        }

        private void ApplyRowTheme(ProcessItem item)
        {
            item.RowForeground = _rowDefaultForeground;

            if (item.IsUnsigned)
            {
                double severity = item.SignatureState switch
                {
                    SignatureTrustState.Unsigned => 1.00,
                    SignatureTrustState.Invalid => 0.82,
                    SignatureTrustState.Expired => 0.60,
                    _ => 0.45
                };

                double cpuBoost = Math.Clamp(item.CpuPercentValue / 45.0, 0.0, 1.0);
                double intensity = Math.Clamp(severity + (cpuBoost * 0.55), 0.20, 1.45);

                item.RowBackground = BuildIntensityBrush(_rowUnsignedBackground, intensity, 0.28);
                item.RowBorderBrush = BuildIntensityBrush(_rowUnsignedBorder, intensity, 0.20);
                item.RowForeground = _rowUnsignedForeground;
                return;
            }

            if (item.IsAppContainer)
            {
                item.RowBackground = _rowAppContainerBackground;
                item.RowBorderBrush = _rowAppContainerBorder;
                item.RowForeground = _rowAppContainerForeground;
                return;
            }

            if (item.IntegrityLevel.Equals("Low", StringComparison.OrdinalIgnoreCase))
            {
                item.RowBackground = _rowLowIntegrityBackground;
                item.RowBorderBrush = _rowLowIntegrityBorder;
                return;
            }

            if (item.IntegrityLevel.Equals("High", StringComparison.OrdinalIgnoreCase) ||
                item.IntegrityLevel.Equals("System", StringComparison.OrdinalIgnoreCase))
            {
                item.RowBackground = _rowElevatedBackground;
                item.RowBorderBrush = _rowElevatedBorder;
                return;
            }

            if (item.IsSystemOrWindows)
            {
                item.RowBackground = _rowSystemBackground;
                item.RowBorderBrush = _rowSystemBorder;
                item.RowForeground = _rowSystemForeground;
                return;
            }

            item.RowBackground = Brushes.Transparent;
            item.RowBorderBrush = Brushes.Transparent;
            item.RowForeground = _rowDefaultForeground;
        }

        private static Brush BuildIntensityBrush(Brush templateBrush, double intensity, double brightenCap)
        {
            if (templateBrush is not SolidColorBrush solid)
                return templateBrush;

            Color source = solid.Color;
            double alpha = Math.Clamp((source.A / 255.0) * intensity, 0.0, 1.0);
            double brighten = Math.Clamp((intensity - 1.0) * brightenCap, 0.0, brightenCap);

            byte r = (byte)Math.Clamp(Math.Round(source.R + ((255 - source.R) * brighten)), 0, 255);
            byte g = (byte)Math.Clamp(Math.Round(source.G + ((255 - source.G) * brighten)), 0, 255);
            byte b = (byte)Math.Clamp(Math.Round(source.B + ((255 - source.B) * brighten)), 0, 255);
            byte a = (byte)Math.Clamp(Math.Round(alpha * 255.0), 0, 255);

            var result = new SolidColorBrush(Color.FromArgb(a, r, g, b));
            result.Freeze();
            return result;
        }

        private void OnThemeChanged(bool _)
        {
            Dispatcher.BeginInvoke(new Action(() =>
            {
                WindowThemeHelper.ApplyTitleBarTheme(this, App.IsDarkTheme);
                RefreshThemePalette();
                ReapplyRowThemes();
            }), DispatcherPriority.Background);
        }

        private void RefreshThemePalette()
        {
            _rowDefaultForeground = ResolveBrush("ProcessRowDefaultForegroundBrush", Color.FromRgb(0xD8, 0xD8, 0xD8));
            _rowUnsignedBackground = ResolveBrush("ProcessRowUnsignedBackgroundBrush", Color.FromArgb(0x33, 0x50, 0x1F, 0x1F));
            _rowUnsignedBorder = ResolveBrush("ProcessRowUnsignedBorderBrush", Color.FromArgb(0xAA, 0xE3, 0x6B, 0x6B));
            _rowUnsignedForeground = ResolveBrush("ProcessRowUnsignedForegroundBrush", Color.FromRgb(0xF4, 0xD7, 0xD7));
            _rowAppContainerBackground = ResolveBrush("ProcessRowAppContainerBackgroundBrush", Color.FromArgb(0x33, 0x3A, 0x2A, 0x58));
            _rowAppContainerBorder = ResolveBrush("ProcessRowAppContainerBorderBrush", Color.FromArgb(0x99, 0xB0, 0x7A, 0xE8));
            _rowAppContainerForeground = ResolveBrush("ProcessRowAppContainerForegroundBrush", Colors.WhiteSmoke);
            _rowLowIntegrityBackground = ResolveBrush("ProcessRowLowIntegrityBackgroundBrush", Color.FromArgb(0x2D, 0x4C, 0x41, 0x1D));
            _rowLowIntegrityBorder = ResolveBrush("ProcessRowLowIntegrityBorderBrush", Color.FromArgb(0x88, 0xD1, 0xB0, 0x5C));
            _rowElevatedBackground = ResolveBrush("ProcessRowElevatedBackgroundBrush", Color.FromArgb(0x24, 0x2D, 0x3C, 0x52));
            _rowElevatedBorder = ResolveBrush("ProcessRowElevatedBorderBrush", Color.FromArgb(0x70, 0x8A, 0xA8, 0xC7));
            _rowSystemBackground = ResolveBrush("ProcessRowSystemBackgroundBrush", Color.FromArgb(0x22, 0x23, 0x23, 0x23));
            _rowSystemBorder = ResolveBrush("ProcessRowSystemBorderBrush", Color.FromArgb(0x55, 0x5A, 0x5A, 0x5A));
            _rowSystemForeground = ResolveBrush("ProcessRowSystemForegroundBrush", Color.FromRgb(0xB8, 0xB8, 0xB8));
        }

        private void ReapplyRowThemes()
        {
            foreach (var item in _all)
            {
                ApplyRowTheme(item);
            }

            ProcessGrid.Items.Refresh();
        }

        private static Brush ResolveBrush(string key, Color fallback)
        {
            if (Application.Current?.TryFindResource(key) is Brush brush)
            {
                return brush;
            }

            var solid = new SolidColorBrush(fallback);
            solid.Freeze();
            return solid;
        }

        private SignatureTrustState ClassifySignature(string path)
        {
            if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
                return SignatureTrustState.Unknown;

            lock (_cacheLock)
            {
                if (_signatureCache.TryGetValue(path, out var stateCached))
                    return stateCached;
            }

            SignatureTrustState state;

            try
            {
#pragma warning disable SYSLIB0057
                using var certificate = new X509Certificate2(X509Certificate.CreateFromSignedFile(path));
#pragma warning restore SYSLIB0057

                DateTime utcNow = DateTime.UtcNow;
                bool timeValid = utcNow >= certificate.NotBefore.ToUniversalTime() &&
                                 utcNow <= certificate.NotAfter.ToUniversalTime();

                using var chain = new X509Chain();
                chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
                chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
                chain.ChainPolicy.VerificationTime = utcNow;

                bool chainValid = chain.Build(certificate) &&
                                  chain.ChainStatus.All(x => x.Status == X509ChainStatusFlags.NoError);

                if (!timeValid)
                    state = SignatureTrustState.Expired;
                else if (!chainValid)
                    state = SignatureTrustState.Invalid;
                else
                    state = SignatureTrustState.Trusted;
            }
            catch
            {
                state = SignatureTrustState.Unsigned;
            }

            lock (_cacheLock)
            {
                _signatureCache[path] = state;
            }

            return state;
        }

        private ProcessPathMetadata GetPathMetadata(string path, string fallbackProcessName)
        {
            lock (_cacheLock)
            {
                if (_pathMetadataCache.TryGetValue(path, out var cached))
                    return cached;
            }

            var result = new ProcessPathMetadata
            {
                FileName = System.IO.Path.GetFileName(path),
                AppName = fallbackProcessName,
                Company = "",
                SignatureState = ClassifySignature(path)
            };

            try
            {
                var ver = FileVersionInfo.GetVersionInfo(path);
                if (!string.IsNullOrWhiteSpace(ver.ProductName))
                    result.AppName = ver.ProductName;
                result.Company = ver.CompanyName ?? "";
            }
            catch
            {
            }

            lock (_cacheLock)
            {
                _pathMetadataCache[path] = result;
            }
            return result;
        }

        private ImageSource? GetProcessIcon(string path)
        {
            if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
            {
                return _defaultProcessIcon;
            }

            lock (_cacheLock)
            {
                if (_iconCache.TryGetValue(path, out ImageSource? cached))
                    return cached;
            }

            try
            {
                uint cbFileInfo = (uint)Marshal.SizeOf<SHFILEINFO>();
                const uint flags = SHGFI_ICON | SHGFI_SMALLICON;
                IntPtr result = SHGetFileInfo(path, 0, out SHFILEINFO info, cbFileInfo, flags);
                if (result == IntPtr.Zero || info.hIcon == IntPtr.Zero)
                {
                    lock (_cacheLock)
                    {
                        _iconCache[path] = _defaultProcessIcon;
                    }
                    return _defaultProcessIcon;
                }

                try
                {
                    BitmapSource bitmap = Imaging.CreateBitmapSourceFromHIcon(
                        info.hIcon,
                        Int32Rect.Empty,
                        BitmapSizeOptions.FromWidthAndHeight(16, 16));
                    bitmap.Freeze();
                    lock (_cacheLock)
                    {
                        _iconCache[path] = bitmap;
                    }
                    return bitmap;
                }
                finally
                {
                    DestroyIcon(info.hIcon);
                }
            }
            catch
            {
                lock (_cacheLock)
                {
                    _iconCache[path] = _defaultProcessIcon;
                }
                return _defaultProcessIcon;
            }
        }

        private ImageSource? GetDefaultProcessIcon()
        {
            try
            {
                uint cbFileInfo = (uint)Marshal.SizeOf<SHFILEINFO>();
                const uint flags = SHGFI_ICON | SHGFI_SMALLICON | SHGFI_USEFILEATTRIBUTES;
                IntPtr result = SHGetFileInfo("dummy.exe", FILE_ATTRIBUTE_NORMAL, out SHFILEINFO info, cbFileInfo, flags);
                if (result == IntPtr.Zero || info.hIcon == IntPtr.Zero)
                {
                    return null;
                }

                try
                {
                    BitmapSource bitmap = Imaging.CreateBitmapSourceFromHIcon(
                        info.hIcon,
                        Int32Rect.Empty,
                        BitmapSizeOptions.FromWidthAndHeight(16, 16));
                    bitmap.Freeze();
                    return bitmap;
                }
                finally
                {
                    DestroyIcon(info.hIcon);
                }
            }
            catch
            {
                return null;
            }
        }

        private static string TryGetArchitecture(Process process)
        {
            try
            {
                if (!Environment.Is64BitOperatingSystem)
                    return "x86";

                if (IsWow64Process2(process.Handle, out ushort processMachine, out ushort nativeMachine))
                {
                    if (processMachine == IMAGE_FILE_MACHINE_UNKNOWN)
                        return MachineToArch(nativeMachine);
                    return MachineToArch(processMachine);
                }
            }
            catch
            {
            }

            try
            {
                if (IsWow64Process(process.Handle, out bool isWow64))
                    return isWow64 ? "x86" : "x64";
            }
            catch
            {
            }

            return "";
        }

        private static string MachineToArch(ushort machine)
        {
            return machine switch
            {
                IMAGE_FILE_MACHINE_I386 => "x86",
                IMAGE_FILE_MACHINE_AMD64 => "x64",
                IMAGE_FILE_MACHINE_ARM64 => "arm64",
                IMAGE_FILE_MACHINE_ARM => "arm",
                _ => ""
            };
        }

        private static Dictionary<int, int> BuildParentPidMap()
        {
            var map = new Dictionary<int, int>();
            IntPtr snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (snap == INVALID_HANDLE_VALUE)
                return map;

            try
            {
                var pe = new PROCESSENTRY32();
                pe.dwSize = (uint)Marshal.SizeOf<PROCESSENTRY32>();

                if (!Process32First(snap, ref pe))
                    return map;

                do
                {
                    map[(int)pe.th32ProcessID] = (int)pe.th32ParentProcessID;
                }
                while (Process32Next(snap, ref pe));
            }
            finally
            {
                _ = Kernel32Native.CloseHandle(snap);
            }

            return map;
        }

        private static bool TryGetIntegrityInfo(Process p, out string integrity, out bool isAppContainer)
        {
            integrity = "Unknown";
            isAppContainer = false;

            IntPtr token = IntPtr.Zero;
            try
            {
                if (!OpenProcessToken(p.Handle, TOKEN_QUERY, out token))
                    return false;

                if (!TryGetIntegrityLevel(token, out integrity))
                    integrity = "Unknown";

                _ = TryGetTokenIsAppContainer(token, out isAppContainer);
                return true;
            }
            catch
            {
                return false;
            }
            finally
            {
                if (token != IntPtr.Zero)
                    _ = Kernel32Native.CloseHandle(token);
            }
        }

        private static bool TryGetIntegrityLevel(IntPtr token, out string integrity)
        {
            integrity = "Unknown";

            if (!GetTokenInformation(token, TOKEN_INFORMATION_CLASS.TokenIntegrityLevel, IntPtr.Zero, 0, out int cb))
            {
                if (Marshal.GetLastWin32Error() != ERROR_INSUFFICIENT_BUFFER)
                    return false;
            }

            IntPtr pTIL = Marshal.AllocHGlobal(cb);
            try
            {
                if (!GetTokenInformation(token, TOKEN_INFORMATION_CLASS.TokenIntegrityLevel, pTIL, cb, out _))
                    return false;

                var til = Marshal.PtrToStructure<TOKEN_MANDATORY_LABEL>(pTIL);
                IntPtr pSid = til.Label.Sid;
                int subAuthCount = Marshal.ReadByte(GetSidSubAuthorityCount(pSid));
                int rid = Marshal.ReadInt32(GetSidSubAuthority(pSid, subAuthCount - 1));

                integrity = rid switch
                {
                    >= SECURITY_MANDATORY_PROTECTED_PROCESS_RID => "Protected",
                    >= SECURITY_MANDATORY_SYSTEM_RID => "System",
                    >= SECURITY_MANDATORY_HIGH_RID => "High",
                    >= SECURITY_MANDATORY_MEDIUM_RID => "Medium",
                    >= SECURITY_MANDATORY_LOW_RID => "Low",
                    _ => "Untrusted"
                };
                return true;
            }
            finally
            {
                Marshal.FreeHGlobal(pTIL);
            }
        }

        private static bool TryGetTokenIsAppContainer(IntPtr token, out bool isAppContainer)
        {
            isAppContainer = false;
            int size = sizeof(int);
            IntPtr p = Marshal.AllocHGlobal(size);
            try
            {
                if (!GetTokenInformation(token, TOKEN_INFORMATION_CLASS.TokenIsAppContainer, p, size, out _))
                    return false;
                isAppContainer = Marshal.ReadInt32(p) != 0;
                return true;
            }
            finally
            {
                Marshal.FreeHGlobal(p);
            }
        }

        private void Select_Click(object sender, RoutedEventArgs e)
        {
            if (ProcessGrid.SelectedItem is not ProcessItem item)
                return;

            LaunchSelectedImage = false;
            LaunchImagePath = string.Empty;
            SelectedPid = item.Pid;
            UseUsermodeHooks = UseUsermodeHooksCheckBox?.IsChecked == true;
            AutoOpenApiGraphWindow = AutoOpenApiGraphCheckBox?.IsChecked != false;
            UseEarlyBirdApcLaunch = UseUsermodeHooks && (EarlyBirdApcCheckBox?.IsChecked == true);
            DialogResult = true;
            Close();
        }

        private void ProcessGrid_MouseDoubleClick(object sender, MouseButtonEventArgs e)
        {
            Select_Click(sender, e);
        }

        private void ProcessGrid_Sorting(object sender, DataGridSortingEventArgs e)
        {
            e.Handled = true;

            string property = e.Column.SortMemberPath;
            if (string.IsNullOrWhiteSpace(property) && e.Column is DataGridBoundColumn bc && bc.Binding is System.Windows.Data.Binding b)
            {
                property = b.Path?.Path ?? "";
            }

            if (string.IsNullOrWhiteSpace(property))
                return;

            if (string.Equals(_activeSortProperty, property, StringComparison.Ordinal))
            {
                _activeSortDirection = _activeSortDirection == ListSortDirection.Ascending
                    ? ListSortDirection.Descending
                    : ListSortDirection.Ascending;
            }
            else
            {
                _activeSortProperty = property;
                _activeSortDirection = ListSortDirection.Ascending;
            }

            foreach (var column in ProcessGrid.Columns)
            {
                column.SortDirection = null;
            }

            e.Column.SortDirection = _activeSortDirection;

            ApplyFilter();
        }

        private void OpenExe_Click(object sender, RoutedEventArgs e)
        {
            var dlg = new OpenFileDialog
            {
                Filter = "Executable (*.exe)|*.exe",
                CheckFileExists = true,
                Multiselect = false
            };

            if (dlg.ShowDialog(this) != true)
                return;

            if (ShowLaunchOptions)
            {
                LaunchSelectedImage = true;
                LaunchImagePath = dlg.FileName;
                SelectedPid = 0;
                UseUsermodeHooks = UseUsermodeHooksCheckBox?.IsChecked == true;
                AutoOpenApiGraphWindow = AutoOpenApiGraphCheckBox?.IsChecked != false;
                UseEarlyBirdApcLaunch = UseUsermodeHooks && (EarlyBirdApcCheckBox?.IsChecked == true);
                DialogResult = true;
                Close();
                return;
            }

            try
            {
                var started = Process.Start(new ProcessStartInfo(dlg.FileName) { UseShellExecute = true });
                if (started == null)
                {
                    return;
                }

                LaunchSelectedImage = false;
                LaunchImagePath = string.Empty;
                SelectedPid = started.Id;
                UseUsermodeHooks = false;
                AutoOpenApiGraphWindow = false;
                UseEarlyBirdApcLaunch = false;
                DialogResult = true;
                Close();
            }
            catch (Exception ex)
            {
                ThemedMessageBox.Show(this, ex.Message, "Launch failed", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void Cancel_Click(object sender, RoutedEventArgs e)
        {
            DialogResult = false;
            Close();
        }

        private static readonly IntPtr INVALID_HANDLE_VALUE = new(-1);

        private const uint TH32CS_SNAPPROCESS = 0x00000002;
        private const uint TOKEN_QUERY = 0x0008;
        private const int ERROR_INSUFFICIENT_BUFFER = 122;
        private const ushort IMAGE_FILE_MACHINE_UNKNOWN = 0x0000;
        private const ushort IMAGE_FILE_MACHINE_I386 = 0x014c;
        private const ushort IMAGE_FILE_MACHINE_AMD64 = 0x8664;
        private const ushort IMAGE_FILE_MACHINE_ARM = 0x01c0;
        private const ushort IMAGE_FILE_MACHINE_ARM64 = 0xAA64;

        private const int SECURITY_MANDATORY_LOW_RID = 0x1000;
        private const int SECURITY_MANDATORY_MEDIUM_RID = 0x2000;
        private const int SECURITY_MANDATORY_HIGH_RID = 0x3000;
        private const int SECURITY_MANDATORY_SYSTEM_RID = 0x4000;
        private const int SECURITY_MANDATORY_PROTECTED_PROCESS_RID = 0x5000;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct PROCESSENTRY32
        {
            public uint dwSize;
            public uint cntUsage;
            public uint th32ProcessID;
            public IntPtr th32DefaultHeapID;
            public uint th32ModuleID;
            public uint cntThreads;
            public uint th32ParentProcessID;
            public int pcPriClassBase;
            public uint dwFlags;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string szExeFile;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SID_AND_ATTRIBUTES
        {
            public IntPtr Sid;
            public int Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct TOKEN_MANDATORY_LABEL
        {
            public SID_AND_ATTRIBUTES Label;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct UNICODE_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SYSTEM_PROCESS_INFORMATION
        {
            public uint NextEntryOffset;
            public uint NumberOfThreads;
            public long WorkingSetPrivateSize;
            public uint HardFaultCount;
            public uint NumberOfThreadsHighWatermark;
            public ulong CycleTime;
            public long CreateTime;
            public long UserTime;
            public long KernelTime;
            public UNICODE_STRING ImageName;
            public int BasePriority;
            public IntPtr UniqueProcessId;
            public IntPtr InheritedFromUniqueProcessId;
        }

        private enum TOKEN_INFORMATION_CLASS
        {
            TokenUser = 1,
            TokenGroups,
            TokenPrivileges,
            TokenOwner,
            TokenPrimaryGroup,
            TokenDefaultDacl,
            TokenSource,
            TokenType,
            TokenImpersonationLevel,
            TokenStatistics,
            TokenRestrictedSids,
            TokenSessionId,
            TokenGroupsAndPrivileges,
            TokenSessionReference,
            TokenSandBoxInert,
            TokenAuditPolicy,
            TokenOrigin,
            TokenElevationType,
            TokenLinkedToken,
            TokenElevation,
            TokenHasRestrictions,
            TokenAccessInformation,
            TokenVirtualizationAllowed,
            TokenVirtualizationEnabled,
            TokenIntegrityLevel,
            TokenUIAccess,
            TokenMandatoryPolicy,
            TokenLogonSid,
            TokenIsAppContainer = 29
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool Process32First(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool Process32Next(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool GetTokenInformation(
            IntPtr TokenHandle,
            TOKEN_INFORMATION_CLASS TokenInformationClass,
            IntPtr TokenInformation,
            int TokenInformationLength,
            out int ReturnLength);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern IntPtr GetSidSubAuthority(IntPtr pSid, int nSubAuthority);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern IntPtr GetSidSubAuthorityCount(IntPtr pSid);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool IsWow64Process(IntPtr hProcess, out bool wow64Process);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool IsWow64Process2(IntPtr hProcess, out ushort processMachine, out ushort nativeMachine);

        [DllImport("ntdll.dll")]
        private static extern int NtQuerySystemInformation(
            int systemInformationClass,
            IntPtr systemInformation,
            int systemInformationLength,
            out int returnLength);

        private const uint SHGFI_ICON = 0x000000100;
        private const uint SHGFI_SMALLICON = 0x000000001;
        private const uint SHGFI_USEFILEATTRIBUTES = 0x000000010;
        private const uint FILE_ATTRIBUTE_NORMAL = 0x00000080;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct SHFILEINFO
        {
            public IntPtr hIcon;
            public IntPtr iIcon;
            public uint dwAttributes;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string szDisplayName;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 80)]
            public string szTypeName;
        }

        [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
        private static extern IntPtr SHGetFileInfo(
            string pszPath,
            uint dwFileAttributes,
            out SHFILEINFO psfi,
            uint cbFileInfo,
            uint uFlags);

        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool DestroyIcon(IntPtr hIcon);
    }

    public sealed class ProcessFilterRule
    {
        public bool Enabled { get; set; } = true;
        public string Column { get; set; } = "";
        public string Relation { get; set; } = "is";
        public string Value { get; set; } = "";
        public string Action { get; set; } = "Include";
    }

    internal sealed class ProcessPathMetadata
    {
        public string FileName { get; init; } = "";
        public string AppName { get; set; } = "";
        public string Company { get; set; } = "";
        public SignatureTrustState SignatureState { get; init; } = SignatureTrustState.Unknown;
    }

    internal readonly record struct SystemProcessSnapshot(int Pid, int ParentPid, string Name, long CpuTime100ns);

    internal sealed class ProcessEnrichmentSnapshot
    {
        public string Path { get; init; } = "";
        public string FileName { get; init; } = "";
        public string AppName { get; init; } = "";
        public string Company { get; init; } = "";
        public ImageSource? Icon { get; init; }
        public string Architecture { get; init; } = "";
        public string IntegrityLevel { get; init; } = "";
        public bool IsAppContainer { get; init; }
        public string SandboxStatus { get; init; } = "";
        public bool IsSigned { get; init; }
        public bool IsUnsigned { get; init; }
        public string SignedStatus { get; init; } = "";
        public SignatureTrustState SignatureState { get; init; } = SignatureTrustState.Unknown;
        public bool IsSystemOrWindows { get; init; }
    }

    public sealed class ProcessItem
    {
        public string Name { get; init; } = "";
        public string AppName { get; set; } = "";
        public string Company { get; set; } = "";
        public string FileName { get; set; } = "";
        public ImageSource? Icon { get; set; }
        public string Architecture { get; set; } = "";
        public int Pid { get; init; }
        public int ParentPid { get; init; }
        public string ParentName { get; set; } = "";
        public string CpuPercent { get; init; } = "0.0";
        public double CpuPercentValue { get; init; }
        public string IntegrityLevel { get; set; } = "";
        public bool IsAppContainer { get; set; }
        public string SandboxStatus { get; set; } = "";
        public bool IsSigned { get; set; }
        public bool IsUnsigned { get; set; }
        public string SignedStatus { get; set; } = "";
        public SignatureTrustState SignatureState { get; set; } = SignatureTrustState.Unknown;
        public bool IsSystemOrWindows { get; set; }
        public string Relation { get; init; } = "Head";
        public string Path { get; set; } = "";

        public Brush RowBackground { get; set; } = Brushes.Transparent;
        public Brush RowBorderBrush { get; set; } = Brushes.Transparent;
        public Brush RowForeground { get; set; } = Brushes.Black;
    }

    public enum SignatureTrustState
    {
        Unknown = 0,
        Trusted = 1,
        Expired = 2,
        Invalid = 3,
        Unsigned = 4
    }
}
