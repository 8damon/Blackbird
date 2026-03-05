using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Media;

namespace SleepwalkerInterface
{
    internal enum IntelDetailsCategory
    {
        Etw,
        Heuristics,
        ProcessRelations
    }

    public partial class GroupedEventDetailsWindow : Window
    {
        private const string AllEventsLabel = "All Events";
        private const string AllSeveritiesLabel = "All Severities";
        private const string AllDetectionsLabel = "All Detections";
        private const string AllSourcesLabel = "All Sources";
        private const string AllActorsLabel = "All Actors";
        private const string AllTargetsLabel = "All Targets";
        private const string AllTimeLabel = "All Time";
        private const string AllSyscallsLabel = "All Syscalls";

        private static GroupedEventDetailsWindow? _sharedWindow;
        private static readonly Brush StatusRunningBackground = new SolidColorBrush(Color.FromRgb(0x14, 0x3A, 0x1E));
        private static readonly Brush StatusRunningBorder = new SolidColorBrush(Color.FromRgb(0x49, 0xC1, 0x66));
        private static readonly Brush StatusRunningForeground = new SolidColorBrush(Color.FromRgb(0xA9, 0xF5, 0xB8));
        private static readonly Brush StatusWaitingBackground = new SolidColorBrush(Color.FromRgb(0x3D, 0x34, 0x16));
        private static readonly Brush StatusWaitingBorder = new SolidColorBrush(Color.FromRgb(0xDE, 0xC2, 0x62));
        private static readonly Brush StatusWaitingForeground = new SolidColorBrush(Color.FromRgb(0xF8, 0xE9, 0xAF));
        private static readonly Brush StatusExitedBackground = new SolidColorBrush(Color.FromRgb(0x3D, 0x16, 0x16));
        private static readonly Brush StatusExitedBorder = new SolidColorBrush(Color.FromRgb(0xE0, 0x5E, 0x5E));
        private static readonly Brush StatusExitedForeground = new SolidColorBrush(Color.FromRgb(0xF4, 0xC0, 0xC0));
        private static readonly Brush StatusUnknownBackground = new SolidColorBrush(Color.FromRgb(0x1E, 0x1E, 0x1E));
        private static readonly Brush StatusUnknownBorder = new SolidColorBrush(Color.FromRgb(0x4A, 0x4A, 0x4A));
        private static readonly Brush StatusUnknownForeground = new SolidColorBrush(Color.FromRgb(0xB8, 0xB8, 0xB8));
        private static readonly Brush AccessPresentForeground = new SolidColorBrush(Color.FromRgb(0x7B, 0xD6, 0x8E));
        private static readonly Brush AccessAbsentForeground = new SolidColorBrush(Color.FromRgb(0x6F, 0x6F, 0x6F));
        private static readonly Brush AccessLabelForeground = new SolidColorBrush(Color.FromRgb(0xA6, 0xA6, 0xA6));

        private static readonly (string Name, uint Mask, bool FullMask)[] ProcessAccessMatrix =
        {
            ("PROCESS_TERMINATE", 0x00000001u, false),
            ("PROCESS_CREATE_THREAD", 0x00000002u, false),
            ("PROCESS_SET_SESSIONID", 0x00000004u, false),
            ("PROCESS_VM_OPERATION", 0x00000008u, false),
            ("PROCESS_VM_READ", 0x00000010u, false),
            ("PROCESS_VM_WRITE", 0x00000020u, false),
            ("PROCESS_DUP_HANDLE", 0x00000040u, false),
            ("PROCESS_CREATE_PROCESS", 0x00000080u, false),
            ("PROCESS_SET_QUOTA", 0x00000100u, false),
            ("PROCESS_SET_INFORMATION", 0x00000200u, false),
            ("PROCESS_QUERY_INFORMATION", 0x00000400u, false),
            ("PROCESS_SUSPEND_RESUME", 0x00000800u, false),
            ("PROCESS_QUERY_LIMITED_INFORMATION", 0x00001000u, false),
            ("SYNCHRONIZE", 0x00100000u, false),
            ("PROCESS_ALL_ACCESS", 0x001F0FFFu, true)
        };

        private static readonly (string Name, uint Mask, bool FullMask)[] ThreadAccessMatrix =
        {
            ("THREAD_TERMINATE", 0x00000001u, false),
            ("THREAD_SUSPEND_RESUME", 0x00000002u, false),
            ("THREAD_GET_CONTEXT", 0x00000008u, false),
            ("THREAD_SET_CONTEXT", 0x00000010u, false),
            ("THREAD_SET_INFORMATION", 0x00000020u, false),
            ("THREAD_QUERY_INFORMATION", 0x00000040u, false),
            ("THREAD_SET_THREAD_TOKEN", 0x00000080u, false),
            ("THREAD_IMPERSONATE", 0x00000100u, false),
            ("THREAD_DIRECT_IMPERSONATION", 0x00000200u, false),
            ("THREAD_SET_LIMITED_INFORMATION", 0x00000400u, false),
            ("THREAD_QUERY_LIMITED_INFORMATION", 0x00000800u, false),
            ("SYNCHRONIZE", 0x00100000u, false),
            ("THREAD_ALL_ACCESS", 0x001F03FFu, true)
        };

        private sealed class IntelTabState
        {
            public string Title { get; set; } = "";
            public ObservableCollection<GroupedEventDetailRow> Items { get; } = new();
        }

        private sealed class TimelineRow
        {
            public DateTime TimestampUtc { get; set; }
            public string Syscall { get; set; } = "";
            public string Actor { get; set; } = "";
            public string Target { get; set; } = "";
            public string Access { get; set; } = "";
            public string Severity { get; set; } = "";
            public int Hits { get; set; }
            public Brush SeverityBackground { get; set; } = StatusUnknownBackground;
            public Brush SeverityBorder { get; set; } = StatusUnknownBorder;
            public Brush SeverityForeground { get; set; } = StatusUnknownForeground;
            public Brush RowBackground { get; set; } = StatusUnknownBackground;
            public Brush RowBorder { get; set; } = StatusUnknownBorder;
            public GroupedEventDetailRow Representative { get; set; } = new();
        }

        private sealed class SyscallGroupRow
        {
            public string Syscall { get; set; } = "";
            public int Hits { get; set; }
            public string HitsText => $"{Hits}x";
        }

        private sealed class DetailFieldRow
        {
            public string Field { get; set; } = "";
            public string Value { get; set; } = "";
        }

        private sealed class AccessMatrixRow
        {
            public string RightName { get; set; } = "";
            public string ProcessState { get; set; } = "OFF";
            public Brush ProcessStateBrush { get; set; } = AccessAbsentForeground;
            public string ThreadState { get; set; } = "OFF";
            public Brush ThreadStateBrush { get; set; } = AccessAbsentForeground;
        }

        private readonly Dictionary<IntelDetailsCategory, IntelTabState> _tabs = new();
        private ObservableCollection<GroupedEventDetailRow> _activeItems = new();
        private readonly ObservableCollection<TimelineRow> _timelineItems = new();
        private readonly ObservableCollection<SyscallGroupRow> _syscallGroups = new();
        private readonly ObservableCollection<DetailFieldRow> _detailFields = new();
        private readonly ObservableCollection<AccessMatrixRow> _accessMatrixRows = new();
        private ICollectionView? _view;
        private IIntelDetailsProvider? _detailsProvider;

        private IntelDetailsCategory _activeCategory = IntelDetailsCategory.Etw;
        private bool _suppressFilterEvents;
        private bool _suppressTabEvents;
        private bool _suppressSyscallSelectionEvents;
        private string _selectedSyscall = AllSyscallsLabel;
        private string _lastErrorSignature = string.Empty;
        private DateTime _lastErrorUtc = DateTime.MinValue;

        private GroupedEventDetailsWindow()
        {
            _suppressFilterEvents = true;
            _suppressTabEvents = true;

            _tabs[IntelDetailsCategory.Etw] = new IntelTabState { Title = "Sleepwalker ETW" };
            _tabs[IntelDetailsCategory.Heuristics] = new IntelTabState { Title = "Heuristics" };
            _tabs[IntelDetailsCategory.ProcessRelations] = new IntelTabState { Title = "Process Relations" };

            InitializeComponent();
            WindowThemeHelper.ApplyDarkTitleBar(this);

            DetailsGrid.ItemsSource = _timelineItems;
            SyscallGroupList.ItemsSource = _syscallGroups;
            AdditionalFieldsGrid.ItemsSource = _detailFields;
            AccessRightsGrid.ItemsSource = _accessMatrixRows;

            InitializeFilters();
            SetCheckedTabButton(_activeCategory);
            RefreshTabLabels();
            BindActiveCategory();

            _suppressFilterEvents = false;
            _suppressTabEvents = false;
        }

        internal static void ShowUnified(
            Window? owner,
            IntelDetailsCategory category,
            string title,
            IEnumerable<GroupedEventDetailRow> details,
            GroupedEventDetailRow? preferredRow = null)
        {
            try
            {
                if (_sharedWindow == null || !_sharedWindow.IsLoaded)
                {
                    _sharedWindow = new GroupedEventDetailsWindow();
                    _sharedWindow.Closed += SharedWindow_Closed;
                }

                if (owner != null && _sharedWindow.Owner == null && !ReferenceEquals(owner, _sharedWindow))
                {
                    _sharedWindow.Owner = owner;
                }
                if (owner is IIntelDetailsProvider provider)
                {
                    _sharedWindow._detailsProvider = provider;
                }

                _sharedWindow.LoadAllTabsFromProvider();
                _sharedWindow.UpsertCategory(category, title, details);
                _sharedWindow.SwitchToCategory(category);
                if (preferredRow != null)
                {
                    _sharedWindow.ResetFiltersToDefault();
                }
                _sharedWindow.TrySelectPreferredRow(preferredRow);

                if (!_sharedWindow.IsVisible)
                {
                    _sharedWindow.Show();
                }

                _sharedWindow.Activate();
            }
            catch (Exception ex)
            {
                Debug.WriteLine("[IntelDetails][ShowUnified] " + ex);
                MessageBox.Show(
                    owner ?? Application.Current?.MainWindow,
                    $"Intel window failed to open.\n\n{ex.GetType().Name}: {ex.Message}\n\n{ex}",
                    "Intel Details Error",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
            }
        }

        private static void SharedWindow_Closed(object? sender, EventArgs e)
        {
            if (_sharedWindow != null)
            {
                _sharedWindow.Closed -= SharedWindow_Closed;
            }

            _sharedWindow = null;
        }

        private void LoadAllTabsFromProvider()
        {
            if (_detailsProvider == null)
            {
                return;
            }

            foreach (IntelDetailsCategory category in Enum.GetValues(typeof(IntelDetailsCategory)).Cast<IntelDetailsCategory>())
            {
                IReadOnlyList<GroupedEventDetailRow> loaded = _detailsProvider.GetIntelDetails(category);
                string scopedTitle = $"{GetCategoryLabel(category)} • {_detailsProvider.GetIntelScopeLabel()}";
                UpsertCategory(category, scopedTitle, loaded);
            }
        }

        private void UpsertCategory(IntelDetailsCategory category, string title, IEnumerable<GroupedEventDetailRow> details)
        {
            IntelTabState tab = _tabs[category];
            tab.Title = string.IsNullOrWhiteSpace(title) ? GetCategoryLabel(category) : title.Trim();

            tab.Items.Clear();
            foreach (GroupedEventDetailRow row in details.OrderByDescending(x => x.TimestampUtc))
            {
                GroupedEventDetailRow clone = row.Clone();
                clone.Severity = EventDetailFormatting.SeverityLabelFromText(clone.Severity);
                tab.Items.Add(clone);
            }

            RefreshTabLabels();

            if (category == _activeCategory)
            {
                BindActiveCategory();
            }
        }

        private void BindActiveCategory()
        {
            if (!_tabs.TryGetValue(_activeCategory, out IntelTabState? activeTab))
            {
                _activeItems = new ObservableCollection<GroupedEventDetailRow>();
                return;
            }

            _activeItems = activeTab.Items;
            _view = CollectionViewSource.GetDefaultView(_activeItems);
            _view.SortDescriptions.Clear();
            _view.SortDescriptions.Add(new SortDescription(nameof(GroupedEventDetailRow.TimestampUtc), ListSortDirection.Descending));
            _view.Filter = FilterRow;

            RefreshFilterChoices();
            _view.Refresh();
            RefreshSummaryText();
        }

        private void TrySelectPreferredRow(GroupedEventDetailRow? preferredRow)
        {
            if (preferredRow == null || _activeItems.Count == 0)
            {
                return;
            }

            GroupedEventDetailRow? match = _activeItems.FirstOrDefault(x =>
                x.TimestampUtc == preferredRow.TimestampUtc &&
                string.Equals(x.Event, preferredRow.Event, StringComparison.OrdinalIgnoreCase) &&
                string.Equals(x.Detection, preferredRow.Detection, StringComparison.OrdinalIgnoreCase) &&
                string.Equals(x.Actor, preferredRow.Actor, StringComparison.OrdinalIgnoreCase) &&
                string.Equals(x.Target, preferredRow.Target, StringComparison.OrdinalIgnoreCase));

            match ??= _activeItems.FirstOrDefault(x =>
                x.TimestampUtc == preferredRow.TimestampUtc &&
                string.Equals(x.Event, preferredRow.Event, StringComparison.OrdinalIgnoreCase) &&
                string.Equals(x.Detection, preferredRow.Detection, StringComparison.OrdinalIgnoreCase));

            if (match == null && !string.IsNullOrWhiteSpace(preferredRow.EventTid))
            {
                match = _activeItems.FirstOrDefault(x =>
                    string.Equals(x.Event, preferredRow.Event, StringComparison.OrdinalIgnoreCase) &&
                    string.Equals(x.Detection, preferredRow.Detection, StringComparison.OrdinalIgnoreCase) &&
                    string.Equals(x.EventTid, preferredRow.EventTid, StringComparison.OrdinalIgnoreCase));
            }

            if (match == null)
            {
                return;
            }

            SelectTimelineRowForDetail(match);
        }

        private void ResetFiltersToDefault()
        {
            _suppressFilterEvents = true;
            SearchBox.Text = string.Empty;
            EventFilterBox.SelectedIndex = 0;
            SeverityFilterBox.SelectedIndex = 0;
            DetectionFilterBox.SelectedIndex = 0;
            SourceFilterBox.SelectedIndex = 0;
            ActorFilterBox.SelectedIndex = 0;
            TargetFilterBox.SelectedIndex = 0;
            TimeWindowBox.SelectedIndex = 0;
            GroupRepeatedToggle.IsChecked = true;
            _suppressFilterEvents = false;

            _selectedSyscall = AllSyscallsLabel;
            _suppressSyscallSelectionEvents = true;
            if (SyscallGroupList.Items.Count > 0)
            {
                SyscallGroupList.SelectedIndex = 0;
            }
            _suppressSyscallSelectionEvents = false;

            _view?.Refresh();
            RefreshSummaryText();
        }

        private void InitializeFilters()
        {
            _suppressFilterEvents = true;
            SearchBox.Text = string.Empty;
            EventFilterBox.ItemsSource = new[] { AllEventsLabel };
            EventFilterBox.SelectedIndex = 0;
            SeverityFilterBox.ItemsSource = new[] { AllSeveritiesLabel };
            SeverityFilterBox.SelectedIndex = 0;
            DetectionFilterBox.ItemsSource = new[] { AllDetectionsLabel };
            DetectionFilterBox.SelectedIndex = 0;
            SourceFilterBox.ItemsSource = new[] { AllSourcesLabel };
            SourceFilterBox.SelectedIndex = 0;
            ActorFilterBox.ItemsSource = new[] { AllActorsLabel };
            ActorFilterBox.SelectedIndex = 0;
            TargetFilterBox.ItemsSource = new[] { AllTargetsLabel };
            TargetFilterBox.SelectedIndex = 0;
            TimeWindowBox.ItemsSource = new[] { AllTimeLabel, "Last 1m", "Last 5m", "Last 15m", "Last 1h" };
            TimeWindowBox.SelectedIndex = 0;
            GroupRepeatedToggle.IsChecked = true;
            _suppressFilterEvents = false;
        }

        private void RefreshFilterChoices()
        {
            _suppressFilterEvents = true;

            string previousEvent = EventFilterBox.SelectedItem as string ?? AllEventsLabel;
            string previousSeverity = SeverityFilterBox.SelectedItem as string ?? AllSeveritiesLabel;
            string previousDetection = DetectionFilterBox.SelectedItem as string ?? AllDetectionsLabel;
            string previousSource = SourceFilterBox.SelectedItem as string ?? AllSourcesLabel;
            string previousActor = ActorFilterBox.SelectedItem as string ?? AllActorsLabel;
            string previousTarget = TargetFilterBox.SelectedItem as string ?? AllTargetsLabel;

            var events = _activeItems
                .Select(x => x.Event)
                .Where(x => !string.IsNullOrWhiteSpace(x))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(x => x, StringComparer.OrdinalIgnoreCase)
                .ToList();
            events.Insert(0, AllEventsLabel);
            EventFilterBox.ItemsSource = events;
            EventFilterBox.SelectedItem = SelectOrFallback(events, previousEvent, AllEventsLabel);

            var severities = _activeItems
                .Select(x => x.Severity)
                .Where(x => !string.IsNullOrWhiteSpace(x))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(x => x, StringComparer.OrdinalIgnoreCase)
                .ToList();
            severities.Insert(0, AllSeveritiesLabel);
            SeverityFilterBox.ItemsSource = severities;
            SeverityFilterBox.SelectedItem = SelectOrFallback(severities, previousSeverity, AllSeveritiesLabel);

            var detections = _activeItems
                .Select(x => x.Detection)
                .Where(x => !string.IsNullOrWhiteSpace(x))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(x => x, StringComparer.OrdinalIgnoreCase)
                .ToList();
            detections.Insert(0, AllDetectionsLabel);
            DetectionFilterBox.ItemsSource = detections;
            DetectionFilterBox.SelectedItem = SelectOrFallback(detections, previousDetection, AllDetectionsLabel);

            var sources = _activeItems
                .Select(x => x.Source)
                .Where(x => !string.IsNullOrWhiteSpace(x))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(x => x, StringComparer.OrdinalIgnoreCase)
                .ToList();
            sources.Insert(0, AllSourcesLabel);
            SourceFilterBox.ItemsSource = sources;
            SourceFilterBox.SelectedItem = SelectOrFallback(sources, previousSource, AllSourcesLabel);

            var actors = _activeItems
                .Select(x => x.Actor)
                .Where(x => !string.IsNullOrWhiteSpace(x))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(x => x, StringComparer.OrdinalIgnoreCase)
                .ToList();
            actors.Insert(0, AllActorsLabel);
            ActorFilterBox.ItemsSource = actors;
            ActorFilterBox.SelectedItem = SelectOrFallback(actors, previousActor, AllActorsLabel);

            var targets = _activeItems
                .Select(x => x.Target)
                .Where(x => !string.IsNullOrWhiteSpace(x))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(x => x, StringComparer.OrdinalIgnoreCase)
                .ToList();
            targets.Insert(0, AllTargetsLabel);
            TargetFilterBox.ItemsSource = targets;
            TargetFilterBox.SelectedItem = SelectOrFallback(targets, previousTarget, AllTargetsLabel);

            _suppressFilterEvents = false;
        }

        private static string SelectOrFallback(IReadOnlyCollection<string> choices, string previous, string fallback)
        {
            if (choices.Contains(previous, StringComparer.OrdinalIgnoreCase))
            {
                return choices.First(x => string.Equals(x, previous, StringComparison.OrdinalIgnoreCase));
            }

            return fallback;
        }

        private void RefreshTabLabels()
        {
            if (!_tabs.TryGetValue(IntelDetailsCategory.Etw, out IntelTabState? etw) ||
                !_tabs.TryGetValue(IntelDetailsCategory.Heuristics, out IntelTabState? heuristics) ||
                !_tabs.TryGetValue(IntelDetailsCategory.ProcessRelations, out IntelTabState? relations))
            {
                return;
            }

            EtwTabButton.Content = $"ETW ({etw.Items.Count})";
            HeuristicsTabButton.Content = $"Heuristics ({heuristics.Items.Count})";
            RelationsTabButton.Content = $"Process Relations ({relations.Items.Count})";
        }

        private void SetCheckedTabButton(IntelDetailsCategory category)
        {
            _suppressTabEvents = true;
            EtwTabButton.IsChecked = category == IntelDetailsCategory.Etw;
            HeuristicsTabButton.IsChecked = category == IntelDetailsCategory.Heuristics;
            RelationsTabButton.IsChecked = category == IntelDetailsCategory.ProcessRelations;
            _suppressTabEvents = false;
        }

        private void SwitchToCategory(IntelDetailsCategory category)
        {
            if (!_tabs.ContainsKey(category))
            {
                return;
            }

            _activeCategory = category;
            SetCheckedTabButton(category);
            EnsureCategoryLoaded(category);
            BindActiveCategory();
        }

        private void EnsureCategoryLoaded(IntelDetailsCategory category)
        {
            IntelTabState tab = _tabs[category];
            if (tab.Items.Count > 0 || _detailsProvider == null)
            {
                return;
            }

            IReadOnlyList<GroupedEventDetailRow> loaded = _detailsProvider.GetIntelDetails(category);
            tab.Title = GetCategoryLabel(category);
            tab.Items.Clear();
            foreach (GroupedEventDetailRow row in loaded.OrderByDescending(x => x.TimestampUtc))
            {
                tab.Items.Add(row.Clone());
            }

            RefreshTabLabels();
        }

        private static string GetCategoryLabel(IntelDetailsCategory category)
        {
            return category switch
            {
                IntelDetailsCategory.Etw => "ETW",
                IntelDetailsCategory.Heuristics => "Heuristics",
                IntelDetailsCategory.ProcessRelations => "Process Relations",
                _ => "Intel"
            };
        }

        private bool FilterRow(object obj)
        {
            try
            {
                if (obj is not GroupedEventDetailRow row)
                {
                    return false;
                }

                string selectedEvent = EventFilterBox.SelectedItem as string ?? AllEventsLabel;
                if (!selectedEvent.Equals(AllEventsLabel, StringComparison.OrdinalIgnoreCase) &&
                    !string.Equals(row.Event, selectedEvent, StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }

                string selectedSeverity = SeverityFilterBox.SelectedItem as string ?? AllSeveritiesLabel;
                if (!selectedSeverity.Equals(AllSeveritiesLabel, StringComparison.OrdinalIgnoreCase) &&
                    !string.Equals(row.Severity, selectedSeverity, StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }

                string selectedDetection = DetectionFilterBox.SelectedItem as string ?? AllDetectionsLabel;
                if (!selectedDetection.Equals(AllDetectionsLabel, StringComparison.OrdinalIgnoreCase) &&
                    !string.Equals(row.Detection, selectedDetection, StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }

                string selectedSource = SourceFilterBox.SelectedItem as string ?? AllSourcesLabel;
                if (!selectedSource.Equals(AllSourcesLabel, StringComparison.OrdinalIgnoreCase) &&
                    !string.Equals(row.Source, selectedSource, StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }

                string selectedActor = ActorFilterBox.SelectedItem as string ?? AllActorsLabel;
                if (!selectedActor.Equals(AllActorsLabel, StringComparison.OrdinalIgnoreCase) &&
                    !string.Equals(row.Actor, selectedActor, StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }

                string selectedTarget = TargetFilterBox.SelectedItem as string ?? AllTargetsLabel;
                if (!selectedTarget.Equals(AllTargetsLabel, StringComparison.OrdinalIgnoreCase) &&
                    !string.Equals(row.Target, selectedTarget, StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }

                TimeSpan? window = GetSelectedWindow();
                if (window.HasValue)
                {
                    DateTime minUtc = DateTime.UtcNow - window.Value;
                    if (row.TimestampUtc < minUtc)
                    {
                        return false;
                    }
                }

                string query = (SearchBox.Text ?? string.Empty).Trim();
                if (query.Length > 0 &&
                    !row.FilterText.Contains(query, StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }

                return true;
            }
            catch
            {
                return false;
            }
        }

        private TimeSpan? GetSelectedWindow()
        {
            string selected = TimeWindowBox.SelectedItem as string ?? AllTimeLabel;
            return selected switch
            {
                "Last 1m" => TimeSpan.FromMinutes(1),
                "Last 5m" => TimeSpan.FromMinutes(5),
                "Last 15m" => TimeSpan.FromMinutes(15),
                "Last 1h" => TimeSpan.FromHours(1),
                _ => null
            };
        }

        private string BuildFilterState()
        {
            string query = (SearchBox.Text ?? string.Empty).Trim();
            string eventText = EventFilterBox.SelectedItem as string ?? AllEventsLabel;
            string severity = SeverityFilterBox.SelectedItem as string ?? AllSeveritiesLabel;
            string detection = DetectionFilterBox.SelectedItem as string ?? AllDetectionsLabel;
            string source = SourceFilterBox.SelectedItem as string ?? AllSourcesLabel;
            string actor = ActorFilterBox.SelectedItem as string ?? AllActorsLabel;
            string target = TargetFilterBox.SelectedItem as string ?? AllTargetsLabel;
            string window = TimeWindowBox.SelectedItem as string ?? AllTimeLabel;
            string syscall = _selectedSyscall;
            string grouped = GroupRepeatedToggle.IsChecked == true ? "grouped" : "expanded";
            return $"event={eventText}, sev={severity}, detect={detection}, src={source}, actor={actor}, target={target}, syscall={syscall}, window={window}, mode={grouped}, q={(query.Length == 0 ? "<none>" : query)}";
        }

        private void RefreshSummaryText()
        {
            try
            {
                if (!_tabs.TryGetValue(_activeCategory, out IntelTabState? activeTab))
                {
                    HeaderBlock.Text = "Intel Details";
                    SummaryBlock.Text = "Initializing...";
                    FilterStateBlock.Text = "Waiting for tab state.";
                    return;
                }

                int total = _activeItems.Count;
                List<GroupedEventDetailRow> filteredRows = GetFilteredRows();
                RefreshSyscallGroups(filteredRows);
                List<GroupedEventDetailRow> scopedRows = ApplySyscallScope(filteredRows);

                string scope = GetCategoryLabel(_activeCategory);
                string title = activeTab.Title;
                string scopeLabel = _detailsProvider?.GetIntelScopeLabel() ?? "Session";
                string mode = GroupRepeatedToggle.IsChecked == true ? "grouped timeline" : "expanded timeline";

                HeaderBlock.Text = $"Intel Details: {scope} • {scopeLabel}";
                SummaryBlock.Text = $"{title} • {scopedRows.Count}/{filteredRows.Count} shown ({total} total) • {mode}";
                FilterStateBlock.Text = BuildFilterState();

                UpdateDetectionSummary(scopedRows);
                RefreshTimelineRows(scopedRows);
                UpdateScopeStateBadge();
            }
            catch (Exception ex)
            {
                ReportException("RefreshSummaryText", ex, showDialog: false);
                HeaderBlock.Text = "Intel Details";
                SummaryBlock.Text = $"Render fallback active ({ex.GetType().Name})";
                FilterStateBlock.Text = ex.Message;
                _timelineItems.Clear();
                _detailFields.Clear();
                UpdateDeepDetail(null);
            }
        }

        private List<GroupedEventDetailRow> GetFilteredRows()
        {
            if (_view == null)
            {
                return new List<GroupedEventDetailRow>();
            }

            return _view
                .Cast<GroupedEventDetailRow>()
                .OrderByDescending(x => x.TimestampUtc)
                .ToList();
        }

        private List<GroupedEventDetailRow> ApplySyscallScope(IReadOnlyList<GroupedEventDetailRow> rows)
        {
            if (_selectedSyscall.Equals(AllSyscallsLabel, StringComparison.OrdinalIgnoreCase))
            {
                return rows.ToList();
            }

            return rows
                .Where(x => ExtractSyscallLabel(x).Equals(_selectedSyscall, StringComparison.OrdinalIgnoreCase))
                .ToList();
        }

        private void RefreshSyscallGroups(IReadOnlyList<GroupedEventDetailRow> rows)
        {
            string previousSelection = _selectedSyscall;
            var grouped = rows
                .GroupBy(ExtractSyscallLabel, StringComparer.OrdinalIgnoreCase)
                .Select(g => new SyscallGroupRow
                {
                    Syscall = g.Key,
                    Hits = g.Count()
                })
                .OrderByDescending(x => x.Hits)
                .ThenBy(x => x.Syscall, StringComparer.OrdinalIgnoreCase)
                .ToList();

            _suppressSyscallSelectionEvents = true;
            _syscallGroups.Clear();
            _syscallGroups.Add(new SyscallGroupRow
            {
                Syscall = AllSyscallsLabel,
                Hits = rows.Count
            });
            foreach (SyscallGroupRow row in grouped)
            {
                _syscallGroups.Add(row);
            }

            if (!_syscallGroups.Any(x => x.Syscall.Equals(previousSelection, StringComparison.OrdinalIgnoreCase)))
            {
                previousSelection = AllSyscallsLabel;
            }

            _selectedSyscall = previousSelection;
            SyscallGroupList.SelectedItem = _syscallGroups.FirstOrDefault(x =>
                x.Syscall.Equals(previousSelection, StringComparison.OrdinalIgnoreCase));
            _suppressSyscallSelectionEvents = false;
        }

        private void RefreshTimelineRows(IReadOnlyList<GroupedEventDetailRow> rows)
        {
            GroupedEventDetailRow? previous = (DetailsGrid.SelectedItem as TimelineRow)?.Representative;
            IEnumerable<TimelineRow> timeline = GroupRepeatedToggle.IsChecked == true
                ? BuildGroupedTimelineRows(rows)
                : BuildExpandedTimelineRows(rows);

            _timelineItems.Clear();
            foreach (TimelineRow row in timeline)
            {
                _timelineItems.Add(row);
            }

            TimelineRow? selected = null;
            if (previous != null)
            {
                selected = _timelineItems.FirstOrDefault(x => IsSameEvent(x.Representative, previous));
            }

            selected ??= _timelineItems.FirstOrDefault();
            if (selected != null)
            {
                DetailsGrid.SelectedItem = selected;
                DetailsGrid.ScrollIntoView(selected);
            }
            else
            {
                DetailsGrid.SelectedItem = null;
            }

            UpdateDeepDetail(selected?.Representative, selected?.Syscall);
        }

        private IEnumerable<TimelineRow> BuildGroupedTimelineRows(IReadOnlyList<GroupedEventDetailRow> rows)
        {
            return rows
                .GroupBy(row => new
                {
                    Syscall = ExtractSyscallLabel(row),
                    Actor = NormalizeText(row.Actor),
                    Target = NormalizeText(row.Target),
                    Access = BuildAccessSummary(row),
                    Severity = NormalizeSeverity(row.Severity)
                })
                .Select(group =>
                {
                    GroupedEventDetailRow rep = group.OrderByDescending(x => x.TimestampUtc).First();
                    return CreateTimelineRow(
                        rep,
                        group.Key.Syscall,
                        group.Key.Actor,
                        group.Key.Target,
                        group.Key.Access,
                        group.Key.Severity,
                        group.Count());
                })
                .OrderByDescending(x => x.TimestampUtc);
        }

        private IEnumerable<TimelineRow> BuildExpandedTimelineRows(IReadOnlyList<GroupedEventDetailRow> rows)
        {
            foreach (GroupedEventDetailRow row in rows.OrderByDescending(x => x.TimestampUtc))
            {
                yield return CreateTimelineRow(
                    row,
                    ExtractSyscallLabel(row),
                    NormalizeText(row.Actor),
                    NormalizeText(row.Target),
                    BuildAccessSummary(row),
                    NormalizeSeverity(row.Severity),
                    1);
            }
        }

        private TimelineRow CreateTimelineRow(
            GroupedEventDetailRow representative,
            string syscall,
            string actor,
            string target,
            string access,
            string severity,
            int hits)
        {
            (Brush bg, Brush border, Brush fg) = GetSeverityPalette(severity);
            return new TimelineRow
            {
                TimestampUtc = representative.TimestampUtc,
                Syscall = syscall,
                Actor = actor,
                Target = target,
                Access = access,
                Severity = severity,
                Hits = hits,
                SeverityBackground = bg,
                SeverityBorder = border,
                SeverityForeground = fg,
                RowBackground = BuildRowHighlightBrush(bg),
                RowBorder = BuildRowHighlightBrush(border),
                Representative = representative
            };
        }

        private static Brush BuildRowHighlightBrush(Brush source)
        {
            if (source is SolidColorBrush solid)
            {
                return new SolidColorBrush(Color.FromArgb(0x24, solid.Color.R, solid.Color.G, solid.Color.B));
            }

            return StatusUnknownBackground;
        }

        private void UpdateDetectionSummary(IReadOnlyList<GroupedEventDetailRow> rows)
        {
            if (rows.Count == 0)
            {
                DetectionNameBlock.Text = "-";
                DetectionSeverityBlock.Text = "Unknown";
                DetectionActorBlock.Text = "-";
                DetectionTargetBlock.Text = "-";
                DetectionRangeBlock.Text = "Events: 0";
                DetectionSeverityBadge.Background = StatusUnknownBackground;
                DetectionSeverityBadge.BorderBrush = StatusUnknownBorder;
                DetectionSeverityBlock.Foreground = StatusUnknownForeground;
                return;
            }

            IGrouping<string, GroupedEventDetailRow> detectionGroup = rows
                .GroupBy(x => NormalizeText(x.Detection), StringComparer.OrdinalIgnoreCase)
                .OrderByDescending(g => g.Count())
                .ThenBy(g => g.Key, StringComparer.OrdinalIgnoreCase)
                .First();
            List<GroupedEventDetailRow> primaryRows = detectionGroup.ToList();

            string severity = primaryRows
                .Select(x => NormalizeSeverity(x.Severity))
                .OrderByDescending(GetSeverityRank)
                .ThenBy(x => x, StringComparer.OrdinalIgnoreCase)
                .First();
            (Brush sevBg, Brush sevBorder, Brush sevFg) = GetSeverityPalette(severity);

            string actor = primaryRows
                .GroupBy(x => NormalizeText(x.Actor), StringComparer.OrdinalIgnoreCase)
                .OrderByDescending(g => g.Count())
                .ThenBy(g => g.Key, StringComparer.OrdinalIgnoreCase)
                .First().Key;
            string target = primaryRows
                .GroupBy(x => NormalizeText(x.Target), StringComparer.OrdinalIgnoreCase)
                .OrderByDescending(g => g.Count())
                .ThenBy(g => g.Key, StringComparer.OrdinalIgnoreCase)
                .First().Key;
            DateTime firstSeen = primaryRows.Min(x => x.TimestampUtc);
            DateTime lastSeen = primaryRows.Max(x => x.TimestampUtc);

            string syscallSummary = string.Join(", ",
                primaryRows
                    .GroupBy(ExtractSyscallLabel, StringComparer.OrdinalIgnoreCase)
                    .OrderByDescending(g => g.Count())
                    .ThenBy(g => g.Key, StringComparer.OrdinalIgnoreCase)
                    .Take(4)
                    .Select(g => $"{g.Key} ({g.Count()}x)"));

            if (string.IsNullOrWhiteSpace(syscallSummary))
            {
                syscallSummary = "-";
            }

            DetectionNameBlock.Text = detectionGroup.Key;
            DetectionSeverityBlock.Text = severity.ToUpperInvariant();
            DetectionSeverityBadge.Background = sevBg;
            DetectionSeverityBadge.BorderBrush = sevBorder;
            DetectionSeverityBlock.Foreground = sevFg;
            DetectionActorBlock.Text = actor;
            DetectionTargetBlock.Text = target;
            DetectionRangeBlock.Text =
                $"Events: {primaryRows.Count} | First: {firstSeen:HH:mm:ss.fff} | Last: {lastSeen:HH:mm:ss.fff} | Syscalls: {syscallSummary}";
        }

        private static bool IsSameEvent(GroupedEventDetailRow left, GroupedEventDetailRow right)
        {
            return left.TimestampUtc == right.TimestampUtc &&
                   left.Event.Equals(right.Event, StringComparison.OrdinalIgnoreCase) &&
                   left.Detection.Equals(right.Detection, StringComparison.OrdinalIgnoreCase) &&
                   left.Actor.Equals(right.Actor, StringComparison.OrdinalIgnoreCase) &&
                   left.Target.Equals(right.Target, StringComparison.OrdinalIgnoreCase);
        }

        private void SelectTimelineRowForDetail(GroupedEventDetailRow preferred)
        {
            TimelineRow? match = _timelineItems.FirstOrDefault(x => IsSameEvent(x.Representative, preferred));
            if (match == null)
            {
                string syscall = ExtractSyscallLabel(preferred);
                string access = BuildAccessSummary(preferred);
                match = _timelineItems.FirstOrDefault(x =>
                    x.Syscall.Equals(syscall, StringComparison.OrdinalIgnoreCase) &&
                    x.Actor.Equals(NormalizeText(preferred.Actor), StringComparison.OrdinalIgnoreCase) &&
                    x.Target.Equals(NormalizeText(preferred.Target), StringComparison.OrdinalIgnoreCase) &&
                    x.Access.Equals(access, StringComparison.OrdinalIgnoreCase));
            }

            if (match == null)
            {
                return;
            }

            DetailsGrid.SelectedItem = match;
            DetailsGrid.ScrollIntoView(match);
            UpdateDeepDetail(match.Representative, match.Syscall);
        }

        private void UpdateDeepDetail(GroupedEventDetailRow? row, string? syscallHint = null)
        {
            _detailFields.Clear();
            if (row == null)
            {
                DetailSyscallBlock.Text = "Name: -";
                DetailActorBlock.Text = "Actor: -";
                DetailTargetBlock.Text = "Target: -";
                AccessMaskBlock.Text = "Mask: none";
                _accessMatrixRows.Clear();
                DetailMemoryBlock.Text = "No context";
                DetailReasonBlock.Text = "No reason provided";
                DetailRegistersBlock.Text = "No register capture available.";
                RawEventBox.Text = string.Empty;
                return;
            }

            Dictionary<string, string> parsed = ParseRawFields(row.Details);
            string syscall = string.IsNullOrWhiteSpace(syscallHint) ? ExtractSyscallLabel(row) : syscallHint;

            DetailSyscallBlock.Text = $"Name: {syscall}";
            DetailActorBlock.Text = $"Actor: {NormalizeText(row.Actor)}";
            DetailTargetBlock.Text = $"Target: {NormalizeText(row.Target)}";
            RenderAccessDetailMatrix(row, parsed);
            DetailMemoryBlock.Text = BuildMemoryContext(parsed);
            DetailReasonBlock.Text = BuildReason(row, parsed);
            DetailRegistersBlock.Text = BuildRegisterContext(row, parsed);
            RawEventBox.Text = string.IsNullOrWhiteSpace(row.Details) ? "<empty>" : row.Details;

            var known = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "src", "task", "opcode", "id", "eventPid", "eventTid",
                "corrFlags", "flags", "corrAccess", "access", "desiredAccess",
                "corrAgeMs", "reason", "origin", "stack0", "stack1", "module",
                "path", "protect", "pageBase", "allocationBase", "regionSize",
                "regionProtect", "regionState", "regionType", "captureFlags",
                "fullFrameCount", "fullFrames", "stackSnapshotAddress",
                "stackSnapshotSize", "stackSnapshot", "deepSample", "deepSampleSize",
                "sampleDisasmHint", "rax", "rbx", "rcx", "rdx", "rsi", "rdi",
                "rbp", "rsp", "r8", "r9", "r10", "r11", "r12", "r13", "r14",
                "r15", "rip", "eflags", "dr0", "dr1", "dr2", "dr3", "dr6", "dr7",
                "evidence", "actor", "target", "hits"
            };

            foreach (KeyValuePair<string, string> pair in parsed
                .Where(x => !known.Contains(x.Key))
                .OrderBy(x => x.Key, StringComparer.OrdinalIgnoreCase))
            {
                _detailFields.Add(new DetailFieldRow
                {
                    Field = pair.Key,
                    Value = string.IsNullOrWhiteSpace(pair.Value) ? "-" : pair.Value
                });
            }

            if (_detailFields.Count == 0)
            {
                _detailFields.Add(new DetailFieldRow { Field = "(none)", Value = "-" });
            }
        }

        private static string BuildReason(GroupedEventDetailRow row, IReadOnlyDictionary<string, string> parsed)
        {
            string reason = FirstNonEmpty(
                row.Reason,
                GetParsedValue(parsed, "reason"),
                row.Detection);

            var sb = new StringBuilder();
            sb.AppendLine(reason);

            string flags = FirstNonEmpty(row.Flags, GetParsedValue(parsed, "corrFlags"), GetParsedValue(parsed, "flags"));
            if (!string.IsNullOrWhiteSpace(flags))
            {
                sb.AppendLine($"Flags: {flags}");
            }

            return sb.ToString().TrimEnd();
        }

        private void RenderAccessDetailMatrix(GroupedEventDetailRow row, IReadOnlyDictionary<string, string> parsed)
        {
            string raw = FirstNonEmpty(
                row.Access,
                GetParsedValue(parsed, "corrAccess"),
                GetParsedValue(parsed, "access"),
                GetParsedValue(parsed, "desiredAccess"));

            _accessMatrixRows.Clear();
            if (!TryParseHexU32(raw, out uint accessMask))
            {
                AccessMaskBlock.Text = $"Mask: {(string.IsNullOrWhiteSpace(raw) ? "none" : raw)}";
                _accessMatrixRows.Add(new AccessMatrixRow
                {
                    RightName = "Unparsed access",
                    ProcessState = "-",
                    ProcessStateBrush = AccessLabelForeground,
                    ThreadState = "-",
                    ThreadStateBrush = AccessLabelForeground
                });
                return;
            }

            AccessMaskBlock.Text = $"Mask: 0x{accessMask:X8}";
            var processRights = ProcessAccessMatrix.ToDictionary(x => x.Name, StringComparer.OrdinalIgnoreCase);
            var threadRights = ThreadAccessMatrix.ToDictionary(x => x.Name, StringComparer.OrdinalIgnoreCase);
            var orderedNames = ProcessAccessMatrix
                .Select(x => x.Name)
                .Concat(ThreadAccessMatrix.Select(x => x.Name))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();

            foreach (string rightName in orderedNames)
            {
                string processState = "-";
                Brush processBrush = AccessLabelForeground;
                if (processRights.TryGetValue(rightName, out var processRight))
                {
                    bool on = processRight.FullMask
                        ? (accessMask & processRight.Mask) == processRight.Mask
                        : (accessMask & processRight.Mask) != 0;
                    processState = on ? "ON" : "OFF";
                    processBrush = on ? AccessPresentForeground : AccessAbsentForeground;
                }

                string threadState = "-";
                Brush threadBrush = AccessLabelForeground;
                if (threadRights.TryGetValue(rightName, out var threadRight))
                {
                    bool on = threadRight.FullMask
                        ? (accessMask & threadRight.Mask) == threadRight.Mask
                        : (accessMask & threadRight.Mask) != 0;
                    threadState = on ? "ON" : "OFF";
                    threadBrush = on ? AccessPresentForeground : AccessAbsentForeground;
                }

                _accessMatrixRows.Add(new AccessMatrixRow
                {
                    RightName = rightName,
                    ProcessState = processState,
                    ProcessStateBrush = processBrush,
                    ThreadState = threadState,
                    ThreadStateBrush = threadBrush
                });
            }
        }

        private static bool IsThreadAccessContext(GroupedEventDetailRow row, IReadOnlyDictionary<string, string> parsed)
        {
            string flags = FirstNonEmpty(row.Flags, GetParsedValue(parsed, "flags"), GetParsedValue(parsed, "corrFlags"));
            if (flags.Contains("THREAD_OBJECT", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            if (row.Event.Contains("Thread", StringComparison.OrdinalIgnoreCase) ||
                row.Detection.Contains("THREAD", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            string accessText = NormalizeText(row.Access);
            return accessText.Contains("THREAD_", StringComparison.OrdinalIgnoreCase);
        }

        private static string BuildMemoryContext(IReadOnlyDictionary<string, string> parsed)
        {
            var lines = new List<string>();
            AddIfPresent(lines, parsed, "origin");
            AddIfPresent(lines, parsed, "pageBase");
            AddIfPresent(lines, parsed, "stack0");
            AddIfPresent(lines, parsed, "stack1");
            AddIfPresent(lines, parsed, "module");
            AddIfPresent(lines, parsed, "path");
            AddIfPresent(lines, parsed, "protect");
            AddIfPresent(lines, parsed, "allocationBase");
            AddIfPresent(lines, parsed, "regionSize");
            AddIfPresent(lines, parsed, "regionProtect");
            AddIfPresent(lines, parsed, "regionState");
            AddIfPresent(lines, parsed, "regionType");
            AddIfPresent(lines, parsed, "stackSnapshotAddress");
            AddIfPresent(lines, parsed, "stackSnapshotSize");
            if (parsed.TryGetValue("stackSnapshot", out string? stackSnapshot) && !string.IsNullOrWhiteSpace(stackSnapshot))
            {
                string compact = stackSnapshot.Trim();
                if (compact.Length > 192)
                {
                    compact = compact[..192] + "...";
                }
                lines.Add($"stackSnapshot: {compact}");
            }

            if (lines.Count == 0)
            {
                return "No memory/execution context available.";
            }

            return string.Join(Environment.NewLine, lines);
        }

        private static string BuildRegisterContext(GroupedEventDetailRow row, IReadOnlyDictionary<string, string> parsed)
        {
            var lines = new List<string>();
            string[] registerKeys =
            {
                "rax", "eax", "rbx", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11",
                "r12", "r13", "r14", "r15", "rsp", "rbp", "rip", "eflags", "dr0", "dr1", "dr2", "dr3", "dr6", "dr7"
            };

            foreach (string key in registerKeys)
            {
                if (parsed.TryGetValue(key, out string? value) && !string.IsNullOrWhiteSpace(value))
                {
                    lines.Add($"{key.ToUpperInvariant()}: {value.Trim()}");
                }
            }

            if (parsed.TryGetValue("captureFlags", out string? captureFlags) && !string.IsNullOrWhiteSpace(captureFlags))
            {
                lines.Add($"CAPTURE_FLAGS: {captureFlags.Trim()}");
            }
            if (parsed.TryGetValue("fullFrameCount", out string? fullFrameCount) && !string.IsNullOrWhiteSpace(fullFrameCount))
            {
                lines.Add($"FULL_FRAME_COUNT: {fullFrameCount.Trim()}");
            }
            if (parsed.TryGetValue("fullFrames", out string? fullFrames) && !string.IsNullOrWhiteSpace(fullFrames))
            {
                lines.Add($"FULL_FRAMES: {fullFrames.Trim()}");
            }
            if (parsed.TryGetValue("stackSnapshotAddress", out string? stackAddress) && !string.IsNullOrWhiteSpace(stackAddress))
            {
                string stackSize = GetParsedValue(parsed, "stackSnapshotSize");
                lines.Add($"STACK_SNAPSHOT: {stackAddress.Trim()} size={stackSize}");
            }

            if (lines.Count == 0)
            {
                byte[] sampleBytes = ParseHexByteList(GetParsedValue(parsed, "deepSample"));
                if (TryExtractSyscallIdFromSample(sampleBytes, out uint syscallId))
                {
                    lines.Add($"EAX: 0x{syscallId:X} (syscall id)");
                    lines.Add("R10: mirrors RCX (syscall stub convention)");
                    string origin = FirstNonEmpty(GetParsedValue(parsed, "origin"), GetParsedValue(parsed, "stack0"));
                    if (!string.IsNullOrWhiteSpace(origin))
                    {
                        lines.Add($"RIP: {origin}");
                    }
                    lines.Add("RCX/RDX/R8/R9: argument registers not captured by current telemetry");
                }
            }

            return lines.Count == 0
                ? "No register capture available."
                : string.Join(Environment.NewLine, lines);
        }

        private static byte[] ParseHexByteList(string text)
        {
            if (string.IsNullOrWhiteSpace(text) || text.Equals("<none>", StringComparison.OrdinalIgnoreCase))
            {
                return Array.Empty<byte>();
            }

            var bytes = new List<byte>();
            foreach (string token in text.Split(new[] { ' ', '\t', '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
            {
                if (byte.TryParse(token, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out byte value))
                {
                    bytes.Add(value);
                }
            }

            return bytes.ToArray();
        }

        private static bool TryExtractSyscallIdFromSample(byte[] bytes, out uint syscallId)
        {
            syscallId = 0;
            if (bytes.Length < 11)
            {
                return false;
            }

            for (int i = 0; i <= bytes.Length - 11; i += 1)
            {
                if (bytes[i] == 0x4C &&
                    bytes[i + 1] == 0x8B &&
                    bytes[i + 2] == 0xD1 &&
                    bytes[i + 3] == 0xB8 &&
                    bytes[i + 8] == 0x0F &&
                    bytes[i + 9] == 0x05)
                {
                    syscallId = (uint)(bytes[i + 4] |
                                       (bytes[i + 5] << 8) |
                                       (bytes[i + 6] << 16) |
                                       (bytes[i + 7] << 24));
                    return true;
                }
            }

            return false;
        }

        private static void AddIfPresent(List<string> lines, IReadOnlyDictionary<string, string> parsed, string key)
        {
            if (parsed.TryGetValue(key, out string? value) && !string.IsNullOrWhiteSpace(value))
            {
                lines.Add($"{key}: {value.Trim()}");
            }
        }

        private static string BuildAccessDetail(GroupedEventDetailRow row, IReadOnlyDictionary<string, string> parsed)
        {
            string raw = FirstNonEmpty(
                row.Access,
                GetParsedValue(parsed, "corrAccess"),
                GetParsedValue(parsed, "access"),
                GetParsedValue(parsed, "desiredAccess"));

            if (string.IsNullOrWhiteSpace(raw))
            {
                return "None";
            }

            if (TryParseHexU32(raw, out uint accessMask))
            {
                string described = EventDetailFormatting.DescribeHandleAccess(accessMask);
                string[] tokens = described
                    .Split(new[] { '|' }, StringSplitOptions.RemoveEmptyEntries)
                    .Select(x => x.Trim())
                    .Where(x => x.Length > 0)
                    .ToArray();
                if (tokens.Length == 0)
                {
                    return $"0x{accessMask:X8}";
                }

                return $"0x{accessMask:X8}{Environment.NewLine}{string.Join(Environment.NewLine, tokens)}";
            }

            return raw;
        }

        private static string BuildAccessSummary(GroupedEventDetailRow row)
        {
            Dictionary<string, string> parsed = ParseRawFields(row.Details);
            string raw = FirstNonEmpty(
                row.Access,
                GetParsedValue(parsed, "corrAccess"),
                GetParsedValue(parsed, "access"),
                GetParsedValue(parsed, "desiredAccess"));

            if (TryParseHexU32(raw, out uint accessMask))
            {
                return $"0x{accessMask:X8}";
            }

            string compact = NormalizeText(raw);
            if (compact.Length > 48)
            {
                return compact[..48] + "...";
            }

            return compact;
        }

        private static string ExtractSyscallLabel(GroupedEventDetailRow row)
        {
            Dictionary<string, string> parsed = ParseRawFields(row.Details);
            string candidate = FirstNonEmpty(
                GetParsedValue(parsed, "api"),
                GetParsedValue(parsed, "syscall"),
                GetParsedValue(parsed, "syscallLabel"),
                FindNtToken(row.Details),
                FindNtToken(row.Event),
                NormalizeText(row.Event),
                NormalizeText(row.Detection));

            return candidate;
        }

        private static string FindNtToken(string? text)
        {
            if (string.IsNullOrWhiteSpace(text))
            {
                return string.Empty;
            }

            char[] separators = { ' ', ';', ',', ':', '|', '\t', '\r', '\n', '(', ')' };
            foreach (string token in text.Split(separators, StringSplitOptions.RemoveEmptyEntries))
            {
                if (token.StartsWith("Nt", StringComparison.OrdinalIgnoreCase))
                {
                    return token.Trim();
                }
            }

            return string.Empty;
        }

        private static Dictionary<string, string> ParseRawFields(string? details)
        {
            var parsed = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            if (string.IsNullOrWhiteSpace(details))
            {
                return parsed;
            }

            string text = details.Trim();
            int index = 0;
            while (index < text.Length)
            {
                while (index < text.Length && char.IsWhiteSpace(text[index]))
                {
                    index += 1;
                }

                if (index >= text.Length)
                {
                    break;
                }

                int keyStart = index;
                while (index < text.Length && text[index] != '=' && !char.IsWhiteSpace(text[index]))
                {
                    index += 1;
                }

                if (index >= text.Length || text[index] != '=')
                {
                    while (index < text.Length && !char.IsWhiteSpace(text[index]))
                    {
                        index += 1;
                    }
                    continue;
                }

                string key = text[keyStart..index].Trim();
                index += 1;

                int valueStart = index;
                while (index < text.Length)
                {
                    if (!char.IsWhiteSpace(text[index]))
                    {
                        index += 1;
                        continue;
                    }

                    int probe = index;
                    while (probe < text.Length && char.IsWhiteSpace(text[probe]))
                    {
                        probe += 1;
                    }

                    if (probe >= text.Length)
                    {
                        index = probe;
                        break;
                    }

                    int nextKeyStart = probe;
                    while (probe < text.Length && text[probe] != '=' && !char.IsWhiteSpace(text[probe]))
                    {
                        probe += 1;
                    }

                    if (probe < text.Length && text[probe] == '=' && probe > nextKeyStart)
                    {
                        break;
                    }

                    index += 1;
                }

                string value = text[valueStart..index].Trim();
                if (!string.IsNullOrWhiteSpace(key))
                {
                    parsed[key] = value;
                }
            }

            return parsed;
        }

        private static string GetParsedValue(IReadOnlyDictionary<string, string> parsed, string key)
        {
            return parsed.TryGetValue(key, out string? value) ? value : string.Empty;
        }

        private static string FirstNonEmpty(params string[] values)
        {
            foreach (string value in values)
            {
                if (!string.IsNullOrWhiteSpace(value))
                {
                    return value.Trim();
                }
            }

            return string.Empty;
        }

        private static string NormalizeText(string? value)
        {
            return string.IsNullOrWhiteSpace(value) ? "-" : value.Trim();
        }

        private static string NormalizeSeverity(string? severity)
        {
            return EventDetailFormatting.SeverityLabelFromText(severity);
        }

        private static int GetSeverityRank(string severity)
        {
            string value = NormalizeSeverity(severity);
            if (value.Contains("critical", StringComparison.OrdinalIgnoreCase))
            {
                return 5;
            }
            if (value.Contains("high", StringComparison.OrdinalIgnoreCase))
            {
                return 4;
            }
            if (value.Contains("medium", StringComparison.OrdinalIgnoreCase))
            {
                return 3;
            }
            if (value.Contains("low", StringComparison.OrdinalIgnoreCase))
            {
                return 2;
            }

            return 1;
        }

        private static (Brush Background, Brush Border, Brush Foreground) GetSeverityPalette(string severity)
        {
            string value = NormalizeSeverity(severity);
            if (value.Contains("critical", StringComparison.OrdinalIgnoreCase) ||
                value.Contains("high", StringComparison.OrdinalIgnoreCase))
            {
                return (StatusExitedBackground, StatusExitedBorder, StatusExitedForeground);
            }
            if (value.Contains("medium", StringComparison.OrdinalIgnoreCase))
            {
                return (
                    new SolidColorBrush(Color.FromRgb(0x3D, 0x2A, 0x16)),
                    new SolidColorBrush(Color.FromRgb(0xE0, 0x9A, 0x5E)),
                    new SolidColorBrush(Color.FromRgb(0xF6, 0xD1, 0xAF)));
            }
            if (value.Contains("low", StringComparison.OrdinalIgnoreCase))
            {
                return (StatusWaitingBackground, StatusWaitingBorder, StatusWaitingForeground);
            }

            return (StatusUnknownBackground, StatusUnknownBorder, StatusUnknownForeground);
        }

        private static bool TryParseHexU32(string? text, out uint value)
        {
            value = 0;
            if (string.IsNullOrWhiteSpace(text))
            {
                return false;
            }

            string token = text.Trim();
            if (token.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            {
                token = token[2..];
            }

            int end = token.IndexOfAny(new[] { ' ', ';', ',', ')' });
            if (end >= 0)
            {
                token = token[..end];
            }

            return uint.TryParse(token, System.Globalization.NumberStyles.HexNumber, null, out value);
        }

        private void UpdateScopeStateBadge()
        {
            IntelScopeStatus status = _detailsProvider?.GetIntelScopeStatus() ?? IntelScopeStatus.Unknown;
            switch (status)
            {
            case IntelScopeStatus.Running:
                ScopeStateBlock.Text = "Running";
                ScopeStateBadge.Background = StatusRunningBackground;
                ScopeStateBadge.BorderBrush = StatusRunningBorder;
                ScopeStateBlock.Foreground = StatusRunningForeground;
                break;
            case IntelScopeStatus.Waiting:
                ScopeStateBlock.Text = "Suspended / Wait";
                ScopeStateBadge.Background = StatusWaitingBackground;
                ScopeStateBadge.BorderBrush = StatusWaitingBorder;
                ScopeStateBlock.Foreground = StatusWaitingForeground;
                break;
            case IntelScopeStatus.Exited:
                ScopeStateBlock.Text = "Exited";
                ScopeStateBadge.Background = StatusExitedBackground;
                ScopeStateBadge.BorderBrush = StatusExitedBorder;
                ScopeStateBlock.Foreground = StatusExitedForeground;
                break;
            default:
                ScopeStateBlock.Text = "Unknown";
                ScopeStateBadge.Background = StatusUnknownBackground;
                ScopeStateBadge.BorderBrush = StatusUnknownBorder;
                ScopeStateBlock.Foreground = StatusUnknownForeground;
                break;
            }
        }

        private void TabButton_Checked(object sender, RoutedEventArgs e)
        {
            if (_suppressTabEvents)
            {
                return;
            }

            if (sender is not RadioButton button ||
                button.Tag is not string tag ||
                !Enum.TryParse(tag, true, out IntelDetailsCategory category))
            {
                return;
            }

            SwitchToCategory(category);
        }

        private void Filter_Changed(object sender, EventArgs e)
        {
            if (_suppressFilterEvents)
            {
                return;
            }

            try
            {
                _view?.Refresh();
            }
            catch (Exception ex)
            {
                ReportException("Filter_Changed", ex, showDialog: false);
            }
            RefreshSummaryText();
        }

        private void ClearFilterButton_Click(object sender, RoutedEventArgs e)
        {
            _suppressFilterEvents = true;
            SearchBox.Text = string.Empty;
            EventFilterBox.SelectedIndex = 0;
            SeverityFilterBox.SelectedIndex = 0;
            DetectionFilterBox.SelectedIndex = 0;
            SourceFilterBox.SelectedIndex = 0;
            ActorFilterBox.SelectedIndex = 0;
            TargetFilterBox.SelectedIndex = 0;
            TimeWindowBox.SelectedIndex = 0;
            GroupRepeatedToggle.IsChecked = true;
            _suppressFilterEvents = false;

            _selectedSyscall = AllSyscallsLabel;
            _suppressSyscallSelectionEvents = true;
            if (SyscallGroupList.Items.Count > 0)
            {
                SyscallGroupList.SelectedIndex = 0;
            }
            _suppressSyscallSelectionEvents = false;

            try
            {
                _view?.Refresh();
            }
            catch (Exception ex)
            {
                ReportException("ClearFilterButton_Click", ex, showDialog: false);
            }
            RefreshSummaryText();
        }

        private void TimelineGrouping_Changed(object sender, RoutedEventArgs e)
        {
            if (_suppressFilterEvents)
            {
                return;
            }

            RefreshSummaryText();
        }

        private void SyscallGroupList_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (_suppressSyscallSelectionEvents)
            {
                return;
            }

            if (SyscallGroupList.SelectedItem is SyscallGroupRow selected)
            {
                _selectedSyscall = selected.Syscall;
            }
            else
            {
                _selectedSyscall = AllSyscallsLabel;
            }

            RefreshSummaryText();
        }

        private void DetailsGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (DetailsGrid.SelectedItem is TimelineRow timeline)
            {
                UpdateDeepDetail(timeline.Representative, timeline.Syscall);
                return;
            }

            UpdateDeepDetail(null);
        }

        private void TitleBar_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
        {
            if (e.LeftButton != MouseButtonState.Pressed)
            {
                return;
            }

            if (e.ClickCount >= 2)
            {
                WindowState = WindowState == WindowState.Maximized
                    ? WindowState.Normal
                    : WindowState.Maximized;
                return;
            }

            try
            {
                DragMove();
            }
            catch (Exception ex)
            {
                Debug.WriteLine("[IntelDetails][DragMove] " + ex.Message);
            }
        }

        private void WindowMinimize_Click(object sender, RoutedEventArgs e)
        {
            WindowState = WindowState.Minimized;
        }

        private void WindowMaximize_Click(object sender, RoutedEventArgs e)
        {
            WindowState = WindowState == WindowState.Maximized
                ? WindowState.Normal
                : WindowState.Maximized;
        }

        private void WindowClose_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }

        private void DetailsGrid_MouseDoubleClick(object sender, MouseButtonEventArgs e)
        {
            TimelineRow? timeline = GetRowFromSource(e.OriginalSource as DependencyObject)
                ?? DetailsGrid.SelectedItem as TimelineRow;
            GroupedEventDetailRow? row = timeline?.Representative;
            if (row == null)
            {
                return;
            }

            try
            {
                if (_activeCategory == IntelDetailsCategory.Heuristics &&
                    DirectSyscallSuspectWindow.IsDirectSyscallDetection(row.Detection))
                {
                    IReadOnlyList<GroupedEventDetailRow> related = _activeItems
                        .Where(x => string.Equals(x.Detection, row.Detection, StringComparison.OrdinalIgnoreCase))
                        .OrderByDescending(x => x.TimestampUtc)
                        .Take(4000)
                        .Select(x => x.Clone())
                        .ToList();

                    DirectSyscallSuspectWindow.ShowForGroup(this, row.Detection, related);
                    return;
                }

                EventRecordInspectorWindow.ShowForRow(
                    this,
                    GetCategoryLabel(_activeCategory),
                    row);
            }
            catch (Exception ex)
            {
                ReportException("DetailsGrid_MouseDoubleClick", ex, showDialog: true);
            }
        }

        private static TimelineRow? GetRowFromSource(DependencyObject? source)
        {
            while (source != null)
            {
                if (source is DataGridRow row && row.Item is TimelineRow timelineRow)
                {
                    return timelineRow;
                }

                source = VisualTreeHelper.GetParent(source);
            }

            return null;
        }

        private void ReportException(string context, Exception ex, bool showDialog)
        {
            string signature = $"{context}|{ex.GetType().FullName}|{ex.Message}";
            bool shouldShowDialog = showDialog ||
                                    !string.Equals(signature, _lastErrorSignature, StringComparison.Ordinal) ||
                                    (DateTime.UtcNow - _lastErrorUtc) > TimeSpan.FromSeconds(5);

            _lastErrorSignature = signature;
            _lastErrorUtc = DateTime.UtcNow;

            Debug.WriteLine($"[IntelDetails][{context}] {ex}");

            if (!Dispatcher.CheckAccess())
            {
                Dispatcher.Invoke(() => ReportException(context, ex, showDialog));
                return;
            }

            if (SummaryBlock != null)
            {
                SummaryBlock.Text = $"Error in {context}: {ex.GetType().Name}";
            }
            if (FilterStateBlock != null)
            {
                FilterStateBlock.Text = ex.Message;
            }

            if (shouldShowDialog)
            {
                MessageBox.Show(
                    this,
                    $"{context}\n\n{ex.GetType().Name}: {ex.Message}\n\n{ex.StackTrace}",
                    "Intel Details Error",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
            }
        }
    }
}
