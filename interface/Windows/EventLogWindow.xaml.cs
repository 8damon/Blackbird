using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Media;

namespace SleepwalkerInterface
{
    public sealed class EventLogCardOpenRequestedEventArgs : EventArgs
    {
        public string Group { get; }
        public string SubType { get; }
        public string Summary { get; }

        public EventLogCardOpenRequestedEventArgs(string group, string subType, string summary)
        {
            Group = group ?? string.Empty;
            SubType = subType ?? string.Empty;
            Summary = summary ?? string.Empty;
        }
    }

    public partial class EventLogWindow : Window
    {
        private readonly ObservableCollection<EventLogCardItem> _cards = new();
        private readonly ICollectionView _cardView;
        private int _rawEventCount;
        public event EventHandler<EventLogCardOpenRequestedEventArgs>? EtwFeedRequested;

        public EventLogWindow()
        {
            InitializeComponent();
            WindowThemeHelper.ApplyDarkTitleBar(this);

            EventCardList.ItemsSource = _cards;
            _cardView = CollectionViewSource.GetDefaultView(_cards);
            _cardView.Filter = FilterCard;

            GroupFilterBox.ItemsSource = new[] { "All Groups" };
            GroupFilterBox.SelectedIndex = 0;
            SubtypeFilterBox.ItemsSource = new[] { "All Subtypes" };
            SubtypeFilterBox.SelectedIndex = 0;
            SearchBox.Text = "";
            RefreshSummaryText();
        }

        public void RefreshEvents(IEnumerable<TelemetryEvent> events)
        {
            var snapshot = events?.ToList() ?? new List<TelemetryEvent>();
            _rawEventCount = snapshot.Count;

            var grouped = new Dictionary<string, EventLogCardItem>(StringComparer.OrdinalIgnoreCase);
            foreach (var ev in snapshot)
            {
                string group = string.IsNullOrWhiteSpace(ev.Group) ? "Other" : ev.Group;
                string subtype = ev.SubType ?? "";
                string summary = ev.Summary ?? "";
                string details = ev.Details ?? "";
                string key = $"{group}\u001F{subtype}\u001F{ev.PID}\u001F{ev.TID}\u001F{summary}\u001F{details}";

                if (!grouped.TryGetValue(key, out var item))
                {
                    grouped[key] = new EventLogCardItem
                    {
                        Group = group,
                        SubType = subtype,
                        PID = ev.PID,
                        TID = ev.TID,
                        Summary = summary,
                        Details = details,
                        FirstSeenUtc = ev.TimestampUtc,
                        LastSeenUtc = ev.TimestampUtc,
                        Count = 1
                    };
                }
                else
                {
                    item.Count += 1;
                    if (ev.TimestampUtc < item.FirstSeenUtc)
                    {
                        item.FirstSeenUtc = ev.TimestampUtc;
                    }
                    if (ev.TimestampUtc > item.LastSeenUtc)
                    {
                        item.LastSeenUtc = ev.TimestampUtc;
                    }
                }
            }

            _cards.Clear();
            foreach (var item in grouped.Values.OrderByDescending(x => x.LastSeenUtc))
            {
                _cards.Add(item);
            }

            RefreshFilterChoices();
            _cardView.Refresh();
            RefreshSummaryText();
            NoDataOverlay.Visibility = _cards.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        }

        private bool FilterCard(object obj)
        {
            if (obj is not EventLogCardItem card)
            {
                return false;
            }

            string selectedGroup = GroupFilterBox.SelectedItem as string ?? "All Groups";
            if (!string.Equals(selectedGroup, "All Groups", StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(card.Group, selectedGroup, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            string selectedSubtype = SubtypeFilterBox.SelectedItem as string ?? "All Subtypes";
            if (!string.Equals(selectedSubtype, "All Subtypes", StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(card.SubTypeDisplay, selectedSubtype, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            string query = SearchBox.Text?.Trim() ?? "";
            if (query.Length == 0)
            {
                return true;
            }

            return card.SearchText.Contains(query, StringComparison.OrdinalIgnoreCase);
        }

        private void Filter_Changed(object sender, EventArgs e)
        {
            _cardView.Refresh();
            RefreshSummaryText();
        }

        private void ClearFilterButton_Click(object sender, RoutedEventArgs e)
        {
            SearchBox.Text = "";
            GroupFilterBox.SelectedIndex = 0;
            SubtypeFilterBox.SelectedIndex = 0;
            _cardView.Refresh();
            RefreshSummaryText();
        }

        private void EventCardList_MouseDoubleClick(object sender, MouseButtonEventArgs e)
        {
            EventLogCardItem? card = GetCardFromEventSource(e.OriginalSource as DependencyObject)
                ?? EventCardList.SelectedItem as EventLogCardItem;
            if (card == null)
            {
                return;
            }

            EtwFeedRequested?.Invoke(this, new EventLogCardOpenRequestedEventArgs(card.Group, card.SubType, card.Summary));
        }

        private EventLogCardItem? GetCardFromEventSource(DependencyObject? source)
        {
            while (source != null)
            {
                if (source is ListViewItem item && item.DataContext is EventLogCardItem card)
                {
                    return card;
                }

                source = VisualTreeHelper.GetParent(source);
            }

            return null;
        }

        private void RefreshFilterChoices()
        {
            string previousGroup = GroupFilterBox.SelectedItem as string ?? "All Groups";
            string previousSubtype = SubtypeFilterBox.SelectedItem as string ?? "All Subtypes";

            var groups = _cards
                .Select(x => x.Group)
                .Where(x => !string.IsNullOrWhiteSpace(x))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(x => x, StringComparer.OrdinalIgnoreCase)
                .ToList();
            groups.Insert(0, "All Groups");
            GroupFilterBox.ItemsSource = groups;
            GroupFilterBox.SelectedItem = groups.Contains(previousGroup, StringComparer.OrdinalIgnoreCase)
                ? groups.First(x => string.Equals(x, previousGroup, StringComparison.OrdinalIgnoreCase))
                : "All Groups";

            var subtypes = _cards
                .Select(x => x.SubTypeDisplay)
                .Where(x => !string.IsNullOrWhiteSpace(x))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(x => x, StringComparer.OrdinalIgnoreCase)
                .ToList();
            subtypes.Insert(0, "All Subtypes");
            SubtypeFilterBox.ItemsSource = subtypes;
            SubtypeFilterBox.SelectedItem = subtypes.Contains(previousSubtype, StringComparer.OrdinalIgnoreCase)
                ? subtypes.First(x => string.Equals(x, previousSubtype, StringComparison.OrdinalIgnoreCase))
                : "All Subtypes";
        }

        private void RefreshSummaryText()
        {
            int shown = _cardView.Cast<object>().Count();
            SummaryBlock.Text = $"Grouped events: {shown} pattern(s) from {_rawEventCount} event(s)";
            string query = SearchBox.Text?.Trim() ?? "";
            string group = GroupFilterBox.SelectedItem as string ?? "All Groups";
            string subtype = SubtypeFilterBox.SelectedItem as string ?? "All Subtypes";
            FilterStateBlock.Text = $"group={group}, subtype={subtype}, query={(query.Length == 0 ? "<none>" : query)}";
        }

        private void Root_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
        {
            if (e.ChangedButton != MouseButton.Left || e.ClickCount != 1)
                return;

            try
            {
                DragMove();
            }
            catch
            {
            }
        }

        private void TopClose_Click(object sender, RoutedEventArgs e) => Close();

        private sealed class EventLogCardItem
        {
            public string Group { get; set; } = "Other";
            public string SubType { get; set; } = "";
            public int PID { get; set; }
            public int TID { get; set; }
            public string Summary { get; set; } = "";
            public string Details { get; set; } = "";
            public DateTime FirstSeenUtc { get; set; }
            public DateTime LastSeenUtc { get; set; }
            public int Count { get; set; }

            public string CountLabel => Count <= 1 ? "1x" : $"{Count}x";
            public string SubTypeDisplay => string.IsNullOrWhiteSpace(SubType) ? "(none)" : SubType;
            public string LaneLabel => string.IsNullOrWhiteSpace(SubType) ? Group : $"{Group}/{SubType}";
            public string ActorLabel => $"PID {PID}  TID {TID}";
            public string TimeLabel =>
                Count <= 1
                    ? $"{LastSeenUtc:HH:mm:ss.fff}Z"
                    : $"{FirstSeenUtc:HH:mm:ss.fff}Z → {LastSeenUtc:HH:mm:ss.fff}Z";
            public string SearchText =>
                $"{Group} {SubType} {PID} {TID} {Summary} {Details} {TimeLabel}";
        }
    }
}
