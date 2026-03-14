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

namespace BlackbirdInterface
{
    public sealed class EventLogCardOpenRequestedEventArgs : EventArgs
    {
        public string Group { get; }
        public string SubType { get; }
        public string Summary { get; }
        public string Details { get; }
        public int Pid { get; }
        public int Tid { get; }

        public EventLogCardOpenRequestedEventArgs(string group, string subType, string summary, string details, int pid, int tid)
        {
            Group = group ?? string.Empty;
            SubType = subType ?? string.Empty;
            Summary = summary ?? string.Empty;
            Details = details ?? string.Empty;
            Pid = pid;
            Tid = tid;
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
            string selectedKey = (EventCardList.SelectedItem as EventLogCardItem)?.Key ?? string.Empty;
            int selectedIndex = EventCardList.SelectedIndex;

            var grouped = new Dictionary<string, EventLogCardAggregate>(StringComparer.OrdinalIgnoreCase);
            foreach (var ev in snapshot)
            {
                string group = string.IsNullOrWhiteSpace(ev.Group) ? "Other" : ev.Group;
                string subtype = ev.SubType ?? "";
                string summary = ev.Summary ?? "";
                string details = ev.Details ?? "";
                string key = $"{group}\u001F{subtype}\u001F{ev.PID}\u001F{ev.TID}\u001F{summary}";

                if (!grouped.TryGetValue(key, out var item))
                {
                    grouped[key] = new EventLogCardAggregate
                    {
                        Key = key,
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
                        item.Details = details;
                    }
                }
            }

            var validKeys = new HashSet<string>(grouped.Keys, StringComparer.OrdinalIgnoreCase);
            for (int i = _cards.Count - 1; i >= 0; i -= 1)
            {
                if (!validKeys.Contains(_cards[i].Key))
                {
                    _cards.RemoveAt(i);
                }
            }

            var cardsByKey = _cards.ToDictionary(x => x.Key, x => x, StringComparer.OrdinalIgnoreCase);
            var orderedAggregates = grouped.Values
                .OrderByDescending(x => x.LastSeenUtc)
                .ToList();
            var nextOrder = new List<EventLogCardItem>(orderedAggregates.Count);
            foreach (EventLogCardAggregate aggregate in orderedAggregates)
            {
                EventLogCardItem card;
                if (!string.IsNullOrWhiteSpace(selectedKey) &&
                    string.Equals(aggregate.Key, selectedKey, StringComparison.OrdinalIgnoreCase) &&
                    cardsByKey.TryGetValue(selectedKey, out EventLogCardItem? selectedExisting))
                {
                    card = selectedExisting;
                }
                else if (!cardsByKey.TryGetValue(aggregate.Key, out card!))
                {
                    card = new EventLogCardItem();
                }

                PopulateCard(card, aggregate);
                nextOrder.Add(card);
            }

            if (!string.IsNullOrWhiteSpace(selectedKey) && selectedIndex >= 0)
            {
                int selectedPos = nextOrder.FindIndex(x => string.Equals(x.Key, selectedKey, StringComparison.OrdinalIgnoreCase));
                if (selectedPos >= 0)
                {
                    EventLogCardItem selectedCard = nextOrder[selectedPos];
                    nextOrder.RemoveAt(selectedPos);
                    int pinnedIndex = Math.Min(selectedIndex, nextOrder.Count);
                    nextOrder.Insert(pinnedIndex, selectedCard);
                }
            }

            for (int i = 0; i < nextOrder.Count; i += 1)
            {
                EventLogCardItem desired = nextOrder[i];
                if (i >= _cards.Count)
                {
                    _cards.Add(desired);
                    continue;
                }

                if (ReferenceEquals(_cards[i], desired))
                {
                    continue;
                }

                int currentIndex = _cards.IndexOf(desired);
                if (currentIndex >= 0)
                {
                    _cards.Move(currentIndex, i);
                }
                else
                {
                    _cards.Insert(i, desired);
                }
            }

            while (_cards.Count > nextOrder.Count)
            {
                _cards.RemoveAt(_cards.Count - 1);
            }

            RefreshFilterChoices();
            _cardView.Refresh();
            if (!string.IsNullOrWhiteSpace(selectedKey))
            {
                EventLogCardItem? selected = _cards.FirstOrDefault(x => string.Equals(x.Key, selectedKey, StringComparison.OrdinalIgnoreCase));
                if (selected != null)
                {
                    EventCardList.SelectedItem = selected;
                    EventCardList.ScrollIntoView(selected);
                }
            }
            RefreshSummaryText();
            NoDataOverlay.Visibility = _cards.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        }

        private static void PopulateCard(EventLogCardItem card, EventLogCardAggregate aggregate)
        {
            card.Key = aggregate.Key;
            card.Group = aggregate.Group;
            card.SubType = aggregate.SubType;
            card.PID = aggregate.PID;
            card.TID = aggregate.TID;
            card.Summary = aggregate.Summary;
            card.Details = aggregate.Details;
            card.FirstSeenUtc = aggregate.FirstSeenUtc;
            card.LastSeenUtc = aggregate.LastSeenUtc;
            card.Count = aggregate.Count;
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

            EtwFeedRequested?.Invoke(
                this,
                new EventLogCardOpenRequestedEventArgs(card.Group, card.SubType, card.Summary, card.Details, card.PID, card.TID));
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
            WindowChromeBehavior.HandleRootDragMove(this, e);
        }

        private void TopClose_Click(object sender, RoutedEventArgs e) => Close();

        private sealed class EventLogCardItem
        {
            public string Key { get; set; } = "";
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

        private sealed class EventLogCardAggregate
        {
            public string Key { get; set; } = "";
            public string Group { get; set; } = "Other";
            public string SubType { get; set; } = "";
            public int PID { get; set; }
            public int TID { get; set; }
            public string Summary { get; set; } = "";
            public string Details { get; set; } = "";
            public DateTime FirstSeenUtc { get; set; }
            public DateTime LastSeenUtc { get; set; }
            public int Count { get; set; }
        }
    }
}
