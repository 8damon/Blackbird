using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;

namespace BlackbirdInterface
{
    public partial class LaneSettingsWindow : Window
    {
        private readonly MainWindow _host;
        private readonly ObservableCollection<LaneFilterRule> _rules = new();
        private readonly ObservableCollection<LaneStateRow> _lanes = new();
        private Brush _laneEnabledRowBrush = Brushes.Transparent;
        private Brush _laneDisabledRowBrush = Brushes.Transparent;

        public LaneSettingsWindow(MainWindow host)
        {
            InitializeComponent();
            WindowThemeHelper.WireThemeAwareTitleBar(this);
            _host = host ?? throw new ArgumentNullException(nameof(host));
            RulesGrid.ItemsSource = _rules;
            LaneGrid.ItemsSource = _lanes;
            RefreshThemePalette();

            Loaded += (_, __) =>
            {
                RefreshLaneList();
                PopulateRuleValueChoices();
                ApplyRules();
            };
            Closed += (_, __) => App.ThemeChanged -= OnThemeChanged;
            App.ThemeChanged += OnThemeChanged;
        }

        private void Root_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
        {
            WindowChromeBehavior.HandleRootDragMove(this, e);
        }

        private void Refresh_Click(object sender, RoutedEventArgs e)
        {
            RefreshLaneList();
            ApplyRules();
        }

        private void RuleValueBox_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key != Key.Enter)
                return;

            AddRule_Click(sender, new RoutedEventArgs());
            e.Handled = true;
        }

        private void AddRule_Click(object sender, RoutedEventArgs e)
        {
            string field = (RuleFieldBox.SelectedItem as ComboBoxItem)?.Content?.ToString() ?? "Lane";
            string relation = (RuleRelationBox.SelectedItem as ComboBoxItem)?.Content?.ToString() ?? "contains";
            string action = (RuleActionBox.SelectedItem as ComboBoxItem)?.Content?.ToString() ?? "Include";
            string value = (RuleValueBox.SelectedItem as string) ?? RuleValueBox.Text?.Trim() ?? "";

            if (string.IsNullOrWhiteSpace(value))
                return;

            _rules.Add(new LaneFilterRule { Enabled = true, Field = field, Relation = relation, Value = value,
                                            Action = action });

            RuleValueBox.SelectedItem = null;
            RuleValueBox.Text = "";
            ApplyRules();
        }

        private void RuleFieldBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            PopulateRuleValueChoices();
        }

        private void RemoveRule_Click(object sender, RoutedEventArgs e)
        {
            if (RulesGrid.SelectedItem is not LaneFilterRule rule)
                return;

            _rules.Remove(rule);
            ApplyRules();
        }

        private void MoveRuleUp_Click(object sender, RoutedEventArgs e) => MoveRule(-1);
        private void MoveRuleDown_Click(object sender, RoutedEventArgs e) => MoveRule(1);
        private void RuleEnabled_Click(object sender, RoutedEventArgs e) => ApplyRules();

        private void ClearRules_Click(object sender, RoutedEventArgs e)
        {
            _rules.Clear();
            ApplyRules();
        }

        private void ApplyFilters_Click(object sender, RoutedEventArgs e) => ApplyRules();

        private void MoveRule(int delta)
        {
            if (RulesGrid.SelectedItem is not LaneFilterRule rule)
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
            ApplyRules();
        }

        private void RefreshLaneList()
        {
            var keys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var obj in _host.EventsPaneHost.Timeline.Items)
            {
                if (obj is not TelemetryEvent te)
                    continue;

                string key = string.IsNullOrWhiteSpace(te.SubType) ? te.Group : $"{te.Group}/{te.SubType}";

                if (!string.IsNullOrWhiteSpace(key))
                    keys.Add(key);
            }

            _lanes.Clear();
            foreach (var key in keys.OrderBy(k => k, StringComparer.OrdinalIgnoreCase))
            {
                string group = key.Contains('/') ? key.Split('/')[0] : key;
                _lanes.Add(new LaneStateRow { Key = key, Group = group });
            }

            PopulateRuleValueChoices();
        }

        private void PopulateRuleValueChoices()
        {
            if (RuleValueBox == null)
            {
                return;
            }

            string selectedField = (RuleFieldBox.SelectedItem as ComboBoxItem)?.Content?.ToString() ?? "Lane";
            string priorText = (RuleValueBox.SelectedItem as string) ?? RuleValueBox.Text ?? string.Empty;

            IEnumerable<string> values = selectedField.Equals("Group", StringComparison.OrdinalIgnoreCase)
                                             ? _lanes.Select(x => x.Group)
                                                   .Where(x => !string.IsNullOrWhiteSpace(x))
                                                   .Distinct(StringComparer.OrdinalIgnoreCase)
                                             : _lanes.Select(x => x.Key)
                                                   .Where(x => !string.IsNullOrWhiteSpace(x))
                                                   .Distinct(StringComparer.OrdinalIgnoreCase);

            var ordered = values.OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToList();
            RuleValueBox.ItemsSource = ordered;

            if (ordered.Count == 0)
            {
                RuleValueBox.SelectedItem = null;
                RuleValueBox.Text = string.Empty;
                return;
            }

            string? exact =
                ordered.FirstOrDefault(x => string.Equals(x, priorText, StringComparison.OrdinalIgnoreCase));
            if (exact != null)
            {
                RuleValueBox.SelectedItem = exact;
                return;
            }

            RuleValueBox.SelectedItem = null;
            RuleValueBox.Text = string.Empty;
        }

        private void ApplyRules()
        {
            var active = _rules.Where(r => r.Enabled).ToList();
            bool hasInclude = active.Any(r => r.Action.Equals("Include", StringComparison.OrdinalIgnoreCase));

            foreach (var lane in _lanes)
            {
                bool state = !hasInclude;
                string source = hasInclude ? "Default off" : "Default on";

                foreach (var rule in active)
                {
                    if (!RuleMatches(lane, rule))
                        continue;

                    state = rule.Action.Equals("Include", StringComparison.OrdinalIgnoreCase);
                    source = $"{rule.Action}: {rule.Relation} '{rule.Value}'";
                }

                lane.State = state ? "On" : "Off";
                lane.Source = source;
                lane.RowBackground = state ? _laneEnabledRowBrush : _laneDisabledRowBrush;

                _host.EventsPaneHost.Timeline.SetLaneVisible(lane.Key, state);
            }

            // keep active focus if still visible
            _host.SetLaneFocus(_host.GetLaneFocus());
            LaneGrid.Items.Refresh();
        }

        private static bool RuleMatches(LaneStateRow lane, LaneFilterRule rule)
        {
            string left = rule.Field.Equals("Group", StringComparison.OrdinalIgnoreCase) ? lane.Group : lane.Key;
            string right = rule.Value ?? "";
            string relation = rule.Relation?.Trim().ToLowerInvariant() ?? "contains";

            return relation switch { "is" => string.Equals(left, right, StringComparison.OrdinalIgnoreCase),
                                     "contains" => left.Contains(right, StringComparison.OrdinalIgnoreCase),
                                     "begins with" => left.StartsWith(right, StringComparison.OrdinalIgnoreCase),
                                     "ends with" => left.EndsWith(right, StringComparison.OrdinalIgnoreCase),
                                     _ => left.Contains(right, StringComparison.OrdinalIgnoreCase) };
        }

        private void LaneGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (LaneGrid.SelectedItem is not LaneStateRow row)
                return;

            _host.SetLaneFocus(row.State.Equals("On", StringComparison.OrdinalIgnoreCase) ? row.Key : null);
        }

        private void Close_Click(object sender, RoutedEventArgs e) => Close();

        private void OnThemeChanged(bool _)
        {
            Dispatcher.BeginInvoke(new Action(() =>
                                              {
                                                  RefreshThemePalette();
                                                  ApplyRules();
                                              }),
                                   DispatcherPriority.Background);
        }

        private void RefreshThemePalette()
        {
            _laneEnabledRowBrush = ResolveBrush("LaneRowEnabledBrush", Color.FromArgb(0x2A, 0x28, 0x5B, 0x2E));
            _laneDisabledRowBrush = ResolveBrush("LaneRowDisabledBrush", Color.FromArgb(0x2A, 0x5B, 0x28, 0x28));
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
    }

    public sealed class LaneFilterRule
    {
        public bool Enabled { get; set; } = true;
        public string Field { get; set; } = "Lane";
        public string Relation { get; set; } = "contains";
        public string Value { get; set; } = "";
        public string Action { get; set; } = "Include";
    }

    public sealed class LaneStateRow
    {
        public string Key { get; set; } = "";
        public string Group { get; set; } = "";
        public string State { get; set; } = "On";
        public string Source { get; set; } = "";
        public Brush RowBackground { get; set; } = Brushes.Transparent;
    }
}
