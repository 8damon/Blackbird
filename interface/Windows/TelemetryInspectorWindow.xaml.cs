using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Windows;
using System.Windows.Data;

namespace BlackbirdInterface
{
    public partial class TelemetryInspectorWindow : Window
    {
        private static readonly string[] SeverityFilters =
        {
            "All",
            "Critical",
            "High",
            "Medium",
            "Low",
            "Info",
            "Unknown"
        };

        private readonly ObservableCollection<GroupedEventRow> _groups = new();
        private readonly ObservableCollection<GroupedEventDetailRow> _details = new();
        private readonly ObservableCollection<InspectorFieldNode> _fieldNodes = new();
        private readonly ICollectionView _groupView;
        private readonly Func<uint, uint, IoctlParsedEvent?>? _handleEvidenceResolver;
        private IoctlParsedEvent? _selectedHandleEvidence;
        private int _severityFilterIndex;
        private string _selectedRawText = string.Empty;

        private TelemetryInspectorWindow(
            string title,
            string subtitle,
            IEnumerable<GroupedEventRow> groups,
            GroupedEventRow? selectedGroup,
            Func<uint, uint, IoctlParsedEvent?>? handleEvidenceResolver)
        {
            InitializeComponent();
            WindowThemeHelper.ApplyDarkTitleBar(this);

            Title = string.IsNullOrWhiteSpace(title) ? "Telemetry Inspector" : title.Trim();
            HeaderBlock.Text = Title;
            SummaryBlock.Text = string.IsNullOrWhiteSpace(subtitle) ? "No telemetry available" : subtitle.Trim();
            _handleEvidenceResolver = handleEvidenceResolver;

            GroupsGrid.ItemsSource = _groups;
            DetailsGrid.ItemsSource = _details;
            FieldsTreeView.ItemsSource = _fieldNodes;

            _groupView = CollectionViewSource.GetDefaultView(_groups);
            _groupView.Filter = FilterGroup;

            foreach (GroupedEventRow row in groups
                         .Select(x => x.Clone())
                         .OrderByDescending(x => x.LastSeenUtc)
                         .ThenBy(x => x.Event, StringComparer.OrdinalIgnoreCase))
            {
                _groups.Add(row);
            }

            UpdateSeverityFilterLabel();
            RefreshWindowSummary();
            SelectInitialGroup(selectedGroup?.GroupKey);
        }

        internal static void ShowForRows(
            Window? owner,
            string title,
            string subtitle,
            IEnumerable<GroupedEventRow> groups,
            GroupedEventRow? selectedGroup,
            Func<uint, uint, IoctlParsedEvent?>? handleEvidenceResolver)
        {
            var window = new TelemetryInspectorWindow(title, subtitle, groups, selectedGroup, handleEvidenceResolver);
            if (owner != null && !ReferenceEquals(owner, window))
            {
                window.Owner = owner;
            }

            window.Show();
            window.Activate();
        }

        private void RefreshWindowSummary()
        {
            List<GroupedEventRow> visibleGroups = _groupView.Cast<GroupedEventRow>().ToList();
            GroupCountBlock.Text = visibleGroups.Count.ToString(CultureInfo.InvariantCulture);
            OccurrenceCountBlock.Text = visibleGroups
                .Sum(x => x.Details.Count == 0 ? Math.Max(1, x.Hits) : x.Details.Count)
                .ToString(CultureInfo.InvariantCulture);

            if (visibleGroups.Count == 0)
            {
                WindowRangeBlock.Text = "-";
                SelectionBlock.Text = "-";
                SelectionTimeBlock.Text = "-";
                return;
            }

            DateTime first = visibleGroups
                .SelectMany(x => x.Details.Count == 0 ? new[] { x.LastSeenUtc } : x.Details.Select(d => d.TimestampUtc))
                .DefaultIfEmpty(DateTime.UtcNow)
                .Min();
            DateTime last = visibleGroups
                .SelectMany(x => x.Details.Count == 0 ? new[] { x.LastSeenUtc } : x.Details.Select(d => d.TimestampUtc))
                .DefaultIfEmpty(DateTime.UtcNow)
                .Max();
            WindowRangeBlock.Text = $"{first:HH:mm:ss.fff} - {last:HH:mm:ss.fff}";
        }

        private bool FilterGroup(object obj)
        {
            if (obj is not GroupedEventRow row)
            {
                return false;
            }

            string selectedSeverity = SeverityFilters[_severityFilterIndex];
            if (!selectedSeverity.Equals("All", StringComparison.OrdinalIgnoreCase) &&
                !row.Severity.Equals(selectedSeverity, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            string query = (SearchBox.Text ?? string.Empty).Trim();
            if (query.Length == 0)
            {
                return true;
            }

            if (row.Event.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                row.Detection.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                row.Severity.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                row.GroupKey.Contains(query, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            return row.Details.Any(x => x.FilterText.Contains(query, StringComparison.OrdinalIgnoreCase));
        }

        private void SelectInitialGroup(string? preferredGroupKey)
        {
            _groupView.Refresh();

            GroupedEventRow? match = null;
            if (!string.IsNullOrWhiteSpace(preferredGroupKey))
            {
                match = _groups.FirstOrDefault(x => string.Equals(x.GroupKey, preferredGroupKey, StringComparison.Ordinal));
            }

            match ??= _groupView.Cast<GroupedEventRow>().FirstOrDefault();
            if (match != null)
            {
                GroupsGrid.SelectedItem = match;
                GroupsGrid.ScrollIntoView(match);
                return;
            }

            UpdateDetails(null);
        }

        private void SearchBox_TextChanged(object sender, System.Windows.Controls.TextChangedEventArgs e)
        {
            _ = sender;
            _ = e;
            ApplyGroupFilter();
        }

        private void SeverityFilterButton_Click(object sender, RoutedEventArgs e)
        {
            _ = sender;
            _ = e;
            _severityFilterIndex = (_severityFilterIndex + 1) % SeverityFilters.Length;
            UpdateSeverityFilterLabel();
            ApplyGroupFilter();
        }

        private void UpdateSeverityFilterLabel()
        {
            SeverityFilterButton.Content = $"Severity: {SeverityFilters[_severityFilterIndex]}";
        }

        private void ApplyGroupFilter()
        {
            _groupView.Refresh();
            RefreshWindowSummary();

            if (GroupsGrid.SelectedItem is not GroupedEventRow selected ||
                !_groupView.Cast<GroupedEventRow>().Contains(selected))
            {
                GroupsGrid.SelectedItem = _groupView.Cast<GroupedEventRow>().FirstOrDefault();
            }

            if (GroupsGrid.SelectedItem == null)
            {
                UpdateDetails(null);
            }
        }

        private void GroupsGrid_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
        {
            _ = sender;
            _ = e;
            UpdateDetails(GroupsGrid.SelectedItem as GroupedEventRow);
        }

        private void DetailsGrid_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
        {
            _ = sender;
            _ = e;
            UpdateSelectedDetail(DetailsGrid.SelectedItem as GroupedEventDetailRow);
        }

        private void UpdateDetails(GroupedEventRow? group)
        {
            _details.Clear();

            if (group == null)
            {
                SelectionBlock.Text = "-";
                DetailCountBlock.Text = "0 detail rows";
                SelectionTimeBlock.Text = "-";
                UpdateSelectedDetail(null);
                return;
            }

            SelectionBlock.Text = $"{group.Event} / {group.Detection}";
            SelectionTimeBlock.Text = group.LastSeenUtc == default ? "-" : group.LastSeenUtc.ToString("HH:mm:ss.fff");

            foreach (GroupedEventDetailRow detail in group.Details
                         .Select(x => x.Clone())
                         .OrderByDescending(x => x.TimestampUtc))
            {
                _details.Add(detail);
            }

            DetailCountBlock.Text = $"{_details.Count.ToString(CultureInfo.InvariantCulture)} detail row{(_details.Count == 1 ? string.Empty : "s")}";
            DetailsGrid.SelectedIndex = _details.Count == 0 ? -1 : 0;
            if (_details.Count == 0)
            {
                UpdateSelectedDetail(null);
            }
        }

        private void UpdateSelectedDetail(GroupedEventDetailRow? detail)
        {
            _fieldNodes.Clear();
            _selectedHandleEvidence = null;
            _selectedRawText = string.Empty;

            if (detail == null)
            {
                return;
            }

            Dictionary<string, string> parsed = EventDetailsParsing.ParseRawFields(detail.Details);
            uint actorPid = ResolveActorPid(detail, parsed);
            uint targetPid = ResolveTargetPid(detail, parsed);
            _selectedRawText = detail.Details ?? string.Empty;

            if (_handleEvidenceResolver != null && actorPid != 0 && targetPid != 0)
            {
                _selectedHandleEvidence = _handleEvidenceResolver(actorPid, targetPid);
            }

            string disassembly = BuildDisassemblyText(detail, parsed, _selectedHandleEvidence);
            List<InspectorStackRow> stackRows = BuildStackRows(parsed, _selectedHandleEvidence);
            BuildFieldTree(detail, parsed, actorPid, targetPid, stackRows, disassembly, _selectedRawText, _selectedHandleEvidence != null);
        }

        private void BuildFieldTree(
            GroupedEventDetailRow detail,
            Dictionary<string, string> parsed,
            uint actorPid,
            uint targetPid,
            IReadOnlyList<InspectorStackRow> stackRows,
            string disassembly,
            string rawText,
            bool hasHandleEvidence)
        {
            _fieldNodes.Clear();

            InspectorFieldNode AddSection(string name, bool expanded = true)
            {
                var node = new InspectorFieldNode
                {
                    Name = name,
                    Kind = "section",
                    IsExpanded = expanded
                };
                _fieldNodes.Add(node);
                return node;
            }

            static void AddPair(InspectorFieldNode parent, string name, string value)
            {
                if (string.IsNullOrWhiteSpace(value))
                {
                    return;
                }

                parent.Children.Add(new InspectorFieldNode
                {
                    Name = name,
                    Value = value.Trim(),
                    Kind = "pair"
                });
            }

            static void AddLine(InspectorFieldNode parent, string value, string kind = "line")
            {
                if (string.IsNullOrWhiteSpace(value))
                {
                    return;
                }

                parent.Children.Add(new InspectorFieldNode
                {
                    Value = value,
                    Kind = kind
                });
            }

            InspectorFieldNode selection = AddSection("Frame");
            AddLine(selection, $"{detail.Event} / {detail.Detection}", "note");
            AddPair(selection, "Timestamp", detail.TimestampUtc == default ? "-" : detail.TimestampUtc.ToString("O"));
            AddPair(selection, "Severity", detail.Severity);
            AddPair(selection, "Source", detail.Source);
            AddPair(selection, "Actor", detail.Actor);
            AddPair(selection, "Target", detail.Target);
            AddPair(selection, "Actor PID", actorPid == 0 ? "-" : actorPid.ToString(CultureInfo.InvariantCulture));
            AddPair(selection, "Target PID", targetPid == 0 ? "-" : targetPid.ToString(CultureInfo.InvariantCulture));
            AddPair(selection, "Argument Summary", detail.ArgumentSummary);
            if (detail.HitCount > 1)
            {
                AddPair(selection, "Occurrences", detail.HitCount.ToString(CultureInfo.InvariantCulture));
            }
            AddPair(selection, "Reason", EventDetailsParsing.FallbackText(detail.Reason));
            AddPair(selection, "Correlated Handle Evidence", hasHandleEvidence ? "Available" : "None");

            foreach (string category in parsed.Keys
                         .Select(CategoryForKey)
                         .Distinct(StringComparer.OrdinalIgnoreCase)
                         .OrderBy(CategoryRank)
                         .ThenBy(x => x, StringComparer.OrdinalIgnoreCase))
            {
                InspectorFieldNode section = AddSection(category, false);
                foreach ((string key, string value) in parsed
                             .Where(x => string.Equals(CategoryForKey(x.Key), category, StringComparison.OrdinalIgnoreCase))
                             .OrderBy(x => x.Key, StringComparer.OrdinalIgnoreCase))
                {
                    AddPair(section, key, value);
                }
            }

            InspectorFieldNode stackSection = AddSection("Captured Stack");
            if (stackRows.Count == 0)
            {
                AddLine(stackSection, "No captured stack frames for this occurrence.", "note");
            }
            else
            {
                foreach (InspectorStackRow row in stackRows)
                {
                    AddPair(stackSection, $"[{row.Index}] {row.Notes}", row.Address);
                }
            }

            InspectorFieldNode disassemblySection = AddSection("Disassembly");
            foreach (string line in SplitLines(disassembly))
            {
                AddLine(disassemblySection, line, line.StartsWith("summary:", StringComparison.OrdinalIgnoreCase) ? "note" : "line");
            }

            InspectorFieldNode rawSection = AddSection("Raw", false);
            foreach (string line in WrapRawForTree(rawText))
            {
                AddLine(rawSection, line);
            }
        }

        private List<InspectorStackRow> BuildStackRows(Dictionary<string, string> parsed, IoctlParsedEvent? evidence)
        {
            var rows = new List<InspectorStackRow>();
            int index = 0;

            foreach ((string key, string value) in parsed
                         .Where(x => IsCapturedStackFrameKey(x.Key))
                         .OrderBy(x => StackFrameSortKey(x.Key))
                         .ThenBy(x => x.Key, StringComparer.OrdinalIgnoreCase))
            {
                if (string.IsNullOrWhiteSpace(value) ||
                    value.Equals("<none>", StringComparison.OrdinalIgnoreCase) ||
                    value.Equals("0x0", StringComparison.OrdinalIgnoreCase) ||
                    value.Equals("0", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                rows.Add(new InspectorStackRow
                {
                    Index = index.ToString(CultureInfo.InvariantCulture),
                    Address = value,
                    Notes = key
                });
                index += 1;
            }

            if (parsed.TryGetValue("fullFrames", out string? fullFrames) &&
                !string.IsNullOrWhiteSpace(fullFrames) &&
                !fullFrames.Equals("<none>", StringComparison.OrdinalIgnoreCase))
            {
                foreach (string frame in fullFrames.Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                {
                    if (frame.Equals("0x0", StringComparison.OrdinalIgnoreCase) || frame.Equals("0", StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    rows.Add(new InspectorStackRow
                    {
                        Index = index.ToString(CultureInfo.InvariantCulture),
                        Address = frame,
                        Notes = "fullFrames"
                    });
                    index += 1;
                }
            }

            if (evidence == null || rows.Count != 0)
            {
                return rows;
            }

            AppendHandleFrames(rows, evidence.Frames, evidence.FrameCount, "frames", ref index);
            AppendHandleFrames(rows, evidence.FullFrames, evidence.FullFrameCount, "fullFrames", ref index);
            AppendHandleFrames(rows, evidence.ThreadFrames, evidence.ThreadFrameCount, "threadFrames", ref index);
            return rows;
        }

        private static void AppendHandleFrames(List<InspectorStackRow> rows, ulong[]? frames, uint count, string notes, ref int index)
        {
            if (frames == null || frames.Length == 0 || count == 0)
            {
                return;
            }

            int safeCount = Math.Min(frames.Length, (int)count);
            for (int i = 0; i < safeCount; i += 1)
            {
                if (frames[i] == 0)
                {
                    continue;
                }

                rows.Add(new InspectorStackRow
                {
                    Index = index.ToString(CultureInfo.InvariantCulture),
                    Address = $"0x{frames[i]:X}",
                    Notes = notes
                });
                index += 1;
            }
        }

        private string BuildDisassemblyText(GroupedEventDetailRow detail, Dictionary<string, string> parsed, IoctlParsedEvent? evidence)
        {
            if (evidence != null)
            {
                return EventDetailFormatting.FormatSampleDisassembly(
                    evidence.DeepSample,
                    (int)evidence.DeepSampleSize,
                    evidence.OriginAddress,
                    evidence.OriginPath,
                    evidence.DeepAllocationBase,
                    evidence.DeepRegionSize,
                    evidence.DeepRegionProtect,
                    evidence.DeepRegionState,
                    evidence.DeepRegionType);
            }

            byte[] sample = ParseHexBytes(parsed.TryGetValue("deepSample", out string? sampleHex) ? sampleHex : null);
            if (sample.Length != 0)
            {
                ulong origin = ParseHexU64(parsed, "origin");
                ulong regionBase = ParseHexU64(parsed, "deepAllocationBase");
                ulong regionSize = ParseHexU64(parsed, "deepRegionSize");
                uint regionProtect = ParseHexU32(parsed, "deepRegionProtect");
                uint regionState = ParseHexU32(parsed, "deepRegionState");
                uint regionType = ParseHexU32(parsed, "deepRegionType");
                string modulePath = parsed.TryGetValue("originPath", out string? originPath) && !string.IsNullOrWhiteSpace(originPath)
                    ? originPath
                    : detail.Target;

                return EventDetailFormatting.FormatSampleDisassembly(
                    sample,
                    sample.Length,
                    origin,
                    modulePath,
                    regionBase,
                    regionSize,
                    regionProtect,
                    regionState,
                    regionType);
            }

            if (parsed.TryGetValue("reason", out string? reason) && !string.IsNullOrWhiteSpace(reason))
            {
                return $"summary: {reason}";
            }

            return "summary: no captured code bytes were attached to this occurrence";
        }

        private static string CategoryForKey(string key)
        {
            string normalized = key.Trim();
            if (normalized.StartsWith("task", StringComparison.OrdinalIgnoreCase) ||
                normalized.StartsWith("opcode", StringComparison.OrdinalIgnoreCase) ||
                normalized.StartsWith("id", StringComparison.OrdinalIgnoreCase) ||
                normalized.StartsWith("event", StringComparison.OrdinalIgnoreCase) ||
                normalized.StartsWith("severity", StringComparison.OrdinalIgnoreCase) ||
                normalized.StartsWith("source", StringComparison.OrdinalIgnoreCase) ||
                normalized.StartsWith("family", StringComparison.OrdinalIgnoreCase))
            {
                return "Header";
            }

            if (normalized.StartsWith("actor", StringComparison.OrdinalIgnoreCase) ||
                normalized.StartsWith("target", StringComparison.OrdinalIgnoreCase) ||
                normalized.StartsWith("process", StringComparison.OrdinalIgnoreCase) ||
                normalized.StartsWith("thread", StringComparison.OrdinalIgnoreCase) ||
                normalized.StartsWith("caller", StringComparison.OrdinalIgnoreCase) ||
                normalized.StartsWith("creator", StringComparison.OrdinalIgnoreCase) ||
                normalized.StartsWith("parent", StringComparison.OrdinalIgnoreCase) ||
                normalized.StartsWith("session", StringComparison.OrdinalIgnoreCase))
            {
                return "Identity";
            }

            if (normalized.StartsWith("corr", StringComparison.OrdinalIgnoreCase) ||
                normalized.StartsWith("reason", StringComparison.OrdinalIgnoreCase) ||
                normalized.StartsWith("detection", StringComparison.OrdinalIgnoreCase))
            {
                return "Detection";
            }

            if (normalized.StartsWith("class", StringComparison.OrdinalIgnoreCase) ||
                normalized.StartsWith("desiredAccess", StringComparison.OrdinalIgnoreCase) ||
                normalized.StartsWith("origin", StringComparison.OrdinalIgnoreCase) ||
                normalized.StartsWith("deep", StringComparison.OrdinalIgnoreCase) ||
                normalized.StartsWith("status", StringComparison.OrdinalIgnoreCase) ||
                normalized.StartsWith("capture", StringComparison.OrdinalIgnoreCase))
            {
                return "Handle";
            }

            if (normalized.StartsWith("start", StringComparison.OrdinalIgnoreCase) ||
                normalized.StartsWith("image", StringComparison.OrdinalIgnoreCase) ||
                normalized.StartsWith("stack", StringComparison.OrdinalIgnoreCase) ||
                normalized.StartsWith("fullFrames", StringComparison.OrdinalIgnoreCase))
            {
                return "Execution";
            }

            if (normalized.StartsWith("key", StringComparison.OrdinalIgnoreCase) ||
                normalized.StartsWith("value", StringComparison.OrdinalIgnoreCase) ||
                normalized.StartsWith("notify", StringComparison.OrdinalIgnoreCase) ||
                normalized.StartsWith("data", StringComparison.OrdinalIgnoreCase))
            {
                return "Registry";
            }

            return "Other";
        }

        private static int CategoryRank(string category)
        {
            return category switch
            {
                "Header" => 0,
                "Identity" => 1,
                "Detection" => 2,
                "Handle" => 3,
                "Execution" => 4,
                "Registry" => 5,
                _ => 6
            };
        }

        private void ExpandAll_Click(object sender, RoutedEventArgs e)
        {
            _ = sender;
            _ = e;
            SetTreeExpansion(_fieldNodes, true);
        }

        private void CollapseAll_Click(object sender, RoutedEventArgs e)
        {
            _ = sender;
            _ = e;
            SetTreeExpansion(_fieldNodes, false);
        }

        private void CopyVisible_Click(object sender, RoutedEventArgs e)
        {
            _ = sender;
            _ = e;
            var sb = new StringBuilder();
            foreach (InspectorFieldNode node in _fieldNodes)
            {
                AppendFieldNode(sb, node, 0);
            }
            Clipboard.SetText(sb.ToString().Trim());
        }

        private void CopyRaw_Click(object sender, RoutedEventArgs e)
        {
            _ = sender;
            _ = e;
            Clipboard.SetText(_selectedRawText);
        }

        private static void AppendFieldNode(StringBuilder sb, InspectorFieldNode node, int depth)
        {
            string indent = new string(' ', depth * 2);
            string label = node.Kind switch
            {
                "section" => node.Name,
                "pair" => $"{node.Name}: {node.Value}",
                _ => node.Value
            };

            sb.Append(indent).AppendLine(label);
            foreach (InspectorFieldNode child in node.Children)
            {
                AppendFieldNode(sb, child, depth + 1);
            }
        }

        private static void SetTreeExpansion(IEnumerable<InspectorFieldNode> nodes, bool isExpanded)
        {
            foreach (InspectorFieldNode node in nodes)
            {
                node.IsExpanded = isExpanded;
                SetTreeExpansion(node.Children, isExpanded);
            }
        }

        private static uint ResolveActorPid(GroupedEventDetailRow detail, IReadOnlyDictionary<string, string> parsed)
        {
            return ResolvePid(detail.ActorPid, detail.Actor, parsed, "actor", "sourcePid", "caller", "callerPid", "creator", "creatorPid");
        }

        private static uint ResolveTargetPid(GroupedEventDetailRow detail, IReadOnlyDictionary<string, string> parsed)
        {
            return ResolvePid(detail.TargetPid, detail.Target, parsed, "target", "targetPid", "explicitTargetPid");
        }

        private static uint ResolvePid(
            uint explicitPid,
            string identityText,
            IReadOnlyDictionary<string, string> parsed,
            params string[] keys)
        {
            if (explicitPid != 0)
            {
                return explicitPid;
            }

            foreach (string key in keys)
            {
                if (parsed.TryGetValue(key, out string? value))
                {
                    if (EventDetailsParsing.TryParseUInt(value, out uint parsedPid) && parsedPid != 0)
                    {
                        return parsedPid;
                    }

                    if (EventDetailsParsing.TryParsePidFromIdentity(value, out parsedPid) && parsedPid != 0)
                    {
                        return parsedPid;
                    }
                }
            }

            return EventDetailsParsing.TryParsePidFromIdentity(identityText, out uint identityPid) ? identityPid : 0;
        }

        private void OpenHandleWindowButton_Click(object sender, RoutedEventArgs e)
        {
            _ = sender;
            _ = e;
            if (_selectedHandleEvidence == null)
            {
                return;
            }

            string context = DetailsGrid.SelectedItem is GroupedEventDetailRow detail
                ? $"{detail.Detection} / {detail.Actor} -> {detail.Target}"
                : "Correlated handle evidence";
            HandleEvidenceWindow.ShowForEvidence(this, context, _selectedHandleEvidence.Clone());
        }

        private static byte[] ParseHexBytes(string? hex)
        {
            if (string.IsNullOrWhiteSpace(hex) || hex.Equals("<none>", StringComparison.OrdinalIgnoreCase))
            {
                return Array.Empty<byte>();
            }

            var bytes = new List<byte>();
            foreach (string token in hex.Split(new[] { ' ', '\t', '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
            {
                if (byte.TryParse(token, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out byte parsed))
                {
                    bytes.Add(parsed);
                }
            }

            return bytes.ToArray();
        }

        private static uint ParseHexU32(IReadOnlyDictionary<string, string> parsed, string key)
        {
            return parsed.TryGetValue(key, out string? value) && EventDetailsParsing.TryParseHexU32(value, out uint parsedValue)
                ? parsedValue
                : 0;
        }

        private static ulong ParseHexU64(IReadOnlyDictionary<string, string> parsed, string key)
        {
            return parsed.TryGetValue(key, out string? value) && EventDetailsParsing.TryParseHexU64(value, out ulong parsedValue)
                ? parsedValue
                : 0;
        }

        private static bool IsCapturedStackFrameKey(string key)
        {
            return key.StartsWith("stack", StringComparison.OrdinalIgnoreCase) &&
                   key.Length > 5 &&
                   char.IsDigit(key[5]);
        }

        private static int StackFrameSortKey(string key)
        {
            return int.TryParse(key[5..], NumberStyles.Integer, CultureInfo.InvariantCulture, out int index)
                ? index
                : int.MaxValue;
        }

        private static IEnumerable<string> SplitLines(string text)
        {
            if (string.IsNullOrWhiteSpace(text))
            {
                yield return "unavailable";
                yield break;
            }

            foreach (string line in text.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None))
            {
                yield return line.Length == 0 ? " " : line;
            }
        }

        private static IEnumerable<string> WrapRawForTree(string text)
        {
            if (string.IsNullOrWhiteSpace(text))
            {
                yield return "<empty>";
                yield break;
            }

            const int width = 120;
            string remaining = text.Trim();
            while (remaining.Length > 0)
            {
                int take = Math.Min(width, remaining.Length);
                yield return remaining[..take];
                remaining = remaining[take..].TrimStart();
            }
        }
    }
}

