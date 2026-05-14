using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;

namespace BlackbirdInterface
{
    internal sealed class GroupedEventPaneState
    {
        private readonly BulkObservableCollection<GroupedEventRow> _items = new();
        private readonly List<GroupedEventRow> _allItems = new();
        private readonly Dictionary<string, GroupedEventRow> _byKey = new(StringComparer.Ordinal);
        private readonly Dictionary<string, GroupedEventRow> _visibleByKey = new(StringComparer.Ordinal);
        private readonly Dictionary<string, Dictionary<string, GroupedEventDetailRow>> _detailSigByGroupKey =
            new(StringComparer.Ordinal);

        internal BulkObservableCollection<GroupedEventRow> VisibleItems => _items;
        internal List<GroupedEventRow> AllItems => _allItems;
        internal Dictionary<string, GroupedEventRow> ByKey => _byKey;
        internal Dictionary<string, Dictionary<string, GroupedEventDetailRow>> DetailSigByGroupKey =>
            _detailSigByGroupKey;

        internal int ItemCount => _items.Count;
        internal int TotalRawCount { get; private set; }
        internal int TotalDetailRows { get; private set; }

        internal void IncrementRawCount(int hits)
        {
            TotalRawCount += Math.Max(0, hits);
        }

        internal void IncrementDetailCount(int count)
        {
            TotalDetailRows += Math.Max(0, count);
        }

        internal void ReplaceDetailCount(int nextValue)
        {
            TotalDetailRows = Math.Max(0, nextValue);
        }

        internal bool TryGetRow(string key,
                                [NotNullWhen(true)] out GroupedEventRow? row) => _byKey.TryGetValue(key, out row);

        internal void TrackRow(GroupedEventRow row)
        {
            _allItems.Add(row);
            _byKey[row.GroupKey] = row;
            TotalDetailRows += row.Details.Count;
            RebuildDetailSigMap(row);
        }

        internal void RegisterDetail(GroupedEventRow row, GroupedEventDetailRow detail)
        {
            TotalDetailRows += 1;
            if (string.IsNullOrEmpty(detail.ArgumentSummary))
            {
                return;
            }

            if (!_detailSigByGroupKey.TryGetValue(row.GroupKey, out Dictionary<string, GroupedEventDetailRow>? map))
            {
                map = new Dictionary<string, GroupedEventDetailRow>(StringComparer.Ordinal);
                _detailSigByGroupKey[row.GroupKey] = map;
            }

            map[detail.ArgumentSummary] = detail;
        }

        internal bool TryGetDetail(string groupKey, string detailSignature,
                                   [NotNullWhen(true)] out GroupedEventDetailRow? detail)
        {
            detail = null;
            return !string.IsNullOrEmpty(detailSignature) &&
                   _detailSigByGroupKey.TryGetValue(groupKey, out Dictionary<string, GroupedEventDetailRow>? map) &&
                   map.TryGetValue(detailSignature, out detail);
        }

        internal void RemoveDetailReference(string groupKey, GroupedEventDetailRow detail)
        {
            if (string.IsNullOrEmpty(detail.ArgumentSummary) ||
                !_detailSigByGroupKey.TryGetValue(groupKey, out Dictionary<string, GroupedEventDetailRow>? map) ||
                !map.TryGetValue(detail.ArgumentSummary, out GroupedEventDetailRow? mapped) ||
                !ReferenceEquals(mapped, detail))
            {
                return;
            }

            map.Remove(detail.ArgumentSummary);
            if (map.Count == 0)
            {
                _detailSigByGroupKey.Remove(groupKey);
            }
        }

        internal void EvictOverflow(int maxGroupCount)
        {
            while (_allItems.Count > maxGroupCount)
            {
                GroupedEventRow evicted = _allItems[0];
                string evictKey = evicted.GroupKey;
                _allItems.RemoveAt(0);
                _byKey.Remove(evictKey);
                _detailSigByGroupKey.Remove(evictKey);
                TotalDetailRows = Math.Max(0, TotalDetailRows - evicted.Details.Count);
                if (_visibleByKey.Remove(evictKey))
                {
                    _items.Remove(evicted);
                }
            }
        }

        internal IReadOnlyList<GroupedEventRow> SnapshotItems() => _allItems.Select(static x => x.Clone()).ToList();

        internal
            GroupedEventRow? GetSelectedGroupClone(object? selectedItem) => (selectedItem as GroupedEventRow)?.Clone();

        internal void LoadHistory(IEnumerable<GroupedEventRow> groups,
                                  Func<GroupedEventRow, GroupedEventRow>? normalizeRow = null)
        {
            Clear();

            foreach (GroupedEventRow source in groups)
            {
                GroupedEventRow row = normalizeRow == null ? source.Clone() : normalizeRow(source.Clone());
                _allItems.Add(row);
                _byKey[row.GroupKey] = row;
                TotalRawCount += Math.Max(1, row.Hits);
                TotalDetailRows += row.Details.Count;
                RebuildDetailSigMap(row);
            }
        }

        internal void Clear()
        {
            _items.Clear();
            _allItems.Clear();
            _byKey.Clear();
            _visibleByKey.Clear();
            _detailSigByGroupKey.Clear();
            TotalRawCount = 0;
            TotalDetailRows = 0;
        }

        internal void TrimDetailPayload(int keepPerGroup, Func<GroupedEventRow, GroupedEventRow>? normalizeRow = null)
        {
            int keep = Math.Max(1, keepPerGroup);
            for (int i = 0; i < _allItems.Count; i += 1)
            {
                GroupedEventRow row = _allItems[i];
                if (row.Details.Count <= keep)
                {
                    continue;
                }

                int originalCount = row.Details.Count;
                row.Details = GroupedEventCompaction.SelectImportantDetails(row.Details, keep);
                if (normalizeRow != null)
                {
                    row = normalizeRow(row);
                    _allItems[i] = row;
                }

                TotalDetailRows -= Math.Max(0, originalCount - row.Details.Count);
                _byKey[row.GroupKey] = row;
                RebuildDetailSigMap(row);
            }
        }

        internal void ApplyFilter(Func<GroupedEventRow, bool> predicate)
        {
            var visible = new List<GroupedEventRow>();
            _visibleByKey.Clear();
            foreach (GroupedEventRow row in _allItems)
            {
                if (!predicate(row))
                {
                    continue;
                }

                visible.Add(row);
                _visibleByKey[row.GroupKey] = row;
            }

            _items.ReplaceAll(visible);
        }

        internal void SyncVisibleRow(GroupedEventRow row, Func<GroupedEventRow, bool> predicate)
        {
            bool matches = predicate(row);
            bool visible = _visibleByKey.ContainsKey(row.GroupKey);
            if (matches)
            {
                if (!visible)
                {
                    _items.Add(row);
                    _visibleByKey[row.GroupKey] = row;
                }

                return;
            }

            if (!visible)
            {
                return;
            }

            _visibleByKey.Remove(row.GroupKey);
            _items.Remove(row);
        }

        internal bool IsVisible(string groupKey) => _visibleByKey.ContainsKey(groupKey);

        internal void RebuildDetailSigMap(GroupedEventRow row)
        {
            _detailSigByGroupKey.Remove(row.GroupKey);
            var map = new Dictionary<string, GroupedEventDetailRow>(StringComparer.Ordinal);
            foreach (GroupedEventDetailRow detail in row.Details)
            {
                if (!string.IsNullOrEmpty(detail.ArgumentSummary))
                {
                    map[detail.ArgumentSummary] = detail;
                }
            }

            if (map.Count > 0)
            {
                _detailSigByGroupKey[row.GroupKey] = map;
            }
        }
    }
}
