using System;
using System.Collections.Generic;
using System.Linq;

namespace BlackbirdInterface
{
    internal static class GroupedEventCompaction
    {
        internal static List<GroupedEventDetailRow> SelectImportantDetails(IEnumerable<GroupedEventDetailRow> details,
                                                                           int keep)
        {
            int limit = Math.Max(1, keep);
            List<GroupedEventDetailRow> source = details?.ToList() ?? new List<GroupedEventDetailRow>();
            if (source.Count <= limit)
            {
                return source.OrderBy(x => x.TimestampUtc).ToList();
            }

            int hotKeep = Math.Max(1, limit / 2);
            int recentKeep = Math.Max(1, limit - hotKeep);
            var selected = new Dictionary<string, GroupedEventDetailRow>(StringComparer.Ordinal);

            AddPreferred(selected, source.OrderByDescending(x => Math.Max(1, x.HitCount))
                                       .ThenByDescending(x => x.TimestampUtc)
                                       .Take(hotKeep));

            AddPreferred(selected, source.OrderByDescending(x => x.TimestampUtc).Take(recentKeep));

            if (selected.Count < limit)
            {
                AddPreferred(
                    selected,
                    source.OrderByDescending(x => Math.Max(1, x.HitCount)).ThenByDescending(x => x.TimestampUtc));
            }

            return selected.Values.OrderByDescending(x => Math.Max(1, x.HitCount))
                .ThenByDescending(x => x.TimestampUtc)
                .Take(limit)
                .OrderBy(x => x.TimestampUtc)
                .ToList();
        }

        private static void AddPreferred(Dictionary<string, GroupedEventDetailRow> selected,
                                         IEnumerable<GroupedEventDetailRow> candidates)
        {
            foreach (GroupedEventDetailRow candidate in candidates)
            {
                string key = BuildDetailKey(candidate);
                if (!selected.ContainsKey(key))
                {
                    selected[key] = candidate;
                }
            }
        }

        private static string BuildDetailKey(GroupedEventDetailRow detail)
        {
            return string.Join("|", detail.TimestampUtc.Ticks.ToString(), detail.ActorPid.ToString(),
                               detail.TargetPid.ToString(), detail.Event ?? string.Empty,
                               detail.Detection ?? string.Empty, detail.ArgumentSummary ?? string.Empty,
                               detail.Details ?? string.Empty);
        }
    }
}
