using System;
using System.Collections.Generic;
using System.Linq;

namespace BlackbirdInterface
{
    internal sealed class DiagnosticsStateEntry
    {
        public string Key { get; set; } = string.Empty;
        public string Value { get; set; } = string.Empty;
    }

    internal static class DiagnosticsState
    {
        private static readonly object Sync = new();
        private static readonly Dictionary<string, string> Values = new(StringComparer.OrdinalIgnoreCase);
        private static readonly Dictionary<string, long> Counters = new(StringComparer.OrdinalIgnoreCase);

        public static void SetValue(string key, string value)
        {
            lock (Sync)
            {
                Values[key] = value;
            }
        }

        public static string? GetValue(string key)
        {
            lock (Sync)
            {
                return Values.TryGetValue(key, out string? v) ? v : null;
            }
        }

        public static void Increment(string key, long amount = 1)
        {
            lock (Sync)
            {
                Counters.TryGetValue(key, out long current);
                Counters[key] = current + amount;
            }
        }

        public static void ResetCounter(string key)
        {
            lock (Sync)
            {
                Counters[key] = 0;
            }
        }

        public static IReadOnlyList<string> SnapshotLines()
        {
            lock (Sync)
            {
                var lines = new List<string>
                {
                    $"State Snapshot UTC {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss}"
                };

                foreach (var pair in Values.OrderBy(x => x.Key, StringComparer.OrdinalIgnoreCase))
                {
                    lines.Add($"{pair.Key}: {pair.Value}");
                }

                foreach (var pair in Counters.OrderBy(x => x.Key, StringComparer.OrdinalIgnoreCase))
                {
                    lines.Add($"{pair.Key}: {pair.Value}");
                }

                return lines;
            }
        }

        public static IReadOnlyList<DiagnosticsStateEntry> SnapshotEntries()
        {
            lock (Sync)
            {
                var entries = new List<DiagnosticsStateEntry>();
                foreach (var pair in Values.OrderBy(x => x.Key, StringComparer.OrdinalIgnoreCase))
                {
                    entries.Add(new DiagnosticsStateEntry { Key = pair.Key, Value = pair.Value });
                }

                return entries;
            }
        }
    }
}


