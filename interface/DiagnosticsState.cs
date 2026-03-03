using System;
using System.Collections.Generic;
using System.Linq;

namespace SleepwalkerInterface
{
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
    }
}
