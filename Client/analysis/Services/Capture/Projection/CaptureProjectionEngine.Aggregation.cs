using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace BlackbirdInterface.Capture
{
    internal sealed partial class CaptureProjectionEngine
    {
        private void AddMemoryAttribution(MemoryRegionAttributionSample sample)
        {
            _memoryAttributions.Add(CloneMemoryRegionAttributionSample(sample));
            TrimHead(_memoryAttributions, MaxMemoryAttributions);
        }

        private void AddGroup(Dictionary<string, GroupedEventRow> groups, string key, string eventName, string severity,
                              string detection, string source, uint actorPid, uint targetPid, string argument,
                              string details, DateTime observedUtc, int hitCount)
        {
            if (!groups.TryGetValue(key, out GroupedEventRow? row))
            {
                row = new GroupedEventRow { GroupKey = key,
                                            Event = eventName,
                                            Severity = severity,
                                            Detection = detection,
                                            Actor = PidLabel(actorPid),
                                            Target = PidLabel(targetPid),
                                            ArgumentPreview = Truncate(argument, 256) };
                groups[key] = row;
            }

            row.LastSeenUtc = observedUtc;
            row.Hits += Math.Max(1, hitCount);
            row.Actor = PidLabel(actorPid);
            row.Target = PidLabel(targetPid);
            if (!string.IsNullOrWhiteSpace(argument))
            {
                row.ArgumentPreview = Truncate(argument, 256);
            }
            row.Details.Add(
                new GroupedEventDetailRow { TimestampUtc = observedUtc, Event = eventName, Severity = severity,
                                            Detection = detection, Source = source, Actor = PidLabel(actorPid),
                                            Target = PidLabel(targetPid), ActorPid = actorPid, TargetPid = targetPid,
                                            ArgumentSummary = Truncate(argument, 512), HitCount = Math.Max(1, hitCount),
                                            Details = Truncate(details, 4096) });
            TrimHead(row.Details, MaxGroupedDetails);
        }

        private void AddExtended(string type, string actor, string target, string subject, string operation,
                                 DateTime observedUtc, int hits, string detail = "")
        {
            string key = $"{type}|{actor}|{target}|{subject}|{operation}";
            if (!_extendedRows.TryGetValue(key, out ExtendedActivityRowSnapshot? row))
            {
                row = new ExtendedActivityRowSnapshot { TypeLabel = type, ActorLabel = actor, TargetLabel = target,
                                                        SubjectLabel = Truncate(subject, 512),
                                                        OperationLabel = operation };
                _extendedRows[key] = row;
            }

            row.Hits += Math.Max(1, hits);
            row.LastSeenUtc = observedUtc;
            row.LastSeenLabel = observedUtc.ToString("O", CultureInfo.InvariantCulture);
            row.DetailLabel = Truncate(FirstNonEmpty(detail, row.DetailLabel), 1024);

            if (_extendedRows.Count > MaxExtendedRows)
            {
                foreach (string evict in _extendedRows.OrderBy(x => x.Value.LastSeenUtc)
                             .Take(_extendedRows.Count - MaxExtendedRows)
                             .Select(x => x.Key)
                             .ToArray())
                {
                    _extendedRows.Remove(evict);
                }
            }
        }

        private void PersistStackSnapshot(uint threadId, string state, DateTime observedUtc, ulong[] frames)
        {
            if (threadId == 0 || frames.Length == 0)
            {
                return;
            }

            int tid = unchecked((int)threadId);
            if (!_threadStacks.TryGetValue(tid, out ThreadStackHistoryArchiveEntry? history))
            {
                if (_threadStacks.Count >= MaxThreadStackHistories)
                {
                    return;
                }

                history = new ThreadStackHistoryArchiveEntry { Tid = tid, State = state };
                _threadStacks[tid] = history;
            }

            int count = Math.Min(frames.Length, 64);
            var snapshot = new ThreadStackSessionSnapshot {
                CapturedAtUtc = observedUtc,
                Frames = frames.Take(count)
                             .Select((address, index) =>
                                         new StackFrameRow { Index = index, Address = $"0x{address:X}",
                                                             InstructionPointerRaw = address, Module = string.Empty,
                                                             Symbol = string.Empty, IsCurrent = index == 0 })
                             .ToList()
            };
            history.Snapshots.Add(snapshot);
            TrimHead(history.Snapshots, MaxThreadStackSnapshotsPerThread);
        }

        private void PersistStackSnapshot(uint threadId, string state, ThreadStackSessionSnapshot snapshot)
        {
            if (threadId == 0 || snapshot.Frames.Count == 0)
            {
                return;
            }

            int tid = unchecked((int)threadId);
            if (!_threadStacks.TryGetValue(tid, out ThreadStackHistoryArchiveEntry? history))
            {
                if (_threadStacks.Count >= MaxThreadStackHistories)
                {
                    return;
                }

                history = new ThreadStackHistoryArchiveEntry { Tid = tid, State = state };
                _threadStacks[tid] = history;
            }

            if (string.IsNullOrWhiteSpace(history.State))
            {
                history.State = state;
            }

            history.Snapshots.Add(snapshot.Clone());
            TrimHead(history.Snapshots, MaxThreadStackSnapshotsPerThread);
        }

        private static StackFrameRow
        CloneStackFrameRow(StackFrameRow frame) => new() { Index = frame.Index,
                                                           Address = frame.Address,
                                                           Module = frame.Module,
                                                           Symbol = frame.Symbol,
                                                           InstructionPointerRaw = frame.InstructionPointerRaw,
                                                           FramePointerRaw = frame.FramePointerRaw,
                                                           FrameSpanBytes = frame.FrameSpanBytes,
                                                           IsCurrent = frame.IsCurrent };

        private static ThreadContextSnapshot? CloneThreadContextSnapshot(ThreadContextSnapshot? snapshot) =>
            snapshot == null
                ? null
                : new ThreadContextSnapshot { Rip = snapshot.Rip, Rsp = snapshot.Rsp, Rbp = snapshot.Rbp,
                                              Rax = snapshot.Rax, Rbx = snapshot.Rbx, Rcx = snapshot.Rcx,
                                              Rdx = snapshot.Rdx, Rsi = snapshot.Rsi, Rdi = snapshot.Rdi,
                                              R8 = snapshot.R8,   R9 = snapshot.R9,   R10 = snapshot.R10,
                                              R11 = snapshot.R11, R12 = snapshot.R12, R13 = snapshot.R13,
                                              R14 = snapshot.R14, R15 = snapshot.R15, Dr0 = snapshot.Dr0,
                                              Dr1 = snapshot.Dr1, Dr2 = snapshot.Dr2, Dr3 = snapshot.Dr3,
                                              Dr6 = snapshot.Dr6, Dr7 = snapshot.Dr7, EFlags = snapshot.EFlags };

        private static void IncrementCount(Dictionary<string, int> counts, string key, int delta)
        {
            string safeKey = string.IsNullOrWhiteSpace(key) ? "(unknown)" : key.Trim();
            counts.TryGetValue(safeKey, out int current);
            counts[safeKey] = current + Math.Max(1, delta);
        }

        private static string FormatTopCounts(Dictionary<string, int> counts, int max) =>
            counts.Count == 0 ? "none"
                              : string.Join(",", counts.OrderByDescending(static x => x.Value)
                                                     .ThenBy(static x => x.Key, StringComparer.OrdinalIgnoreCase)
                                                     .Take(max)
                                                     .Select(static x => $"{x.Key}={x.Value}"));

        private static List<GroupedEventRow> MergeGroups(IEnumerable<GroupedEventRow> existing,
                                                         IEnumerable<GroupedEventRow> additions) =>
            existing.Concat(additions)
                .GroupBy(x => x.GroupKey, StringComparer.OrdinalIgnoreCase)
                .Select(group =>
                        {
                            GroupedEventRow merged = group.First().Clone();
                            foreach (GroupedEventRow row in group.Skip(1))
                            {
                                merged.Hits += row.Hits;
                                if (row.LastSeenUtc > merged.LastSeenUtc)
                                {
                                    merged.LastSeenUtc = row.LastSeenUtc;
                                    merged.Event = row.Event;
                                    merged.Severity = row.Severity;
                                    merged.Detection = row.Detection;
                                    merged.ArgumentPreview = row.ArgumentPreview;
                                }
                                merged.Details.AddRange(row.Details.Select(x => x.Clone()));
                            }
                            if (merged.Details.Count > MaxGroupedDetails)
                            {
                                merged.Details = merged.Details.OrderByDescending(x => x.TimestampUtc)
                                                     .Take(MaxGroupedDetails)
                                                     .OrderBy(x => x.TimestampUtc)
                                                     .ToList();
                            }
                            return merged;
                        })
                .OrderByDescending(x => SeverityRank(x.Severity))
                .ThenByDescending(x => x.Hits)
                .ThenByDescending(x => x.LastSeenUtc)
                .ToList();

        private static List<ApiCallGraphRowSnapshot> MergeApiRows(IEnumerable<ApiCallGraphRowSnapshot> existing,
                                                                  IEnumerable<ApiCallGraphRowSnapshot> additions)
        {
            var rows = new Dictionary<string, ApiCallGraphRowSnapshot>(StringComparer.OrdinalIgnoreCase);
            foreach (ApiCallGraphRowSnapshot row in existing.Concat(additions))
            {
                string key =
                    $"api:{row.SourcePid}:{row.TargetPid}:{row.ThreadId}:{row.ApiName}:{row.SensorOrigin}:{row.CallerOrigin}:{row.OriginModule}";
                if (!rows.TryGetValue(key, out ApiCallGraphRowSnapshot? current) ||
                    row.LastSeenUtc > current.LastSeenUtc ||
                    row.DetailFull.Length > current.DetailFull.Length)
                {
                    rows[key] = row.Clone();
                }
            }

            return rows.Values.OrderByDescending(static x => x.Hits)
                .ThenByDescending(static x => x.LastSeenUtc)
                .Take(MaxApiGraphRows)
                .ToList();
        }

        private static List<ExtendedActivityRowSnapshot>
        MergeExtendedRows(IEnumerable<ExtendedActivityRowSnapshot> existing,
                          IEnumerable<ExtendedActivityRowSnapshot> additions)
        {
            var rows = new Dictionary<string, ExtendedActivityRowSnapshot>(StringComparer.OrdinalIgnoreCase);
            foreach (ExtendedActivityRowSnapshot row in existing.Concat(additions))
            {
                string key =
                    $"{row.TypeLabel}|{row.ActorLabel}|{row.TargetLabel}|{row.SubjectLabel}|{row.OperationLabel}";
                if (!rows.TryGetValue(key, out ExtendedActivityRowSnapshot? current) ||
                    row.LastSeenUtc > current.LastSeenUtc)
                {
                    rows[key] = row.Clone();
                }
            }

            return rows.Values.OrderByDescending(static x => x.LastSeenUtc)
                .ThenByDescending(static x => x.Hits)
                .Take(MaxExtendedRows)
                .ToList();
        }

        private static List<ThreadStackHistoryArchiveEntry>
        MergeThreadStacks(IEnumerable<ThreadStackHistoryArchiveEntry> existing,
                          IEnumerable<ThreadStackHistoryArchiveEntry> additions)
        {
            var rows = new Dictionary<int, ThreadStackHistoryArchiveEntry>();
            foreach (ThreadStackHistoryArchiveEntry history in existing.Concat(additions))
            {
                if (!rows.TryGetValue(history.Tid, out ThreadStackHistoryArchiveEntry? current))
                {
                    rows[history.Tid] = history.Clone();
                    continue;
                }

                foreach (ThreadStackSessionSnapshot snapshot in history.Snapshots)
                {
                    bool duplicate = current.Snapshots.Any(x => x.CapturedAtUtc == snapshot.CapturedAtUtc &&
                                                                x.Frames.Count == snapshot.Frames.Count);
                    if (!duplicate)
                    {
                        current.Snapshots.Add(snapshot.Clone());
                    }
                }

                current.Snapshots = current.Snapshots.OrderByDescending(static x => x.CapturedAtUtc)
                                        .Take(MaxThreadStackSnapshotsPerThread)
                                        .OrderBy(static x => x.CapturedAtUtc)
                                        .ToList();
            }

            return rows.Values.OrderByDescending(static x => x.Snapshots.Count)
                .ThenBy(static x => x.Tid)
                .Take(MaxThreadStackHistories)
                .ToList();
        }
    }
}
