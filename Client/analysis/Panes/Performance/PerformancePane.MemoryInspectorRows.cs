using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;

namespace BlackbirdInterface
{
    public partial class PerformancePane
    {
        private void RebuildMemoryAttributionRows(IEnumerable<MemoryPageSample> pages, DateTime cutoffUtc)
        {
            List<ThreadMemoryRange> threadRanges = BuildThreadMemoryRanges(_pid);
            MemoryAttributionLookup attributionLookup = BuildMemoryAttributionLookup(cutoffUtc);
            ThreadExecutionHeuristicIndex threadExecutionLookup = BuildThreadExecutionHeuristicIndex(cutoffUtc);
            List<MemoryAttributionRow> rows =
                pages
                    .Select(
                        page =>
                        {
                            MemoryRegionAttributionSample? attribution =
                                FindLatestMemoryRegionAttribution(page, attributionLookup);
                            ThreadExecutionMemoryHeuristic? threadHeuristic =
                                ShouldUseThreadExecutionHeuristic(page)
                                    ? threadExecutionLookup.FindBest(page.BaseAddress, page.RegionSize)
                                    : null;
                            string allocator = NormalizeDisplayText(DescribeAllocator(attribution, threadHeuristic));
                            string source =
                                NormalizeDisplayText(DescribeResolvedMemorySource(page, attribution, threadHeuristic));
                            string trust = DescribeResolvedMemoryTrust(page, attribution, threadHeuristic);
                            string context =
                                NormalizeDisplayText(DescribeResolvedMemoryContext(page, attribution, threadHeuristic));
                            string lifecycle =
                                NormalizeDisplayText(DescribeResolvedMemoryLifecycle(attribution, threadHeuristic));
                            string priorityBand =
                                DetermineMemoryPriorityBand(page, trust, attribution, threadHeuristic);
                            string category = NormalizeDisplayText(DescribeResolvedMemoryCategory(page));
                            string highlightBand = DetermineMemoryHighlightBand(category);
                            uint threadTid = ResolveThreadTidForPage(page, category, threadRanges);
                            if (threadTid == 0)
                            {
                                threadTid = ResolveThreadTidForAttribution(attribution);
                            }
                            if (threadTid == 0 && threadHeuristic != null)
                            {
                                threadTid = threadHeuristic.ThreadId;
                            }
                            string highlightLabel = DetermineMemoryHighlightLabel(category, highlightBand);
                            if (threadHeuristic != null && string.IsNullOrWhiteSpace(highlightLabel))
                            {
                                highlightLabel = "EXEC?";
                            }

                            return new MemoryAttributionRow { BaseAddress = $"0x{page.BaseAddress:X}",
                                                              Size = FormatBytes((long)Math.Min(page.RegionSize,
                                                                                                (ulong) long.MaxValue)),
                                                              State = DescribeMemoryStateForInspector(page),
                                                              Type = DescribeMemoryTypeForInspector(page),
                                                              Protect = DescribeProtectionAcronym(page.Protect),
                                                              Category = category,
                                                              Allocator = allocator,
                                                              Source = source,
                                                              Context = context,
                                                              Lifecycle = lifecycle,
                                                              Trust = trust,
                                                              PriorityBand = priorityBand,
                                                              HighlightBand = highlightBand,
                                                              HighlightLabel = highlightLabel,
                                                              ThreadTid = threadTid,
                                                              SortRank = MemoryPriorityBandRank(priorityBand),
                                                              RegionSizeBytes = page.RegionSize,
                                                              BaseAddressValue = page.BaseAddress };
                        })
                    .OrderBy(row => row.SortRank)
                    .ThenByDescending(row => row.RegionSizeBytes)
                    .ThenBy(row => row.BaseAddressValue)
                    .Take(768)
                    .ToList();

            ApplyMemoryAttributionRows(rows);
        }

        private MemoryAttributionLookup BuildMemoryAttributionLookup(DateTime cutoffUtc)
        {
            var lookup = new MemoryAttributionLookup();
            if (_pid <= 0 || _memoryRegionAttributionHistory.Count == 0)
            {
                return lookup;
            }

            uint targetPid = unchecked((uint)_pid);
            for (int i = _memoryRegionAttributionHistory.Count - 1; i >= 0; i -= 1)
            {
                MemoryRegionAttributionSample sample = _memoryRegionAttributionHistory[i];
                if (sample.TimestampUtc > cutoffUtc)
                {
                    continue;
                }
                if (sample.TargetPid != 0 && sample.TargetPid != targetPid)
                {
                    continue;
                }

                ulong baseAddress = sample.BaseAddress != 0 ? sample.BaseAddress : sample.AllocationBase;
                ulong size = sample.RegionSize;
                if (baseAddress == 0 || size == 0)
                {
                    continue;
                }

                lookup.Add(sample, baseAddress, size);
            }

            return lookup;
        }

        private ThreadExecutionHeuristicIndex BuildThreadExecutionHeuristicIndex(DateTime cutoffUtc)
        {
            const int maxSnapshotsPerThread = 16;
            const int maxFramesPerSnapshot = 16;

            var index = new ThreadExecutionHeuristicIndex();
            if (_pid <= 0)
            {
                return index;
            }

            uint targetPid = unchecked((uint)_pid);
            Dictionary<uint, ThreadLifecycleEventSample> latestThreadStarts =
                BuildLatestThreadStartMap(cutoffUtc, targetPid);
            foreach (ThreadLifecycleEventSample sample in latestThreadStarts.Values)
            {
                uint ownerPid = sample.ProcessPid != 0 ? sample.ProcessPid : targetPid;
                AddThreadExecutionEvidence(index, sample.ThreadId, ownerPid, sample.CreatorPid, sample.StartAddress,
                                           sample.TimestampUtc, "thread start", string.Empty, string.Empty, 85);
            }

            foreach (ThreadStackHistoryArchiveEntry history in _threadStackHistories)
            {
                if (history.Tid <= 0)
                {
                    continue;
                }

                uint tid = unchecked((uint)history.Tid);
                latestThreadStarts.TryGetValue(tid, out ThreadLifecycleEventSample? lifecycle);
                uint ownerPid = lifecycle != null && lifecycle.ProcessPid != 0 ? lifecycle.ProcessPid : targetPid;
                uint creatorPid = lifecycle?.CreatorPid ?? 0;
                foreach (ThreadStackSessionSnapshot snapshot in SelectThreadStackSnapshots(history, cutoffUtc,
                                                                                           maxSnapshotsPerThread))
                {
                    DateTime observedUtc = snapshot.CapturedAtUtc;
                    ulong rip = snapshot.ContextSnapshot?.Rip ?? 0;
                    AddThreadExecutionEvidence(index, tid, ownerPid, creatorPid, rip, observedUtc, "current RIP",
                                               string.Empty, string.Empty, 100);

                    int frameCount = 0;
                    foreach (StackFrameRow frame in snapshot.Frames.OrderBy(static frame => frame.Index))
                    {
                        if (frame.InstructionPointerRaw == 0)
                        {
                            continue;
                        }

                        string evidenceKind = frame.IsCurrent ? "current frame" : "stack frame";
                        int score = frame.IsCurrent ? 95 : 70;
                        AddThreadExecutionEvidence(index, tid, ownerPid, creatorPid, frame.InstructionPointerRaw,
                                                   observedUtc, evidenceKind, frame.Module, frame.Symbol, score);
                        frameCount += 1;
                        if (frameCount >= maxFramesPerSnapshot)
                        {
                            break;
                        }
                    }
                }
            }

            return index;
        }

        private Dictionary<uint, ThreadLifecycleEventSample> BuildLatestThreadStartMap(DateTime cutoffUtc,
                                                                                       uint targetPid)
        {
            var latestByTid = new Dictionary<uint, ThreadLifecycleEventSample>();
            foreach (ThreadLifecycleEventSample sample in _threadLifecycleHistory)
            {
                if (sample.TimestampUtc > cutoffUtc || sample.ThreadId == 0 ||
                    !IsThreadLifecycleForTarget(sample, targetPid))
                {
                    continue;
                }

                if (sample.EventKind.Equals("Exit", StringComparison.OrdinalIgnoreCase))
                {
                    latestByTid.Remove(sample.ThreadId);
                    continue;
                }

                if (sample.StartAddress == 0)
                {
                    continue;
                }

                latestByTid[sample.ThreadId] = sample;
            }

            return latestByTid;
        }

        private static bool IsThreadLifecycleForTarget(ThreadLifecycleEventSample sample, uint targetPid)
        {
            return targetPid == 0 || sample.ProcessPid == 0 || sample.ProcessPid == targetPid;
        }

        private static IEnumerable<ThreadStackSessionSnapshot>
        SelectThreadStackSnapshots(ThreadStackHistoryArchiveEntry history, DateTime cutoffUtc, int maxSnapshots)
        {
            int emitted = 0;
            for (int i = history.Snapshots.Count - 1; i >= 0 && emitted < maxSnapshots; i -= 1)
            {
                ThreadStackSessionSnapshot snapshot = history.Snapshots[i];
                if (snapshot.CapturedAtUtc > cutoffUtc)
                {
                    continue;
                }

                emitted += 1;
                yield return snapshot;
            }
        }

        private static void AddThreadExecutionEvidence(ThreadExecutionHeuristicIndex index, uint threadId,
                                                       uint ownerPid, uint creatorPid, ulong address,
                                                       DateTime observedUtc, string evidenceKind, string module,
                                                       string symbol, int score)
        {
            if (threadId == 0 || address == 0)
            {
                return;
            }

            index.Add(new ThreadExecutionMemoryHeuristic { ThreadId = threadId, OwnerPid = ownerPid,
                                                           CreatorPid = creatorPid, Address = address,
                                                           ObservedUtc = observedUtc, EvidenceKind = evidenceKind,
                                                           Module = module, Symbol = symbol, Score = score });
        }

        private void RebuildMemoryAttributionRowsFromAttributions(DateTime cutoffUtc)
        {
            var latestByBase = new Dictionary<ulong, MemoryRegionAttributionSample>();
            for (int i = 0; i < _memoryRegionAttributionHistory.Count; i += 1)
            {
                MemoryRegionAttributionSample sample = _memoryRegionAttributionHistory[i];
                ulong key = sample.AllocationBase != 0 ? sample.AllocationBase : sample.BaseAddress;
                if (key == 0)
                {
                    continue;
                }

                if (!latestByBase.TryGetValue(key, out MemoryRegionAttributionSample? existing) ||
                    sample.TimestampUtc > existing.TimestampUtc)
                {
                    latestByBase[key] = sample;
                }
            }

            var pages = latestByBase.Values.Select(ToSyntheticMemoryPage)
                            .Where(static page => page.BaseAddress != 0 && page.RegionSize != 0)
                            .ToList();

            if (pages.Count == 0)
            {
                MemoryAttributionRows.Clear();
                return;
            }

            RebuildMemoryAttributionRows(pages, cutoffUtc);
        }

        private static MemoryPageSample ToSyntheticMemoryPage(MemoryRegionAttributionSample sample)
        {
            uint protect = sample.CurrentProtection != 0 ? sample.CurrentProtection : sample.InitialProtection;
            string regionKind = string.IsNullOrWhiteSpace(sample.RegionKind) ? "Observed" : sample.RegionKind;
            uint type = regionKind.Equals("Image", StringComparison.OrdinalIgnoreCase)    ? 0x1000000u
                        : regionKind.Equals("Mapped", StringComparison.OrdinalIgnoreCase) ? 0x40000u
                                                                                          : 0x20000u;

            return new MemoryPageSample {
                BaseAddress = sample.BaseAddress != 0 ? sample.BaseAddress : sample.AllocationBase,
                AllocationBase = sample.AllocationBase != 0 ? sample.AllocationBase : sample.BaseAddress,
                RegionSize = sample.RegionSize == 0 ? 1UL : sample.RegionSize,
                State = 0x1000,
                Protect = protect,
                AllocationProtect = protect,
                Type = type,
                StateLabel = "MEM_COMMIT",
                ProtectLabel = protect == 0 ? "Observed" : EventDetailFormatting.DescribeMemoryProtection(protect),
                TypeLabel = type == 0x1000000u ? "MEM_IMAGE"
                            : type == 0x40000u ? "MEM_MAPPED"
                                               : "MEM_PRIVATE",
                Category = regionKind,
                SpecialUse = sample.EventKind,
                BackingPath = sample.OriginPath,
                ModulePath = sample.OriginPath,
                Sr71Owned = sample.BlackbirdOwned,
                Sr71OwnerTag = sample.BlackbirdOwned ? "BK Instrumentation" : string.Empty
            };
        }

        private static string BuildModuleKey(ModuleInfoRow module)
        {
            string path = (module.Path ?? string.Empty).Trim();
            if (!string.IsNullOrWhiteSpace(path))
            {
                return path;
            }

            return $"{module.Name}|{module.BaseAddress}";
        }

        private void ApplyMemoryAttributionRows(IReadOnlyList<MemoryAttributionRow> rows)
        {
            if (ShouldBulkReplaceMemoryAttributionRows(rows))
            {
                MemoryAttributionRows.ReplaceAll(rows);
                return;
            }

            var desiredKeys = new HashSet<(ulong BaseAddress, ulong RegionSize)>(
                rows.Select(static row => (row.BaseAddressValue, row.RegionSizeBytes)));

            for (int i = MemoryAttributionRows.Count - 1; i >= 0; i -= 1)
            {
                MemoryAttributionRow existing = MemoryAttributionRows[i];
                if (!desiredKeys.Contains((existing.BaseAddressValue, existing.RegionSizeBytes)))
                {
                    MemoryAttributionRows.RemoveAt(i);
                }
            }

            var existingByKey =
                MemoryAttributionRows.ToDictionary(static row => (row.BaseAddressValue, row.RegionSizeBytes));

            for (int i = 0; i < rows.Count; i += 1)
            {
                MemoryAttributionRow incoming = rows[i];
                (ulong, ulong) key = (incoming.BaseAddressValue, incoming.RegionSizeBytes);
                if (existingByKey.TryGetValue(key, out MemoryAttributionRow? existing))
                {
                    existing.UpdateFrom(incoming);
                    int currentIndex = MemoryAttributionRows.IndexOf(existing);
                    if (currentIndex >= 0 && currentIndex != i)
                    {
                        MemoryAttributionRows.Move(currentIndex, i);
                    }
                    continue;
                }

                MemoryAttributionRows.Insert(i, incoming);
                existingByKey[key] = incoming;
            }

            while (MemoryAttributionRows.Count > rows.Count)
            {
                MemoryAttributionRows.RemoveAt(MemoryAttributionRows.Count - 1);
            }
        }

        private void RebuildThreadLifecycleRows(DateTime cutoffUtc)
        {
            ThreadLifecycleRows.Clear();
            IEnumerable<ThreadLifecycleEventSample> rows =
                _threadLifecycleHistory.Where(x => x.TimestampUtc <= cutoffUtc)
                    .OrderByDescending(x => x.TimestampUtc)
                    .Take(256);
            foreach (ThreadLifecycleEventSample row in rows)
            {
                ThreadLifecycleRows.Add(new ThreadLifecycleRow(row));
            }
        }

        private MemoryRegionAttributionSample? FindLatestMemoryRegionAttribution(MemoryPageSample page,
                                                                                 MemoryAttributionLookup lookup)
        {
            if (_pid <= 0 || page.BaseAddress == 0 || page.RegionSize == 0 || lookup.IsEmpty)
            {
                return null;
            }

            MemoryRegionAttributionSample? latestLifecycle = null;
            foreach (MemoryRegionAttributionSample candidate in lookup.FindOverlaps(page.BaseAddress, page.RegionSize))
            {
                ulong candidateBase = candidate.BaseAddress != 0 ? candidate.BaseAddress : candidate.AllocationBase;
                ulong candidateSize = candidate.RegionSize;
                if (!MemoryRegionsOverlap(page.BaseAddress, page.RegionSize, candidateBase, candidateSize))
                {
                    continue;
                }

                if (latestLifecycle == null)
                {
                    latestLifecycle = candidate;
                }

                if (IsPrimaryMemoryAttributionEvent(candidate))
                {
                    return candidate;
                }
            }

            return latestLifecycle;
        }

        private sealed class MemoryAttributionLookup
        {
            private const int BucketShift = 16;
            private const int MaxBucketsPerRegion = 4096;
            private readonly Dictionary<ulong, List<MemoryRegionAttributionSample>> _byBucket = new();
            private readonly List<MemoryRegionAttributionSample> _largeRegions = new();

            public bool IsEmpty => _byBucket.Count == 0 && _largeRegions.Count == 0;

            public void Add(MemoryRegionAttributionSample sample, ulong baseAddress, ulong size)
            {
                ulong start = baseAddress >> BucketShift;
                ulong endAddress = baseAddress + size - 1;
                if (endAddress < baseAddress)
                {
                    endAddress = ulong.MaxValue;
                }

                ulong end = endAddress >> BucketShift;
                ulong bucketCount = end >= start ? (end - start + 1) : 1;
                if (bucketCount > MaxBucketsPerRegion)
                {
                    _largeRegions.Add(sample);
                    return;
                }

                for (ulong bucket = start; bucket <= end; bucket += 1)
                {
                    AddToBucket(bucket, sample);
                    if (bucket == ulong.MaxValue)
                    {
                        break;
                    }
                }
            }

            public IEnumerable<MemoryRegionAttributionSample> FindOverlaps(ulong baseAddress, ulong size)
            {
                ulong start = baseAddress >> BucketShift;
                ulong endAddress = baseAddress + size - 1;
                if (endAddress < baseAddress)
                {
                    endAddress = ulong.MaxValue;
                }

                ulong end = endAddress >> BucketShift;
                var seen = new HashSet<MemoryRegionAttributionSample>();
                for (int i = 0; i < _largeRegions.Count; i += 1)
                {
                    if (seen.Add(_largeRegions[i]))
                    {
                        yield return _largeRegions[i];
                    }
                }

                ulong bucketCount = end >= start ? (end - start + 1) : 1;
                if (bucketCount > MaxBucketsPerRegion)
                {
                    foreach (List<MemoryRegionAttributionSample> bucketSamples in _byBucket.Values)
                    {
                        for (int i = 0; i < bucketSamples.Count; i += 1)
                        {
                            if (seen.Add(bucketSamples[i]))
                            {
                                yield return bucketSamples[i];
                            }
                        }
                    }

                    yield break;
                }

                for (ulong bucket = start; bucket <= end; bucket += 1)
                {
                    if (_byBucket.TryGetValue(bucket, out List<MemoryRegionAttributionSample>? samples))
                    {
                        for (int i = 0; i < samples.Count; i += 1)
                        {
                            if (seen.Add(samples[i]))
                            {
                                yield return samples[i];
                            }
                        }
                    }

                    if (bucket == ulong.MaxValue)
                    {
                        break;
                    }
                }
            }

            private void AddToBucket(ulong bucket, MemoryRegionAttributionSample sample)
            {
                if (!_byBucket.TryGetValue(bucket, out List<MemoryRegionAttributionSample>? samples))
                {
                    samples = new List<MemoryRegionAttributionSample>(2);
                    _byBucket[bucket] = samples;
                }

                samples.Add(sample);
            }
        }

        private sealed class ThreadExecutionMemoryHeuristic
        {
            public uint ThreadId { get; init; }
            public uint OwnerPid { get; init; }
            public uint CreatorPid { get; init; }
            public ulong Address { get; init; }
            public DateTime ObservedUtc { get; init; }
            public string EvidenceKind { get; init; } = string.Empty;
            public string Module { get; init; } = string.Empty;
            public string Symbol { get; init; } = string.Empty;
            public int Score { get; init; }
        }

        private sealed class ThreadExecutionHeuristicIndex
        {
            private const int BucketShift = 16;
            private const int MaxBucketsPerQuery = 4096;
            private readonly Dictionary<ulong, List<ThreadExecutionMemoryHeuristic>> _byBucket = new();
            private readonly List<ThreadExecutionMemoryHeuristic> _all = new();

            public void Add(ThreadExecutionMemoryHeuristic evidence)
            {
                _all.Add(evidence);
                ulong bucket = evidence.Address >> BucketShift;
                if (!_byBucket.TryGetValue(bucket, out List<ThreadExecutionMemoryHeuristic>? entries))
                {
                    entries = new List<ThreadExecutionMemoryHeuristic>(2);
                    _byBucket[bucket] = entries;
                }

                entries.Add(evidence);
            }

            public ThreadExecutionMemoryHeuristic? FindBest(ulong baseAddress, ulong size)
            {
                if (baseAddress == 0 || size == 0 || _all.Count == 0)
                {
                    return null;
                }

                ulong start = baseAddress >> BucketShift;
                ulong endAddress = baseAddress + size - 1;
                if (endAddress < baseAddress)
                {
                    endAddress = ulong.MaxValue;
                }

                ulong end = endAddress >> BucketShift;
                ulong bucketCount = end >= start ? end - start + 1 : 1;
                ThreadExecutionMemoryHeuristic? best = null;
                if (bucketCount > MaxBucketsPerQuery)
                {
                    foreach (ThreadExecutionMemoryHeuristic candidate in _all)
                    {
                        if (ContainsAddress(baseAddress, size, candidate.Address))
                        {
                            best = SelectBetter(best, candidate);
                        }
                    }

                    return best;
                }

                for (ulong bucket = start; bucket <= end; bucket += 1)
                {
                    if (_byBucket.TryGetValue(bucket, out List<ThreadExecutionMemoryHeuristic>? entries))
                    {
                        foreach (ThreadExecutionMemoryHeuristic candidate in entries)
                        {
                            if (ContainsAddress(baseAddress, size, candidate.Address))
                            {
                                best = SelectBetter(best, candidate);
                            }
                        }
                    }

                    if (bucket == ulong.MaxValue)
                    {
                        break;
                    }
                }

                return best;
            }

            private static ThreadExecutionMemoryHeuristic SelectBetter(ThreadExecutionMemoryHeuristic? current,
                                                                       ThreadExecutionMemoryHeuristic candidate)
            {
                if (current == null)
                {
                    return candidate;
                }

                if (candidate.Score != current.Score)
                {
                    return candidate.Score > current.Score ? candidate : current;
                }

                if (candidate.ObservedUtc != current.ObservedUtc)
                {
                    return candidate.ObservedUtc > current.ObservedUtc ? candidate : current;
                }

                return candidate.ThreadId < current.ThreadId ? candidate : current;
            }
        }
    }
}
