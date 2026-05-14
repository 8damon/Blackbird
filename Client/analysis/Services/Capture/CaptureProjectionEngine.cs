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
        private const int MaxPerformanceSamples = 7_200;
        private const int MaxMemoryAttributions = 80_000;
        private const int MaxThreadLifecycleEvents = 120_000;
        private const int MaxGroupedDetails = 256;
        private const int MaxApiGraphRows = 120_000;
        private const int MaxExtendedRows = 160_000;
        private const int MaxThreadStackHistories = 8_192;
        private const int MaxThreadStackSnapshotsPerThread = 256;
        private const int MaxStatusLines = 512;

        private readonly object _sync = new();
        private readonly int _targetPid;
        private readonly string _captureId;
        private readonly string _sourceLabel;
        private readonly DateTime _captureStartUtc;
        private readonly List<PerformanceSample> _performance = new();
        private readonly List<MemoryRegionAttributionSample> _memoryAttributions = new();
        private readonly List<ThreadLifecycleEventSample> _threadLifecycle = new();
        private readonly Dictionary<string, GroupedEventRow> _etwGroups = new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, GroupedEventRow> _heuristicGroups = new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, GroupedEventRow> _filesystemGroups = new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, GroupedEventRow> _registryGroups = new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, GroupedEventRow> _relationGroups = new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, ApiCallGraphRowSnapshot> _apiGraphRows =
            new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, ExtendedActivityRowSnapshot> _extendedRows =
            new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<int, ThreadStackHistoryArchiveEntry> _threadStacks = new();
        private readonly HashSet<int> _trackedPids = new();
        private readonly List<string> _statusLines = new();
        private readonly Dictionary<string, int> _etwFamilyCounts = new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, int> _etwEventCounts = new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, int> _apiCandidateCounts = new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, DateTime> _observedHookStackLastPersistByThread =
            new(StringComparer.Ordinal);
        private readonly Dictionary<string, DateTime> _threadStackFallbackLastCaptureByThread =
            new(StringComparer.Ordinal);
        private readonly HashSet<string> _pendingThreadStackFallbackKeys = new(StringComparer.Ordinal);
        private readonly List<Task> _pendingThreadStackCaptures = new();
        private CaptureExecutionPhaseState _executionPhase = CaptureExecutionPhaseState.ActiveDefault;
        private int _observedHookStacks;
        private int _fallbackStackCaptures;
        private int _fallbackStackMisses;
        private int _ioctlTotal;
        private int _etwTotal;

        internal CaptureProjectionEngine(int targetPid, string captureId, string sourceLabel = "BlackbirdCaptureCore")
        {
            _targetPid = targetPid;
            _captureId = captureId ?? string.Empty;
            _sourceLabel = string.IsNullOrWhiteSpace(sourceLabel) ? "BlackbirdCaptureCore" : sourceLabel.Trim();
            _captureStartUtc = DateTime.UtcNow;
            if (targetPid > 0)
            {
                _trackedPids.Add(targetPid);
            }
        }

        internal event Action<IReadOnlyList<HeuristicEventView>>? HeuristicsMaterialized;

        internal CaptureExecutionPhaseState ExecutionPhase
        {
            get {
                lock (_sync)
                {
                    return _executionPhase;
                }
            }
        }

        internal void SetExecutionPhase(CaptureExecutionPhase phase, DateTime timestampUtc = default,
                                        string reason = "")
        {
            DateTime observedUtc = timestampUtc == default ? DateTime.UtcNow : timestampUtc;
            lock (_sync)
            {
                CaptureExecutionPhaseState previous = _executionPhase;
                _executionPhase = CaptureExecutionPolicy.CreateState(phase, observedUtc, previous);

                string detail =
                    $"phase={phase} resumeUtc={_executionPhase.ResumeUtc?.ToString("O", CultureInfo.InvariantCulture) ?? "n/a"} " +
                    $"startupUntilUtc={_executionPhase.StartupUntilUtc?.ToString("O", CultureInfo.InvariantCulture) ?? "n/a"}";
                if (!string.IsNullOrWhiteSpace(reason))
                {
                    detail = $"{detail} reason={reason.Trim()}";
                }

                _statusLines.Add($"{observedUtc:O} execution-phase {detail}");
                TrimHead(_statusLines, MaxStatusLines);
                AddExtended("Diagnostics", CaptureActorLabel, PidLabel((uint)_targetPid), "execution-phase",
                            phase.ToString(), observedUtc, 1, detail);
            }
        }

        internal bool TrackObservedPid(int pid, string reason)
        {
            if (pid <= 0)
            {
                return false;
            }

            lock (_sync)
            {
                return TrackPid(unchecked((uint)pid), DateTime.UtcNow, reason);
            }
        }

        internal int[] SnapshotTrackedPids()
        {
            lock (_sync)
            {
                return _trackedPids.OrderBy(x => x).ToArray();
            }
        }

        internal int[] RefreshTrackedProcessTree(string reason)
        {
            int[] roots = SnapshotTrackedPids();
            int[] descendants = ProcessTreeSnapshot.DiscoverDescendants(roots);
            if (descendants.Length == 0)
            {
                return Array.Empty<int>();
            }

            var added = new List<int>();
            lock (_sync)
            {
                DateTime nowUtc = DateTime.UtcNow;
                foreach (int descendantPid in descendants)
                {
                    if (TrackPid(unchecked((uint)descendantPid), nowUtc, reason))
                    {
                        added.Add(descendantPid);
                    }
                }
            }

            return added.ToArray();
        }
    }
}
