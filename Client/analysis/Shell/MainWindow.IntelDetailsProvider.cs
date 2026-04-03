using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;

namespace BlackbirdInterface
{
    public partial class MainWindow
    {
        IReadOnlyList<GroupedEventDetailRow> IIntelDetailsProvider.GetIntelDetails(IntelDetailsCategory category)
        {
            int pid = _currentSession?.Pid ?? TryGetPid();
            if (pid <= 0)
            {
                return new List<GroupedEventDetailRow>();
            }

            if (TryGetIntelDetailsFromBackingStore(pid, category, out IReadOnlyList<GroupedEventDetailRow> backed) &&
                backed.Count > 0)
            {
                return backed;
            }

            if (TryGetIntelGroupedRowsFromSession(pid, category, out IReadOnlyList<GroupedEventRow> groups))
            {
                return FlattenGroupedDetails(groups);
            }

            return category switch
            {
                IntelDetailsCategory.Etw => FlattenGroupedDetails(EtwPaneHost.SnapshotItems()),
                IntelDetailsCategory.Heuristics => FlattenGroupedDetails(HeuristicsPaneHost.SnapshotItems()),
                IntelDetailsCategory.Filesystem => FlattenGroupedDetails(FilesystemPaneHost.SnapshotItems()),
                IntelDetailsCategory.ProcessRelations => FlattenGroupedDetails(ProcessRelationsPaneHost.SnapshotItems()),
                _ => new List<GroupedEventDetailRow>()
            };
        }

        string IIntelDetailsProvider.GetIntelScopeLabel()
        {
            if (_currentSession == null)
            {
                return "No active session";
            }

            string title = NormalizeSessionTitle(_currentSession.Title);
            return $"{title} [PID {_currentSession.Pid}]";
        }

        IntelScopeStatus IIntelDetailsProvider.GetIntelScopeStatus()
        {
            if (_currentSession == null || _currentSession.Pid <= 0)
            {
                return IntelScopeStatus.Unknown;
            }

            if (_currentSession.TargetExited)
            {
                return IntelScopeStatus.Exited;
            }

            if (_currentSession.OfflineSnapshot)
            {
                return IntelScopeStatus.Exited;
            }

            if (_targetExecutionSuspended)
            {
                return CacheScopeStatus(_currentSession.Pid, IntelScopeStatus.Waiting);
            }

            int pid = _currentSession.Pid;
            DateTime now = DateTime.UtcNow;
            if (_scopeStatusCachePid == pid &&
                (now - _scopeStatusCacheUtc).TotalMilliseconds < 750)
            {
                return _scopeStatusCache;
            }

            try
            {
                using Process process = Process.GetProcessById(pid);
                if (process.HasExited)
                {
                    return CacheScopeStatus(pid, IntelScopeStatus.Exited);
                }

                bool sawThread = false;
                bool anyRunning = false;
                bool anyWaiting = false;
                bool anySuspended = false;

                foreach (ProcessThread thread in process.Threads)
                {
                    sawThread = true;
                    try
                    {
                        if (thread.ThreadState == System.Diagnostics.ThreadState.Running)
                        {
                            anyRunning = true;
                            break;
                        }

                        if (thread.ThreadState == System.Diagnostics.ThreadState.Wait)
                        {
                            anyWaiting = true;
                            if (thread.WaitReason == ThreadWaitReason.Suspended ||
                                thread.WaitReason == ThreadWaitReason.UserRequest)
                            {
                                anySuspended = true;
                            }
                        }
                    }
                    catch
                    {
                    }
                }

                if (!sawThread)
                {
                    return CacheScopeStatus(pid, IntelScopeStatus.Running);
                }

                if (anyRunning)
                {
                    return CacheScopeStatus(pid, IntelScopeStatus.Running);
                }

                if (anySuspended || anyWaiting)
                {
                    return CacheScopeStatus(pid, IntelScopeStatus.Waiting);
                }

                return CacheScopeStatus(pid, IntelScopeStatus.Running);
            }
            catch
            {
                return CacheScopeStatus(pid, IntelScopeStatus.Unknown);
            }
        }

        private IntelScopeStatus CacheScopeStatus(int pid, IntelScopeStatus status)
        {
            _scopeStatusCachePid = pid;
            _scopeStatusCache = status;
            _scopeStatusCacheUtc = DateTime.UtcNow;
            return status;
        }

        private bool TryGetIntelGroupedRowsFromSession(
            int pid,
            IntelDetailsCategory category,
            out IReadOnlyList<GroupedEventRow> groups)
        {
            groups = Array.Empty<GroupedEventRow>();

            if (_currentSession?.Pid == pid)
            {
                EnsureSessionMaterialized(_currentSession);
            }

            switch (category)
            {
            case IntelDetailsCategory.Etw:
                if (_etwHistoryByPid.TryGetValue(pid, out List<GroupedEventRow>? etwRows) && etwRows.Count > 0)
                {
                    groups = etwRows;
                    return true;
                }
                break;
            case IntelDetailsCategory.Heuristics:
                if (_heuristicsHistoryByPid.TryGetValue(pid, out List<GroupedEventRow>? heurRows) && heurRows.Count > 0)
                {
                    groups = heurRows;
                    return true;
                }
                break;
            case IntelDetailsCategory.Filesystem:
                if (_filesystemHistoryByPid.TryGetValue(pid, out List<GroupedEventRow>? fsRows) && fsRows.Count > 0)
                {
                    groups = fsRows;
                    return true;
                }
                break;
            case IntelDetailsCategory.ProcessRelations:
                if (_relationsHistoryByPid.TryGetValue(pid, out List<GroupedEventRow>? relRows) && relRows.Count > 0)
                {
                    groups = relRows;
                    return true;
                }
                break;
            }

            return false;
        }

        private static IReadOnlyList<GroupedEventDetailRow> FlattenGroupedDetails(IEnumerable<GroupedEventRow> groups)
        {
            return groups
                .SelectMany(x => x.Details)
                .OrderByDescending(x => x.TimestampUtc)
                .Take(50000)
                .Select(x => x.Clone())
                .ToList();
        }
    }
}

