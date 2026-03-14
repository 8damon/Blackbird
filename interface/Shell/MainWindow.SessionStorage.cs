using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Windows;

namespace BlackbirdInterface
{
    public partial class MainWindow
    {
        private static readonly TimeSpan SessionSpillInterval = TimeSpan.FromSeconds(15);
        private const int LiveGroupedDetailSpillThreshold = 24_000;
        private const int LiveThreadStackSpillThreshold = 512;
        private readonly string _sessionCacheDirectory =
            Path.Combine(Path.GetTempPath(), "Blackbird", "session-cache");

        private string? _sessionFilePath;

        private void EnsureSessionCacheDirectory()
        {
            Directory.CreateDirectory(_sessionCacheDirectory);
        }

        private string AllocateSessionCachePath(int pid)
        {
            EnsureSessionCacheDirectory();
            return Path.Combine(_sessionCacheDirectory, $"pid-{pid}-{Guid.NewGuid():N}.swlkr");
        }

        private SessionFileTab BuildTabSnapshot(ProcessSessionTab tab)
        {
            bool hasPersistedSnapshot = TryLoadTabSnapshot(tab, out SessionFileTab? persistedSnapshot) &&
                                        persistedSnapshot != null;
            bool hasInlineData = HasInlineSessionData(tab);
            if (!hasInlineData &&
                hasPersistedSnapshot)
            {
                persistedSnapshot ??= new SessionFileTab();
                persistedSnapshot.Title = NormalizeSessionTitle(tab.Title);
                persistedSnapshot.CaptureStartUtc = tab.CaptureStartUtc;
                persistedSnapshot.ViewDurationSeconds = tab.ViewDurationSeconds;
                persistedSnapshot.ViewStartSeconds = tab.ViewStartSeconds;
                persistedSnapshot.LaneFocusKey = tab.LaneFocusKey;
                persistedSnapshot.UseUsermodeHooks = tab.UseUsermodeHooks;
                persistedSnapshot.TargetExited = tab.TargetExited;
                persistedSnapshot.OfflineSnapshot = tab.OfflineSnapshot;
                return persistedSnapshot;
            }

            EnsureSessionMaterialized(tab);

            IEnumerable<TelemetryEvent> sessionEvents = EnumerateSessionEvents(tab);
            List<TelemetryEvent> events = sessionEvents.Any()
                ? sessionEvents.Select(CloneTelemetryEvent).ToList()
                : (persistedSnapshot?.Events.Select(CloneTelemetryEvent).ToList() ?? new List<TelemetryEvent>());
            List<PerformanceSample> performanceHistory = tab.PerformanceHistory.Count > 0
                ? tab.PerformanceHistory.Select(ClonePerformanceSample).ToList()
                : (persistedSnapshot?.PerformanceHistory.Select(ClonePerformanceSample).ToList() ?? new List<PerformanceSample>());
            List<ThreadLifecycleEventSample> threadLifecycleHistory = tab.ThreadLifecycleHistory.Count > 0
                ? tab.ThreadLifecycleHistory.Select(CloneThreadLifecycleEvent).ToList()
                : (persistedSnapshot?.ThreadLifecycleHistory.Select(CloneThreadLifecycleEvent).ToList() ?? new List<ThreadLifecycleEventSample>());
            List<GroupedEventRow> etw = _etwHistoryByPid.TryGetValue(tab.Pid, out var etwRows)
                ? etwRows.Select(x => x.Clone()).ToList()
                : (persistedSnapshot?.EtwGroups.Select(x => x.Clone()).ToList() ?? new List<GroupedEventRow>());
            List<GroupedEventRow> heuristics = _heuristicsHistoryByPid.TryGetValue(tab.Pid, out var heurRows)
                ? heurRows.Select(x => x.Clone()).ToList()
                : (persistedSnapshot?.HeuristicsGroups.Select(x => x.Clone()).ToList() ?? new List<GroupedEventRow>());
            List<GroupedEventRow> filesystem = _filesystemHistoryByPid.TryGetValue(tab.Pid, out var fsRows)
                ? fsRows.Select(x => x.Clone()).ToList()
                : (persistedSnapshot?.FilesystemGroups.Select(x => x.Clone()).ToList() ?? new List<GroupedEventRow>());
            List<GroupedEventRow> relations = _relationsHistoryByPid.TryGetValue(tab.Pid, out var relRows)
                ? relRows.Select(x => x.Clone()).ToList()
                : (persistedSnapshot?.ProcessRelationsGroups.Select(x => x.Clone()).ToList() ?? new List<GroupedEventRow>());
            List<ApiCallGraphRowSnapshot> apiGraph = _apiGraphHistoryByPid.TryGetValue(tab.Pid, out var apiRows)
                ? apiRows.Select(x => new ApiCallGraphRowSnapshot
                {
                    ApiName = x.ApiName,
                    SensorOrigin = x.SensorOrigin,
                    SourcePid = x.SourcePid,
                    TargetPid = x.TargetPid,
                    ThreadId = x.ThreadId,
                    Hits = x.Hits,
                    LastSeenUtc = x.LastSeenUtc
                }).ToList()
                : (persistedSnapshot?.ApiGraphRows.Select(x => new ApiCallGraphRowSnapshot
                {
                    ApiName = x.ApiName,
                    SensorOrigin = x.SensorOrigin,
                    SourcePid = x.SourcePid,
                    TargetPid = x.TargetPid,
                    ThreadId = x.ThreadId,
                    Hits = x.Hits,
                    LastSeenUtc = x.LastSeenUtc
                }).ToList() ?? new List<ApiCallGraphRowSnapshot>());
            List<ThreadStackHistoryArchiveEntry> threadStacks = tab.ThreadStackHistories.Count > 0
                ? tab.ThreadStackHistories.Select(x => x.Clone()).ToList()
                : (persistedSnapshot?.ThreadStackHistories.Select(x => x.Clone()).ToList() ?? new List<ThreadStackHistoryArchiveEntry>());

            return new SessionFileTab
            {
                Pid = tab.Pid,
                Title = NormalizeSessionTitle(tab.Title),
                CaptureStartUtc = tab.CaptureStartUtc,
                ViewDurationSeconds = tab.ViewDurationSeconds,
                ViewStartSeconds = tab.ViewStartSeconds,
                LaneFocusKey = tab.LaneFocusKey,
                UseUsermodeHooks = tab.UseUsermodeHooks,
                TargetExited = tab.TargetExited,
                OfflineSnapshot = tab.OfflineSnapshot,
                Events = events,
                PerformanceHistory = performanceHistory,
                ThreadLifecycleHistory = threadLifecycleHistory,
                EtwGroups = etw,
                HeuristicsGroups = heuristics,
                FilesystemGroups = filesystem,
                ProcessRelationsGroups = relations,
                ApiGraphRows = apiGraph,
                ThreadStackHistories = threadStacks
            };
        }

        private void SaveTabToBackingStore(ProcessSessionTab tab)
        {
            if (tab.Pid <= 0)
            {
                return;
            }

            SessionFileTab snapshot = BuildTabSnapshot(tab);
            string path = tab.BackingStorePath ?? AllocateSessionCachePath(tab.Pid);
            tab.BackingStorePath = path;

            var archive = new SessionFileArchive
            {
                Version = 1,
                SavedUtc = DateTime.UtcNow,
                ActivePid = tab.Pid,
                Tabs = new List<SessionFileTab> { snapshot }
            };
            SessionFileStorage.SaveArchive(path, archive);

            tab.Events.Clear();
            tab.PerformanceHistory.Clear();
            tab.ThreadLifecycleHistory.Clear();
            tab.ThreadStackHistories.Clear();
            _etwHistoryByPid.Remove(tab.Pid);
            _heuristicsHistoryByPid.Remove(tab.Pid);
            _filesystemHistoryByPid.Remove(tab.Pid);
            _relationsHistoryByPid.Remove(tab.Pid);
            _apiGraphHistoryByPid.Remove(tab.Pid);
        }

        private void EnsureSessionMaterialized(ProcessSessionTab tab)
        {
            bool hasInlineData = tab.Events.Count > 0 ||
                                 tab.PerformanceHistory.Count > 0 ||
                                 tab.ThreadLifecycleHistory.Count > 0 ||
                                 _etwHistoryByPid.ContainsKey(tab.Pid) ||
                                 _heuristicsHistoryByPid.ContainsKey(tab.Pid) ||
                                 _filesystemHistoryByPid.ContainsKey(tab.Pid) ||
                                 _relationsHistoryByPid.ContainsKey(tab.Pid) ||
                                 _apiGraphHistoryByPid.ContainsKey(tab.Pid);
            if (hasInlineData)
            {
                return;
            }

            if (string.IsNullOrWhiteSpace(tab.BackingStorePath) || !File.Exists(tab.BackingStorePath))
            {
                return;
            }

            SessionFileArchive archive = SessionFileStorage.LoadArchive(tab.BackingStorePath);
            SessionFileTab? snapshot = archive.Tabs.FirstOrDefault(x => x.Pid == tab.Pid) ??
                                       archive.Tabs.FirstOrDefault();
            if (snapshot == null)
            {
                return;
            }

            tab.CaptureStartUtc = snapshot.CaptureStartUtc;
            tab.ViewDurationSeconds = snapshot.ViewDurationSeconds;
            tab.ViewStartSeconds = snapshot.ViewStartSeconds;
            tab.LaneFocusKey = snapshot.LaneFocusKey;
            tab.UseUsermodeHooks = snapshot.UseUsermodeHooks;
            tab.TargetExited = snapshot.TargetExited;
            tab.OfflineSnapshot = snapshot.OfflineSnapshot;

            tab.Events.Clear();
            tab.Events.AddRange(snapshot.Events);

            tab.PerformanceHistory.Clear();
            tab.PerformanceHistory.AddRange(snapshot.PerformanceHistory.Select(ClonePerformanceSample));
            tab.ThreadLifecycleHistory.Clear();
            tab.ThreadLifecycleHistory.AddRange(snapshot.ThreadLifecycleHistory.Select(CloneThreadLifecycleEvent));
            tab.ThreadStackHistories.Clear();
            tab.ThreadStackHistories.AddRange(snapshot.ThreadStackHistories.Select(x => x.Clone()));

            _etwHistoryByPid[tab.Pid] = CompactGroupsForMemory(snapshot.EtwGroups, 48);
            _heuristicsHistoryByPid[tab.Pid] = CompactGroupsForMemory(snapshot.HeuristicsGroups, 48);
            _filesystemHistoryByPid[tab.Pid] = CompactGroupsForMemory(snapshot.FilesystemGroups, 48);
            _relationsHistoryByPid[tab.Pid] = CompactGroupsForMemory(snapshot.ProcessRelationsGroups, 48);
            _apiGraphHistoryByPid[tab.Pid] = snapshot.ApiGraphRows
                .Select(x => new ApiCallGraphRowSnapshot
                {
                    ApiName = x.ApiName,
                    SensorOrigin = x.SensorOrigin,
                    SourcePid = x.SourcePid,
                    TargetPid = x.TargetPid,
                    ThreadId = x.ThreadId,
                    Hits = x.Hits,
                    LastSeenUtc = x.LastSeenUtc
                })
                .ToList();
        }

        private bool TryLoadTabSnapshot(ProcessSessionTab tab, out SessionFileTab? snapshot)
        {
            snapshot = null;
            if (tab.Pid <= 0 || string.IsNullOrWhiteSpace(tab.BackingStorePath) || !File.Exists(tab.BackingStorePath))
            {
                return false;
            }

            SessionFileArchive archive = SessionFileStorage.LoadArchive(tab.BackingStorePath);
            snapshot = archive.Tabs.FirstOrDefault(x => x.Pid == tab.Pid) ??
                       archive.Tabs.FirstOrDefault();
            return snapshot != null;
        }

        private bool HasInlineSessionData(ProcessSessionTab tab)
        {
            return (ReferenceEquals(tab, _currentSession) && _allEvents.Count > 0) ||
                   tab.Events.Count > 0 ||
                   tab.PerformanceHistory.Count > 0 ||
                   tab.ThreadLifecycleHistory.Count > 0 ||
                   tab.ThreadStackHistories.Count > 0 ||
                   _etwHistoryByPid.ContainsKey(tab.Pid) ||
                   _heuristicsHistoryByPid.ContainsKey(tab.Pid) ||
                   _filesystemHistoryByPid.ContainsKey(tab.Pid) ||
                   _relationsHistoryByPid.ContainsKey(tab.Pid) ||
                   _apiGraphHistoryByPid.ContainsKey(tab.Pid);
        }

        private IEnumerable<TelemetryEvent> EnumerateSessionEvents(ProcessSessionTab tab)
        {
            if (ReferenceEquals(tab, _currentSession))
            {
                return _allEvents;
            }

            return tab.Events;
        }

        private bool TryGetIntelDetailsFromBackingStore(
            int pid,
            IntelDetailsCategory category,
            out IReadOnlyList<GroupedEventDetailRow> details)
        {
            details = Array.Empty<GroupedEventDetailRow>();
            if (pid <= 0)
            {
                return false;
            }

            ProcessSessionTab? tab = _processTabs.FirstOrDefault(x => x.Pid == pid);
            if (tab == null || string.IsNullOrWhiteSpace(tab.BackingStorePath) || !File.Exists(tab.BackingStorePath))
            {
                return false;
            }

            SessionFileArchive archive = SessionFileStorage.LoadArchive(tab.BackingStorePath);
            SessionFileTab? snapshot = archive.Tabs.FirstOrDefault(x => x.Pid == pid) ??
                                       archive.Tabs.FirstOrDefault();
            if (snapshot == null)
            {
                return false;
            }

            IEnumerable<GroupedEventRow> groups = category switch
            {
                IntelDetailsCategory.Etw => snapshot.EtwGroups,
                IntelDetailsCategory.Heuristics => snapshot.HeuristicsGroups,
                IntelDetailsCategory.Filesystem => snapshot.FilesystemGroups,
                IntelDetailsCategory.ProcessRelations => snapshot.ProcessRelationsGroups,
                _ => Enumerable.Empty<GroupedEventRow>()
            };

            details = FlattenGroupedDetails(groups);
            return details.Count > 0;
        }

        private static List<GroupedEventRow> CompactGroupsForMemory(IEnumerable<GroupedEventRow> source, int maxDetailsPerGroup)
        {
            var compacted = new List<GroupedEventRow>();
            int keep = Math.Max(1, maxDetailsPerGroup);
            foreach (GroupedEventRow row in source)
            {
                GroupedEventRow clone = row.Clone();
                if (clone.Details.Count > keep)
                {
                    clone.Details = clone.Details
                        .OrderByDescending(x => x.TimestampUtc)
                        .Take(keep)
                        .OrderBy(x => x.TimestampUtc)
                        .ToList();
                }
                compacted.Add(clone);
            }

            return compacted;
        }

        private SessionFileArchive BuildWorkspaceArchive()
        {
            SaveCurrentSessionState();

            var archive = new SessionFileArchive
            {
                Version = 1,
                SavedUtc = DateTime.UtcNow,
                ActivePid = _currentSession?.Pid ?? 0
            };

            foreach (ProcessSessionTab tab in _processTabs)
            {
                archive.Tabs.Add(BuildTabSnapshot(tab));
            }

            foreach (ProcessSessionTab tab in _processTabs.Where(x => !ReferenceEquals(x, _currentSession)))
            {
                SaveTabToBackingStore(tab);
            }

            return archive;
        }

        private void ApplyWorkspaceArchive(SessionFileArchive archive, bool merge)
        {
            if (archive.Tabs.Count == 0)
            {
                throw new InvalidDataException("Session archive does not contain any tabs.");
            }

            if (!merge)
            {
                SaveCurrentSessionState();
                StopTargetExitWatcher();
                StopBackendSession();
                _perf?.Stop();
                _samplerPid = 0;

                _suppressTabSelectionChange = true;
                _processTabs.Clear();
                ProcessTabs.SelectedItem = null;
                _suppressTabSelectionChange = false;

                _etwHistoryByPid.Clear();
                _heuristicsHistoryByPid.Clear();
                _filesystemHistoryByPid.Clear();
                _relationsHistoryByPid.Clear();
                _apiGraphHistoryByPid.Clear();
                _currentSession = null;
            }

            foreach (SessionFileTab incoming in archive.Tabs)
            {
                if (incoming.Pid <= 0)
                {
                    continue;
                }

                ProcessSessionTab tab = _processTabs.FirstOrDefault(x => x.Pid == incoming.Pid)
                    ?? AddOrSelectProcessTab(incoming.Pid, incoming.Title, select: false);

                tab.Title = NormalizeSessionTitle(string.IsNullOrWhiteSpace(incoming.Title) ? $"PID {incoming.Pid}" : incoming.Title);
                tab.CaptureStartUtc = incoming.CaptureStartUtc;
                tab.ViewDurationSeconds = incoming.ViewDurationSeconds;
                tab.ViewStartSeconds = incoming.ViewStartSeconds;
                tab.LaneFocusKey = incoming.LaneFocusKey;
                tab.UseUsermodeHooks = incoming.UseUsermodeHooks;
                tab.TargetExited = incoming.TargetExited;
                tab.OfflineSnapshot = true;

                string path = tab.BackingStorePath ?? AllocateSessionCachePath(tab.Pid);
                tab.BackingStorePath = path;
                SessionFileStorage.SaveArchive(path, new SessionFileArchive
                {
                    Version = 1,
                    SavedUtc = DateTime.UtcNow,
                    ActivePid = incoming.Pid,
                    Tabs = new List<SessionFileTab>
                    {
                        new SessionFileTab
                        {
                            Pid = incoming.Pid,
                            Title = NormalizeSessionTitle(tab.Title),
                            CaptureStartUtc = incoming.CaptureStartUtc,
                            ViewDurationSeconds = incoming.ViewDurationSeconds,
                            ViewStartSeconds = incoming.ViewStartSeconds,
                            LaneFocusKey = incoming.LaneFocusKey,
                            UseUsermodeHooks = incoming.UseUsermodeHooks,
                            TargetExited = incoming.TargetExited,
                            OfflineSnapshot = true,
                            Events = incoming.Events,
                            PerformanceHistory = incoming.PerformanceHistory,
                            ThreadLifecycleHistory = incoming.ThreadLifecycleHistory,
                            EtwGroups = incoming.EtwGroups,
                            HeuristicsGroups = incoming.HeuristicsGroups,
                            FilesystemGroups = incoming.FilesystemGroups,
                            ProcessRelationsGroups = incoming.ProcessRelationsGroups,
                            ApiGraphRows = incoming.ApiGraphRows,
                            ThreadStackHistories = incoming.ThreadStackHistories
                        }
                    }
                });

                tab.Events.Clear();
                tab.PerformanceHistory.Clear();
                tab.ThreadLifecycleHistory.Clear();
                tab.ThreadStackHistories.Clear();
                _etwHistoryByPid.Remove(tab.Pid);
                _heuristicsHistoryByPid.Remove(tab.Pid);
                _filesystemHistoryByPid.Remove(tab.Pid);
                _relationsHistoryByPid.Remove(tab.Pid);
                _apiGraphHistoryByPid.Remove(tab.Pid);
            }

            ProcessSessionTab? toSelect = _processTabs.FirstOrDefault(x => x.Pid == archive.ActivePid) ??
                                          _processTabs.FirstOrDefault();
            if (toSelect == null)
            {
                return;
            }

            _suppressTabSelectionChange = true;
            ProcessTabs.SelectedItem = toSelect;
            _suppressTabSelectionChange = false;
            SwitchToSession(toSelect);
        }

        private void SaveSessionAs_Click(object sender, RoutedEventArgs e)
        {
            SaveSessionArchiveViaDialog();
        }

        private void ExportSession_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new SaveFileDialog
            {
                Filter =
                    "SIEM JSON Lines (*.jsonl)|*.jsonl|" +
                    "SIEM CSV (*.csv)|*.csv|" +
                    "CEF (*.cef)|*.cef|" +
                    "ATT&CK-ready CSV (*.attack.csv)|*.attack.csv|" +
                    "Blackbird Session Archive (*.swlkr;*.blackbird)|*.swlkr;*.blackbird|" +
                    "All files (*.*)|*.*",
                DefaultExt = ".jsonl",
                AddExtension = true,
                OverwritePrompt = true,
                FileName = $"blackbird-export-{DateTime.UtcNow:yyyyMMdd-HHmmss}.jsonl"
            };

            if (dialog.ShowDialog(this) != true)
            {
                return;
            }

            try
            {
                SessionFileArchive archive = BuildWorkspaceArchive();
                if (dialog.FilterIndex == 5)
                {
                    SessionFileStorage.SaveArchive(dialog.FileName, archive);
                    StatusBlock.Text = $"SESSION EXPORTED: {Path.GetFileName(dialog.FileName)}";
                    return;
                }

                SessionExportFormat format = dialog.FilterIndex switch
                {
                    1 => SessionExportFormat.JsonLines,
                    2 => SessionExportFormat.Csv,
                    3 => SessionExportFormat.Cef,
                    4 => SessionExportFormat.AttackCsv,
                    _ => SessionExportFormat.JsonLines
                };
                SessionExportService.Export(dialog.FileName, archive, format);
                StatusBlock.Text = $"SESSION EXPORTED: {Path.GetFileName(dialog.FileName)}";
            }
            catch (Exception ex)
            {
                ThemedMessageBox.Show(this, $"Failed to export session.\n\n{ex.Message}", "Export Session", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private bool TryOpenSessionArchivePath(string path, bool merge, out string error)
        {
            error = string.Empty;
            if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
            {
                error = "Session file not found.";
                return false;
            }

            try
            {
                SessionFileArchive archive = SessionFileStorage.LoadArchive(path);
                ApplyWorkspaceArchive(archive, merge);
                if (!merge)
                {
                    _sessionFilePath = path;
                }

                string verb = merge ? "IMPORTED" : "OPENED";
                StatusBlock.Text = $"SESSION {verb}: {Path.GetFileName(path)}";
                return true;
            }
            catch (Exception ex)
            {
                error = ex.Message;
                return false;
            }
        }

        private void OpenSession_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new OpenFileDialog
            {
                Filter = "Blackbird Session Archive (*.swlkr;*.blackbird)|*.swlkr;*.blackbird|All files (*.*)|*.*",
                CheckFileExists = true,
                Multiselect = false
            };

            if (dialog.ShowDialog(this) != true)
            {
                return;
            }

            if (!TryOpenSessionArchivePath(dialog.FileName, merge: false, out string error))
            {
                ThemedMessageBox.Show(this, $"Failed to open session.\n\n{error}", "Open Session", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void ImportSession_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new OpenFileDialog
            {
                Filter = "Blackbird Session Archive (*.swlkr;*.blackbird)|*.swlkr;*.blackbird|All files (*.*)|*.*",
                CheckFileExists = true,
                Multiselect = false
            };

            if (dialog.ShowDialog(this) != true)
            {
                return;
            }

            if (!TryOpenSessionArchivePath(dialog.FileName, merge: true, out string error))
            {
                ThemedMessageBox.Show(this, $"Failed to import session.\n\n{error}", "Import Session", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private bool PrepareSessionShutdown()
        {
            if (_isMainWindowShuttingDown || !HasSessionCacheData())
            {
                return true;
            }

            MessageBoxResult choice = ThemedMessageBox.Show(
                this,
                "Save the current Blackbird session before exit?\n\nSelecting No removes the temporary session datastore on teardown.",
                "Exit Session",
                MessageBoxButton.YesNoCancel,
                MessageBoxImage.Question);
            if (choice == MessageBoxResult.Cancel)
            {
                return false;
            }

            return choice != MessageBoxResult.Yes || SaveSessionArchiveViaDialog();
        }

        private bool SaveSessionArchiveViaDialog()
        {
            var dialog = new SaveFileDialog
            {
                Filter = "Blackbird Session Archive (*.swlkr;*.blackbird)|*.swlkr;*.blackbird|All files (*.*)|*.*",
                DefaultExt = ".swlkr",
                AddExtension = true,
                OverwritePrompt = true,
                FileName = $"blackbird-{DateTime.UtcNow:yyyyMMdd-HHmmss}.swlkr"
            };

            if (!string.IsNullOrWhiteSpace(_sessionFilePath))
            {
                dialog.InitialDirectory = Path.GetDirectoryName(_sessionFilePath);
            }

            if (dialog.ShowDialog(this) != true)
            {
                return false;
            }

            try
            {
                SessionFileArchive archive = BuildWorkspaceArchive();
                SessionFileStorage.SaveArchive(dialog.FileName, archive);
                _sessionFilePath = dialog.FileName;
                StatusBlock.Text = $"SESSION SAVED: {Path.GetFileName(dialog.FileName)}";
                return true;
            }
            catch (Exception ex)
            {
                ThemedMessageBox.Show(this, $"Failed to save session.\n\n{ex.Message}", "Save Session", MessageBoxButton.OK, MessageBoxImage.Error);
                return false;
            }
        }

        private bool HasSessionCacheData()
        {
            if (_currentSession != null &&
                (_allEvents.Count > 0 ||
                 _currentSession.PerformanceHistory.Count > 0 ||
                 _currentSession.ThreadLifecycleHistory.Count > 0 ||
                 _currentSession.ThreadStackHistories.Count > 0))
            {
                return true;
            }

            return _processTabs.Any(x => HasInlineSessionData(x) || (!string.IsNullOrWhiteSpace(x.BackingStorePath) && File.Exists(x.BackingStorePath)));
        }

        private void CleanupTemporarySessionBackingStores()
        {
            foreach (ProcessSessionTab tab in _processTabs)
            {
                if (string.IsNullOrWhiteSpace(tab.BackingStorePath) || !File.Exists(tab.BackingStorePath))
                {
                    continue;
                }

                try
                {
                    File.Delete(tab.BackingStorePath);
                }
                catch
                {
                }
            }
        }

        private void SpillCurrentSessionWorkingSetIfNeeded()
        {
            if (_currentSession == null || _currentSession.OfflineSnapshot || _currentSession.Pid <= 0)
            {
                return;
            }

            DateTime now = DateTime.UtcNow;
            if (_currentSession.BackingStorePath != null &&
                File.Exists(_currentSession.BackingStorePath) &&
                now - File.GetLastWriteTimeUtc(_currentSession.BackingStorePath) < SessionSpillInterval)
            {
                return;
            }

            int totalGroupedDetails =
                EtwPaneHost.SnapshotItems().Sum(x => x.Details.Count) +
                HeuristicsPaneHost.SnapshotItems().Sum(x => x.Details.Count) +
                FilesystemPaneHost.SnapshotItems().Sum(x => x.Details.Count) +
                ProcessRelationsPaneHost.SnapshotItems().Sum(x => x.Details.Count);
            int threadStackSnapshots = _currentSession.ThreadStackHistories.Sum(x => x.Snapshots.Count);
            if (totalGroupedDetails < LiveGroupedDetailSpillThreshold &&
                threadStackSnapshots < LiveThreadStackSpillThreshold)
            {
                return;
            }

            _currentSession.CaptureStartUtc = _captureStartUtc;
            _currentSession.LaneFocusKey = _laneFocusKey;
            _currentSession.ViewDurationSeconds = EventsPaneHost.Timeline.ViewDurationSeconds;
            _currentSession.ViewStartSeconds = EventsPaneHost.Timeline.ViewStartSeconds;
            SaveIntelSessionState(_currentSession.Pid);

            SessionFileTab snapshot = BuildTabSnapshot(_currentSession);
            string path = _currentSession.BackingStorePath ?? AllocateSessionCachePath(_currentSession.Pid);
            _currentSession.BackingStorePath = path;
            SessionFileStorage.SaveArchive(path, new SessionFileArchive
            {
                Version = SessionFileStorage.CurrentVersion,
                SavedUtc = now,
                ActivePid = _currentSession.Pid,
                Tabs = new List<SessionFileTab> { snapshot }
            });

            EtwPaneHost.TrimDetailPayload(48);
            HeuristicsPaneHost.TrimDetailPayload(48);
            FilesystemPaneHost.TrimDetailPayload(48);
            ProcessRelationsPaneHost.TrimDetailPayload(48);
            TrimThreadStackHistories(_currentSession, 64);
            SaveIntelSessionState(_currentSession.Pid);
        }

        private static void TrimThreadStackHistories(ProcessSessionTab tab, int keepSnapshotsPerThread)
        {
            int keep = Math.Max(1, keepSnapshotsPerThread);
            foreach (ThreadStackHistoryArchiveEntry history in tab.ThreadStackHistories)
            {
                if (history.Snapshots.Count <= keep)
                {
                    continue;
                }

                history.Snapshots = history.Snapshots
                    .OrderByDescending(x => x.CapturedAtUtc)
                    .Take(keep)
                    .OrderBy(x => x.CapturedAtUtc)
                    .ToList();
            }
        }

        private IReadOnlyList<ThreadStackSessionSnapshot> GetThreadStackHistory(int pid, int tid, string state)
        {
            ProcessSessionTab? tab = ResolveSessionTab(pid);
            if (tab == null)
            {
                return Array.Empty<ThreadStackSessionSnapshot>();
            }

            EnsureSessionMaterialized(tab);
            ThreadStackHistoryArchiveEntry? history = tab.ThreadStackHistories.FirstOrDefault(x =>
                x.Tid == tid &&
                string.Equals(x.State, state ?? string.Empty, StringComparison.OrdinalIgnoreCase));
            return history?.Snapshots.Select(x => x.Clone()).ToList() ?? (IReadOnlyList<ThreadStackSessionSnapshot>)Array.Empty<ThreadStackSessionSnapshot>();
        }

        private void PersistThreadStackSnapshot(int pid, int tid, string state, ThreadStackSessionSnapshot snapshot)
        {
            if (snapshot == null)
            {
                return;
            }

            ProcessSessionTab? tab = ResolveSessionTab(pid);
            if (tab == null)
            {
                return;
            }

            EnsureSessionMaterialized(tab);
            string normalizedState = state ?? string.Empty;
            ThreadStackHistoryArchiveEntry? history = tab.ThreadStackHistories.FirstOrDefault(x =>
                x.Tid == tid &&
                string.Equals(x.State, normalizedState, StringComparison.OrdinalIgnoreCase));
            if (history == null)
            {
                history = new ThreadStackHistoryArchiveEntry
                {
                    Tid = tid,
                    State = normalizedState
                };
                tab.ThreadStackHistories.Add(history);
            }

            int existingIndex = history.Snapshots.FindIndex(x => x.CapturedAtUtc == snapshot.CapturedAtUtc);
            if (existingIndex >= 0)
            {
                history.Snapshots[existingIndex] = snapshot.Clone();
            }
            else
            {
                history.Snapshots.Add(snapshot.Clone());
                history.Snapshots = history.Snapshots
                    .OrderBy(x => x.CapturedAtUtc)
                    .ToList();
            }
        }

        private ProcessSessionTab? ResolveSessionTab(int pid)
        {
            if (_currentSession != null && _currentSession.Pid == pid)
            {
                return _currentSession;
            }

            return _processTabs.FirstOrDefault(x => x.Pid == pid);
        }
    }
}
