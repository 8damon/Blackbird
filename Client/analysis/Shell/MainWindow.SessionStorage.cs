using BlackbirdInterface.Capture;
using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input;

namespace BlackbirdInterface
{
    public partial class MainWindow
    {
        private static readonly TimeSpan SessionSpillInterval = TimeSpan.FromSeconds(15);
        private const string CaptureArchiveExtension = ".bkcap";
        private const string CaptureArchiveSaveFilter =
            "Blackbird Capture Archive (*.bkcap)|*.bkcap|All files (*.*)|*.*";
        private const string CaptureArchiveOpenFilter =
            "Blackbird Capture Archive (*.bkcap)|*.bkcap|Legacy Blackbird Session Archive (*.swlkr;*.blackbird)|*.swlkr;*.blackbird|All files (*.*)|*.*";
        private const int LiveGroupedDetailSpillThreshold = 24_000;
        private const int LiveThreadStackSpillThreshold = 512;
        private const int MaxLiveThreadStackSnapshotsPerThread = 256;
        private const int MaxLiveThreadStackHistoriesPerTab = 512;
        private readonly string _sessionCacheDirectory = Path.Combine(Path.GetTempPath(), "Blackbird", "session-cache");
        private readonly HashSet<string> _ownedTemporaryWorkspaceRoots = new(StringComparer.OrdinalIgnoreCase);

        private string? _sessionFilePath;

        private void EnsureSessionCacheDirectory()
        {
            Directory.CreateDirectory(_sessionCacheDirectory);
        }

        private string AllocateSessionCachePath(int pid)
        {
            EnsureSessionCacheDirectory();
            return Path.Combine(_sessionCacheDirectory, $"pid-{pid}-{Guid.NewGuid():N}");
        }

        private bool IsSessionCachePath(string? path)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                return false;
            }

            try
            {
                string cacheRoot = Path.GetFullPath(_sessionCacheDirectory)
                                       .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
                string candidate =
                    Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);

                return candidate.StartsWith(cacheRoot + Path.DirectorySeparatorChar,
                                            StringComparison.OrdinalIgnoreCase) ||
                       string.Equals(candidate, cacheRoot, StringComparison.OrdinalIgnoreCase);
            }
            catch
            {
                return false;
            }
        }

        private SessionFileArchive CreateSingleTabArchive(SessionFileTab snapshot)
        {
            return new SessionFileArchive { Version = SessionFileStorage.CurrentVersion, SavedUtc = DateTime.UtcNow,
                                            ActivePid = snapshot.Pid, Tabs = new List<SessionFileTab> { snapshot } };
        }

        private void RegisterTemporaryWorkspace(CaptureLoadedWorkspace workspace)
        {
            if (!workspace.IsTemporaryWorkspace || string.IsNullOrWhiteSpace(workspace.WorkspaceRootPath))
            {
                return;
            }

            _ownedTemporaryWorkspaceRoots.Add(Path.GetFullPath(workspace.WorkspaceRootPath));
        }

        private void ReleaseOwnedTemporaryWorkspaces()
        {
            foreach (string workspaceRoot in _ownedTemporaryWorkspaceRoots.ToArray())
            {
                try
                {
                    SessionFileStorage.DeletePath(workspaceRoot);
                }
                catch
                {
                }
            }

            _ownedTemporaryWorkspaceRoots.Clear();
        }

        private SessionFileTab BuildTabSnapshot(ProcessSessionTab tab, bool preferExistingCaptureStore = true)
        {
            bool hasPersistedSnapshot = TryLoadTabSnapshot(tab, out SessionFileTab? persistedSnapshot) &&
                                        persistedSnapshot != null;
            bool hasInlineData = HasInlineSessionData(tab);
            if (!hasInlineData && hasPersistedSnapshot)
            {
                persistedSnapshot ??= new SessionFileTab();
                persistedSnapshot.Title = NormalizeSessionTitle(tab.Title);
                persistedSnapshot.CaptureStartUtc = tab.CaptureStartUtc;
                persistedSnapshot.ViewDurationSeconds = tab.ViewDurationSeconds;
                persistedSnapshot.ViewStartSeconds = tab.ViewStartSeconds;
                persistedSnapshot.LaneFocusKey = tab.LaneFocusKey;
                persistedSnapshot.UseUsermodeHooks = tab.UseUsermodeHooks;
                persistedSnapshot.TargetExited = tab.TargetExited;
                persistedSnapshot.TargetExitReason = tab.TargetExitReason;
                persistedSnapshot.OfflineSnapshot = tab.OfflineSnapshot;
                persistedSnapshot.AnalysisSubjectKind = tab.AnalysisSubjectKind;
                persistedSnapshot.AnalysisSubjectPath = tab.AnalysisSubjectPath;
                persistedSnapshot.AnalysisHostPath = tab.AnalysisHostPath;
                persistedSnapshot.CaptureStorePath = preferExistingCaptureStore ? tab.BackingStorePath : null;
                return persistedSnapshot;
            }

            EnsureSessionMaterialized(tab);

            List<TelemetryEvent> events = EnumerateSessionEvents(tab).Select(CloneTelemetryEvent).ToList();
            List<PerformanceSample> performanceHistory =
                tab.PerformanceHistory.Count > 0
                    ? tab.PerformanceHistory.Select(ClonePerformanceSample).ToList()
                    : (persistedSnapshot?.PerformanceHistory.Select(ClonePerformanceSample).ToList() ??
                       new List<PerformanceSample>());
            List<MemoryRegionAttributionSample> memoryRegionAttributionHistory =
                tab.MemoryRegionAttributionHistory.Count > 0
                    ? tab.MemoryRegionAttributionHistory.Select(CloneMemoryRegionAttributionSample).ToList()
                    : (persistedSnapshot?.MemoryRegionAttributionHistory.Select(CloneMemoryRegionAttributionSample)
                           .ToList() ??
                       new List<MemoryRegionAttributionSample>());
            List<ThreadLifecycleEventSample> threadLifecycleHistory =
                tab.ThreadLifecycleHistory.Count > 0
                    ? tab.ThreadLifecycleHistory.Select(CloneThreadLifecycleEvent).ToList()
                    : (persistedSnapshot?.ThreadLifecycleHistory.Select(CloneThreadLifecycleEvent).ToList() ??
                       new List<ThreadLifecycleEventSample>());
            List<GroupedEventRow> etw =
                _etwHistoryByPid.TryGetValue(tab.Pid, out var etwRows)
                    ? etwRows.Select(x => x.Clone()).ToList()
                    : (persistedSnapshot?.EtwGroups.Select(x => x.Clone()).ToList() ?? new List<GroupedEventRow>());
            List<GroupedEventRow> heuristics =
                _heuristicsHistoryByPid.TryGetValue(tab.Pid, out var heurRows)
                    ? heurRows.Select(x => x.Clone()).ToList()
                    : (persistedSnapshot?.HeuristicsGroups.Select(x => x.Clone()).ToList() ??
                       new List<GroupedEventRow>());
            List<GroupedEventRow> filesystem =
                _filesystemHistoryByPid.TryGetValue(tab.Pid, out var fsRows)
                    ? fsRows.Select(x => x.Clone()).ToList()
                    : (persistedSnapshot?.FilesystemGroups.Select(x => x.Clone()).ToList() ??
                       new List<GroupedEventRow>());
            List<GroupedEventRow> registry = _registryHistoryByPid.TryGetValue(tab.Pid, out var regRows)
                                                 ? regRows.Select(x => x.Clone()).ToList()
                                                 : (persistedSnapshot?.RegistryGroups.Select(x => x.Clone()).ToList() ??
                                                    new List<GroupedEventRow>());
            List<GroupedEventRow> relations =
                _relationsHistoryByPid.TryGetValue(tab.Pid, out var relRows)
                    ? relRows.Select(x => x.Clone()).ToList()
                    : (persistedSnapshot?.ProcessRelationsGroups.Select(x => x.Clone()).ToList() ??
                       new List<GroupedEventRow>());
            List<ApiCallGraphRowSnapshot> apiGraph =
                _apiGraphHistoryByPid.TryGetValue(tab.Pid, out var apiRows)
                    ? apiRows.Select(x => x.Clone()).ToList()
                    : (persistedSnapshot?.ApiGraphRows.Select(x => x.Clone()).ToList() ??
                       new List<ApiCallGraphRowSnapshot>());
            List<ExtendedActivityRowSnapshot> extended =
                _extendedHistoryByPid.TryGetValue(tab.Pid, out var extRows)
                    ? extRows.Select(x => x.Clone()).ToList()
                    : (persistedSnapshot?.ExtendedActivityRows.Select(x => x.Clone()).ToList() ??
                       new List<ExtendedActivityRowSnapshot>());
            List<ThreadStackHistoryArchiveEntry> threadStacks =
                tab.ThreadStackHistories.Count > 0
                    ? tab.ThreadStackHistories.Select(x => x.Clone()).ToList()
                    : (persistedSnapshot?.ThreadStackHistories.Select(x => x.Clone()).ToList() ??
                       new List<ThreadStackHistoryArchiveEntry>());

            var snapshot =
                new SessionFileTab { Pid = tab.Pid,
                                     Title = NormalizeSessionTitle(tab.Title),
                                     CaptureStartUtc = tab.CaptureStartUtc,
                                     ViewDurationSeconds = tab.ViewDurationSeconds,
                                     ViewStartSeconds = tab.ViewStartSeconds,
                                     LaneFocusKey = tab.LaneFocusKey,
                                     UseUsermodeHooks = tab.UseUsermodeHooks,
                                     KernelHooksEnabled = tab.KernelHooksEnabled,
                                     SignatureIntelEnabled = tab.SignatureIntelEnabled,
                                     SignatureIntelMemoryScanEnabled = tab.SignatureIntelMemoryScanEnabled,
                                     SignatureIntelPageScanEnabled = tab.SignatureIntelPageScanEnabled,
                                     TargetExited = tab.TargetExited,
                                     TargetExitReason = tab.TargetExitReason,
                                     OfflineSnapshot = tab.OfflineSnapshot,
                                     AnalysisSubjectKind = tab.AnalysisSubjectKind,
                                     AnalysisSubjectPath = tab.AnalysisSubjectPath,
                                     AnalysisHostPath = tab.AnalysisHostPath,
                                     CaptureStorePath = preferExistingCaptureStore ? tab.BackingStorePath : null,
                                     Events = events,
                                     PerformanceHistory = performanceHistory,
                                     MemoryRegionAttributionHistory = memoryRegionAttributionHistory,
                                     ThreadLifecycleHistory = threadLifecycleHistory,
                                     EtwGroups = etw,
                                     HeuristicsGroups = heuristics,
                                     FilesystemGroups = filesystem,
                                     RegistryGroups = registry,
                                     ProcessRelationsGroups = relations,
                                     ApiGraphRows = apiGraph,
                                     ExtendedActivityRows = extended,
                                     ThreadStackHistories = threadStacks };
            if (_captureProjection != null && tab.Pid == _filterRootPid)
            {
                _captureProjection.WaitForPendingStackCaptures(TimeSpan.FromMilliseconds(250));
                _captureProjection.ApplyToTab(snapshot);
            }

            return snapshot;
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
            snapshot.CaptureStorePath = path;

            SessionFileArchive archive = CreateSingleTabArchive(snapshot);
            SessionFileStorage.SaveArchive(path, archive);

            tab.Events.Clear();
            tab.PerformanceHistory.Clear();
            tab.MemoryRegionAttributionHistory.Clear();
            tab.ThreadLifecycleHistory.Clear();
            tab.ThreadStackHistories.Clear();
            _etwHistoryByPid.Remove(tab.Pid);
            _heuristicsHistoryByPid.Remove(tab.Pid);
            _filesystemHistoryByPid.Remove(tab.Pid);
            _registryHistoryByPid.Remove(tab.Pid);
            _relationsHistoryByPid.Remove(tab.Pid);
            _apiGraphHistoryByPid.Remove(tab.Pid);
            _extendedHistoryByPid.Remove(tab.Pid);
        }

        private void EnsureSessionMaterialized(ProcessSessionTab tab)
        {
            bool hasInlineData =
                tab.Events.Count > 0 || tab.PerformanceHistory.Count > 0 ||
                tab.MemoryRegionAttributionHistory.Count > 0 || tab.ThreadLifecycleHistory.Count > 0 ||
                _etwHistoryByPid.ContainsKey(tab.Pid) || _heuristicsHistoryByPid.ContainsKey(tab.Pid) ||
                _filesystemHistoryByPid.ContainsKey(tab.Pid) || _registryHistoryByPid.ContainsKey(tab.Pid) ||
                _relationsHistoryByPid.ContainsKey(tab.Pid) || _apiGraphHistoryByPid.ContainsKey(tab.Pid) ||
                _extendedHistoryByPid.ContainsKey(tab.Pid);
            if (hasInlineData)
            {
                return;
            }

            if (!SessionFileStorage.Exists(tab.BackingStorePath))
            {
                return;
            }

            SessionFileArchive archive = SessionFileStorage.LoadArchive(tab.BackingStorePath!);
            SessionFileTab? snapshot =
                archive.Tabs.FirstOrDefault(x => x.Pid == tab.Pid) ?? archive.Tabs.FirstOrDefault();
            if (snapshot == null)
            {
                return;
            }

            tab.CaptureStartUtc = snapshot.CaptureStartUtc;
            tab.ViewDurationSeconds = snapshot.ViewDurationSeconds;
            tab.ViewStartSeconds = snapshot.ViewStartSeconds;
            tab.LaneFocusKey = snapshot.LaneFocusKey;
            tab.UseUsermodeHooks = snapshot.UseUsermodeHooks;
            tab.KernelHooksEnabled = snapshot.KernelHooksEnabled;
            tab.SignatureIntelEnabled = snapshot.SignatureIntelEnabled;
            tab.SignatureIntelMemoryScanEnabled = snapshot.SignatureIntelMemoryScanEnabled;
            tab.SignatureIntelPageScanEnabled = snapshot.SignatureIntelPageScanEnabled;
            tab.TargetExited = snapshot.TargetExited;
            tab.TargetExitReason = snapshot.TargetExitReason;
            tab.OfflineSnapshot = snapshot.OfflineSnapshot;
            tab.AnalysisSubjectKind = snapshot.AnalysisSubjectKind;
            tab.AnalysisSubjectPath = snapshot.AnalysisSubjectPath;
            tab.AnalysisHostPath = snapshot.AnalysisHostPath;
            tab.BackingStorePath = snapshot.CaptureStorePath ?? tab.BackingStorePath;

            tab.Events.Clear();
            tab.Events.AddRange(snapshot.Events);

            tab.PerformanceHistory.Clear();
            tab.PerformanceHistory.AddRange(snapshot.PerformanceHistory.Select(ClonePerformanceSample));
            tab.MemoryRegionAttributionHistory.Clear();
            tab.MemoryRegionAttributionHistory.AddRange(
                snapshot.MemoryRegionAttributionHistory.Select(CloneMemoryRegionAttributionSample));
            tab.ThreadLifecycleHistory.Clear();
            tab.ThreadLifecycleHistory.AddRange(snapshot.ThreadLifecycleHistory.Select(CloneThreadLifecycleEvent));
            tab.ThreadStackHistories.Clear();
            tab.ThreadStackHistories.AddRange(snapshot.ThreadStackHistories.Select(x => x.Clone()));

            _etwHistoryByPid[tab.Pid] = snapshot.EtwGroups.Select(x => x.Clone()).ToList();
            _heuristicsHistoryByPid[tab.Pid] = snapshot.HeuristicsGroups.Select(x => x.Clone()).ToList();
            _filesystemHistoryByPid[tab.Pid] = snapshot.FilesystemGroups.Select(x => x.Clone()).ToList();
            _registryHistoryByPid[tab.Pid] = snapshot.RegistryGroups.Select(x => x.Clone()).ToList();
            _relationsHistoryByPid[tab.Pid] = snapshot.ProcessRelationsGroups.Select(x => x.Clone()).ToList();
            _apiGraphHistoryByPid[tab.Pid] = snapshot.ApiGraphRows.Select(x => x.Clone()).ToList();
            _extendedHistoryByPid[tab.Pid] = snapshot.ExtendedActivityRows.Select(x => x.Clone()).ToList();
        }

        private bool TryLoadTabSnapshot(ProcessSessionTab tab, out SessionFileTab? snapshot)
        {
            snapshot = null;
            if (tab.Pid <= 0 || !SessionFileStorage.Exists(tab.BackingStorePath))
            {
                return false;
            }

            SessionFileArchive archive = SessionFileStorage.LoadArchive(tab.BackingStorePath!);
            snapshot = archive.Tabs.FirstOrDefault(x => x.Pid == tab.Pid) ?? archive.Tabs.FirstOrDefault();
            return snapshot != null;
        }

        private bool HasInlineSessionData(ProcessSessionTab tab)
        {
            return (ReferenceEquals(tab, _currentSession) && _allEvents.Count > 0) || tab.Events.Count > 0 ||
                   tab.PerformanceHistory.Count > 0 || tab.MemoryRegionAttributionHistory.Count > 0 ||
                   tab.ThreadLifecycleHistory.Count > 0 || tab.ThreadStackHistories.Count > 0 ||
                   _etwHistoryByPid.ContainsKey(tab.Pid) || _heuristicsHistoryByPid.ContainsKey(tab.Pid) ||
                   _filesystemHistoryByPid.ContainsKey(tab.Pid) || _registryHistoryByPid.ContainsKey(tab.Pid) ||
                   _relationsHistoryByPid.ContainsKey(tab.Pid) || _apiGraphHistoryByPid.ContainsKey(tab.Pid) ||
                   _extendedHistoryByPid.ContainsKey(tab.Pid);
        }

        private IEnumerable<TelemetryEvent> EnumerateSessionEvents(ProcessSessionTab tab)
        {
            if (ReferenceEquals(tab, _currentSession))
            {
                return _allEvents;
            }

            return tab.Events;
        }

        private bool TryGetIntelDetailsFromBackingStore(int pid, IntelDetailsCategory category,
                                                        out IReadOnlyList<GroupedEventDetailRow> details)
        {
            details = Array.Empty<GroupedEventDetailRow>();
            if (pid <= 0)
            {
                return false;
            }

            ProcessSessionTab? tab = _processTabs.FirstOrDefault(x => x.Pid == pid);
            if (tab == null || !SessionFileStorage.Exists(tab.BackingStorePath))
            {
                return false;
            }

            SessionFileArchive archive = SessionFileStorage.LoadArchive(tab.BackingStorePath!);
            SessionFileTab? snapshot = archive.Tabs.FirstOrDefault(x => x.Pid == pid) ?? archive.Tabs.FirstOrDefault();
            if (snapshot == null)
            {
                return false;
            }

            IEnumerable<GroupedEventRow> groups =
                category switch { IntelDetailsCategory.Etw => snapshot.EtwGroups,
                                  IntelDetailsCategory.Heuristics => snapshot.HeuristicsGroups,
                                  IntelDetailsCategory.Filesystem => snapshot.FilesystemGroups,
                                  IntelDetailsCategory.ProcessRelations => snapshot.ProcessRelationsGroups,
                                  _ => Enumerable.Empty<GroupedEventRow>() };

            details = FlattenGroupedDetails(groups);
            return details.Count > 0;
        }

        private SessionFileArchive BuildWorkspaceArchive()
        {
            _liveCaptureStore?.Flush();
            SyncCurrentSessionStateToMemory();

            var archive = new SessionFileArchive { Version = SessionFileStorage.CurrentVersion,
                                                   SavedUtc = DateTime.UtcNow, ActivePid = _currentSession?.Pid ?? 0 };

            foreach (ProcessSessionTab tab in _processTabs)
            {
                bool reuseExistingCaptureStore =
                    !ReferenceEquals(tab, _currentSession) || tab.OfflineSnapshot || tab.TargetExited;
                archive.Tabs.Add(BuildTabSnapshot(tab, reuseExistingCaptureStore));
            }

            return archive;
        }

        private async Task<SessionFileArchive> BuildWorkspaceArchiveAsync(string statusText)
        {
            Cursor? previousCursor = Mouse.OverrideCursor;
            string previousStatus = StatusBlock.Text;
            try
            {
                Mouse.OverrideCursor = Cursors.Wait;
                StatusBlock.Text = statusText;
                await Task.Yield();

                _liveCaptureStore?.Flush();
                await System.Windows.Threading.Dispatcher.Yield(System.Windows.Threading.DispatcherPriority.Background);

                SyncCurrentSessionStateToMemory();
                await System.Windows.Threading.Dispatcher.Yield(System.Windows.Threading.DispatcherPriority.Background);

                var archive =
                    new SessionFileArchive { Version = SessionFileStorage.CurrentVersion, SavedUtc = DateTime.UtcNow,
                                             ActivePid = _currentSession?.Pid ?? 0 };

                List<ProcessSessionTab> tabs = _processTabs.ToList();
                foreach (ProcessSessionTab tab in tabs)
                {
                    bool reuseExistingCaptureStore =
                        !ReferenceEquals(tab, _currentSession) || tab.OfflineSnapshot || tab.TargetExited;
                    archive.Tabs.Add(BuildTabSnapshot(tab, reuseExistingCaptureStore));
                    await System.Windows.Threading.Dispatcher.Yield(
                        System.Windows.Threading.DispatcherPriority.Background);
                }

                return archive;
            }
            finally
            {
                Mouse.OverrideCursor = previousCursor;
                if (string.Equals(StatusBlock.Text, statusText, StringComparison.Ordinal))
                {
                    StatusBlock.Text = previousStatus;
                }
            }
        }

        private async Task ApplyWorkspaceArchiveAsync(CaptureLoadedWorkspace workspace, bool merge)
        {
            SessionFileArchive archive = workspace.Archive;
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
                ReleaseOwnedTemporaryWorkspaces();
            }

            await System.Windows.Threading.Dispatcher.Yield(System.Windows.Threading.DispatcherPriority.Background);

            foreach (SessionFileTab incoming in archive.Tabs)
            {
                if (incoming.Pid <= 0)
                {
                    continue;
                }

                ProcessSessionTab tab = _processTabs.FirstOrDefault(x => x.Pid == incoming.Pid) ??
                                        AddOrSelectProcessTab(incoming.Pid, incoming.Title, select: false);

                tab.Title = NormalizeSessionTitle(string.IsNullOrWhiteSpace(incoming.Title) ? $"PID {incoming.Pid}"
                                                                                            : incoming.Title);
                tab.CaptureStartUtc = incoming.CaptureStartUtc;
                tab.ViewDurationSeconds = incoming.ViewDurationSeconds;
                tab.ViewStartSeconds = incoming.ViewStartSeconds;
                tab.LaneFocusKey = incoming.LaneFocusKey;
                tab.UseUsermodeHooks = incoming.UseUsermodeHooks;
                tab.KernelHooksEnabled = incoming.KernelHooksEnabled;
                tab.SignatureIntelEnabled = incoming.SignatureIntelEnabled;
                tab.SignatureIntelMemoryScanEnabled = incoming.SignatureIntelMemoryScanEnabled;
                tab.SignatureIntelPageScanEnabled = incoming.SignatureIntelPageScanEnabled;
                tab.TargetExited = incoming.TargetExited;
                tab.TargetExitReason = incoming.TargetExitReason;
                tab.OfflineSnapshot = true;
                tab.AnalysisSubjectKind = incoming.AnalysisSubjectKind;
                tab.AnalysisSubjectPath = incoming.AnalysisSubjectPath;
                tab.AnalysisHostPath = incoming.AnalysisHostPath;

                bool usingBackingStore = false;
                if (workspace.TabPaths.TryGetValue(incoming.Pid, out string? existingPath) &&
                    SessionFileStorage.Exists(existingPath))
                {
                    tab.BackingStorePath = existingPath;
                    usingBackingStore = true;
                }
                else
                {
                    tab.BackingStorePath = null;
                    MaterializeLoadedSnapshot(tab, incoming);
                }

                if (usingBackingStore)
                {
                    tab.Events.Clear();
                    tab.PerformanceHistory.Clear();
                    tab.MemoryRegionAttributionHistory.Clear();
                    tab.ThreadLifecycleHistory.Clear();
                    tab.ThreadStackHistories.Clear();
                    _etwHistoryByPid.Remove(tab.Pid);
                    _heuristicsHistoryByPid.Remove(tab.Pid);
                    _filesystemHistoryByPid.Remove(tab.Pid);
                    _registryHistoryByPid.Remove(tab.Pid);
                    _relationsHistoryByPid.Remove(tab.Pid);
                    _apiGraphHistoryByPid.Remove(tab.Pid);
                    _extendedHistoryByPid.Remove(tab.Pid);
                }

                await System.Windows.Threading.Dispatcher.Yield(System.Windows.Threading.DispatcherPriority.Background);
            }

            ProcessSessionTab? toSelect =
                _processTabs.FirstOrDefault(x => x.Pid == archive.ActivePid) ?? _processTabs.FirstOrDefault();
            if (toSelect == null)
            {
                return;
            }

            SessionFileTab? selectedSnapshot =
                archive.Tabs.FirstOrDefault(x => x.Pid == toSelect.Pid) ?? archive.Tabs.FirstOrDefault();
            if (selectedSnapshot != null)
            {
                await System.Windows.Threading.Dispatcher.Yield(System.Windows.Threading.DispatcherPriority.Background);
                MaterializeLoadedSnapshot(toSelect, selectedSnapshot);
            }

            _suppressTabSelectionChange = true;
            ProcessTabs.SelectedItem = toSelect;
            _suppressTabSelectionChange = false;
            SwitchToSession(toSelect);
            await System.Windows.Threading.Dispatcher.Yield(System.Windows.Threading.DispatcherPriority.Background);
        }

        private void MaterializeLoadedSnapshot(ProcessSessionTab tab, SessionFileTab snapshot)
        {
            tab.Events.Clear();
            tab.Events.AddRange(snapshot.Events.Select(CloneTelemetryEvent));
            tab.PerformanceHistory.Clear();
            tab.PerformanceHistory.AddRange(snapshot.PerformanceHistory.Select(ClonePerformanceSample));
            tab.MemoryRegionAttributionHistory.Clear();
            tab.MemoryRegionAttributionHistory.AddRange(
                snapshot.MemoryRegionAttributionHistory.Select(CloneMemoryRegionAttributionSample));
            tab.ThreadLifecycleHistory.Clear();
            tab.ThreadLifecycleHistory.AddRange(snapshot.ThreadLifecycleHistory.Select(CloneThreadLifecycleEvent));
            tab.ThreadStackHistories.Clear();
            tab.ThreadStackHistories.AddRange(snapshot.ThreadStackHistories.Select(x => x.Clone()));

            _etwHistoryByPid[tab.Pid] = snapshot.EtwGroups.Select(x => x.Clone()).ToList();
            _heuristicsHistoryByPid[tab.Pid] = snapshot.HeuristicsGroups.Select(x => x.Clone()).ToList();
            _filesystemHistoryByPid[tab.Pid] = snapshot.FilesystemGroups.Select(x => x.Clone()).ToList();
            _registryHistoryByPid[tab.Pid] = snapshot.RegistryGroups.Select(x => x.Clone()).ToList();
            _relationsHistoryByPid[tab.Pid] = snapshot.ProcessRelationsGroups.Select(x => x.Clone()).ToList();
            _apiGraphHistoryByPid[tab.Pid] = snapshot.ApiGraphRows.Select(x => x.Clone()).ToList();
            _extendedHistoryByPid[tab.Pid] = snapshot.ExtendedActivityRows.Select(x => x.Clone()).ToList();
        }

        private async void SaveSessionAs_Click(object sender, RoutedEventArgs e)
        {
            await SaveSessionArchiveViaDialogAsync();
        }

        private async void ExportSession_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new SaveFileDialog {
                Filter = "Blackbird Capture Archive (*.bkcap)|*.bkcap|" + "SIEM JSON Lines (*.jsonl)|*.jsonl|" +
                         "SIEM CSV (*.csv)|*.csv|" + "CEF (*.cef)|*.cef|" +
                         "ATT&CK-ready CSV (*.attack.csv)|*.attack.csv|" + "All files (*.*)|*.*",
                DefaultExt = CaptureArchiveExtension, AddExtension = true, OverwritePrompt = true,
                FileName = $"Blackbird-export-{DateTime.UtcNow:yyyyMMdd-HHmmss}{CaptureArchiveExtension}"
            };

            if (dialog.ShowDialog(this) != true)
            {
                return;
            }

            try
            {
                SessionFileArchive archive = await BuildWorkspaceArchiveAsync("Preparing session export...");
                if (IsCaptureArchivePath(dialog.FileName))
                {
                    await RunSessionStorageOperationAsync(
                        "Exporting session...",
                        () => Task.Run(() => SessionFileStorage.SaveArchive(dialog.FileName, archive)));
                    StatusBlock.Text = $"SESSION EXPORTED: {Path.GetFileName(dialog.FileName)}";
                    return;
                }

                SessionExportFormat format = ResolveSessionExportFormat(dialog.FileName, dialog.FilterIndex);
                await RunSessionStorageOperationAsync(
                    "Exporting session...",
                    () => Task.Run(() => SessionExportService.Export(dialog.FileName, archive, format)));
                StatusBlock.Text = $"SESSION EXPORTED: {Path.GetFileName(dialog.FileName)}";
            }
            catch (Exception ex)
            {
                ThemedMessageBox.Show(this, $"Failed to export session.\n\n{ex.Message}", "Export Session",
                                      MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private async void ExportDetections_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new SaveFileDialog {
                Filter = "SIEM Detection JSON Lines (*.detections.jsonl)|*.detections.jsonl|" +
                         "Splunk HEC Events (*.splunk.json)|*.splunk.json|" +
                         "Elastic ECS NDJSON (*.ecs.ndjson)|*.ecs.ndjson|" +
                         "CEF Detections (*.detections.cef)|*.detections.cef|" +
                         "Detection CSV (*.detections.csv)|*.detections.csv|" + "All files (*.*)|*.*",
                DefaultExt = ".detections.jsonl", AddExtension = true, OverwritePrompt = true,
                FileName = $"Blackbird-detections-{DateTime.UtcNow:yyyyMMdd-HHmmss}.detections.jsonl"
            };

            if (dialog.ShowDialog(this) != true)
            {
                return;
            }

            try
            {
                SessionFileArchive archive = await BuildWorkspaceArchiveAsync("Preparing detections export...");
                SessionExportFormat format = ResolveDetectionExportFormat(dialog.FileName, dialog.FilterIndex);
                int exported = await RunSessionStorageOperationAsync(
                    "Exporting detections...",
                    () => Task.Run(() => SessionExportService.Export(dialog.FileName, archive, format)));
                StatusBlock.Text = $"DETECTIONS EXPORTED: {exported} events -> {Path.GetFileName(dialog.FileName)}";
                if (exported == 0)
                {
                    ThemedMessageBox.Show(this, "No detections were available to export.", "Export Detections",
                                          MessageBoxButton.OK, MessageBoxImage.Information);
                }
            }
            catch (Exception ex)
            {
                ThemedMessageBox.Show(this, $"Failed to export detections.\n\n{ex.Message}", "Export Detections",
                                      MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private async Task<string> TryOpenSessionArchivePathAsync(string path, bool merge)
        {
            if (string.IsNullOrWhiteSpace(path) || !SessionFileStorage.Exists(path))
            {
                return "Session file not found.";
            }

            try
            {
                CaptureLoadedWorkspace workspace =
                    await RunSessionStorageOperationAsync(merge ? "Importing session..." : "Opening session...",
                                                          () => Task.Run(() => SessionFileStorage.LoadWorkspace(path)));
                RegisterTemporaryWorkspace(workspace);
                await ApplyWorkspaceArchiveAsync(workspace, merge);
                if (!merge)
                {
                    _sessionFilePath = path;
                }

                string verb = merge ? "IMPORTED" : "OPENED";
                StatusBlock.Text = $"SESSION {verb}: {Path.GetFileName(path)}";
                return string.Empty;
            }
            catch (Exception ex)
            {
                return ex.Message.Contains("manifest not found", StringComparison.OrdinalIgnoreCase)
                           ? "Capture archive is invalid or incomplete."
                           : ex.Message;
            }
        }

        private async void OpenSession_Click(object sender, RoutedEventArgs e)
        {
            var dialog =
                new OpenFileDialog { Filter = CaptureArchiveOpenFilter, CheckFileExists = true, Multiselect = false };

            if (dialog.ShowDialog(this) != true)
            {
                return;
            }

            string error = await TryOpenSessionArchivePathAsync(dialog.FileName, merge: false);
            if (!string.IsNullOrEmpty(error))
            {
                ThemedMessageBox.Show(this, $"Failed to open session.\n\n{error}", "Open Session", MessageBoxButton.OK,
                                      MessageBoxImage.Error);
            }
        }

        private async void ImportSession_Click(object sender, RoutedEventArgs e)
        {
            var dialog =
                new OpenFileDialog { Filter = CaptureArchiveOpenFilter, CheckFileExists = true, Multiselect = false };

            if (dialog.ShowDialog(this) != true)
            {
                return;
            }

            string error = await TryOpenSessionArchivePathAsync(dialog.FileName, merge: true);
            if (!string.IsNullOrEmpty(error))
            {
                ThemedMessageBox.Show(this, $"Failed to import session.\n\n{error}", "Import Session",
                                      MessageBoxButton.OK, MessageBoxImage.Error);
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
                "Exit Session", MessageBoxButton.YesNoCancel, MessageBoxImage.Question);
            if (choice == MessageBoxResult.Cancel)
            {
                return false;
            }

            return choice != MessageBoxResult.Yes || SaveSessionArchiveViaDialog();
        }

        private bool SaveSessionArchiveViaDialog()
        {
            var dialog =
                new SaveFileDialog { Filter = CaptureArchiveSaveFilter, DefaultExt = CaptureArchiveExtension,
                                     AddExtension = true, OverwritePrompt = true,
                                     FileName =
                                         $"Blackbird-{DateTime.UtcNow:yyyyMMdd-HHmmss}{CaptureArchiveExtension}" };

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
                ThemedMessageBox.Show(this, $"Failed to save session.\n\n{ex.Message}", "Save Session",
                                      MessageBoxButton.OK, MessageBoxImage.Error);
                return false;
            }
        }

        private async Task<bool> SaveSessionArchiveViaDialogAsync()
        {
            var dialog =
                new SaveFileDialog { Filter = CaptureArchiveSaveFilter, DefaultExt = CaptureArchiveExtension,
                                     AddExtension = true, OverwritePrompt = true,
                                     FileName =
                                         $"Blackbird-{DateTime.UtcNow:yyyyMMdd-HHmmss}{CaptureArchiveExtension}" };

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
                SessionFileArchive archive = await BuildWorkspaceArchiveAsync("Preparing session save...");
                await RunSessionStorageOperationAsync(
                    "Saving session...",
                    () => Task.Run(() => SessionFileStorage.SaveArchive(dialog.FileName, archive)));
                _sessionFilePath = dialog.FileName;
                StatusBlock.Text = $"SESSION SAVED: {Path.GetFileName(dialog.FileName)}";
                return true;
            }
            catch (Exception ex)
            {
                ThemedMessageBox.Show(this, $"Failed to save session.\n\n{ex.Message}", "Save Session",
                                      MessageBoxButton.OK, MessageBoxImage.Error);
                return false;
            }
        }

        private async Task RunSessionStorageOperationAsync(string statusText, Func<Task> operation)
        {
            await RunSessionStorageOperationAsync(statusText, async () =>
                                                              {
                                                                  await operation();
                                                                  return true;
                                                              });
        }

        private async Task<T> RunSessionStorageOperationAsync<T>(string statusText, Func<Task<T>> operation)
        {
            Cursor? previousCursor = Mouse.OverrideCursor;
            string previousStatus = StatusBlock.Text;
            try
            {
                Mouse.OverrideCursor = Cursors.Wait;
                StatusBlock.Text = statusText;
                await Task.Yield();
                return await operation();
            }
            finally
            {
                Mouse.OverrideCursor = previousCursor;
                if (string.Equals(StatusBlock.Text, statusText, StringComparison.Ordinal))
                {
                    StatusBlock.Text = previousStatus;
                }
            }
        }

        private static bool IsCaptureArchivePath(string path)
        {
            string extension = Path.GetExtension(path ?? string.Empty);
            return extension.Equals(CaptureArchiveExtension, StringComparison.OrdinalIgnoreCase) ||
                   extension.Equals(".swlkr", StringComparison.OrdinalIgnoreCase) ||
                   extension.Equals(".blackbird", StringComparison.OrdinalIgnoreCase);
        }

        private static SessionExportFormat ResolveSessionExportFormat(string path, int filterIndex)
        {
            string fileName = Path.GetFileName(path ?? string.Empty);
            if (fileName.EndsWith(".attack.csv", StringComparison.OrdinalIgnoreCase))
            {
                return SessionExportFormat.AttackCsv;
            }

            return Path.GetExtension(path ?? string.Empty).ToLowerInvariant() switch
            {
                ".jsonl" => SessionExportFormat.JsonLines, ".csv" => SessionExportFormat.Csv,
                ".cef" => SessionExportFormat.Cef,
                _ => filterIndex switch
                {
                    2 => SessionExportFormat.JsonLines,
                    3 => SessionExportFormat.Csv,
                    4 => SessionExportFormat.Cef,
                    5 => SessionExportFormat.AttackCsv,
                    _ => SessionExportFormat.JsonLines
                }
            };
        }

        private static SessionExportFormat ResolveDetectionExportFormat(string path, int filterIndex)
        {
            if (filterIndex is >= 1 and <= 5)
            {
                return filterIndex switch {
                    1 => SessionExportFormat.DetectionJsonLines,
                    2 => SessionExportFormat.SplunkHecJson,
                    3 => SessionExportFormat.ElasticEcsJsonLines,
                    4 => SessionExportFormat.DetectionCef,
                    5 => SessionExportFormat.DetectionCsv,
                    _ => SessionExportFormat.DetectionJsonLines
                };
            }

            string fileName = Path.GetFileName(path ?? string.Empty);
            if (fileName.EndsWith(".detections.csv", StringComparison.OrdinalIgnoreCase))
            {
                return SessionExportFormat.DetectionCsv;
            }
            if (fileName.EndsWith(".detections.cef", StringComparison.OrdinalIgnoreCase))
            {
                return SessionExportFormat.DetectionCef;
            }
            if (fileName.EndsWith(".splunk.json", StringComparison.OrdinalIgnoreCase))
            {
                return SessionExportFormat.SplunkHecJson;
            }
            if (fileName.EndsWith(".ecs.ndjson", StringComparison.OrdinalIgnoreCase))
            {
                return SessionExportFormat.ElasticEcsJsonLines;
            }
            if (fileName.EndsWith(".detections.jsonl", StringComparison.OrdinalIgnoreCase))
            {
                return SessionExportFormat.DetectionJsonLines;
            }

            return SessionExportFormat.DetectionJsonLines;
        }

        private bool HasSessionCacheData()
        {
            if (_currentSession != null &&
                (_allEvents.Count > 0 || _currentSession.PerformanceHistory.Count > 0 ||
                 _currentSession.ThreadLifecycleHistory.Count > 0 || _currentSession.ThreadStackHistories.Count > 0))
            {
                return true;
            }

            return _processTabs.Any(x => HasInlineSessionData(x) || SessionFileStorage.Exists(x.BackingStorePath));
        }

        private void CleanupTemporarySessionBackingStores()
        {
            foreach (ProcessSessionTab tab in _processTabs)
            {
                if (!IsSessionCachePath(tab.BackingStorePath) || !SessionFileStorage.Exists(tab.BackingStorePath))
                {
                    continue;
                }

                try
                {
                    SessionFileStorage.DeletePath(tab.BackingStorePath);
                }
                catch
                {
                }
            }

            ReleaseOwnedTemporaryWorkspaces();
        }

        private void SpillCurrentSessionWorkingSetIfNeeded()
        {
            if (_currentSession == null || _currentSession.OfflineSnapshot || _currentSession.Pid <= 0)
            {
                return;
            }

            if (_liveCaptureStore != null)
            {
                return;
            }

            DateTime now = DateTime.UtcNow;
            if (_currentSession.BackingStorePath != null &&
                SessionFileStorage.Exists(_currentSession.BackingStorePath) &&
                now - SessionFileStorage.GetLastWriteTimeUtc(_currentSession.BackingStorePath) < SessionSpillInterval)
            {
                return;
            }

            int totalGroupedDetails = EtwPaneHost.DetailRowCount + HeuristicsPaneHost.DetailRowCount +
                                      FilesystemPaneHost.DetailRowCount + ProcessRelationsPaneHost.DetailRowCount;
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
            snapshot.CaptureStorePath = path;
            SessionFileStorage.SaveArchive(path, CreateSingleTabArchive(snapshot));
            SaveIntelSessionState(_currentSession.Pid);
        }

        private IReadOnlyList<ThreadStackSessionSnapshot> GetThreadStackHistory(int pid, int tid, string state)
        {
            ProcessSessionTab? tab = ResolveSessionTab(pid);
            if (tab == null)
            {
                return Array.Empty<ThreadStackSessionSnapshot>();
            }

            EnsureSessionMaterialized(tab);
            return tab.ThreadStackHistories.Where(x => x.Tid == tid)
                .SelectMany(x => x.Snapshots)
                .Select(x => x.Clone())
                .OrderBy(x => x.CapturedAtUtc)
                .ToList();
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
            ThreadStackHistoryArchiveEntry? history = tab.ThreadStackHistories.FirstOrDefault(x => x.Tid == tid);
            if (history == null)
            {
                history = new ThreadStackHistoryArchiveEntry { Tid = tid, State = normalizedState };
                tab.ThreadStackHistories.Add(history);
            }

            if (!string.IsNullOrWhiteSpace(normalizedState))
            {
                history.State = normalizedState;
            }

            int existingIndex = history.Snapshots.FindIndex(x => x.CapturedAtUtc == snapshot.CapturedAtUtc);
            if (existingIndex >= 0)
            {
                history.Snapshots[existingIndex] = snapshot.Clone();
            }
            else
            {
                history.Snapshots.Add(snapshot.Clone());
                history.Snapshots = history.Snapshots.OrderBy(x => x.CapturedAtUtc).ToList();
            }

            if (history.Snapshots.Count > MaxLiveThreadStackSnapshotsPerThread)
            {
                history.Snapshots =
                    history.Snapshots.Skip(history.Snapshots.Count - MaxLiveThreadStackSnapshotsPerThread).ToList();
            }

            if (tab.ThreadStackHistories.Count > MaxLiveThreadStackHistoriesPerTab)
            {
                List<ThreadStackHistoryArchiveEntry> retained =
                    tab.ThreadStackHistories
                        .OrderByDescending(x => x.Snapshots.Count == 0 ? DateTime.MinValue
                                                                       : x.Snapshots.Max(s => s.CapturedAtUtc))
                        .Take(MaxLiveThreadStackHistoriesPerTab)
                        .OrderBy(x => x.Tid)
                        .ToList();
                tab.ThreadStackHistories.Clear();
                tab.ThreadStackHistories.AddRange(retained);
            }

            if (ReferenceEquals(tab, _currentSession))
            {
                PerformancePaneHost.LoadThreadStackHistory(tab.ThreadStackHistories);
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
