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
    internal sealed class CaptureProjectionEngine
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

        internal void ObservePerformance(PerformanceSample sample)
        {
            lock (_sync)
            {
                _performance.Add(ClonePerformanceSample(sample));
                TrimHead(_performance, MaxPerformanceSamples);
            }
        }

        internal void ObserveStatus(string line)
        {
            string value = (line ?? string.Empty).Trim();
            if (value.Length == 0)
            {
                return;
            }

            lock (_sync)
            {
                DateTime nowUtc = DateTime.UtcNow;
                _statusLines.Add($"{nowUtc:O} {value}");
                TrimHead(_statusLines, MaxStatusLines);
                AddExtended("Diagnostics", CaptureActorLabel, _sourceLabel, "session-status", value, nowUtc, 1);
            }
        }

        internal void ObserveIoctl(IoctlParsedEvent record, DateTime timestampUtc)
        {
            if (record == null)
            {
                return;
            }

            DateTime observedUtc = timestampUtc == default ? DateTime.UtcNow : timestampUtc;
            lock (_sync)
            {
                _ioctlTotal += 1;
                TrackIoctlProcessRelationships(record, observedUtc);
                switch (record.Type)
                {
                case BlackbirdNative.EventTypeHandle:
                    ObserveHandleIoctl(record, observedUtc);
                    break;
                case BlackbirdNative.EventTypeThread:
                    ObserveThreadIoctl(record, observedUtc);
                    break;
                case BlackbirdNative.EventTypeFileSystem:
                    ObserveFilesystemIoctl(record, observedUtc);
                    break;
                case BlackbirdNative.EventTypeRegistry:
                    ObserveRegistryIoctl(record, observedUtc);
                    break;
                case BlackbirdNative.EventTypeEnterprise:
                    ObserveEnterpriseIoctl(record, observedUtc);
                    break;
                default:
                    AddExtended("IOCTL", PidLabel(record.CallerPid), PidLabel(record.TargetPid), "Unknown",
                                $"type={record.Type} sequence={record.Sequence}", observedUtc, 1);
                    break;
                }
            }
        }

        internal void ObserveEtw(BrokerEtwEventView view)
        {
            if (view == null)
            {
                return;
            }

            DateTime observedUtc = view.TimestampUtc == default ? DateTime.UtcNow : view.TimestampUtc;
            lock (_sync)
            {
                _etwTotal += Math.Max(1, view.RepeatCount);
                string family = DescribeEtwFamily(view.Family);
                string eventName = FirstNonEmpty(view.EventName, view.DetectionName, "ETW");
                string detection = FirstNonEmpty(view.DetectionName, eventName);
                string source = FirstNonEmpty(view.Source, "ETW");
                uint actorPid = ResolveActorPid(view);
                uint targetPid = ResolveTargetPid(view);
                bool apiCandidate = EventDetailFormatting.IsApiGraphCandidate(view);
                bool highSignal = apiCandidate || !string.IsNullOrWhiteSpace(view.DetectionName) ||
                                  view.Family == BlackbirdNative.IpcEtwFamilyDetection ||
                                  view.Family == BlackbirdNative.IpcEtwFamilyThreatIntel || view.Severity >= 5;
                string details =
                    highSignal ? view.Details : FirstNonEmpty(view.Reason, view.Operation, eventName, view.Summary);
                string argument = apiCandidate ? FirstNonEmpty(view.ArgumentSummary, view.Reason, details)
                                               : FirstNonEmpty(view.Reason, view.Operation, eventName);
                int hitCount = Math.Max(1, view.RepeatCount);

                IncrementCount(_etwFamilyCounts, family, hitCount);
                IncrementCount(_etwEventCounts, $"{family}/{eventName}", hitCount);
                TrackEtwProcessRelationships(view, actorPid, targetPid, observedUtc);
                PersistObservedHookStackSnapshot(view, observedUtc);
                QueueThreadStackFallbackCapture(view, observedUtc);

                AddGroup(_etwGroups, $"etw:{source}:{family}:{eventName}:{actorPid}:{targetPid}", eventName,
                         SeverityLabel(view.Severity), detection, $"{source}/{family}", actorPid, targetPid, argument,
                         details, observedUtc, hitCount);

                if (!string.IsNullOrWhiteSpace(view.DetectionName) ||
                    view.Family == BlackbirdNative.IpcEtwFamilyDetection ||
                    view.Family == BlackbirdNative.IpcEtwFamilyThreatIntel)
                {
                    AddGroup(_heuristicGroups, $"heuristic:{view.DetectionName}:{actorPid}:{targetPid}:{view.Reason}",
                             eventName, SeverityLabel(view.Severity), detection, source, actorPid, targetPid, argument,
                             details, observedUtc, hitCount);
                }

                if (view.Family == BlackbirdNative.IpcEtwFamilyRegistry || !string.IsNullOrWhiteSpace(view.KeyPath))
                {
                    ObserveEtwRegistry(view, observedUtc);
                }

                ProcessEtwRelation(view, observedUtc);
                ProcessApiGraph(view, observedUtc);
                ProcessMemoryAttribution(view, observedUtc);

                AddExtended(family, PidLabel(actorPid), PidLabel(targetPid),
                            FirstNonEmpty(view.KeyPath, view.ImagePath, view.OriginPath, source),
                            FirstNonEmpty(view.Operation, eventName, detection), observedUtc, hitCount, argument);
            }
        }

        internal void WaitForPendingStackCaptures(TimeSpan timeout)
        {
            Task[] pending;
            lock (_sync)
            {
                pending = _pendingThreadStackCaptures.Where(static task => !task.IsCompleted).ToArray();
            }

            if (pending.Length == 0)
            {
                return;
            }

            try
            {
                Task.WaitAll(pending, timeout);
            }
            catch (AggregateException)
            {
            }

            lock (_sync)
            {
                _pendingThreadStackCaptures.RemoveAll(static task => task.IsCompleted);
            }
        }

        internal void CaptureStaticProcessSnapshot(string imagePath, string displayName, string peKindLabel,
                                                   LaunchProfile profile)
        {
            lock (_sync)
            {
                DateTime nowUtc = DateTime.UtcNow;
                FileInfo? sample = TryGetFileInfo(imagePath);
                string peDetail =
                    sample == null
                        ? $"kind={peKindLabel} path={imagePath}"
                        : $"kind={peKindLabel} path={imagePath} bytes={sample.Length} createdUtc={sample.CreationTimeUtc:O} modifiedUtc={sample.LastWriteTimeUtc:O}";
                AddExtended("PE", PidLabel((uint)_targetPid), displayName, imagePath, "sample-metadata", nowUtc, 1,
                            peDetail);
                AddGroup(_etwGroups, $"pe:{imagePath}", "PE Snapshot", "Info", $"PE {peKindLabel}", _sourceLabel,
                         (uint)_targetPid, 0, imagePath, peDetail, nowUtc, 1);

                string launchDetail =
                    $"targetKind={profile.TargetKind} workingDirectory={profile.WorkingDirectory} args={profile.CommandLineArguments} integrity={profile.IntegrityLevel} priority={profile.Priority} inheritHandles={profile.InheritHandles} parentPid={profile.ParentProcessId} dllMode={profile.DllMode} dllExport={profile.DllExportName} dllOrdinal={profile.DllExportOrdinal}";
                AddExtended("Diagnostics", CaptureActorLabel, PidLabel((uint)_targetPid), "launch-options",
                            "launch-profile", nowUtc, 1, launchDetail);

                try
                {
                    using Process process = Process.GetProcessById(_targetPid);
                    foreach (ProcessModule module in process.Modules.Cast<ProcessModule>().Take(2048))
                    {
                        string modulePath = SafeModulePath(module);
                        string moduleDetail =
                            $"base=0x{module.BaseAddress.ToInt64():X} size=0x{module.ModuleMemorySize:X} file={modulePath}";
                        AddGroup(_etwGroups, $"module:{module.BaseAddress.ToInt64():X}:{modulePath}", "Module Snapshot",
                                 "Info", Path.GetFileName(modulePath), "Process.Modules", (uint)_targetPid, 0,
                                 modulePath, moduleDetail, nowUtc, 1);
                        AddExtended("Module", PidLabel((uint)_targetPid), modulePath,
                                    $"0x{module.BaseAddress.ToInt64():X}", "loaded-module", nowUtc, 1, moduleDetail);
                    }

                    foreach (ProcessThread thread in process.Threads.Cast<ProcessThread>().Take(4096))
                    {
                        var sampleThread = new ThreadLifecycleEventSample {
                            TimestampUtc = nowUtc, ProcessPid = (uint)_targetPid, ThreadId = unchecked((uint)thread.Id),
                            EventKind = "Observed",
                            Notes =
                                $"state={thread.ThreadState} wait={SafeWaitReason(thread)} startUtc={FormatNullableUtc(SafeThreadStart(thread))}"
                        };
                        _threadLifecycle.Add(sampleThread);
                    }

                    TrimHead(_threadLifecycle, MaxThreadLifecycleEvents);
                }
                catch (Exception ex)
                {
                    AddExtended("Diagnostics", CaptureActorLabel, PidLabel((uint)_targetPid), "process-snapshot",
                                "snapshot-warning", nowUtc, 1, ex.Message);
                }
            }
        }

        internal string FinalizeRun(int exitCode, int ioctlEvents, int etwEvents, TimeSpan duration)
        {
            lock (_sync)
            {
                string detail =
                    $"capture={_captureId} targetPid={_targetPid} trackedPids={string.Join(",", _trackedPids.OrderBy(x => x))} exitCode={exitCode} durationMs={duration.TotalMilliseconds:0} ioctl={ioctlEvents} etw={etwEvents} perfSamples={_performance.Count} memoryAttributions={_memoryAttributions.Count} apiRows={_apiGraphRows.Count} extendedRows={_extendedRows.Count} threadStacks={_threadStacks.Count} observedHookStacks={_observedHookStacks} fallbackStacks={_fallbackStackCaptures} fallbackMisses={_fallbackStackMisses} etwFamilies=[{FormatTopCounts(_etwFamilyCounts, 10)}] apiCandidates=[{FormatTopCounts(_apiCandidateCounts, 10)}] topEtw=[{FormatTopCounts(_etwEventCounts, 12)}]";
                AddExtended("Diagnostics", CaptureActorLabel, PidLabel((uint)_targetPid), "run-summary",
                            "capture-finalized", DateTime.UtcNow, 1, detail);
                AddGroup(_heuristicGroups, $"diagnostics:{_captureId}:summary", "Run Diagnostics", "Info",
                         "Capture finalized", _sourceLabel, (uint)_targetPid, 0, "run-summary",
                         detail + Environment.NewLine + string.Join(Environment.NewLine, _statusLines.TakeLast(64)),
                         DateTime.UtcNow, 1);
                return detail;
            }
        }

        internal void ApplyToTab(SessionFileTab tab, LaunchProfile profile, string imagePath, string displayName,
                                 int exitCode)
        {
            lock (_sync)
            {
                tab.Title = string.IsNullOrWhiteSpace(displayName) ? tab.Title : displayName;
                tab.CaptureStartUtc = _captureStartUtc;
                tab.ViewDurationSeconds = Math.Max(120, (DateTime.UtcNow - _captureStartUtc).TotalSeconds);
                tab.UseUsermodeHooks = true;
                tab.KernelHooksEnabled = true;
                tab.SignatureIntelEnabled = true;
                tab.SignatureIntelMemoryScanEnabled = true;
                tab.SignatureIntelPageScanEnabled = true;
                tab.TargetExited = true;
                tab.TargetExitReason = $"runner finalized exitCode={exitCode}";
                tab.OfflineSnapshot = true;
                tab.AnalysisSubjectKind = profile.TargetKind;
                tab.AnalysisSubjectPath = profile.TargetKind == LaunchTargetKind.Dll
                                              ? FirstNonEmpty(profile.AnalysisSubjectPath, imagePath)
                                              : imagePath;
                tab.AnalysisHostPath = profile.AnalysisHostPath;
                ApplyProjectionToTabLocked(tab);
            }
        }

        internal void ApplyToTab(SessionFileTab tab)
        {
            lock (_sync)
            {
                ApplyProjectionToTabLocked(tab);
            }
        }

        private void ApplyProjectionToTabLocked(SessionFileTab tab)
        {
            if (tab.PerformanceHistory.Count == 0)
            {
                tab.PerformanceHistory = _performance.Select(ClonePerformanceSample).ToList();
            }
            if (tab.MemoryRegionAttributionHistory.Count == 0)
            {
                tab.MemoryRegionAttributionHistory =
                    _memoryAttributions.Select(CloneMemoryRegionAttributionSample).ToList();
            }
            if (tab.ThreadLifecycleHistory.Count == 0)
            {
                tab.ThreadLifecycleHistory = _threadLifecycle.Select(CloneThreadLifecycleEvent).ToList();
            }
            tab.EtwGroups = MergeGroups(tab.EtwGroups, _etwGroups.Values);
            tab.HeuristicsGroups = MergeGroups(tab.HeuristicsGroups, _heuristicGroups.Values);
            tab.FilesystemGroups = MergeGroups(tab.FilesystemGroups, _filesystemGroups.Values);
            tab.RegistryGroups = MergeGroups(tab.RegistryGroups, _registryGroups.Values);
            tab.ProcessRelationsGroups = MergeGroups(tab.ProcessRelationsGroups, _relationGroups.Values);
            tab.ApiGraphRows = MergeApiRows(tab.ApiGraphRows, _apiGraphRows.Values);
            tab.ExtendedActivityRows = MergeExtendedRows(tab.ExtendedActivityRows, _extendedRows.Values);
            tab.ThreadStackHistories = MergeThreadStacks(tab.ThreadStackHistories, _threadStacks.Values);
        }

        private void ObserveHandleIoctl(IoctlParsedEvent record, DateTime observedUtc)
        {
            uint actor = record.CallerPid;
            uint target = record.TargetPid;
            string detection =
                actor != 0 && target != 0 && actor != target ? "Cross-process handle" : "Handle activity";
            string detail =
                $"caller={actor} target={target} desiredAccess=0x{record.DesiredAccess:X8} class={record.HandleClass} flags=0x{record.HandleFlags:X8} origin=0x{record.OriginAddress:X} originPath={record.OriginPath} deepBase=0x{record.DeepAllocationBase:X} deepSize=0x{record.DeepRegionSize:X} deepProtect=0x{record.DeepRegionProtect:X8}";

            AddGroup(_relationGroups, $"handle:{actor}:{target}:{record.DesiredAccess:X8}:{record.OriginPath}",
                     "HandleOpen", "Info", detection, "Kernel-IOCTL", actor, target,
                     $"access=0x{record.DesiredAccess:X8}", detail, observedUtc, 1);
            AddExtended("Process", PidLabel(actor), PidLabel(target), "handle", "OpenProcess/Handle", observedUtc, 1,
                        detail);

            if (record.DeepAllocationBase != 0 || record.DeepRegionSize != 0)
            {
                AddMemoryAttribution(new MemoryRegionAttributionSample {
                    TimestampUtc = observedUtc, TargetPid = target, ActorPid = actor, ActorTid = 0,
                    AllocationBase = record.DeepAllocationBase, BaseAddress = record.DeepAllocationBase,
                    RegionSize = record.DeepRegionSize, ApiName = "KernelHandleOpen", EventKind = "RemoteMemoryProbe",
                    RegionKind = record.DeepRegionType == 0x1000000 ? "Image" : "Unknown",
                    RegionIdentity = $"memory:{target}:{record.DeepAllocationBase:X}", OriginPath = record.OriginPath,
                    SourceFamily = "Kernel-IOCTL", CurrentProtection = record.DeepRegionProtect,
                    ObservedByKernel = true, CrossProcess = actor != 0 && target != 0 && actor != target,
                    LifecycleSummary =
                        $"handle memory probe target={target} base=0x{record.DeepAllocationBase:X} size=0x{record.DeepRegionSize:X} protect={EventDetailFormatting.DescribeMemoryProtection(record.DeepRegionProtect)}"
                });
            }
        }

        private void TrackIoctlProcessRelationships(IoctlParsedEvent record, DateTime observedUtc)
        {
            if (record.Type != BlackbirdNative.EventTypeThread)
            {
                return;
            }

            if (IsTrackedPid(record.CreatorPid))
            {
                TrackPid(record.ProcessPid, observedUtc,
                         $"thread-create creator={record.CreatorPid} tid={record.ThreadId}");
            }
        }

        private void TrackEtwProcessRelationships(BrokerEtwEventView view, uint actorPid, uint targetPid,
                                                  DateTime observedUtc)
        {
            if (view.Family == BlackbirdNative.IpcEtwFamilyProcess &&
                (view.Flags & BlackbirdNative.IpcEtwFlagProcessIsCreate) != 0)
            {
                uint childPid = FirstNonZero(view.ProcessPid, targetPid, view.ExplicitTargetPid, view.EventProcessId);
                uint creatorPid = FirstNonZero(view.CreatorPid, view.ParentPid, actorPid, view.CallerPid);
                if (IsTrackedPid(creatorPid) || IsTrackedPid(view.ParentPid))
                {
                    TrackPid(childPid, observedUtc, $"process-create creator={creatorPid} parent={view.ParentPid}");
                }
                return;
            }

            if (view.Family == BlackbirdNative.IpcEtwFamilyThread)
            {
                uint processPid = FirstNonZero(view.ProcessPid, targetPid, view.ExplicitTargetPid, view.EventProcessId);
                uint creatorPid = FirstNonZero(view.CreatorPid, actorPid, view.CallerPid);
                if (IsTrackedPid(creatorPid))
                {
                    TrackPid(processPid, observedUtc, $"thread-create creator={creatorPid} tid={view.ThreadId}");
                }
            }
        }

        private bool IsTrackedPid(uint pid) => pid > 0 && pid <= int.MaxValue
                                               && _trackedPids.Contains(unchecked((int)pid));

        private bool TrackPid(uint pid, DateTime observedUtc, string reason)
        {
            if (pid == 0 || pid > int.MaxValue)
            {
                return false;
            }

            int processId = unchecked((int)pid);
            if (_trackedPids.Count >= 1024 || !_trackedPids.Add(processId))
            {
                return false;
            }

            AddExtended("Process", PidLabel((uint)_targetPid), PidLabel(pid), "tracked-descendant", "tracked",
                        observedUtc, 1, reason);
            return true;
        }

        private string CaptureActorLabel =>
            string.IsNullOrWhiteSpace(_captureId) ? _sourceLabel : $"{_sourceLabel} {_captureId}";

        private void ObserveThreadIoctl(IoctlParsedEvent record, DateTime observedUtc)
        {
            var sample = new ThreadLifecycleEventSample {
                TimestampUtc = observedUtc,
                ProcessPid = record.ProcessPid,
                ThreadId = record.ThreadId,
                CreatorPid = record.CreatorPid,
                Flags = record.ThreadFlags,
                StartAddress = record.StartAddress,
                ImageBase = record.ImageBase,
                ImageSize = record.ImageSize,
                EventKind = "Thread",
                Notes =
                    $"creator={record.CreatorPid} start=0x{record.StartAddress:X} image=0x{record.ImageBase:X}/0x{record.ImageSize:X} flags=0x{record.ThreadFlags:X8}"
            };
            _threadLifecycle.Add(sample);
            TrimHead(_threadLifecycle, MaxThreadLifecycleEvents);

            AddGroup(_relationGroups,
                     $"thread:{record.CreatorPid}:{record.ProcessPid}:{record.ThreadId}:{record.StartAddress:X}",
                     "ThreadCreate", "Info", "Thread lifecycle", "Kernel-IOCTL", record.CreatorPid, record.ProcessPid,
                     $"tid={record.ThreadId} start=0x{record.StartAddress:X}", sample.Notes, observedUtc, 1);
            AddExtended("Thread", PidLabel(record.CreatorPid), PidLabel(record.ProcessPid), $"TID {record.ThreadId}",
                        "thread-observed", observedUtc, 1, sample.Notes);
            PersistStackSnapshot(record.ThreadId, "Kernel thread notify", observedUtc,
                                 record.ThreadFrames.Length > 0 ? record.ThreadFrames : record.FullFrames);
        }

        private void ObserveFilesystemIoctl(IoctlParsedEvent record, DateTime observedUtc)
        {
            string operation = DescribeFileOperation(record.FileOperation);
            string path = FirstNonEmpty(record.FilePath, $"fileObject=0x{record.FileObject:X}");
            string detail =
                $"operation={operation} pid={record.FileProcessPid} tid={record.FileThreadId} path={path} length={record.FileLength} offset={record.FileByteOffset} status=0x{record.FileStatus:X} desiredAccess=0x{record.FileDesiredAccess:X8} share=0x{record.FileShareAccess:X8} flags=0x{record.FileFlags:X8}";
            AddGroup(_filesystemGroups, $"file:{record.FileProcessPid}:{operation}:{path}", operation, "Info",
                     "Filesystem activity", "Kernel-IOCTL", record.FileProcessPid, 0, path, detail, observedUtc, 1);
            AddExtended("Filesystem", PidLabel(record.FileProcessPid), path, path, operation, observedUtc, 1, detail);
        }

        private void ObserveRegistryIoctl(IoctlParsedEvent record, DateTime observedUtc)
        {
            string operation = DescribeRegistryOperation(record.RegistryOperation);
            string path = BuildRegistryPath(record.RegistryKeyPath, record.RegistryValueName);
            string severity = (record.RegistryFlags & (BlackbirdNative.RegistryFlagHighValuePath |
                                                       BlackbirdNative.RegistryFlagSensitiveQuery)) != 0
                                  ? "High"
                                  : "Info";
            string detail =
                $"operation={operation} pid={record.RegistryProcessPid} tid={record.RegistryThreadId} key={record.RegistryKeyPath} value={record.RegistryValueName} dataType={record.RegistryDataType} dataSize={record.RegistryDataSize} notifyClass={record.RegistryNotifyClass} flags=0x{record.RegistryFlags:X8}";
            AddGroup(_registryGroups, $"registry:{record.RegistryProcessPid}:{operation}:{path}", operation, severity,
                     "Registry activity", "Kernel-IOCTL", record.RegistryProcessPid, 0, path, detail, observedUtc, 1);
            AddExtended("Registry", PidLabel(record.RegistryProcessPid), path, path, operation, observedUtc, 1, detail);

            if (!severity.Equals("Info", StringComparison.OrdinalIgnoreCase))
            {
                AddGroup(_heuristicGroups, $"registry-probe:{record.RegistryProcessPid}:{path}", "RegistryTelemetry",
                         severity, "Sensitive registry probe", "Kernel-IOCTL", record.RegistryProcessPid, 0, path,
                         detail, observedUtc, 1);
            }
        }

        private void ObserveEnterpriseIoctl(IoctlParsedEvent record, DateTime observedUtc)
        {
            string operation = $"Enterprise-{record.EnterpriseOperation}";
            string severity = (record.EnterpriseFlags & BlackbirdNative.EnterpriseFlagCritical) != 0 ? "Critical"
                              : (record.EnterpriseFlags & BlackbirdNative.EnterpriseFlagHighSignal) != 0 ? "High"
                                                                                                        : "Info";
            string detail =
                $"operation={record.EnterpriseOperation} actor={record.EnterpriseProcessPid} tid={record.EnterpriseThreadId} target={record.EnterpriseTargetProcessPid} targetTid={record.EnterpriseTargetThreadId} desiredAccess=0x{record.EnterpriseDesiredAccess:X8} flags=0x{record.EnterpriseFlags:X8} status=0x{record.EnterpriseStatus:X8}";
            AddGroup(_heuristicGroups,
                     $"enterprise:{record.EnterpriseProcessPid}:{record.EnterpriseTargetProcessPid}:{record.EnterpriseOperation}",
                     operation, severity, "Enterprise activity", "Kernel-IOCTL", record.EnterpriseProcessPid,
                     record.EnterpriseTargetProcessPid, operation, detail, observedUtc, 1);
            AddExtended("Enterprise", PidLabel(record.EnterpriseProcessPid), PidLabel(record.EnterpriseTargetProcessPid),
                        operation, severity, observedUtc, 1, detail);
        }

        private void ObserveEtwRegistry(BrokerEtwEventView view, DateTime observedUtc)
        {
            uint actor = ResolveActorPid(view);
            string path = BuildRegistryPath(view.KeyPath, view.ValueName);
            string operation = FirstNonEmpty(view.Operation, view.EventName, "Registry");
            AddGroup(_registryGroups, $"etw-registry:{actor}:{operation}:{path}", operation,
                     SeverityLabel(view.Severity), FirstNonEmpty(view.DetectionName, "Registry ETW"),
                     FirstNonEmpty(view.Source, "ETW"), actor, ResolveTargetPid(view), path, view.Details, observedUtc,
                     Math.Max(1, view.RepeatCount));
        }

        private void ProcessEtwRelation(BrokerEtwEventView view, DateTime observedUtc)
        {
            uint actor = ResolveActorPid(view);
            uint target = ResolveTargetPid(view);
            if (actor == 0 && target == 0)
            {
                return;
            }

            string relation =
                view.Family switch { BlackbirdNative.IpcEtwFamilyProcess =>
                                         (view.Flags & BlackbirdNative.IpcEtwFlagProcessIsCreate) != 0 ? "ProcessCreate"
                                                                                                       : "Process",
                                     BlackbirdNative.IpcEtwFamilyThread => "ThreadCreate",
                                     BlackbirdNative.IpcEtwFamilyHandle => "HandleOpen",
                                     BlackbirdNative.IpcEtwFamilyApc => "ApcQueue",
                                     BlackbirdNative.IpcEtwFamilyUserHook => "ApiCall",
                                     _ => string.Empty };
            if (relation.Length == 0)
            {
                return;
            }

            string detail = view.Details;
            AddGroup(_relationGroups,
                     $"etw-relation:{relation}:{actor}:{target}:{view.EventName}:{view.ImagePath}:{view.CommandLine}",
                     relation, SeverityLabel(view.Severity), FirstNonEmpty(view.DetectionName, relation),
                     FirstNonEmpty(view.Source, "ETW"), actor, target,
                     FirstNonEmpty(view.ImagePath, view.CommandLine, view.ArgumentSummary), detail, observedUtc,
                     Math.Max(1, view.RepeatCount));
        }

        private void ProcessApiGraph(BrokerEtwEventView view, DateTime observedUtc)
        {
            if (!EventDetailFormatting.IsApiGraphCandidate(view))
            {
                return;
            }

            uint sourcePid = ResolveActorPid(view);
            uint targetPid = ResolveTargetPid(view);
            uint threadId = view.ThreadId != 0 ? view.ThreadId : view.EventThreadId;
            string apiName = FirstNonEmpty(view.EventName, view.Operation, view.DetectionName, "API");
            IncrementCount(_apiCandidateCounts, apiName, Math.Max(1, view.RepeatCount));
            string sensor = EventDetailFormatting.ClassifyHookSensorOrigin(view);
            string callerOrigin = FirstNonEmpty(view.CallerOriginLabel, "unknown");
            string originModule = Path.GetFileName(FirstNonEmpty(view.OriginPath, view.ImagePath));
            string key = $"api:{sourcePid}:{targetPid}:{threadId}:{apiName}:{sensor}:{callerOrigin}:{originModule}";
            if (!_apiGraphRows.TryGetValue(key, out ApiCallGraphRowSnapshot? row))
            {
                row = new ApiCallGraphRowSnapshot { ApiName = apiName,           SensorOrigin = sensor,
                                                    CallerOrigin = callerOrigin, OriginModule = originModule,
                                                    SourcePid = sourcePid,       TargetPid = targetPid,
                                                    ThreadId = threadId,         FirstSeenUtc = observedUtc };
                _apiGraphRows[key] = row;
            }

            row.Hits += Math.Max(1, view.RepeatCount);
            row.LastSeenUtc = observedUtc;
            row.ActionLabel = FirstNonEmpty(view.ArgumentSummary, view.Operation, view.Reason, view.Summary);
            row.DetailFull = view.Details;
            row.ContextLabel = FirstNonEmpty(view.Reason, view.ArgumentSummary);
            row.FlagsLabel = view.Flags == 0 ? string.Empty : $"0x{view.Flags:X8}";
            row.CallChainLabel = BuildStackSummary(view.Stack, view.StackCount);

            if (_apiGraphRows.Count > MaxApiGraphRows)
            {
                foreach (string evict in _apiGraphRows.OrderBy(x => x.Value.LastSeenUtc)
                             .Take(_apiGraphRows.Count - MaxApiGraphRows)
                             .Select(x => x.Key)
                             .ToArray())
                {
                    _apiGraphRows.Remove(evict);
                }
            }

            PersistStackSnapshot(threadId, "API hook", observedUtc, view.Stack);
        }

        private void PersistObservedHookStackSnapshot(BrokerEtwEventView view, DateTime observedUtc)
        {
            if (view.Family != BlackbirdNative.IpcEtwFamilyUserHook ||
                view.SourceId != BlackbirdNative.IpcEtwSourceUserHook || view.StackCount == 0 || view.Stack.Length == 0)
            {
                return;
            }

            uint pid = FirstNonZero(view.ProcessPid, view.ActorPid, view.EventProcessId);
            uint tid = FirstNonZero(view.EventThreadId, view.ThreadId);
            if (pid == 0 || tid == 0 || pid > int.MaxValue || tid > int.MaxValue)
            {
                return;
            }

            string throttleKey = $"{pid}:{tid}";
            if (_observedHookStackLastPersistByThread.TryGetValue(throttleKey, out DateTime lastPersistUtc) &&
                observedUtc < lastPersistUtc.AddMilliseconds(250))
            {
                return;
            }

            _observedHookStackLastPersistByThread[throttleKey] = observedUtc;
            PersistStackSnapshot(tid, "Observed hook stack", observedUtc, view.Stack);
            _observedHookStacks += 1;
        }

        private void QueueThreadStackFallbackCapture(BrokerEtwEventView view, DateTime observedUtc)
        {
            if (view.StackCount != 0 || !ShouldCaptureThreadStackFallback(view))
            {
                return;
            }

            uint pid = FirstNonZero(view.ProcessPid, view.ActorPid, view.EventProcessId);
            uint tid = FirstNonZero(view.EventThreadId, view.ThreadId);
            if (pid == 0 || tid == 0 || pid > int.MaxValue || tid > int.MaxValue)
            {
                return;
            }

            string key = $"{pid}:{tid}";
            if (_threadStackFallbackLastCaptureByThread.TryGetValue(key, out DateTime lastCaptureUtc) &&
                observedUtc < lastCaptureUtc.AddSeconds(6))
            {
                return;
            }

            if (_pendingThreadStackFallbackKeys.Count >= 32 || !_pendingThreadStackFallbackKeys.Add(key))
            {
                return;
            }

            _threadStackFallbackLastCaptureByThread[key] = observedUtc;
            int capturePid = unchecked((int)pid);
            int captureTid = unchecked((int)tid);
            Task task = Task.Run(() =>
                                 {
                                     ThreadStackResolveResult result =
                                         ThreadStackResolver.Resolve(capturePid, captureTid, "Hook fallback");
                                     return CreateThreadStackFallbackSnapshot(observedUtc, result);
                                 })
                            .ContinueWith(
                                task =>
                                {
                                    lock (_sync)
                                    {
                                        _pendingThreadStackFallbackKeys.Remove(key);
                                        if (task.Status == TaskStatus.RanToCompletion && task.Result != null &&
                                            task.Result.Frames.Count > 0)
                                        {
                                            PersistStackSnapshot(unchecked((uint)captureTid), "Fallback hook stack",
                                                                 task.Result);
                                            _fallbackStackCaptures += 1;
                                        }
                                        else
                                        {
                                            _fallbackStackMisses += 1;
                                        }
                                    }
                                },
                                TaskScheduler.Default);
            _pendingThreadStackCaptures.Add(task);
        }

        private static bool ShouldCaptureThreadStackFallback(BrokerEtwEventView view)
        {
            if (view.Family != BlackbirdNative.IpcEtwFamilyUserHook)
            {
                return false;
            }

            string api = FirstNonEmpty(view.Operation, view.EventName);
            if (api.Length == 0)
            {
                return false;
            }

            if (!api.StartsWith("Nt", StringComparison.OrdinalIgnoreCase) &&
                !api.StartsWith("Zw", StringComparison.OrdinalIgnoreCase) &&
                !api.StartsWith("Co", StringComparison.OrdinalIgnoreCase) &&
                !api.Contains("Trace", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            bool highSignal = view.Severity >= 4 ||
                              api.Equals("NtMapViewOfSection", StringComparison.OrdinalIgnoreCase) ||
                              api.Equals("ZwMapViewOfSection", StringComparison.OrdinalIgnoreCase) ||
                              api.Equals("NtCreateSection", StringComparison.OrdinalIgnoreCase) ||
                              api.Equals("ZwCreateSection", StringComparison.OrdinalIgnoreCase) ||
                              api.Equals("NtWriteVirtualMemory", StringComparison.OrdinalIgnoreCase) ||
                              api.Equals("NtProtectVirtualMemory", StringComparison.OrdinalIgnoreCase) ||
                              api.Equals("NtCreateThreadEx", StringComparison.OrdinalIgnoreCase);
            if (!highSignal)
            {
                return false;
            }

            return view.SourceId == BlackbirdNative.IpcEtwSourceBlackbird ||
                   view.SourceId == BlackbirdNative.IpcEtwSourceUserHook ||
                   EventDetailFormatting.IsKernelHookTelemetry(view);
        }

        private static ThreadStackSessionSnapshot? CreateThreadStackFallbackSnapshot(DateTime capturedUtc,
                                                                                     ThreadStackResolveResult result)
        {
            if (result.Frames.Count == 0)
            {
                return null;
            }

            return new ThreadStackSessionSnapshot { CapturedAtUtc = capturedUtc,
                                                    TebAddress = result.TebAddress,
                                                    StackBase = result.StackBase,
                                                    StackTop = result.StackTop,
                                                    TebFlags = result.TebFlags,
                                                    StackPointer = result.StackPointer,
                                                    ContextSnapshot =
                                                        CloneThreadContextSnapshot(result.ContextSnapshot),
                                                    Frames = result.Frames.Select(CloneStackFrameRow).ToList() };
        }

        private void ProcessMemoryAttribution(BrokerEtwEventView view, DateTime observedUtc)
        {
            uint targetPid = ResolveMemoryTargetPid(view);
            if (targetPid == 0)
            {
                return;
            }

            string apiName = FirstNonEmpty(view.EventName, view.Operation, view.DetectionName);
            string eventKind = string.Empty;
            string regionKind = string.Empty;
            ulong baseAddress = 0;
            ulong regionSize = 0;
            uint currentProtect = 0;
            uint previousProtect = 0;
            uint sampleBytes = 0;
            bool threadStartObserved = false;
            ulong threadStartAddress = 0;

            if (view.Family == BlackbirdNative.IpcEtwFamilyImage && view.ImageBase != 0)
            {
                eventKind = "ImageMap";
                regionKind = "Image";
                baseAddress = view.ImageBase;
                regionSize = view.ImageSize;
                currentProtect = view.StartRegionProtect;
            }
            else if (view.Family == BlackbirdNative.IpcEtwFamilyThread && view.StartAddress != 0)
            {
                eventKind = "ThreadStart";
                regionKind = view.ImageBase != 0 ? "Image" : "Unknown";
                baseAddress = view.ImageBase != 0 ? view.ImageBase : NormalizeRegionAddress(view.StartAddress);
                regionSize = view.ImageSize != 0 ? view.ImageSize : 1;
                currentProtect = view.StartRegionProtect;
                threadStartObserved = true;
                threadStartAddress = view.StartAddress;
            }
            else if (view.Family == BlackbirdNative.IpcEtwFamilyUserHook && !string.IsNullOrWhiteSpace(apiName))
            {
                Dictionary<string, string> fields = view.GetOrCreateHookFieldMap();
                if (apiName.Equals("NtAllocateVirtualMemory", StringComparison.OrdinalIgnoreCase) ||
                    apiName.Equals("NtAllocateVirtualMemoryEx", StringComparison.OrdinalIgnoreCase))
                {
                    eventKind = "PrivateAllocate";
                    regionKind = "Private";
                    baseAddress = FirstU64(fields, "base", "baseAddress", "c1", "a1");
                    regionSize = FirstU64(fields, "size", "regionSize", "c3", "a3");
                    currentProtect = (uint)FirstU64(fields, "protect", "c3", "a5", "c5");
                }
                else if (apiName.Equals("NtProtectVirtualMemory", StringComparison.OrdinalIgnoreCase))
                {
                    eventKind = "ProtectChange";
                    baseAddress = FirstU64(fields, "base", "baseAddress", "c1", "a1");
                    regionSize = FirstU64(fields, "size", "regionSize", "c2", "a2");
                    currentProtect = (uint)FirstU64(fields, "newProtect", "protect", "c2", "a3", "c3");
                    previousProtect = (uint)FirstU64(fields, "oldProtect", "a4", "c4");
                }
                else if (apiName.Equals("NtWriteVirtualMemory", StringComparison.OrdinalIgnoreCase))
                {
                    eventKind = "MemoryWrite";
                    baseAddress = FirstU64(fields, "base", "baseAddress", "c1", "a1");
                    regionSize = Math.Max(1UL, FirstU64(fields, "size", "regionSize", "c3", "a3"));
                    sampleBytes = (uint)Math.Min(uint.MaxValue, view.DeepSampleSize);
                }
                else if (apiName.Equals("NtMapViewOfSection", StringComparison.OrdinalIgnoreCase) ||
                         apiName.Equals("NtMapViewOfSectionEx", StringComparison.OrdinalIgnoreCase))
                {
                    eventKind = "SectionMap";
                    regionKind = (view.Flags & BlackbirdNative.IpcEtwFlagHookSectionImage) != 0 ? "Image" : "Mapped";
                    baseAddress = FirstU64(fields, "baseAddress", "base", "c2", "a2");
                    regionSize = FirstU64(fields, "viewSize", "size", "c3", "a4", "a6");
                    currentProtect = (uint)FirstU64(fields, "win32Protect", "protect", "a6", "c6", "c5");
                }
                else
                {
                    return;
                }
            }
            else
            {
                return;
            }

            if (baseAddress == 0)
            {
                baseAddress = NormalizeRegionAddress(threadStartAddress);
            }
            if (baseAddress == 0)
            {
                return;
            }

            string regionIdentity = $"memory:{targetPid}:{baseAddress:X}";
            string lifecycle =
                $"{eventKind} pid={targetPid} base=0x{baseAddress:X} size=0x{regionSize:X} protect={EventDetailFormatting.DescribeMemoryProtection(currentProtect)} api={apiName}";
            AddMemoryAttribution(new MemoryRegionAttributionSample {
                TimestampUtc = observedUtc,
                ProcessStartKey = view.ProcessStartKey,
                TargetPid = targetPid,
                ActorPid = ResolveActorPid(view),
                ActorTid = view.ThreadId != 0 ? view.ThreadId : view.EventThreadId,
                AllocationBase = baseAddress,
                BaseAddress = baseAddress,
                RegionSize = regionSize == 0 ? 1 : regionSize,
                ApiName = apiName,
                EventKind = eventKind,
                RegionKind = string.IsNullOrWhiteSpace(regionKind) ? "Unknown" : regionKind,
                RegionIdentity = regionIdentity,
                OriginPath = FirstNonEmpty(view.OriginPath, view.ImagePath),
                SourceFamily = DescribeEtwFamily(view.Family),
                CallerOrigin = view.CallerOriginLabel,
                FirstUserFrame = view.OriginAddress,
                FrameSummary = BuildStackSummary(view.Stack, view.StackCount),
                UnwindClean = (view.Flags & BlackbirdNative.IpcEtwFlagUnwindMetadataValid) != 0,
                FrameChainHadGaps = (view.Flags & BlackbirdNative.IpcEtwFlagFramesOutsideTebStack) != 0,
                ObservedByKernel = view.SourceId == BlackbirdNative.IpcEtwSourceBlackbird,
                ObservedByUserHook = view.SourceId == BlackbirdNative.IpcEtwSourceUserHook,
                CrossProcess = ResolveActorPid(view) != 0 && ResolveActorPid(view) != targetPid,
                ImageBacked = string.Equals(regionKind, "Image", StringComparison.OrdinalIgnoreCase),
                InitialProtection = currentProtect,
                CurrentProtection = currentProtect,
                PreviousProtection = previousProtect,
                SampleBytes = sampleBytes,
                LifecycleSummary = lifecycle,
                ThreadStartObserved = threadStartObserved,
                ThreadId = threadStartObserved ? (view.ThreadId != 0 ? view.ThreadId : view.EventThreadId) : 0,
                ThreadStartAddress = threadStartAddress,
                SignatureLevel = view.SignatureLevel,
                SignatureType = view.SignatureType
            });

            AddExtended("Memory", PidLabel(ResolveActorPid(view)), PidLabel(targetPid), $"0x{baseAddress:X}", eventKind,
                        observedUtc, 1, lifecycle);
        }

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
                row = new GroupedEventRow { GroupKey = key, Event = eventName, Severity = severity,
                                            Detection = detection, ArgumentPreview = Truncate(argument, 256) };
                groups[key] = row;
            }

            row.LastSeenUtc = observedUtc;
            row.Hits += Math.Max(1, hitCount);
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

        private static uint ResolveActorPid(BrokerEtwEventView view) => FirstNonZero(view.ActorPid, view.CallerPid,
                                                                                     view.EventProcessId,
                                                                                     view.ProcessPid);

        private static uint ResolveTargetPid(BrokerEtwEventView view) => FirstNonZero(view.TargetPid,
                                                                                      view.ExplicitTargetPid,
                                                                                      view.ProcessPid,
                                                                                      view.EventProcessId);

        private static uint ResolveMemoryTargetPid(BrokerEtwEventView view) =>
            FirstNonZero(view.TargetPid, view.ExplicitTargetPid, view.ProcessPid, view.EventProcessId, view.ActorPid);

        private static uint FirstNonZero(params uint[] values)
        {
            foreach (uint value in values)
            {
                if (value != 0)
                {
                    return value;
                }
            }

            return 0;
        }

        private static string PidLabel(uint pid) => pid == 0 ? "-" : $"{ProcessIdentityResolver.Describe(pid)} ({pid})";

        private static string
        DescribeEtwFamily(uint family) => family switch { BlackbirdNative.IpcEtwFamilyHandle => "Handle",
                                                          BlackbirdNative.IpcEtwFamilyThread => "Thread",
                                                          BlackbirdNative.IpcEtwFamilyProcess => "Process",
                                                          BlackbirdNative.IpcEtwFamilyImage => "Image",
                                                          BlackbirdNative.IpcEtwFamilyRegistry => "Registry",
                                                          BlackbirdNative.IpcEtwFamilyApc => "APC",
                                                          BlackbirdNative.IpcEtwFamilyDetection => "Detection",
                                                          BlackbirdNative.IpcEtwFamilyThreatIntel => "ThreatIntel",
                                                          BlackbirdNative.IpcEtwFamilySocket => "Socket",
                                                          BlackbirdNative.IpcEtwFamilyUserHook => "API",
                                                          _ => "ETW" };

        private static string DescribeFileOperation(uint operation) => operation switch {
            BlackbirdNative.FileOperationCreate => "Create",
            BlackbirdNative.FileOperationRead => "Read",
            BlackbirdNative.FileOperationWrite => "Write",
            BlackbirdNative.FileOperationClose => "Close",
            BlackbirdNative.FileOperationCleanup => "Cleanup",
            BlackbirdNative.FileOperationSetInformation => "SetInformation",
            BlackbirdNative.FileOperationQueryInformation => "QueryInformation",
            BlackbirdNative.FileOperationDirectoryControl => "DirectoryControl",
            BlackbirdNative.FileOperationFsControl => "FsControl",
            _ => "Unknown"
        };

        private static string DescribeRegistryOperation(uint operation) => operation switch {
            BlackbirdNative.RegistryOperationQueryValue => "QueryValue",
            BlackbirdNative.RegistryOperationQueryKey => "QueryKey",
            BlackbirdNative.RegistryOperationEnumerateKey => "EnumerateKey",
            BlackbirdNative.RegistryOperationEnumerateValue => "EnumerateValue",
            BlackbirdNative.RegistryOperationSetValue => "SetValue",
            BlackbirdNative.RegistryOperationCreateKey => "CreateKey",
            BlackbirdNative.RegistryOperationOpenKey => "OpenKey",
            BlackbirdNative.RegistryOperationDeleteValue => "DeleteValue",
            BlackbirdNative.RegistryOperationDeleteKey => "DeleteKey",
            _ => "Unknown"
        };

        private static string BuildRegistryPath(string keyPath,
                                                string valueName) => string.IsNullOrWhiteSpace(valueName)
                                                                         ? FirstNonEmpty(keyPath, "(registry)")
                                                                         : $"{keyPath}\\{valueName}";

        private static string SeverityLabel(uint severity)
        {
            if (severity >= 5)
            {
                return "Critical";
            }
            if (severity >= 4)
            {
                return "High";
            }
            if (severity >= 2)
            {
                return "Medium";
            }

            return "Info";
        }

        private static int SeverityRank(string severity) =>
            (severity ?? string.Empty).Trim().ToLowerInvariant() switch { "critical" => 5, "high" => 4, "medium" => 3,
                                                                          "low" => 2,      "info" => 1,
                                                                          _ => 0 };

        private static string BuildStackSummary(ulong[]? stack, uint stackCount)
        {
            int count = Math.Min(stack?.Length ?? 0, (int)Math.Min(stackCount, 8));
            if (count <= 0)
            {
                return string.Empty;
            }

            return string.Join(" <- ", stack!.Take(count).Select(x => $"0x{x:X}"));
        }

        private static ulong NormalizeRegionAddress(ulong address) => address & ~0xFFFUL;

        private static ulong FirstU64(IReadOnlyDictionary<string, string> fields, params string[] keys)
        {
            foreach (string key in keys)
            {
                if (!fields.TryGetValue(key, out string? value) || string.IsNullOrWhiteSpace(value))
                {
                    continue;
                }

                string trimmed = value.Trim();
                if (trimmed.StartsWith("0x", StringComparison.OrdinalIgnoreCase) &&
                    ulong.TryParse(trimmed.AsSpan(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture,
                                   out ulong parsedHex))
                {
                    return parsedHex;
                }

                if (ulong.TryParse(trimmed, NumberStyles.Integer, CultureInfo.InvariantCulture, out ulong parsed))
                {
                    return parsed;
                }
            }

            return 0;
        }

        private static string FirstNonEmpty(params string?[] values)
        {
            foreach (string? value in values)
            {
                if (!string.IsNullOrWhiteSpace(value))
                {
                    return value.Trim();
                }
            }

            return string.Empty;
        }

        private static string Truncate(string? value, int maxChars)
        {
            if (string.IsNullOrEmpty(value) || value.Length <= maxChars)
            {
                return value ?? string.Empty;
            }

            return value[..maxChars];
        }

        private static void TrimHead<T>(List<T> rows, int maxRows)
        {
            if (rows.Count > maxRows)
            {
                rows.RemoveRange(0, rows.Count - maxRows);
            }
        }

        private static FileInfo? TryGetFileInfo(string path)
        {
            try
            {
                return File.Exists(path) ? new FileInfo(path) : null;
            }
            catch
            {
                return null;
            }
        }

        private static string SafeModulePath(ProcessModule module)
        {
            try
            {
                return module.FileName ?? module.ModuleName ?? string.Empty;
            }
            catch
            {
                return module.ModuleName ?? string.Empty;
            }
        }

        private static string SafeWaitReason(ProcessThread thread)
        {
            try
            {
                return thread.ThreadState == System.Diagnostics.ThreadState.Wait ? thread.WaitReason.ToString()
                                                                                 : string.Empty;
            }
            catch
            {
                return string.Empty;
            }
        }

        private static DateTime? SafeThreadStart(ProcessThread thread)
        {
            try
            {
                return thread.StartTime.ToUniversalTime();
            }
            catch
            {
                return null;
            }
        }

        private static string FormatNullableUtc(DateTime? value) =>
            value.HasValue ? value.Value.ToString("O", CultureInfo.InvariantCulture) : string.Empty;

        private static PerformanceSample ClonePerformanceSample(PerformanceSample src) => new() {
            TimestampUtc = src.TimestampUtc,
            CoreCount = src.CoreCount,
            CpuPercent = src.CpuPercent,
            CoresUsedPercent = src.CoresUsedPercent,
            DiskReadBytesPerSec = src.DiskReadBytesPerSec,
            DiskWriteBytesPerSec = src.DiskWriteBytesPerSec,
            PrivateBytes = src.PrivateBytes,
            ReservedBytes = src.ReservedBytes,
            CommitBytes = src.CommitBytes,
            ImageBytes = src.ImageBytes,
            MappedBytes = src.MappedBytes,
            PrivateVadBytes = src.PrivateVadBytes,
            NetInBytesPerSec = src.NetInBytesPerSec,
            NetOutBytesPerSec = src.NetOutBytesPerSec,
            NetPacketsPerSec = src.NetPacketsPerSec,
            TopThreads = src.TopThreads
                             .Select(t => new ThreadUsageSample { Tid = t.Tid, CpuMsDelta = t.CpuMsDelta,
                                                                  State = t.State, WaitReason = t.WaitReason,
                                                                  Kind = t.Kind, StartTimeUtc = t.StartTimeUtc,
                                                                  TargetSuspended = t.TargetSuspended })
                             .ToList(),
            CoreUsage = src.CoreUsage
                            .Select(c => new CoreUsageSample { CoreIndex = c.CoreIndex, BusyPercent = c.BusyPercent,
                                                               DominantTid = c.DominantTid,
                                                               DominantThreadKind = c.DominantThreadKind,
                                                               DominantThreadCpuMs = c.DominantThreadCpuMs,
                                                               ThreadCount = c.ThreadCount })
                            .ToList(),
            MemoryMetrics = src.MemoryMetrics
                                .Select(m => new MemoryMetricSample { Metric = m.Metric, Value = m.Value,
                                                                      BytesValue = m.BytesValue })
                                .ToList(),
            MemoryPages = src.MemoryPages
                              .Select(m => new MemoryPageSample { BaseAddress = m.BaseAddress,
                                                                  AllocationBase = m.AllocationBase,
                                                                  RegionSize = m.RegionSize,
                                                                  State = m.State,
                                                                  Protect = m.Protect,
                                                                  AllocationProtect = m.AllocationProtect,
                                                                  Type = m.Type,
                                                                  StateLabel = m.StateLabel,
                                                                  ProtectLabel = m.ProtectLabel,
                                                                  TypeLabel = m.TypeLabel,
                                                                  Category = m.Category,
                                                                  SpecialUse = m.SpecialUse,
                                                                  BackingPath = m.BackingPath,
                                                                  ModulePath = m.ModulePath,
                                                                  Sr71Owned = m.Sr71Owned,
                                                                  Sr71OwnerTag = m.Sr71OwnerTag,
                                                                  WorkingSetValid = m.WorkingSetValid,
                                                                  WorkingSetShared = m.WorkingSetShared,
                                                                  WorkingSetShareCount = m.WorkingSetShareCount,
                                                                  WorkingSetLocked = m.WorkingSetLocked,
                                                                  WorkingSetLargePage = m.WorkingSetLargePage,
                                                                  SnapshotOffset = m.SnapshotOffset,
                                                                  SnapshotBytes = m.SnapshotBytes?.ToArray() })
                              .ToList()
        };

        private static ThreadLifecycleEventSample
        CloneThreadLifecycleEvent(ThreadLifecycleEventSample src) => new() { TimestampUtc = src.TimestampUtc,
                                                                             ProcessPid = src.ProcessPid,
                                                                             ThreadId = src.ThreadId,
                                                                             CreatorPid = src.CreatorPid,
                                                                             Flags = src.Flags,
                                                                             StartAddress = src.StartAddress,
                                                                             ImageBase = src.ImageBase,
                                                                             ImageSize = src.ImageSize,
                                                                             EventKind = src.EventKind,
                                                                             Notes = src.Notes };

        private static MemoryRegionAttributionSample CloneMemoryRegionAttributionSample(
            MemoryRegionAttributionSample src) => new() { TimestampUtc = src.TimestampUtc,
                                                          ProcessStartKey = src.ProcessStartKey,
                                                          TargetPid = src.TargetPid,
                                                          ActorPid = src.ActorPid,
                                                          ActorTid = src.ActorTid,
                                                          AllocationBase = src.AllocationBase,
                                                          BaseAddress = src.BaseAddress,
                                                          RegionSize = src.RegionSize,
                                                          ApiName = src.ApiName,
                                                          EventKind = src.EventKind,
                                                          RegionKind = src.RegionKind,
                                                          RegionIdentity = src.RegionIdentity,
                                                          OriginPath = src.OriginPath,
                                                          SourceFamily = src.SourceFamily,
                                                          ExecutionContext = src.ExecutionContext,
                                                          CallerOrigin = src.CallerOrigin,
                                                          FirstUserFrame = src.FirstUserFrame,
                                                          FirstUserFrameModule = src.FirstUserFrameModule,
                                                          FrameSummary = src.FrameSummary,
                                                          UnwindClean = src.UnwindClean,
                                                          FrameChainHadGaps = src.FrameChainHadGaps,
                                                          ObservedByKernel = src.ObservedByKernel,
                                                          ObservedByUserHook = src.ObservedByUserHook,
                                                          BlackbirdOwned = src.BlackbirdOwned,
                                                          CrossProcess = src.CrossProcess,
                                                          ImageBacked = src.ImageBacked,
                                                          InitialProtection = src.InitialProtection,
                                                          CurrentProtection = src.CurrentProtection,
                                                          PreviousProtection = src.PreviousProtection,
                                                          FirstExecutableTransition = src.FirstExecutableTransition,
                                                          MapCount = src.MapCount,
                                                          WriteCount = src.WriteCount,
                                                          ProtectCount = src.ProtectCount,
                                                          ThreadStartCount = src.ThreadStartCount,
                                                          ProtectFlipCount = src.ProtectFlipCount,
                                                          RapidProtectFlipCount = src.RapidProtectFlipCount,
                                                          ExecutableFlipCount = src.ExecutableFlipCount,
                                                          GuardNoAccessFlipCount = src.GuardNoAccessFlipCount,
                                                          WritableExecutableFlipCount = src.WritableExecutableFlipCount,
                                                          ProtectionTransition = src.ProtectionTransition,
                                                          EntropyBits = src.EntropyBits,
                                                          MaxEntropyBits = src.MaxEntropyBits,
                                                          EntropyFlipCount = src.EntropyFlipCount,
                                                          RapidEntropyFlipCount = src.RapidEntropyFlipCount,
                                                          HighEntropyWriteCount = src.HighEntropyWriteCount,
                                                          SampleBytes = src.SampleBytes,
                                                          LifecycleSummary = src.LifecycleSummary,
                                                          ThreadStartObserved = src.ThreadStartObserved,
                                                          ThreadId = src.ThreadId,
                                                          ThreadStartAddress = src.ThreadStartAddress,
                                                          FunctionTableRegistered = src.FunctionTableRegistered,
                                                          FunctionTablePointer = src.FunctionTablePointer,
                                                          SignatureLevel = src.SignatureLevel,
                                                          SignatureType = src.SignatureType };

        private static class ProcessTreeSnapshot
        {
            private const uint TH32CS_SNAPPROCESS = 0x00000002;
            private static readonly IntPtr InvalidHandleValue = new(-1);

            internal static int[] DiscoverDescendants(int[] roots)
            {
                HashSet<int> rootSet = roots.Where(static processId => processId > 0).ToHashSet();
                if (rootSet.Count == 0)
                {
                    return Array.Empty<int>();
                }

                Dictionary<int, int> parentByPid = SnapshotParents();
                if (parentByPid.Count == 0)
                {
                    return Array.Empty<int>();
                }

                var descendants = new HashSet<int>();
                bool changed;
                do
                {
                    changed = false;
                    foreach ((int processId, int parentPid) in parentByPid)
                    {
                        if (processId <= 0 || rootSet.Contains(processId) || descendants.Contains(processId))
                        {
                            continue;
                        }

                        if (rootSet.Contains(parentPid) || descendants.Contains(parentPid))
                        {
                            descendants.Add(processId);
                            changed = true;
                        }
                    }
                } while (changed);

                return descendants.OrderBy(static processId => processId).ToArray();
            }

            private static Dictionary<int, int> SnapshotParents()
            {
                IntPtr snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
                if (snapshot == IntPtr.Zero || snapshot == InvalidHandleValue)
                {
                    return new Dictionary<int, int>();
                }

                try
                {
                    var entry = new PROCESSENTRY32 { dwSize = (uint)Marshal.SizeOf<PROCESSENTRY32>() };
                    var parents = new Dictionary<int, int>();
                    if (!Process32FirstW(snapshot, ref entry))
                    {
                        return parents;
                    }

                    do
                    {
                        if (entry.th32ProcessID <= int.MaxValue && entry.th32ParentProcessID <= int.MaxValue)
                        {
                            parents[unchecked((int)entry.th32ProcessID)] = unchecked((int)entry.th32ParentProcessID);
                        }
                    } while (Process32NextW(snapshot, ref entry));

                    return parents;
                }
                finally
                {
                    _ = CloseHandle(snapshot);
                }
            }

            [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
            private struct PROCESSENTRY32
            {
                internal uint dwSize;
                internal uint cntUsage;
                internal uint th32ProcessID;
                internal IntPtr th32DefaultHeapID;
                internal uint th32ModuleID;
                internal uint cntThreads;
                internal uint th32ParentProcessID;
                internal int pcPriClassBase;
                internal uint dwFlags;
                [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
                internal string szExeFile;
            }

            [DllImport("kernel32.dll", SetLastError = true)]
            private static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

            [DllImport("kernel32.dll", SetLastError = true)]
            [return:MarshalAs(UnmanagedType.Bool)]
            private static extern bool Process32FirstW(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

            [DllImport("kernel32.dll", SetLastError = true)]
            [return:MarshalAs(UnmanagedType.Bool)]
            private static extern bool Process32NextW(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

            [DllImport("kernel32.dll", SetLastError = true)]
            [return:MarshalAs(UnmanagedType.Bool)]
            private static extern bool CloseHandle(IntPtr hObject);
        }
    }
}
