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

        internal void ObserveHeuristics(IReadOnlyList<HeuristicEventView> findings)
        {
            if (findings == null || findings.Count == 0)
            {
                return;
            }

            lock (_sync)
            {
                foreach (HeuristicEventView finding in findings)
                {
                    AddHeuristicFindingLocked(finding);
                }
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

                if ((!string.IsNullOrWhiteSpace(view.DetectionName) ||
                     view.Family == BlackbirdNative.IpcEtwFamilyDetection ||
                     view.Family == BlackbirdNative.IpcEtwFamilyThreatIntel) &&
                    ShouldPromoteDetectionLocked(actorPid, targetPid, observedUtc, detection, eventName, details))
                {
                    string operatorDetection = OperatorDetectionFormatter.Format(
                        detection, actorPid, targetPid, FirstNonEmpty(view.Operation, view.EventName));
                    if (!string.IsNullOrWhiteSpace(operatorDetection))
                    {
                        AddGroup(_heuristicGroups,
                                 $"heuristic:{operatorDetection}:{actorPid}:{targetPid}:{view.Reason}", eventName,
                                 SeverityLabel(view.Severity), operatorDetection, source, actorPid, targetPid, argument,
                                 details, observedUtc, hitCount);
                    }
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

                IReadOnlyList<ProcessCapabilityObservation> capabilities = ProcessCapabilityCatalog.Observe(view);
                for (int i = 0; i < capabilities.Count; i += 1)
                {
                    ProcessCapabilityObservation capability = capabilities[i];
                    AddExtended("Process Capability", PidLabel(capability.ActorPid), PidLabel(capability.TargetPid),
                                capability.Name, capability.State, observedUtc, hitCount, capability.Detail);
                }
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
    }
}
