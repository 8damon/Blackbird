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

            if (!severity.Equals("Info", StringComparison.OrdinalIgnoreCase) &&
                ShouldPromoteDetectionLocked(record.RegistryProcessPid, 0, observedUtc, "REGISTRY_SENSITIVE_PROBE",
                                             "RegistryTelemetry", detail))
            {
                string detection = OperatorDetectionFormatter.Format("REGISTRY_SENSITIVE_PROBE",
                                                                     record.RegistryProcessPid, 0, "RegistryTelemetry");
                AddGroup(_heuristicGroups, $"registry-probe:{record.RegistryProcessPid}:{path}", "RegistryTelemetry",
                         severity, detection, "Kernel-IOCTL", record.RegistryProcessPid, 0, path, detail, observedUtc,
                         1);
            }
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

        private void AddHeuristicFindingLocked(HeuristicEventView? finding)
        {
            if (finding == null || string.IsNullOrWhiteSpace(finding.DetectionName))
            {
                return;
            }

            DateTime observedUtc = finding.TimestampUtc == default ? DateTime.UtcNow : finding.TimestampUtc;
            uint actor = finding.ActorPid;
            uint target = finding.TargetPid;
            string detection = finding.DetectionName.Trim();
            string eventName = FirstNonEmpty(finding.EventName, detection);
            string source = FirstNonEmpty(finding.Source, _sourceLabel);
            string reason = FirstNonEmpty(finding.Reason, finding.Evidence, detection);
            string evidence = FirstNonEmpty(finding.Evidence, finding.Reason, detection);
            string detail = $"{finding.Details}; operation={eventName}; {evidence}";
            int hitCount = Math.Max(1, finding.RepeatCount);

            if (!ShouldPromoteDetectionLocked(actor, target, observedUtc, detection, eventName, evidence))
            {
                AddExtended("Suppressed Detection", PidLabel(actor), PidLabel(target), detection,
                            "execution-phase-gate", observedUtc, hitCount, detail);
                return;
            }

            AddGroup(_heuristicGroups, $"heuristic:{detection}:{eventName}:{actor}:{target}:{Truncate(reason, 160)}",
                     eventName, SeverityLabel(finding.Severity), detection, source, actor, target, reason, detail,
                     observedUtc, hitCount);
            AddExtended("Detection", PidLabel(actor), PidLabel(target), detection, eventName, observedUtc, hitCount,
                        detail);
            HeuristicsMaterialized?.Invoke(new[] { finding.Clone() });
        }

        private bool ShouldPromoteDetectionLocked(uint actor, uint target, DateTime observedUtc, string detectionName,
                                                  string eventName, string evidence, bool strongEvidence = false)
        {
            return !CaptureExecutionPolicy.ShouldSuppressPromotion(_executionPhase, observedUtc, actor,
                                                                   target == 0 ? actor : target, IsTrackedPid,
                                                                   detectionName, eventName, evidence, strongEvidence);
        }
    }
}
