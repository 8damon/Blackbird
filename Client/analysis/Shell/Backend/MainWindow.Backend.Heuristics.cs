using BlackbirdInterface.Capture;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using System.Windows.Media;

namespace BlackbirdInterface
{
    public partial class MainWindow
    {
        private HeuristicEventView? EvaluateCrossProcessMemoryHeuristic(BrokerEtwEventView view)
        {
            if (IsBlackbirdOwnEvent(view) || HasFailedHookStatus(view))
            {
                return null;
            }

            string apiName = !string.IsNullOrWhiteSpace(view.EventName)
                                 ? view.EventName
                                 : (!string.IsNullOrWhiteSpace(view.Operation) ? view.Operation : string.Empty);
            if (string.IsNullOrEmpty(apiName))
            {
                return null;
            }

            uint actor = view.ActorPid != 0 ? view.ActorPid : view.ProcessPid;
            uint target = view.TargetPid != 0 ? view.TargetPid : actor;
            if (actor == 0 || actor == target)
            {
                return null;
            }

            string pairKey = $"{actor}|{target}";

            if (apiName.Equals("NtWriteVirtualMemory", StringComparison.OrdinalIgnoreCase))
            {
                _crossProcWriteCountByPair.TryGetValue(pairKey, out int count);
                count += 1;
                _crossProcWriteCountByPair[pairKey] = count;

                if (count != 5 && count != 25 && count != 100)
                {
                    return null;
                }

                uint severity = count >= 100 ? 8u : count >= 25 ? 7u : 6u;
                return new HeuristicEventView {
                    TimestampUtc = view.TimestampUtc,
                    LastSeenUtc = view.TimestampUtc,
                    Severity = severity,
                    DetectionName = "CROSS_PROCESS_WRITE_PATTERN",
                    ActorPid = actor,
                    TargetPid = target,
                    Source = "BK/MemoryPattern",
                    EventName = "NtWriteVirtualMemory",
                    Reason = $"reason=cross-process write accumulation; count={count}; actor={actor}; target={target}",
                    Evidence = $"NtWriteVirtualMemory observed {count}x from pid {actor} into pid {target}",
                    RepeatCount = 1
                };
            }

            if (apiName.Equals("NtAllocateVirtualMemory", StringComparison.OrdinalIgnoreCase))
            {
                Dictionary<string, string> fields = ParseReasonFields(view.Reason ?? string.Empty);
                uint protect = (uint)FirstU64(fields, "protect", "c3", "a5");
                bool isRwx = protect != 0 && (protect & 0x40u) != 0;
                if (!isRwx)
                {
                    return null;
                }

                _crossProcRwxAllocCountByPair.TryGetValue(pairKey, out int count);
                count += 1;
                _crossProcRwxAllocCountByPair[pairKey] = count;

                if (count != 3 && count != 12 && count != 48)
                {
                    return null;
                }

                uint severity = count >= 48 ? 9u : count >= 12 ? 8u : 7u;
                return new HeuristicEventView {
                    TimestampUtc = view.TimestampUtc,
                    LastSeenUtc = view.TimestampUtc,
                    Severity = severity,
                    DetectionName = "CROSS_PROCESS_RWX_ALLOC_PATTERN",
                    ActorPid = actor,
                    TargetPid = target,
                    Source = "BK/MemoryPattern",
                    EventName = "NtAllocateVirtualMemory",
                    Reason =
                        $"reason=repeated cross-process RWX allocation; count={count}; actor={actor}; target={target}",
                    Evidence =
                        $"NtAllocateVirtualMemory(PAGE_EXECUTE_READWRITE) observed {count}x from pid {actor} into pid {target}",
                    RepeatCount = 1
                };
            }

            return null;
        }

        private HeuristicEventView? EvaluateMemoryLifecycleHeuristic(MemoryRegionAttributionSample sample)
        {
            if (sample.BlackbirdOwned || sample.TargetPid == 0)
            {
                return null;
            }

            bool protectEvent = sample.ProtectFlipCount != 0 &&
                                sample.EventKind.Equals("ProtectChange", StringComparison.OrdinalIgnoreCase);
            bool guardNoAccessSignal = sample.GuardNoAccessFlipCount != 0;
            bool writableExecutableSignal = sample.WritableExecutableFlipCount != 0;
            bool firstHighSignalProtect = sample.ProtectFlipCount == 1 &&
                                          (guardNoAccessSignal || writableExecutableSignal || sample.CrossProcess);
            bool repeatedProtect = protectEvent && (IsMemoryPatternMilestone(sample.ProtectFlipCount) ||
                                                    sample.RapidProtectFlipCount == 1 ||
                                                    IsMemoryPatternMilestone(sample.RapidProtectFlipCount));
            if (protectEvent && (firstHighSignalProtect || repeatedProtect))
            {
                uint severity = ComputeMemoryLifecycleSeverity(sample, protectSignal: true, entropySignal: false);
                string detectionName = guardNoAccessSignal        ? "MEMORY_GUARD_NOACCESS_PROTECTION_FLIP"
                                       : writableExecutableSignal ? "MEMORY_WRITABLE_EXECUTABLE_PROTECTION_FLIP"
                                                                  : "MEMORY_PROTECTION_FLIP_PATTERN";
                string transition =
                    string.IsNullOrWhiteSpace(sample.ProtectionTransition) ? "unknown" : sample.ProtectionTransition;
                string entropyText =
                    sample.EntropyBits >= 0 ? sample.EntropyBits.ToString("F2", CultureInfo.InvariantCulture) : "n/a";
                string maxEntropyText = sample.MaxEntropyBits >= 0
                                            ? sample.MaxEntropyBits.ToString("F2", CultureInfo.InvariantCulture)
                                            : "n/a";

                return new HeuristicEventView {
                    TimestampUtc = sample.TimestampUtc == default ? DateTime.UtcNow : sample.TimestampUtc,
                    LastSeenUtc = sample.TimestampUtc == default ? DateTime.UtcNow : sample.TimestampUtc,
                    Severity = severity,
                    DetectionName = detectionName,
                    ActorPid = sample.ActorPid != 0 ? sample.ActorPid : sample.TargetPid,
                    TargetPid = sample.TargetPid,
                    Source = "BK/MemoryLifecycle",
                    EventName = string.IsNullOrWhiteSpace(sample.ApiName) ? sample.EventKind : sample.ApiName,
                    Reason =
                        $"reason=memory protection flip pattern; region=0x{sample.BaseAddress:X}; size=0x{sample.RegionSize:X}; " +
                        $"transition={transition}; flips={sample.ProtectFlipCount}; rapid={sample.RapidProtectFlipCount}; " +
                        $"execFlips={sample.ExecutableFlipCount}; guardNoAccessFlips={sample.GuardNoAccessFlipCount}; " +
                        $"wxFlips={sample.WritableExecutableFlipCount}; writes={sample.WriteCount}; entropy={entropyText}; maxEntropy={maxEntropyText}",
                    Evidence =
                        $"Region 0x{sample.BaseAddress:X} changed protection {transition}; " +
                        $"protection flips={sample.ProtectFlipCount}, rapid flips={sample.RapidProtectFlipCount}, " +
                        $"exec/guard/WX flips={sample.ExecutableFlipCount}/{sample.GuardNoAccessFlipCount}/{sample.WritableExecutableFlipCount}, " +
                        $"writes={sample.WriteCount}, entropy={entropyText} bits/byte"
                };
            }

            bool entropyEvent = sample.EventKind.Equals("MemoryWrite", StringComparison.OrdinalIgnoreCase) &&
                                HasUsableEntropySample(sample);
            bool highEntropy = entropyEvent && sample.EntropyBits >= MemoryHighEntropyBits;
            bool repeatedEntropyShift = entropyEvent && (IsMemoryPatternMilestone(sample.EntropyFlipCount) ||
                                                         sample.RapidEntropyFlipCount == 1 ||
                                                         IsMemoryPatternMilestone(sample.RapidEntropyFlipCount));
            bool highEntropyMilestone = highEntropy && IsHighEntropyWriteMilestone(sample.HighEntropyWriteCount);
            if (entropyEvent && (highEntropyMilestone || repeatedEntropyShift))
            {
                uint severity = ComputeMemoryLifecycleSeverity(sample, protectSignal: false, entropySignal: true);
                string entropyText = sample.EntropyBits.ToString("F2", CultureInfo.InvariantCulture);
                string maxEntropyText = sample.MaxEntropyBits >= 0
                                            ? sample.MaxEntropyBits.ToString("F2", CultureInfo.InvariantCulture)
                                            : entropyText;
                string detectionName =
                    highEntropy ? "MEMORY_HIGH_ENTROPY_WRITE_PATTERN" : "MEMORY_ENTROPY_SHIFT_PATTERN";

                return new HeuristicEventView {
                    TimestampUtc = sample.TimestampUtc == default ? DateTime.UtcNow : sample.TimestampUtc,
                    LastSeenUtc = sample.TimestampUtc == default ? DateTime.UtcNow : sample.TimestampUtc,
                    Severity = severity,
                    DetectionName = detectionName,
                    ActorPid = sample.ActorPid != 0 ? sample.ActorPid : sample.TargetPid,
                    TargetPid = sample.TargetPid,
                    Source = "BK/MemoryLifecycle",
                    EventName = string.IsNullOrWhiteSpace(sample.ApiName) ? sample.EventKind : sample.ApiName,
                    Reason =
                        $"reason=memory entropy pattern; region=0x{sample.BaseAddress:X}; size=0x{sample.RegionSize:X}; " +
                        $"entropy={entropyText}; maxEntropy={maxEntropyText}; entropyFlips={sample.EntropyFlipCount}; " +
                        $"rapidEntropyFlips={sample.RapidEntropyFlipCount}; highEntropyWrites={sample.HighEntropyWriteCount}; " +
                        $"sampleBytes={sample.SampleBytes}; protectFlips={sample.ProtectFlipCount}",
                    Evidence =
                        $"Region 0x{sample.BaseAddress:X} write sample entropy={entropyText} bits/byte " +
                        $"(max={maxEntropyText}, entropy flips={sample.EntropyFlipCount}, high entropy writes={sample.HighEntropyWriteCount}, " +
                        $"sample bytes={sample.SampleBytes})"
                };
            }

            return null;
        }

        private HeuristicEventView? EvaluateAntiAnalysisHeuristic(BrokerEtwEventView view)
        {
            if (IsBlackbirdOwnEvent(view) || HasFailedHookStatus(view))
            {
                return null;
            }

            string apiName = !string.IsNullOrWhiteSpace(view.Operation)
                                 ? view.Operation
                                 : (!string.IsNullOrWhiteSpace(view.EventName) ? view.EventName : string.Empty);
            if (string.IsNullOrWhiteSpace(apiName))
            {
                return null;
            }

            Dictionary<string, string> fields = BuildHookFieldMap(view);
            uint actor = view.ActorPid != 0 ? view.ActorPid : view.ProcessPid;
            uint target = view.TargetPid != 0 ? view.TargetPid : actor;
            if (actor == 0)
            {
                return null;
            }

            if (apiName.Equals("NtQueryInformationProcess", StringComparison.OrdinalIgnoreCase))
            {
                uint infoClass = (uint)FirstU64(fields, "processInformationClass", "ProcessInformationClass",
                                                "infoClass", "class", "a1", "c1");
                string className = infoClass switch {
                    7 => "ProcessDebugPort",
                    30 => "ProcessDebugObjectHandle",
                    31 => "ProcessDebugFlags",
                    _ => string.Empty
                };
                if (string.IsNullOrWhiteSpace(className))
                {
                    return null;
                }

                if (!TryBuildRequiredStackEvidence(view, "ANTI_DEBUG_PROCESS_QUERY", out string stackEvidence,
                                                   out _))
                {
                    return null;
                }

                string evidence = $"{apiName} {className} actor={actor} target={target}";
                if (!string.IsNullOrWhiteSpace(stackEvidence))
                {
                    evidence = $"{evidence}; {stackEvidence}";
                }
                return BuildAntiAnalysisFinding(
                    view.TimestampUtc, actor, target, "ANTI_DEBUG_PROCESS_QUERY", 6, "UserHook/AntiAnalysis", apiName,
                    $"queried anti-debug process information class {className} (0x{infoClass:X})", evidence);
            }

            if (apiName.Equals("NtQuerySystemInformation", StringComparison.OrdinalIgnoreCase) ||
                apiName.Equals("NtQuerySystemInformationEx", StringComparison.OrdinalIgnoreCase))
            {
                uint infoClass = (uint)FirstU64(fields, "systemInformationClass", "SystemInformationClass", "infoClass",
                                                "class", "a0", "c0");
                if (infoClass == 35)
                {
                    if (!TryBuildRequiredStackEvidence(view, "ANTI_DEBUG_KERNEL_DEBUGGER_QUERY",
                                                       out string stackEvidence, out _))
                    {
                        return null;
                    }

                    string evidence = $"{apiName} SystemKernelDebuggerInformation actor={actor}";
                    if (!string.IsNullOrWhiteSpace(stackEvidence))
                    {
                        evidence = $"{evidence}; {stackEvidence}";
                    }
                    return BuildAntiAnalysisFinding(
                        view.TimestampUtc, actor, target, "ANTI_DEBUG_KERNEL_DEBUGGER_QUERY", 6,
                        "UserHook/AntiAnalysis", apiName,
                        "queried kernel debugger state with SystemKernelDebuggerInformation", evidence);
                }

                if (infoClass == 76)
                {
                    if (!TryBuildRequiredStackEvidence(view, "ANTI_VM_FIRMWARE_TABLE_QUERY",
                                                       out string stackEvidence, out _))
                    {
                        return null;
                    }

                    string evidence = $"{apiName} SystemFirmwareTableInformation actor={actor}";
                    if (!string.IsNullOrWhiteSpace(stackEvidence))
                    {
                        evidence = $"{evidence}; {stackEvidence}";
                    }
                    return BuildAntiAnalysisFinding(
                        view.TimestampUtc, actor, target, "ANTI_VM_FIRMWARE_TABLE_QUERY", 5, "UserHook/AntiAnalysis",
                        apiName, "queried firmware tables commonly used for hypervisor/vendor checks", evidence);
                }
            }

            return null;
        }

        private HeuristicEventView? EvaluateImageSectionMapHeuristic(BrokerEtwEventView view)
        {
            if (IsBlackbirdOwnEvent(view) || HasFailedHookStatus(view))
            {
                return null;
            }

            string apiName = !string.IsNullOrWhiteSpace(view.Operation)
                                 ? view.Operation
                                 : (!string.IsNullOrWhiteSpace(view.EventName) ? view.EventName : string.Empty);
            if (!IsImageSectionMapApi(apiName))
            {
                return null;
            }

            uint actor = view.ActorPid != 0     ? view.ActorPid
                         : view.ProcessPid != 0 ? view.ProcessPid
                                                : view.EventProcessId;
            if (actor == 0)
            {
                return null;
            }

            uint tid = view.EventThreadId != 0 ? view.EventThreadId : view.ThreadId;
            DateTime observedUtc = view.TimestampUtc == default ? DateTime.UtcNow : view.TimestampUtc;
            Dictionary<string, string> fields = BuildHookFieldMap(view);
            string mappedPath = ExtractMappedImagePath(view, fields);
            RecentImageFileAccess ? linkedAccess;
            RecentImageMapState mapState;

            lock (_imageMapCorrelationLock)
            {
                PruneImageMapCorrelationCachesLocked(observedUtc);
                linkedAccess = FindRecentImageFileAccessLocked(actor, tid, mappedPath, observedUtc);
                if (string.IsNullOrWhiteSpace(mappedPath) && linkedAccess != null)
                {
                    mappedPath = linkedAccess.Path;
                }

                mappedPath = NormalizeCorrelationPath(mappedPath);
                if (!IsImagePathForMapping(mappedPath))
                {
                    return null;
                }
                if (IsBlackbirdInternalCorrelationPath(mappedPath) ||
                    IsLikelyNativeLoaderImageMap(view, mappedPath, actor, observedUtc))
                {
                    return null;
                }

                mapState = RememberImageMapLocked(actor, mappedPath, apiName, observedUtc, linkedAccess);
            }

            string fileName = ModuleNameFromPath(mappedPath);
            bool isNtdll = fileName.Equals("ntdll.dll", StringComparison.OrdinalIgnoreCase);
            bool hasFilesystemLink = linkedAccess != null;
            bool emitMilestone = mapState.Count == 2 || mapState.Count == 4 || mapState.Count == 8 ||
                                 (mapState.Count > 0 && mapState.Count % 16 == 0);
            if (!emitMilestone)
            {
                return null;
            }

            if (!isNtdll && !hasFilesystemLink && mapState.Count < 4)
            {
                return null;
            }

            uint severity = isNtdll ? 5u : hasFilesystemLink ? 4u : 3u;
            string fileEvidence =
                hasFilesystemLink
                    ? $"linkedFs={DescribeFileOperation(linkedAccess!.Operation)} pid={linkedAccess.Pid} tid={linkedAccess.Tid} path={linkedAccess.Path}"
                    : "linkedFs=<none>";
            string targetText = view.TargetPid == 0 || view.TargetPid == actor
                                    ? "self"
                                    : view.TargetPid.ToString(CultureInfo.InvariantCulture);
            string reason =
                isNtdll
                    ? "repeated mapping of ntdll.dll in one process; normal loader startup maps it once, so later repeat maps are worth review"
                    : "repeated image-backed section mapping correlated with recent filesystem image access";

            return new HeuristicEventView {
                TimestampUtc = observedUtc,
                LastSeenUtc = observedUtc,
                Severity = severity,
                DetectionName = isNtdll ? "REPEATED_NTDLL_IMAGE_MAPPING" : "REPEATED_IMAGE_SECTION_MAPPING",
                ActorPid = actor,
                TargetPid = view.TargetPid == 0 ? actor : view.TargetPid,
                Source = "BK/ImageMapCorrelation",
                EventName = apiName,
                Reason = $"reason={reason}; count={mapState.Count}; target={targetText}",
                Evidence =
                    $"api={apiName} path={mappedPath} firstSeen={mapState.FirstSeenUtc:O} lastSeen={mapState.LastSeenUtc:O} {fileEvidence}",
                RepeatCount = 1
            };
        }
    }
}
