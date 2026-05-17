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
        private void RememberRecentImageFileAccess(IoctlParsedEvent record, DateTime observedUtc)
        {
            if (record.Type != BlackbirdNative.EventTypeFileSystem || record.FileProcessPid == 0 ||
                (record.FileOperation != BlackbirdNative.FileOperationCreate &&
                 record.FileOperation != BlackbirdNative.FileOperationRead))
            {
                return;
            }

            string path = NormalizeCorrelationPath(record.FilePath);
            if (!IsImagePathForMapping(path) || IsBlackbirdInternalCorrelationPath(path))
            {
                return;
            }

            var access = new RecentImageFileAccess { TimestampUtc = observedUtc,
                                                     Pid = record.FileProcessPid,
                                                     Tid = record.FileThreadId,
                                                     Operation = record.FileOperation,
                                                     Path = path,
                                                     FileName = ModuleNameFromPath(path) };

            lock (_imageMapCorrelationLock)
            {
                PruneImageMapCorrelationCachesLocked(observedUtc);
                _recentImageFileAccesses.Add(access);
                if (_recentImageFileAccesses.Count > MaxRecentImageFileAccesses)
                {
                    _recentImageFileAccesses.RemoveRange(0,
                                                         _recentImageFileAccesses.Count - MaxRecentImageFileAccesses);
                }
            }
        }

        private void ResetImageMapCorrelationCaches()
        {
            lock (_imageMapCorrelationLock)
            {
                _recentImageFileAccesses.Clear();
                _recentImageMapByPidPath.Clear();
                _lastImageMapCorrelationPruneUtc = DateTime.MinValue;
            }
        }

        private void PruneImageMapCorrelationCachesLocked(DateTime nowUtc)
        {
            if (_lastImageMapCorrelationPruneUtc != DateTime.MinValue &&
                nowUtc < _lastImageMapCorrelationPruneUtc.AddSeconds(2))
            {
                return;
            }

            DateTime fileCutoff = nowUtc - ImageMapFileCorrelationWindow - TimeSpan.FromSeconds(2);
            _recentImageFileAccesses.RemoveAll(x => x.TimestampUtc < fileCutoff);

            DateTime mapCutoff = nowUtc - ImageMapRepeatWindow;
            foreach (string key in _recentImageMapByPidPath.Where(x => x.Value.LastSeenUtc < mapCutoff)
                         .Select(x => x.Key)
                         .ToList())
            {
                _recentImageMapByPidPath.Remove(key);
            }

            if (_recentImageMapByPidPath.Count > MaxRecentImageMapStates)
            {
                foreach (string key in _recentImageMapByPidPath.OrderBy(x => x.Value.LastSeenUtc)
                             .Take(_recentImageMapByPidPath.Count - MaxRecentImageMapStates)
                             .Select(x => x.Key)
                             .ToList())
                {
                    _recentImageMapByPidPath.Remove(key);
                }
            }

            _lastImageMapCorrelationPruneUtc = nowUtc;
        }

        private RecentImageFileAccess? FindRecentImageFileAccessLocked(uint pid, uint tid, string mappedPath,
                                                                       DateTime observedUtc)
        {
            string normalizedPath = NormalizeCorrelationPath(mappedPath);
            string fileName = ModuleNameFromPath(normalizedPath);
            bool hasPath = !string.IsNullOrWhiteSpace(normalizedPath);
            bool hasFileName =
                !string.IsNullOrWhiteSpace(fileName) && !fileName.Equals("unknown", StringComparison.OrdinalIgnoreCase);

            return _recentImageFileAccesses
                .Where(x => x.Pid == pid &&
                            IsWithinCorrelationWindow(x.TimestampUtc, observedUtc, ImageMapFileCorrelationWindow) &&
                            (!hasPath || x.Path.Equals(normalizedPath, StringComparison.OrdinalIgnoreCase) ||
                             (hasFileName && x.FileName.Equals(fileName, StringComparison.OrdinalIgnoreCase))))
                .OrderByDescending(x => x.Tid == tid && tid != 0)
                .ThenByDescending(x => x.Path.Equals(normalizedPath, StringComparison.OrdinalIgnoreCase))
                .ThenBy(x => Math.Abs((x.TimestampUtc - observedUtc).TotalMilliseconds))
                .FirstOrDefault();
        }

        private RecentImageMapState RememberImageMapLocked(uint pid, string mappedPath, string apiName,
                                                           DateTime observedUtc, RecentImageFileAccess? linkedAccess)
        {
            string key = $"{pid}|{mappedPath}";
            if (!_recentImageMapByPidPath.TryGetValue(key, out RecentImageMapState? state) ||
                observedUtc > state.LastSeenUtc.Add(ImageMapRepeatWindow))
            {
                state = new RecentImageMapState {
                    FirstSeenUtc = observedUtc, LastSeenUtc = observedUtc,           Path = mappedPath,
                    LastApi = apiName,          LastLinkedFileAccess = linkedAccess, Count = 0
                };
                _recentImageMapByPidPath[key] = state;
            }

            state.Count += 1;
            state.LastSeenUtc = observedUtc;
            state.LastApi = apiName;
            if (linkedAccess != null)
            {
                state.LastLinkedFileAccess = linkedAccess;
            }

            return state.Clone();
        }

        private static bool IsWithinCorrelationWindow(DateTime leftUtc, DateTime rightUtc, TimeSpan window) =>
            Math.Abs((leftUtc - rightUtc).TotalMilliseconds) <= window.TotalMilliseconds;

        private static bool IsImageSectionMapApi(string apiName)
        {
            string api = (apiName ?? string.Empty).Trim();
            return api.Equals("NtMapViewOfSection", StringComparison.OrdinalIgnoreCase) ||
                   api.Equals("ZwMapViewOfSection", StringComparison.OrdinalIgnoreCase) ||
                   api.Equals("NtCreateSection", StringComparison.OrdinalIgnoreCase) ||
                   api.Equals("ZwCreateSection", StringComparison.OrdinalIgnoreCase) ||
                   api.Equals("CreateFileMappingA", StringComparison.OrdinalIgnoreCase) ||
                   api.Equals("CreateFileMappingW", StringComparison.OrdinalIgnoreCase) ||
                   api.Equals("CreateFileMapping", StringComparison.OrdinalIgnoreCase) ||
                   api.Equals("MapViewOfFile", StringComparison.OrdinalIgnoreCase) ||
                   api.Equals("MapViewOfFileEx", StringComparison.OrdinalIgnoreCase);
        }

        private static string ExtractMappedImagePath(BrokerEtwEventView view,
                                                     IReadOnlyDictionary<string, string> fields)
        {
            foreach (string candidate in new[] {
                         view.ImagePath, ReadTrimmedField(fields, "sectionPath"), ReadTrimmedField(fields, "filePath"),
                         ReadTrimmedField(fields, "imagePath"), ReadTrimmedField(fields, "modulePath"),
                         ReadTrimmedField(fields, "mappedPath"), ReadTrimmedField(fields, "path"),
                         ReadTrimmedField(fields, "objectName"), ReadTrimmedField(fields, "name")
                     })
            {
                string normalized = NormalizeCorrelationPath(candidate);
                if (IsImagePathForMapping(normalized))
                {
                    return normalized;
                }
            }

            return string.Empty;
        }

        private static string NormalizeCorrelationPath(string? path)
        {
            string value = (path ?? string.Empty).Trim().Trim('"');
            if (value.Length == 0)
            {
                return string.Empty;
            }

            value = value.Replace('/', '\\');
            if (value.StartsWith("\\??\\", StringComparison.OrdinalIgnoreCase))
            {
                value = value[4..];
            }
            if (value.StartsWith("file:", StringComparison.OrdinalIgnoreCase))
            {
                value = value[5..].TrimStart('\\');
            }

            return value.Trim();
        }

        private static bool IsImagePathForMapping(string? path)
        {
            string name = ModuleNameFromPath(path ?? string.Empty);
            return name.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) ||
                   name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ||
                   name.EndsWith(".ocx", StringComparison.OrdinalIgnoreCase) ||
                   name.EndsWith(".sys", StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsBlackbirdInternalCorrelationPath(string? path)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                return false;
            }

            return EventDetailFormatting.IsBlackbirdInternalPath(path) ||
                   EventDetailFormatting.IsBlackbirdInternalModule(ModuleNameFromPath(path));
        }

        private bool IsLikelyNativeLoaderImageMap(BrokerEtwEventView view, string mappedPath, uint actor,
                                                  DateTime observedUtc)
        {
            if (view.Family != BlackbirdNative.IpcEtwFamilyUserHook || actor == 0 ||
                !IsHookCurrentProcessTarget(view) || !IsHookImageSection(view))
            {
                return false;
            }

            bool systemCaller = (view.Flags & BlackbirdNative.IpcEtwFlagHookCallerAllSystem) != 0 ||
                                view.CallerOriginLabel.Equals("system", StringComparison.OrdinalIgnoreCase);
            bool cleanLoaderTrace = (view.Flags & (BlackbirdNative.IpcEtwFlagHookCallerHasUnmapped |
                                                   BlackbirdNative.IpcEtwFlagHookCallerHasNonSystemDll)) == 0;
            if (!systemCaller || !cleanLoaderTrace || !IsWindowsSystemImagePath(mappedPath))
            {
                return false;
            }

            return IsWithinObservedStartupWindow(actor, observedUtc, TimeSpan.FromSeconds(4));
        }

        private bool IsWithinObservedStartupWindow(uint pid, DateTime observedUtc, TimeSpan window)
        {
            if (pid == 0)
            {
                return false;
            }

            if (!_observedProcessStartUtcByPid.TryGetValue(pid, out DateTime startUtc))
            {
                if (_currentSession == null || _currentSession.Pid != unchecked((int)pid))
                {
                    return false;
                }

                startUtc = _currentSession.CaptureStartUtc;
            }

            if (observedUtc < startUtc)
            {
                return true;
            }

            return observedUtc - startUtc <= window;
        }

        private static bool IsWindowsSystemImagePath(string? path)
        {
            string value = NormalizeCorrelationPath(path);
            if (string.IsNullOrWhiteSpace(value))
            {
                return false;
            }

            return value.Contains("\\Windows\\System32\\", StringComparison.OrdinalIgnoreCase) ||
                   value.Contains("\\Windows\\SysWOW64\\", StringComparison.OrdinalIgnoreCase) ||
                   value.Contains("\\Windows\\WinSxS\\", StringComparison.OrdinalIgnoreCase);
        }

        private HeuristicEventView? BuildAntiAnalysisFinding(DateTime timestampUtc, uint actor, uint target,
                                                             string detection, uint severity, string source,
                                                             string eventName, string reason, string evidence)
        {
            string keyEvidence = StripStackEvidenceForAggregation(evidence);
            string key = $"{actor}|{target}|{detection}|{keyEvidence}";
            _antiAnalysisCountByEvidence.TryGetValue(key, out int count);
            count += 1;
            _antiAnalysisCountByEvidence[key] = count;
            if (count != 1 && count != 5 && count != 25 && count != 100)
            {
                return null;
            }

            return new HeuristicEventView { TimestampUtc = timestampUtc,
                                            LastSeenUtc = timestampUtc,
                                            Severity = severity,
                                            DetectionName = detection,
                                            ActorPid = actor,
                                            TargetPid = target == 0 ? actor : target,
                                            Source = source,
                                            EventName = eventName,
                                            Reason = $"reason={reason}; hits={count}",
                                            Evidence = evidence,
                                            RepeatCount = 1 };
        }

        private static string StripStackEvidenceForAggregation(string evidence)
        {
            if (string.IsNullOrWhiteSpace(evidence))
            {
                return string.Empty;
            }

            int stackEvidenceIndex = evidence.IndexOf("; stackEvidence=", StringComparison.OrdinalIgnoreCase);
            return stackEvidenceIndex > 0 ? evidence[..stackEvidenceIndex] : evidence;
        }

        private static bool HasDetectionTrait(BrokerEtwEventView view, uint trait) => (view.DetectionTraits & trait) !=
                                                                                      0;

        private static bool IsDirectSyscallDetection(BrokerEtwEventView view)
        {
            if (HasDetectionTrait(view, BlackbirdNative.IpcEtwTraitDirectSyscall))
            {
                return true;
            }

            if (IsDirectSyscallHandleTelemetry(view))
            {
                return true;
            }

            string detection = view.DetectionName;
            if (string.IsNullOrWhiteSpace(detection))
            {
                return false;
            }

            return detection.Contains("DIRECT_SYSCALL", StringComparison.OrdinalIgnoreCase) ||
                   detection.Contains("DIRECT-SYSCALL", StringComparison.OrdinalIgnoreCase) ||
                   detection.Contains("SUSPECT_HANDLE_OPERATION", StringComparison.OrdinalIgnoreCase) ||
                   detection.Contains("ANOMALY_ON_HANDLE_OP", StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsDirectSyscallHandleTelemetry(BrokerEtwEventView view)
        {
            if (view.Family != BlackbirdNative.IpcEtwFamilyHandle)
            {
                return false;
            }

            if (view.ClassName.Equals("DIRECT-SYSCALL-SUSPECT", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            bool exportMismatch = (view.Flags & HandleFlagSyscallExportMismatch) != 0;
            bool stackSpoof = (view.Flags & HandleFlagStackSpoofSuspect) != 0;
            bool execOutsideNtdll =
                (view.Flags & HandleFlagExecProtect) != 0 && (view.Flags & HandleFlagFromNtdll) == 0;
            return exportMismatch || stackSpoof || execOutsideNtdll;
        }

        private static bool IsHookTamperDetection(BrokerEtwEventView view)
        {
            if (HasDetectionTrait(view, BlackbirdNative.IpcEtwTraitHookTamper))
            {
                return true;
            }

            string detection = view.DetectionName;
            if (string.IsNullOrWhiteSpace(detection))
            {
                return false;
            }

            return detection.Contains("USERMODE_HOOK_TAMPERED", StringComparison.OrdinalIgnoreCase) ||
                   detection.Contains("AMSI_PATCH_TAMPERED", StringComparison.OrdinalIgnoreCase) ||
                   detection.Contains("ETW_PATCH_TAMPERED", StringComparison.OrdinalIgnoreCase) ||
                   detection.Contains("IAT_TAMPER", StringComparison.OrdinalIgnoreCase) ||
                   detection.Contains("EAT_TAMPER", StringComparison.OrdinalIgnoreCase) ||
                   detection.Contains("NTDLL_IMAGE_TAMPER", StringComparison.OrdinalIgnoreCase) ||
                   detection.Contains("SR71_HOOK_WRITE_BLOCKED", StringComparison.OrdinalIgnoreCase) ||
                   detection.Contains("SR71_HOOK_PROTECT_BLOCKED", StringComparison.OrdinalIgnoreCase) ||
                   detection.Contains("HOOK_TAMPER", StringComparison.OrdinalIgnoreCase);
        }
    }
}
