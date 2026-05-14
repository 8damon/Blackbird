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
        private static string BuildHandleEvidenceText(IoctlParsedEvent record)
        {
            string accessDecoded = EventDetailFormatting.DescribeHandleAccess(record.DesiredAccess);
            string flagsDecoded = EventDetailFormatting.DescribeHandleFlags(record.HandleFlags);
            string sampleHex = EventDetailFormatting.FormatSampleHex(record.DeepSample, (int)record.DeepSampleSize);
            string disasm = EventDetailFormatting.InferSampleBytes(record.DeepSample, (int)record.DeepSampleSize);
            string stackSnapshotHex =
                EventDetailFormatting.FormatSampleHex(record.StackSnapshot, (int)record.StackSnapshotSize);
            string stack0 = record.Frames.Length > 0 ? FormatIoctlCodeAddress(record, record.Frames[0]) : "n/a";
            string stack1 = record.Frames.Length > 1 ? FormatIoctlCodeAddress(record, record.Frames[1]) : "n/a";
            string moduleName = EventDetailFormatting.ModuleNameFromPath(record.OriginPath);
            string originAddress = FormatIoctlCodeAddress(record, record.OriginAddress);
            string allocationBase = FormatIoctlCodeAddress(record, record.DeepAllocationBase);
            string fullFrames = BuildFrameList(record, record.FullFrames, record.FullFrameCount);
            string captureFlags = DescribeCaptureFlags(record.CaptureFlags);
            string directSyscallName =
                EventDetailFormatting.ResolveDirectSyscallApi(record.DesiredAccess, record.HandleFlags);
            string directSyscallLabel = EventDetailFormatting.BuildDirectSyscallLabel(
                record.DesiredAccess, record.HandleFlags, record.DeepSample, (int)record.DeepSampleSize);
            bool hasContext = (record.CaptureFlags & 0x00000001u) != 0;
            bool hasDebugRegs = (record.CaptureFlags & 0x00000002u) != 0;
            bool hasFullFrames = (record.CaptureFlags & 0x00000004u) != 0;
            bool hasStackSnapshot = (record.CaptureFlags & 0x00000008u) != 0;

            string frameSegment = hasFullFrames ? $"fullFrameCount={record.FullFrameCount} fullFrames={fullFrames} "
                                                : "fullFrameCount=0 fullFrames=<none> ";

            string registerSegment =
                hasContext
                    ? $"rax=0x{record.RegRax:X} rbx=0x{record.RegRbx:X} rcx=0x{record.RegRcx:X} rdx=0x{record.RegRdx:X} " +
                          $"rsi=0x{record.RegRsi:X} rdi=0x{record.RegRdi:X} rbp=0x{record.RegRbp:X} rsp=0x{record.RegRsp:X} " +
                          $"r8=0x{record.RegR8:X} r9=0x{record.RegR9:X} r10=0x{record.RegR10:X} r11=0x{record.RegR11:X} " +
                          $"r12=0x{record.RegR12:X} r13=0x{record.RegR13:X} r14=0x{record.RegR14:X} r15=0x{record.RegR15:X} " +
                          $"rip=0x{record.RegRip:X} eflags=0x{record.RegEFlags:X} "
                    : string.Empty;

            string debugSegment =
                hasDebugRegs
                    ? $"dr0=0x{record.RegDr0:X} dr1=0x{record.RegDr1:X} dr2=0x{record.RegDr2:X} dr3=0x{record.RegDr3:X} dr6=0x{record.RegDr6:X} dr7=0x{record.RegDr7:X} "
                    : string.Empty;

            string stackSegment =
                hasStackSnapshot
                    ? $"stackSnapshotAddress=0x{record.StackSnapshotAddress:X} stackSnapshotSize={record.StackSnapshotSize} stackSnapshot={stackSnapshotHex} "
                    : "stackSnapshotAddress=0x0 stackSnapshotSize=0 stackSnapshot=<none> ";

            return $"ioctlEvidence class={record.HandleClass} syscallName={directSyscallName} syscallLabel={directSyscallLabel.Replace(' ', '_')} access=0x{record.DesiredAccess:X8} ({accessDecoded}) flags=0x{record.HandleFlags:X8} ({flagsDecoded}) " +
                   $"origin={originAddress} protect=0x{record.OriginProtect:X8} module={moduleName} " +
                   $"allocationBase={allocationBase} regionSize=0x{record.DeepRegionSize:X} regionProtect=0x{record.DeepRegionProtect:X8} ({EventDetailFormatting.DescribeMemoryProtection(record.DeepRegionProtect)}) " +
                   $"regionState=0x{record.DeepRegionState:X8} ({EventDetailFormatting.DescribeMemoryState(record.DeepRegionState)}) regionType=0x{record.DeepRegionType:X8} ({EventDetailFormatting.DescribeMemoryType(record.DeepRegionType)}) " +
                   $"path={record.OriginPath} stack0={stack0} stack1={stack1} " +
                   $"captureFlags=0x{record.CaptureFlags:X8} ({captureFlags}) " + frameSegment + registerSegment +
                   debugSegment + stackSegment +
                   $"deepSampleSize={record.DeepSampleSize} deepSample={sampleHex} sampleDisasmHint={disasm}";
        }

        private static string DescribeCaptureFlags(uint captureFlags)
        {
            var labels = new List<string>();
            if ((captureFlags & 0x00000001u) != 0)
            {
                labels.Add("CONTEXT");
            }
            if ((captureFlags & 0x00000002u) != 0)
            {
                labels.Add("DEBUG_REGS");
            }
            if ((captureFlags & 0x00000004u) != 0)
            {
                labels.Add("FULL_FRAMES");
            }
            if ((captureFlags & 0x00000008u) != 0)
            {
                labels.Add("STACK_SNAPSHOT");
            }

            return labels.Count == 0 ? "NONE" : string.Join("|", labels);
        }

        private static string BuildFrameList(IoctlParsedEvent record, ulong[]? frames, uint frameCount)
        {
            if (frames == null || frames.Length == 0 || frameCount == 0)
            {
                return "<none>";
            }

            int safeCount = Math.Min(frames.Length, (int)frameCount);
            var list = new List<string>(safeCount);
            for (int i = 0; i < safeCount; i += 1)
            {
                ulong frame = frames[i];
                if (frame == 0)
                {
                    continue;
                }

                list.Add(FormatIoctlCodeAddress(record, frame));
            }

            return list.Count == 0 ? "<none>" : string.Join(",", list);
        }

        private static string FormatIoctlCodeAddress(IoctlParsedEvent record, ulong address)
        {
            if (address == 0)
            {
                return "n/a";
            }

            string moduleName = EventDetailFormatting.ModuleNameFromPath(record.OriginPath);
            ulong allocationBase = record.DeepAllocationBase;
            ulong regionSize = record.DeepRegionSize;
            bool inRange = regionSize == 0 ||
                           (regionSize <= ulong.MaxValue - allocationBase && address < allocationBase + regionSize);
            if (!moduleName.Equals("unknown", StringComparison.OrdinalIgnoreCase) && allocationBase != 0 &&
                address >= allocationBase && inRange)
            {
                string section = (record.DeepRegionType & 0x01000000u) != 0 ? ".image" : ".region";
                return $"{moduleName}{section}+0x{address - allocationBase:X}";
            }

            return $"unresolved+0x{address:X}";
        }

        private static bool IsHighRiskIoctlAccess(uint desiredAccess, bool isThreadObject)
        {
            if (isThreadObject)
            {
                bool threadAll = (desiredAccess & 0x001F03FFu) == 0x001F03FFu;
                return threadAll || (desiredAccess & (0x0002u | 0x0008u | 0x0010u)) != 0;
            }

            bool processAll = (desiredAccess & 0x001F0FFFu) == 0x001F0FFFu;
            return processAll || (desiredAccess & (0x0002u | 0x0008u | 0x0010u | 0x0020u)) != 0;
        }

        private static bool ShouldKeepDirectSyscallHeuristicFromEvidence(IoctlParsedEvent record)
        {
            if (record.HandleClass == 2)
            {
                return true;
            }

            bool exportMismatch = (record.HandleFlags & HandleFlagSyscallExportMismatch) != 0;
            bool stackSpoof = (record.HandleFlags & HandleFlagStackSpoofSuspect) != 0;
            bool execOutsideNtdll =
                (record.HandleFlags & HandleFlagExecProtect) != 0 && (record.HandleFlags & HandleFlagFromNtdll) == 0;
            bool framesOutsideTeb = (record.HandleFlags & HandleFlagFramesOutsideTebStack) != 0;
            return exportMismatch || stackSpoof || execOutsideNtdll || framesOutsideTeb;
        }

        private static bool IsGdiSubsystemModule(string? originPath)
        {
            if (string.IsNullOrWhiteSpace(originPath))
            {
                return false;
            }

            string module = EventDetailFormatting.ModuleNameFromPath(originPath).ToLowerInvariant();
            return module is "win32u.dll" or "gdi32.dll" or "gdi32full.dll" or "user32.dll" or "user32full.dll";
        }

        private static string DescribeFileOperation(uint operation)
        {
            return operation switch { BlackbirdNative.FileOperationCreate => "CREATE",
                                      BlackbirdNative.FileOperationRead => "READ",
                                      BlackbirdNative.FileOperationWrite => "WRITE",
                                      BlackbirdNative.FileOperationClose => "CLOSE",
                                      BlackbirdNative.FileOperationCleanup => "CLEANUP",
                                      BlackbirdNative.FileOperationSetInformation => "SET_INFORMATION",
                                      BlackbirdNative.FileOperationQueryInformation => "QUERY_INFORMATION",
                                      BlackbirdNative.FileOperationDirectoryControl => "DIRECTORY_CONTROL",
                                      BlackbirdNative.FileOperationFsControl => "FS_CONTROL",
                                      _ => "UNKNOWN" };
        }

        private static string BuildFileSummaryPath(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                return "<unknown>";
            }

            const int maxChars = 84;
            if (path.Length <= maxChars)
            {
                return path;
            }

            return "..." + path[^maxChars..];
        }

        private static string BuildFilesystemClusterKey(IoctlParsedEvent record)
        {
            string path = string.IsNullOrWhiteSpace(record.FilePath) ? "<unknown>" : record.FilePath;
            return $"{record.FileOperation}|{record.FileProcessPid}|{path}";
        }

        private void ResetFilesystemTimelineCluster()
        {
            _filesystemClusterOperationCounts.Clear();
            _filesystemClusterSamplesByOperation.Clear();
            _filesystemClusterTotal = 0;
            _filesystemClusterWindowStartUtc = DateTime.MinValue;
            _filesystemClusterLastSeenUtc = DateTime.MinValue;
        }

        private IReadOnlyList<TelemetryEvent> FlushFilesystemTimelineClusterIfNeeded(DateTime nowUtc, bool force)
        {
            if (_filesystemClusterTotal <= 0)
            {
                return Array.Empty<TelemetryEvent>();
            }

            if (!force && (nowUtc - _filesystemClusterLastSeenUtc) < FilesystemTimelineClusterIdleFlush)
            {
                return Array.Empty<TelemetryEvent>();
            }

            double windowMs =
                Math.Max(1, (_filesystemClusterLastSeenUtc - _filesystemClusterWindowStartUtc).TotalMilliseconds);
            var emitted = new List<TelemetryEvent>(_filesystemClusterOperationCounts.Count);
            foreach (var entry in _filesystemClusterOperationCounts.OrderByDescending(x => x.Value).ThenBy(x => x.Key))
            {
                if (entry.Value <= 0)
                {
                    continue;
                }

                int count = entry.Value;
                (uint Pid, uint Tid, string Path, uint Operation) sample =
                    _filesystemClusterSamplesByOperation.TryGetValue(entry.Key, out var found)
                        ? found
                        : (0u, 0u, "<unknown>", 0u);
                string operationName = DescribeFileOperation(sample.Operation);
                string samplePath = string.IsNullOrWhiteSpace(sample.Path) ? "<unknown>" : sample.Path;
                string summaryPath = BuildFileSummaryPath(samplePath);
                emitted.Add(new TelemetryEvent {
                    TimestampUtc = _filesystemClusterLastSeenUtc, PID = unchecked((int)sample.Pid),
                    TID = unchecked((int)sample.Tid), Group = "Filesystem", SubType = operationName,
                    Summary = $"{operationName} x{count} pid={sample.Pid} path={summaryPath}",
                    Details =
                        $"windowStart={_filesystemClusterWindowStartUtc:O} windowEnd={_filesystemClusterLastSeenUtc:O} windowMs={windowMs:0} " +
                        $"operation={operationName} count={count} clusterTotal={_filesystemClusterTotal} samplePid={sample.Pid} sampleTid={sample.Tid} samplePath={samplePath}"
                });
            }

            ResetFilesystemTimelineCluster();
            return emitted;
        }

        private IReadOnlyList<TelemetryEvent> AccumulateFilesystemTimelineCluster(IoctlParsedEvent record,
                                                                                  DateTime nowUtc)
        {
            if (record.Type != BlackbirdNative.EventTypeFileSystem)
            {
                return Array.Empty<TelemetryEvent>();
            }

            var emitted = new List<TelemetryEvent>();
            if (_filesystemClusterTotal > 0 &&
                (nowUtc - _filesystemClusterWindowStartUtc) >= FilesystemTimelineClusterWindow)
            {
                emitted.AddRange(FlushFilesystemTimelineClusterIfNeeded(nowUtc, force: true));
            }

            if (_filesystemClusterTotal == 0)
            {
                _filesystemClusterWindowStartUtc = nowUtc;
            }

            string clusterKey = BuildFilesystemClusterKey(record);
            _filesystemClusterTotal += 1;
            _filesystemClusterLastSeenUtc = nowUtc;
            _filesystemClusterOperationCounts.TryGetValue(clusterKey, out int count);
            _filesystemClusterOperationCounts[clusterKey] = count + 1;
            if (!_filesystemClusterSamplesByOperation.ContainsKey(clusterKey))
            {
                _filesystemClusterSamplesByOperation[clusterKey] =
                    (record.FileProcessPid, record.FileThreadId,
                     string.IsNullOrWhiteSpace(record.FilePath) ? "<unknown>" : record.FilePath, record.FileOperation);
            }

            if (_filesystemClusterTotal >= FilesystemTimelineClusterFlushCount)
            {
                emitted.AddRange(FlushFilesystemTimelineClusterIfNeeded(nowUtc, force: true));
            }

            return emitted.Count == 0 ? Array.Empty<TelemetryEvent>() : emitted;
        }

        private TelemetryEvent? MapIoctlRecord(IoctlParsedEvent record)
        {
            DateTime now = DateTime.UtcNow;
            if (record.Type == BlackbirdNative.EventTypeHandle)
            {
                RememberHandleEvidence(record);
                uint caller = record.CallerPid;
                uint target = record.TargetPid;

                if (caller != 0 && !_filterTrackedPids.IsEmpty && !_filterTrackedPids.ContainsKey(caller))
                {
                    return null;
                }
                string originModuleForFilter = EventDetailFormatting.ModuleNameFromPath(record.OriginPath);
                if (EventDetailFormatting.IsSr71Module(originModuleForFilter))
                {
                    return null;
                }

                string className = record.HandleClass switch {
                    1 => "LEGITIMATE-SYSCALL",
                    2 => "DIRECT-SYSCALL-SUSPECT",
                    _ => "UNKNOWN"
                };
                string syscallLabel = EventDetailFormatting.BuildDirectSyscallLabel(
                    record.DesiredAccess, record.HandleFlags, record.DeepSample, (int)record.DeepSampleSize);

                return new TelemetryEvent {
                    TimestampUtc = now,
                    PID = unchecked((int)caller),
                    TID = unchecked((int)record.ThreadId),
                    Group = "Kernel-IOCTL",
                    SubType = "Handle",
                    Summary =
                        $"{className} {syscallLabel} caller={caller} target={target} access=0x{record.DesiredAccess:X8}",
                    Details = BuildHandleEvidenceText(record)
                };
            }

            if (record.Type == BlackbirdNative.EventTypeThread)
            {
                uint process = record.ProcessPid;
                uint creator = record.CreatorPid;

                if (creator != 0 && process != 0 && creator != process && !_filterTrackedPids.IsEmpty &&
                    !_filterTrackedPids.ContainsKey(creator))
                {
                    return null;
                }

                string eventKind =
                    DetermineThreadLifecycleKind(record.ThreadFlags, record.StartAddress, record.ImageSize);
                string threadFlags = EventDetailFormatting.DescribeThreadFlags(record.ThreadFlags);
                return new TelemetryEvent {
                    TimestampUtc = now,
                    PID = unchecked((int)process),
                    TID = unchecked((int)record.ThreadId),
                    Group = "Kernel-IOCTL",
                    SubType = $"Thread{eventKind}",
                    Summary = $"{eventKind} creator={creator} process={process} flags=0x{record.ThreadFlags:X8}",
                    Details =
                        $"seq={record.Sequence} start=0x{record.StartAddress:X} imageBase=0x{record.ImageBase:X} imageSize=0x{record.ImageSize:X} decodedFlags={threadFlags}"
                };
            }

            if (record.Type == BlackbirdNative.EventTypeFileSystem)
            {
                return null;
            }

            return null;
        }

        private bool ShouldAcceptFilesystemRecord(IoctlParsedEvent record)
        {
            if (record.Type != BlackbirdNative.EventTypeFileSystem)
            {
                return true;
            }

            uint pid = record.FileProcessPid;
            if (pid == 0 || (!_filterTrackedPids.IsEmpty && !_filterTrackedPids.ContainsKey(pid)))
            {
                return false;
            }

            return !IsBlackbirdInternalFilesystemPath(record.FilePath);
        }

        private bool ShouldEvaluateSignatureIntelForIoctl(IoctlParsedEvent record, bool acceptFilesystem)
        {
            if (record.Type == BlackbirdNative.EventTypeFileSystem)
            {
                return acceptFilesystem;
            }

            if (record.Type == BlackbirdNative.EventTypeRegistry)
            {
                return record.RegistryProcessPid != 0 && IsTrackedPid(record.RegistryProcessPid);
            }

            if (record.Type == BlackbirdNative.EventTypeHandle)
            {
                if (record.CallerPid != 0 && !IsTrackedPid(record.CallerPid))
                {
                    return false;
                }

                string originModule = EventDetailFormatting.ModuleNameFromPath(record.OriginPath);
                return !EventDetailFormatting.IsSr71Module(originModule);
            }

            if (record.Type == BlackbirdNative.EventTypeThread)
            {
                if (record.CreatorPid != 0 && record.ProcessPid != 0 && record.CreatorPid != record.ProcessPid)
                {
                    return IsTrackedPid(record.CreatorPid);
                }

                return IsTrackedPid(record.ProcessPid);
            }

            return true;
        }

        private static bool IsBlackbirdInternalFilesystemPath(string? path)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                return false;
            }

            string normalized = path.Replace('/', '\\').Trim();
            return normalized.Contains("\\ProgramData\\Blackbird", StringComparison.OrdinalIgnoreCase) ||
                   normalized.Contains("\\Device\\HarddiskVolume3\\ProgramData\\Blackbird",
                                       StringComparison.OrdinalIgnoreCase) ||
                   normalized.EndsWith("\\controller.log", StringComparison.OrdinalIgnoreCase) ||
                   normalized.EndsWith("\\controller.log.1", StringComparison.OrdinalIgnoreCase);
        }

        private static IoctlParsedEvent? MapIoctlFilesystem(IoctlParsedEvent record)
        {
            return record.Type == BlackbirdNative.EventTypeFileSystem ? record : null;
        }

        private static IoctlParsedEvent? MapIoctlRegistry(IoctlParsedEvent record)
        {
            return record.Type == BlackbirdNative.EventTypeRegistry ? record : null;
        }

        private static ThreadLifecycleEventSample? MapIoctlThreadLifecycle(IoctlParsedEvent record)
        {
            if (record.Type != BlackbirdNative.EventTypeThread)
            {
                return null;
            }

            DateTime now = DateTime.UtcNow;
            string eventKind = DetermineThreadLifecycleKind(record.ThreadFlags, record.StartAddress, record.ImageSize);
            string decodedFlags = EventDetailFormatting.DescribeThreadFlags(record.ThreadFlags);

            return new ThreadLifecycleEventSample { TimestampUtc = now,           ProcessPid = record.ProcessPid,
                                                    ThreadId = record.ThreadId,   CreatorPid = record.CreatorPid,
                                                    Flags = record.ThreadFlags,   StartAddress = record.StartAddress,
                                                    ImageBase = record.ImageBase, ImageSize = record.ImageSize,
                                                    EventKind = eventKind,        Notes = $"flags={decodedFlags}" };
        }

        private static string DetermineThreadLifecycleKind(uint threadFlags, ulong startAddress, ulong imageSize)
        {
            if ((threadFlags & 0x00000200u) != 0)
            {
                return "Exit";
            }

            if ((threadFlags & 0x00000001u) == 0 && startAddress == 0 && imageSize == 0)
            {
                return "Exit";
            }

            if ((threadFlags & 0x00000001u) != 0)
            {
                return "Start";
            }

            return "Update";
        }

        private ProcessRelationView? MapIoctlRelation(IoctlParsedEvent record)
        {
            DateTime now = DateTime.UtcNow;
            if (record.Type == BlackbirdNative.EventTypeHandle)
            {
                uint source = record.CallerPid;
                uint target = record.TargetPid;
                if (source == 0 || target == 0 || source == target)
                {
                    return null;
                }

                if (!_filterTrackedPids.IsEmpty && !_filterTrackedPids.ContainsKey(source))
                {
                    return null;
                }
                string accessDecoded = EventDetailFormatting.DescribeHandleAccess(record.DesiredAccess);
                string flagsDecoded = EventDetailFormatting.DescribeHandleFlags(record.HandleFlags);
                string originModule = EventDetailFormatting.ModuleNameFromPath(record.OriginPath);
                bool isSr71Handle = EventDetailFormatting.IsSr71Module(originModule);
                if (isSr71Handle)
                {
                    return null;
                }
                string detailSignature =
                    $"handle|{source}|{target}|{record.DesiredAccess:X8}|{record.HandleFlags:X8}|{originModule}";
                string detailText =
                    $"sourcePid={source} targetPid={target} relationType=HandleOpen access=0x{record.DesiredAccess:X8} ({accessDecoded}) " +
                    $"flags=0x{record.HandleFlags:X8} ({flagsDecoded}) originModule={originModule} " +
                    $"handleOwner={(isSr71Handle ? "SR71" : "ActorProcess")}";

                return new ProcessRelationView { FirstSeenUtc = now,
                                                 LastSeenUtc = now,
                                                 SourcePid = source,
                                                 TargetPid = target,
                                                 RelationType = "HandleOpen",
                                                 LastAccessMask = record.DesiredAccess,
                                                 LastFlags = record.HandleFlags,
                                                 OriginSource = "Kernel-IOCTL",
                                                 OriginModule = originModule,
                                                 DetailSignature = detailSignature,
                                                 DetailText = detailText,
                                                 RepeatCount = 1 };
            }

            if (record.Type == BlackbirdNative.EventTypeThread)
            {
                uint source = record.CreatorPid;
                uint target = record.ProcessPid;
                if (source == 0 || target == 0 || source == target)
                {
                    return null;
                }

                if (!_filterTrackedPids.IsEmpty && !_filterTrackedPids.ContainsKey(source))
                {
                    return null;
                }

                return new ProcessRelationView { FirstSeenUtc = now,
                                                 LastSeenUtc = now,
                                                 SourcePid = source,
                                                 TargetPid = target,
                                                 RelationType = "ThreadCreate",
                                                 LastAccessMask = 0,
                                                 LastFlags = record.ThreadFlags,
                                                 OriginSource = "Kernel-IOCTL",
                                                 OriginModule =
                                                     EventDetailFormatting.ModuleNameFromPath(record.OriginPath),
                                                 RepeatCount = 1 };
            }

            return null;
        }

        private static ProcessRelationView? MapEtwRelation(BrokerEtwEventView view)
        {
            if (view.Family != BlackbirdNative.IpcEtwFamilyProcess ||
                (view.Flags & BlackbirdNative.IpcEtwFlagProcessIsCreate) == 0)
            {
                return null;
            }

            uint source =
                view.CreatorPid != 0 ? view.CreatorPid : (view.ParentPid != 0 ? view.ParentPid : view.ActorPid);
            uint target = view.ProcessPid != 0 ? view.ProcessPid : view.TargetPid;
            if (source == 0 || target == 0 || source == target)
            {
                return null;
            }

            uint createStatus = unchecked((uint)view.CreateStatus);
            string detailSignature = $"create|{source}|{target}|0x{view.ProcessStartKey:X}|0x{createStatus:X8}";
            string detailText =
                $"sourcePid={source} targetPid={target} relationType=ProcessCreate creatorPid={view.CreatorPid} " +
                $"parentPid={view.ParentPid} createStatus=0x{createStatus:X8} startKey=0x{view.ProcessStartKey:X} " +
                $"imagePath={view.ImagePath}";

            return new ProcessRelationView { FirstSeenUtc = view.TimestampUtc,
                                             LastSeenUtc = view.TimestampUtc,
                                             SourcePid = source,
                                             TargetPid = target,
                                             RelationType = "ProcessCreate",
                                             LastAccessMask = 0,
                                             LastFlags = view.Flags,
                                             OriginSource = view.Source,
                                             OriginModule = EventDetailFormatting.ModuleNameFromPath(view.ImagePath),
                                             DetailSignature = detailSignature,
                                             DetailText = detailText,
                                             RepeatCount = 1 };
        }

        private HeuristicEventView? MapIoctlHeuristic(IoctlParsedEvent record)
        {
            HeuristicEventView? antiAnalysis = EvaluateAntiAnalysisIoctlHeuristic(record);
            if (antiAnalysis != null)
            {
                return antiAnalysis;
            }

            if (record.Type != BlackbirdNative.EventTypeHandle || record.CallerPid == 0 || record.TargetPid == 0)
            {
                return null;
            }

            if (record.HandleClass != 2)
            {
                return null;
            }

            DateTime now = DateTime.UtcNow;
            bool isThreadObject = (record.HandleFlags & HandleFlagThreadObject) != 0;
            bool highRiskAccess = IsHighRiskIoctlAccess(record.DesiredAccess, isThreadObject);
            bool exportMismatch = (record.HandleFlags & HandleFlagSyscallExportMismatch) != 0;
            bool stackSpoof = (record.HandleFlags & HandleFlagStackSpoofSuspect) != 0;
            bool stackValidated = (record.HandleFlags & HandleFlagStackValidated) != 0;
            bool tebBoundsValid = (record.HandleFlags & HandleFlagTebStackBoundsValid) != 0;
            bool execOutsideNtdll =
                (record.HandleFlags & HandleFlagExecProtect) != 0 && (record.HandleFlags & HandleFlagFromNtdll) == 0;
            uint severity = exportMismatch ? 6u : highRiskAccess ? 5u : (stackSpoof || execOutsideNtdll) ? 4u : 3u;

            string handleFlagsDecoded = EventDetailFormatting.DescribeHandleFlags(record.HandleFlags);
            string corrAccessDecoded = EventDetailFormatting.DescribeHandleAccess(record.DesiredAccess);
            string syscallName =
                EventDetailFormatting.ResolveDirectSyscallApi(record.DesiredAccess, record.HandleFlags);
            string directSyscallDetectionName =
                BuildDirectSyscallDetectionName(record.CallerPid, record.TargetPid, syscallName);
            string syscallSummary = EventDetailFormatting.BuildDirectSyscallSummary(
                record.CallerPid.ToString(CultureInfo.InvariantCulture),
                record.TargetPid.ToString(CultureInfo.InvariantCulture), record.DesiredAccess, record.HandleFlags,
                record.DeepSample, (int)record.DeepSampleSize, record.OriginPath);

            return new HeuristicEventView {
                TimestampUtc = now,
                LastSeenUtc = now,
                Severity = severity,
                DetectionName = directSyscallDetectionName,
                ActorPid = record.CallerPid,
                TargetPid = record.TargetPid,
                Source = "Kernel-IOCTL",
                EventName = "HandleTelemetry",
                CorrelationFlags = 0,
                CorrelationAccessMask = record.DesiredAccess,
                CorrelationAgeMs = 0,
                Reason =
                    $"{syscallSummary}; ioctlClass={record.HandleClass}; directClass=true; highRiskAccess={highRiskAccess}; " +
                    $"exportMismatch={exportMismatch}; stackSpoof={stackSpoof}; stackValidated={stackValidated}; " +
                    $"tebBoundsValid={tebBoundsValid}; execOutsideNtdll={execOutsideNtdll}; " +
                    $"handleFlags={handleFlagsDecoded}; access={corrAccessDecoded}",
                Evidence = BuildHandleEvidenceText(record),
                RepeatCount = 1
            };
        }

        private HeuristicEventView? EvaluateAntiAnalysisIoctlHeuristic(IoctlParsedEvent record)
        {
            DateTime now = DateTime.UtcNow;
            if (record.Type == BlackbirdNative.EventTypeFileSystem)
            {
                if (!ShouldAcceptFilesystemRecord(record))
                {
                    return null;
                }

                uint pid = record.FileProcessPid;
                string path = record.FilePath ?? string.Empty;
                if (!TryMatchVirtualizationArtifact(path, out string artifact))
                {
                    return null;
                }

                string evidence =
                    $"filesystem operation=0x{record.FileOperation:X} pid={pid} tid={record.FileThreadId} artifact={artifact} path={path}";
                return BuildAntiAnalysisFinding(now, pid, pid, "ANTI_VM_FILESYSTEM_ARTIFACT_PROBE", 5,
                                                "Kernel-IOCTL/AntiAnalysis", "FileSystemTelemetry",
                                                $"probed virtualization filesystem artifact {artifact}", evidence);
            }

            if (record.Type == BlackbirdNative.EventTypeRegistry)
            {
                uint pid = record.RegistryProcessPid;
                if (pid == 0 || (!_filterTrackedPids.IsEmpty && !_filterTrackedPids.ContainsKey(pid)))
                {
                    return null;
                }
                if (!IsRegistryProbeOperation(record.RegistryOperation))
                {
                    return null;
                }

                string registryPath = BuildRegistryProbePath(record);
                if (!TryMatchVirtualizationArtifact(registryPath, out string artifact))
                {
                    return null;
                }

                string operation = DescribeRegistryProbeOperation(record.RegistryOperation);
                string evidence =
                    $"registry operation={operation} pid={pid} tid={record.RegistryThreadId} artifact={artifact} path={registryPath}";
                return BuildAntiAnalysisFinding(now, pid, pid, "ANTI_VM_REGISTRY_ARTIFACT_PROBE", 5,
                                                "Kernel-IOCTL/AntiAnalysis", "RegistryTelemetry",
                                                $"queried virtualization registry artifact {artifact}", evidence);
            }

            return null;
        }

        private static string BuildRegistryProbePath(IoctlParsedEvent record)
        {
            string key = record.RegistryKeyPath ?? string.Empty;
            string value = record.RegistryValueName ?? string.Empty;
            if (string.IsNullOrWhiteSpace(value))
            {
                return key;
            }

            return string.IsNullOrWhiteSpace(key) ? value : $"{key}\\{value}";
        }

        private static bool IsRegistryProbeOperation(uint operation)
        {
            return operation is BlackbirdNative.RegistryOperationQueryValue or BlackbirdNative
                .RegistryOperationQueryKey or BlackbirdNative.RegistryOperationEnumerateKey or
                    BlackbirdNative.RegistryOperationEnumerateValue or BlackbirdNative.RegistryOperationOpenKey;
        }

        private static string DescribeRegistryProbeOperation(uint operation)
        {
            return operation switch { BlackbirdNative.RegistryOperationQueryValue => "QUERY_VALUE",
                                      BlackbirdNative.RegistryOperationQueryKey => "QUERY_KEY",
                                      BlackbirdNative.RegistryOperationEnumerateKey => "ENUMERATE_KEY",
                                      BlackbirdNative.RegistryOperationEnumerateValue => "ENUMERATE_VALUE",
                                      BlackbirdNative.RegistryOperationOpenKey => "OPEN_KEY",
                                      _ => $"0x{operation:X}" };
        }

        private static bool TryMatchVirtualizationArtifact(string? text, out string artifact)
        {
            artifact = string.Empty;
            if (string.IsNullOrWhiteSpace(text))
            {
                return false;
            }

            string normalized = text.Replace('/', '\\').Trim();
            for (int i = 0; i < VirtualizationArtifactPatterns.Length; i += 1)
            {
                if (normalized.Contains(VirtualizationArtifactPatterns[i].Token, StringComparison.OrdinalIgnoreCase))
                {
                    artifact = VirtualizationArtifactPatterns[i].Label;
                    return true;
                }
            }

            return false;
        }
    }
}
