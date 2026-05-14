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
using System.Windows.Shapes;

namespace BlackbirdInterface
{
    public partial class MainWindow
    {
        private bool ShouldTrackRawIoctlRecord(IoctlParsedEvent record)
        {
            return record.Type switch { BlackbirdNative.EventTypeHandle => ShouldTrackRawHandleIoctl(record),
                                        BlackbirdNative.EventTypeThread => ShouldTrackRawThreadIoctl(record),
                                        BlackbirdNative.EventTypeFileSystem =>
                                            record.FileProcessPid == 0 || IsTrackedPid(record.FileProcessPid),
                                        BlackbirdNative.EventTypeRegistry =>
                                            record.RegistryProcessPid == 0 || IsTrackedPid(record.RegistryProcessPid),
                                        _ => false };
        }

        private bool ShouldTrackRawHandleIoctl(IoctlParsedEvent record)
        {
            if (record.CallerPid == 0 || record.TargetPid == 0)
            {
                return false;
            }

            if (!IsTrackedPid(record.CallerPid))
            {
                return false;
            }

            string originModule = EventDetailFormatting.ModuleNameFromPath(record.OriginPath);
            return !EventDetailFormatting.IsSr71Module(originModule);
        }

        private bool ShouldTrackRawThreadIoctl(IoctlParsedEvent record)
        {
            if (record.ProcessPid == 0)
            {
                return false;
            }

            if (record.CreatorPid != 0 && record.CreatorPid != record.ProcessPid && !IsTrackedPid(record.CreatorPid))
            {
                return false;
            }

            return true;
        }

        private static bool ShouldAdmitIoctlRecord(IoctlParsedEvent record, long pendingCount)
        {
            if (pendingCount >= MaxPendingIoctlEvents)
            {
                return false;
            }

            if (pendingCount < IoctlPressureSoftLimit)
            {
                return true;
            }

            return pendingCount >= IoctlPressureCriticalLimit ? IsCriticalIoctlRecord(record)
                                                              : IsImportantIoctlRecord(record);
        }

        private static bool IsImportantIoctlRecord(IoctlParsedEvent record)
        {
            return record.Type switch { BlackbirdNative.EventTypeHandle => IsImportantHandleIoctl(record),
                                        BlackbirdNative.EventTypeThread => IsImportantThreadIoctl(record),
                                        BlackbirdNative.EventTypeFileSystem => IsImportantFilesystemIoctl(record),
                                        _ => false };
        }

        private static bool IsCriticalIoctlRecord(IoctlParsedEvent record)
        {
            return record.Type switch { BlackbirdNative.EventTypeHandle => IsCriticalHandleIoctl(record),
                                        BlackbirdNative.EventTypeThread => IsCriticalThreadIoctl(record),
                                        BlackbirdNative.EventTypeFileSystem => IsCriticalFilesystemIoctl(record),
                                        _ => false };
        }

        private static bool IsImportantHandleIoctl(IoctlParsedEvent record)
        {
            bool isThreadObject = (record.HandleFlags & 0x00000010u) != 0;
            return record.HandleClass == 2 || (record.HandleFlags & (HighSignalHandleMask | 0x00000080u)) != 0 ||
                   IsHighRiskIoctlAccess(record.DesiredAccess, isThreadObject);
        }

        private static bool IsCriticalHandleIoctl(IoctlParsedEvent record)
        {
            bool isThreadObject = (record.HandleFlags & 0x00000010u) != 0;
            return record.HandleClass == 2 || (record.HandleFlags & HighSignalHandleMask) != 0 ||
                   ((record.HandleFlags & 0x00000080u) != 0 &&
                    IsHighRiskIoctlAccess(record.DesiredAccess, isThreadObject));
        }

        private static bool IsImportantThreadIoctl(IoctlParsedEvent record)
        {
            string kind = DetermineThreadLifecycleKind(record.ThreadFlags, record.StartAddress, record.ImageSize);
            return kind != "Update" || (record.ThreadFlags & ThreadHighSignalMask) != 0 ||
                   (record.CreatorPid != 0 && record.ProcessPid != 0 && record.CreatorPid != record.ProcessPid);
        }

        private static bool IsCriticalThreadIoctl(IoctlParsedEvent record)
        {
            return (record.ThreadFlags & ThreadHighSignalMask) != 0 ||
                   (record.CreatorPid != 0 && record.ProcessPid != 0 && record.CreatorPid != record.ProcessPid);
        }

        private static bool IsImportantFilesystemIoctl(IoctlParsedEvent record)
        {
            return record.FileOperation switch {
                BlackbirdNative.FileOperationCreate or BlackbirdNative.FileOperationWrite or
                    BlackbirdNative.FileOperationSetInformation or
                        BlackbirdNative.FileOperationDirectoryControl or BlackbirdNative.FileOperationFsControl => true,
                _ => record.FileStatus != 0
            };
        }

        private static bool IsCriticalFilesystemIoctl(IoctlParsedEvent record)
        {
            return record.FileOperation switch {
                BlackbirdNative.FileOperationCreate or BlackbirdNative.FileOperationWrite or
                    BlackbirdNative.FileOperationSetInformation or BlackbirdNative.FileOperationFsControl => true,
                _ => record.FileStatus != 0
            };
        }

        private static bool ShouldPersistIoctlRecord(IoctlParsedEvent record, TelemetryEvent? telemetry,
                                                     ProcessRelationView? relation, HeuristicEventView? heuristic,
                                                     IoctlParsedEvent? filesystem)
        {
            if (filesystem != null || heuristic != null || relation != null)
            {
                return true;
            }

            if (telemetry == null)
            {
                return false;
            }

            return record.Type switch { BlackbirdNative.EventTypeHandle => IsImportantHandleIoctl(record),
                                        BlackbirdNative.EventTypeThread => IsImportantThreadIoctl(record),
                                        _ => false };
        }

        private bool IsTrackedPid(uint pid)
        {
            return pid == 0 || _filterTrackedPids.IsEmpty || _filterTrackedPids.ContainsKey(pid);
        }

        private static bool ShouldTrackRawEtwEvent(BlackbirdNative.BkIpcEtwEvent etw)
        {
            byte[] detectionName = etw.DetectionName ?? Array.Empty<byte>();
            if (detectionName.Length > 0 && detectionName[0] != 0)
            {
                return true;
            }

            if (IsRawDirectSyscallEtwEvent(etw))
            {
                return true;
            }

            if (etw.Family == BlackbirdNative.IpcEtwFamilyImage &&
                ProcessCapabilityCatalog.HasCapabilityModule(BlackbirdNative.WideBufferToString(etw.ImagePath)))
            {
                return true;
            }

            if (etw.Severity >= 4)
            {
                return true;
            }

            if (etw.Source == BlackbirdNative.IpcEtwSourceThreatIntel)
            {
                return etw.Task == 1 || etw.Task == 2 || etw.Task == 7;
            }

            return etw.Family switch {
                BlackbirdNative.IpcEtwFamilyProcess => (etw.Flags & BlackbirdNative.IpcEtwFlagProcessIsCreate) != 0,
                BlackbirdNative.IpcEtwFamilyThread or BlackbirdNative.IpcEtwFamilyApc or
                    BlackbirdNative.IpcEtwFamilyUserHook or BlackbirdNative.IpcEtwFamilySocket => true,
                BlackbirdNative.IpcEtwFamilyRegistry => (etw.Flags & BlackbirdNative.IpcEtwFlagRegistryHighValue) != 0,
                _ => false
            };
        }

        private static bool IsRawDirectSyscallEtwEvent(BlackbirdNative.BkIpcEtwEvent etw)
        {
            if ((etw.DetectionTraits & BlackbirdNative.IpcEtwTraitDirectSyscall) != 0)
            {
                return true;
            }

            if (etw.Family != BlackbirdNative.IpcEtwFamilyHandle)
            {
                return false;
            }

            string className = BlackbirdNative.AnsiBufferToString(etw.ClassName);
            if (className.Equals("DIRECT-SYSCALL-SUSPECT", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            bool exportMismatch = (etw.Flags & HandleFlagSyscallExportMismatch) != 0;
            bool stackSpoof = (etw.Flags & HandleFlagStackSpoofSuspect) != 0;
            bool execOutsideNtdll = (etw.Flags & HandleFlagExecProtect) != 0 && (etw.Flags & HandleFlagFromNtdll) == 0;
            return exportMismatch || stackSpoof || execOutsideNtdll;
        }

        private static bool ShouldAdmitEtwEvent(BlackbirdNative.BkIpcEtwEvent etw, long pendingCount)
        {
            byte[] detectionName = etw.DetectionName ?? Array.Empty<byte>();

            if (pendingCount >= MaxPendingEtwEvents)
            {
                return false;
            }

            if (pendingCount < EtwPressureSoftLimit)
            {
                return true;
            }

            bool critical = (detectionName.Length > 0 && detectionName[0] != 0) || etw.Severity >= 6 ||
                            IsRawDirectSyscallEtwEvent(etw) ||
                            (etw.Family == BlackbirdNative.IpcEtwFamilyProcess &&
                             (etw.Flags & BlackbirdNative.IpcEtwFlagProcessIsCreate) != 0) ||
                            etw.Family == BlackbirdNative.IpcEtwFamilyUserHook;

            if (pendingCount >= EtwPressureCriticalLimit)
            {
                return critical;
            }

            return critical || etw.Family == BlackbirdNative.IpcEtwFamilyThread ||
                   etw.Family == BlackbirdNative.IpcEtwFamilyApc ||
                   etw.Source == BlackbirdNative.IpcEtwSourceThreatIntel;
        }
    }
}
