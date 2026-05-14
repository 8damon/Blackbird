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
        private void SaveIntelSessionState(int pid)
        {
            if (pid <= 0)
            {
                return;
            }

            _etwHistoryByPid[pid] = EtwPaneHost.SnapshotItems().Select(x => x.Clone()).ToList();
            _heuristicsHistoryByPid[pid] = HeuristicsPaneHost.SnapshotItems().Select(x => x.Clone()).ToList();
            _filesystemHistoryByPid[pid] = FilesystemPaneHost.SnapshotItems().Select(x => x.Clone()).ToList();
            _registryHistoryByPid[pid] = RegistryPaneHost.SnapshotItems().Select(x => x.Clone()).ToList();
            _relationsHistoryByPid[pid] = ProcessRelationsPaneHost.SnapshotItems().Select(x => x.Clone()).ToList();
            _apiGraphHistoryByPid[pid] = _apiGraphRowsByKey.Values.Select(static x => x.Clone()).ToList();
            _extendedHistoryByPid[pid] = _extendedRowsByKey.Values.Select(static x => x.Clone()).ToList();
        }

        private void RestoreIntelSessionState(int pid)
        {
            IEnumerable<GroupedEventRow> etw =
                _etwHistoryByPid.TryGetValue(pid, out var a) ? a : Array.Empty<GroupedEventRow>();
            IEnumerable<GroupedEventRow> heur =
                _heuristicsHistoryByPid.TryGetValue(pid, out var c) ? c : Array.Empty<GroupedEventRow>();
            IEnumerable<GroupedEventRow> fs =
                _filesystemHistoryByPid.TryGetValue(pid, out var d) ? d : Array.Empty<GroupedEventRow>();
            IEnumerable<GroupedEventRow> reg =
                _registryHistoryByPid.TryGetValue(pid, out var dr) ? dr : Array.Empty<GroupedEventRow>();
            IEnumerable<GroupedEventRow> rel =
                _relationsHistoryByPid.TryGetValue(pid, out var e) ? e : Array.Empty<GroupedEventRow>();
            IEnumerable<ApiCallGraphRowSnapshot> apiGraph =
                _apiGraphHistoryByPid.TryGetValue(pid, out var f) ? f : Array.Empty<ApiCallGraphRowSnapshot>();
            IEnumerable<ExtendedActivityRowSnapshot> extended =
                _extendedHistoryByPid.TryGetValue(pid, out var g) ? g : Array.Empty<ExtendedActivityRowSnapshot>();

            EtwPaneHost.LoadHistory(etw.Select(x => x.Clone()).ToList());
            HeuristicsPaneHost.LoadHistory(heur.Select(x => x.Clone()).ToList());
            FilesystemPaneHost.LoadHistory(fs.Select(x => x.Clone()).ToList());
            RegistryPaneHost.LoadHistory(reg.Select(x => x.Clone()).ToList());
            ProcessRelationsPaneHost.SetRootPid(pid);
            ProcessRelationsPaneHost.LoadHistory(rel.Select(x => x.Clone()).ToList());
            _apiGraphRowsByKey.Clear();
            _extendedRowsByKey.Clear();
            _extendedCapabilityRows.Clear();
            _apiGraphReasonByKey.Clear();
            _apiGraphActionByKey.Clear();
            _apiGraphDecodedByKey.Clear();
            _apiGraphFramesByKey.Clear();
            _apiGraphSensorByKey.Clear();
            _apiGraphTimelineLastEmitByKey.Clear();
            _observedHookStackLastPersistByThread.Clear();
            _threadStackFallbackLastCaptureByThread.Clear();
            _pendingThreadStackFallbackCaptures.Clear();
            _apiMemorySignalsByPage.Clear();
            _crossProcWriteCountByPair.Clear();
            _crossProcRwxAllocCountByPair.Clear();
            _antiAnalysisCountByEvidence.Clear();
            ResetImageMapCorrelationCaches();
            _extendedViewRows.Clear();
            foreach (ApiCallGraphRowSnapshot row in apiGraph)
            {
                string sensorOrigin = string.IsNullOrWhiteSpace(row.SensorOrigin) ? "Unclassified" : row.SensorOrigin;
                string callerOrigin = NormalizeApiCallerOrigin(row.CallerOrigin);
                string originModule = NormalizeApiOriginModule(row.OriginModule);
                string key = BuildApiGraphKey(row.SourcePid, row.TargetPid, row.ThreadId, row.ApiName, sensorOrigin,
                                              callerOrigin, originModule);
                _apiGraphRowsByKey[key] = row.Clone();
                _apiGraphSensorByKey[key] = sensorOrigin;
            }
            foreach (ExtendedActivityRowSnapshot row in extended)
            {
                string key = BuildExtendedActivityKey(row.TypeLabel, row.ActorLabel, row.TargetLabel, row.SubjectLabel,
                                                      row.OperationLabel);
                _extendedRowsByKey[key] = row.Clone();
            }
            PublishApiGraphSnapshot();
            PublishExtendedActivitySnapshot();
            if (EtwPaneHost.ItemCount > 0)
            {
                FindExplorerItem("ETW")?.PushPreviewValue(EtwPaneHost.TotalRawCount);
            }
            if (HeuristicsPaneHost.ItemCount > 0)
            {
                FindExplorerItem("Heuristics")?.PushPreviewValue(HeuristicsPaneHost.TotalRawCount);
            }
            if (FilesystemPaneHost.ItemCount > 0)
            {
                FindExplorerItem("Filesystem")?.PushPreviewValue(FilesystemPaneHost.TotalRawCount);
            }
            if (RegistryPaneHost.ItemCount > 0)
            {
                FindExplorerItem("Registry")?.PushPreviewValue(RegistryPaneHost.TotalRawCount);
            }
            if (ProcessRelationsPaneHost.ItemCount > 0)
            {
                FindExplorerItem("Process Relations")?.PushPreviewValue(ProcessRelationsPaneHost.TotalRawCount);
            }
            RefreshExplorerDataBadges();
        }

        private static System.Windows.Media.Brush BuildApiSensorBackground(string sensor)
        {
            return sensor.StartsWith("Kernel", StringComparison.OrdinalIgnoreCase)
                       ? new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0x45, 0x1A, 0x1A))
                   : sensor.StartsWith("Usermode", StringComparison.OrdinalIgnoreCase)
                       ? new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0x12, 0x2D, 0x4A))
                       : new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0x24, 0x24, 0x24));
        }

        private static System.Windows.Media.Brush BuildApiSensorForeground(string sensor)
        {
            return sensor.StartsWith("Kernel", StringComparison.OrdinalIgnoreCase)
                       ? new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0xFF, 0xC7, 0xC7))
                   : sensor.StartsWith("Usermode", StringComparison.OrdinalIgnoreCase)
                       ? new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0xB9, 0xE3, 0xFF))
                       : new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0xD0, 0xD0, 0xD0));
        }

        private static System.Windows.Media.Brush BuildApiHeatTrackBackground(string sensor, string callerOrigin)
        {
            callerOrigin = NormalizeApiCallerOrigin(callerOrigin);
            return callerOrigin switch {
                "process-image" =>
                    new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0x0F, 0x31, 0x2C)),
                "non-system-dll" =>
                    new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0x38, 0x28, 0x10)),
                "unbacked" =>
                    new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0x3E, 0x10, 0x22)),
                "system" =>
                    new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0x23, 0x28, 0x31)),
                _ =>
                    sensor.StartsWith("Kernel", StringComparison.OrdinalIgnoreCase)
                        ? new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0x3A, 0x18, 0x18))
                    : sensor.StartsWith("Usermode", StringComparison.OrdinalIgnoreCase)
                        ? new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0x13, 0x27, 0x3D))
                        : new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0x21, 0x26, 0x2D))
            };
        }

        private static System.Windows.Media.Brush BuildApiHeatFillBackground(string sensor, string callerOrigin)
        {
            callerOrigin = NormalizeApiCallerOrigin(callerOrigin);
            return callerOrigin switch {
                "process-image" =>
                    new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0x4D, 0xBF, 0xA9)),
                "non-system-dll" =>
                    new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0xD8, 0xA1, 0x45)),
                "unbacked" =>
                    new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0xD1, 0x4E, 0x75)),
                "system" =>
                    new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0x6C, 0x78, 0x88)),
                _ =>
                    sensor.StartsWith("Kernel", StringComparison.OrdinalIgnoreCase)
                        ? new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0xB2, 0x4A, 0x4A))
                    : sensor.StartsWith("Usermode", StringComparison.OrdinalIgnoreCase)
                        ? new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0x3E, 0x84, 0xC6))
                        : new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0x5C, 0x66, 0x73))
            };
        }

        private static System.Windows.Media.Brush BuildApiRowBackground(string sensor, string callerOrigin)
        {
            callerOrigin = NormalizeApiCallerOrigin(callerOrigin);
            return callerOrigin switch { "process-image" => new System.Windows.Media.SolidColorBrush(
                                             System.Windows.Media.Color.FromArgb(0x4A, 0x0E, 0x58, 0x4D)),
                                         "non-system-dll" => new System.Windows.Media.SolidColorBrush(
                                             System.Windows.Media.Color.FromArgb(0x4A, 0x66, 0x43, 0x0D)),
                                         "unbacked" => new System.Windows.Media.SolidColorBrush(
                                             System.Windows.Media.Color.FromArgb(0x52, 0x71, 0x18, 0x33)),
                                         "system" => new System.Windows.Media.SolidColorBrush(
                                             System.Windows.Media.Color.FromArgb(0x30, 0x35, 0x3C, 0x45)),
                                         _ => sensor.StartsWith("Kernel", StringComparison.OrdinalIgnoreCase)
                                                  ? new System.Windows.Media.SolidColorBrush(
                                                        System.Windows.Media.Color.FromArgb(0x44, 0x6E, 0x1D, 0x1D))
                                              : sensor.StartsWith("Usermode", StringComparison.OrdinalIgnoreCase)
                                                  ? new System.Windows.Media.SolidColorBrush(
                                                        System.Windows.Media.Color.FromArgb(0x44, 0x16, 0x39, 0x59))
                                                  : new System.Windows.Media.SolidColorBrush(
                                                        System.Windows.Media.Color.FromArgb(0x22, 0x36, 0x36, 0x36)) };
        }

        private static System.Windows.Media.Brush BuildApiRowBorder(string sensor, string callerOrigin)
        {
            _ = sensor;
            callerOrigin = NormalizeApiCallerOrigin(callerOrigin);
            return callerOrigin switch {
                "process-image" =>
                    new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0x64, 0xD9, 0xC1)),
                "non-system-dll" =>
                    new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0xE2, 0xB0, 0x5E)),
                "unbacked" =>
                    new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0xE0, 0x65, 0x8D)),
                "system" =>
                    new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0x6F, 0x7C, 0x8A)),
                _ => new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0x44, 0x4C, 0x56))
            };
        }

        private static System.Windows.Media.Brush BuildApiGraphEdgeBrush(string sensor, string callerOrigin,
                                                                         double heat)
        {
            heat = Math.Clamp(heat, 0.0, 1.0);
            callerOrigin = NormalizeApiCallerOrigin(callerOrigin);
            if (callerOrigin == "process-image")
            {
                byte red = (byte)Math.Clamp(62 + (int)Math.Round(28 * heat), 0, 255);
                byte green = (byte)Math.Clamp(176 + (int)Math.Round(48 * heat), 0, 255);
                byte blue = (byte)Math.Clamp(152 + (int)Math.Round(40 * heat), 0, 255);
                return new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(red, green, blue));
            }

            if (callerOrigin == "non-system-dll")
            {
                byte red = (byte)Math.Clamp(180 + (int)Math.Round(48 * heat), 0, 255);
                byte green = (byte)Math.Clamp(128 + (int)Math.Round(40 * heat), 0, 255);
                byte blue = (byte)Math.Clamp(52 + (int)Math.Round(18 * heat), 0, 255);
                return new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(red, green, blue));
            }

            if (callerOrigin == "unbacked")
            {
                byte red = (byte)Math.Clamp(194 + (int)Math.Round(38 * heat), 0, 255);
                byte green = (byte)Math.Clamp(68 + (int)Math.Round(22 * heat), 0, 255);
                byte blue = (byte)Math.Clamp(112 + (int)Math.Round(32 * heat), 0, 255);
                return new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(red, green, blue));
            }

            if (callerOrigin == "system")
            {
                byte shade = (byte)Math.Clamp(118 + (int)Math.Round(52 * heat), 0, 255);
                return new System.Windows.Media.SolidColorBrush(
                    System.Windows.Media.Color.FromRgb(shade, shade, (byte)Math.Clamp(shade + 8, 0, 255)));
            }

            if (sensor.StartsWith("Kernel", StringComparison.OrdinalIgnoreCase))
            {
                byte red = (byte)Math.Clamp(150 + (int)Math.Round(80 * heat), 0, 255);
                byte green = (byte)Math.Clamp(65 + (int)Math.Round(25 * heat), 0, 255);
                byte blue = (byte)Math.Clamp(65 + (int)Math.Round(25 * heat), 0, 255);
                return new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(red, green, blue));
            }

            if (sensor.StartsWith("Usermode", StringComparison.OrdinalIgnoreCase))
            {
                byte red = (byte)Math.Clamp(70 + (int)Math.Round(25 * heat), 0, 255);
                byte green = (byte)Math.Clamp(125 + (int)Math.Round(45 * heat), 0, 255);
                byte blue = (byte)Math.Clamp(178 + (int)Math.Round(50 * heat), 0, 255);
                return new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(red, green, blue));
            }

            byte neutralShade = (byte)Math.Clamp(110 + (int)Math.Round(70 * heat), 0, 255);
            return new System.Windows.Media.SolidColorBrush(
                System.Windows.Media.Color.FromRgb(neutralShade, neutralShade, neutralShade));
        }

        private static System.Windows.Media.Brush BuildApiCallerOriginBackground(string callerOrigin)
        {
            return NormalizeApiCallerOrigin(callerOrigin) switch {
                "process-image" =>
                    new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0x14, 0x42, 0x39)),
                "non-system-dll" =>
                    new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0x4D, 0x34, 0x12)),
                "unbacked" =>
                    new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0x56, 0x16, 0x2D)),
                "system" =>
                    new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0x2C, 0x33, 0x3B)),
                _ => new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0x26, 0x26, 0x26))
            };
        }

        private static System.Windows.Media.Brush BuildApiCallerOriginForeground(string callerOrigin)
        {
            return NormalizeApiCallerOrigin(callerOrigin) switch {
                "process-image" =>
                    new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0xC0, 0xFF, 0xEE)),
                "non-system-dll" =>
                    new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0xFF, 0xE1, 0xB0)),
                "unbacked" =>
                    new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0xFF, 0xC2, 0xD4)),
                "system" =>
                    new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0xD2, 0xDA, 0xE2)),
                _ => new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0xD8, 0xD8, 0xD8))
            };
        }
    }
}
