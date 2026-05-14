using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Input;
using System.Windows.Threading;

namespace BlackbirdInterface
{
    public partial class MainWindow
    {
        private void TogglePaneOrder()
        {
            _performanceOnTop = !_performanceOnTop;
            ApplyPaneOrder();
        }

        private void ToggleIntelPaneOrder()
        {
            _heuristicsOnTop = !_heuristicsOnTop;
            ApplyIntelPaneOrder();
        }

        private void ApplyPaneOrder()
        {
            if (_performanceOnTop)
            {
                Grid.SetRow(PerformancePaneRow, 0);
                Grid.SetRow(EventsPaneRow, 2);
                PerformancePaneRow.Margin = new Thickness(0, 0, 0, 3);
                EventsPaneRow.Margin = new Thickness(0, 3, 0, 0);
            }
            else
            {
                Grid.SetRow(EventsPaneRow, 0);
                Grid.SetRow(PerformancePaneRow, 2);
                EventsPaneRow.Margin = new Thickness(0, 0, 0, 3);
                PerformancePaneRow.Margin = new Thickness(0, 3, 0, 0);
            }
        }

        private void ApplyIntelPaneOrder()
        {
            if (_heuristicsOnTop)
            {
                Grid.SetRow(HeuristicsDockBorder, 0);
                Grid.SetRow(EtwDockBorder, 2);
                HeuristicsDockBorder.Margin = new Thickness(0, 0, 0, 3);
                EtwDockBorder.Margin = new Thickness(0, 3, 0, 0);
            }
            else
            {
                Grid.SetRow(EtwDockBorder, 0);
                Grid.SetRow(HeuristicsDockBorder, 2);
                EtwDockBorder.Margin = new Thickness(0, 0, 0, 3);
                HeuristicsDockBorder.Margin = new Thickness(0, 3, 0, 0);
            }

            ApplyDockVisibilityFromExplorer();
        }

        private void BeginPaneHeaderDrag(bool isEventsPane, Point screenPosition)
        {
            if (isEventsPane)
            {
                if (_eventsFloatWindow == null)
                    ToggleFloatDock();

                if (_eventsFloatWindow == null)
                    return;

                _draggingEventsPaneHeader = true;
                _draggingPerformancePaneHeader = false;
                _floatingPaneDragOffset =
                    new Vector(screenPosition.X - _eventsFloatWindow.Left, screenPosition.Y - _eventsFloatWindow.Top);
            }
            else
            {
                if (_performanceFloatWindow == null)
                    TogglePerformanceFloatDock();

                if (_performanceFloatWindow == null)
                    return;

                _draggingPerformancePaneHeader = true;
                _draggingEventsPaneHeader = false;
                _floatingPaneDragOffset = new Vector(screenPosition.X - _performanceFloatWindow.Left,
                                                     screenPosition.Y - _performanceFloatWindow.Top);
            }

            ContinuePaneHeaderDrag(isEventsPane, screenPosition);
        }

        private void ContinuePaneHeaderDrag(bool isEventsPane, Point screenPosition)
        {
            if (isEventsPane && !_draggingEventsPaneHeader)
                return;
            if (!isEventsPane && !_draggingPerformancePaneHeader)
                return;

            var floatingWindow = isEventsPane ? (Window ?) _eventsFloatWindow: _performanceFloatWindow;
            if (floatingWindow == null)
                return;

            floatingWindow.Left = screenPosition.X - _floatingPaneDragOffset.X;
            floatingWindow.Top = screenPosition.Y - _floatingPaneDragOffset.Y;
            UpdateDockPreview(screenPosition);
        }

        private void EndPaneHeaderDrag(bool isEventsPane, Point screenPosition)
        {
            if (isEventsPane)
                _draggingEventsPaneHeader = false;
            else
                _draggingPerformancePaneHeader = false;

            var slot = GetDockDropSlot(screenPosition);
            HideDockPreview();

            if (slot == DockDropSlot.None)
                return;

            if (isEventsPane)
            {
                _eventsFloatWindow?.Close();
                _performanceOnTop = slot == DockDropSlot.Bottom;
            }
            else
            {
                _performanceFloatWindow?.Close();
                _performanceOnTop = slot == DockDropSlot.Top;
            }

            ApplyPaneOrder();
        }

        private DockDropSlot GetDockDropSlot(Point screenPosition)
        {
            if (DockGrid.ActualWidth < 8 || DockGrid.ActualHeight < 8)
                return DockDropSlot.None;

            var dockTopLeft = DockGrid.PointToScreen(new Point(0, 0));
            var dockRect = new Rect(dockTopLeft, new Size(DockGrid.ActualWidth, DockGrid.ActualHeight));
            if (!dockRect.Contains(screenPosition))
                return DockDropSlot.None;

            double relativeY = screenPosition.Y - dockRect.Top;
            return relativeY <= dockRect.Height * 0.5 ? DockDropSlot.Top : DockDropSlot.Bottom;
        }

        private void UpdateDockPreview(Point screenPosition)
        {
            var slot = GetDockDropSlot(screenPosition);
            DockPreviewTop.Visibility = slot == DockDropSlot.Top ? Visibility.Visible : Visibility.Collapsed;
            DockPreviewBottom.Visibility = slot == DockDropSlot.Bottom ? Visibility.Visible : Visibility.Collapsed;
        }

        private void HideDockPreview()
        {
            DockPreviewTop.Visibility = Visibility.Collapsed;
            DockPreviewBottom.Visibility = Visibility.Collapsed;
        }

        private enum DockDropSlot
        {
            None,
            Top,
            Bottom
        }

        private readonly struct EventSelectionKey : IEquatable<EventSelectionKey>
        {
            public EventSelectionKey(TelemetryEvent ev)
            {
                TimestampUtc = ev.TimestampUtc;
                Pid = ev.PID;
                Tid = ev.TID;
                Group = ev.Group ?? string.Empty;
                SubType = ev.SubType ?? string.Empty;
                Summary = ev.Summary ?? string.Empty;
                Details = ev.Details ?? string.Empty;
            }

            private DateTime TimestampUtc { get; }
            private int Pid { get; }
            private int Tid { get; }
            private string Group { get; }
            private string SubType { get; }
            private string Summary { get; }
            private string Details { get; }

            public bool Matches(TelemetryEvent ev)
            {
                return ev.TimestampUtc == TimestampUtc && ev.PID == Pid && ev.TID == Tid &&
                       string.Equals(ev.Group ?? string.Empty, Group, StringComparison.OrdinalIgnoreCase) &&
                       string.Equals(ev.SubType ?? string.Empty, SubType, StringComparison.OrdinalIgnoreCase) &&
                       string.Equals(ev.Summary ?? string.Empty, Summary, StringComparison.Ordinal) &&
                       string.Equals(ev.Details ?? string.Empty, Details, StringComparison.Ordinal);
            }

            public bool Equals(EventSelectionKey other)
            {
                return TimestampUtc == other.TimestampUtc && Pid == other.Pid && Tid == other.Tid &&
                       string.Equals(Group, other.Group, StringComparison.OrdinalIgnoreCase) &&
                       string.Equals(SubType, other.SubType, StringComparison.OrdinalIgnoreCase) &&
                       string.Equals(Summary, other.Summary, StringComparison.Ordinal) &&
                       string.Equals(Details, other.Details, StringComparison.Ordinal);
            }

            public override bool Equals(object? obj) => obj is EventSelectionKey other && Equals(other);

            public override int GetHashCode()
            {
                HashCode hash = new();
                hash.Add(TimestampUtc);
                hash.Add(Pid);
                hash.Add(Tid);
                hash.Add(Group, StringComparer.OrdinalIgnoreCase);
                hash.Add(SubType, StringComparer.OrdinalIgnoreCase);
                hash.Add(Summary, StringComparer.Ordinal);
                hash.Add(Details, StringComparer.Ordinal);
                return hash.ToHashCode();
            }
        }

        private static TelemetryEvent CloneTelemetryEvent(TelemetryEvent src)
        {
            return new TelemetryEvent { TimestampUtc = src.TimestampUtc,
                                        PID = src.PID,
                                        TID = src.TID,
                                        Group = src.Group,
                                        SubType = src.SubType,
                                        ProcessName = src.ProcessName,
                                        Summary = src.Summary,
                                        Details = src.Details };
        }

        private static PerformanceSample ClonePerformanceSample(PerformanceSample src)
        {
            return new PerformanceSample {
                TimestampUtc = src.TimestampUtc,
                CoreCount = src.CoreCount,
                CpuPercent = src.CpuPercent,
                CoresUsedPercent = src.CoresUsedPercent,
                DiskReadBytesPerSec = src.DiskReadBytesPerSec,
                DiskWriteBytesPerSec = src.DiskWriteBytesPerSec,
                PrivateBytes = src.PrivateBytes,
                ReservedBytes = src.ReservedBytes,
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
                                                                      WorkingSetLargePage = m.WorkingSetLargePage })
                                  .ToList()
            };
        }

        private static ThreadLifecycleEventSample CloneThreadLifecycleEvent(ThreadLifecycleEventSample src)
        {
            return new ThreadLifecycleEventSample { TimestampUtc = src.TimestampUtc,
                                                    ProcessPid = src.ProcessPid,
                                                    ThreadId = src.ThreadId,
                                                    CreatorPid = src.CreatorPid,
                                                    Flags = src.Flags,
                                                    StartAddress = src.StartAddress,
                                                    ImageBase = src.ImageBase,
                                                    ImageSize = src.ImageSize,
                                                    EventKind = src.EventKind,
                                                    Notes = src.Notes };
        }

        private static MemoryRegionAttributionSample
        CloneMemoryRegionAttributionSample(MemoryRegionAttributionSample src)
        {
            return new MemoryRegionAttributionSample { TimestampUtc = src.TimestampUtc,
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
        }

        private sealed class ApiCallGraphMainRowView
        {
            public string GraphKey { get; set; } = string.Empty;
            public string ThreadGroupKey { get; set; } = string.Empty;
            public string ViewModeKey { get; set; } = "call";
            public string ApiName { get; set; } = string.Empty;
            public string OriginModule { get; set; } = string.Empty;
            public string ActionLabel { get; set; } = string.Empty;
            public string SensorLabel { get; set; } = string.Empty;
            public string CallerOriginKey { get; set; } = string.Empty;
            public string CallerOriginLabel { get; set; } = string.Empty;
            public string CallChainLabel { get; set; } = string.Empty;
            public Brush? CallerOriginBackground { get; set; }
            public Brush? CallerOriginForeground { get; set; }
            public Brush? SensorBackground { get; set; }
            public Brush? SensorForeground { get; set; }
            public Brush? HeatTrackBackground { get; set; }
            public Brush? HeatFillBackground { get; set; }
            public Brush? RowBackground { get; set; }
            public Brush? RowBorderBrush { get; set; }
            public string SourceLabel { get; set; } = string.Empty;
            public string TargetLabel { get; set; } = string.Empty;
            public string ThreadLabel { get; set; } = string.Empty;
            public string Field1Label { get; set; } = "Base";
            public string Field2Label { get; set; } = "Size";
            public string Field3Label { get; set; } = "Alloc Type";
            public string Field4Label { get; set; } = "Protect";
            public string BaseLabel { get; set; } = string.Empty;
            public string SizeLabel { get; set; } = string.Empty;
            public string AllocTypeLabel { get; set; } = string.Empty;
            public string ProtectLabel { get; set; } = string.Empty;
            public string LastSeen { get; set; } = string.Empty;
            public string AbsoluteLastSeen { get; set; } = string.Empty;
            public string FirstSeen { get; set; } = string.Empty;
            public string AbsoluteFirstSeen { get; set; } = string.Empty;
            public DateTime FirstSeenUtc { get; set; }
            public DateTime LastSeenUtc { get; set; }
            public int Hits { get; set; }
            public double HeatPercent { get; set; }
            public double ActivityFillWidth { get; set; }
            public string DetailFull { get; set; } = string.Empty;
            public List<string> RawGraphKeys { get; set; } = new();
            public List<ApiThreadDetailRowView> ThreadDetails { get; set; } = new();
            public bool HasThreadDetails => ThreadDetails.Count > 0;
            public Visibility ThreadDetailsVisibility => HasThreadDetails ? Visibility.Visible : Visibility.Collapsed;
            public string ThreadSummary =>
                HasThreadDetails ? $"{ThreadDetails.Count} threads / {Hits} hits" : string.Empty;
        }

        private sealed class ApiThreadDetailRowView
        {
            public string ThreadLabel { get; set; } = string.Empty;
            public string SourceLabel { get; set; } = string.Empty;
            public string TargetLabel { get; set; } = string.Empty;
            public string ArgumentSummary { get; set; } = string.Empty;
            public int Hits { get; set; }
            public string LastSeen { get; set; } = string.Empty;
        }

        public void SetLaneFocus(string? laneKey)
        {
            _laneFocusKey = string.IsNullOrWhiteSpace(laneKey) ? null : laneKey;
            FocusViewport();
        }

        public string? GetLaneFocus() => _laneFocusKey;
    }
}
