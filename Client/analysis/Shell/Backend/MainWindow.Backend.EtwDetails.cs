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
        private void EnsureEtwDisplayDetails(BrokerEtwEventView view)
        {
            if (!string.IsNullOrWhiteSpace(view.DisplayDetails))
            {
                return;
            }

            view.DisplayDetails = BuildEtwDisplayDetail(view);
        }

        private List<ApiCallGraphMainRowView> ApplyApiViewFilters(IEnumerable<ApiCallGraphMainRowView> rows)
        {
            string callFilter = (ApiFilterCallBox?.Text ?? string.Empty).Trim();
            string actionFilter = (ApiFilterActionBox?.Text ?? string.Empty).Trim();
            string sensorFilter =
                ((ApiFilterSensorBox?.SelectedItem as ComboBoxItem)?.Content as string ?? "All Sensors").Trim();
            string originFilter =
                ((ApiFilterOriginBox?.SelectedItem as ComboBoxItem)?.Content as string ?? "All Origins").Trim();
            string callerFilter = (ApiFilterCallerBox?.Text ?? string.Empty).Trim();
            string targetFilter = (ApiFilterTargetBox?.Text ?? string.Empty).Trim();
            string threadFilter = (ApiFilterThreadBox?.Text ?? string.Empty).Trim();
            string regionFilter = (ApiFilterRegionBox?.Text ?? string.Empty).Trim();
            string protectFilter = (ApiFilterProtectBox?.Text ?? string.Empty).Trim();
            string minHitsFilter = (ApiFilterMinHitsBox?.Text ?? string.Empty).Trim();
            int minHits = 0;
            _ = int.TryParse(minHitsFilter, NumberStyles.Integer, CultureInfo.InvariantCulture, out minHits);

            bool Matches(string candidate, string filter) =>
                string.IsNullOrWhiteSpace(filter) || (!string.IsNullOrWhiteSpace(candidate) &&
                                                      candidate.Contains(filter, StringComparison.OrdinalIgnoreCase));

            bool MatchesSensor(string candidate) =>
                string.IsNullOrWhiteSpace(sensorFilter) ||
                sensorFilter.Equals("All Sensors", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(candidate, sensorFilter, StringComparison.OrdinalIgnoreCase);

            bool MatchesOrigin(string candidate) =>
                string.IsNullOrWhiteSpace(originFilter) ||
                originFilter.Equals("All Origins", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(candidate, originFilter, StringComparison.OrdinalIgnoreCase);

            bool MatchesThreadDetails(ApiCallGraphMainRowView row, string filter) =>
                string.IsNullOrWhiteSpace(filter) ||
                row.ThreadDetails.Any(x => Matches(x.ThreadLabel, filter) || Matches(x.ArgumentSummary, filter) ||
                                           Matches(x.SourceLabel, filter) || Matches(x.TargetLabel, filter));

            return rows
                .Where(row => Matches(row.ApiName, callFilter) && Matches(row.ActionLabel, actionFilter) &&
                              MatchesSensor(row.SensorLabel) && MatchesOrigin(row.CallerOriginLabel) &&
                              Matches(row.SourceLabel, callerFilter) && Matches(row.TargetLabel, targetFilter) &&
                              (Matches(row.ThreadLabel, threadFilter) || MatchesThreadDetails(row, threadFilter)) &&
                              (Matches(row.BaseLabel, regionFilter) || Matches(row.SizeLabel, regionFilter) ||
                               Matches(row.AllocTypeLabel, regionFilter) || Matches(row.ProtectLabel, regionFilter) ||
                               MatchesThreadDetails(row, regionFilter)) &&
                              (Matches(row.ProtectLabel, protectFilter) || Matches(row.AllocTypeLabel, protectFilter) ||
                               MatchesThreadDetails(row, protectFilter)) &&
                              row.Hits >= Math.Max(0, minHits))
                .OrderByDescending(x => x.Hits)
                .ThenByDescending(x => x.LastSeen, StringComparer.Ordinal)
                .ToList();
        }

        private ApiCallStructuredFields BuildApiCallStructuredFields(string apiName, string rawReason,
                                                                     string decodedAction, BrokerEtwEventView? view)
        {
            Dictionary<string, string> fields = ParseReasonFields(rawReason);
            string action = SummarizeApiReason(decodedAction);
            string field1Label = "Base";
            string field2Label = "Context";
            string field3Label = "Alloc Type";
            string field4Label = "Flags";
            string field1Value = string.Empty;
            string field2Value = string.Empty;
            string field3Value = string.Empty;
            string field4Value = string.Empty;

            if (apiName.Equals("NtAllocateVirtualMemory", StringComparison.OrdinalIgnoreCase))
            {
                ulong baseAddress = FirstU64(fields, "base", "c0", "a1");
                ulong regionSize = FirstU64(fields, "size", "c1", "a3");
                uint allocationType = (uint)FirstU64(fields, "allocType", "c2", "a4");
                uint protect = (uint)FirstU64(fields, "protect", "c3", "a5");
                field1Value = FormatObservedPointer(view, baseAddress);
                field2Value =
                    regionSize == 0
                        ? string.Empty
                        : $"base={(baseAddress == 0 ? "?" : FormatObservedPointer(view, baseAddress))}  size=0x{regionSize:X}";
                field3Value = allocationType == 0
                                  ? string.Empty
                                  : $"0x{allocationType:X} {DescribeMemoryAllocationType(allocationType)}";
                field4Value = protect == 0 ? string.Empty : $"0x{protect:X} {DescribeMemoryProtect(protect)}";
            }
            else if (apiName.Equals("NtProtectVirtualMemory", StringComparison.OrdinalIgnoreCase))
            {
                ulong baseAddress = FirstU64(fields, "base", "c0", "a1");
                ulong regionSize = FirstU64(fields, "size", "c1", "a2");
                uint protect = (uint)FirstU64(fields, "newProtect", "c2", "a3");
                field1Value = FormatObservedPointer(view, baseAddress);
                field2Value =
                    regionSize == 0
                        ? string.Empty
                        : $"base={(baseAddress == 0 ? "?" : FormatObservedPointer(view, baseAddress))}  size=0x{regionSize:X}";
                field4Value = protect == 0 ? string.Empty : $"0x{protect:X} {DescribeMemoryProtect(protect)}";
            }
            else if (apiName.Equals("NtWriteVirtualMemory", StringComparison.OrdinalIgnoreCase) ||
                     apiName.Equals("NtReadVirtualMemory", StringComparison.OrdinalIgnoreCase))
            {
                ulong baseAddress = FirstU64(fields, "base", "c0", "a1");
                ulong regionSize = FirstU64(fields, "size", "c1", "a3");
                field1Value = FormatObservedPointer(view, baseAddress);
                field2Value =
                    regionSize == 0
                        ? string.Empty
                        : $"base={(baseAddress == 0 ? "?" : FormatObservedPointer(view, baseAddress))}  size=0x{regionSize:X}";
            }
            else if (apiName.Equals("LdrLoadDll", StringComparison.OrdinalIgnoreCase) ||
                     apiName.StartsWith("LoadLibrary", StringComparison.OrdinalIgnoreCase))
            {
                field1Label = "Module";
                field2Label = "Context";
                field3Label = "Flags";
                field4Label = "Result";

                field1Value = DecodeModuleHookName(apiName, view);
                ulong handle = FirstU64(fields, "handle");
                ulong flags = FirstU64(fields, "flags");
                ulong status = FirstU64(fields, "status");

                field2Value = handle == 0 ? (string.IsNullOrWhiteSpace(field1Value) ? string.Empty : field1Value)
                                          : $"{field1Value}  handle=0x{handle:X}".Trim();
                field3Value = flags == 0 ? "0x0" : $"0x{flags:X}";
                field4Value =
                    apiName.Equals("LdrLoadDll", StringComparison.OrdinalIgnoreCase) ? $"0x{status:X8}" : string.Empty;
            }
            else if (apiName.Equals("RtlAddFunctionTable", StringComparison.OrdinalIgnoreCase) ||
                     apiName.Equals("RtlInstallFunctionTableCallback", StringComparison.OrdinalIgnoreCase) ||
                     apiName.Equals("RtlDeleteFunctionTable", StringComparison.OrdinalIgnoreCase))
            {
                field1Label = "Base";
                field2Label = "Context";
                field3Label = "Length";
                field4Label = "Callback";
                ulong baseAddress = FirstU64(fields, "baseAddress", "a2", "a1");
                ulong length = FirstU64(fields, "length", "a2");
                ulong callback = FirstU64(fields, "callback", "a3");
                field1Value = FormatObservedPointer(view, baseAddress);
                field2Value = apiName.Equals("RtlDeleteFunctionTable", StringComparison.OrdinalIgnoreCase)
                                  ? $"table={FormatObservedPointer(view, FirstU64(fields, "table", "a0"))}"
                                  : $"table={FormatObservedPointer(view, FirstU64(fields, "tableId", "table", "a0"))}";
                field3Value = length == 0 ? string.Empty : $"0x{length:X}";
                field4Value = FormatObservedPointer(view, callback);
            }

            return new ApiCallStructuredFields { Action = string.IsNullOrWhiteSpace(action) ? apiName : action,
                                                 Field1Label = field1Label,
                                                 Field2Label = field2Label,
                                                 Field3Label = field3Label,
                                                 Field4Label = field4Label,
                                                 Field1Value = field1Value,
                                                 Field2Value = field2Value,
                                                 Field3Value = field3Value,
                                                 Field4Value = field4Value };
        }

        private static string DecodeModuleHookName(string apiName, BrokerEtwEventView? view)
        {
            if (view == null || view.DeepSample == null || view.DeepSample.Length == 0 || view.DeepSampleSize == 0)
            {
                return string.Empty;
            }

            int sampleSize = Math.Min(view.DeepSample.Length, (int)view.DeepSampleSize);
            if (sampleSize <= 0)
            {
                return string.Empty;
            }

            if (apiName.Equals("LoadLibraryA", StringComparison.OrdinalIgnoreCase) ||
                apiName.Equals("LoadLibraryExA", StringComparison.OrdinalIgnoreCase))
            {
                int zeroIndex = Array.IndexOf(view.DeepSample, (byte)0, 0, sampleSize);
                int length = zeroIndex >= 0 ? zeroIndex : sampleSize;
                return length > 0 ? Encoding.ASCII.GetString(view.DeepSample, 0, length).Trim() : string.Empty;
            }

            int byteLength = sampleSize & ~1;
            if (byteLength <= 0)
            {
                return string.Empty;
            }

            string decoded = Encoding.Unicode.GetString(view.DeepSample, 0, byteLength);
            int nul = decoded.IndexOf('\0');
            if (nul >= 0)
            {
                decoded = decoded[..nul];
            }

            return decoded.Trim();
        }

        private void RenderApiGraphCanvas(IReadOnlyList<ApiCallGraphRowSnapshot> rows, string? selectedKey)
        {
            if (ApiViewGraphCanvas == null)
            {
                return;
            }

            ApiViewGraphCanvas.Children.Clear();

            if (rows.Count == 0)
            {
                ApiViewGraphCanvas.Width = 540;
                ApiViewGraphCanvas.Height = 240;
                var empty = new System.Windows.Controls.TextBlock {
                    Text = "No live call graph yet",
                    Foreground = (System.Windows.Media.Brush)FindResource("WinMutedTextBrush")
                };
                System.Windows.Controls.Canvas.SetLeft(empty, 16);
                System.Windows.Controls.Canvas.SetTop(empty, 16);
                ApiViewGraphCanvas.Children.Add(empty);
                return;
            }

            ApiCallGraphRowSnapshot? selectedRow = rows.FirstOrDefault(
                row =>
                {
                    string sensor = string.IsNullOrWhiteSpace(row.SensorOrigin) ? "Unclassified" : row.SensorOrigin;
                    string callerOrigin = NormalizeApiCallerOrigin(row.CallerOrigin);
                    string originModule = NormalizeApiOriginModule(row.OriginModule);
                    string key = BuildApiGraphKey(row.SourcePid, row.TargetPid, row.ThreadId, row.ApiName, sensor,
                                                  callerOrigin, originModule);
                    return string.Equals(key, selectedKey, StringComparison.Ordinal);
                });

            List<ApiCallGraphRowSnapshot> visible =
                rows.OrderByDescending(x => x.Hits).ThenByDescending(x => x.LastSeenUtc).Take(12).ToList();
            if (selectedRow != null && !visible.Contains(selectedRow))
            {
                visible.Add(selectedRow);
            }

            var sourceNodes = visible.GroupBy(x => x.SourcePid)
                                  .Select(x => new { Pid = x.Key, Hits = x.Sum(y => Math.Max(1, y.Hits)),
                                                     Selected = selectedRow != null &&
                                                                x.Any(y => y.SourcePid == selectedRow.SourcePid) })
                                  .Where(x => x.Pid != 0)
                                  .OrderByDescending(x => x.Hits)
                                  .Take(6)
                                  .ToList();
            var apiNodes =
                visible.GroupBy(x => string.IsNullOrWhiteSpace(x.ApiName) ? "unknown" : x.ApiName)
                    .Select(x => new { Api = x.Key, Hits = x.Sum(y => Math.Max(1, y.Hits)),
                                       Selected = selectedRow != null &&
                                                  x.Any(y => string.Equals(y.ApiName, selectedRow.ApiName,
                                                                           StringComparison.OrdinalIgnoreCase)) })
                    .OrderByDescending(x => x.Hits)
                    .Take(8)
                    .ToList();
            var targetNodes =
                visible.GroupBy(x => x.TargetPid != 0 ? x.TargetPid : x.SourcePid)
                    .Select(x => new { Pid = x.Key, Hits = x.Sum(y => Math.Max(1, y.Hits)),
                                       Selected = selectedRow != null &&
                                                  x.Any(y => (y.TargetPid != 0 ? y.TargetPid : y.SourcePid) ==
                                                             (selectedRow.TargetPid != 0 ? selectedRow.TargetPid
                                                                                         : selectedRow.SourcePid)) })
                    .Where(x => x.Pid != 0)
                    .OrderByDescending(x => x.Hits)
                    .Take(6)
                    .ToList();

            double canvasWidth = 920;
            double nodeWidth = 170;
            double apiNodeWidth = 188;
            double nodeHeight = 40;
            double leftX = 26;
            double middleX = 364;
            double rightX = canvasWidth - nodeWidth - 26;
            double topY = 42;
            double verticalSpacing = 56;
            double canvasHeight = Math.Max(
                264,
                topY + Math.Max(sourceNodes.Count, Math.Max(apiNodes.Count, targetNodes.Count)) * verticalSpacing + 40);
            ApiViewGraphCanvas.Width = canvasWidth;
            ApiViewGraphCanvas.Height = canvasHeight;

            var sourcePositions = new Dictionary<uint, System.Windows.Point>();
            var apiPositions = new Dictionary<string, System.Windows.Point>(StringComparer.OrdinalIgnoreCase);
            var targetPositions = new Dictionary<uint, System.Windows.Point>();

            AddColumnLabel(leftX + (nodeWidth / 2.0), 14, "CALLERS");
            AddColumnLabel(middleX + (apiNodeWidth / 2.0), 14, "APIS");
            AddColumnLabel(rightX + (nodeWidth / 2.0), 14, "TARGETS");

            for (int i = 0; i < sourceNodes.Count; i += 1)
            {
                double y = topY + (i * verticalSpacing);
                sourcePositions[sourceNodes[i].Pid] =
                    new System.Windows.Point(leftX + nodeWidth, y + (nodeHeight / 2.0));
                AddApiGraphProcessNode(leftX, y, nodeWidth, nodeHeight, sourceNodes[i].Pid, true,
                                       sourceNodes[i].Selected);
            }

            for (int i = 0; i < apiNodes.Count; i += 1)
            {
                double y = topY + (i * verticalSpacing);
                apiPositions[apiNodes[i].Api] =
                    new System.Windows.Point(middleX + apiNodeWidth / 2.0, y + (nodeHeight / 2.0));
                AddApiGraphApiNode(middleX, y, apiNodeWidth, nodeHeight, apiNodes[i].Api, apiNodes[i].Selected);
            }

            for (int i = 0; i < targetNodes.Count; i += 1)
            {
                double y = topY + (i * verticalSpacing);
                targetPositions[targetNodes[i].Pid] = new System.Windows.Point(rightX, y + (nodeHeight / 2.0));
                AddApiGraphProcessNode(rightX, y, nodeWidth, nodeHeight, targetNodes[i].Pid, false,
                                       targetNodes[i].Selected);
            }

            int maxHits = Math.Max(1, visible.Max(x => Math.Max(1, x.Hits)));
            foreach (ApiCallGraphRowSnapshot row in visible)
            {
                uint sourcePid = row.SourcePid;
                uint targetPid = row.TargetPid != 0 ? row.TargetPid : row.SourcePid;
                string apiName = string.IsNullOrWhiteSpace(row.ApiName) ? "unknown" : row.ApiName;
                string sensor = string.IsNullOrWhiteSpace(row.SensorOrigin) ? "Unclassified" : row.SensorOrigin;
                string callerOrigin = NormalizeApiCallerOrigin(row.CallerOrigin);
                string originModule = NormalizeApiOriginModule(row.OriginModule);
                string rowKey = BuildApiGraphKey(row.SourcePid, row.TargetPid, row.ThreadId, row.ApiName, sensor,
                                                 callerOrigin, originModule);
                bool isSelected = !string.IsNullOrWhiteSpace(selectedKey) &&
                                  string.Equals(rowKey, selectedKey, StringComparison.Ordinal);
                if (!sourcePositions.TryGetValue(sourcePid, out System.Windows.Point sourcePoint) ||
                    !apiPositions.TryGetValue(apiName, out System.Windows.Point apiPoint) ||
                    !targetPositions.TryGetValue(targetPid, out System.Windows.Point end))
                {
                    continue;
                }

                double heat = Math.Clamp(row.Hits / (double)maxHits, 0.0, 1.0);
                var lineBrush = BuildApiGraphEdgeBrush(sensor, callerOrigin, heat);
                bool selfLoop = sourcePid == targetPid;
                DrawCurve(sourcePoint, new System.Windows.Point(middleX, apiPoint.Y), lineBrush, heat, isSelected,
                          forward: true, selfLoop: false);
                DrawCurve(new System.Windows.Point(middleX + apiNodeWidth, apiPoint.Y), end, lineBrush, heat,
                          isSelected, forward: true, selfLoop: selfLoop);
            }

            void AddColumnLabel(double centerX, double y, string label)
            {
                var block = new System.Windows.Controls.TextBlock {
                    Text = label, FontSize = 10, FontWeight = FontWeights.SemiBold,
                    Foreground = (System.Windows.Media.Brush)FindResource("WinMutedTextBrush")
                };
                block.Measure(new Size(double.PositiveInfinity, double.PositiveInfinity));
                System.Windows.Controls.Canvas.SetLeft(block, centerX - (block.DesiredSize.Width / 2.0));
                System.Windows.Controls.Canvas.SetTop(block, y);
                ApiViewGraphCanvas.Children.Add(block);
            }

            void DrawCurve(System.Windows.Point start, System.Windows.Point end, System.Windows.Media.Brush stroke,
                           double heat, bool selected, bool forward, bool selfLoop)
            {
                var figure = new System.Windows.Media.PathFigure { StartPoint = start };
                System.Windows.Point arrowBase;
                System.Windows.Vector direction;
                if (selfLoop)
                {
                    double loopWidth = 64;
                    double loopHeight = 28;
                    var first = new System.Windows.Point(start.X + loopWidth * 0.35, start.Y - loopHeight);
                    var second = new System.Windows.Point(end.X - loopWidth * 0.35, end.Y - loopHeight);
                    figure.Segments.Add(new System.Windows.Media.BezierSegment(first, second, end, true));
                    arrowBase = second;
                    direction = end - second;
                }
                else
                {
                    double controlOffset = Math.Max(48, Math.Abs(end.X - start.X) * 0.32);
                    var first = new System.Windows.Point(start.X + controlOffset, start.Y);
                    var second = new System.Windows.Point(end.X - controlOffset, end.Y);
                    figure.Segments.Add(new System.Windows.Media.BezierSegment(first, second, end, true));
                    arrowBase = second;
                    direction = end - second;
                }
                var geometry = new System.Windows.Media.PathGeometry();
                geometry.Figures.Add(figure);

                ApiViewGraphCanvas.Children.Add(
                    new System.Windows.Shapes.Path { Data = geometry, Stroke = stroke,
                                                     StrokeThickness = (selected ? 2.1 : 1.0) + (2.9 * heat),
                                                     Opacity = selected ? 0.98 : 0.28 });

                if (forward)
                {
                    DrawArrowHead(end, direction, stroke, selected ? 0.98 : 0.45);
                }
            }

            void DrawArrowHead(System.Windows.Point tip, System.Windows.Vector direction,
                               System.Windows.Media.Brush stroke, double opacity)
            {
                if (direction.LengthSquared < 1)
                {
                    direction = new System.Windows.Vector(1, 0);
                }

                direction.Normalize();
                System.Windows.Vector normal = new(-direction.Y, direction.X);
                const double arrowLength = 9;
                const double arrowWidth = 4.5;
                System.Windows.Point p1 = tip - (direction * arrowLength) + (normal * arrowWidth);
                System.Windows.Point p2 = tip - (direction * arrowLength) - (normal * arrowWidth);
                var geometry = new System.Windows.Media.PathGeometry();
                var figure = new System.Windows.Media.PathFigure { StartPoint = tip, IsClosed = true, IsFilled = true };
                figure.Segments.Add(new System.Windows.Media.LineSegment(p1, true));
                figure.Segments.Add(new System.Windows.Media.LineSegment(p2, true));
                geometry.Figures.Add(figure);
                ApiViewGraphCanvas.Children.Add(new System.Windows.Shapes.Path { Data = geometry, Fill = stroke,
                                                                                 Stroke = stroke, Opacity = opacity });
            }

            void AddApiGraphProcessNode(double x, double y, double width, double height, uint pid, bool sourceSide,
                                        bool selected)
            {
                string processName = GetApiGraphProcessName(pid);
                string title = string.IsNullOrWhiteSpace(processName) ? "Process" : processName;
                var border = new System.Windows.Controls.Border {
                    Width = width,
                    Height = height,
                    CornerRadius = new CornerRadius(8),
                    Background = new System.Windows.Media.SolidColorBrush(
                        sourceSide ? (selected ? System.Windows.Media.Color.FromArgb(235, 22, 86, 140)
                                               : System.Windows.Media.Color.FromArgb(220, 17, 63, 103))
                                   : (selected ? System.Windows.Media.Color.FromArgb(235, 140, 34, 38)
                                               : System.Windows.Media.Color.FromArgb(220, 110, 25, 28))),
                    BorderBrush = new System.Windows.Media.SolidColorBrush(
                        sourceSide ? (selected ? System.Windows.Media.Color.FromRgb(118, 203, 255)
                                               : System.Windows.Media.Color.FromRgb(80, 172, 255))
                                   : (selected ? System.Windows.Media.Color.FromRgb(255, 139, 139)
                                               : System.Windows.Media.Color.FromRgb(255, 109, 109))),
                    BorderThickness = new Thickness(selected ? 2 : 1),
                    Opacity = selected ? 1.0 : 0.78,
                    Child =
                        new System.Windows.Controls
                            .StackPanel {
                                VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(10, 3, 10, 3),
                                Children = { new System.Windows.Controls.TextBlock {
                                                Text = title, TextAlignment = TextAlignment.Center,
                                                TextTrimming = TextTrimming.CharacterEllipsis,
                                                FontWeight = FontWeights.SemiBold,
                                                Foreground = new System.Windows.Media
                                                                 .SolidColorBrush(System.Windows.Media.Colors.White)
                                            },
                                             new System.Windows.Controls.TextBlock { Text = $"PID {pid}",
                                                                                     Margin = new Thickness(0, 1, 0, 0),
                                                                                     TextAlignment =
                                                                                         TextAlignment.Center,
                                                                                     Foreground =
                                                                                         new System.Windows.Media.SolidColorBrush(System
                                                                                                                                      .Windows
                                                                                                                                      .Media
                                                                                                                                      .Color
                                                                                                                                      .FromRgb(
                                                                                                                                          220, 225, 230)) } }
                            }
                };
                System.Windows.Controls.Canvas.SetLeft(border, x);
                System.Windows.Controls.Canvas.SetTop(border, y);
                ApiViewGraphCanvas.Children.Add(border);
            }

            void AddApiGraphApiNode(double x, double y, double width, double height, string label, bool selected)
            {
                var border =
                    new System.Windows.Controls.Border {
                        Width = width,
                        Height = height,
                        CornerRadius = new CornerRadius(8),
                        Background = new System.Windows.Media.SolidColorBrush(
                            selected ? System.Windows.Media.Color.FromArgb(236, 42, 49, 58)
                                     : System.Windows.Media.Color.FromArgb(225, 32, 36, 43)),
                        BorderBrush = new System.Windows.Media.SolidColorBrush(
                            selected ? System.Windows.Media.Color.FromRgb(195, 205, 216)
                                     : System.Windows.Media.Color.FromRgb(128, 140, 154)),
                        BorderThickness = new Thickness(selected ? 2 : 1),
                        Opacity = selected ? 1.0 : 0.82,
                        Child =
                            new System.Windows.Controls.TextBlock {
                                Text = label, Margin = new Thickness(10, 0, 10, 0),
                                VerticalAlignment = VerticalAlignment.Center, TextAlignment = TextAlignment.Center,
                                TextTrimming = TextTrimming.CharacterEllipsis, FontWeight = FontWeights.SemiBold,
                                Foreground = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Colors.White)
                            },
                        Cursor = System.Windows.Input.Cursors.Hand
                    };
                border.MouseLeftButtonDown += (_, e) =>
                {
                    SelectApiViewRowByApiName(label);
                    if (e.ClickCount >= 2)
                    {
                        OpenApiInspector(label);
                    }
                    e.Handled = true;
                };
                System.Windows.Controls.Canvas.SetLeft(border, x);
                System.Windows.Controls.Canvas.SetTop(border, y);
                ApiViewGraphCanvas.Children.Add(border);
            }
        }

        private static string SummarizeApiReason(string? reason)
        {
            if (string.IsNullOrWhiteSpace(reason))
            {
                return string.Empty;
            }

            string compact = reason.Replace('\r', ' ').Replace('\n', ' ').Trim();
            if (compact.Length <= 260)
            {
                return compact;
            }

            return compact[..260] + "...";
        }

        private static string BuildApiGraphKey(uint sourcePid, uint targetPid, uint threadId, string apiName,
                                               string sensorOrigin, string callerOrigin, string originModule) =>
            $"{sourcePid}|{targetPid}|{threadId}|{apiName}|{sensorOrigin}|{callerOrigin}|{originModule}";

        private static string NormalizeApiCallerOrigin(string? callerOrigin)
        {
            string normalized = (callerOrigin ?? string.Empty).Trim().ToLowerInvariant();
            return normalized.Length == 0 ? "unknown" : normalized;
        }

        private static string NormalizeApiOriginModule(string? originModule)
        {
            string normalized = (originModule ?? string.Empty).Trim();
            return normalized.Length == 0 ? "unknown" : normalized;
        }

        private static string GetApiCallerOriginDisplayLabel(string callerOrigin, string? sensor = null,
                                                             string? originModule = null)
        {
            string moduleName = EventDetailFormatting.ModuleNameFromPath(originModule);
            bool hasModuleName = !string.IsNullOrWhiteSpace(moduleName) &&
                                 !moduleName.Equals("unknown", StringComparison.OrdinalIgnoreCase);
            return NormalizeApiCallerOrigin(
                callerOrigin) switch { "process-image" => "Process Image", "non-system-dll" => "Other DLL",
                                       "unbacked" => "Unbacked / Shellcode", "system" => "System DLL Chain",
                                       _ => !string.IsNullOrWhiteSpace(sensor) &&
                                                    sensor.StartsWith("Kernel", StringComparison.OrdinalIgnoreCase)
                                                ? "Kernel"
                                            : hasModuleName ? $"Module: {moduleName}"
                                                            : "Unresolved Caller" };
        }

        private static bool IsInternalHookFrame(string? modulePath, string? frameText = null)
        {
            if (EventDetailFormatting.IsBlackbirdInternalPath(modulePath) ||
                EventDetailFormatting.IsBlackbirdInternalModule(modulePath))
            {
                return true;
            }

            string candidate = (frameText ?? string.Empty).Trim();
            return candidate.StartsWith("SR71", StringComparison.OrdinalIgnoreCase) ||
                   candidate.StartsWith("J58", StringComparison.OrdinalIgnoreCase) ||
                   candidate.StartsWith("BlackbirdController", StringComparison.OrdinalIgnoreCase) ||
                   candidate.StartsWith("BlackbirdInterface", StringComparison.OrdinalIgnoreCase);
        }

        private static List<string> BuildHookFrameList(BrokerEtwEventView view,
                                                       IReadOnlyDictionary<string, string> fields)
        {
            ulong[] stack = view.Stack ?? Array.Empty<ulong>();
            var frames = new List<string>(BlackbirdNative.MaxIpcStackFrames);

            void AddFrameText(string frame)
            {
                if (string.IsNullOrWhiteSpace(frame))
                {
                    return;
                }

                frame = frame.Trim();
                if (frames.Count == 0 || !string.Equals(frames[^1], frame, StringComparison.OrdinalIgnoreCase))
                {
                    frames.Add(frame);
                }
            }

            for (int i = 0; i < Math.Min((int)view.StackCount, BlackbirdNative.MaxIpcStackFrames); i += 1)
            {
                string symbolKey = $"stack{i}Symbol";
                string pathKey = $"stack{i}Path";
                if (fields.TryGetValue(symbolKey, out string? symbolValue) && !string.IsNullOrWhiteSpace(symbolValue))
                {
                    string frameText = symbolValue.Trim();
                    string? pathValue = null;
                    if (fields.TryGetValue(pathKey, out string? resolvedPath) && !string.IsNullOrWhiteSpace(resolvedPath))
                    {
                        pathValue = resolvedPath.Trim();
                    }
                    if (IsInternalHookFrame(pathValue, frameText))
                    {
                        continue;
                    }
                    if (!string.IsNullOrWhiteSpace(pathValue))
                    {
                        string moduleName = EventDetailFormatting.ModuleNameFromPath(pathValue);
                        if (!string.IsNullOrWhiteSpace(moduleName) &&
                            !moduleName.Equals("unknown", StringComparison.OrdinalIgnoreCase) &&
                            frameText.IndexOf(moduleName, StringComparison.OrdinalIgnoreCase) < 0)
                        {
                            frameText = $"{moduleName}!{frameText}";
                        }
                    }
                    AddFrameText(frameText);
                    continue;
                }

                ulong rawIp = i < stack.Length ? stack[i] : 0;
                if (rawIp != 0)
                {
                    AddFrameText($"0x{rawIp:X}");
                }
            }

            if (frames.Count == 0 &&
                fields.TryGetValue("originSymbol", out string? originSymbol) &&
                !string.IsNullOrWhiteSpace(originSymbol) &&
                !IsInternalHookFrame(null, originSymbol))
            {
                AddFrameText(originSymbol);
            }

            return frames;
        }

        private static string BuildHookCallChainText(BrokerEtwEventView view,
                                                     IReadOnlyDictionary<string, string> fields)
        {
            List<string> frames = BuildHookFrameList(view, fields);
            return frames.Count == 0 ? string.Empty : "CallChain: " + string.Join(" -> ", frames);
        }

        private string FormatObservedPointer(BrokerEtwEventView? view, ulong address, string? modulePath = null,
                                             ulong moduleBase = 0, ulong moduleSize = 0)
        {
            if (address == 0)
            {
                return string.Empty;
            }

            string directModuleText =
                EventDetailFormatting.FormatModuleRelativeAddress(modulePath, moduleBase, moduleSize, address);
            if (!string.IsNullOrWhiteSpace(directModuleText) &&
                !string.Equals(directModuleText, $"0x{address:X}", StringComparison.OrdinalIgnoreCase))
            {
                return directModuleText;
            }

            if (view != null)
            {
                uint targetPid =
                    view.TargetPid != 0 ? view.TargetPid : (view.ProcessPid != 0 ? view.ProcessPid : view.ActorPid);
                ulong processStartKey = ResolveObservedProcessStartKey(targetPid, view.ProcessStartKey);
                if (TryResolveKnownRegionForAddress(targetPid, processStartKey, address, out _, out ulong regionBase,
                                                    out ulong regionSize, out string regionKind,
                                                    out uint currentProtection))
                {
                    ulong pageBase = address & ~0xFFFUL;
                    string regionText =
                        $"{regionKind.ToLowerInvariant()}+0x{address - regionBase:X} [0x{address:X}; page 0x{pageBase:X}; region 0x{regionBase:X}+0x{regionSize:X}; {EventDetailFormatting.DescribeMemoryProtection(currentProtection)}]";

                    if (string.Equals(regionKind, "Image", StringComparison.OrdinalIgnoreCase))
                    {
                        string imageText = EventDetailFormatting.FormatModuleRelativeAddress(
                            view.ImagePath, view.ImageBase != 0 ? view.ImageBase : regionBase,
                            view.ImageSize != 0 ? view.ImageSize : regionSize, address);
                        if (!string.IsNullOrWhiteSpace(imageText) &&
                            !string.Equals(imageText, $"0x{address:X}", StringComparison.OrdinalIgnoreCase))
                        {
                            return $"{imageText}; page 0x{pageBase:X}";
                        }
                    }

                    return regionText;
                }

                string viewImageText = EventDetailFormatting.FormatModuleRelativeAddress(view.ImagePath, view.ImageBase,
                                                                                         view.ImageSize, address);
                if (!string.IsNullOrWhiteSpace(viewImageText) &&
                    !string.Equals(viewImageText, $"0x{address:X}", StringComparison.OrdinalIgnoreCase))
                {
                    return viewImageText;
                }
            }

            return $"0x{address:X}";
        }

        private string BuildHookFrameSummary(BrokerEtwEventView view, IReadOnlyDictionary<string, string> fields) =>
            AppendThreadStackFallbackSummary(view, BuildHookFrameSummaryCore(view, fields));

        private static string BuildHookFrameSummaryCore(BrokerEtwEventView view,
                                                        IReadOnlyDictionary<string, string> fields)
        {
            var sb = new StringBuilder(512);
            string sensor = EventDetailFormatting.ClassifyHookSensorOrigin(view);
            string originModule = ResolveHookOriginModule(view, fields);
            string origin =
                GetApiCallerOriginDisplayLabel(NormalizeApiCallerOrigin(view.CallerOriginLabel), sensor, originModule);
            string immediate = EventDetailFormatting.HookImmediateCallerLabel(view.Flags);
            string deepOrigin = EventDetailFormatting.HookDeepOriginLabel(view.Flags);
            string sr71Component = EventDetailFormatting.HookComponentLabel(view.Flags);
            string resolvedReturnAddress = ResolveHookReturnAddressLabel(view, fields, originModule);
            bool kernelCaller = (view.Flags & BlackbirdNative.IpcEtwFlagHookKernelCaller) != 0;
            bool userCaller = (view.Flags & BlackbirdNative.IpcEtwFlagHookUserCaller) != 0;
            bool currentTarget = IsHookCurrentProcessTarget(view);
            bool imageSection = IsHookImageSection(view);
            bool containsOwnModule = EventDetailFormatting.HookTraceContainsOwnModule(view.Flags);
            bool returnAddressResolved = !string.IsNullOrWhiteSpace(resolvedReturnAddress);
            bool returnAddressPresentInStack = false;
            ulong[] stack = view.Stack ?? Array.Empty<ulong>();
            int compareFrames = Math.Min((int)view.StackCount, stack.Length);
            for (int i = 0; i < compareFrames; i += 1)
            {
                if (stack[i] == view.OriginAddress && view.OriginAddress != 0)
                {
                    returnAddressPresentInStack = true;
                    break;
                }
            }

            sb.Append("Origin: ").AppendLine(origin);
            if (kernelCaller || userCaller)
            {
                sb.Append("Caller Mode: ").AppendLine(kernelCaller ? "Kernel" : "User");
            }
            sb.Append("Target Scope: ").AppendLine(currentTarget ? "Current Process" : "External / Cross-Process");
            sb.Append("Memory Backing: ").AppendLine(imageSection ? "Image-backed" : "Private / Non-image");
            if (!string.IsNullOrWhiteSpace(sr71Component))
            {
                sb.Append("SR71 Component: ").AppendLine(sr71Component);
            }
            sb.Append("SR71 Frames Present: ").AppendLine(containsOwnModule ? "yes" : "no");
            if (!string.IsNullOrWhiteSpace(immediate) &&
                !immediate.Equals("Unknown", StringComparison.OrdinalIgnoreCase) &&
                !immediate.Equals("Unresolved Caller", StringComparison.OrdinalIgnoreCase))
            {
                sb.Append("Immediate Caller: ").AppendLine(immediate);
            }
            if (!string.IsNullOrWhiteSpace(deepOrigin) &&
                !deepOrigin.Equals("Unknown", StringComparison.OrdinalIgnoreCase) &&
                !deepOrigin.Equals("Unresolved Caller", StringComparison.OrdinalIgnoreCase))
            {
                sb.Append("Deep Origin: ").AppendLine(deepOrigin);
            }
            if (!string.IsNullOrWhiteSpace(originModule))
            {
                sb.Append("Origin Module: ").AppendLine(originModule);
            }
            if (view.OriginAddress != 0)
            {
                sb.Append("Return Address: ")
                    .AppendLine(!string.IsNullOrWhiteSpace(resolvedReturnAddress)
                                    ? resolvedReturnAddress
                                    : $"0x{view.OriginAddress.ToString("X", CultureInfo.InvariantCulture)}");
                sb.Append("Return Address Resolved: ").AppendLine(returnAddressResolved ? "yes" : "no");
                sb.Append("Return Address In Stack: ").AppendLine(returnAddressPresentInStack ? "yes" : "no");
            }
            sb.Append("Stack Frames Captured: ")
                .Append(view.StackCount.ToString(CultureInfo.InvariantCulture))
                .AppendLine();
            if (fields.TryGetValue("startSymbol", out string? startSymbol) && !string.IsNullOrWhiteSpace(startSymbol))
            {
                sb.Append("Start Routine: ").AppendLine(startSymbol);
            }

            List<string> frames = BuildHookFrameList(view, fields);
            if (frames.Count > 0)
            {
                sb.AppendLine("Frames:");
                for (int i = 0; i < frames.Count; i += 1)
                {
                    sb.Append("  ").Append(i + 1).Append(". ").AppendLine(frames[i]);
                    string pathKey = $"stack{i}Path";
                    if (fields.TryGetValue(pathKey, out string? framePath) && !string.IsNullOrWhiteSpace(framePath))
                    {
                        sb.Append("     ").AppendLine(framePath.Trim());
                    }
                }
            }

            if (!string.IsNullOrWhiteSpace(view.OriginPath))
            {
                sb.Append("Origin Path: ").AppendLine(view.OriginPath.Trim());
            }

            return sb.ToString().TrimEnd();
        }

        private string AppendThreadStackFallbackSummary(BrokerEtwEventView view, string summary)
        {
            if (view.StackCount != 0)
            {
                return summary;
            }

            string fallback = BuildThreadStackFallbackSummary(view);
            if (string.IsNullOrWhiteSpace(fallback))
            {
                string source = EventDetailFormatting.IsKernelHookTelemetry(view) ||
                                        view.SourceId == BlackbirdNative.IpcEtwSourceBlackbird
                                    ? "kernel/driver telemetry did not include user frames"
                                    : "hook telemetry did not include frames";
                string note = $"Thread Stack Fallback: pending or unavailable ({source})";
                return string.IsNullOrWhiteSpace(summary) ? note : $"{summary}{Environment.NewLine}{note}";
            }

            return string.IsNullOrWhiteSpace(summary) ? fallback : $"{summary}{Environment.NewLine}{fallback}";
        }

        private string BuildThreadStackFallbackSummary(BrokerEtwEventView view)
        {
            uint pid = view.ProcessPid != 0 ? view.ProcessPid
                       : view.ActorPid != 0 ? view.ActorPid
                                            : view.EventProcessId;
            uint tid = view.EventThreadId != 0 ? view.EventThreadId : view.ThreadId;
            if (pid == 0 || tid == 0 || pid > int.MaxValue || tid > int.MaxValue)
            {
                return string.Empty;
            }

            DateTime observedUtc = view.TimestampUtc == default ? DateTime.UtcNow : view.TimestampUtc;
            IReadOnlyList<ThreadStackSessionSnapshot> history =
                GetThreadStackHistory(unchecked((int)pid), unchecked((int)tid), string.Empty);
            ThreadStackSessionSnapshot? snapshot =
                history.Where(x => x.Frames.Count > 0)
                    .OrderBy(x => Math.Abs((x.CapturedAtUtc - observedUtc).TotalMilliseconds))
                    .FirstOrDefault();
            if (snapshot == null)
            {
                return string.Empty;
            }

            double deltaMs = Math.Abs((snapshot.CapturedAtUtc - observedUtc).TotalMilliseconds);
            if (deltaMs > 5000)
            {
                return string.Empty;
            }

            var sb = new StringBuilder(512);
            sb.Append("Thread Stack Fallback: ")
                .Append(snapshot.Frames.Count.ToString(CultureInfo.InvariantCulture))
                .Append(" frames from Thread Stack window history, deltaMs=")
                .Append(deltaMs.ToString("0", CultureInfo.InvariantCulture))
                .AppendLine();
            int frameCount = Math.Min(12, snapshot.Frames.Count);
            for (int i = 0; i < frameCount; i += 1)
            {
                StackFrameRow frame = snapshot.Frames[i];
                string label = !string.IsNullOrWhiteSpace(frame.Symbol)    ? frame.Symbol
                               : !string.IsNullOrWhiteSpace(frame.Address) ? frame.Address
                                                                           : $"0x{frame.InstructionPointerRaw:X}";
                if (!string.IsNullOrWhiteSpace(frame.Module) &&
                    label.IndexOf(frame.Module, StringComparison.OrdinalIgnoreCase) < 0)
                {
                    label = $"{frame.Module}!{label}";
                }
                sb.Append("  ").Append(i + 1).Append(". ").AppendLine(label);
            }

            return sb.ToString().TrimEnd();
        }

        private static string ResolveHookOriginModule(BrokerEtwEventView view,
                                                      IReadOnlyDictionary<string, string> fields)
        {
            string originModule = EventDetailFormatting.ModuleNameFromPath(view.OriginPath);
            if (!string.Equals(originModule, "unknown", StringComparison.OrdinalIgnoreCase) &&
                !EventDetailFormatting.IsBlackbirdInternalModule(originModule) &&
                !EventDetailFormatting.IsBlackbirdInternalPath(view.OriginPath))
            {
                return originModule;
            }

            if (fields.TryGetValue("originSymbol", out string? originSymbol) && !string.IsNullOrWhiteSpace(originSymbol))
            {
                string trimmed = originSymbol.Trim();
                int plus = trimmed.IndexOf('+');
                if (plus > 0)
                {
                    trimmed = trimmed[..plus].Trim();
                }

                if (!IsInternalHookFrame(null, trimmed))
                {
                    return trimmed;
                }
            }

            for (int i = 0; i < Math.Min((int)view.StackCount, BlackbirdNative.MaxIpcStackFrames); i += 1)
            {
                string pathKey = $"stack{i}Path";
                string symbolKey = $"stack{i}Symbol";
                string? pathValue = null;

                if (fields.TryGetValue(pathKey, out string? resolvedPath) && !string.IsNullOrWhiteSpace(resolvedPath))
                {
                    pathValue = resolvedPath.Trim();
                    if (!IsInternalHookFrame(pathValue))
                    {
                        string moduleFromPath = EventDetailFormatting.ModuleNameFromPath(pathValue);
                        if (!string.Equals(moduleFromPath, "unknown", StringComparison.OrdinalIgnoreCase))
                        {
                            return moduleFromPath;
                        }
                    }
                }

                if (fields.TryGetValue(symbolKey, out string? symbolValue) &&
                    !string.IsNullOrWhiteSpace(symbolValue) &&
                    !IsInternalHookFrame(pathValue, symbolValue))
                {
                    string trimmed = symbolValue.Trim();
                    int plus = trimmed.IndexOf('+');
                    if (plus > 0)
                    {
                        trimmed = trimmed[..plus].Trim();
                    }

                    if (!string.IsNullOrWhiteSpace(trimmed))
                    {
                        return trimmed;
                    }
                }
            }

            return originModule;
        }

        private static string ResolveHookReturnAddressLabel(BrokerEtwEventView view,
                                                            IReadOnlyDictionary<string, string> fields,
                                                            string originModule)
        {
            ulong[] stack = view.Stack ?? Array.Empty<ulong>();

            if (fields.TryGetValue("originSymbol", out string? originSymbol) && !string.IsNullOrWhiteSpace(originSymbol))
            {
                string trimmed = originSymbol.Trim();
                if (!IsInternalHookFrame(null, trimmed))
                {
                    return trimmed;
                }
            }

            for (int i = 0; i < Math.Min((int)view.StackCount, BlackbirdNative.MaxIpcStackFrames); i += 1)
            {
                if (stack.Length <= i || stack[i] != view.OriginAddress)
                {
                    continue;
                }

                string symbolKey = $"stack{i}Symbol";
                if (fields.TryGetValue(symbolKey, out string? stackSymbol) && !string.IsNullOrWhiteSpace(stackSymbol))
                {
                    return stackSymbol.Trim();
                }
            }

            if (!string.IsNullOrWhiteSpace(originModule) &&
                !originModule.Equals("unknown", StringComparison.OrdinalIgnoreCase) && view.OriginAddress != 0)
            {
                return $"{originModule}!0x{view.OriginAddress:X}";
            }

            return string.Empty;
        }

        private static string BuildHookFrameSummary(IReadOnlyDictionary<string, string> fields)
        {
            var view = new BrokerEtwEventView();
            if (fields.TryGetValue("originPath", out string? originPath))
            {
                view.OriginPath = originPath;
            }
            if (fields.TryGetValue("kind", out string? kind) &&
                string.Equals(kind, "kernel_ntapi", StringComparison.OrdinalIgnoreCase))
            {
                view.Source = "BK";
                view.SourceId = BlackbirdNative.IpcEtwSourceBlackbird;
                view.Family = BlackbirdNative.IpcEtwFamilyUserHook;
            }

            return BuildHookFrameSummaryCore(view, fields);
        }

        private string FormatApiProcessLabel(uint pid)
        {
            if (pid == 0)
            {
                return string.Empty;
            }

            string processName = GetApiGraphProcessName(pid);
            return string.IsNullOrWhiteSpace(processName)
                       ? pid.ToString(CultureInfo.InvariantCulture)
                       : $"{processName} ({pid.ToString(CultureInfo.InvariantCulture)})";
        }

        private string FormatApiTargetLabel(uint sourcePid, uint targetPid) =>
            sourcePid != 0 && targetPid != 0 && sourcePid == targetPid ? "self" : FormatApiProcessLabel(targetPid);

        private static string FormatApiRelativeAge(DateTime lastSeenUtc)
        {
            if (lastSeenUtc == default)
            {
                return string.Empty;
            }

            TimeSpan age = DateTime.UtcNow - lastSeenUtc;
            if (age < TimeSpan.Zero)
            {
                age = TimeSpan.Zero;
            }

            if (age.TotalSeconds >= 1)
            {
                return $"{age.TotalSeconds:0.0}s ago";
            }

            return $"{Math.Max(0, age.TotalMilliseconds):0} ms ago";
        }

        private (string Action, string Detail) BuildApiDecodedAction(BrokerEtwEventView view, string rawReason)
        {
            string apiName = !string.IsNullOrWhiteSpace(view.Operation) ? view.Operation : view.EventName;
            if (string.IsNullOrWhiteSpace(apiName))
            {
                apiName = "unknown";
            }

            Dictionary<string, string> fields = BuildHookFieldMap(view);
            string action = BuildGenericApiActionLabel(apiName, fields);
            string detail;
            string argumentText = BuildResolvedHookArgumentsText(apiName, view, fields);
            bool hasExecutionContext =
                TryDescribeHookExecutionContext(view, fields, out string contextHeadline, out string contextDetail);

            if (TryBuildMemoryAction(apiName, view, fields, out string memoryAction, out string memoryDetail))
            {
                action = memoryAction;
                string frameSummary = BuildHookFrameSummary(view, fields);
                var detailBuilder = new StringBuilder(memoryDetail.TrimEnd());
                if (!string.IsNullOrWhiteSpace(frameSummary))
                {
                    detailBuilder.AppendLine().AppendLine().Append(frameSummary);
                }
                if (!string.IsNullOrWhiteSpace(argumentText))
                {
                    detailBuilder.AppendLine().AppendLine().Append(argumentText);
                }
                detail = detailBuilder.ToString();
                if (hasExecutionContext)
                {
                    if (contextHeadline.Equals("Loader / Image Mapping", StringComparison.OrdinalIgnoreCase))
                    {
                        action += " [loader]";
                    }
                    else if (contextHeadline.Equals("Kernel Caller", StringComparison.OrdinalIgnoreCase))
                    {
                        action += " [kernel]";
                    }

                    detail =
                        $"{contextHeadline}{Environment.NewLine}{contextDetail}{Environment.NewLine}{Environment.NewLine}{detail}";
                }
            }
            else
            {
                var sb = new StringBuilder(512);
                sb.AppendLine(action);
                if (hasExecutionContext)
                {
                    if (contextHeadline.Equals("Loader / Image Mapping", StringComparison.OrdinalIgnoreCase))
                    {
                        action += " [loader]";
                    }
                    else if (contextHeadline.Equals("Kernel Caller", StringComparison.OrdinalIgnoreCase))
                    {
                        action += " [kernel]";
                    }
                    else if (contextHeadline.Contains("Startup", StringComparison.OrdinalIgnoreCase))
                    {
                        action += " [startup]";
                    }

                    sb.AppendLine().AppendLine(contextHeadline);
                    sb.AppendLine(contextDetail);
                }
                string frameSummary = BuildHookFrameSummary(view, fields);
                if (!string.IsNullOrWhiteSpace(frameSummary))
                {
                    sb.AppendLine().AppendLine(frameSummary);
                }
                if (!string.IsNullOrWhiteSpace(argumentText))
                {
                    sb.AppendLine().AppendLine(argumentText);
                }
                string contextText = BuildGenericEtwDisplayDetail(view, fields, includeHeadline: false);
                if (!string.IsNullOrWhiteSpace(contextText))
                {
                    sb.AppendLine().Append(contextText);
                }
                detail = sb.ToString().Trim();
            }

            return (action, detail);
        }
    }
}
