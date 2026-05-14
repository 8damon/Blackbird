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
        private void SetupExplorer()
        {
            _explorer.Clear();

            _explorer.Add(new GraphExplorerItem(
                "Events", new SolidColorBrush(Color.FromRgb(0xAA, 0x7D, 0x4A))) { IsEnabled = true });
            _explorer.Add(new GraphExplorerItem(
                "Performance", new SolidColorBrush(Color.FromRgb(0x58, 0xB6, 0x58))) { IsEnabled = true });
            _explorer.Add(new GraphExplorerItem(
                "ETW", new SolidColorBrush(Color.FromRgb(0xD2, 0x89, 0x34))) { IsEnabled = true });
            _explorer.Add(new GraphExplorerItem("Heuristics", new SolidColorBrush(Color.FromRgb(0xD2, 0x55, 0x55)),
                                                "Detections") { IsEnabled = true });
            _explorer.Add(new GraphExplorerItem(
                "Filesystem", new SolidColorBrush(Color.FromRgb(0x45, 0x8E, 0x7A))) { IsEnabled = true });
            _explorer.Add(new GraphExplorerItem(
                "Registry", new SolidColorBrush(Color.FromRgb(0x7A, 0x5E, 0xA8))) { IsEnabled = true });
            _explorer.Add(new GraphExplorerItem(
                "Process Relations", new SolidColorBrush(Color.FromRgb(0xD2, 0xB8, 0x55))) { IsEnabled = true });

            GraphExplorer.ItemsSource = _explorer;

            foreach (var item in _explorer)
            {
                item.PropertyChanged += (_, args) =>
                {
                    if (string.Equals(args.PropertyName, nameof(GraphExplorerItem.IsEnabled), StringComparison.Ordinal))
                    {
                        ApplyDockVisibilityFromExplorer();
                    }
                };
            }

            RefreshExplorerDataBadges();
            ApplyDockVisibilityFromExplorer();
        }

        private GraphExplorerItem? FindExplorerItem(string name) =>
            _explorer.FirstOrDefault(x => string.Equals(x.Name, name, StringComparison.OrdinalIgnoreCase));

        private void SetExplorerHasData(string name, bool hasData)
        {
            var item = FindExplorerItem(name);
            if (item != null)
            {
                item.HasData = hasData;
                if (!hasData)
                {
                    item.ClearPreviewValues();
                }
            }
        }

        private void RefreshExplorerDataBadges()
        {
            SetExplorerHasData("Events", _allEvents.Count > 0);
            SetExplorerHasData("Performance",
                               _hasPerformanceData || (_currentSession?.PerformanceHistory.Count ?? 0) > 0);
            SetExplorerHasData("ETW", EtwPaneHost.ItemCount > 0);
            SetExplorerHasData("Heuristics", HeuristicsPaneHost.ItemCount > 0);
            SetExplorerHasData("Filesystem", FilesystemPaneHost.ItemCount > 0);
            SetExplorerHasData("Process Relations", ProcessRelationsPaneHost.ItemCount > 0);
        }

        private void ApplyDockVisibilityFromExplorer()
        {
            bool showEvents = _explorer.FirstOrDefault(x => x.Name == "Events")?.IsEnabled ?? true;
            bool showPerf = _explorer.FirstOrDefault(x => x.Name == "Performance")?.IsEnabled ?? true;
            bool showEtw = _explorer.FirstOrDefault(x => x.Name == "ETW")?.IsEnabled ?? true;
            bool showHeuristics = _explorer.FirstOrDefault(x => x.Name == "Heuristics")?.IsEnabled ?? true;
            bool showFilesystem = _explorer.FirstOrDefault(x => x.Name == "Filesystem")?.IsEnabled ?? true;
            bool showRegistry = _explorer.FirstOrDefault(x => x.Name == "Registry")?.IsEnabled ?? true;
            bool showRelations = _explorer.FirstOrDefault(x => x.Name == "Process Relations")?.IsEnabled ?? true;

            if (!showEvents && _eventsFloatWindow != null)
                _eventsFloatWindow.Close();
            if (!showEvents && _eventLogWindow != null)
                _eventLogWindow.Close();
            if (!showPerf && _performanceFloatWindow != null)
                _performanceFloatWindow.Close();
            if (!showEtw && _etwFloatWindow != null)
                _etwFloatWindow.Close();
            if (!showHeuristics && _heuristicsFloatWindow != null)
                _heuristicsFloatWindow.Close();

            bool showEventsContent = showEvents && _eventsPaneVisible && !_eventsPaneFloating;
            bool showPerformanceContent = showPerf && _performancePaneVisible && !_performancePaneFloating;
            bool showEtwContent = showEtw && !_etwPaneFloating;
            bool showHeuristicsContent = showHeuristics && !_heuristicsPaneFloating;
            bool showFilesystemContent = showFilesystem;
            bool showRegistryContent = showRegistry;
            bool showRelationsContent = showRelations;

            EventsDockBorder.Visibility = showEventsContent ? Visibility.Visible : Visibility.Collapsed;
            PerformanceDockBorder.Visibility = showPerformanceContent ? Visibility.Visible : Visibility.Collapsed;

            CollapsedEventsBar.Visibility =
                (showEvents && !_eventsPaneVisible && !_eventsPaneFloating) ? Visibility.Visible : Visibility.Collapsed;
            CollapsedPerformanceBar.Visibility = (showPerf && !_performancePaneVisible && !_performancePaneFloating)
                                                     ? Visibility.Visible
                                                     : Visibility.Collapsed;

            DockGrid.RowDefinitions[0].Height =
                showEvents ? (_eventsPaneFloating
                                  ? new GridLength(0)
                                  : (_eventsPaneVisible ? new GridLength(4, GridUnitType.Star) : new GridLength(28)))
                           : new GridLength(0);

            DockGrid.RowDefinitions[2].Height =
                showPerf ? (_performancePaneFloating
                                ? new GridLength(0)
                                : (_performancePaneVisible ? new GridLength(5, GridUnitType.Star) : new GridLength(28)))
                         : new GridLength(0);

            DockGrid.RowDefinitions[1].Height =
                (showEventsContent && showPerformanceContent) ? new GridLength(2) : new GridLength(0);

            EtwDockBorder.Visibility = showEtwContent ? Visibility.Visible : Visibility.Collapsed;
            HeuristicsDockBorder.Visibility = showHeuristicsContent ? Visibility.Visible : Visibility.Collapsed;
            FilesystemDockBorder.Visibility = showFilesystemContent ? Visibility.Visible : Visibility.Collapsed;
            RegistryDockBorder.Visibility = showRegistryContent ? Visibility.Visible : Visibility.Collapsed;
            ProcessRelationsDockBorder.Visibility = showRelationsContent ? Visibility.Visible : Visibility.Collapsed;

            bool row0Visible = (Grid.GetRow(EtwDockBorder) == 0 && showEtwContent) ||
                               (Grid.GetRow(HeuristicsDockBorder) == 0 && showHeuristicsContent);
            bool row2Visible = (Grid.GetRow(EtwDockBorder) == 2 && showEtwContent) ||
                               (Grid.GetRow(HeuristicsDockBorder) == 2 && showHeuristicsContent);
            bool row4Visible = showFilesystemContent;
            bool row6Visible = showRegistryContent;
            bool row8Visible = showRelationsContent;
            IntelligenceDock.RowDefinitions[0].Height =
                row0Visible ? new GridLength(1, GridUnitType.Star) : new GridLength(0);
            IntelligenceDock.RowDefinitions[2].Height =
                row2Visible ? new GridLength(1, GridUnitType.Star) : new GridLength(0);
            IntelligenceDock.RowDefinitions[4].Height =
                row4Visible ? new GridLength(1, GridUnitType.Star) : new GridLength(0);
            IntelligenceDock.RowDefinitions[6].Height =
                row6Visible ? new GridLength(1, GridUnitType.Star) : new GridLength(0);
            IntelligenceDock.RowDefinitions[8].Height =
                row8Visible ? new GridLength(1, GridUnitType.Star) : new GridLength(0);
            IntelligenceDock.RowDefinitions[1].Height =
                (row0Visible && row2Visible) ? new GridLength(2) : new GridLength(0);
            IntelligenceDock.RowDefinitions[3].Height =
                (row2Visible && row4Visible) ? new GridLength(2) : new GridLength(0);
            IntelligenceDock.RowDefinitions[5].Height =
                (row4Visible && row6Visible) ? new GridLength(2) : new GridLength(0);
            IntelligenceDock.RowDefinitions[7].Height =
                (row6Visible && row8Visible) ? new GridLength(2) : new GridLength(0);

            bool showIntel = row0Visible || row2Visible || row4Visible || row6Visible || row8Visible;
            if (_mainViewMode != MainInterfaceViewMode.Telemetry)
            {
                showIntel = false;
            }
            IntelligenceColumn.Width = showIntel ? new GridLength(560) : new GridLength(0);
            IntelligenceSplitterColumn.Width = showIntel ? new GridLength(2) : new GridLength(0);
            IntelligenceSplitter.Visibility = showIntel ? Visibility.Visible : Visibility.Collapsed;
            IntelligenceDock.Visibility = showIntel ? Visibility.Visible : Visibility.Collapsed;
        }

        private void GraphExplorer_PreviewMouseLeftButtonUp(object sender, MouseButtonEventArgs e)
        {
            var element = e.OriginalSource as DependencyObject;
            if (element == null)
                return;

            var container = ItemsControl.ContainerFromElement(GraphExplorer, element) as ListBoxItem;
            if (container?.DataContext is not GraphExplorerItem item)
                return;

            item.IsEnabled = !item.IsEnabled;
            e.Handled = true;
        }
    }
}
