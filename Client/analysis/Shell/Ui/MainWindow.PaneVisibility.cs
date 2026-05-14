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
        private void HideEventsPane()
        {
            _eventsPaneVisible = false;
            ApplyDockVisibilityFromExplorer();
        }

        private void ShowEventsPane()
        {
            _eventsPaneVisible = true;
            ApplyDockVisibilityFromExplorer();
        }

        private void HidePerformancePane()
        {
            _performancePaneVisible = false;
            ApplyDockVisibilityFromExplorer();
        }

        private void HideEtwPane()
        {
            var sw = FindExplorerItem("ETW");
            if (sw != null)
                sw.IsEnabled = false;
            ApplyDockVisibilityFromExplorer();
        }

        private void HideHeuristicsPane()
        {
            var heur = FindExplorerItem("Heuristics");
            if (heur != null)
                heur.IsEnabled = false;
            ApplyDockVisibilityFromExplorer();
        }

        private void HideFilesystemPane()
        {
            var fs = FindExplorerItem("Filesystem");
            if (fs != null)
                fs.IsEnabled = false;
            ApplyDockVisibilityFromExplorer();
        }

        private void HideRegistryPane()
        {
            var reg = FindExplorerItem("Registry");
            if (reg != null)
                reg.IsEnabled = false;
            ApplyDockVisibilityFromExplorer();
        }

        private void HideProcessRelationsPane()
        {
            var rel = FindExplorerItem("Process Relations");
            if (rel != null)
                rel.IsEnabled = false;
            ApplyDockVisibilityFromExplorer();
        }

        private void SetExplorerPaneEnabled(string name, bool enabled)
        {
            var item = FindExplorerItem(name);
            if (item != null)
            {
                item.IsEnabled = enabled;
            }
        }

        private void ShowEtwPane()
        {
            SetExplorerPaneEnabled("ETW", true);
            ApplyDockVisibilityFromExplorer();
        }

        private void ShowHeuristicsPane()
        {
            SetExplorerPaneEnabled("Heuristics", true);
            ApplyDockVisibilityFromExplorer();
        }

        private void ShowFilesystemPane()
        {
            SetExplorerPaneEnabled("Filesystem", true);
            ApplyDockVisibilityFromExplorer();
        }

        private void ShowRegistryPane()
        {
            SetExplorerPaneEnabled("Registry", true);
            ApplyDockVisibilityFromExplorer();
        }

        private void ShowProcessRelationsPane()
        {
            SetExplorerPaneEnabled("Process Relations", true);
            ApplyDockVisibilityFromExplorer();
        }

        private void ShowPerformancePane()
        {
            _performancePaneVisible = true;
            ApplyDockVisibilityFromExplorer();
        }

        private void CollapsedEventsBar_MouseLeftButtonUp(object sender, MouseButtonEventArgs e)
        {
            ShowEventsPane();
            e.Handled = true;
        }

        private void CollapsedPerformanceBar_MouseLeftButtonUp(object sender, MouseButtonEventArgs e)
        {
            ShowPerformancePane();
            e.Handled = true;
        }

        private void CollapseOrExpandPane()
        {
            if (_eventsPaneVisible)
                HideEventsPane();
            else
                ShowEventsPane();
        }

        private void CollapseOrExpandPerformancePane()
        {
            if (_performancePaneVisible)
                HidePerformancePane();
            else
                ShowPerformancePane();
        }
    }
}
