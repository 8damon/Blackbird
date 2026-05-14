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
        private void OpenOrActivateEventLogWindow()
        {
            if (_eventLogWindow == null)
            {
                UndockEventLog();
                return;
            }

            if (_eventLogWindow.WindowState == WindowState.Minimized)
            {
                _eventLogWindow.WindowState = WindowState.Normal;
            }
            _eventLogWindow.Activate();
        }

        private void SetMainInterfaceViewMode(MainInterfaceViewMode mode)
        {
            _mainViewMode = mode;
            if (DockGrid != null)
            {
                DockGrid.Visibility =
                    mode == MainInterfaceViewMode.Telemetry ? Visibility.Visible : Visibility.Collapsed;
            }
            if (ApiViewBorder != null)
            {
                ApiViewBorder.Visibility =
                    mode == MainInterfaceViewMode.Api ? Visibility.Visible : Visibility.Collapsed;
            }
            if (ExtendedViewBorder != null)
            {
                ExtendedViewBorder.Visibility =
                    mode == MainInterfaceViewMode.Extended ? Visibility.Visible : Visibility.Collapsed;
            }
            ApplyDockVisibilityFromExplorer();
            UpdateMainViewButtons(mode);

            if (IsLoaded)
            {
                RebuildToolbarViewMenuOptions();
            }
        }

        private void UpdateMainViewButtons(MainInterfaceViewMode mode)
        {
            SetMainViewButtonSelected(MainViewButton, mode == MainInterfaceViewMode.Telemetry);
            SetMainViewButtonSelected(ApiViewButton, mode == MainInterfaceViewMode.Api);
            SetMainViewButtonSelected(ExtendedViewButton, mode == MainInterfaceViewMode.Extended);
        }

        private static void SetMainViewButtonSelected(Button? button, bool selected)
        {
            if (button == null)
            {
                return;
            }
            button.IsEnabled = !selected;
            button.Opacity = selected ? 0.72 : 1.0;
        }

        private void MainView_Click(object sender, RoutedEventArgs e)
        {
            _ = sender;
            _ = e;
            SetMainInterfaceViewMode(MainInterfaceViewMode.Telemetry);
        }

        private void ApiView_Click(object sender, RoutedEventArgs e)
        {
            _ = sender;
            _ = e;
            SetMainInterfaceViewMode(MainInterfaceViewMode.Api);
        }

        private void ExtendedView_Click(object sender, RoutedEventArgs e)
        {
            _ = sender;
            _ = e;
            SetMainInterfaceViewMode(MainInterfaceViewMode.Extended);
        }

        private void OpenDiagnosticsWindow()
        {
            var w = new DiagnosticsWindow(TryGetPid()) { Owner = this };
            w.Show();
        }

        private void SignatureIntelRules_Click(object sender, RoutedEventArgs e)
        {
            _ = sender;
            _ = e;
            OpenSignatureIntelRulesWindow();
        }
    }
}
