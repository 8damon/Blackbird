using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;

namespace BlackbirdInterface
{
    public partial class InterfaceSettingsWindow : Window
    {
        private readonly MainWindow _host;
        private readonly ObservableCollection<ShortcutBindingRow> _rows = new();
        private readonly ObservableCollection<string> _directPdbFiles = new();
        private readonly ObservableCollection<string> _pdbDirectories = new();
        private ShortcutBindingRow? _capturingRow;

        public InterfaceSettingsWindow(MainWindow host, UiThemeMode themeMode, IEnumerable<ShortcutBindingRow> rows,
                                       InterfacePreferences preferences, SymbolSettings symbolSettings)
        {
            InitializeComponent();
            _host = host ?? throw new ArgumentNullException(nameof(host));
            WindowThemeHelper.WireThemeAwareTitleBar(this);

            ShortcutGrid.ItemsSource = _rows;
            DirectPdbFilesList.ItemsSource = _directPdbFiles;
            PdbDirectoriesList.ItemsSource = _pdbDirectories;
            foreach (ShortcutBindingRow row in rows.Select(static row => row.Clone()))
            {
                _rows.Add(row);
            }

            SetThemeSelection(themeMode);
            SetPreferenceSelection(preferences);
            SetSymbolSelection(symbolSettings);
            UpdateCaptureStatus();
        }

        private void Root_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
        {
            WindowChromeBehavior.HandleRootDragMove(this, e);
        }

        private void ThemeModeBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            _ = sender;
            _ = e;
        }

        private void RebindShortcut_Click(object sender, RoutedEventArgs e)
        {
            if ((sender as FrameworkElement)?.Tag is not ShortcutBindingRow row)
            {
                return;
            }

            _capturingRow = row;
            UpdateCaptureStatus();
            ShortcutGrid.SelectedItem = row;
            Focus();
        }

        private void ClearShortcut_Click(object sender, RoutedEventArgs e)
        {
            if ((sender as FrameworkElement)?.Tag is not ShortcutBindingRow row)
            {
                return;
            }

            row.GestureText = string.Empty;
            if (ReferenceEquals(_capturingRow, row))
            {
                _capturingRow = null;
            }
            UpdateCaptureStatus();
        }

        private void ResetShortcut_Click(object sender, RoutedEventArgs e)
        {
            if ((sender as FrameworkElement)?.Tag is not ShortcutBindingRow row)
            {
                return;
            }

            row.GestureText = row.DefaultGestureText;
            if (ReferenceEquals(_capturingRow, row))
            {
                _capturingRow = null;
            }
            UpdateCaptureStatus();
        }

        private void Defaults_Click(object sender, RoutedEventArgs e)
        {
            _ = sender;
            _ = e;
            foreach (ShortcutBindingRow row in _rows)
            {
                row.GestureText = row.DefaultGestureText;
            }

            SetThemeSelection(UiThemeMode.Dark);
            SetPreferenceSelection(InterfacePreferences.Defaults());
            SetSymbolSelection(SymbolSettings.Defaults());
            _capturingRow = null;
            UpdateCaptureStatus();
        }

        private void Apply_Click(object sender, RoutedEventArgs e)
        {
            _ = sender;
            _ = e;
            ApplySettings();
        }

        private void Close_Click(object sender, RoutedEventArgs e)
        {
            _ = sender;
            _ = e;
            Close();
        }

        private void Window_PreviewKeyDown(object sender, KeyEventArgs e)
        {
            _ = sender;
            if (_capturingRow == null)
            {
                return;
            }

            if (e.Key == Key.Escape)
            {
                _capturingRow = null;
                UpdateCaptureStatus();
                e.Handled = true;
                return;
            }

            if (e.Key == Key.Back || e.Key == Key.Delete)
            {
                _capturingRow.GestureText = string.Empty;
                _capturingRow = null;
                UpdateCaptureStatus();
                e.Handled = true;
                return;
            }

            if (!TryBuildGestureText(e, out string gestureText))
            {
                e.Handled = true;
                return;
            }

            foreach (ShortcutBindingRow row in _rows)
            {
                if (!ReferenceEquals(row, _capturingRow) &&
                    string.Equals(row.GestureText, gestureText, StringComparison.OrdinalIgnoreCase))
                {
                    row.GestureText = string.Empty;
                }
            }

            _capturingRow.GestureText = gestureText;
            _capturingRow = null;
            UpdateCaptureStatus();
            e.Handled = true;
        }

        protected override void OnClosing(CancelEventArgs e)
        {
            ApplySettings();
            base.OnClosing(e);
        }

        private void ApplySettings()
        {
            _host.ApplyInterfaceSettings(GetSelectedThemeMode(),
                                         _rows.ToDictionary(static row => row.Id, static row => row.GestureText,
                                                            StringComparer.OrdinalIgnoreCase),
                                         GetSelectedPreferences(),
                                         GetSelectedSymbolSettings());
        }

        private UiThemeMode GetSelectedThemeMode()
        {
            string? tag = (ThemeModeBox.SelectedItem as ComboBoxItem)?.Tag as string;
            return Enum.TryParse(tag, ignoreCase: true, out UiThemeMode mode) ? mode : UiThemeMode.Dark;
        }

        private void SetThemeSelection(UiThemeMode mode)
        {
            foreach (object item in ThemeModeBox.Items)
            {
                if (item is ComboBoxItem comboItem && comboItem.Tag is string tag &&
                    string.Equals(tag, mode.ToString(), StringComparison.OrdinalIgnoreCase))
                {
                    ThemeModeBox.SelectedItem = comboItem;
                    return;
                }
            }

            ThemeModeBox.SelectedIndex = 1;
        }

        private InterfacePreferences GetSelectedPreferences()
        {
            return new InterfacePreferences { AutoSwitchToApiViewOnHookLaunch =
                                                  AutoSwitchApiViewCheckBox?.IsChecked == true,
                                              ShowEventsPane = ShowEventsPaneCheckBox?.IsChecked == true,
                                              ShowPerformancePane = ShowPerformancePaneCheckBox?.IsChecked == true,
                                              ShowEtwPane = ShowEtwPaneCheckBox?.IsChecked == true,
                                              ShowDetectionsPane = ShowDetectionsPaneCheckBox?.IsChecked == true,
                                              ShowFilesystemPane = ShowFilesystemPaneCheckBox?.IsChecked == true,
                                              ShowRegistryPane = ShowRegistryPaneCheckBox?.IsChecked == true,
                                              ShowProcessRelationsPane =
                                                  ShowProcessRelationsPaneCheckBox?.IsChecked == true,
                                              PerformancePaneOnTop = PerformanceOnTopCheckBox?.IsChecked == true,
                                              DetectionsPaneOnTop = DetectionsOnTopCheckBox?.IsChecked == true,
                                              DefaultApiPresentationMode = GetSelectedApiPresentationMode() };
        }

        private void SetPreferenceSelection(InterfacePreferences? preferences)
        {
            InterfacePreferences selection = (preferences ?? InterfacePreferences.Defaults()).Clone();
            if (AutoSwitchApiViewCheckBox != null)
            {
                AutoSwitchApiViewCheckBox.IsChecked = selection.AutoSwitchToApiViewOnHookLaunch;
            }
            if (ShowEventsPaneCheckBox != null)
            {
                ShowEventsPaneCheckBox.IsChecked = selection.ShowEventsPane;
            }
            if (ShowPerformancePaneCheckBox != null)
            {
                ShowPerformancePaneCheckBox.IsChecked = selection.ShowPerformancePane;
            }
            if (ShowEtwPaneCheckBox != null)
            {
                ShowEtwPaneCheckBox.IsChecked = selection.ShowEtwPane;
            }
            if (ShowDetectionsPaneCheckBox != null)
            {
                ShowDetectionsPaneCheckBox.IsChecked = selection.ShowDetectionsPane;
            }
            if (ShowFilesystemPaneCheckBox != null)
            {
                ShowFilesystemPaneCheckBox.IsChecked = selection.ShowFilesystemPane;
            }
            if (ShowRegistryPaneCheckBox != null)
            {
                ShowRegistryPaneCheckBox.IsChecked = selection.ShowRegistryPane;
            }
            if (ShowProcessRelationsPaneCheckBox != null)
            {
                ShowProcessRelationsPaneCheckBox.IsChecked = selection.ShowProcessRelationsPane;
            }
            if (PerformanceOnTopCheckBox != null)
            {
                PerformanceOnTopCheckBox.IsChecked = selection.PerformancePaneOnTop;
            }
            if (DetectionsOnTopCheckBox != null)
            {
                DetectionsOnTopCheckBox.IsChecked = selection.DetectionsPaneOnTop;
            }

            SetApiPresentationSelection(selection.DefaultApiPresentationMode);
        }

        private string GetSelectedApiPresentationMode()
        {
            string? tag = (DefaultApiPresentationBox?.SelectedItem as ComboBoxItem)?.Tag as string;
            return AnalystSettingsStore.NormalizeApiPresentation(tag);
        }

        private void SetApiPresentationSelection(string mode)
        {
            string normalized = AnalystSettingsStore.NormalizeApiPresentation(mode);
            if (DefaultApiPresentationBox == null)
            {
                return;
            }

            foreach (object item in DefaultApiPresentationBox.Items)
            {
                if (item is ComboBoxItem comboItem && comboItem.Tag is string tag &&
                    string.Equals(tag, normalized, StringComparison.OrdinalIgnoreCase))
                {
                    DefaultApiPresentationBox.SelectedItem = comboItem;
                    return;
                }
            }

            DefaultApiPresentationBox.SelectedIndex = 0;
        }

        private SymbolSettings GetSelectedSymbolSettings()
        {
            var settings = new SymbolSettings {
                EnablePdbResolution = EnablePdbResolutionCheckBox?.IsChecked == true,
                AllowMicrosoftSymbolServer = AllowMicrosoftSymbolServerCheckBox?.IsChecked == true,
                SymbolServerUrl = SymbolSettings.NormalizeServerUrl(SymbolServerUrlTextBox?.Text),
                SymbolCacheDirectory = SymbolSettings.NormalizeDirectory(SymbolCacheDirectoryTextBox?.Text,
                                                                         SymbolSettings.DefaultCacheDirectory())
            };
            settings.DirectPdbFiles.AddRange(SymbolSettings.NormalizePaths(_directPdbFiles));
            settings.PdbDirectories.AddRange(SymbolSettings.NormalizePaths(_pdbDirectories));
            return settings;
        }

        private void SetSymbolSelection(SymbolSettings? settings)
        {
            SymbolSettings selection = (settings ?? SymbolSettings.Defaults()).Clone();
            if (EnablePdbResolutionCheckBox != null)
            {
                EnablePdbResolutionCheckBox.IsChecked = selection.EnablePdbResolution;
            }
            if (AllowMicrosoftSymbolServerCheckBox != null)
            {
                AllowMicrosoftSymbolServerCheckBox.IsChecked = selection.AllowMicrosoftSymbolServer;
            }
            if (SymbolServerUrlTextBox != null)
            {
                SymbolServerUrlTextBox.Text = SymbolSettings.NormalizeServerUrl(selection.SymbolServerUrl);
            }
            if (SymbolCacheDirectoryTextBox != null)
            {
                SymbolCacheDirectoryTextBox.Text = selection.NormalizedCacheDirectory;
            }

            _directPdbFiles.Clear();
            foreach (string path in SymbolSettings.NormalizePaths(selection.DirectPdbFiles))
            {
                _directPdbFiles.Add(path);
            }

            _pdbDirectories.Clear();
            foreach (string path in SymbolSettings.NormalizePaths(selection.PdbDirectories))
            {
                _pdbDirectories.Add(path);
            }
        }

        private void AddDirectPdb_Click(object sender, RoutedEventArgs e)
        {
            _ = sender;
            _ = e;
            var dialog = new OpenFileDialog {
                Filter = "Program database (*.pdb)|*.pdb|All files (*.*)|*.*",
                CheckFileExists = true,
                Multiselect = true
            };
            if (dialog.ShowDialog(this) != true)
            {
                return;
            }

            foreach (string file in dialog.FileNames)
            {
                AddUnique(_directPdbFiles, file);
            }
        }

        private void RemoveDirectPdb_Click(object sender, RoutedEventArgs e)
        {
            _ = sender;
            _ = e;
            RemoveSelectedItems(DirectPdbFilesList, _directPdbFiles);
        }

        private void AddPdbDirectory_Click(object sender, RoutedEventArgs e)
        {
            _ = sender;
            _ = e;
            var dialog = new OpenFolderDialog { Multiselect = false };
            if (dialog.ShowDialog(this) == true)
            {
                AddUnique(_pdbDirectories, dialog.FolderName);
            }
        }

        private void RemovePdbDirectory_Click(object sender, RoutedEventArgs e)
        {
            _ = sender;
            _ = e;
            RemoveSelectedItems(PdbDirectoriesList, _pdbDirectories);
        }

        private void BrowseSymbolCache_Click(object sender, RoutedEventArgs e)
        {
            _ = sender;
            _ = e;
            var dialog = new OpenFolderDialog { Multiselect = false };
            if (!string.IsNullOrWhiteSpace(SymbolCacheDirectoryTextBox?.Text))
            {
                dialog.InitialDirectory = SymbolCacheDirectoryTextBox.Text.Trim();
            }

            if (dialog.ShowDialog(this) == true && SymbolCacheDirectoryTextBox != null)
            {
                SymbolCacheDirectoryTextBox.Text = dialog.FolderName;
            }
        }

        private static void AddUnique(ObservableCollection<string> collection, string path)
        {
            string trimmed = (path ?? string.Empty).Trim();
            if (trimmed.Length == 0 ||
                collection.Any(existing => string.Equals(existing, trimmed, StringComparison.OrdinalIgnoreCase)))
            {
                return;
            }

            collection.Add(trimmed);
        }

        private static void RemoveSelectedItems(ListBox listBox, ObservableCollection<string> collection)
        {
            foreach (string item in listBox.SelectedItems.Cast<string>().ToList())
            {
                collection.Remove(item);
            }
        }

        private void UpdateCaptureStatus()
        {
            if (_capturingRow == null)
            {
                CaptureStatusBlock.Text =
                    "Select Rebind, then press the new shortcut. Escape cancels. Backspace clears.";
                return;
            }

            CaptureStatusBlock.Text = $"Press a new shortcut for {_capturingRow.Label}.";
        }

        private static bool TryBuildGestureText(KeyEventArgs e, out string gestureText)
        {
            gestureText = string.Empty;
            Key key = e.Key == Key.System ? e.SystemKey : e.Key;
            if (key is Key.LeftCtrl or Key.RightCtrl or Key.LeftAlt or Key.RightAlt or Key.LeftShift or
                    Key.RightShift or Key.LWin or Key.RWin)
            {
                return false;
            }

            ModifierKeys modifiers = Keyboard.Modifiers;
            if (modifiers == ModifierKeys.None &&
                key is not Key.F1 and not Key.F2 and not Key.F3 and not Key.F4 and not Key.F5 and not Key.F6 and not
                    Key.F7 and not Key.F8 and not Key.F9 and not Key.F10 and not Key.F11 and not Key.F12)
            {
                return false;
            }

            gestureText = new KeyGesture(key, modifiers)
                              .GetDisplayStringForCulture(System.Globalization.CultureInfo.InvariantCulture);
            return !string.IsNullOrWhiteSpace(gestureText);
        }
    }

    public sealed class ShortcutBindingRow : INotifyPropertyChanged
    {
        private string _gestureText = string.Empty;

        public required string Id { get; init; }
        public required string Label { get; init; }
        public required string Description { get; init; }
        public required string DefaultGestureText { get; init; }

        public string GestureText
        {
            get => _gestureText;
            set {
                if (string.Equals(_gestureText, value, StringComparison.Ordinal))
                {
                    return;
                }

                _gestureText = value ?? string.Empty;
                OnPropertyChanged();
                OnPropertyChanged(nameof(RebindButtonText));
            }
        }

        public string RebindButtonText => string.IsNullOrWhiteSpace(GestureText) ? "Bind" : "Rebind";

        public event PropertyChangedEventHandler? PropertyChanged;

        public ShortcutBindingRow Clone()
        {
            return new ShortcutBindingRow { Id = Id, Label = Label, Description = Description,
                                            DefaultGestureText = DefaultGestureText, GestureText = GestureText };
        }

        private void OnPropertyChanged([CallerMemberName] string? propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }
}
