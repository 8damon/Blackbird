using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows;
using System.Windows.Input;

namespace BlackbirdInterface
{
    public partial class MainWindow
    {
        private sealed record ShortcutDefinition(string Id, string Label, string Description,
                                                 string DefaultGestureText);

        private static readonly ShortcutDefinition[] ShortcutDefinitions = {
            new("timeline_back_10", "Timeline Back 10s", "Move the global timeline 10 seconds backward.",
                "Ctrl+Alt+Left"),
            new("timeline_back_1", "Timeline Back 1s", "Move the global timeline 1 second backward.", "Ctrl+Left"),
            new("timeline_forward_1", "Timeline Forward 1s", "Move the global timeline 1 second forward.",
                "Ctrl+Right"),
            new("timeline_forward_10", "Timeline Forward 10s", "Move the global timeline 10 seconds forward.",
                "Ctrl+Alt+Right"),
            new("open_memory_inspector", "Memory Inspector", "Open or focus the memory allocator inspector window.",
                "Ctrl+Shift+M"),
            new("open_parallel_stacks", "Parallel Stacks", "Open the parallel stacks comparison window.",
                "Ctrl+Shift+T"),
            new("open_lane_settings", "Lane Filters", "Open the lane filter window for the event timeline.",
                "Ctrl+Shift+L"),
            new("open_diagnostics", "Diagnostics", "Open the diagnostics window.", "Ctrl+Shift+D"),
            new("open_interface_settings", "Interface Settings", "Open this settings window.", "Ctrl+Alt+S")
        };

        private readonly Dictionary<string, RoutedUICommand> _shortcutCommands = new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, string> _shortcutBindings = new(StringComparer.OrdinalIgnoreCase);
        private readonly List<InputBinding> _managedShortcutBindings = new();
        private InterfacePreferences _interfacePreferences = InterfacePreferences.Defaults();
        private SymbolSettings _symbolSettings = SymbolSettings.Defaults();
        private InterfaceSettingsWindow? _interfaceSettingsWindow;

        private void InitializeInterfaceSettings()
        {
            _interfacePreferences = AnalystSettingsStore.LoadInterfacePreferences();
            _symbolSettings = AnalystSettingsStore.LoadSymbolSettings();
            EnsureShortcutCommands();
            LoadShortcutBindings();
            ApplyShortcutBindings();
            ApplyInterfacePreferences(_interfacePreferences, persist: false);
        }

        internal void ApplyInterfaceSettings(UiThemeMode mode, IReadOnlyDictionary<string, string> bindings,
                                             InterfacePreferences preferences, SymbolSettings symbolSettings)
        {
            App.SetThemeMode(mode);

            _shortcutBindings.Clear();
            foreach (ShortcutDefinition definition in ShortcutDefinitions)
            {
                if (bindings.TryGetValue(definition.Id, out string? gesture))
                {
                    _shortcutBindings[definition.Id] = gesture ?? string.Empty;
                }
                else
                {
                    _shortcutBindings[definition.Id] = definition.DefaultGestureText;
                }
            }

            AnalystSettingsStore.SaveShortcutBindings(_shortcutBindings);
            ApplyShortcutBindings();
            ApplyInterfacePreferences(preferences, persist: true);
            ApplySymbolSettings(symbolSettings, persist: true);
        }

        private void OpenInterfaceSettings()
        {
            if (_interfaceSettingsWindow != null)
            {
                if (_interfaceSettingsWindow.WindowState == WindowState.Minimized)
                {
                    _interfaceSettingsWindow.WindowState = WindowState.Normal;
                }

                _interfaceSettingsWindow.Activate();
                return;
            }

            _interfaceSettingsWindow = new InterfaceSettingsWindow(
                this,
                App.CurrentThemeMode,
                ShortcutDefinitions.Select(definition => new ShortcutBindingRow
                {
                    Id = definition.Id,
                    Label = definition.Label,
                    Description = definition.Description,
                    DefaultGestureText = definition.DefaultGestureText,
                    GestureText = _shortcutBindings.TryGetValue(definition.Id, out string? gesture)
                        ? gesture
                        : definition.DefaultGestureText
                }),
                SnapshotCurrentInterfacePreferences(),
                _symbolSettings.Clone())
            {
                Owner = this
            };
            _interfaceSettingsWindow.Closed += (_, __) => _interfaceSettingsWindow = null;
            _interfaceSettingsWindow.Show();
        }

        private void InterfaceSettings_Click(object sender, RoutedEventArgs e)
        {
            _ = sender;
            _ = e;
            OpenInterfaceSettings();
        }

        private void EnsureShortcutCommands()
        {
            if (_shortcutCommands.Count != 0)
            {
                return;
            }

            foreach (ShortcutDefinition definition in ShortcutDefinitions)
            {
                var command = new RoutedUICommand(definition.Label, definition.Id, typeof(MainWindow));
                _shortcutCommands[definition.Id] = command;
                CommandBindings.Add(new CommandBinding(command, (_, __) => ExecuteShortcut(definition.Id),
                                                       (_, args) => args.CanExecute = true));
            }
        }

        private void LoadShortcutBindings()
        {
            Dictionary<string, string> storedBindings = AnalystSettingsStore.LoadShortcutBindings();
            _shortcutBindings.Clear();
            foreach (ShortcutDefinition definition in ShortcutDefinitions)
            {
                _shortcutBindings[definition.Id] = storedBindings.TryGetValue(definition.Id, out string? gesture)
                    ? gesture
                    : definition.DefaultGestureText;
            }
        }

        private void ApplyShortcutBindings()
        {
            foreach (InputBinding binding in _managedShortcutBindings)
            {
                InputBindings.Remove(binding);
            }
            _managedShortcutBindings.Clear();

            var converter = new KeyGestureConverter();
            foreach (ShortcutDefinition definition in ShortcutDefinitions)
            {
                if (!_shortcutCommands.TryGetValue(definition.Id, out RoutedUICommand? command))
                {
                    continue;
                }

                if (!_shortcutBindings.TryGetValue(definition.Id, out string? gestureText) ||
                    string.IsNullOrWhiteSpace(gestureText))
                {
                    continue;
                }

                try
                {
                    if (converter.ConvertFromInvariantString(gestureText) is not KeyGesture gesture)
                    {
                        continue;
                    }

                    var binding = new KeyBinding(command, gesture);
                    InputBindings.Add(binding);
                    _managedShortcutBindings.Add(binding);
                }
                catch
                {
                }
            }
        }

        private void ExecuteShortcut(string id)
        {
            switch (id)
            {
            case "timeline_back_10":
                NudgeTopTimeTravel(-10);
                break;
            case "timeline_back_1":
                NudgeTopTimeTravel(-1);
                break;
            case "timeline_forward_1":
                NudgeTopTimeTravel(1);
                break;
            case "timeline_forward_10":
                NudgeTopTimeTravel(10);
                break;
            case "open_memory_inspector":
                break;
            case "open_parallel_stacks":
                ShowPerformancePane();
                OpenParallelStacksWindow();
                break;
            case "open_lane_settings":
                OpenLaneSettings();
                break;
            case "open_diagnostics":
                OpenDiagnosticsWindow();
                break;
            case "open_interface_settings":
                OpenInterfaceSettings();
                break;
            }
        }

        private void ApplyInterfacePreferences(InterfacePreferences preferences, bool persist)
        {
            _interfacePreferences = (preferences ?? InterfacePreferences.Defaults()).Clone();
            ApplyApiPresentationPreference();

            if (_explorer.Count != 0)
            {
                _eventsPaneVisible = _interfacePreferences.ShowEventsPane;
                _performancePaneVisible = _interfacePreferences.ShowPerformancePane;
                SetExplorerPaneEnabled("Events", _interfacePreferences.ShowEventsPane);
                SetExplorerPaneEnabled("Performance", _interfacePreferences.ShowPerformancePane);
                SetExplorerPaneEnabled("ETW", _interfacePreferences.ShowEtwPane);
                SetExplorerPaneEnabled("Heuristics", _interfacePreferences.ShowDetectionsPane);
                SetExplorerPaneEnabled("Filesystem", _interfacePreferences.ShowFilesystemPane);
                SetExplorerPaneEnabled("Registry", _interfacePreferences.ShowRegistryPane);
                SetExplorerPaneEnabled("Process Relations", _interfacePreferences.ShowProcessRelationsPane);
                _performanceOnTop = _interfacePreferences.PerformancePaneOnTop;
                _heuristicsOnTop = _interfacePreferences.DetectionsPaneOnTop;
                ApplyPaneOrder();
                ApplyIntelPaneOrder();
                ApplyDockVisibilityFromExplorer();
                RebuildToolbarViewMenuOptions();
            }

            if (persist)
            {
                AnalystSettingsStore.SaveInterfacePreferences(_interfacePreferences);
            }
        }

        private void ApplyApiPresentationPreference()
        {
            if (ApiViewModeBox == null)
            {
                return;
            }

            string mode =
                AnalystSettingsStore.NormalizeApiPresentation(_interfacePreferences.DefaultApiPresentationMode);
            ApiViewModeBox.SelectedIndex = string.Equals(mode, InterfacePreferences.ApiPresentationThreadTimeline,
                                                         StringComparison.OrdinalIgnoreCase)
                                               ? 1
                                               : 0;
        }

        private bool ShouldAutoSwitchToApiViewForHookCapture() => _interfacePreferences.AutoSwitchToApiViewOnHookLaunch;

        private InterfacePreferences SnapshotCurrentInterfacePreferences()
        {
            InterfacePreferences snapshot = _interfacePreferences.Clone();
            snapshot.ShowEventsPane = IsEventsPaneOpen();
            snapshot.ShowPerformancePane = IsPerformancePaneOpen();
            snapshot.ShowEtwPane = IsEtwPaneOpen();
            snapshot.ShowDetectionsPane = IsHeuristicsPaneOpen();
            snapshot.ShowFilesystemPane = IsFilesystemPaneOpen();
            snapshot.ShowRegistryPane = IsRegistryPaneOpen();
            snapshot.ShowProcessRelationsPane = IsRelationsPaneOpen();
            snapshot.PerformancePaneOnTop = _performanceOnTop;
            snapshot.DetectionsPaneOnTop = _heuristicsOnTop;
            snapshot.DefaultApiPresentationMode = _apiViewPresentationMode == ApiViewPresentationMode.ThreadTimeline
                                                      ? InterfacePreferences.ApiPresentationThreadTimeline
                                                      : InterfacePreferences.ApiPresentationCallGraph;
            return snapshot;
        }

        private void PersistCurrentInterfacePreferences()
        {
            _interfacePreferences = SnapshotCurrentInterfacePreferences();
            AnalystSettingsStore.SaveInterfacePreferences(_interfacePreferences);
        }

        private void ApplySymbolSettings(SymbolSettings settings, bool persist)
        {
            _symbolSettings = (settings ?? SymbolSettings.Defaults()).Clone();
            ResxSymbolService.ClearCaches();
            if (persist)
            {
                AnalystSettingsStore.SaveSymbolSettings(_symbolSettings);
            }
        }
    }
}
