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
        private InterfaceSettingsWindow? _interfaceSettingsWindow;

        private void InitializeInterfaceSettings()
        {
            EnsureShortcutCommands();
            LoadShortcutBindings();
            ApplyShortcutBindings();
        }

        internal void ApplyInterfaceSettings(UiThemeMode mode, IReadOnlyDictionary<string, string> bindings)
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
                }))
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
                ShowPerformancePane();
                PerformancePaneHost.ShowMemoryInspectorWindow();
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
    }
}
