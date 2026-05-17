using Microsoft.Win32;
using System;
using System.Collections.Generic;

namespace BlackbirdInterface
{
    internal static class AnalystSettingsStore
    {
        private const string RootKeyPath = @"Software\TITAN Softwork Solutions\BK\Interface";
        private const string ThemeValueName = "ThemeMode";
        private const string ShortcutKeyPath = RootKeyPath + @"\Shortcuts";
        private const string PreferencesKeyPath = RootKeyPath + @"\Preferences";
        private const string SymbolsKeyPath = RootKeyPath + @"\Symbols";

        internal static UiThemeMode LoadThemeMode()
        {
            try
            {
                using RegistryKey? key = Registry.CurrentUser.OpenSubKey(RootKeyPath);
                string? raw = key?.GetValue(ThemeValueName) as string;
                if (!string.IsNullOrWhiteSpace(raw) && Enum.TryParse(raw, ignoreCase: true, out UiThemeMode mode))
                {
                    return mode;
                }
            }
            catch
            {
            }

            return UiThemeMode.Dark;
        }

        internal static void SaveThemeMode(UiThemeMode mode)
        {
            try
            {
                using RegistryKey key = Registry.CurrentUser.CreateSubKey(RootKeyPath);
                key.SetValue(ThemeValueName, mode.ToString(), RegistryValueKind.String);
            }
            catch
            {
            }
        }

        internal static Dictionary<string, string> LoadShortcutBindings()
        {
            var bindings = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            try
            {
                using RegistryKey? key = Registry.CurrentUser.OpenSubKey(ShortcutKeyPath);
                if (key == null)
                {
                    return bindings;
                }

                foreach (string valueName in key.GetValueNames())
                {
                    if (key.GetValue(valueName) is string gesture)
                    {
                        bindings[valueName] = gesture;
                    }
                }
            }
            catch
            {
            }

            return bindings;
        }

        internal static void SaveShortcutBindings(IReadOnlyDictionary<string, string> bindings)
        {
            try
            {
                using RegistryKey key = Registry.CurrentUser.CreateSubKey(ShortcutKeyPath);
                foreach (string valueName in key.GetValueNames())
                {
                    key.DeleteValue(valueName, throwOnMissingValue: false);
                }

                foreach ((string id, string gesture) in bindings)
                {
                    if (string.IsNullOrWhiteSpace(id))
                    {
                        continue;
                    }

                    key.SetValue(id, gesture ?? string.Empty, RegistryValueKind.String);
                }
            }
            catch
            {
            }
        }

        internal static InterfacePreferences LoadInterfacePreferences()
        {
            InterfacePreferences preferences = InterfacePreferences.Defaults();
            try
            {
                using RegistryKey? key = Registry.CurrentUser.OpenSubKey(PreferencesKeyPath);
                if (key == null)
                {
                    return preferences;
                }

                preferences.AutoSwitchToApiViewOnHookLaunch =
                    ReadBool(key, nameof(InterfacePreferences.AutoSwitchToApiViewOnHookLaunch),
                             preferences.AutoSwitchToApiViewOnHookLaunch);
                preferences.ShowEventsPane =
                    ReadBool(key, nameof(InterfacePreferences.ShowEventsPane), preferences.ShowEventsPane);
                preferences.ShowPerformancePane =
                    ReadBool(key, nameof(InterfacePreferences.ShowPerformancePane), preferences.ShowPerformancePane);
                preferences.ShowEtwPane =
                    ReadBool(key, nameof(InterfacePreferences.ShowEtwPane), preferences.ShowEtwPane);
                preferences.ShowDetectionsPane =
                    ReadBool(key, nameof(InterfacePreferences.ShowDetectionsPane), preferences.ShowDetectionsPane);
                preferences.ShowFilesystemPane =
                    ReadBool(key, nameof(InterfacePreferences.ShowFilesystemPane), preferences.ShowFilesystemPane);
                preferences.ShowRegistryPane =
                    ReadBool(key, nameof(InterfacePreferences.ShowRegistryPane), preferences.ShowRegistryPane);
                preferences.ShowProcessRelationsPane = ReadBool(
                    key, nameof(InterfacePreferences.ShowProcessRelationsPane), preferences.ShowProcessRelationsPane);
                preferences.PerformancePaneOnTop =
                    ReadBool(key, nameof(InterfacePreferences.PerformancePaneOnTop), preferences.PerformancePaneOnTop);
                preferences.DetectionsPaneOnTop =
                    ReadBool(key, nameof(InterfacePreferences.DetectionsPaneOnTop), preferences.DetectionsPaneOnTop);
                preferences.DefaultApiPresentationMode =
                    ReadString(key, nameof(InterfacePreferences.DefaultApiPresentationMode),
                               preferences.DefaultApiPresentationMode);
            }
            catch
            {
            }

            return preferences;
        }

        internal static void SaveInterfacePreferences(InterfacePreferences preferences)
        {
            try
            {
                using RegistryKey key = Registry.CurrentUser.CreateSubKey(PreferencesKeyPath);
                WriteBool(key, nameof(InterfacePreferences.AutoSwitchToApiViewOnHookLaunch),
                          preferences.AutoSwitchToApiViewOnHookLaunch);
                WriteBool(key, nameof(InterfacePreferences.ShowEventsPane), preferences.ShowEventsPane);
                WriteBool(key, nameof(InterfacePreferences.ShowPerformancePane), preferences.ShowPerformancePane);
                WriteBool(key, nameof(InterfacePreferences.ShowEtwPane), preferences.ShowEtwPane);
                WriteBool(key, nameof(InterfacePreferences.ShowDetectionsPane), preferences.ShowDetectionsPane);
                WriteBool(key, nameof(InterfacePreferences.ShowFilesystemPane), preferences.ShowFilesystemPane);
                WriteBool(key, nameof(InterfacePreferences.ShowRegistryPane), preferences.ShowRegistryPane);
                WriteBool(key, nameof(InterfacePreferences.ShowProcessRelationsPane),
                          preferences.ShowProcessRelationsPane);
                WriteBool(key, nameof(InterfacePreferences.PerformancePaneOnTop), preferences.PerformancePaneOnTop);
                WriteBool(key, nameof(InterfacePreferences.DetectionsPaneOnTop), preferences.DetectionsPaneOnTop);
                key.SetValue(nameof(InterfacePreferences.DefaultApiPresentationMode),
                             NormalizeApiPresentation(preferences.DefaultApiPresentationMode),
                             RegistryValueKind.String);
            }
            catch
            {
            }
        }

        internal static SymbolSettings LoadSymbolSettings()
        {
            return SymbolSettingsStore.LoadSymbolSettings();
        }

        internal static void SaveSymbolSettings(SymbolSettings settings)
        {
            SymbolSettingsStore.SaveSymbolSettings(settings);
        }

        private static bool ReadBool(RegistryKey key, string name, bool fallback)
        {
            object? value = key.GetValue(name);
            return value switch { int intValue => intValue != 0,
                                  string text when bool.TryParse(text, out bool parsed) => parsed,
                                  string text when int.TryParse(text, out int parsed) => parsed != 0,
                                  _ => fallback };
        }

        private static string ReadString(RegistryKey key, string name, string fallback)
        {
            string? value = key.GetValue(name) as string;
            return NormalizeApiPresentation(string.IsNullOrWhiteSpace(value) ? fallback : value);
        }

        private static string ReadRawString(RegistryKey key, string name, string fallback)
        {
            string? value = key.GetValue(name) as string;
            return string.IsNullOrWhiteSpace(value) ? fallback : value.Trim();
        }

        private static string[] ReadStringArray(RegistryKey key, string name)
        {
            object? value = key.GetValue(name);
            if (value is string[] values)
            {
                return values;
            }

            if (value is string single && !string.IsNullOrWhiteSpace(single))
            {
                return single.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            }

            return Array.Empty<string>();
        }

        private static void WriteBool(RegistryKey key, string name, bool value)
        {
            key.SetValue(name, value ? 1 : 0, RegistryValueKind.DWord);
        }

        internal static string NormalizeApiPresentation(string? mode)
        {
            return string.Equals(mode, InterfacePreferences.ApiPresentationThreadTimeline,
                                 StringComparison.OrdinalIgnoreCase)
                       ? InterfacePreferences.ApiPresentationThreadTimeline
                       : InterfacePreferences.ApiPresentationCallGraph;
        }
    }

    public sealed class InterfacePreferences
    {
        internal const string ApiPresentationCallGraph = "CallGraph";
        internal const string ApiPresentationThreadTimeline = "ThreadTimeline";

        public bool AutoSwitchToApiViewOnHookLaunch { get; set; }
        public bool ShowEventsPane { get; set; } = true;
        public bool ShowPerformancePane { get; set; } = true;
        public bool ShowEtwPane { get; set; } = true;
        public bool ShowDetectionsPane { get; set; } = true;
        public bool ShowFilesystemPane { get; set; } = true;
        public bool ShowRegistryPane { get; set; } = true;
        public bool ShowProcessRelationsPane { get; set; } = true;
        public bool PerformancePaneOnTop { get; set; }
        public bool DetectionsPaneOnTop { get; set; }
        public string DefaultApiPresentationMode { get; set; } = ApiPresentationCallGraph;

        internal static InterfacePreferences Defaults() => new();

        internal InterfacePreferences Clone()
        {
            return new InterfacePreferences {
                AutoSwitchToApiViewOnHookLaunch = AutoSwitchToApiViewOnHookLaunch,
                ShowEventsPane = ShowEventsPane,
                ShowPerformancePane = ShowPerformancePane,
                ShowEtwPane = ShowEtwPane,
                ShowDetectionsPane = ShowDetectionsPane,
                ShowFilesystemPane = ShowFilesystemPane,
                ShowRegistryPane = ShowRegistryPane,
                ShowProcessRelationsPane = ShowProcessRelationsPane,
                PerformancePaneOnTop = PerformancePaneOnTop,
                DetectionsPaneOnTop = DetectionsPaneOnTop,
                DefaultApiPresentationMode = AnalystSettingsStore.NormalizeApiPresentation(DefaultApiPresentationMode)
            };
        }
    }
}
