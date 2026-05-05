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
    }
}
