using Microsoft.Win32;
using System;

namespace BlackbirdInterface
{
    internal static class SymbolSettingsStore
    {
        private const string RootKeyPath = @"Software\TITAN Softwork Solutions\BK\Interface";
        private const string SymbolsKeyPath = RootKeyPath + @"\Symbols";

        internal static SymbolSettings LoadSymbolSettings()
        {
            SymbolSettings settings = SymbolSettings.Defaults();
            try
            {
                using RegistryKey? key = Registry.CurrentUser.OpenSubKey(SymbolsKeyPath);
                if (key == null)
                {
                    return settings;
                }

                settings.EnablePdbResolution =
                    ReadBool(key, nameof(SymbolSettings.EnablePdbResolution), settings.EnablePdbResolution);
                settings.AllowMicrosoftSymbolServer =
                    ReadBool(key, nameof(SymbolSettings.AllowMicrosoftSymbolServer),
                             settings.AllowMicrosoftSymbolServer);
                settings.SymbolServerUrl =
                    SymbolSettings.NormalizeServerUrl(ReadRawString(key, nameof(SymbolSettings.SymbolServerUrl),
                                                                    settings.SymbolServerUrl));
                settings.SymbolCacheDirectory =
                    SymbolSettings.NormalizeDirectory(
                        ReadRawString(key, nameof(SymbolSettings.SymbolCacheDirectory),
                                      settings.SymbolCacheDirectory),
                        SymbolSettings.DefaultCacheDirectory());
                settings.DirectPdbFiles.AddRange(ReadStringArray(key, nameof(SymbolSettings.DirectPdbFiles)));
                settings.PdbDirectories.AddRange(ReadStringArray(key, nameof(SymbolSettings.PdbDirectories)));
            }
            catch
            {
            }

            return settings.Clone();
        }

        internal static void SaveSymbolSettings(SymbolSettings settings)
        {
            SymbolSettings snapshot = (settings ?? SymbolSettings.Defaults()).Clone();
            try
            {
                using RegistryKey key = Registry.CurrentUser.CreateSubKey(SymbolsKeyPath);
                WriteBool(key, nameof(SymbolSettings.EnablePdbResolution), snapshot.EnablePdbResolution);
                WriteBool(key, nameof(SymbolSettings.AllowMicrosoftSymbolServer),
                          snapshot.AllowMicrosoftSymbolServer);
                key.SetValue(nameof(SymbolSettings.SymbolServerUrl),
                             SymbolSettings.NormalizeServerUrl(snapshot.SymbolServerUrl),
                             RegistryValueKind.String);
                key.SetValue(nameof(SymbolSettings.SymbolCacheDirectory),
                             SymbolSettings.NormalizeDirectory(snapshot.SymbolCacheDirectory,
                                                               SymbolSettings.DefaultCacheDirectory()),
                             RegistryValueKind.String);
                key.SetValue(nameof(SymbolSettings.DirectPdbFiles),
                             SymbolSettings.NormalizePaths(snapshot.DirectPdbFiles).ToArray(),
                             RegistryValueKind.MultiString);
                key.SetValue(nameof(SymbolSettings.PdbDirectories),
                             SymbolSettings.NormalizePaths(snapshot.PdbDirectories).ToArray(),
                             RegistryValueKind.MultiString);
            }
            catch
            {
            }
        }

        private static bool ReadBool(RegistryKey key, string name, bool fallback)
        {
            object? value = key.GetValue(name);
            return value switch { int intValue => intValue != 0,
                                  string text when bool.TryParse(text, out bool parsed) => parsed,
                                  string text when int.TryParse(text, out int parsed) => parsed != 0,
                                  _ => fallback };
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
    }
}
