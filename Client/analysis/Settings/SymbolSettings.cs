using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace BlackbirdInterface
{
    public sealed class SymbolSettings
    {
        public const string DefaultSymbolServerUrl = "https://msdl.microsoft.com/download/symbols";

        public bool EnablePdbResolution { get; set; }
        public List<string> DirectPdbFiles { get; } = new();
        public List<string> PdbDirectories { get; } = new();
        public bool AllowMicrosoftSymbolServer { get; set; }
        public string SymbolServerUrl { get; set; } = DefaultSymbolServerUrl;
        public string SymbolCacheDirectory { get; set; } = DefaultCacheDirectory();

        public static SymbolSettings Defaults() => new();

        public SymbolSettings Clone()
        {
            var clone = new SymbolSettings {
                EnablePdbResolution = EnablePdbResolution,
                AllowMicrosoftSymbolServer = AllowMicrosoftSymbolServer,
                SymbolServerUrl = NormalizeServerUrl(SymbolServerUrl),
                SymbolCacheDirectory = NormalizeDirectory(SymbolCacheDirectory, DefaultCacheDirectory())
            };
            clone.DirectPdbFiles.AddRange(NormalizePaths(DirectPdbFiles));
            clone.PdbDirectories.AddRange(NormalizePaths(PdbDirectories));
            return clone;
        }

        internal string NormalizedCacheDirectory =>
            NormalizeDirectory(SymbolCacheDirectory, DefaultCacheDirectory());

        internal string BuildDbgHelpSearchPath(bool includeConfiguredSymbols)
        {
            var entries = new List<string>();
            AddUnique(entries, NormalizedCacheDirectory);

            if (includeConfiguredSymbols)
            {
                foreach (string pdbFile in NormalizePaths(DirectPdbFiles))
                {
                    string? parent = Path.GetDirectoryName(pdbFile);
                    AddUnique(entries, parent);
                }

                foreach (string directory in NormalizePaths(PdbDirectories))
                {
                    AddUnique(entries, directory);
                }

                string server = NormalizeServerUrl(SymbolServerUrl);
                if (AllowMicrosoftSymbolServer && IsHttpUrl(server))
                {
                    AddUnique(entries, $"srv*{NormalizedCacheDirectory}*{server}");
                }
            }

            return string.Join(';', entries);
        }

        internal string Fingerprint()
        {
            return string.Join(
                "|",
                EnablePdbResolution ? "1" : "0",
                string.Join(";", NormalizePaths(DirectPdbFiles)),
                string.Join(";", NormalizePaths(PdbDirectories)),
                AllowMicrosoftSymbolServer ? "1" : "0",
                NormalizeServerUrl(SymbolServerUrl),
                NormalizedCacheDirectory);
        }

        internal static string DefaultCacheDirectory()
        {
            string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            if (string.IsNullOrWhiteSpace(localAppData))
            {
                localAppData = Path.GetTempPath();
            }

            return Path.Combine(localAppData, "Blackbird", "Symbols");
        }

        internal static string NormalizeServerUrl(string? value)
        {
            string trimmed = (value ?? string.Empty).Trim();
            return trimmed.Length == 0 ? DefaultSymbolServerUrl : trimmed;
        }

        internal static string NormalizeDirectory(string? value, string fallback)
        {
            string trimmed = (value ?? string.Empty).Trim();
            return trimmed.Length == 0 ? fallback : trimmed;
        }

        internal static List<string> NormalizePaths(IEnumerable<string>? paths)
        {
            var output = new List<string>();
            if (paths == null)
            {
                return output;
            }

            foreach (string raw in paths)
            {
                string trimmed = (raw ?? string.Empty).Trim();
                if (trimmed.Length == 0 ||
                    output.Any(existing => string.Equals(existing, trimmed, StringComparison.OrdinalIgnoreCase)))
                {
                    continue;
                }

                output.Add(trimmed);
            }

            return output;
        }

        private static bool IsHttpUrl(string value) =>
            value.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
            value.StartsWith("https://", StringComparison.OrdinalIgnoreCase);

        private static void AddUnique(List<string> entries, string? value)
        {
            string trimmed = (value ?? string.Empty).Trim();
            if (trimmed.Length == 0 ||
                entries.Any(existing => string.Equals(existing, trimmed, StringComparison.OrdinalIgnoreCase)))
            {
                return;
            }

            entries.Add(trimmed);
        }
    }
}
