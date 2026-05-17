using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text.Json;

namespace BlackbirdInterface
{
    internal static class ResxSymbolService
    {
        private const string DisabledSymbolServerSentinel = "disabled";
        private static readonly object s_lock = new();
        private static readonly Dictionary<string, SymbolIndex> s_indexCache = new(StringComparer.OrdinalIgnoreCase);
        private static readonly Dictionary<string, PeDebugInfo?> s_debugInfoCache = new(StringComparer.OrdinalIgnoreCase);

        internal static void ClearCaches()
        {
            lock (s_lock)
            {
                s_indexCache.Clear();
                s_debugInfoCache.Clear();
            }
        }

        internal static bool TryResolveSymbol(int pid, string? imagePath, string? moduleName, ulong rva,
                                              out string symbol)
        {
            symbol = string.Empty;
            string normalizedImage = NormalizeFullPath(imagePath);
            if (normalizedImage.Length == 0 || !File.Exists(normalizedImage))
            {
                return false;
            }

            SymbolSettings settings = SymbolSettingsStore.LoadSymbolSettings();
            if (!settings.EnablePdbResolution)
            {
                return false;
            }

            string? pdbOverride = SymbolContextRegistry.FindPdbOverride(pid, normalizedImage, moduleName);
            if (!TryGetIndex(normalizedImage, settings, pdbOverride, out SymbolIndex? index))
            {
                return false;
            }

            return index != null && index.TryResolve(rva, out symbol);
        }

        private static bool TryGetIndex(string imagePath, SymbolSettings settings, string? pdbOverride,
                                        out SymbolIndex? index)
        {
            index = null;
            string? pdbPath = ResolvePdbPath(imagePath, settings, pdbOverride);
            if (pdbPath == null && !settings.AllowMicrosoftSymbolServer)
            {
                return false;
            }

            string key = BuildCacheKey(imagePath, pdbPath, settings);
            lock (s_lock)
            {
                if (s_indexCache.TryGetValue(key, out SymbolIndex? cached))
                {
                    index = cached;
                    return cached.Symbols.Count != 0;
                }
            }

            if (!TryLoadIndex(imagePath, pdbPath, settings, out SymbolIndex? loaded))
            {
                return false;
            }

            lock (s_lock)
            {
                s_indexCache[key] = loaded;
            }

            index = loaded;
            return loaded.Symbols.Count != 0;
        }

        private static bool TryLoadIndex(string imagePath, string? pdbPath, SymbolSettings settings,
                                         out SymbolIndex index)
        {
            index = new SymbolIndex(Array.Empty<SymbolRecord>());
            string optionsJson = BuildShowSymbolsOptions(pdbPath, settings);
            lock (s_lock)
            {
                using var scope = new ResxEnvironmentScope(settings);
                if (!ResxNative.TryShowSymbols(imagePath, optionsJson, out string json, out _))
                {
                    return false;
                }

                if (!TryParseSymbols(json, out List<SymbolRecord> symbols))
                {
                    return false;
                }

                index = new SymbolIndex(symbols.OrderBy(static s => s.Rva).ToArray());
                return true;
            }
        }

        private static string? ResolvePdbPath(string imagePath, SymbolSettings settings, string? pdbOverride)
        {
            string normalizedOverride = NormalizeFullPath(pdbOverride);
            if (normalizedOverride.Length != 0 && File.Exists(normalizedOverride))
            {
                return normalizedOverride;
            }

            PeDebugInfo? debugInfo = GetPeDebugInfo(imagePath, settings);
            string pdbName = debugInfo?.PdbName ?? Path.ChangeExtension(Path.GetFileName(imagePath), ".pdb");
            string guidAge = debugInfo?.GuidAge ?? string.Empty;

            foreach (string directPdb in SymbolSettings.NormalizePaths(settings.DirectPdbFiles)
                         .Select(NormalizeFullPath)
                         .Where(static p => p.Length != 0 && File.Exists(p)))
            {
                if (string.Equals(Path.GetFileName(directPdb), pdbName, StringComparison.OrdinalIgnoreCase))
                {
                    return directPdb;
                }
            }

            string sibling = Path.ChangeExtension(imagePath, ".pdb");
            if (File.Exists(sibling) &&
                string.Equals(Path.GetFileName(sibling), pdbName, StringComparison.OrdinalIgnoreCase))
            {
                return sibling;
            }

            foreach (string directory in SymbolSettings.NormalizePaths(settings.PdbDirectories)
                         .Select(NormalizeFullPath)
                         .Where(Directory.Exists))
            {
                if (guidAge.Length != 0)
                {
                    string storePath = Path.Combine(directory, pdbName, guidAge, pdbName);
                    if (File.Exists(storePath))
                    {
                        return storePath;
                    }
                }

                string flatPath = Path.Combine(directory, pdbName);
                if (File.Exists(flatPath))
                {
                    return flatPath;
                }
            }

            return null;
        }

        private static PeDebugInfo? GetPeDebugInfo(string imagePath, SymbolSettings settings)
        {
            string key = $"{imagePath}|{GetFileTicks(imagePath)}";
            lock (s_lock)
            {
                if (s_debugInfoCache.TryGetValue(key, out PeDebugInfo? cached))
                {
                    return cached;
                }

                using var scope = new ResxEnvironmentScope(settings);
                PeDebugInfo? info = null;
                if (ResxNative.TryPeInfo(imagePath, "{\"json\":true,\"quiet\":true,\"no_pdb\":true}",
                                          out string json, out _) &&
                    TryParsePeDebugInfo(json, out PeDebugInfo parsed))
                {
                    info = parsed;
                }

                s_debugInfoCache[key] = info;
                return info;
            }
        }

        private static string BuildShowSymbolsOptions(string? pdbPath, SymbolSettings settings)
        {
            var options = new Dictionary<string, object?> {
                ["json"] = true,
                ["quiet"] = true,
                ["reload"] = false,
                ["sym_path"] = BuildResxSymbolPath(settings),
                ["sym_server"] = settings.AllowMicrosoftSymbolServer
                                    ? SymbolSettings.NormalizeServerUrl(settings.SymbolServerUrl)
                                    : DisabledSymbolServerSentinel
            };
            if (!string.IsNullOrWhiteSpace(pdbPath))
            {
                options["pdb_file"] = pdbPath;
            }

            return JsonSerializer.Serialize(options);
        }

        private static string BuildResxSymbolPath(SymbolSettings settings)
        {
            var entries = new List<string>();
            AddUnique(entries, settings.NormalizedCacheDirectory);
            foreach (string directPdb in SymbolSettings.NormalizePaths(settings.DirectPdbFiles))
            {
                AddUnique(entries, Path.GetDirectoryName(directPdb));
            }

            foreach (string directory in SymbolSettings.NormalizePaths(settings.PdbDirectories))
            {
                AddUnique(entries, directory);
            }

            return string.Join(';', entries);
        }

        private static bool TryParsePeDebugInfo(string json, out PeDebugInfo info)
        {
            info = default;
            try
            {
                using JsonDocument document = JsonDocument.Parse(json);
                if (!TryGetProperty(document.RootElement, "payload", out JsonElement payload) ||
                    !TryGetProperty(payload, "peinfo", out JsonElement peinfo) ||
                    !TryGetProperty(peinfo, "debug", out JsonElement debug))
                {
                    return false;
                }

                string pdbName = ReadString(debug, "pdb_name");
                string guidAge = ReadString(debug, "pdb_guid_age");
                if (pdbName.Length == 0)
                {
                    return false;
                }

                info = new PeDebugInfo(pdbName, guidAge);
                return true;
            }
            catch
            {
                return false;
            }
        }

        private static bool TryParseSymbols(string json, out List<SymbolRecord> symbols)
        {
            symbols = new List<SymbolRecord>();
            try
            {
                using JsonDocument document = JsonDocument.Parse(json);
                if (!TryGetProperty(document.RootElement, "payload", out JsonElement payload) ||
                    !TryGetProperty(payload, "symbols", out JsonElement array) ||
                    array.ValueKind != JsonValueKind.Array)
                {
                    return false;
                }

                foreach (JsonElement element in array.EnumerateArray())
                {
                    string name = ReadString(element, "name");
                    if (name.Length == 0 ||
                        !TryReadUInt64(element, "rva", out ulong rva) ||
                        rva == 0)
                    {
                        continue;
                    }

                    _ = TryReadUInt64(element, "size", out ulong size);
                    symbols.Add(new SymbolRecord(rva, size, name));
                }

                return symbols.Count != 0;
            }
            catch
            {
                return false;
            }
        }

        private static string BuildCacheKey(string imagePath, string? pdbPath, SymbolSettings settings)
        {
            return string.Join(
                "|",
                imagePath,
                GetFileTicks(imagePath).ToString(CultureInfo.InvariantCulture),
                pdbPath ?? string.Empty,
                GetFileTicks(pdbPath).ToString(CultureInfo.InvariantCulture),
                settings.Fingerprint());
        }

        private static long GetFileTicks(string? path)
        {
            try
            {
                return !string.IsNullOrWhiteSpace(path) && File.Exists(path)
                           ? File.GetLastWriteTimeUtc(path).Ticks
                           : 0;
            }
            catch
            {
                return 0;
            }
        }

        private static string NormalizeFullPath(string? path)
        {
            string trimmed = (path ?? string.Empty).Trim();
            if (trimmed.Length == 0)
            {
                return string.Empty;
            }

            try
            {
                return Path.GetFullPath(trimmed);
            }
            catch
            {
                return trimmed;
            }
        }

        private static bool TryGetProperty(JsonElement element, string name, out JsonElement value)
        {
            if (element.ValueKind == JsonValueKind.Object && element.TryGetProperty(name, out value))
            {
                return true;
            }

            value = default;
            return false;
        }

        private static string ReadString(JsonElement element, string name) =>
            TryGetProperty(element, name, out JsonElement value) && value.ValueKind == JsonValueKind.String
                ? value.GetString()?.Trim() ?? string.Empty
                : string.Empty;

        private static bool TryReadUInt64(JsonElement element, string name, out ulong value)
        {
            value = 0;
            if (!TryGetProperty(element, name, out JsonElement property))
            {
                return false;
            }

            return property.ValueKind switch {
                JsonValueKind.Number => property.TryGetUInt64(out value),
                JsonValueKind.String => TryParseFlexibleUInt64(property.GetString(), out value),
                _ => false
            };
        }

        private static bool TryParseFlexibleUInt64(string? text, out ulong value)
        {
            value = 0;
            string trimmed = (text ?? string.Empty).Trim();
            if (trimmed.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            {
                return ulong.TryParse(trimmed.AsSpan(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture,
                                      out value);
            }

            return ulong.TryParse(trimmed, NumberStyles.Integer, CultureInfo.InvariantCulture, out value);
        }

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

        private readonly record struct PeDebugInfo(string PdbName, string GuidAge);
        private readonly record struct SymbolRecord(ulong Rva, ulong Size, string Name);

        private sealed class SymbolIndex
        {
            public SymbolIndex(IReadOnlyList<SymbolRecord> symbols)
            {
                Symbols = symbols;
            }

            public IReadOnlyList<SymbolRecord> Symbols { get; }

            public bool TryResolve(ulong rva, out string symbol)
            {
                symbol = string.Empty;
                if (Symbols.Count == 0)
                {
                    return false;
                }

                int lo = 0;
                int hi = Symbols.Count - 1;
                int best = -1;
                while (lo <= hi)
                {
                    int mid = lo + ((hi - lo) / 2);
                    if (Symbols[mid].Rva <= rva)
                    {
                        best = mid;
                        lo = mid + 1;
                    }
                    else
                    {
                        hi = mid - 1;
                    }
                }

                if (best < 0)
                {
                    return false;
                }

                SymbolRecord record = Symbols[best];
                ulong displacement = rva - record.Rva;
                if (record.Size != 0 && displacement >= record.Size)
                {
                    return false;
                }

                if (record.Size == 0 && displacement > 0x10000)
                {
                    return false;
                }

                symbol = displacement == 0 ? record.Name : $"{record.Name}+0x{displacement:X}";
                return true;
            }
        }

        private sealed class ResxEnvironmentScope : IDisposable
        {
            private readonly string? _oldNtSymbolPath;
            private readonly string? _oldNtAltSymbolPath;
            private readonly string? _oldResxSymbolCache;

            public ResxEnvironmentScope(SymbolSettings settings)
            {
                _oldNtSymbolPath = Environment.GetEnvironmentVariable("_NT_SYMBOL_PATH");
                _oldNtAltSymbolPath = Environment.GetEnvironmentVariable("_NT_ALT_SYMBOL_PATH");
                _oldResxSymbolCache = Environment.GetEnvironmentVariable("RESX_SYMBOL_CACHE");

                Environment.SetEnvironmentVariable("RESX_SYMBOL_CACHE", settings.NormalizedCacheDirectory);
                Environment.SetEnvironmentVariable("_NT_SYMBOL_PATH",
                                                   settings.BuildDbgHelpSearchPath(settings.EnablePdbResolution));
                Environment.SetEnvironmentVariable("_NT_ALT_SYMBOL_PATH", string.Empty);
            }

            public void Dispose()
            {
                Environment.SetEnvironmentVariable("_NT_SYMBOL_PATH", _oldNtSymbolPath);
                Environment.SetEnvironmentVariable("_NT_ALT_SYMBOL_PATH", _oldNtAltSymbolPath);
                Environment.SetEnvironmentVariable("RESX_SYMBOL_CACHE", _oldResxSymbolCache);
            }
        }
    }
}
