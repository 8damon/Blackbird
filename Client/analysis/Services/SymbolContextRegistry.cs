using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace BlackbirdInterface
{
    internal static class SymbolContextRegistry
    {
        private static readonly object s_lock = new();
        private static readonly Dictionary<int, List<TargetPdbMapping>> s_processMappings = new();

        internal static void RegisterProcessTarget(int pid, string? imagePath, string? pdbPath)
        {
            if (pid <= 0)
            {
                return;
            }

            string normalizedImage = NormalizePath(imagePath);
            string normalizedPdb = NormalizePath(pdbPath);
            lock (s_lock)
            {
                if (normalizedImage.Length == 0 || normalizedPdb.Length == 0)
                {
                    s_processMappings.Remove(pid);
                    return;
                }

                s_processMappings[pid] = new List<TargetPdbMapping> {
                    new(normalizedImage, normalizedPdb)
                };
            }
        }

        internal static string? FindPdbOverride(int pid, string? modulePath, string? moduleName)
        {
            if (pid <= 0)
            {
                return null;
            }

            string normalizedModule = NormalizePath(modulePath);
            string normalizedName = (moduleName ?? string.Empty).Trim();
            lock (s_lock)
            {
                if (!s_processMappings.TryGetValue(pid, out List<TargetPdbMapping>? mappings))
                {
                    return null;
                }

                foreach (TargetPdbMapping mapping in mappings)
                {
                    if (normalizedModule.Length != 0 &&
                        string.Equals(mapping.ImagePath, normalizedModule, StringComparison.OrdinalIgnoreCase))
                    {
                        return mapping.PdbPath;
                    }

                    if (normalizedName.Length != 0 &&
                        string.Equals(Path.GetFileName(mapping.ImagePath), normalizedName,
                                      StringComparison.OrdinalIgnoreCase))
                    {
                        return mapping.PdbPath;
                    }
                }
            }

            return null;
        }

        private static string NormalizePath(string? path)
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

        private readonly record struct TargetPdbMapping(string ImagePath, string PdbPath);
    }
}
