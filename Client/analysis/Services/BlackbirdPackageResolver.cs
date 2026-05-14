using System;
using System.Collections.Generic;
using System.IO;

namespace BlackbirdInterface
{
    internal static class BlackbirdPackageResolver
    {
        internal static string ResolveRuntimeFile(string fileName)
        {
            foreach (string directory in EnumerateRuntimeDirectories())
            {
                string candidate = Path.Combine(directory, fileName);
                if (File.Exists(candidate))
                {
                    return candidate;
                }
            }

            return Path.Combine(ResolveBaseDirectory(), fileName);
        }

        internal static string ResolveBaseDirectory()
        {
            string baseDirectory = AppContext.BaseDirectory;
            if (string.IsNullOrWhiteSpace(baseDirectory))
            {
                baseDirectory = Environment.CurrentDirectory;
            }

            return Path.GetFullPath(baseDirectory);
        }

        internal static string? ResolvePackageRoot()
        {
            foreach (string start in EnumerateStartDirectories())
            {
                DirectoryInfo? current = new(start);
                while (current != null)
                {
                    if (File.Exists(Path.Combine(current.FullName, "Scripts", "installer.ps1")))
                    {
                        return current.FullName;
                    }

                    current = current.Parent;
                }
            }

            return null;
        }

        internal static string? ResolveScript(string scriptName)
        {
            string? root = ResolvePackageRoot();
            if (string.IsNullOrWhiteSpace(root))
            {
                return null;
            }

            string candidate = Path.Combine(root, "Scripts", scriptName);
            return File.Exists(candidate) ? candidate : null;
        }

        internal static string? ResolvePackageArtifact(string fileName)
        {
            foreach (string directory in EnumerateRuntimeDirectories())
            {
                string candidate = Path.Combine(directory, fileName);
                if (File.Exists(candidate))
                {
                    return candidate;
                }
            }

            string? root = ResolvePackageRoot();
            if (string.IsNullOrWhiteSpace(root))
            {
                return null;
            }

            string[] relativeCandidates = { fileName,
                                            Path.Combine("x64", "PublicRelease", fileName),
                                            Path.Combine("x64", "Release", fileName),
                                            Path.Combine("x64", "TEMPUS_DEBUG", fileName),
                                            Path.Combine("x64", "Debug", fileName),
                                            Path.Combine("vcxproj", "x64", "Release", fileName),
                                            Path.Combine("vcxproj", "x64", "TEMPUS_DEBUG", fileName),
                                            Path.Combine("vcxproj", "x64", "Debug", fileName) };

            foreach (string relative in relativeCandidates)
            {
                string candidate = Path.Combine(root, relative);
                if (File.Exists(candidate))
                {
                    return candidate;
                }
            }

            return null;
        }

        private static IEnumerable<string> EnumerateRuntimeDirectories()
        {
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (string start in EnumerateStartDirectories())
            {
                DirectoryInfo? current = new(start);
                for (int depth = 0; current != null && depth < 5; depth++, current = current.Parent)
                {
                    if (seen.Add(current.FullName))
                    {
                        yield return current.FullName;
                    }
                }
            }

            string programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            if (!string.IsNullOrWhiteSpace(programFiles))
            {
                string blackbirdDir = Path.Combine(programFiles, "Blackbird");
                if (seen.Add(blackbirdDir))
                {
                    yield return blackbirdDir;
                }
            }
        }

        private static IEnumerable<string> EnumerateStartDirectories()
        {
            yield return ResolveBaseDirectory();

            string currentDirectory = Environment.CurrentDirectory;
            if (!string.IsNullOrWhiteSpace(currentDirectory))
            {
                yield return Path.GetFullPath(currentDirectory);
            }
        }
    }
}
