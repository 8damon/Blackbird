using System;
using System.Collections.Concurrent;
using System.Diagnostics;

namespace SleepwalkerInterface
{
    internal static class ProcessIdentityResolver
    {
        private static readonly ConcurrentDictionary<int, string> NameByPid = new();

        internal static void Prime(uint pid)
        {
            _ = Resolve(pid);
        }

        internal static string Resolve(uint pid)
        {
            if (pid == 0 || pid > int.MaxValue)
            {
                return "unknown";
            }

            return NameByPid.GetOrAdd((int)pid, static id =>
            {
                try
                {
                    using Process process = Process.GetProcessById(id);
                    string name = process.ProcessName;
                    if (string.IsNullOrWhiteSpace(name))
                    {
                        return "unknown";
                    }
                    return name;
                }
                catch
                {
                    return "unknown";
                }
            });
        }

        internal static string Describe(uint pid)
        {
            if (pid == 0)
            {
                return "-";
            }

            return $"{pid} ({Resolve(pid)})";
        }
    }
}
