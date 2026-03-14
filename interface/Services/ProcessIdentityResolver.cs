using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;

namespace BlackbirdInterface
{
    internal static class ProcessIdentityResolver
    {
        private readonly record struct ProcessIdentity(string DisplayName, string HoverText);

        private static readonly ConcurrentDictionary<int, ProcessIdentity> IdentityByPid = new();
        private static readonly ConcurrentDictionary<int, byte> PendingPids = new();
        private static readonly ConcurrentQueue<int> PendingQueue = new();
        private static readonly AutoResetEvent QueueSignal = new(false);
        private static readonly Task[] Workers = StartWorkers();

        internal static void Prime(uint pid)
        {
            if (pid == 0 || pid > int.MaxValue)
            {
                return;
            }

            int key = (int)pid;
            if (IdentityByPid.ContainsKey(key))
            {
                return;
            }

            if (PendingPids.TryAdd(key, 0))
            {
                PendingQueue.Enqueue(key);
                QueueSignal.Set();
            }
        }

        internal static string Resolve(uint pid)
            => ResolveIdentity(pid).DisplayName;

        internal static string HoverText(uint pid)
            => ResolveIdentity(pid).HoverText;

        internal static string Describe(uint pid)
            => Resolve(pid);

        private static ProcessIdentity ResolveIdentity(uint pid)
        {
            if (pid == 0 || pid > int.MaxValue)
            {
                return new ProcessIdentity("-", "PID unavailable");
            }

            int key = (int)pid;
            if (IdentityByPid.TryGetValue(key, out ProcessIdentity cached))
            {
                return cached;
            }

            ProcessIdentity resolved = ResolveCore(key);
            IdentityByPid[key] = resolved;
            return resolved;
        }

        private static Task[] StartWorkers()
        {
            int workerCount = Math.Clamp(Environment.ProcessorCount / 4, 1, 4);
            var workers = new Task[workerCount];
            for (int i = 0; i < workers.Length; i += 1)
            {
                workers[i] = Task.Factory.StartNew(
                    WorkerLoop,
                    CancellationToken.None,
                    TaskCreationOptions.LongRunning,
                    TaskScheduler.Default);
            }

            return workers;
        }

        private static void WorkerLoop()
        {
            while (true)
            {
                if (!PendingQueue.TryDequeue(out int pid))
                {
                    QueueSignal.WaitOne(125);
                    continue;
                }

                PendingPids.TryRemove(pid, out _);
                IdentityByPid.TryAdd(pid, ResolveCore(pid));
            }
        }

        private static ProcessIdentity ResolveCore(int pid)
        {
            try
            {
                using Process process = Process.GetProcessById(pid);
                string name = process.ProcessName;
                if (string.IsNullOrWhiteSpace(name))
                {
                    return new ProcessIdentity($"pid:{pid}", $"PID {pid}");
                }

                return new ProcessIdentity(name, $"{name} (PID {pid})");
            }
            catch
            {
                return new ProcessIdentity($"pid:{pid}", $"PID {pid}");
            }
        }
    }
}
