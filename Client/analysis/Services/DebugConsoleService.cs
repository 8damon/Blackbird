using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO.MemoryMappedFiles;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace BlackbirdInterface
{
    internal sealed class DebugConsoleEntry
    {
        public DateTime TimestampLocal { get; init; }
        public int ProcessId { get; init; }
        public string Source { get; init; } = string.Empty;
        public string Message { get; init; } = string.Empty;

        public string FilterText => $"{TimestampLocal:O} {ProcessId} {Source} {Message}";
    }

    internal static class DebugConsoleService
    {
        private const uint AttachParentProcess = 0xFFFFFFFF;
        private const int MaxEntries = 4096;
        private static readonly object s_gate = new();
        private static readonly Queue<DebugConsoleEntry> s_entries = new();
        private static bool s_started;
        private static bool s_consoleAttached;
        private static bool s_outputCaptureSubscribed;
        private static CancellationTokenSource? s_listenerCts;
        private static Task? s_listenerTask;

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool AllocConsole();

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool AttachConsole(uint dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool FreeConsole();

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool SetConsoleTitleW(string lpConsoleTitle);

        public static event Action<DebugConsoleEntry>? EntryReceived;

        public static void Start(bool attachConsole)
        {
            lock (s_gate)
            {
                if (s_started)
                {
                    if (attachConsole && !s_consoleAttached)
                    {
                        AttachDebugConsole();
                    }

                    return;
                }

                if (attachConsole)
                {
                    AttachDebugConsole();
                }

                s_started = true;
                WriteLocal("debug console online");

                if (!s_outputCaptureSubscribed)
                {
                    OutputCapture.LineReceived += OnOutputCaptureLineReceived;
                    s_outputCaptureSubscribed = true;
                }

                s_listenerCts = new CancellationTokenSource();
                s_listenerTask = Task.Run(() => RunOutputDebugStringListener(s_listenerCts.Token));
            }
        }

        public static void Stop()
        {
            lock (s_gate)
            {
                if (!s_started)
                {
                    return;
                }

                if (s_listenerCts != null)
                {
                    s_listenerCts.Cancel();
                }
            }

            try
            {
                s_listenerTask?.Wait(1000);
            }
            catch
            {
            }

            lock (s_gate)
            {
                if (s_outputCaptureSubscribed)
                {
                    OutputCapture.LineReceived -= OnOutputCaptureLineReceived;
                    s_outputCaptureSubscribed = false;
                }

                s_listenerTask = null;
                s_listenerCts?.Dispose();
                s_listenerCts = null;
                s_started = false;
                if (s_consoleAttached)
                {
                    _ = FreeConsole();
                    s_consoleAttached = false;
                }
            }
        }

        public static IReadOnlyList<DebugConsoleEntry> Snapshot()
        {
            lock (s_gate)
            {
                return s_entries.ToArray();
            }
        }

        public static void WriteLocal(string message)
        {
            WriteEntry("INTERFACE", Environment.ProcessId, message);
        }

        public static void WriteExternal(string source, int processId, string? message)
        {
            WriteEntry(source, processId, message);
        }

        private static void OnOutputCaptureLineReceived(string line)
        {
            WriteEntry("INTERFACE", Environment.ProcessId, line);
        }

        private static void AttachDebugConsole()
        {
            if (!AttachConsole(AttachParentProcess))
            {
                _ = AllocConsole();
            }

            Console.OutputEncoding = Encoding.UTF8;
            Console.InputEncoding = Encoding.UTF8;
            _ = SetConsoleTitleW("BK Interface Debug Console");
            s_consoleAttached = true;
        }

        private static void WriteEntry(string source, int processId, string? message)
        {
            if (!s_started || string.IsNullOrWhiteSpace(message))
            {
                return;
            }

            string trimmed = message.TrimEnd('\r', '\n');
            var entry = new DebugConsoleEntry { TimestampLocal = DateTime.Now, ProcessId = processId,
                                                Source = source ?? string.Empty, Message = trimmed };

            lock (s_gate)
            {
                if (s_entries.Count >= MaxEntries)
                {
                    s_entries.Dequeue();
                }

                s_entries.Enqueue(entry);
            }

            try
            {
                if (s_consoleAttached)
                {
                    Console.WriteLine($"[{entry.TimestampLocal:HH:mm:ss.fff}] [{source}] {trimmed}");
                }
            }
            catch
            {
            }

            EntryReceived?.Invoke(entry);
        }

        private static void RunOutputDebugStringListener(CancellationToken cancellationToken)
        {
            const int bufferSize = 4096;
            EventWaitHandle? bufferReady = null;
            EventWaitHandle? dataReady = null;

            try
            {
                bufferReady = new EventWaitHandle(false, EventResetMode.AutoReset, "DBWIN_BUFFER_READY");
                dataReady = new EventWaitHandle(false, EventResetMode.AutoReset, "DBWIN_DATA_READY");
                using MemoryMappedFile mapping =
                    MemoryMappedFile.CreateOrOpen("DBWIN_BUFFER", bufferSize, MemoryMappedFileAccess.ReadWrite);
                using MemoryMappedViewAccessor accessor =
                    mapping.CreateViewAccessor(0, bufferSize, MemoryMappedFileAccess.Read);

                WriteLocal("OutputDebugString listener online");

                while (!cancellationToken.IsCancellationRequested)
                {
                    bufferReady.Set();
                    int signaled =
                        WaitHandle.WaitAny(new WaitHandle[] { dataReady, cancellationToken.WaitHandle }, 250);
                    if (signaled != 0)
                    {
                        continue;
                    }

                    int pid = accessor.ReadInt32(0);
                    byte[] bytes = new byte[bufferSize - sizeof(int)];
                    accessor.ReadArray(sizeof(int), bytes, 0, bytes.Length);

                    int terminator = Array.IndexOf(bytes, (byte)0);
                    if (terminator < 0)
                    {
                        terminator = bytes.Length;
                    }

                    string text = Encoding.Default.GetString(bytes, 0, terminator).TrimEnd('\r', '\n', '\0');
                    if (string.IsNullOrWhiteSpace(text))
                    {
                        continue;
                    }

                    if (pid == Environment.ProcessId)
                    {
                        continue;
                    }

                    string source = ResolveSourceLabel(pid);
                    WriteEntry(source, pid, text);
                    OutputCapture.AppendExternalLine($"[{source}:{pid}] {text}");
                }
            }
            catch (Exception ex)
            {
                WriteLocal($"OutputDebugString listener degraded: {ex.Message}");
            }
            finally
            {
                bufferReady?.Dispose();
                dataReady?.Dispose();
            }
        }

        private static string ResolveSourceLabel(int pid)
        {
            try
            {
                using var process = System.Diagnostics.Process.GetProcessById(pid);
                string name = process.ProcessName;
                if (name.IndexOf("BlackbirdController", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    return "CONTROLLER";
                }

                if (name.IndexOf("BlackbirdInterface", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    return "INTERFACE";
                }

                return $"{name}:{pid}";
            }
            catch (Win32Exception)
            {
                return $"PID:{pid}";
            }
            catch (InvalidOperationException)
            {
                return $"PID:{pid}";
            }
        }
    }
}
