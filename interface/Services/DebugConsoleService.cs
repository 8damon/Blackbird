using System;
using System.ComponentModel;
using System.IO.MemoryMappedFiles;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace BlackbirdInterface
{
    internal static class DebugConsoleService
    {
        private const uint AttachParentProcess = 0xFFFFFFFF;
        private static readonly object s_gate = new();
        private static bool s_started;
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

        public static void Start()
        {
            lock (s_gate)
            {
                if (s_started)
                {
                    return;
                }

                if (!AttachConsole(AttachParentProcess))
                {
                    _ = AllocConsole();
                }

                Console.OutputEncoding = Encoding.UTF8;
                Console.InputEncoding = Encoding.UTF8;
                _ = SetConsoleTitleW("Blackbird Interface Debug Console");
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
                _ = FreeConsole();
            }
        }

        public static void WriteLocal(string message)
        {
            WriteLine("INTERFACE", message);
        }

        private static void OnOutputCaptureLineReceived(string line)
        {
            WriteLine("INTERFACE", line);
        }

        private static void WriteLine(string source, string? message)
        {
            if (!s_started || string.IsNullOrWhiteSpace(message))
            {
                return;
            }

            try
            {
                Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [{source}] {message.TrimEnd('\r', '\n')}");
            }
            catch
            {
            }
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
                using MemoryMappedFile mapping = MemoryMappedFile.CreateOrOpen("DBWIN_BUFFER", bufferSize, MemoryMappedFileAccess.ReadWrite);
                using MemoryMappedViewAccessor accessor = mapping.CreateViewAccessor(0, bufferSize, MemoryMappedFileAccess.Read);

                WriteLocal("OutputDebugString listener online");

                while (!cancellationToken.IsCancellationRequested)
                {
                    bufferReady.Set();
                    int signaled = WaitHandle.WaitAny(new WaitHandle[] { dataReady, cancellationToken.WaitHandle }, 250);
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
                    WriteLine(source, text);
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
