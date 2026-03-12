using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;

namespace BlackbirdInterface
{
    internal static class OutputCapture
    {
        private static readonly object s_lock = new();
        private static readonly Queue<string> s_lines = new();
        private static bool s_initialized;
        private const int MaxLines = 4000;

        public static event Action<string>? LineReceived;

        public static void Initialize()
        {
            if (s_initialized)
                return;

            s_initialized = true;
            Trace.Listeners.Add(new OutputTraceListener());
            Console.SetOut(new TeeWriter(Console.Out, AppendLine));
            Console.SetError(new TeeWriter(Console.Error, AppendLine));
            AppendLine("Output capture initialized.");
        }

        public static IReadOnlyList<string> Snapshot()
        {
            lock (s_lock)
            {
                return s_lines.ToArray();
            }
        }

        public static void AppendLine(string? text)
        {
            if (text == null)
                return;

            string line = text.TrimEnd('\r', '\n');
            if (line.Length == 0)
                return;

            lock (s_lock)
            {
                if (s_lines.Count >= MaxLines)
                    s_lines.Dequeue();
                s_lines.Enqueue($"[{DateTime.Now:HH:mm:ss}] {line}");
            }

            LineReceived?.Invoke(line);
        }

        private sealed class OutputTraceListener : TraceListener
        {
            public override void Write(string? message)
            {
                if (message == null)
                    return;

                foreach (var part in message.Split('\n'))
                    AppendLine(part);
            }

            public override void WriteLine(string? message)
            {
                AppendLine(message);
            }
        }

        private sealed class TeeWriter : TextWriter
        {
            private readonly TextWriter _inner;
            private readonly Action<string> _sink;
            public override Encoding Encoding => _inner.Encoding;

            public TeeWriter(TextWriter inner, Action<string> sink)
            {
                _inner = inner;
                _sink = sink;
            }

            public override void WriteLine(string? value)
            {
                _inner.WriteLine(value);
                if (value != null)
                    _sink(value);
            }

            public override void Write(char value)
            {
                _inner.Write(value);
            }
        }
    }
}
