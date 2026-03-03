using System;
using System.Buffers.Binary;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace SleepwalkerInterface
{
    internal static class SleepwalkerNative
    {
        internal const uint StreamHandle = 0x00000001;
        internal const uint StreamMemory = 0x00000002;
        internal const uint StreamThread = 0x00000004;
        internal const uint StreamAll = StreamHandle | StreamMemory | StreamThread;

        internal const uint EventTypeHandle = 1;
        internal const uint EventTypeThread = 2;

        internal const uint IpcCapDriverProxy = 0x00000001;
        internal const uint IpcCapEtwTiSession = 0x00000002;
        internal const uint IpcCapEtwTiUplink = 0x00000004;

        internal const uint IpcEtwSourceUnknown = 0;
        internal const uint IpcEtwSourceSleepwalker = 1;
        internal const uint IpcEtwSourceThreatIntel = 2;

        internal const int ErrorNoMoreItems = 259;
        internal const int ErrorNoMoreEntries = 259;
        internal const int ErrorDeviceNotConnected = 1167;
        internal const int ErrorOperationAborted = 995;
        internal const int ErrorNotReady = 21;
        internal const int ErrorBrokenPipe = 109;
        internal const int ErrorNotSupported = 50;
        internal const int ErrorInvalidFunction = 1;

        internal const int EventReadBufferBytes = 2048;

        private const int MaxIpcEventNameChars = 96;
        private const int MaxIpcDetectionNameChars = 128;

        [StructLayout(LayoutKind.Sequential, Pack = 8)]
        internal struct SwStatsResponse
        {
            public uint SubscriptionCount;
            public uint QueueDepth;
            public uint DroppedEvents;
            public uint Reserved;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 8)]
        internal struct SwIpcEtwEvent
        {
            public uint Source;
            public ushort EventId;
            public ushort Opcode;
            public ushort Task;
            public ushort Reserved0;
            public uint EventProcessId;
            public uint EventThreadId;
            public uint Severity;
            public uint Reserved1;
            public ulong PrimaryPid;
            public ulong SecondaryPid;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = MaxIpcEventNameChars)]
            public ushort[] EventName;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = MaxIpcDetectionNameChars)]
            public byte[] DetectionName;
        }

        [DllImport("SleepwalkerSensorCore.dll", EntryPoint = "SLEEPWALKERSCUseClientProtocol", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool UseClientProtocol(string? pipeName, uint connectTimeoutMs);

        [DllImport("SleepwalkerSensorCore.dll", EntryPoint = "SLEEPWALKERSCOpenControlDevice", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
        internal static extern IntPtr OpenControlDevice();

        [DllImport("SleepwalkerSensorCore.dll", EntryPoint = "SLEEPWALKERSCGetBrokerInfo", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool GetBrokerInfo(out uint capabilities, [MarshalAs(UnmanagedType.Bool)] out bool threatIntelEnabled);

        [DllImport("SleepwalkerSensorCore.dll", EntryPoint = "SLEEPWALKERSCGetBrokerThreatIntelEnableError", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
        internal static extern uint GetBrokerThreatIntelEnableError();

        [DllImport("SleepwalkerSensorCore.dll", EntryPoint = "SLEEPWALKERSCSetPids", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool SetPids(IntPtr device, [In] uint[] processIds, uint processCount, uint streamMask);

        [DllImport("SleepwalkerSensorCore.dll", EntryPoint = "SLEEPWALKERSCGetEvent", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool GetEventRaw(IntPtr device, IntPtr recordBuffer, out uint bytesReturned);

        [DllImport("SleepwalkerSensorCore.dll", EntryPoint = "SLEEPWALKERSCGetEtwEvent", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool GetEtwEvent(IntPtr device, out SwIpcEtwEvent etwEvent, uint timeoutMs);

        [DllImport("SleepwalkerSensorCore.dll", EntryPoint = "SLEEPWALKERSCGetStats", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool GetStats(IntPtr device, out SwStatsResponse stats, out uint bytesReturned);

        [DllImport("SleepwalkerSensorCore.dll", EntryPoint = "SLEEPWALKERSCSetShutdownMode", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool SetShutdownMode(IntPtr device);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CloseHandle(IntPtr hObject);

        internal static string WideBufferToString(ushort[]? buffer)
        {
            if (buffer == null || buffer.Length == 0)
            {
                return string.Empty;
            }

            int len = Array.IndexOf(buffer, (ushort)0);
            if (len < 0)
            {
                len = buffer.Length;
            }

            if (len == 0)
            {
                return string.Empty;
            }

            char[] chars = new char[len];
            for (int i = 0; i < len; i += 1)
            {
                chars[i] = (char)buffer[i];
            }

            return new string(chars);
        }

        internal static string AnsiBufferToString(byte[]? buffer)
        {
            if (buffer == null || buffer.Length == 0)
            {
                return string.Empty;
            }

            int len = Array.IndexOf(buffer, (byte)0);
            if (len < 0)
            {
                len = buffer.Length;
            }

            if (len == 0)
            {
                return string.Empty;
            }

            return System.Text.Encoding.ASCII.GetString(buffer, 0, len);
        }

        internal static Win32Exception LastError(string context)
        {
            int err = Marshal.GetLastWin32Error();
            return new Win32Exception(err, $"{context} (win32={err})");
        }

        internal static bool TryParseIoctlEvent(byte[] buffer, int bytesRead, out IoctlParsedEvent parsed)
        {
            parsed = new IoctlParsedEvent();
            if (bytesRead < 24)
            {
                return false;
            }

            uint type = ReadU32(buffer, 4);
            parsed.Type = type;
            parsed.StreamMask = ReadU32(buffer, 8);
            parsed.Sequence = ReadU32(buffer, 12);

            const int payloadOffset = 24;
            if (bytesRead < payloadOffset + 56)
            {
                return false;
            }

            if (type == EventTypeHandle)
            {
                parsed.CallerPid = ToPid(ReadU64(buffer, payloadOffset + 0));
                parsed.TargetPid = ToPid(ReadU64(buffer, payloadOffset + 8));
                parsed.DesiredAccess = ReadU32(buffer, payloadOffset + 16);
                parsed.HandleClass = ReadU32(buffer, payloadOffset + 20);
                parsed.OriginAddress = ReadU64(buffer, payloadOffset + 24);
                parsed.HandleFlags = ReadU32(buffer, payloadOffset + 36);
                return true;
            }

            if (type == EventTypeThread)
            {
                parsed.ProcessPid = ToPid(ReadU64(buffer, payloadOffset + 0));
                parsed.ThreadId = ToPid(ReadU64(buffer, payloadOffset + 8));
                parsed.CreatorPid = ToPid(ReadU64(buffer, payloadOffset + 16));
                parsed.StartAddress = ReadU64(buffer, payloadOffset + 24);
                parsed.ImageBase = ReadU64(buffer, payloadOffset + 32);
                parsed.ImageSize = ReadU64(buffer, payloadOffset + 40);
                parsed.ThreadFlags = ReadU32(buffer, payloadOffset + 48);
                return true;
            }

            return false;
        }

        private static uint ToPid(ulong value)
        {
            return value > uint.MaxValue ? 0u : (uint)value;
        }

        private static uint ReadU32(byte[] buffer, int offset)
        {
            if (offset < 0 || offset + 4 > buffer.Length)
            {
                return 0;
            }

            return BinaryPrimitives.ReadUInt32LittleEndian(buffer.AsSpan(offset, 4));
        }

        private static ulong ReadU64(byte[] buffer, int offset)
        {
            if (offset < 0 || offset + 8 > buffer.Length)
            {
                return 0;
            }

            return BinaryPrimitives.ReadUInt64LittleEndian(buffer.AsSpan(offset, 8));
        }
    }
}
