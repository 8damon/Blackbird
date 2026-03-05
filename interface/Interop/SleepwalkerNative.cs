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
        internal const uint IpcCapSharedRing = 0x00000008;

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
        private const int MaxIpcReasonChars = 256;

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
            public uint CorrelationFlags;
            public uint CorrelationAccessMask;
            public uint CorrelationAgeMs;
            public uint Reserved2;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = MaxIpcReasonChars)]
            public ushort[] Reason;
        }

        [DllImport("SleepwalkerSensorCore.dll", EntryPoint = "SLEEPWALKERSCUseClientProtocol", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool UseClientProtocol(string? pipeName, uint connectTimeoutMs);

        [DllImport("SleepwalkerSensorCore.dll", EntryPoint = "SLEEPWALKERSCOpenControlDevice", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
        internal static extern IntPtr OpenControlDevice();

        [DllImport("SleepwalkerSensorCore.dll", EntryPoint = "SLEEPWALKERSCCloseControlDevice", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CloseControlDevice(IntPtr device);

        [DllImport("SleepwalkerSensorCore.dll", EntryPoint = "SLEEPWALKERSCGetBrokerInfo", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool GetBrokerInfo(out uint capabilities, [MarshalAs(UnmanagedType.Bool)] out bool threatIntelEnabled);

        [DllImport("SleepwalkerSensorCore.dll", EntryPoint = "SLEEPWALKERSCHasSharedChannel", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool HasSharedChannel(
            IntPtr device,
            [MarshalAs(UnmanagedType.Bool)] out bool hasIoctlChannel,
            [MarshalAs(UnmanagedType.Bool)] out bool hasEtwChannel);

        [DllImport("SleepwalkerSensorCore.dll", EntryPoint = "SLEEPWALKERSCGetLastSharedRingError", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
        internal static extern uint GetLastSharedRingError();

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

            return SanitizeTelemetryText(new string(chars));
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

            return SanitizeTelemetryText(System.Text.Encoding.ASCII.GetString(buffer, 0, len));
        }

        private static string SanitizeTelemetryText(string? value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return string.Empty;
            }

            string trimmed = value.Replace('\0', ' ').Trim();
            if (trimmed.Length == 0)
            {
                return string.Empty;
            }

            Span<char> scratch = stackalloc char[trimmed.Length];
            int written = 0;
            for (int i = 0; i < trimmed.Length; i += 1)
            {
                char ch = trimmed[i];
                if (!char.IsControl(ch) || ch == '\t')
                {
                    scratch[written++] = ch;
                }
            }

            return written == 0 ? string.Empty : new string(scratch.Slice(0, written));
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
            if (type == EventTypeHandle)
            {
                const int legacyHandlePayloadSize = 744;
                const int fullFrameSlots = 32;
                const int stackSnapshotBytes = 256;
                if (bytesRead < payloadOffset + legacyHandlePayloadSize)
                {
                    return false;
                }

                parsed.CallerPid = ToPid(ReadU64(buffer, payloadOffset + 0));
                parsed.TargetPid = ToPid(ReadU64(buffer, payloadOffset + 8));
                parsed.DesiredAccess = ReadU32(buffer, payloadOffset + 16);
                parsed.HandleClass = ReadU32(buffer, payloadOffset + 20);
                parsed.OriginAddress = ReadU64(buffer, payloadOffset + 24);
                parsed.OriginProtect = ReadU32(buffer, payloadOffset + 32);
                parsed.HandleFlags = ReadU32(buffer, payloadOffset + 36);
                parsed.FrameCount = ReadU32(buffer, payloadOffset + 40);
                parsed.Frames = new ulong[8];
                for (int i = 0; i < parsed.Frames.Length; i += 1)
                {
                    parsed.Frames[i] = ReadU64(buffer, payloadOffset + 48 + (i * 8));
                }
                parsed.StatusOpenProcess = ReadI32(buffer, payloadOffset + 112);
                parsed.StatusBasicInfo = ReadI32(buffer, payloadOffset + 116);
                parsed.StatusSectionName = ReadI32(buffer, payloadOffset + 120);
                parsed.DeepAllocationBase = ReadU64(buffer, payloadOffset + 128);
                parsed.DeepRegionSize = ReadU64(buffer, payloadOffset + 136);
                parsed.DeepRegionProtect = ReadU32(buffer, payloadOffset + 144);
                parsed.DeepRegionState = ReadU32(buffer, payloadOffset + 148);
                parsed.DeepRegionType = ReadU32(buffer, payloadOffset + 152);
                parsed.DeepSampleSize = ReadU32(buffer, payloadOffset + 156);
                parsed.DeepSample = new byte[64];
                int deepCopy = Math.Min(parsed.DeepSample.Length, Math.Min((int)parsed.DeepSampleSize, Math.Max(0, bytesRead - (payloadOffset + 160))));
                if (deepCopy > 0)
                {
                    Buffer.BlockCopy(buffer, payloadOffset + 160, parsed.DeepSample, 0, deepCopy);
                }
                parsed.OriginPath = ReadWideFixedString(buffer, payloadOffset + 224, 260);

                int extendedBase = payloadOffset + legacyHandlePayloadSize;
                parsed.CaptureFlags = ReadU32(buffer, extendedBase + 0);
                parsed.FullFrameCount = ReadU32(buffer, extendedBase + 4);
                parsed.FullFrames = new ulong[fullFrameSlots];
                for (int i = 0; i < parsed.FullFrames.Length; i += 1)
                {
                    parsed.FullFrames[i] = ReadU64(buffer, extendedBase + 8 + (i * 8));
                }

                int registerOffset = extendedBase + 264;
                parsed.RegRax = ReadU64(buffer, registerOffset + 0);
                parsed.RegRbx = ReadU64(buffer, registerOffset + 8);
                parsed.RegRcx = ReadU64(buffer, registerOffset + 16);
                parsed.RegRdx = ReadU64(buffer, registerOffset + 24);
                parsed.RegRsi = ReadU64(buffer, registerOffset + 32);
                parsed.RegRdi = ReadU64(buffer, registerOffset + 40);
                parsed.RegRbp = ReadU64(buffer, registerOffset + 48);
                parsed.RegRsp = ReadU64(buffer, registerOffset + 56);
                parsed.RegR8 = ReadU64(buffer, registerOffset + 64);
                parsed.RegR9 = ReadU64(buffer, registerOffset + 72);
                parsed.RegR10 = ReadU64(buffer, registerOffset + 80);
                parsed.RegR11 = ReadU64(buffer, registerOffset + 88);
                parsed.RegR12 = ReadU64(buffer, registerOffset + 96);
                parsed.RegR13 = ReadU64(buffer, registerOffset + 104);
                parsed.RegR14 = ReadU64(buffer, registerOffset + 112);
                parsed.RegR15 = ReadU64(buffer, registerOffset + 120);
                parsed.RegRip = ReadU64(buffer, registerOffset + 128);
                parsed.RegEFlags = ReadU64(buffer, registerOffset + 136);
                parsed.RegDr0 = ReadU64(buffer, registerOffset + 144);
                parsed.RegDr1 = ReadU64(buffer, registerOffset + 152);
                parsed.RegDr2 = ReadU64(buffer, registerOffset + 160);
                parsed.RegDr3 = ReadU64(buffer, registerOffset + 168);
                parsed.RegDr6 = ReadU64(buffer, registerOffset + 176);
                parsed.RegDr7 = ReadU64(buffer, registerOffset + 184);
                parsed.StackSnapshotAddress = ReadU64(buffer, registerOffset + 192);
                parsed.StackSnapshotSize = ReadU32(buffer, registerOffset + 200);
                parsed.StackSnapshot = new byte[stackSnapshotBytes];
                int stackCopy = Math.Min(
                    parsed.StackSnapshot.Length,
                    Math.Min((int)parsed.StackSnapshotSize, Math.Max(0, bytesRead - (registerOffset + 204))));
                if (stackCopy > 0)
                {
                    Buffer.BlockCopy(buffer, registerOffset + 204, parsed.StackSnapshot, 0, stackCopy);
                }
                return true;
            }

            if (type == EventTypeThread)
            {
                const int threadPayloadSize = 120;
                if (bytesRead < payloadOffset + threadPayloadSize)
                {
                    return false;
                }

                parsed.ProcessPid = ToPid(ReadU64(buffer, payloadOffset + 0));
                parsed.ThreadId = ToPid(ReadU64(buffer, payloadOffset + 8));
                parsed.CreatorPid = ToPid(ReadU64(buffer, payloadOffset + 16));
                parsed.StartAddress = ReadU64(buffer, payloadOffset + 24);
                parsed.ImageBase = ReadU64(buffer, payloadOffset + 32);
                parsed.ImageSize = ReadU64(buffer, payloadOffset + 40);
                parsed.ThreadFlags = ReadU32(buffer, payloadOffset + 48);
                parsed.ThreadFrameCount = ReadU32(buffer, payloadOffset + 52);
                parsed.ThreadFrames = new ulong[8];
                for (int i = 0; i < parsed.ThreadFrames.Length; i += 1)
                {
                    parsed.ThreadFrames[i] = ReadU64(buffer, payloadOffset + 56 + (i * 8));
                }
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

        private static int ReadI32(byte[] buffer, int offset)
        {
            if (offset < 0 || offset + 4 > buffer.Length)
            {
                return 0;
            }

            return BinaryPrimitives.ReadInt32LittleEndian(buffer.AsSpan(offset, 4));
        }

        private static ulong ReadU64(byte[] buffer, int offset)
        {
            if (offset < 0 || offset + 8 > buffer.Length)
            {
                return 0;
            }

            return BinaryPrimitives.ReadUInt64LittleEndian(buffer.AsSpan(offset, 8));
        }

        private static string ReadWideFixedString(byte[] buffer, int offset, int maxChars)
        {
            if (offset < 0 || maxChars <= 0 || offset >= buffer.Length)
            {
                return string.Empty;
            }

            int maxBytes = Math.Min(maxChars * 2, buffer.Length - offset);
            if (maxBytes <= 0)
            {
                return string.Empty;
            }

            int terminator = -1;
            for (int i = 0; i + 1 < maxBytes; i += 2)
            {
                if (buffer[offset + i] == 0 && buffer[offset + i + 1] == 0)
                {
                    terminator = i;
                    break;
                }
            }

            int lenBytes = terminator >= 0 ? terminator : maxBytes;
            if (lenBytes <= 0)
            {
                return string.Empty;
            }

            return System.Text.Encoding.Unicode.GetString(buffer, offset, lenBytes);
        }
    }
}
