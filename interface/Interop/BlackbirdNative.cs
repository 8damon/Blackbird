using System;
using System.Buffers.Binary;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace BlackbirdInterface
{
    internal static class BlackbirdNative
    {
        internal const uint StreamHandle = 0x00000001;
        internal const uint StreamMemory = 0x00000002;
        internal const uint StreamThread = 0x00000004;
        internal const uint StreamFilesystem = 0x00000008;
        internal const uint StreamAll = StreamHandle | StreamMemory | StreamThread | StreamFilesystem;

        internal const uint EventTypeHandle = 1;
        internal const uint EventTypeThread = 2;
        internal const uint EventTypeFileSystem = 3;

        internal const uint FileOperationUnknown = 0;
        internal const uint FileOperationCreate = 1;
        internal const uint FileOperationRead = 2;
        internal const uint FileOperationWrite = 3;
        internal const uint FileOperationClose = 4;
        internal const uint FileOperationCleanup = 5;
        internal const uint FileOperationSetInformation = 6;
        internal const uint FileOperationQueryInformation = 7;
        internal const uint FileOperationDirectoryControl = 8;
        internal const uint FileOperationFsControl = 9;

        internal const uint IpcCapDriverProxy = 0x00000001;
        internal const uint IpcCapEtwTiSession = 0x00000002;
        internal const uint IpcCapEtwTiUplink = 0x00000004;
        internal const uint IpcCapSharedRing = 0x00000008;
        internal const uint IpcCapUserHookIngest = 0x00000010;

        internal const uint IpcEtwSourceUnknown = 0;
        internal const uint IpcEtwSourceBlackbird = 1;
        internal const uint IpcEtwSourceThreatIntel = 2;
        internal const uint IpcEtwSourceKernelNetwork = 3;

        internal const int ErrorNoMoreItems = 259;
        internal const int ErrorNoMoreEntries = 259;
        internal const int ErrorDeviceNotConnected = 1167;
        internal const int ErrorOperationAborted = 995;
        internal const int ErrorNotReady = 21;
        internal const int ErrorBrokenPipe = 109;
        internal const int ErrorNotSupported = 50;
        internal const int ErrorInvalidFunction = 1;

        internal const int EventReadBufferBytes = 8192;
        internal const int MaxIpcHookImagePathChars = 1024;
        internal const uint IpcUserHookTargetNone = 0;
        internal const uint IpcUserHookTargetAttach = 1;
        internal const uint IpcUserHookTargetLaunch = 2;
        internal const uint IpcUserHookFlagLaunchEarlybirdApc = 0x00000001;

        private const int MaxIpcEventNameChars = 96;
        private const int MaxIpcDetectionNameChars = 128;
        private const int MaxIpcReasonChars = 256;
        private const int MaxIpcShortTextChars = 64;
        private const int MaxIpcImagePathChars = 260;
        private const int MaxIpcCommandLineChars = 512;
        private const int MaxIpcKeyPathChars = 512;
        private const int MaxIpcValueNameChars = 256;
        private const int MaxIpcStackFrames = 8;
        private const int MaxIpcDeepSampleBytes = 64;

        internal const uint IpcEtwFamilyUnknown = 0;
        internal const uint IpcEtwFamilyHandle = 1;
        internal const uint IpcEtwFamilyThread = 2;
        internal const uint IpcEtwFamilyProcess = 3;
        internal const uint IpcEtwFamilyImage = 4;
        internal const uint IpcEtwFamilyRegistry = 5;
        internal const uint IpcEtwFamilyApc = 6;
        internal const uint IpcEtwFamilyDetection = 7;
        internal const uint IpcEtwFamilyThreatIntel = 8;
        internal const uint IpcEtwFamilySocket = 9;
        internal const uint IpcEtwFamilyUserHook = 10;

        internal const uint IpcEtwFlagHandleExecProtect = 0x00000001;
        internal const uint IpcEtwFlagHandleFromNtdll = 0x00000002;
        internal const uint IpcEtwFlagHandleFromExe = 0x00000004;
        internal const uint IpcEtwFlagThreadGotStart = 0x00000008;
        internal const uint IpcEtwFlagThreadGotRange = 0x00000010;
        internal const uint IpcEtwFlagThreadRemoteCreator = 0x00000020;
        internal const uint IpcEtwFlagThreadOutsideMainImage = 0x00000040;
        internal const uint IpcEtwFlagProcessIsCreate = 0x00000080;
        internal const uint IpcEtwFlagImageSystemMode = 0x00000100;
        internal const uint IpcEtwFlagImageSignatureKnown = 0x00000200;
        internal const uint IpcEtwFlagRegistryHighValue = 0x00000400;
        internal const uint IpcEtwFlagApcDuplicateOperation = 0x00000800;

        [StructLayout(LayoutKind.Sequential, Pack = 8)]
        internal struct BkStatsResponse
        {
            public uint SubscriptionCount;
            public uint QueueDepth;
            public uint DroppedEvents;
            public uint Reserved;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 8)]
        internal struct BkIpcEtwEvent
        {
            public uint Source;
            public uint Family;
            public ushort EventId;
            public ushort Opcode;
            public ushort Task;
            public ushort Reserved0;
            public uint EventProcessId;
            public uint EventThreadId;
            public uint Severity;
            public uint Flags;
            public ulong ProcessId;
            public ulong ThreadId;
            public ulong CallerPid;
            public ulong TargetPid;
            public ulong ParentProcessId;
            public ulong CreatorProcessId;
            public ulong CreatorThreadId;
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
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = MaxIpcShortTextChars)]
            public byte[] ClassName;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = MaxIpcShortTextChars)]
            public byte[] Operation;
            public uint DesiredAccess;
            public uint OriginProtect;
            public ulong OriginAddress;
            public int StatusOpenProcess;
            public int StatusBasicInfo;
            public int StatusSectionName;
            public uint StackCount;
            public uint Reserved3;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = MaxIpcStackFrames)]
            public ulong[] Stack;
            public ulong DeepAllocationBase;
            public ulong DeepRegionSize;
            public uint DeepRegionProtect;
            public uint DeepRegionState;
            public uint DeepRegionType;
            public uint DeepSampleSize;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = MaxIpcDeepSampleBytes)]
            public byte[] DeepSample;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = MaxIpcImagePathChars)]
            public ushort[] OriginPath;
            public ulong StartAddress;
            public ulong ImageBase;
            public ulong ImageSize;
            public uint StartRegionProtect;
            public uint StartRegionState;
            public uint StartRegionType;
            public int StartRegionStatus;
            public uint SessionId;
            public int CreateStatus;
            public ulong ProcessStartKey;
            public byte SignatureLevel;
            public byte SignatureType;
            public ushort Reserved4;
            public uint NotifyClass;
            public uint DataType;
            public uint DataSize;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = MaxIpcImagePathChars)]
            public ushort[] ImagePath;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = MaxIpcCommandLineChars)]
            public ushort[] CommandLine;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = MaxIpcKeyPathChars)]
            public ushort[] KeyPath;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = MaxIpcValueNameChars)]
            public ushort[] ValueName;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 8)]
        internal struct BkSetUserHookTargetResponse
        {
            public uint ProcessId;
            public int Status;
            public uint Reserved0;
            public uint Reserved1;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = MaxIpcHookImagePathChars)]
            public ushort[] ImagePath;
        }

        [DllImport("BlackbirdSensorCore.dll", EntryPoint = "BLACKBIRDSCUseClientProtocol", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool UseClientProtocol(string? pipeName, uint connectTimeoutMs);

        [DllImport("BlackbirdSensorCore.dll", EntryPoint = "BLACKBIRDSCOpenControlDevice", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
        internal static extern IntPtr OpenControlDevice();

        [DllImport("BlackbirdSensorCore.dll", EntryPoint = "BLACKBIRDSCCloseControlDevice", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CloseControlDevice(IntPtr device);

        [DllImport("BlackbirdSensorCore.dll", EntryPoint = "BLACKBIRDSCGetBrokerInfo", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool GetBrokerInfo(out uint capabilities, [MarshalAs(UnmanagedType.Bool)] out bool threatIntelEnabled);

        [DllImport("BlackbirdSensorCore.dll", EntryPoint = "BLACKBIRDSCHasSharedChannel", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool HasSharedChannel(
            IntPtr device,
            [MarshalAs(UnmanagedType.Bool)] out bool hasIoctlChannel,
            [MarshalAs(UnmanagedType.Bool)] out bool hasEtwChannel);

        [DllImport("BlackbirdSensorCore.dll", EntryPoint = "BLACKBIRDSCGetLastSharedRingError", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
        internal static extern uint GetLastSharedRingError();

        [DllImport("BlackbirdSensorCore.dll", EntryPoint = "BLACKBIRDSCGetBrokerThreatIntelEnableError", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
        internal static extern uint GetBrokerThreatIntelEnableError();

        [DllImport("BlackbirdSensorCore.dll", EntryPoint = "BLACKBIRDSCSetPids", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool SetPids(IntPtr device, [In] uint[] processIds, uint processCount, uint streamMask);

        [DllImport("BlackbirdSensorCore.dll", EntryPoint = "BLACKBIRDSCGetEvent", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool GetEventRaw(IntPtr device, IntPtr recordBuffer, out uint bytesReturned);

        [DllImport("BlackbirdSensorCore.dll", EntryPoint = "BLACKBIRDSCGetEtwEvent", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool GetEtwEvent(IntPtr device, out BkIpcEtwEvent etwEvent, uint timeoutMs);

        [DllImport("BlackbirdSensorCore.dll", EntryPoint = "BLACKBIRDSCGetStats", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool GetStats(IntPtr device, out BkStatsResponse stats, out uint bytesReturned);

        [DllImport("BlackbirdSensorCore.dll", EntryPoint = "BLACKBIRDSCSetShutdownMode", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool SetShutdownMode(IntPtr device);

        [DllImport("BlackbirdSensorCore.dll", EntryPoint = "BLACKBIRDSCSetUserHookTarget", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool SetUserHookTarget(
            IntPtr device,
            uint mode,
            uint processId,
            uint flags,
            string? imagePath,
            string? hookDllPath,
            out BkSetUserHookTargetResponse response);

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
                const int baseHandlePayloadSize = 744;
                const int fullFrameSlots = 32;
                const int stackSnapshotBytes = 256;
                if (bytesRead < payloadOffset + baseHandlePayloadSize)
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

                int extendedBase = payloadOffset + baseHandlePayloadSize;
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

            if (type == EventTypeFileSystem)
            {
                const int filePayloadSize = 1140;
                if (bytesRead < payloadOffset + filePayloadSize)
                {
                    return false;
                }

                parsed.FileProcessPid = ToPid(ReadU64(buffer, payloadOffset + 0));
                parsed.FileThreadId = ToPid(ReadU64(buffer, payloadOffset + 8));
                parsed.FileObject = ReadU64(buffer, payloadOffset + 16);
                parsed.FileId = ReadU64(buffer, payloadOffset + 24);
                parsed.FileByteOffset = ReadU64(buffer, payloadOffset + 32);
                parsed.FileLength = ReadU64(buffer, payloadOffset + 40);
                parsed.FileStatus = ReadU64(buffer, payloadOffset + 48);
                parsed.FileInformation = ReadU64(buffer, payloadOffset + 56);
                parsed.FileOperation = ReadU32(buffer, payloadOffset + 64);
                parsed.FileMajorCode = ReadU32(buffer, payloadOffset + 68);
                parsed.FileMinorCode = ReadU32(buffer, payloadOffset + 72);
                parsed.FileIrpFlags = ReadU32(buffer, payloadOffset + 76);
                parsed.FileCreateOptions = ReadU32(buffer, payloadOffset + 80);
                parsed.FileCreateDisposition = ReadU32(buffer, payloadOffset + 84);
                parsed.FileDesiredAccess = ReadU32(buffer, payloadOffset + 88);
                parsed.FileShareAccess = ReadU32(buffer, payloadOffset + 92);
                parsed.FileFlags = ReadU32(buffer, payloadOffset + 96);
                parsed.FilePath = ReadWideFixedString(buffer, payloadOffset + 100, 520);
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
