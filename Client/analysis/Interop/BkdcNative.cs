using System;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;

namespace BlackbirdInterface
{
    internal static class BkdcNative
    {
        private const string DllName = "BKDC.dll";

        internal const byte TargetKindNone = 0;
        internal const byte TargetKindDirect = 1;
        internal const byte TargetKindIndirect = 2;
        internal const byte TargetKindIat = 3;
        internal const byte TargetKindEat = 4;

        /// True if BKDC.dll was found and loaded successfully.
        internal static bool IsAvailable { get; }

        static BkdcNative()
        {
            bool found = TryLocateDll(out string? resolvedPath);
            IsAvailable = found && resolvedPath != null &&
                          NativeLibrary.TryLoad(resolvedPath, typeof(BkdcNative).Assembly, null, out _);

            DiagnosticsState.SetValue(
                "Disassembly Engine",
                IsAvailable ? "Ready" : $"Disabled — {DllName} not found. Build Lib/BK_disassembler to enable.");
        }

        private static bool TryLocateDll(out string? path)
        {
            string[] candidates = [
                Path.Combine(AppContext.BaseDirectory, DllName),
                Path.Combine(Environment.CurrentDirectory, DllName),
            ];

            string? pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            if (!string.IsNullOrWhiteSpace(pf))
            {
                candidates = [..candidates, Path.Combine(pf, "Blackbird", DllName)];
            }

            foreach (string candidate in candidates)
            {
                if (File.Exists(candidate))
                {
                    path = candidate;
                    return true;
                }
            }

            path = null;
            return false;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 8)]
        internal struct BkdcInstruction
        {
            public ulong Address;
            public byte Size;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 7)]
            public byte[] Pad;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
            public byte[] Mnemonic;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 160)]
            public byte[] OpStr;
            public ulong ResolvedTarget;
            public byte TargetKind;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 7)]
            public byte[] Pad2;

            public string GetMnemonic() => NullTerminatedAscii(Mnemonic);
            public string GetOpStr() => NullTerminatedAscii(OpStr);

            private static string NullTerminatedAscii(byte[]? buf)
            {
                if (buf == null)
                    return string.Empty;
                int len = Array.IndexOf(buf, (byte)0);
                return System.Text.Encoding.ASCII.GetString(buf, 0, len < 0 ? buf.Length : len);
            }
        }

        [DllImport(DllName, EntryPoint = "BkDsDisassemble", CallingConvention = CallingConvention.Cdecl)]
        private static extern uint BkdcDisassembleNative(IntPtr bytes, uint byteLen, ulong baseAddress, IntPtr outBuf,
                                                         uint outCapacity);

        [DllImport(DllName, EntryPoint = "BkDsDisassembleEx", CallingConvention = CallingConvention.Cdecl)]
        private static extern uint BkdcDisassembleExNative(IntPtr bytes, uint byteLen, ulong baseAddress, IntPtr outBuf,
                                                           uint outCapacity, IntPtr context);

        [DllImport(DllName, EntryPoint = "BkDcSetExportMap", CallingConvention = CallingConvention.Cdecl)]
        [return:MarshalAs(UnmanagedType.I1)]
        private static extern bool BkdcSetExportMapNative(IntPtr entries, uint count, out IntPtr context);

        [DllImport(DllName, EntryPoint = "BkDcFreeContext", CallingConvention = CallingConvention.Cdecl)]
        private static extern void BkdcFreeContextNative(IntPtr context);

        /// Disassemble `code` as x64 at `baseAddress`.
        /// Returns an empty array if BKDC.dll is unavailable.
        internal static BkdcInstruction[] Disassemble(byte[] code, ulong baseAddress, int maxInstructions = 512)
        {
            if (!IsAvailable || code == null || code.Length == 0)
                return Array.Empty<BkdcInstruction>();

            int stride = Marshal.SizeOf<BkdcInstruction>();
            IntPtr pCode = Marshal.AllocHGlobal(code.Length);
            IntPtr pOut = Marshal.AllocHGlobal(stride * maxInstructions);
            try
            {
                Marshal.Copy(code, 0, pCode, code.Length);
                uint count = BkdcDisassembleNative(pCode, (uint)code.Length, baseAddress, pOut, (uint)maxInstructions);
                var result = new BkdcInstruction[count];
                for (int i = 0; i < (int)count; i++)
                    result[i] = Marshal.PtrToStructure<BkdcInstruction>(pOut + i * stride);
                return result;
            }
            finally
            {
                Marshal.FreeHGlobal(pCode);
                Marshal.FreeHGlobal(pOut);
            }
        }
    }
}
