using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace BlackbirdInterface
{
    [SupportedOSPlatform("windows")]
    internal static class ThreadStackResolver
    {
        private const uint THREAD_SUSPEND_RESUME = 0x0002;
        private const uint THREAD_GET_CONTEXT = 0x0008;
        private const uint THREAD_QUERY_INFORMATION = 0x0040;
        private const uint PROCESS_QUERY_INFORMATION = 0x0400;
        private const uint PROCESS_VM_READ = 0x0010;

        private const uint CONTEXT_AMD64 = 0x00100000;
        private const uint CONTEXT_CONTROL = CONTEXT_AMD64 | 0x00000001;
        private const uint CONTEXT_INTEGER = CONTEXT_AMD64 | 0x00000002;
        private const uint CONTEXT_FULL = CONTEXT_CONTROL | CONTEXT_INTEGER;

        private const uint IMAGE_FILE_MACHINE_AMD64 = 0x8664;
        private const uint AddrModeFlat = 3;
        private const int MaxFrames = 128;
        private const int MaxSymbolName = 1024;

        private const uint SYMOPT_UNDNAME = 0x00000002;
        private const uint SYMOPT_DEFERRED_LOADS = 0x00000004;
        private const uint SYMOPT_LOAD_LINES = 0x00000010;

        private static readonly FunctionTableAccessRoutine64 s_functionTableAccess = SymFunctionTableAccess64;
        private static readonly GetModuleBaseRoutine64 s_getModuleBase = SymGetModuleBase64;
        private static readonly object s_dbgHelpLock = new();

        public static ThreadStackResolveResult Resolve(int pid, int tid, string state)
        {
            if (!Environment.Is64BitProcess)
                return new ThreadStackResolveResult(new List<StackFrameRow>(), "", 0, 0, 0, null, 0, null);

            bool debugPrivilegeEnabled = Kernel32Native.EnableDebugPrivilege(out int debugPrivilegeError);

            if (tid == GetCurrentThreadId())
                return ResolveCurrentThreadManaged(pid, tid, state);

            IntPtr hProcess = IntPtr.Zero;
            IntPtr hThread = IntPtr.Zero;
            bool closeProcess = false;
            bool threadSuspended = false;
            bool symbolsReady = false;
            bool processMemoryAvailable = false;
            string note = string.Empty;

            try
            {
                hProcess = Kernel32Native.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false,
                                                      unchecked((uint)pid));
                if (hProcess == IntPtr.Zero)
                {
                    int err = Marshal.GetLastWin32Error();
                    if (pid != Environment.ProcessId)
                    {
                        string debugState = debugPrivilegeEnabled
                                                ? "SeDebugPrivilege enabled"
                                                : $"SeDebugPrivilege unavailable win32={debugPrivilegeError}";
                        note =
                            $"OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ) failed win32={err}; {debugState}; showing thread context only if available.";
                        hProcess = GetCurrentProcess();
                    }
                    else
                    {
                        hProcess = GetCurrentProcess();
                        processMemoryAvailable = true;
                    }
                }
                else
                {
                    closeProcess = true;
                    processMemoryAvailable = true;
                }

                hThread =
                    OpenThread(THREAD_QUERY_INFORMATION | THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME, false, (uint)tid);
                if (hThread == IntPtr.Zero)
                {
                    int err = Marshal.GetLastWin32Error();
                    string prefix = string.IsNullOrWhiteSpace(note) ? string.Empty : $"{note} ";
                    return new ThreadStackResolveResult(new List<StackFrameRow>(),
                                                        $"{prefix}Thread handle unavailable (win32={err}).", 0, 0, 0,
                                                        null, 0, null);
                }

                ulong tebAddress = 0;
                ulong stackBase = 0;
                ulong stackTop = 0;
                ushort? tebFlags = null;
                if (processMemoryAvailable)
                {
                    TryReadThreadMetadata(hProcess, hThread, out tebAddress, out stackBase, out stackTop, out tebFlags);
                }

                if (SuspendThread(hThread) != uint.MaxValue)
                    threadSuspended = true;

                var context = new CONTEXT64 { ContextFlags = CONTEXT_FULL,
                                              DUMMYUNIONNAME = new XMM_SAVE_AREA32 { FloatRegisters = new M128A[8],
                                                                                     XmmRegisters = new M128A[16],
                                                                                     Reserved4 = new byte[96] },
                                              VectorRegister = new M128A[26] };

                if (!GetThreadContext(hThread, ref context))
                {
                    int err = Marshal.GetLastWin32Error();
                    string prefix = string.IsNullOrWhiteSpace(note) ? string.Empty : $"{note} ";
                    return new ThreadStackResolveResult(new List<StackFrameRow>(),
                                                        $"{prefix}GetThreadContext failed (win32={err}).", tebAddress,
                                                        stackBase, stackTop, tebFlags, 0, null);
                }

                if (!processMemoryAvailable)
                {
                    return new ThreadStackResolveResult(new List<StackFrameRow>(), note, tebAddress, stackBase,
                                                        stackTop, tebFlags, context.Rsp, BuildSnapshot(context));
                }

                var moduleRanges = BuildModuleRanges(pid);
                List<StackFrameRow> frames;
                lock (s_dbgHelpLock)
                {
                    SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_LOAD_LINES);
                    symbolsReady = SymInitialize(hProcess, null, true);
                    try
                    {
                        frames = WalkFrames(hProcess, hThread, ref context, moduleRanges, symbolsReady);
                    }
                    finally
                    {
                        if (symbolsReady)
                        {
                            _ = SymCleanup(hProcess);
                            symbolsReady = false;
                        }
                    }
                }

                return new ThreadStackResolveResult(frames, note, tebAddress, stackBase, stackTop, tebFlags,
                                                    context.Rsp, BuildSnapshot(context));
            }
            catch (Exception ex)
            {
                return new ThreadStackResolveResult(new List<StackFrameRow>(), $"Stack resolve failed: {ex.Message}", 0,
                                                    0, 0, null, 0, null);
            }
            finally
            {
                if (threadSuspended)
                    _ = ResumeThread(hThread);
                if (hThread != IntPtr.Zero)
                    _ = Kernel32Native.CloseHandle(hThread);
                if (symbolsReady)
                {
                    lock (s_dbgHelpLock)
                    {
                        _ = SymCleanup(hProcess);
                    }
                }
                if (closeProcess && hProcess != IntPtr.Zero)
                    _ = Kernel32Native.CloseHandle(hProcess);
            }
        }

        private static ThreadStackResolveResult ResolveCurrentThreadManaged(int pid, int tid, string state)
        {
            var frames = new List<StackFrameRow>();
            var st = new StackTrace(true);
            var stackFrames = st.GetFrames() ?? Array.Empty<StackFrame>();
            int idx = 0;

            foreach (var f in stackFrames)
            {
                var m = f.GetMethod();
                string module = m?.DeclaringType?.FullName ?? "<managed>";
                string symbol = m == null ? "<unknown>" : $"{m.Name}()";
                string source = f.GetFileName() ?? "";
                int line = f.GetFileLineNumber();
                if (!string.IsNullOrWhiteSpace(source) && line > 0)
                    symbol += $"  ({source}:{line})";

                frames.Add(new StackFrameRow { Index = idx++, Address = "managed", Module = module, Symbol = symbol });
            }

            return new ThreadStackResolveResult(frames, "", 0, 0, 0, null, 0, null);
        }

        private static ThreadContextSnapshot BuildSnapshot(CONTEXT64 context)
        {
            return new ThreadContextSnapshot {
                Rip = context.Rip, Rsp = context.Rsp, Rbp = context.Rbp, Rax = context.Rax,      Rbx = context.Rbx,
                Rcx = context.Rcx, Rdx = context.Rdx, Rsi = context.Rsi, Rdi = context.Rdi,      R8 = context.R8,
                R9 = context.R9,   R10 = context.R10, R11 = context.R11, R12 = context.R12,      R13 = context.R13,
                R14 = context.R14, R15 = context.R15, Dr0 = context.Dr0, Dr1 = context.Dr1,      Dr2 = context.Dr2,
                Dr3 = context.Dr3, Dr6 = context.Dr6, Dr7 = context.Dr7, EFlags = context.EFlags
            };
        }

        private static void TryReadThreadMetadata(IntPtr hProcess, IntPtr hThread, out ulong tebAddress,
                                                  out ulong stackBase, out ulong stackTop, out ushort? tebFlags)
        {
            tebAddress = 0;
            stackBase = 0;
            stackTop = 0;
            tebFlags = null;

            try
            {
                int status = NtQueryInformationThread(hThread, 0, out THREAD_BASIC_INFORMATION tbi,
                                                      Marshal.SizeOf<THREAD_BASIC_INFORMATION>(), out _);
                if (status != 0 || tbi.TebBaseAddress == IntPtr.Zero)
                    return;

                tebAddress = (ulong)tbi.TebBaseAddress.ToInt64();

                int tibSize = Marshal.SizeOf<NT_TIB64>();
                byte[] tibBuf = new byte[tibSize];
                if (ReadProcessMemory(hProcess, tbi.TebBaseAddress, tibBuf, tibBuf.Length, out IntPtr bytesRead) &&
                    bytesRead.ToInt64() >= tibSize)
                {
                    GCHandle handle = GCHandle.Alloc(tibBuf, GCHandleType.Pinned);
                    try
                    {
                        var tib = Marshal.PtrToStructure<NT_TIB64>(handle.AddrOfPinnedObject());
                        stackBase = tib.StackBase;
                        stackTop = tib.StackLimit;
                    }
                    finally
                    {
                        handle.Free();
                    }
                }

                // Best-effort read of SameTebFlags (x64 common offset 0x17EE).
                byte[] flags = new byte[2];
                nint flagsAddress = (nint)(tebAddress + 0x17EE);
                if (ReadProcessMemory(hProcess, (IntPtr)flagsAddress, flags, flags.Length, out IntPtr flagsRead) &&
                    flagsRead.ToInt64() == 2)
                {
                    tebFlags = BitConverter.ToUInt16(flags, 0);
                }
            }
            catch
            {
            }
        }

        private static List<StackFrameRow> WalkFrames(IntPtr hProcess, IntPtr hThread, ref CONTEXT64 context,
                                                      List<ModuleRange> modules, bool symbolsReady)
        {
            var rows = new List<StackFrameRow>();

            var frame = new STACKFRAME64 { AddrPC = new ADDRESS64 { Offset = context.Rip, Mode = AddrModeFlat },
                                           AddrFrame = new ADDRESS64 { Offset = context.Rbp, Mode = AddrModeFlat },
                                           AddrStack = new ADDRESS64 { Offset = context.Rsp, Mode = AddrModeFlat },
                                           Params = new ulong[4], Reserved = new ulong[3] };

            AddFrameRow(rows, hProcess, context.Rip, context.Rbp, modules, symbolsReady);
            ulong lastAddress = context.Rip;

            for (int i = 0; i < MaxFrames; i++)
            {
                bool ok = StackWalk64(IMAGE_FILE_MACHINE_AMD64, hProcess, hThread, ref frame, ref context, IntPtr.Zero,
                                      s_functionTableAccess, s_getModuleBase, IntPtr.Zero);

                if (!ok)
                    break;

                ulong addr = frame.AddrPC.Offset;
                if (addr == 0)
                    break;

                if (addr == lastAddress)
                {
                    break;
                }

                AddFrameRow(rows, hProcess, addr, frame.AddrFrame.Offset, modules, symbolsReady);
                lastAddress = addr;
            }

            return rows;
        }

        private static void AddFrameRow(List<StackFrameRow> rows, IntPtr hProcess, ulong address, ulong framePointer,
                                        List<ModuleRange> modules, bool symbolsReady)
        {
            if (address == 0 || rows.Count >= MaxFrames)
            {
                return;
            }

            ResolveFrame(hProcess, address, modules, symbolsReady, out var module, out var symbol,
                         out var displayAddress);
            rows.Add(new StackFrameRow { Index = rows.Count, Address = displayAddress, Module = module, Symbol = symbol,
                                         InstructionPointerRaw = address, FramePointerRaw = framePointer });
        }

        private static void ResolveFrame(IntPtr hProcess, ulong address, List<ModuleRange> modules, bool symbolsReady,
                                         out string module, out string symbol, out string displayAddress)
        {
            ModuleRange? moduleRange = FindModule(modules, address);
            module = moduleRange?.Name ?? "<unknown>";
            displayAddress = FormatAddress(moduleRange, address);
            symbol = displayAddress;

            if (!symbolsReady)
                return;

            if (TryResolveSymbol(hProcess, address, out var symText))
                symbol = symText;

            if (TryResolveLine(hProcess, address, out var fileLine))
                symbol = $"{symbol} ({fileLine})";
        }

        private static ModuleRange? FindModule(List<ModuleRange> modules, ulong address)
        {
            foreach (var m in modules)
            {
                if (address >= m.Start && address < m.End)
                    return m;
            }

            return null;
        }

        private static string FormatAddress(ModuleRange? module, ulong address)
        {
            if (module is not ModuleRange range)
            {
                return $"0x{address:X}";
            }

            return $"{range.Name}+0x{address - range.Start:X}";
        }

        private static bool TryResolveSymbol(IntPtr hProcess, ulong address, out string symbol)
        {
            symbol = "";
            int headerSize = Marshal.SizeOf<SYMBOL_INFO>();
            IntPtr mem = Marshal.AllocHGlobal(headerSize + MaxSymbolName);
            try
            {
                var info = new SYMBOL_INFO { SizeOfStruct = (uint)headerSize, MaxNameLen = MaxSymbolName,
                                             Reserved = new ulong[2] };
                Marshal.StructureToPtr(info, mem, false);

                if (!SymFromAddr(hProcess, address, out ulong displacement, mem))
                    return false;

                int nameOffset = Marshal.OffsetOf<SYMBOL_INFO>(nameof(SYMBOL_INFO.Name)).ToInt32();
                string name = Marshal.PtrToStringAnsi(IntPtr.Add(mem, nameOffset)) ?? "";
                symbol = displacement > 0 ? $"{name}+0x{displacement:X}" : name;
                return !string.IsNullOrWhiteSpace(name);
            }
            finally
            {
                Marshal.FreeHGlobal(mem);
            }
        }

        private static bool TryResolveLine(IntPtr hProcess, ulong address, out string fileLine)
        {
            fileLine = "";
            var line = new IMAGEHLP_LINE64 { SizeOfStruct = (uint)Marshal.SizeOf<IMAGEHLP_LINE64>() };

            if (!SymGetLineFromAddr64(hProcess, address, out uint displacement, ref line))
                return false;

            if (line.FileName == IntPtr.Zero)
                return false;

            string file = Marshal.PtrToStringAnsi(line.FileName) ?? "";
            if (string.IsNullOrWhiteSpace(file))
                return false;

            fileLine = displacement > 0 ? $"{file}:{line.LineNumber}+0x{displacement:X}" : $"{file}:{line.LineNumber}";
            return true;
        }

        private static List<ModuleRange> BuildModuleRanges(int pid)
        {
            var list = new List<ModuleRange>();
            try
            {
                using var p = Process.GetProcessById(pid);
                foreach (ProcessModule m in p.Modules)
                {
                    ulong start = (ulong)m.BaseAddress.ToInt64();
                    ulong end = start + (ulong)m.ModuleMemorySize;
                    list.Add(new ModuleRange(m.ModuleName, start, end));
                }
            }
            catch
            {
            }

            return list.OrderBy(x => x.Start).ToList();
        }

        private readonly record struct ModuleRange(string Name, ulong Start, ulong End);

        [StructLayout(LayoutKind.Sequential)]
        private struct ADDRESS64
        {
            public ulong Offset;
            public ushort Segment;
            public uint Mode;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct KDHELP64
        {
            public ulong Thread;
            public uint ThCallbackStack;
            public uint ThCallbackBStore;
            public uint NextCallback;
            public uint FramePointer;
            public ulong KiCallUserMode;
            public ulong KeUserCallbackDispatcher;
            public ulong SystemRangeStart;
            public ulong KiUserExceptionDispatcher;
            public ulong StackBase;
            public ulong StackLimit;
            public ulong Reserved0;
            public ulong Reserved1;
            public ulong Reserved2;
            public ulong Reserved3;
            public ulong Reserved4;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct STACKFRAME64
        {
            public ADDRESS64 AddrPC;
            public ADDRESS64 AddrReturn;
            public ADDRESS64 AddrFrame;
            public ADDRESS64 AddrStack;
            public ADDRESS64 AddrBStore;
            public IntPtr FuncTableEntry;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public ulong[] Params;
            public bool Far;
            public bool Virtual;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 3)]
            public ulong[] Reserved;
            public KDHELP64 KdHelp;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct M128A
        {
            public ulong High;
            public long Low;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 16)]
        private struct XMM_SAVE_AREA32
        {
            public ushort ControlWord;
            public ushort StatusWord;
            public byte TagWord;
            public byte Reserved1;
            public ushort ErrorOpcode;
            public uint ErrorOffset;
            public ushort ErrorSelector;
            public ushort Reserved2;
            public uint DataOffset;
            public ushort DataSelector;
            public ushort Reserved3;
            public uint MxCsr;
            public uint MxCsr_Mask;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public M128A[] FloatRegisters;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public M128A[] XmmRegisters;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 96)]
            public byte[] Reserved4;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 16)]
        private struct CONTEXT64
        {
            public ulong P1Home;
            public ulong P2Home;
            public ulong P3Home;
            public ulong P4Home;
            public ulong P5Home;
            public ulong P6Home;

            public uint ContextFlags;
            public uint MxCsr;

            public ushort SegCs;
            public ushort SegDs;
            public ushort SegEs;
            public ushort SegFs;
            public ushort SegGs;
            public ushort SegSs;
            public uint EFlags;

            public ulong Dr0;
            public ulong Dr1;
            public ulong Dr2;
            public ulong Dr3;
            public ulong Dr6;
            public ulong Dr7;

            public ulong Rax;
            public ulong Rcx;
            public ulong Rdx;
            public ulong Rbx;
            public ulong Rsp;
            public ulong Rbp;
            public ulong Rsi;
            public ulong Rdi;
            public ulong R8;
            public ulong R9;
            public ulong R10;
            public ulong R11;
            public ulong R12;
            public ulong R13;
            public ulong R14;
            public ulong R15;

            public ulong Rip;

            public XMM_SAVE_AREA32 DUMMYUNIONNAME;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 26)]
            public M128A[] VectorRegister;
            public ulong VectorControl;

            public ulong DebugControl;
            public ulong LastBranchToRip;
            public ulong LastBranchFromRip;
            public ulong LastExceptionToRip;
            public ulong LastExceptionFromRip;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        private struct SYMBOL_INFO
        {
            public uint SizeOfStruct;
            public uint TypeIndex;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public ulong[] Reserved;
            public uint Index;
            public uint Size;
            public ulong ModBase;
            public uint Flags;
            public ulong Value;
            public ulong Address;
            public uint Register;
            public uint Scope;
            public uint Tag;
            public uint NameLen;
            public uint MaxNameLen;
            public byte Name;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        private struct IMAGEHLP_LINE64
        {
            public uint SizeOfStruct;
            public IntPtr Key;
            public uint LineNumber;
            public IntPtr FileName;
            public ulong Address;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct THREAD_BASIC_INFORMATION
        {
            public int ExitStatus;
            public IntPtr TebBaseAddress;
            public IntPtr ClientIdUniqueProcess;
            public IntPtr ClientIdUniqueThread;
            public IntPtr AffinityMask;
            public int Priority;
            public int BasePriority;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct NT_TIB64
        {
            public ulong ExceptionList;
            public ulong StackBase;
            public ulong StackLimit;
            public ulong SubSystemTib;
            public ulong FiberData;
            public ulong ArbitraryUserPointer;
            public ulong Self;
        }

        private delegate IntPtr FunctionTableAccessRoutine64(IntPtr hProcess, ulong AddrBase);
        private delegate ulong GetModuleBaseRoutine64(IntPtr hProcess, ulong Address);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenThread(uint dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint SuspendThread(IntPtr hThread);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint ResumeThread(IntPtr hThread);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetThreadContext(IntPtr hThread, ref CONTEXT64 lpContext);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr baseAddress, byte[] buffer, int size,
                                                     out IntPtr bytesRead);

        [DllImport("kernel32.dll")]
        private static extern int GetCurrentThreadId();

        [DllImport("ntdll.dll")]
        private static extern int NtQueryInformationThread(IntPtr threadHandle, int threadInformationClass,
                                                           out THREAD_BASIC_INFORMATION threadInformation,
                                                           int threadInformationLength, out int returnLength);

        [DllImport("dbghelp.dll", SetLastError = true)]
        private static extern bool SymInitialize(IntPtr hProcess, string? UserSearchPath, bool fInvadeProcess);

        [DllImport("dbghelp.dll", SetLastError = true)]
        private static extern bool SymCleanup(IntPtr hProcess);

        [DllImport("dbghelp.dll", SetLastError = true)]
        private static extern uint SymSetOptions(uint SymOptions);

        [DllImport("dbghelp.dll", SetLastError = true)]
        private static extern IntPtr SymFunctionTableAccess64(IntPtr hProcess, ulong AddrBase);

        [DllImport("dbghelp.dll", SetLastError = true)]
        private static extern ulong SymGetModuleBase64(IntPtr hProcess, ulong qwAddr);

        [DllImport("dbghelp.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        private static extern bool SymFromAddr(IntPtr hProcess, ulong Address, out ulong Displacement, IntPtr Symbol);

        [DllImport("dbghelp.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        private static extern bool SymGetLineFromAddr64(IntPtr hProcess, ulong qwAddr, out uint pdwDisplacement,
                                                        ref IMAGEHLP_LINE64 Line64);

        [DllImport("dbghelp.dll", SetLastError = true)]
        private static extern bool StackWalk64(uint MachineType, IntPtr hProcess, IntPtr hThread,
                                               ref STACKFRAME64 StackFrame, ref CONTEXT64 ContextRecord,
                                               IntPtr ReadMemoryRoutine,
                                               FunctionTableAccessRoutine64 FunctionTableAccessRoutine,
                                               GetModuleBaseRoutine64 GetModuleBaseRoutine, IntPtr TranslateAddress);
    }

    internal sealed class ThreadStackResolveResult
    {
        public IReadOnlyList<StackFrameRow> Frames { get; }
        public string Note { get; }
        public ulong TebAddress { get; }
        public ulong StackBase { get; }
        public ulong StackTop { get; }
        public ushort? TebFlags { get; }
        public ulong StackPointer { get; }
        public ThreadContextSnapshot? ContextSnapshot { get; }

        public ThreadStackResolveResult(IReadOnlyList<StackFrameRow> frames, string note, ulong tebAddress,
                                        ulong stackBase, ulong stackTop, ushort? tebFlags, ulong stackPointer,
                                        ThreadContextSnapshot? contextSnapshot)
        {
            Frames = frames;
            Note = note;
            TebAddress = tebAddress;
            StackBase = stackBase;
            StackTop = stackTop;
            TebFlags = tebFlags;
            StackPointer = stackPointer;
            ContextSnapshot = contextSnapshot;
        }
    }

    public sealed class ThreadContextSnapshot
    {
        public ulong Rip { get; set; }
        public ulong Rsp { get; set; }
        public ulong Rbp { get; set; }
        public ulong Rax { get; set; }
        public ulong Rbx { get; set; }
        public ulong Rcx { get; set; }
        public ulong Rdx { get; set; }
        public ulong Rsi { get; set; }
        public ulong Rdi { get; set; }
        public ulong R8 { get; set; }
        public ulong R9 { get; set; }
        public ulong R10 { get; set; }
        public ulong R11 { get; set; }
        public ulong R12 { get; set; }
        public ulong R13 { get; set; }
        public ulong R14 { get; set; }
        public ulong R15 { get; set; }
        public ulong Dr0 { get; set; }
        public ulong Dr1 { get; set; }
        public ulong Dr2 { get; set; }
        public ulong Dr3 { get; set; }
        public ulong Dr6 { get; set; }
        public ulong Dr7 { get; set; }
        public uint EFlags { get; set; }
    }
}
