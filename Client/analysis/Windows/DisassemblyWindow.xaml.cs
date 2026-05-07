using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Collections.Concurrent;

namespace BlackbirdInterface
{
    public static class InlinesHelper
    {
        public static readonly DependencyProperty InlinesSourceProperty =
            DependencyProperty.RegisterAttached("InlinesSource", typeof(IReadOnlyList<Inline>), typeof(InlinesHelper),
                                                new PropertyMetadata(null, OnInlinesSourceChanged));

        public static IReadOnlyList<Inline>
        GetInlinesSource(TextBlock t) => (IReadOnlyList<Inline>)t.GetValue(InlinesSourceProperty);

        public static void SetInlinesSource(TextBlock t, IReadOnlyList<Inline> v) => t.SetValue(InlinesSourceProperty,
                                                                                                v);

        private static void OnInlinesSourceChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
        {
            if (d is not TextBlock tb)
                return;
            tb.Inlines.Clear();
            if (e.NewValue is IReadOnlyList<Inline> inlines)
                foreach (var i in inlines)
                    tb.Inlines.Add(i);
        }
    }

    internal static class DisasmColorizer
    {
        private static readonly Dictionary<string, Brush> MnemonicBrushes = new(StringComparer.OrdinalIgnoreCase) {
            { "call", Mk("#88C8FF") },  { "syscall", Mk("#88C8FF") }, { "ret", Mk("#888888") },
            { "retn", Mk("#888888") },  { "retf", Mk("#888888") },    { "nop", Mk("#505050") },
            { "int3", Mk("#505050") },  { "int", Mk("#505050") },     { "ud2", Mk("#505050") },
            { "hlt", Mk("#505050") },   { "pause", Mk("#505050") },   { "push", Mk("#C0B0FF") },
            { "pop", Mk("#C0B0FF") },   { "pushfq", Mk("#C0B0FF") },  { "popfq", Mk("#C0B0FF") },
            { "pushf", Mk("#C0B0FF") }, { "popf", Mk("#C0B0FF") },    { "add", Mk("#FFAACC") },
            { "sub", Mk("#FFAACC") },   { "mul", Mk("#FFAACC") },     { "imul", Mk("#FFAACC") },
            { "div", Mk("#FFAACC") },   { "idiv", Mk("#FFAACC") },    { "inc", Mk("#FFAACC") },
            { "dec", Mk("#FFAACC") },   { "neg", Mk("#FFAACC") },     { "adc", Mk("#FFAACC") },
            { "sbb", Mk("#FFAACC") },   { "and", Mk("#FFCCAA") },     { "or", Mk("#FFCCAA") },
            { "xor", Mk("#FFCCAA") },   { "not", Mk("#FFCCAA") },     { "shl", Mk("#FFCCAA") },
            { "shr", Mk("#FFCCAA") },   { "sar", Mk("#FFCCAA") },     { "ror", Mk("#FFCCAA") },
            { "rol", Mk("#FFCCAA") },   { "rcr", Mk("#FFCCAA") },     { "rcl", Mk("#FFCCAA") },
            { "cmp", Mk("#FFE080") },   { "test", Mk("#FFE080") },
        };

        private static readonly Brush DefaultMnemonicBrush = Mk("#D8D8D8");
        private static readonly Brush JumpBrush = Mk("#FFD080");
        private static readonly Brush RegBrush = Mk("#80DFFF");
        private static readonly Brush ImmBrush = Mk("#FFCC80");
        private static readonly Brush MemBrush = Mk("#80FFB0");
        private static readonly Brush PtrBrush = Mk("#707070");
        private static readonly Brush PunctuationBrush = Mk("#888888");
        private static readonly Brush ImportBrush = Mk("#80FFB0");
        private static readonly Brush DirectTargetBrush = Mk("#88C8FF");
        private static readonly Brush UnknownTargetBrush = Mk("#AAAAAA");

        private static readonly HashSet<string> Registers = new(StringComparer.OrdinalIgnoreCase) {
            "rax",   "rbx",   "rcx",   "rdx",   "rsi",   "rdi",   "rsp",   "rbp",   "r8",     "r9",     "r10",
            "r11",   "r12",   "r13",   "r14",   "r15",   "eax",   "ebx",   "ecx",   "edx",    "esi",    "edi",
            "esp",   "ebp",   "r8d",   "r9d",   "r10d",  "r11d",  "r12d",  "r13d",  "r14d",   "r15d",   "ax",
            "bx",    "cx",    "dx",    "si",    "di",    "sp",    "bp",    "r8w",   "r9w",    "r10w",   "r11w",
            "r12w",  "r13w",  "r14w",  "r15w",  "al",    "bl",    "cl",    "dl",    "sil",    "dil",    "spl",
            "bpl",   "r8b",   "r9b",   "r10b",  "r11b",  "r12b",  "r13b",  "r14b",  "r15b",   "ah",     "bh",
            "ch",    "dh",    "xmm0",  "xmm1",  "xmm2",  "xmm3",  "xmm4",  "xmm5",  "xmm6",   "xmm7",   "xmm8",
            "xmm9",  "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15", "ymm0",  "ymm1",   "ymm2",   "ymm3",
            "ymm4",  "ymm5",  "ymm6",  "ymm7",  "ymm8",  "ymm9",  "ymm10", "ymm11", "ymm12",  "ymm13",  "ymm14",
            "ymm15", "zmm0",  "zmm1",  "zmm2",  "zmm3",  "zmm4",  "zmm5",  "zmm6",  "zmm7",   "zmm8",   "zmm9",
            "zmm10", "zmm11", "zmm12", "zmm13", "zmm14", "zmm15", "rip",   "eip",   "rflags", "eflags", "flags",
            "cs",    "ds",    "es",    "fs",    "gs",    "ss",    "mm0",   "mm1",   "mm2",    "mm3",    "mm4",
            "mm5",   "mm6",   "mm7",   "st0",   "st1",   "st2",   "st3",   "st4",   "st5",    "st6",    "st7",
        };

        private static readonly HashSet<string> SizeKeywords =
            new(StringComparer.OrdinalIgnoreCase) { "byte",    "word",    "dword", "qword", "xmmword",
                                                    "ymmword", "zmmword", "ptr",   "far",   "near" };

        internal static Brush GetMnemonicBrush(string mnemonic)
        {
            if (MnemonicBrushes.TryGetValue(mnemonic, out var b))
                return b;
            if (mnemonic.StartsWith("j", StringComparison.OrdinalIgnoreCase))
                return JumpBrush;
            if (mnemonic.StartsWith("cmov", StringComparison.OrdinalIgnoreCase))
                return Mk("#D8D8D8");
            if (mnemonic.StartsWith("mov", StringComparison.OrdinalIgnoreCase))
                return Mk("#D8D8D8");
            return DefaultMnemonicBrush;
        }

        internal static IReadOnlyList<Inline> TokenizeOperands(string operands)
        {
            var result = new List<Inline>(16);
            if (string.IsNullOrEmpty(operands))
                return result;

            int i = 0;
            while (i < operands.Length)
            {
                char c = operands[i];

                if (c == ' ' || c == '\t')
                {
                    result.Add(Plain(c.ToString()));
                    i++;
                    continue;
                }

                if (c == '[' || c == ']')
                {
                    result.Add(Colored(c.ToString(), MemBrush));
                    i++;
                    continue;
                }

                if (c == ',' || c == '+' || c == '*' || c == ':')
                {
                    result.Add(Colored(c.ToString(), PunctuationBrush));
                    i++;
                    continue;
                }

                if (c == '-')
                {
                    int j = i + 1;
                    while (j < operands.Length && IsWordChar(operands[j]))
                        j++;
                    string tok = operands.Substring(i, j - i);
                    result.Add(Colored(tok, ImmBrush));
                    i = j;
                    continue;
                }

                if (IsWordChar(c))
                {
                    int start = i;
                    while (i < operands.Length && IsWordChar(operands[i]))
                        i++;
                    string word = operands.Substring(start, i - start);

                    if (Registers.Contains(word))
                        result.Add(Colored(word, RegBrush));
                    else if (SizeKeywords.Contains(word))
                        result.Add(Colored(word, PtrBrush));
                    else if (IsHexOrDecimal(word))
                        result.Add(Colored(word, ImmBrush));
                    else
                        result.Add(Plain(word));
                    continue;
                }

                result.Add(Plain(c.ToString()));
                i++;
            }
            return result;
        }

        internal static IReadOnlyList<Inline> BuildResolvedInlines(ulong resolvedTarget, byte targetKind,
                                                                   string formattedAddress)
        {
            if (resolvedTarget == 0)
                return Array.Empty<Inline>();

            return targetKind switch {
                BkdcNative.TargetKindDirect =>
                    new[] { Colored("-> ", PunctuationBrush), Colored(formattedAddress, DirectTargetBrush) },
                BkdcNative.TargetKindIndirect =>
                    new[] { Colored("-> ", PunctuationBrush), Colored("[", MemBrush),
                            Colored(formattedAddress, DirectTargetBrush), Colored("]", MemBrush) },
                BkdcNative.TargetKindIat =>
                    new[] { Colored("-> IAT ", PunctuationBrush), Colored(formattedAddress, ImportBrush) },
                BkdcNative.TargetKindEat =>
                    new[] { Colored("-> EAT ", PunctuationBrush), Colored(formattedAddress, ImportBrush) },
                _ => Array.Empty<Inline>()
            };
        }

        private static bool IsWordChar(char c) => char.IsLetterOrDigit(c) || c == '_' || c == 'x' || c == 'X';

        private static bool IsHexOrDecimal(string s)
        {
            if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                return true;
            if (s.Length > 1 && s[^1] == 'h' && s[..^ 1].All(c => "0123456789abcdefABCDEF".Contains(c)))
                return true;
            return s.All(char.IsDigit);
        }

        private static Brush Mk(string hex)
        {
            var b = new SolidColorBrush((Color)ColorConverter.ConvertFromString(hex));
            b.Freeze();
            return b;
        }

        private static Run Plain(string text) => new(text);
        private static Run Colored(string text, Brush brush) => new(text) { Foreground = brush };
    }

    public sealed class DisassemblyRow
    {
        public string AddressText { get; init; } = string.Empty;
        public string BytesText { get; init; } = string.Empty;
        public string Mnemonic { get; init; } = string.Empty;
        public string Operands { get; init; } = string.Empty;
        public string RowKind { get; set; } = string.Empty;
        public ulong RawAddress { get; init; }
        public Brush MnemonicBrush { get; init; } = Brushes.White;
        public IReadOnlyList<Inline> OperandsInlines { get; init; } = Array.Empty<Inline>();
        public IReadOnlyList<Inline> ResolvedInlines { get; set; } = Array.Empty<Inline>();
    }

    public partial class DisassemblyWindow : Window
    {
        private readonly BlackbirdBackendSession _session;
        private readonly uint _pid;
        private readonly ulong _baseAddress;
        private readonly ulong _regionSize;
        private readonly string _label;
        private readonly byte[]? _snapshotBytes;
        private readonly uint _snapshotOffset;

        private List<DisassemblyRow> _rows = new();
        private byte[] _code = Array.Empty<byte>();

        internal DisassemblyWindow(BlackbirdBackendSession session, uint pid, ulong baseAddress, ulong regionSize,
                                   string label, byte[]? snapshotBytes = null, uint snapshotOffset = 0)
        {
            InitializeComponent();
            WindowThemeHelper.WireThemeAwareTitleBar(this);

            _session = session;
            _pid = pid;
            _baseAddress = baseAddress;
            _regionSize = regionSize;
            _label = label;
            _snapshotBytes = snapshotBytes?.ToArray();
            _snapshotOffset = snapshotOffset;

            TitleBlock.Text = $"Disassembly  {label}  (base 0x{baseAddress:X})  PID {pid}";
            StatusBlock.Text = "Reading...";

            Loaded += async (_, _) => await LoadAsync();
        }

        private static readonly ConcurrentDictionary<int, string> s_SsnTable = new();
        private static volatile bool s_SsnTableBuilt;

        private static IReadOnlyDictionary<int, string> GetSsnTable()
        {
            if (!s_SsnTableBuilt)
            {
                BuildSsnTable();
                s_SsnTableBuilt = true;
            }
            return s_SsnTable;
        }

        private static void BuildSsnTable()
        {
            try
            {
                string ntdllPath =
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "ntdll.dll");
                if (!File.Exists(ntdllPath))
                    return;

                byte[] pe = File.ReadAllBytes(ntdllPath);

                if (pe.Length < 0x40)
                    return;
                int peOffset = BitConverter.ToInt32(pe, 0x3C);
                if (peOffset < 0 || peOffset + 24 + 240 > pe.Length)
                    return;

                if (BitConverter.ToUInt32(pe, peOffset) != 0x00004550u)
                    return;

                int optOffset = peOffset + 24;
                int sizeOfOpt = BitConverter.ToUInt16(pe, peOffset + 20);
                int numSections = BitConverter.ToUInt16(pe, peOffset + 6);
                int sectionOffset = optOffset + sizeOfOpt;

                if (optOffset + 112 + 8 > pe.Length)
                    return;
                int exportRva = BitConverter.ToInt32(pe, optOffset + 112);
                int exportSize = BitConverter.ToInt32(pe, optOffset + 116);
                if (exportRva == 0 || exportSize == 0)
                    return;

                var sections = new List<(int va, int raw, int rawSize)>(numSections);
                for (int s = 0; s < numSections; s++)
                {
                    int sBase = sectionOffset + s * 40;
                    if (sBase + 40 > pe.Length)
                        break;
                    int va = BitConverter.ToInt32(pe, sBase + 12);
                    int rawOff = BitConverter.ToInt32(pe, sBase + 20);
                    int rawSz = BitConverter.ToInt32(pe, sBase + 16);
                    sections.Add((va, rawOff, rawSz));
                }

                int RvaToOffset(int rva)
                {
                    foreach (var (va, raw, sz) in sections)
                        if (rva >= va && rva < va + sz)
                            return raw + (rva - va);
                    return -1;
                }

                string ? ReadAnsiString(int rva)
                {
                    int off = RvaToOffset(rva);
                    if (off < 0 || off >= pe.Length)
                        return null;
                    int end = off;
                    while (end < pe.Length && pe[end] != 0)
                        end++;
                    return System.Text.Encoding.ASCII.GetString(pe, off, end - off);
                }

                int expOff = RvaToOffset(exportRva);
                if (expOff < 0 || expOff + 40 > pe.Length)
                    return;

                int numNames = BitConverter.ToInt32(pe, expOff + 24);
                int addrOfFunctions = BitConverter.ToInt32(pe, expOff + 28);
                int addrOfNames = BitConverter.ToInt32(pe, expOff + 32);
                int addrOfOrdinals = BitConverter.ToInt32(pe, expOff + 36);

                int namesOff = RvaToOffset(addrOfNames);
                int ordinalsOff = RvaToOffset(addrOfOrdinals);
                int functionsOff = RvaToOffset(addrOfFunctions);
                if (namesOff < 0 || ordinalsOff < 0 || functionsOff < 0)
                    return;

                for (int n = 0; n < numNames; n++)
                {
                    int nameRvaOff = namesOff + n * 4;
                    if (nameRvaOff + 4 > pe.Length)
                        break;
                    int nameRva = BitConverter.ToInt32(pe, nameRvaOff);

                    string? name = ReadAnsiString(nameRva);
                    if (name == null)
                        continue;
                    if (!name.StartsWith("Nt", StringComparison.Ordinal) &&
                        !name.StartsWith("Zw", StringComparison.Ordinal))
                        continue;

                    int ordinalOff = ordinalsOff + n * 2;
                    if (ordinalOff + 2 > pe.Length)
                        break;
                    int ordinalIdx = BitConverter.ToUInt16(pe, ordinalOff);

                    int funcRvaOff = functionsOff + ordinalIdx * 4;
                    if (funcRvaOff + 4 > pe.Length)
                        continue;
                    int funcRva = BitConverter.ToInt32(pe, funcRvaOff);

                    int funcOff = RvaToOffset(funcRva);
                    if (funcOff < 0 || funcOff + 8 > pe.Length)
                        continue;
                    if (pe[funcOff] != 0x4C || pe[funcOff + 1] != 0x8B || pe[funcOff + 2] != 0xD1 ||
                        pe[funcOff + 3] != 0xB8)
                        continue;

                    int ssn = BitConverter.ToInt32(pe, funcOff + 4);
                    if (ssn < 0 || ssn > 0xFFF)
                        continue;

                    if (!s_SsnTable.ContainsKey(ssn) || name.StartsWith("Nt", StringComparison.Ordinal))
                        s_SsnTable[ssn] = name;
                }
            }
            catch
            {
            }
        }

        private static readonly Brush SyscallAnnotBrush = MakeAnnotBrush();
        private static Brush MakeAnnotBrush()
        {
            var b = new SolidColorBrush(Color.FromRgb(0xFF, 0x60, 0x60));
            b.Freeze();
            return b;
        }

        private void DetectDirectSyscallStubs()
        {
            if (_rows.Count == 0)
                return;

            var ssnTable = GetSsnTable();
            bool anyFound = false;

            for (int i = 0; i < _rows.Count; i++)
            {
                var row = _rows[i];
                if (!row.Mnemonic.Equals("syscall", StringComparison.OrdinalIgnoreCase))
                    continue;

                int ssn = -1;
                bool hasStubPrologue = false;

                for (int back = i - 1; back >= Math.Max(0, i - 6); back--)
                {
                    var prev = _rows[back];
                    if (!prev.Mnemonic.Equals("mov", StringComparison.OrdinalIgnoreCase))
                        continue;

                    string ops = prev.Operands;

                    if (ops.StartsWith("r10,", StringComparison.OrdinalIgnoreCase) &&
                        ops.EndsWith("rcx", StringComparison.OrdinalIgnoreCase))
                    {
                        hasStubPrologue = true;
                        continue;
                    }

                    if (ops.StartsWith("eax,", StringComparison.OrdinalIgnoreCase) ||
                        ops.StartsWith("eax, ", StringComparison.OrdinalIgnoreCase))
                    {
                        string imm = ops.Split(',').Last().Trim();
                        if (imm.StartsWith("0x", StringComparison.OrdinalIgnoreCase) &&
                            int.TryParse(imm.AsSpan(2), System.Globalization.NumberStyles.HexNumber, null,
                                         out int parsedSsn) &&
                            parsedSsn >= 0 && parsedSsn <= 0xFFF)
                        {
                            ssn = parsedSsn;
                        }
                    }
                }

                string resolvedName = ssn >= 0 && ssnTable.TryGetValue(ssn, out var n) ? n : null!;
                string label = hasStubPrologue ? "direct-syscall stub" : "raw syscall";
                string annot = ssn >= 0 ? $"{label}  SSN=0x{ssn:X}" +
                                              (resolvedName != null ? $"  ({resolvedName})" : "  (unresolved)")
                                        : label;

                row.RowKind = "DirectSyscall";
                row.ResolvedInlines = new[] { new Run(annot) { Foreground = SyscallAnnotBrush } };
                anyFound = true;

                if (ssn >= 0)
                {
                    for (int back = i - 1; back >= Math.Max(0, i - 4); back--)
                    {
                        var prev = _rows[back];
                        if (prev.Mnemonic.Equals("mov", StringComparison.OrdinalIgnoreCase) &&
                            prev.Operands.StartsWith("eax,", StringComparison.OrdinalIgnoreCase))
                        {
                            prev.RowKind = "DirectSyscall";
                            break;
                        }
                    }
                }
            }

            if (anyFound)
                RefreshGrid();
        }

        private string FormatAddress(ulong address)
        {
            if (address >= _baseAddress && address < _baseAddress + _regionSize)
            {
                string baseName = Path.GetFileName(_label.Trim());
                if (string.IsNullOrEmpty(baseName))
                    baseName = _label.Trim();
                return $"{baseName}+{address - _baseAddress:X}";
            }
            return $"0x{address:X}";
        }

        private static bool IsNullFillInstruction(string mnemonic, string operands) =>
            string.Equals(mnemonic, "add", StringComparison.OrdinalIgnoreCase) &&
            operands.Contains("rax", StringComparison.OrdinalIgnoreCase) &&
            operands.Contains("al", StringComparison.OrdinalIgnoreCase);

        private static bool IsUnreachable(string mnemonic) => mnemonic is "ret" or "retn" or "retf" or "jmp" or "ud2" or
                                                                          "hlt";

        private async System.Threading.Tasks.Task LoadAsync()
        {
            try
            {
                await LoadAsyncCore();
            }
            catch (Exception ex)
            {
                StatusBlock.Text = $"Error: {ex.GetType().Name}: {ex.Message}";
                DebugConsoleService.WriteLocal($"[DISASM] exception pid={_pid} base=0x{_baseAddress:X}: {ex}");
            }
        }

        private async System.Threading.Tasks.Task LoadAsyncCore()
        {
            if (!BkdcNative.IsAvailable)
            {
                StatusBlock.Text =
                    "Disassembly engine unavailable — BKDC.dll not found. " + "Build Lib/BK_disassembler to enable.";
                return;
            }

            byte[]? code = null;
            string? readError = null;
            ulong decodeBase = _baseAddress;

            if (_snapshotBytes is { Length : > 0 })
            {
                code = _snapshotBytes.ToArray();
                decodeBase = _baseAddress + _snapshotOffset;
                StatusBlock.Text = $"Loaded capture snapshot: {code.Length} bytes";
            }
            else
            {
                (code, readError) = await System.Threading.Tasks.Task.Run(
                    () => _session.ReadProcessMemory(_pid, _baseAddress, (uint)Math.Min(_regionSize, 4096)));
            }

            if (code == null || code.Length == 0)
            {
                StatusBlock.Text = $"Memory read failed: {readError ?? "no data returned"}";
                return;
            }

            BkdcNative.BkdcInstruction[] insns =
                await System.Threading.Tasks.Task.Run(() => BkdcNative.Disassemble(code, decodeBase));

            _code = code;

            var rows = new List<DisassemblyRow>(insns.Length);
            bool pastLastReturn = false;
            int lastNonDeadIdx = -1;

            for (int idx = 0; idx < insns.Length; idx++)
            {
                var insn = insns[idx];
                string mn = insn.GetMnemonic();
                string ops = insn.GetOpStr();

                if (IsUnreachable(mn))
                    pastLastReturn = true;

                bool dead = pastLastReturn && IsNullFillInstruction(mn, ops);

                int offset = (int)(insn.Address - _baseAddress);
                int sz = insn.Size;
                string bytesHex = (offset >= 0 && offset + sz <= code.Length)
                                      ? BitConverter.ToString(code, offset, sz).Replace("-", " ")
                                      : string.Empty;

                string resolvedFmt = insn.ResolvedTarget != 0 ? FormatAddress(insn.ResolvedTarget) : string.Empty;

                string rowKind = dead                                           ? "Dead"
                                 : mn is "ret" or "retn" or "retf"              ? "Ret"
                                 : mn is "call"                                 ? "Call"
                                 : mn is "nop" or "int3"                        ? "Nop"
                                 : mn.StartsWith("j", StringComparison.Ordinal) ? "Jump"
                                 : insn.TargetKind is BkdcNative.TargetKindIat or BkdcNative.TargetKindEat
                                     ? "Import"
                                     : string.Empty;

                var row = new DisassemblyRow {
                    RawAddress = insn.Address,
                    AddressText = FormatAddress(insn.Address),
                    BytesText = bytesHex,
                    Mnemonic = mn,
                    Operands = ops,
                    RowKind = rowKind,
                    MnemonicBrush = DisasmColorizer.GetMnemonicBrush(mn),
                    OperandsInlines = DisasmColorizer.TokenizeOperands(ops),
                    ResolvedInlines =
                        DisasmColorizer.BuildResolvedInlines(insn.ResolvedTarget, insn.TargetKind, resolvedFmt),
                };

                rows.Add(row);
                if (!dead)
                    lastNonDeadIdx = rows.Count - 1;
            }

            if (lastNonDeadIdx >= 0 && lastNonDeadIdx < rows.Count - 1)
                rows.RemoveRange(lastNonDeadIdx + 1, rows.Count - lastNonDeadIdx - 1);

            _rows = rows;
            InsnGrid.ItemsSource = _rows;

            DetectDirectSyscallStubs();

            int deadCount = insns.Length - _rows.Count;
            StatusBlock.Text = $"{_rows.Count} instructions  |  {code.Length} bytes  |  base 0x{_baseAddress:X}" +
                               (deadCount > 0 ? $"  |  {deadCount} dead bytes stripped" : string.Empty);
        }

        private void InsnGrid_PreviewKeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.C && (Keyboard.Modifiers & ModifierKeys.Control) != 0)
            {
                CopySelected_Click(sender, e);
                e.Handled = true;
            }
            else if (e.Key == Key.C && Keyboard.Modifiers == (ModifierKeys.Control | ModifierKeys.Shift))
            {
                CopyAll_Click(sender, e);
                e.Handled = true;
            }
            else if (e.Key == Key.A && (Keyboard.Modifiers & ModifierKeys.Control) != 0)
            {
                InsnGrid.SelectAll();
                e.Handled = true;
            }
        }

        private void CopySelected_Click(object sender, RoutedEventArgs e)
        {
            var selected = InsnGrid.SelectedItems.OfType<DisassemblyRow>().ToList();
            if (selected.Count == 0)
                selected = _rows;
            CopyRowsToClipboard(selected);
        }

        private void CopyAll_Click(object sender, RoutedEventArgs e) => CopyRowsToClipboard(_rows);

        private static void CopyRowsToClipboard(IEnumerable<DisassemblyRow> rows)
        {
            var sb = new StringBuilder();
            foreach (var r in rows)
            {
                string resolved = string.Concat(r.ResolvedInlines.OfType<Run>().Select(x => x.Text));
                sb.AppendLine($"{r.AddressText,-30} {r.BytesText,-22} {r.Mnemonic,-9} {r.Operands,-32} {resolved}");
            }
            try
            {
                Clipboard.SetText(sb.ToString());
            }
            catch
            {
            }
        }

        private void ClearHighlights_Click(object sender, RoutedEventArgs e)
        {
            foreach (var r in _rows)
            {
                if (r.RowKind is "ByteMatch" or "CrossRef")
                    r.RowKind = string.Empty;
            }
            RefreshGrid();
            StatusBlock.Text = $"{_rows.Count} instructions  |  base 0x{_baseAddress:X}  |  highlights cleared";
        }

        private void ScanBytePattern_Click(object sender, RoutedEventArgs e)
        {
            string? input = ShowInputDialog(
                "Find Byte Pattern",
                "Enter hex bytes (spaces optional, ?? = wildcard):\n" + "Example:  48 8B 04 25 ?? ?? ?? ??", this);
            if (input == null)
                return;

            byte?[] pattern = ParseHexPattern(input);
            if (pattern.Length == 0)
            {
                MessageBox.Show("No valid hex bytes parsed.", "Bad pattern", MessageBoxButton.OK,
                                MessageBoxImage.Warning);
                return;
            }

            if (_code.Length == 0)
            {
                StatusBlock.Text = "No code loaded yet.";
                return;
            }
            HighlightBytePattern(pattern);
            StatusBlock.Text =
                $"{_rows.Count(r => r.RowKind == "ByteMatch")} byte-pattern match(es) highlighted (yellow)";
        }

        private void ScanCallsTo_Click(object sender, RoutedEventArgs e)
        {
            string? input = ShowInputDialog(
                "Find Calls / Jumps To", "Enter target address (hex, with or without 0x) or symbol substring:", this);
            if (input == null)
                return;

            input = input.Trim();
            ClearScanHighlights();
            int count = 0;
            DisassemblyRow? first = null;

            bool isAddress = ulong.TryParse(input.TrimStart('0', 'x'), System.Globalization.NumberStyles.HexNumber,
                                            null, out ulong targetAddr);

            foreach (var r in _rows)
            {
                if (r.RowKind is not("Call" or "Jump" or "Import") &&
                    !r.Mnemonic.StartsWith("j", StringComparison.OrdinalIgnoreCase) &&
                    !r.Mnemonic.Equals("call", StringComparison.OrdinalIgnoreCase))
                    continue;

                string resolved = string.Concat(r.ResolvedInlines.OfType<Run>().Select(x => x.Text));
                bool hit = isAddress
                               ? resolved.Contains(targetAddr.ToString("X"), StringComparison.OrdinalIgnoreCase) ||
                                     r.Operands.Contains(targetAddr.ToString("X"), StringComparison.OrdinalIgnoreCase)
                               : resolved.Contains(input, StringComparison.OrdinalIgnoreCase) ||
                                     r.Operands.Contains(input, StringComparison.OrdinalIgnoreCase);

                if (hit)
                {
                    r.RowKind = "CrossRef";
                    first ??= r;
                    count++;
                }
            }
            RefreshGrid();
            if (first != null)
                InsnGrid.ScrollIntoView(first);
            StatusBlock.Text = $"{count} cross-reference(s) highlighted (orange)";
        }

        private void ScanYaraHex_Click(object sender, RoutedEventArgs e)
        {
            string? input = ShowInputDialog("Scan YARA Hex String",
                                            "Enter a YARA-style hex string (braces optional, ?? = wildcard):\n" +
                                                "Example:  { 48 8B ?? 04 25 [2-4] 00 }",
                                            this);
            if (input == null)
                return;

            string normalized = Regex.Replace(input, @"\[\d+(?:-\d+)?\]", "??");
            normalized = normalized.Replace("{", "").Replace("}", "");

            ScanBytePatternCore(normalized);
        }

        private void ScanBytePatternCore(string hexInput)
        {
            byte?[] pattern = ParseHexPattern(hexInput);
            if (pattern.Length == 0 || _code.Length == 0)
                return;
            HighlightBytePattern(pattern);
            StatusBlock.Text = $"{_rows.Count(r => r.RowKind == "ByteMatch")} YARA hex match(es) highlighted (yellow)";
        }

        private void HighlightBytePattern(byte?[] pattern)
        {
            var hits = new HashSet<ulong>();
            for (int i = 0; i <= _code.Length - pattern.Length; i++)
            {
                bool ok = true;
                for (int j = 0; j < pattern.Length && ok; j++)
                    if (pattern[j].HasValue && _code[i + j] != pattern[j]!.Value)
                        ok = false;
                if (ok)
                    hits.Add(_baseAddress + (ulong)i);
            }
            ClearScanHighlights();
            DisassemblyRow? first = null;
            foreach (var r in _rows)
            {
                int byteLen = Math.Max(1, r.BytesText.Replace(" ", "").Length / 2);
                if (hits.Any(h => r.RawAddress <= h && h < r.RawAddress + (ulong)byteLen))
                {
                    r.RowKind = "ByteMatch";
                    first ??= r;
                }
            }
            RefreshGrid();
            if (first != null)
                InsnGrid.ScrollIntoView(first);
        }

        private static byte?[] ParseHexPattern(string input)
        {
            var result = new List < byte ?>();
            string cleaned = Regex.Replace(input.ToUpperInvariant(), @"[^0-9A-F?]", " ");
            string[] tokens = cleaned.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            foreach (string tok in tokens)
            {
                if (tok == "??" || tok == "?")
                    result.Add(null);
                else if (tok.Length == 2 && tok.All(c => "0123456789ABCDEF".Contains(c)))
                    result.Add(Convert.ToByte(tok, 16));
                else
                    return Array.Empty < byte ?>();
            }
            return result.ToArray();
        }

        private void ClearScanHighlights()
        {
            foreach (var r in _rows)
                if (r.RowKind is "ByteMatch" or "CrossRef")
                    r.RowKind = string.Empty;
        }

        private void RefreshGrid()
        {
            InsnGrid.ItemsSource = null;
            InsnGrid.ItemsSource = _rows;
        }

        private static string? ShowInputDialog(string title, string prompt, Window owner)
        {
            var dialog = new Window { Title = title,
                                      Width = 480,
                                      Height = 160,
                                      Owner = owner,
                                      WindowStartupLocation = WindowStartupLocation.CenterOwner,
                                      WindowStyle = WindowStyle.ToolWindow,
                                      ResizeMode = ResizeMode.NoResize,
                                      Background = SystemColors.ControlBrush };
            var stack = new StackPanel { Margin = new Thickness(12) };
            stack.Children.Add(
                new TextBlock { Text = prompt, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 8) });
            var tb = new TextBox { FontFamily = new FontFamily("Cascadia Mono, Cascadia Code, Consolas"),
                                   Margin = new Thickness(0, 0, 0, 10) };
            stack.Children.Add(tb);
            var buttons = new StackPanel { Orientation = Orientation.Horizontal,
                                           HorizontalAlignment = HorizontalAlignment.Right };
            string? result = null;
            var ok = new Button { Content = "OK", Width = 70, Margin = new Thickness(0, 0, 8, 0), IsDefault = true };
            var cancel = new Button { Content = "Cancel", Width = 70, IsCancel = true };
            ok.Click += (_, __) =>
            {
                result = tb.Text.Trim();
                dialog.DialogResult = true;
            };
            cancel.Click += (_, __) => dialog.DialogResult = false;
            buttons.Children.Add(ok);
            buttons.Children.Add(cancel);
            stack.Children.Add(buttons);
            dialog.Content = stack;
            tb.Focus();
            return dialog.ShowDialog() == true && !string.IsNullOrWhiteSpace(result) ? result : null;
        }

        private void TitleBar_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
        {
            if (e.ClickCount == 2)
                WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;
            else
                DragMove();
        }

        private void CloseButton_Click(object sender, RoutedEventArgs e) => Close();
    }
}
